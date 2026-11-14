// 仕事のグラフ（起草段階の試作。法律ではない）
//
// 票（仕事の単位）の集まりを DAG として扱う、記録を書かない純関数の集まり。
// 領域に依らない節の形: { id, status, depends_on, resources, approved, risk? }
//   status は SPEC §5 の 'ready' | 'in_progress' | 'review' | 'held' | 'merged' | 'blocked'（領域パックの別名は呼び出し側で正規化済みとする）
//   resources は触る成果物（開発なら票の files_allowed）
//
// 性質（INV-12）: 未承認・blocked の節は、それに依存しない節の着手を妨げない（依存する節だけが待つ）。
//
// 方針（審査 B-F1〜B-F15 の判例）: 文字列は正規化せずに照合しない。形は「決まった形だけを受ける」（許可リスト）。
//   check() は buildGraph の形の検査を通らない生の nodes を受けるので、形の検査（TG-NODE-SHAPE）を必ず通す。
//
// 保証しないこと:
//   - recommend の勧めは助言で、効力はない。着手の許可は Kernel の承認・予算の台帳が決める
//   - AdaptOrch（arXiv 2602.16873）の閾値（θω=0.5, θγ=0.6, θδ=5）は参考の値で、**VGDD の仕事では校正していない**。
//     AdaptOrch 自身、計算量をそろえた比較ではトポロジ固有の寄与は小さいと報告している。勧めの決定には使っていない
//   - resources の判定は、literal・`dir/**`・`prefix*` の単純な形だけ。それ以外の形は「扱えない形」で、
//     包含は false、重なりは true（fail-closed）。見た目が似た別の文字（ホモグリフ）は見分けない
//   - 重なりの判定は、大文字小文字を区別しないファイルシステムを想定して小文字にそろえて比べる（厳しい側）。
//     包含の判定は文字どおり（厳しい側）。シンボリックリンク・ハードリンクで同じ実体を指す場合は見ない
//   - metrics.conflicts は参考の数で、作業量の上限を超えたら途中までの数（conflicts_truncated: true）

import { STATUSES as VOCAB_STATUSES } from './lib/vocab.mjs';

/** 状態の名前（lib/vocab.mjs の STATUSES） */
export const STATUSES = VOCAB_STATUSES;
export const MAX_NODES = 2000;
const MAX_ID = 128;
const MAX_RES = 64;
const MAX_RES_LEN = 512;
const CONFLICT_BUDGET = 3_000_000;

// ---- resources の単純なグロブ ------------------------------------------------
// 意味:  literal L … L だけ ／ deep（base/**）… base 自身と base/ の下のすべて
//        star（p*）… p で始まり、残りに / を含まない文字列（p 自身を含む）

/**
 * 単純なグロブの分類。{type: literal|deep|star, base} | null（扱えない形）。
 * 先頭で NFC に直してから受ける（macOS の NFD のファイル名と NFC の同じ名前は同じものとして扱う。base は NFC）。
 * `[id]` のような角かっこ・`?`・`{}`・途中の `*`・ZWJ などの書式文字は扱えない形のまま（角かっこの名前は `dir/**` で代用する）。
 */
export function parsePattern(p0) {
  if (typeof p0 !== 'string' || p0 === '' || p0.length > MAX_RES_LEN) return null;
  const p = p0.normalize('NFC');
  if (/[\p{C}\\?[\]{}!]/u.test(p)) return null; // 制御・書式（ゼロ幅等）・バックスラッシュ・扱えない記号
  if (/^\s|\s$/.test(p)) return null;
  if (p.startsWith('/') || p.endsWith('/') || p.includes('//')) return null;
  if (p.split('/').some((s) => s === '.' || s === '..')) return null;
  if (!p.includes('*')) return { type: 'literal', base: p };
  if (p.endsWith('/**')) {
    const base = p.slice(0, -3);
    return base !== '' && !base.includes('*') ? { type: 'deep', base } : null;
  }
  if (p.endsWith('*')) {
    const base = p.slice(0, -1);
    return !base.includes('*') ? { type: 'star', base } : null;
  }
  return null;
}

/** outer が inner を完全に含むか（文字どおり。大文字小文字は区別する）。true | false | null（判定できない） */
export function covers(outer, inner) {
  const o = parsePattern(outer);
  const i = parsePattern(inner);
  if (!o || !i) return null;
  if (o.type === 'literal') return i.type === 'literal' && i.base === o.base;
  if (o.type === 'deep') {
    const under = (s) => s === o.base || s.startsWith(o.base + '/');
    if (i.type === 'literal' || i.type === 'deep') return under(i.base);
    return i.base.startsWith(o.base + '/'); // star(q) は q 自身と q+残り。q が base と同じなら base+x が外れる
  }
  // star
  if (i.type === 'deep') return false; // 深い下の文字列は残りに / を含む
  return i.base.startsWith(o.base) && !i.base.slice(o.base.length).includes('/');
}

const lowKey = (pt) => (pt.type === 'deep' ? pt.base + '/' : pt.base).toLowerCase();

function overlapParsed(pa, pb) {
  if (!pa || !pb) return true;
  const ka = lowKey(pa);
  const kb = lowKey(pb);
  if (pa.type === 'literal' && pb.type === 'literal') return ka === kb;
  return ka.startsWith(kb) || kb.startsWith(ka); // ワイルドカードは前置の関係だけで保守的に重なりとみなす
}

/** 2つの resource が重なりうるか。扱えない形は true（fail-closed）。大文字小文字は区別せずに比べる */
export function overlap(a, b) {
  return overlapParsed(parsePattern(a), parsePattern(b));
}

export function resourcesOverlap(as, bs) {
  if (!Array.isArray(as) || !Array.isArray(bs)) return true; // 読めない resources は重なるとみなす
  const pa = as.map(parsePattern);
  const pb = bs.map(parsePattern);
  for (const a of pa) for (const b of pb) if (overlapParsed(a, b)) return true;
  return false;
}

// ---- 形の検査と構築 ------------------------------------------------------------

/** 節の形（型と大きさ）だけの検査。構造（重複・欠け・循環）は見ない */
export function shapeIssues(nodes) {
  if (!Array.isArray(nodes)) return ['nodes が配列でない'];
  const errors = [];
  nodes.forEach((n, i) => {
    if (!n || typeof n !== 'object' || Array.isArray(n)) { errors.push(`${i} 番目が節（オブジェクト）でない`); return; }
    if (typeof n.id !== 'string' || n.id === '' || n.id.length > MAX_ID) { errors.push(`${i} 番目: id が空でない文字列（${MAX_ID} 字以内）でない`); return; }
    const id = n.id;
    if (!STATUSES.includes(n.status)) errors.push(`${id}: status が不正（${String(n.status)}）`);
    if (!Array.isArray(n.depends_on) || n.depends_on.length > MAX_NODES || n.depends_on.some((d) => typeof d !== 'string')) errors.push(`${id}: depends_on が文字列の配列でない`);
    if (!Array.isArray(n.resources) || n.resources.length > MAX_RES || n.resources.some((r) => typeof r !== 'string')) errors.push(`${id}: resources が文字列の配列（${MAX_RES} 個以内）でない`);
    if (typeof n.approved !== 'boolean') errors.push(`${id}: approved が真偽値でない`);
    if (n.risk !== undefined && !['low', 'mid', 'high'].includes(n.risk)) errors.push(`${id}: risk が不正`);
  });
  return errors;
}

/** 形が正しい節の集まりに対する Kahn 法（反復。再帰しない）。order に入れなかった節が閉路に関わる */
function kahn(list) {
  const idx = new Map();
  list.forEach((n, i) => { if (!idx.has(n.id)) idx.set(n.id, i); });
  const indeg = new Array(list.length).fill(0);
  const out = list.map(() => []);
  list.forEach((n, i) => {
    for (const d of n.depends_on) {
      const j = idx.get(d);
      if (j === undefined) continue; // 欠けた依存は別の検査が見る
      indeg[i]++;
      out[j].push(i);
    }
  });
  const level = new Array(list.length).fill(1);
  const queue = [];
  indeg.forEach((v, i) => { if (v === 0) queue.push(i); });
  const order = [];
  for (let h = 0; h < queue.length; h++) {
    const x = queue[h];
    order.push(x);
    for (const y of out[x]) {
      if (level[x] + 1 > level[y]) level[y] = level[x] + 1;
      if (--indeg[y] === 0) queue.push(y);
    }
  }
  const done = new Set(order);
  const cyc = list.map((n, i) => (done.has(i) ? null : n.id)).filter((x) => x !== null).sort();
  return { idx, order, level, cyc, out };
}

/** 閉路に関わる節の id。形が壊れていても落ちない（形の壊れた節は無視する。形は TG-NODE-SHAPE が見る） */
function cycleMembers(nodes) {
  const list = Array.isArray(nodes)
    ? nodes.filter((n) => n && typeof n.id === 'string' && Array.isArray(n.depends_on) && n.depends_on.every((d) => typeof d === 'string'))
    : [];
  return kahn(list).cyc;
}

/** グラフを作る。壊れていれば errors を返し、graph は返さない（fail-closed。例外を投げない） */
export function buildGraph(nodes) {
  try {
    const errors = shapeIssues(nodes);
    if (errors.length) return { ok: false, errors };
    if (nodes.length > MAX_NODES) return { ok: false, errors: [`節の数が上限 ${MAX_NODES} を超える（${nodes.length}）`] };
    const seen = new Set();
    for (const n of nodes) { if (seen.has(n.id)) errors.push(`id の重複: ${n.id}`); seen.add(n.id); }
    for (const n of nodes) {
      for (const d of n.depends_on) {
        if (d === n.id) errors.push(`自己依存: ${n.id}`);
        else if (!seen.has(d)) errors.push(`存在しない依存: ${n.id} → ${d}`);
      }
    }
    if (errors.length) return { ok: false, errors };
    const k = kahn(nodes);
    if (k.cyc.length) return { ok: false, errors: [`依存の循環: ${k.cyc.join(', ')}`] };
    const byId = new Map();
    for (const n of nodes) byId.set(n.id, { ...n, depends_on: [...n.depends_on], resources: [...n.resources] });
    const ids = [...byId.keys()].sort();
    const level = new Map(nodes.map((n, i) => [n.id, k.level[i]]));
    const pat = new Map(ids.map((id) => [id, byId.get(id).resources.map(parsePattern)]));
    return { ok: true, graph: { ids, byId, level, pat }, errors: [] };
  } catch (e) {
    return { ok: false, errors: [`グラフを作れない（例外: ${String(e && e.message).slice(0, 80)}）`] };
  }
}

function nodesOverlap(graph, a, b) {
  const pa = graph.pat.get(a);
  const pb = graph.pat.get(b);
  for (const x of pa) for (const y of pb) if (overlapParsed(x, y)) return true;
  return false;
}

const bit = (arr, i) => (arr[i >> 5] >>> (i & 31)) & 1;
const setBit = (arr, i) => { arr[i >> 5] |= 1 << (i & 31); };

export function metrics(graph) {
  const ids = graph.ids;
  const n = ids.length;
  let edges = 0;
  for (const id of ids) edges += graph.byId.get(id).depends_on.length;
  const perLevel = new Map();
  for (const id of ids) perLevel.set(graph.level.get(id), (perLevel.get(graph.level.get(id)) || 0) + 1);
  const width = n ? Math.max(...perLevel.values()) : 0;
  const depth = n ? Math.max(...perLevel.keys()) : 0;
  const coupling = n < 2 ? 0 : edges / ((n * (n - 1)) / 2);

  // 祖先の集合（ビット列。ids の添字）。層の順に作る
  const ix = new Map(ids.map((id, i) => [id, i]));
  const words = (n >> 5) + 1;
  const anc = ids.map(() => new Uint32Array(words));
  const byLevel = [...ids].sort((a, b) => graph.level.get(a) - graph.level.get(b));
  for (const id of byLevel) {
    const a = anc[ix.get(id)];
    for (const d of graph.byId.get(id).depends_on) {
      const dj = ix.get(d);
      for (let w = 0; w < words; w++) a[w] |= anc[dj][w];
      setBit(a, dj);
    }
  }
  // 重なる組の候補。キーを並べ替え、前置の関係にある範囲だけを見る（作業量の上限つき）
  const marks = ids.map(() => new Uint32Array(words));
  const unknown = [];
  const entries = [];
  ids.forEach((id, i) => {
    const ps = graph.pat.get(id);
    if (ps.some((p) => p === null)) unknown.push(i);
    for (const p of ps) if (p) entries.push({ k: lowKey(p), lit: p.type === 'literal', i });
  });
  entries.sort((x, y) => (x.k < y.k ? -1 : x.k > y.k ? 1 : 0));
  let budget = CONFLICT_BUDGET;
  let truncated = false;
  outer: for (let a = 0; a < entries.length; a++) {
    for (let b = a + 1; b < entries.length && entries[b].k.startsWith(entries[a].k); b++) {
      if (--budget < 0) { truncated = true; break outer; }
      if (entries[a].i === entries[b].i) continue;
      if (entries[a].lit && entries[b].lit && entries[a].k !== entries[b].k) continue;
      setBit(marks[entries[a].i], entries[b].i);
      setBit(marks[entries[b].i], entries[a].i);
    }
  }
  for (const u of unknown) for (let j = 0; j < n; j++) if (j !== u && graph.pat.get(ids[j]).length > 0) { setBit(marks[u], j); setBit(marks[j], u); }
  let conflicts = 0;
  for (let i = 0; i < n; i++) {
    for (let j = i + 1; j < n; j++) {
      if (bit(marks[i], j) && !bit(anc[i], j) && !bit(anc[j], i)) conflicts++;
    }
  }
  return { n, edges, width, depth, coupling, conflicts, conflicts_truncated: truncated };
}

/** 着手してよい節と、着手できない節の理由 */
export function ready(graph) {
  const ok = [];
  const notReady = [];
  for (const id of graph.ids) {
    const nd = graph.byId.get(id);
    const reasons = [];
    if (nd.status !== 'ready') reasons.push(nd.status === 'blocked' ? 'blocked' : `status_${nd.status}`);
    if (!nd.approved) reasons.push('unapproved');
    for (const d of nd.depends_on) {
      const s = graph.byId.get(d).status;
      if (s === 'merged') continue;
      reasons.push(s === 'blocked' || s === 'held' ? `blocked_dependency:${d}` : `waiting_dependency:${d}`);
    }
    if (reasons.length) notReady.push({ id, reasons });
    else ok.push(id);
  }
  return { ready: ok, not_ready: notReady };
}

/** 占有（範囲）・枠（同時の数）とみなす状態の集合。配列でなければ既定（in_progress だけ。従来の挙動）。知らない状態名は無視する */
function statusSet(v) {
  return new Set(Array.isArray(v) ? v.filter((x) => STATUSES.includes(x)) : ['in_progress']);
}

function normWorkers(limits) {
  const w = limits && limits.workers;
  if (Number.isInteger(w) && w >= 0) return { workers: w, note: null };
  return { workers: 1, note: 'limits.workers が不正または未指定のため 1（逐次。SPEC §9 の既定）とみなした' };
}

/** 今すぐ同時に動かしてよい節の組。resources が重なる節は同じ組に入れない（id の小さい方を優先。決定論的） */
export function schedule(graph, limits, opts = {}) {
  const { workers, note } = normWorkers(limits);
  const occ = statusSet(opts.occupy);
  const slotSt = statusSet(opts.slotStatuses);
  const running = graph.ids.filter((id) => occ.has(graph.byId.get(id).status));
  const slots = Math.max(0, workers - graph.ids.filter((id) => slotSt.has(graph.byId.get(id).status)).length);
  const reasons = {};
  if (note) reasons._limits = note;
  const chosen = [];
  for (const id of ready(graph).ready) {
    const clash = [...running, ...chosen].find((o) => nodesOverlap(graph, id, o));
    if (clash) { reasons[id] = `resource_conflict:${clash}`; continue; }
    if (chosen.length >= slots) { reasons[id] = 'worker_limit'; continue; }
    chosen.push(id);
  }
  return { batches: chosen.length ? [chosen] : [], reasons, slots };
}

export const THRESHOLDS = Object.freeze({
  source: 'AdaptOrch (arXiv 2602.16873) の既定値',
  theta_omega: 0.5,
  theta_gamma: 0.6,
  theta_delta: 5,
  calibrated_for_vgdd: false,
  note: 'この閾値は VGDD の仕事で校正していない。参考の表示で、勧めの決定には使っていない',
});

/** 編成の勧め（助言）。既定は single。limits.workers を超える値は返さない */
export function recommend(graph, limits, opt = {}) {
  const { workers: cap, note } = normWorkers(limits);
  const m = metrics(graph);
  const reasons = [];
  if (note) reasons.push(note);
  reasons.push('既定は single（作業員1・逐次）。逐次の依存が強い仕事で複数エージェントは単一より悪く、検証のない独立並列は誤りを最も増幅した（arXiv 2512.08296 v3。VGDD 自身での測定ではない）');
  reasons.push(`${THRESHOLDS.note}（AdaptOrch の既定 θω=${THRESHOLDS.theta_omega}, θγ=${THRESHOLDS.theta_gamma}, θδ=${THRESHOLDS.theta_delta}）`);
  const out = (topology, workers) => ({ topology, workers: Math.min(workers, cap), reasons, thresholds: THRESHOLDS, metrics: m });

  const sched = schedule(graph, { workers: cap }, { occupy: opt.occupy, slotStatuses: opt.slotStatuses });
  const batch = sched.batches[0] || [];
  const unmerged = graph.ids.filter((id) => graph.byId.get(id).status !== 'merged');
  const highReady = batch.filter((id) => graph.byId.get(id).risk === 'high');
  const highAny = unmerged.filter((id) => graph.byId.get(id).risk === 'high');

  if (cap < 2) {
    reasons.push(`limits.workers=${cap} のため並列にしない`);
    return out('single', 1);
  }
  if (m.depth >= 2 && m.width >= 2 && highAny.length === 0 && opt.allowStaged !== false) {
    reasons.push(`depth=${m.depth}・width=${m.width} のため staged（段ごとに逐次と並列を切り替える。各段の同時の数は schedule が決める）`);
    return out('staged', Math.max(1, Math.min(m.width, batch.length || 1)));
  }
  if (batch.length >= 2 && highReady.length === 0) {
    reasons.push(`着手できて resources が重ならない節が ${batch.length} 個（${batch.join(', ')}）で、高リスクを含まないため parallel`);
    return out('parallel', batch.length);
  }
  if (batch.length >= 2) reasons.push(`高リスクの節（${highReady.join(', ')}）を含むため並列にしない`);
  else if (highAny.length && m.depth >= 2 && m.width >= 2) reasons.push(`高リスクの節（${highAny.join(', ')}）があるため staged にしない`);
  else reasons.push('今すぐ並列に動かせる節が 2 つ未満のため single');
  return out('single', 1);
}

// ---- ガード ------------------------------------------------------------------
// ctx = { nodes, batch（着手の組: id の配列）, limits, occupy?, slotStatuses? }。「この着手の組は許されるか」
//   occupy: 範囲の重なりを見る相手の状態（既定 in_progress だけ）。slotStatuses: 同時の数に数える状態（既定 in_progress だけ）。runstate が review・held を足して使う
// 生の nodes を受けるので、形が壊れていても各ガードは落ちない（形は TG-NODE-SHAPE が止める）

const goodNodes = (nodes) => (Array.isArray(nodes) ? nodes.filter((n) => n && typeof n === 'object' && typeof n.id === 'string') : []);
const byIdOf = (nodes) => new Map(goodNodes(nodes).map((n) => [n.id, n]));
const batchOf = (ctx) => (Array.isArray(ctx.batch) ? ctx.batch : []);
const depsOf = (n) => (Array.isArray(n.depends_on) ? n.depends_on : null);

export const GUARDS = {
  'TG-NODE-SHAPE': (ctx) => {
    const e = shapeIssues(ctx.nodes);
    return e.length ? `節の形が正しくない: ${e.slice(0, 3).join(' / ')}${e.length > 3 ? ` ほか ${e.length - 3} 件` : ''}` : null;
  },
  'TG-SIZE-LIMIT': (ctx) =>
    Array.isArray(ctx.nodes) && ctx.nodes.length > MAX_NODES ? `節の数が上限 ${MAX_NODES} を超える（${ctx.nodes.length}）` : null,
  'TG-ACYCLIC': (ctx) => {
    if (Array.isArray(ctx.nodes) && ctx.nodes.length > MAX_NODES) return null; // 大きさは TG-SIZE-LIMIT が止める
    const c = cycleMembers(ctx.nodes);
    return c.length ? `依存が循環している（自己依存を含む）: ${c.join(', ')}` : null;
  },
  'TG-DEP-EXISTS': (ctx) => {
    const m = byIdOf(ctx.nodes);
    const bad = [];
    for (const n of m.values()) {
      const d = depsOf(n);
      if (!d) { bad.push(`${n.id}(depends_on が配列でない)`); continue; }
      for (const x of d) if (!m.has(x)) bad.push(`${n.id}→${String(x)}`);
    }
    return bad.length ? `存在しない依存（または読めない依存）: ${bad.slice(0, 5).join(', ')}` : null;
  },
  'TG-ID-UNIQUE': (ctx) => {
    if (!Array.isArray(ctx.nodes)) return 'nodes が配列でない';
    const seen = new Set();
    const dup = new Set();
    for (const n of ctx.nodes) { const id = n && n.id; if (seen.has(id)) dup.add(id); seen.add(id); }
    return dup.size ? `id が重複している: ${[...dup].map(String).join(', ')}` : null;
  },
  'TG-BATCH-IN-GRAPH': (ctx) => {
    const m = byIdOf(ctx.nodes);
    const b = batchOf(ctx);
    if (!Array.isArray(ctx.batch)) return '組が配列でない';
    const unknown = b.filter((id) => !m.has(id));
    const dup = b.filter((id, i) => b.indexOf(id) !== i);
    if (unknown.length) return `組にグラフにない節がある: ${unknown.map(String).join(', ')}`;
    if (dup.length) return `組に同じ節が重複している: ${dup.join(', ')}`;
    return null;
  },
  'TG-READY-STATUS': (ctx) => {
    const m = byIdOf(ctx.nodes);
    const bad = batchOf(ctx).filter((id) => m.has(id) && m.get(id).status !== 'ready');
    return bad.length ? `status が ready でない節を着手の組に入れた: ${bad.map((id) => `${id}(${String(m.get(id).status)})`).join(', ')}` : null;
  },
  'TG-APPROVED': (ctx) => {
    const m = byIdOf(ctx.nodes);
    const bad = batchOf(ctx).filter((id) => m.has(id) && m.get(id).approved !== true);
    return bad.length ? `未承認の節を着手の組に入れた: ${bad.join(', ')}` : null;
  },
  'TG-DEPS-MERGED': (ctx) => {
    const m = byIdOf(ctx.nodes);
    const bad = [];
    for (const id of batchOf(ctx)) {
      const n = m.get(id);
      if (!n) continue;
      const d = depsOf(n);
      if (!d) { bad.push(`${id}(depends_on が配列でない)`); continue; }
      for (const x of d) if (!m.has(x) || m.get(x).status !== 'merged') bad.push(`${id}→${String(x)}`);
    }
    return bad.length ? `依存が未統合の節を着手の組に入れた: ${bad.join(', ')}` : null;
  },
  'TG-RESOURCE-DISJOINT': (ctx) => {
    // 鍵を並べ替えて前置の関係だけを見る（metrics と同じ方式）。作業量の上限を超えたら違反（大きすぎて確かめられない。fail-closed）。
    // TG-WORKER-LIMIT の結果には依らない
    const m = byIdOf(ctx.nodes);
    const b = [...new Set(batchOf(ctx))].filter((id) => m.has(id));
    const inBatch = new Set(b);
    const occ = statusSet(ctx.occupy);
    const running = [...m.values()].filter((n) => occ.has(n.status) && !inBatch.has(n.id)).map((n) => n.id);
    const L = [...b.map((id) => ({ id, t: 'b' })), ...running.map((id) => ({ id, t: 'r' }))];
    L.forEach((x) => {
      const r = m.get(x.id).resources;
      x.parsed = Array.isArray(r) && r.length <= MAX_RES ? r.map(parsePattern) : null;
      x.unknown = x.parsed === null || x.parsed.some((q) => q === null);
      x.nonempty = x.parsed === null || x.parsed.length > 0;
    });
    const bad = new Set();
    const pair = (x, y) => { if (x.t === 'b' || y.t === 'b') bad.add(x.id < y.id ? `${x.id}×${y.id}` : `${y.id}×${x.id}`); };
    for (const u of L) if (u.unknown) for (const v of L) if (v !== u && v.nonempty) pair(u, v);
    const entries = [];
    L.forEach((x, i) => { if (!x.unknown) for (const q of x.parsed) entries.push({ k: lowKey(q), lit: q.type === 'literal', i }); });
    entries.sort((p, q) => (p.k < q.k ? -1 : p.k > q.k ? 1 : 0));
    let budget = CONFLICT_BUDGET;
    for (let a = 0; a < entries.length && bad.size < 5; a++) {
      for (let c = a + 1; c < entries.length && entries[c].k.startsWith(entries[a].k); c++) {
        if (--budget < 0) return '重なりの検査が大きすぎて確かめられない（作業量の上限を超えた。拒否する）';
        if (entries[a].i === entries[c].i) continue;
        if (entries[a].lit && entries[c].lit && entries[a].k !== entries[c].k) continue;
        pair(L[entries[a].i], L[entries[c].i]);
        if (bad.size >= 5) break;
      }
    }
    return bad.size ? `resources が重なる節を同時に動かそうとした: ${[...bad].slice(0, 5).join(', ')}` : null;
  },
  'TG-WORKER-LIMIT': (ctx) => {
    const w = ctx.limits && ctx.limits.workers;
    if (!Number.isInteger(w) || w < 0) return 'limits.workers が不正（拒否する）';
    const m = byIdOf(ctx.nodes);
    const inBatch = new Set(batchOf(ctx));
    const slotSt = statusSet(ctx.slotStatuses);
    const running = [...m.values()].filter((n) => slotSt.has(n.status) && !inBatch.has(n.id)).length;
    const total = batchOf(ctx).length + running;
    return total > w ? `同時の数が上限を超える: ${total} > ${w}（作業中 ${running} を含む）` : null;
  },
};

/** 既定は全ガード。guardNames はアブレーション実験（bench）だけが絞る。ガードが例外を投げたら違反（fail-closed） */
export function check(ctx, guardNames = Object.keys(GUARDS)) {
  const violations = [];
  for (const g of guardNames) {
    if (!GUARDS[g]) throw new Error(`未知のガード: ${g}`);
    let r;
    try { r = GUARDS[g](ctx || {}); } catch (e) { r = `検査が例外を投げた（拒否する）: ${String(e && e.message).slice(0, 80)}`; }
    if (r) violations.push({ guard: g, reason: r });
  }
  return { ok: violations.length === 0, violations };
}
