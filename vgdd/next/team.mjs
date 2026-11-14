// 編成案の検証（起草段階の試作。法律ではない）
//
// 狙い: チーフ AI や PM エージェントがタスクに応じて編成（どの役割のエージェントを何体、どの範囲で動かすか）を
// **提案**できるようにしつつ、三権分立と Kernel の強制を保つ。
// 答え: 編成は実行の前に機械が検査するデータであり、承認済みの役割の型（template）が上限。型の中でだけ自由で、
// 編成によって新しい権限は生まれない。
//
// この関数は効力を与えない。AI が提案した編成は、検査に通っても requires_approval: true で、
// 効力は Kernel の起動の窓口と人の承認による。
//
// 保証しないこと:
//   - 起動の窓口がこの検査を呼ぶ配線は、この試作にはない（呼ばなければ何も強制されない）
//   - 役割→branch・既定の系統の表は lib/vocab.mjs の ROLE_TABLE（capabilities.json の roles と checkAgainstCapabilities で照合できる）。
//     tools の上限の表は vgdd/agents から手で転記した仮の表で、実体との一致は検査していない
//   - limits.concurrent_work は「同時に動かす作業員（worker・tester）の数」で、runstate の config.concurrent_work と同じ意味。
//     行政の長（executive_head）は数えず、1 体まで（TM-WORKER-LIMIT）。旧名の limits.workers（行政の総数）は受けない
//   - lineage（モデルの系統）は plan の自己申告。実際に起動したモデルの観測はない
//   - グロブの包含は、文字どおりの一致と末尾 `/**`・`*` の単純な形だけ。それ以外は違反（fail-closed）
//   - 提案者が人であることを plan の中身からは確かめない。requires_approval は常に true で、false になるのは
//     呼び出し側が認証した行為者を context.proposer（kind: 'human'・role: 'owner'）で渡したときだけ（認証はこの関数の外）
//
// 方針（審査 B-F3・B-F4・B-F13 の判例）: plan の自己申告は信用しない。系統は catalog が知っていれば catalog の値を使う。
//   context の値は型を検査し、不正なら違反（fail-closed）。値が undefined のとき既定値で補う（スプレッドで上書きしない）

import { covers, recommend } from './taskgraph.mjs';
import { ROLE_TABLE, BRANCHES as VOCAB_BRANCHES, normLineage as vocabNormLineage, isOwner } from './lib/vocab.mjs';

export const MAX_RES = 64; // member の scope の要素数の上限（検査の作業量の上限）

const BRANCHES = VOCAB_BRANCHES;
// 役割名→branch・系統は vocab の表（ROLE_TABLE）。表にない役割は使えない型
const ROLE_BRANCH = Object.fromEntries(Object.entries(ROLE_TABLE).map(([k, v]) => [k, v.branch]));
// 委任してよい型（SPEC §5 の起動の窓口：行政の長だけが作業員の起動を申請できる）
const ROLE_MAY_DELEGATE = { executive_head: true };
// 型の系統（vocab の既定の系統。AI の型だけ。人・スクリプトの型は編成に入らない）
const ROLE_LINEAGE = Object.fromEntries(Object.entries(ROLE_TABLE).filter(([, v]) => v.kind === 'ai').map(([k, v]) => [k, v.lineage]));
// tools の上限（vgdd/agents の disallowedTools: Agent, WebFetch, WebSearch, NotebookEdit を除いたもの。司法はツールなし）
const WORK_TOOLS = ['Read', 'Edit', 'Write', 'Bash', 'Glob', 'Grep'];
const ROLE_TOOLS = { executive_head: [...WORK_TOOLS, 'Agent'], worker: WORK_TOOLS, tester: WORK_TOOLS, judge: [], codex_judge: [], constitutional_review: [] };
// 所有者の権限・sandbox の外で動く Kernel の処理（vocab の kind: script の役割）。AI の編成に入れられない
const OWNER_AUTHORITY = new Set(Object.entries(ROLE_TABLE).filter(([, v]) => v.kind === 'script').map(([k]) => k));

/** capabilities.json の roles から承認済みの型を作る。表にない役割は branch: null・usable: false（fail-closed） */
export function catalogFromCapabilities(caps) {
  const roles = (caps && caps.roles) || {};
  const catalog = {};
  for (const [id, r] of Object.entries(roles)) {
    const branch = Object.hasOwn(ROLE_BRANCH, id) ? ROLE_BRANCH[id] : null;
    catalog[id] = {
      id,
      kind: r.kind,
      branch,
      usable: branch !== null,
      lineage: Object.hasOwn(ROLE_LINEAGE, id) ? ROLE_LINEAGE[id] : undefined,
      may_delegate: Object.hasOwn(ROLE_MAY_DELEGATE, id) && ROLE_MAY_DELEGATE[id] === true,
      owner_authority: OWNER_AUTHORITY.has(id),
      scope_ceiling: { tools: Object.hasOwn(ROLE_TOOLS, id) ? ROLE_TOOLS[id] : [] }, // resources の上限は票の範囲が決める
    };
  }
  return catalog;
}

const asList = (x) => (Array.isArray(x) ? x : []);
const tpl = (ctx, m) => {
  const c = ctx.context && ctx.context.catalog;
  return c && typeof c === 'object' && m && typeof m.template === 'string' && Object.hasOwn(c, m.template) ? c[m.template] : null;
};
const members = (ctx) => (ctx.plan && Array.isArray(ctx.plan.members) ? ctx.plan.members.filter((m) => m && typeof m === 'object') : []);
const memberById = (ctx) => {
  const map = new Map();
  for (const m of members(ctx)) if (typeof m.id === 'string' && !map.has(m.id)) map.set(m.id, m);
  return map;
};
const branchOf = (ctx, m) => { const t = tpl(ctx, m); return t && t.usable !== false ? t.branch : null; };

/** 系統名の正規形（lib/vocab.mjs の normLineage。知っている系統だけ。ハイフン・別名は null） */
export const normLineage = vocabNormLineage;
/** 実効の系統。catalog の型が系統を持てばその値（plan の申告で上書きできない）。持たなければ plan の申告 */
const lineageOf = (ctx, m) => {
  const t = tpl(ctx, m);
  if (t && t.lineage !== undefined) return normLineage(t.lineage);
  return m.lineage === undefined ? null : normLineage(m.lineage);
};

const DEFAULTS = { depth: 2, members_total: 16, judicial_min: 1 };
const limitsOf = (ctx) => (ctx.context && ctx.context.limits && typeof ctx.context.limits === 'object' ? ctx.context.limits : {});
const intIn = (v, lo, hi) => Number.isInteger(v) && v >= lo && v <= hi;
const maxDepth = (ctx) => (intIn(limitsOf(ctx).depth, 0, 8) ? limitsOf(ctx).depth : DEFAULTS.depth);
const maxMembers = (ctx) => (intIn(limitsOf(ctx).members_total, 1, 64) ? limitsOf(ctx).members_total : DEFAULTS.members_total);
/** 司法の必要数と系統の要否。不正な値は既定（厳しい側）で読み、TM-CONTEXT-SHAPE が違反にする */
const reqOf = (ctx) => {
  const r = ctx.context && ctx.context.required && typeof ctx.context.required === 'object' ? ctx.context.required : {};
  return {
    judicial_min: intIn(r.judicial_min, 1, 16) ? r.judicial_min : DEFAULTS.judicial_min,
    judicial_distinct_lineage: r.judicial_distinct_lineage === false ? false : true,
  };
};

/** 資源の部分集合。1つでも判定できなければ false（fail-closed） */
function resourcesSubset(inner, outer) {
  return asList(inner).every((r) => asList(outer).some((o) => covers(o, r) === true));
}
const toolsSubset = (inner, outer) => asList(inner).every((t) => asList(outer).includes(t));

/** 委任の深さ（根は 0）。number | 'cycle' | 'orphan'（親が plan にない）。反復で、各 member を 1 回ずつ（線形） */
function parentInfo(ctx) {
  const by = memberById(ctx);
  const res = new Map();
  for (const m0 of members(ctx)) {
    if (typeof m0.id !== 'string' || res.has(m0.id)) continue;
    const path = [];
    let cur = m0;
    let v = null;
    let mark = null;
    for (;;) {
      if (res.has(cur.id)) {
        const r = res.get(cur.id);
        if (r === 'visiting') mark = 'cycle';
        else if (typeof r === 'number') v = r;
        else mark = r;
        break;
      }
      res.set(cur.id, 'visiting');
      path.push(cur);
      if (cur.parent === undefined || cur.parent === null) { v = -1; break; }
      const p = typeof cur.parent === 'string' ? by.get(cur.parent) : undefined;
      if (!p) { mark = 'orphan'; break; }
      cur = p;
    }
    for (let k = path.length - 1; k >= 0; k--) {
      if (mark) res.set(path[k].id, mark);
      else { v++; res.set(path[k].id, v); }
    }
  }
  return res;
}

// 各 finder は [{ reason, member? }] を返す
const FINDERS = {
  'TM-CONTEXT-SHAPE': (ctx) => {
    const c = ctx.context;
    if (!c || typeof c !== 'object') return [{ reason: 'context がオブジェクトでない' }];
    const o = [];
    if (!c.catalog || typeof c.catalog !== 'object' || Array.isArray(c.catalog)) o.push({ reason: 'context.catalog がオブジェクトでない' });
    if (!c.ticket || typeof c.ticket !== 'object' || !Array.isArray(c.ticket.resources) || c.ticket.resources.some((r) => typeof r !== 'string')) o.push({ reason: 'context.ticket.resources が文字列の配列でない' });
    const l = c.limits;
    if (!l || typeof l !== 'object') o.push({ reason: 'context.limits がオブジェクトでない' });
    else {
      for (const k of Object.keys(l)) if (!['concurrent_work', 'depth', 'members_total'].includes(k)) o.push({ reason: `limits に知らない欄: ${k.slice(0, 40)}${k === 'workers' ? '（旧名。同時の作業員の数は concurrent_work）' : ''}` });
      if (!intIn(l.concurrent_work, 0, 1000)) o.push({ reason: `limits.concurrent_work が 0〜1000 の整数でない: ${String(l.concurrent_work)}` });
      if (l.depth !== undefined && !intIn(l.depth, 0, 8)) o.push({ reason: `limits.depth が 0〜8 の整数でない: ${String(l.depth)}` });
      if (l.members_total !== undefined && !intIn(l.members_total, 1, 64)) o.push({ reason: `limits.members_total が 1〜64 の整数でない: ${String(l.members_total)}` });
    }
    const r = c.required;
    if (r !== undefined) {
      if (!r || typeof r !== 'object') o.push({ reason: 'context.required がオブジェクトでない' });
      else {
        if (r.judicial_min !== undefined && !intIn(r.judicial_min, 1, 16)) o.push({ reason: `required.judicial_min が 1〜16 の整数でない: ${String(r.judicial_min)}（司法ゼロにはできない）` });
        if (r.judicial_distinct_lineage !== undefined && typeof r.judicial_distinct_lineage !== 'boolean') o.push({ reason: `required.judicial_distinct_lineage が真偽値でない: ${String(r.judicial_distinct_lineage)}` });
      }
    }
    return o;
  },
  'TM-PLAN-SHAPE': (ctx) => {
    const p = ctx.plan;
    const out = [];
    if (!p || typeof p !== 'object' || !Array.isArray(p.members)) return [{ reason: 'plan.members が配列でない' }];
    if (typeof p.task !== 'string' || !p.task) out.push({ reason: 'plan.task がない' });
    if (!p.proposed_by) out.push({ reason: 'plan.proposed_by がない' });
    for (const m of p.members) {
      if (!m || typeof m !== 'object' || typeof m.id !== 'string' || !m.id || m.id.length > 128) { out.push({ reason: 'id のない（または長すぎる）member がある' }); continue; }
      if (typeof m.template !== 'string') out.push({ member: m.id, reason: 'template が文字列でない（複数の型の兼任は不可）' });
      const sc = m.scope;
      if (!sc || !Array.isArray(sc.resources) || !Array.isArray(sc.tools)) out.push({ member: m.id, reason: 'scope.resources / scope.tools が配列でない' });
      else if (sc.resources.length > MAX_RES || sc.tools.length > MAX_RES || sc.resources.some((x) => typeof x !== 'string') || sc.tools.some((x) => typeof x !== 'string')) out.push({ member: m.id, reason: `scope の要素が文字列でない、または ${MAX_RES} 個を超える` });
      if (m.parent !== undefined && m.parent !== null && typeof m.parent !== 'string') out.push({ member: m.id, reason: 'parent が文字列でない' });
    }
    return out;
  },
  'TM-MEMBER-LIMIT': (ctx) => {
    const n = members(ctx).length;
    return n > maxMembers(ctx) ? [{ reason: `member の総数が上限を超える（${n} > ${maxMembers(ctx)}。行政以外も数える）` }] : [];
  },
  'TM-LINEAGE-HONEST': (ctx) => {
    const out = [];
    for (const m of members(ctx)) {
      if (m.lineage === undefined) continue;
      const n = normLineage(m.lineage);
      if (n === null) { out.push({ member: m.id, reason: '系統の申告が知っている系統（vocab の LINEAGES）でない（別名・ハイフンは不可）' }); continue; }
      const t = tpl(ctx, m);
      if (t && t.lineage !== undefined && normLineage(t.lineage) !== n) out.push({ member: m.id, reason: `系統の申告 ${n} が型 ${m.template} の系統 ${String(t.lineage)} と違う（申告では上書きできない）` });
    }
    return out;
  },
  'TM-TEMPLATE-EXISTS': (ctx) =>
    members(ctx).filter((m) => { const t = tpl(ctx, m); return !t || t.usable === false || !BRANCHES.includes(t.branch); })
      .map((m) => ({ member: m.id, reason: `承認済みの型にない（または使えない型）: ${String(m.template)}` })),
  'TM-SCOPE-RESOURCES': (ctx) => {
    const out = [];
    const approved = ctx.context && ctx.context.ticket && ctx.context.ticket.resources;
    for (const m of members(ctx)) {
      const rs = m.scope && m.scope.resources;
      if (!Array.isArray(rs)) continue;
      if (!resourcesSubset(rs, approved)) out.push({ member: m.id, reason: `scope.resources が票の承認された範囲の外（または包含を判定できない）: ${rs.join(', ')}` });
      const t = tpl(ctx, m);
      if (t && t.scope_ceiling && Array.isArray(t.scope_ceiling.resources) && !resourcesSubset(rs, t.scope_ceiling.resources)) out.push({ member: m.id, reason: '型の resources の上限を超える' });
    }
    return out;
  },
  'TM-SCOPE-TOOLS': (ctx) => {
    const out = [];
    for (const m of members(ctx)) {
      const ts = m.scope && m.scope.tools;
      const t = tpl(ctx, m);
      if (!Array.isArray(ts) || !t) continue;
      const ceil = t.scope_ceiling && Array.isArray(t.scope_ceiling.tools) ? t.scope_ceiling.tools : [];
      if (!toolsSubset(ts, ceil)) out.push({ member: m.id, reason: `tools が型の上限を超える: ${ts.filter((x) => !ceil.includes(x)).join(', ')}` });
    }
    return out;
  },
  'TM-DELEG-SCOPE': (ctx) => {
    const by = memberById(ctx);
    const out = [];
    for (const m of members(ctx)) {
      if (m.parent === undefined || m.parent === null) continue;
      const p = by.get(m.parent);
      if (!p || !p.scope || !m.scope) continue;
      if (!resourcesSubset(m.scope.resources, p.scope.resources)) out.push({ member: m.id, reason: `子の resources が親 ${p.id} の範囲を超える（INV-03）` });
      if (!toolsSubset(m.scope.tools, p.scope.tools)) out.push({ member: m.id, reason: `子の tools が親 ${p.id} の範囲を超える（INV-03）` });
    }
    return out;
  },
  'TM-DELEG-ALLOWED': (ctx) => {
    const by = memberById(ctx);
    const out = [];
    for (const m of members(ctx)) {
      if (m.parent === undefined || m.parent === null) continue;
      const p = by.get(m.parent);
      if (!p) { out.push({ member: m.id, reason: `親 ${m.parent} が plan にない` }); continue; }
      const t = tpl(ctx, p);
      if (!t || t.may_delegate !== true) out.push({ member: m.id, reason: `親 ${p.id} の型は委任できない（may_delegate でない）` });
    }
    return out;
  },
  'TM-DELEG-DEPTH': (ctx) => {
    const max = maxDepth(ctx);
    const info = parentInfo(ctx);
    return members(ctx).filter((m) => typeof info.get(m.id) === 'number' && info.get(m.id) > max)
      .map((m) => ({ member: m.id, reason: `委任の深さが上限 ${max} を超える（${info.get(m.id)}）` }));
  },
  'TM-DELEG-CYCLE': (ctx) => {
    const info = parentInfo(ctx);
    return members(ctx).filter((m) => info.get(m.id) === 'cycle').map((m) => ({ member: m.id, reason: '委任が循環している（または循環の下にある）' }));
  },
  'TM-JUDICIAL-INDEPENDENT': (ctx) => {
    const by = memberById(ctx);
    const out = [];
    for (const m of members(ctx)) {
      if (branchOf(ctx, m) === 'judicial' && m.parent !== undefined && m.parent !== null) out.push({ member: m.id, reason: '司法の member は委任されない（parent は null）。司法は裁判所の側が起こす' });
      const p = m.parent != null ? by.get(m.parent) : null;
      if (p && branchOf(ctx, p) === 'judicial') out.push({ member: m.id, reason: `司法 ${p.id} は委任できない` });
    }
    return out;
  },
  'TM-NO-DUAL-ROLE': (ctx) => {
    const groups = new Map();
    for (const m of members(ctx)) { if (typeof m.id !== 'string') continue; (groups.get(m.id) || groups.set(m.id, []).get(m.id)).push(m); }
    const out = [];
    for (const [id, ms] of groups) {
      if (ms.length < 2) continue;
      const bs = new Set(ms.map((m) => branchOf(ctx, m) || `?${m.template}`));
      out.push({ member: id, reason: bs.size > 1 ? `同じ id が複数の権力に現れる: ${[...bs].join(', ')}` : '同じ id の member が重複している' });
    }
    return out;
  },
  'TM-JUDICIARY-PRESENT': (ctx) => {
    const need = reqOf(ctx).judicial_min;
    const n = members(ctx).filter((m) => branchOf(ctx, m) === 'judicial').length;
    return n < need ? [{ reason: `司法の member が足りない（${n} < ${need}）` }] : [];
  },
  'TM-JUDICIARY-LINEAGE': (ctx) => {
    if (reqOf(ctx).judicial_distinct_lineage !== true) return [];
    const js = members(ctx).filter((m) => branchOf(ctx, m) === 'judicial');
    if (js.length === 0) return []; // 不在は TM-JUDICIARY-PRESENT が見る
    const ex = members(ctx).filter((m) => branchOf(ctx, m) === 'executive');
    if (ex.some((m) => !lineageOf(ctx, m))) return [{ reason: '行政の member に系統の申告がなく、司法との違いを確かめられない（fail-closed）' }];
    const exL = new Set(ex.map((m) => lineageOf(ctx, m)));
    const ok = js.some((m) => { const l = lineageOf(ctx, m); return l && !exL.has(l); });
    return ok ? [] : [{ reason: '行政のどの member とも系統の違う司法の member がない（同系統の共謀・同じ見落としへの備え）' }];
  },
  'TM-HUMAN-SEAT': (ctx) =>
    members(ctx).filter((m) => {
      const t = tpl(ctx, m);
      return t && (t.kind === 'human' || t.branch === 'sovereign' || t.branch === 'legislative' || t.owner_authority === true);
    }).map((m) => ({ member: m.id, reason: `AI の編成に入れられない席（人・主権者・立法・オーナーの権限の処理）: ${m.template}` })),
  // 作業員（worker・tester）の数は limits.concurrent_work まで（runstate の同時の作業の数と同じ意味）。行政の長は数えず、1 体まで。
  // ほかの行政の型（表にあって使える行政の型）は作業に数える（厳しい側）
  'TM-WORKER-LIMIT': (ctx) => {
    const w = limitsOf(ctx).concurrent_work;
    if (!Number.isInteger(w) || w < 0) return [{ reason: 'limits.concurrent_work が不正（拒否する）' }];
    const ex = members(ctx).filter((m) => branchOf(ctx, m) === 'executive');
    const heads = ex.filter((m) => m.template === 'executive_head').length;
    const n = ex.length - heads;
    const out = [];
    if (heads > 1) out.push({ reason: `行政の長（executive_head）は 1 体まで（${heads} 体）` });
    if (n > w) out.push({ reason: `作業員（worker・tester）の数が同時の作業の上限を超える（${n} > ${w}）` });
    return out;
  },
  'TM-LIMITS-NO-RAISE': (ctx) => {
    const req = ctx.plan && ctx.plan.limits_requested;
    if (req === undefined || req === null) return [];
    if (typeof req !== 'object') return [{ reason: 'limits_requested の形が不正' }];
    const lim = limitsOf(ctx);
    const out = [];
    for (const [k, v] of Object.entries(req)) {
      if (!(k in lim) || typeof v !== 'number' || typeof lim[k] !== 'number' || v > lim[k]) out.push({ reason: `編成案が上限を広げようとしている: ${k}=${String(v)}（上限 ${String(lim[k])}）` });
    }
    return out;
  },
};

export const GUARDS = Object.fromEntries(
  Object.entries(FINDERS).map(([name, f]) => [name, (ctx) => { const r = f(ctx); return r.length ? r.map((x) => (x.member ? `${x.member}: ${x.reason}` : x.reason)).join(' / ') : null; }]),
);

/** ctx = { plan, context }。既定は全ガード。guardNames は bench だけが絞る。検査が例外を投げたら違反（fail-closed） */
export function check(ctx, guardNames = Object.keys(GUARDS)) {
  const violations = [];
  for (const g of guardNames) {
    if (!FINDERS[g]) throw new Error(`未知のガード: ${g}`);
    let found;
    try { found = FINDERS[g](ctx || {}); } catch (e) { found = [{ reason: `検査が例外を投げた（拒否する）: ${String(e && e.message).slice(0, 80)}` }]; }
    for (const x of found) violations.push({ guard: g, reason: x.reason, ...(x.member ? { member: x.member } : {}) });
  }
  return { ok: violations.length === 0, violations };
}

/**
 * 編成案を検査する。効力は与えない（requires_approval・effect: 'none'）。
 * requires_approval は常に true。false になるのは、呼び出し側が認証した行為者を context.proposer として
 * { kind: 'human', role: 'owner' } で渡したときだけ（plan の proposed_by の自己申告では決めない）。
 * context.graph（taskgraph.buildGraph の graph）があれば、single を勧める票で行政が 2 体以上のとき warnings に出す。
 */
export function validateTeam(plan, context) {
  const { ok, violations } = check({ plan, context });
  const warnings = [];
  const pr = context && context.proposer;
  const requires_approval = !isOwner(pr);
  try {
    const ctx = { plan, context };
    const exec = members(ctx).filter((m) => branchOf(ctx, m) === 'executive').length;
    if (exec >= 2) {
      if (context && context.graph) {
        const rec = recommend(context.graph, { workers: limitsOf(ctx).concurrent_work }); // taskgraph の workers は同時の作業の数
        if (rec.topology === 'single') warnings.push({ guard: 'TM-UNNEEDED-AGENTS', reason: `行政の member が ${exec} 体だが、taskgraph.recommend は single を勧めている（${rec.reasons[rec.reasons.length - 1]}）。人が見て決める` });
      } else warnings.push({ guard: 'TM-UNNEEDED-AGENTS', reason: `行政の member が ${exec} 体。context.graph がないため、並列が要るかを確かめていない` });
    }
  } catch (e) {
    warnings.push({ guard: 'TM-UNNEEDED-AGENTS', reason: '不要な並列の確認で例外が出た（確かめていない）' });
  }
  return { ok, violations, warnings, requires_approval, effect: 'none' };
}
