// 仕事のグラフの実行の状態の記録（runstate）（起草段階の試作。法律ではない）
//
// 今の Kernel では、仕事の状態の移り変わり（着手・申請・差し戻し・承認待ち・夜間の合格・統合・停止）が、bash のスクリプト
// （gate-runner・night-runner・release）と票ファイルの書き換えに埋め込まれ、開発（Git の票）に固有の形になっている。
// これを「領域に依らない状態機械」として取り出し、追記専用の鎖つき記録（lib/chain.mjs）から状態を作り直せる形にする。
// 途中で落ちても、記録を開き直せば同じ状態が作り直せ、続きができる。
//
// Kernel は判断しない：この部品は、誰のどの出来事なら状態を移してよいかを機械的に検査するだけで、合否は司法の判定
// （外から来る出来事 verdict）が決める。verdict の結果の決め方（decide）は SPEC §6・§7 の機械的な写しで、LLM を使わない。
//
// 記録の1行 = { type, rules, op, event_id, actor, ...出来事の項目, seq, at, prev, hash }
//   - 規則の数値・同時の数・法律の系統・必須の審査の一覧は、記録の中の出来事 config（オーナーだけ）で決まる。開く側の申告では決まらない。
//     記録の最初の出来事は config で、config のない記録は config 以外のすべての出来事を拒む。緩める変更は作業中の節がないときだけ
//   - event_id は冪等の鍵（役割と op の組ごと）。同じ内容の二度目は効かず（duplicate）、違う内容で同じ組を使うのは拒む
//   - 時刻は記録の at（chain の now）だけを使い、出来事の項目に時刻は持てない。「記録の上の今」は、それまでの行の at の最大値。
//     追記の時刻が直前までの最大値より前なら、拒まず最大値をそのまま使う（進めない）。時計の戻りと並行の書き込みで行き止まりにならない
//   - 追記する側の実時間（Date.now）より 5 分以上先の時刻の行は、書く時に拒む（RS-TIME-FUTURE。停止は例外）。再生では実時間を見ない。
//     それでも記録の上の今が先に進んだ記録は、オーナーが理由つきで clock_reset（その行の実時間に戻す）で正せる
//   - 通常の openRun は now を受けない（時計は chain の nowIso）。時計を差し替える入口 unsafeOpenRunWithClock は試験専用で、
//     入口があること自体が限界（下）。配置するプロセスから呼ばない
//   - verdict の major は、裁判所のスクリプトが判定の記録の指摘の重さ（critical か major が1件でもあれば true）から機械的に決める。
//     決められない（判定の記録を読めない）ときは true にする（厳しい側）。この部品は申告された値を確かめない
//
// Kernel との対応と、領域に固有のため扱わないこと：
//   - gate-runner の差し戻しに入る needs_rebase・差分が files_allowed の外・HEAD の不一致・保護パスなどの前検査は、この部品に出来事を
//     足さない。領域に固有の前検査として、verdict の audits: 'failed' で入る
//
// 保証できないこと（限界）:
//   - 行為者（actor）は呼び出し側の申告で、本物かどうかは確かめられない。本物であることは「記録を行政が書けない保護領域に置き、
//     役割ごとに別のプロセス・権限で apply を呼ぶ」配置で強制する前提（未配線）。行政の AI が apply を直接呼べる配置では、
//     { role: 'owner', kind: 'human' } を名乗るだけで config も承認も統合もできる
//   - spec_digest・policy_line・request・監査の結果・司法の判定は外から来る値で、中身が本物かはここでは確かめない（形と一致だけ）。
//     判定が必須の審査の一覧と同じ系統の名前で来ること（lineage）も、名乗りであり、本当にその系統のモデルかは確かめない
//   - 記録のファイルと head を一緒に差し替えられる者（オーナーの権限）は、今の規則に合う行を作って足せる（鎖の限界と同じ根）。
//     config を作り直して緩めることも、その者にはできる
//   - 時計を差し替えて書ける入口 unsafeOpenRunWithClock が export されている（試験のため）。これで未来の時刻の行は RS-TIME-FUTURE が拒むが、
//     実時間との比較は呼び出し側の Date.now なので、過去の時刻を使うことは止めない（過去の時刻は「記録の上の今」を進めないので、期限の判定は動かない）。
//     記録のファイルを直接書ける者（オーナーの権限）が未来の時刻の行を足すことは止められない（clock_reset で正す）
//   - lease は期限の記録だけで、プロセスの生死は見ない（長時間の実行の延長・生存確認の出来事は未実装。lease_sec の上限は7日）
//   - 節の id は小文字だけ（^[a-z0-9][a-z0-9._-]{0,63}$）。大文字を含む票の id は呼び出し側で写す（別物として通さないため）
//   - 古い規則の版の行は、オーナーの移行の記録（epoch）に覆われるときだけ、構造の検査（形・重複・存在・遷移）だけで受け入れる
//   - 1つの出来事の処理は節の数に比例する（節 2000・依存の総数 20000 で数十ミリ秒の見込み。試験で1秒以内を確かめる）

import { openChain, digest, canonical, sha256, Refused, nowIso } from './lib/chain.mjs';
import { buildGraph, check as tgCheck, ready as tgReady, schedule, recommend, STATUSES, MAX_NODES } from './taskgraph.mjs';

export const RECORD_TYPE = 'vgdd.runstate.v1';
/** 規則の版。ガードの規則を変えるたびに上げる。各行に rules として記録する（improvement.mjs と同じ。epoch で古い行を覆う） */
export const RULES = 'rs.v1';
export const MAX_EVENTS = 20000;
/** 人（human）の出来事のために取っておく枠。人以外の出来事は、MAX_EVENTS - HUMAN_RESERVE に達したら拒む（行政が使い切ってオーナーの stop・epoch を塞がない） */
export const HUMAN_RESERVE = 2000;
export const MAX_AI_PLANS = 500; // 行政（role: executive）の plan の回数の上限（kind を名乗り変えても数える）
export const MAX_PLAN_NODES = 200; // 1回の plan で足せる節の数
export const HUMAN_NODE_RESERVE = 200; // 節の上限のうち、オーナー（human）のために取ってある数
export const TIME_FUTURE_MS = 5 * 60e3; // 追記する側の実時間より先に進めてよい幅
export const MAX_NODES_TOTAL = MAX_NODES; // 2000
export const MAX_DEPS_PER_NODE = 64;
export const MAX_DEPS_TOTAL = 20000;
export const MAX_SUPERSEDE_CHAIN = 8;
export const OPS = ['config', 'clock_reset', 'plan', 'approve', 'start', 'submit', 'verdict', 'release', 'rule', 'unblock', 'annul', 'expire', 'stop', 'resume', 'epoch'];
const NODE_OPS = new Set(['approve', 'start', 'submit', 'verdict', 'release', 'rule', 'unblock', 'annul', 'expire']);
const BUSY = new Set(['in_progress', 'review', 'held']); // 未統合の作業（範囲を占める）
const SLOT = ['in_progress', 'review']; // 作業員の枠を使う状態（held は人の承認待ちで枠を使わない）
const MAX_VERDICTS = 8;
const MAX_PLAN_SUPERSEDE = 500;

/** 設定（config の出来事の内容）の既定（SPEC §5・§6・§9 に合わせる）。範囲は CFG_BOUNDS */
export const DEFAULT_CONFIG = Object.freeze({
  hold: false, max_attempts: 4, max_returns: 3, max_unavailable: 3, workers: 1, lease_sec: 21600, policy_line: null,
  judiciary: Object.freeze([Object.freeze({ kind: 'judge', lineage: 'claude' }), Object.freeze({ kind: 'judge', lineage: 'codex' })]), security_lineage: 'codex',
});
const CFG_BOUNDS = { max_attempts: [1, 10], max_returns: [1, 3], max_unavailable: [1, 3], workers: [0, 64], lease_sec: [1, 604800] };

// ---- 役割と種類（行為者） ----
export const ROLES = ['owner', 'executive', 'night_agent', 'court', 'reaper'];
export const KINDS = ['human', 'ai', 'script'];
/** op → 起こせる役割（SPEC §5 の表・§6・§7・§8）。種類（human/ai/script）は別の表で別のガードが見る */
const ROLE_OPS = {
  config: ['owner'], clock_reset: ['owner'], plan: ['executive', 'owner'], approve: ['owner'], start: ['executive', 'night_agent'], submit: ['executive', 'night_agent'],
  verdict: ['court'], release: ['owner'], rule: ['owner'], unblock: ['owner'], annul: ['owner'],
  expire: ['court', 'night_agent', 'reaper'], stop: ['owner'], resume: ['owner'], epoch: ['owner'],
};
const KIND_OPS = {
  config: ['human'], clock_reset: ['human'], plan: ['ai', 'human'], approve: ['human'], start: ['ai', 'human', 'script'], submit: ['ai', 'human', 'script'],
  verdict: ['script'], release: ['human'], rule: ['human'], unblock: ['human'], annul: ['human'],
  expire: ['script'], stop: ['human'], resume: ['human'], epoch: ['human'],
};

// ---- 文字列の正規化と許可リスト（NFKC・前後の空白を落としてから、決まった形だけを受ける） ----
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const nf = (s) => (typeof s === 'string' ? s.normalize('NFKC').trim() : null);
const NODE_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const NAME_RE = /^[a-z][a-z0-9_.-]{0,39}$/;
const ROLE_RE = /^[a-z][a-z0-9_]{0,39}$/;
const LINEAGE_RE = /^[a-z][a-z0-9_]{0,39}$/; // ハイフンを許さない（openai と open-ai を別の系統にしない）
const EVENT_ID_RE = /^[a-z0-9][a-z0-9._:-]{0,127}$/;
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const REQUEST_RE = /^(sha256:[0-9a-f]{64}|[0-9a-f]{7,64})$/;
const POLICY_RE = /^p\d+\.\d+$/;
const REASON_RE = /^[^\p{Cc}\p{Cf}]+$/u;
const tok = (re) => (v) => { const s = nf(v); return s !== null && re.test(s) ? { v: s } : { e: '形が正しくない' }; };
const reasonP = (v) => { const s = nf(v); return s !== null && s.length >= 1 && s.length <= 1000 && REASON_RE.test(s) ? { v: s } : { e: '理由が空・長すぎる・制御文字を含む' }; };
const intP = (min, max) => (v) => (Number.isSafeInteger(v) && v >= min && v <= max ? { v } : { e: `${min}〜${max} の整数でない` });
const enumP = (...xs) => (v) => { const s = nf(v); return s !== null && xs.includes(s) ? { v: s } : { e: `${xs.join('/')} のどれかでない` }; };
const boolP = (v) => (v === true || v === false ? { v } : { e: '真偽値でない' });
const resP = (v) => (typeof v === 'string' && v.length >= 1 && v.length <= 512 && !/\p{C}/u.test(v) ? { v } : { e: 'resources の要素が文字列（512字以内・制御文字なし）でない' });
const hashP = (v) => (v === 'genesis' || (typeof v === 'string' && /^[0-9a-f]{64}$/.test(v)) ? { v } : { e: 'ハッシュの形でない' });
const policyOrNullP = (v) => (v === null ? { v: null } : tok(POLICY_RE)(v));
function listP(item, max, { unique = false, sortKey = null, min = 0 } = {}) {
  return (v) => {
    if (!Array.isArray(v) || v.length > max || v.length < min) return { e: `配列（${min}〜${max}個）でない` };
    const out = [];
    for (const x of v) { const r = item(x); if (r.e) return { e: r.e }; out.push(r.v); }
    if (unique) { const ks = out.map((x) => (typeof x === 'string' ? x : canonical(x))); if (new Set(ks).size !== ks.length) return { e: '重複がある' }; }
    if (sortKey) out.sort((a, b) => { const x = sortKey(a); const y = sortKey(b); return x < y ? -1 : x > y ? 1 : 0; });
    return { v: out };
  };
}
/** req の項目は必須、opt は任意。知らない項目は拒む（許可リスト。__proto__ も own キーとして拒む） */
function objP(req, opt = {}) {
  return (v) => {
    if (!isObj(v)) return { e: 'オブジェクトでない' };
    const out = {};
    for (const k of Object.keys(v)) if (!Object.hasOwn(req, k) && !Object.hasOwn(opt, k)) return { e: `知らない項目: ${k.slice(0, 40)}` };
    for (const [k, p] of Object.entries(req)) { if (!Object.hasOwn(v, k)) return { e: `${k} が要る` }; const r = p(v[k]); if (r.e) return { e: `${k}: ${r.e}` }; out[k] = r.v; }
    for (const [k, p] of Object.entries(opt)) if (Object.hasOwn(v, k) && v[k] !== undefined) { const r = p(v[k]); if (r.e) return { e: `${k}: ${r.e}` }; out[k] = r.v; }
    return { v: out };
  };
}

const nodeP = tok(NODE_RE);
const nodeDefP = objP({ id: nodeP, depends_on: listP(nodeP, MAX_DEPS_PER_NODE, { unique: true, sortKey: (x) => x }), resources: listP(resP, 64, { sortKey: (x) => x }) },
  { risk: enumP('low', 'mid', 'high'), security_review: boolP });
const judiciaryItemP = objP({ kind: enumP('judge'), lineage: tok(LINEAGE_RE) });
const verdictItemP = objP({ kind: enumP('judge', 'security'), judge: tok(NAME_RE), lineage: tok(LINEAGE_RE), verdict: enumP('APPROVED', 'CHANGES_REQUIRED', 'UNAVAILABLE'), major: boolP });
const SCHEMA = {
  config: objP({ hold: boolP, max_attempts: intP(...CFG_BOUNDS.max_attempts), max_returns: intP(...CFG_BOUNDS.max_returns), max_unavailable: intP(...CFG_BOUNDS.max_unavailable),
    workers: intP(...CFG_BOUNDS.workers), lease_sec: intP(...CFG_BOUNDS.lease_sec), policy_line: policyOrNullP,
    judiciary: listP(judiciaryItemP, 6, { unique: true, min: 1, sortKey: (x) => x.lineage }), security_lineage: tok(LINEAGE_RE) }, { reason: reasonP }),
  clock_reset: objP({}, { reason: reasonP }),
  plan: objP({ nodes: listP(nodeDefP, MAX_PLAN_NODES) }, { supersede: listP(objP({ old: nodeP, new: nodeP }), MAX_PLAN_SUPERSEDE) }),
  approve: objP({ node: nodeP, spec_digest: tok(DIGEST_RE), policy_line: tok(POLICY_RE), def_digest: tok(DIGEST_RE) }),
  start: objP({ node: nodeP, spec_digest: tok(DIGEST_RE), lease_sec: intP(1, 604800) }),
  submit: objP({ node: nodeP, request: tok(REQUEST_RE) }),
  verdict: objP({ node: nodeP, request: tok(REQUEST_RE), audits: enumP('passed', 'failed', 'not_run'),
    verdicts: listP(verdictItemP, MAX_VERDICTS, { sortKey: (x) => `${x.kind}:${x.lineage}` }) }),
  release: objP({ node: nodeP, request: tok(REQUEST_RE) }),
  rule: objP({ node: nodeP, request: tok(REQUEST_RE), decision: enumP('merge', 'return') }, { reason: reasonP }),
  unblock: objP({ node: nodeP }, { reason: reasonP, extra_returns: intP(0, 3), extra_attempts: intP(0, 5), extra_unavailable: intP(0, 3) }),
  annul: objP({ node: nodeP }, { reason: reasonP }),
  expire: objP({ node: nodeP }),
  stop: objP({}, { reason: reasonP }),
  resume: objP({}, { reason: reasonP }),
  epoch: objP({ covers: objP({ count: intP(0, MAX_EVENTS), last_hash: hashP }) }, { reason: reasonP }),
};
const REASON_REQUIRED = new Set(['clock_reset', 'stop', 'resume', 'rule', 'unblock', 'annul', 'epoch']);

/** 出来事の正規化と形の検査。{ ok, ev, errors }。ev は op・event_id と各項目（正規化済み） */
export function parseEvent(raw) {
  if (!isObj(raw)) return { ok: false, ev: null, errors: ['出来事がオブジェクトでない'] };
  const op = typeof raw.op === 'string' ? raw.op : null;
  if (op === null || !OPS.includes(op)) return { ok: false, ev: null, errors: ['op が不正（知らない出来事の種類）'] };
  const id = tok(EVENT_ID_RE)(raw.event_id);
  if (id.e) return { ok: false, ev: null, errors: ['event_id が不正（小文字・数字と . _ : - の128字以内）'] };
  const rest = Object.create(null); // __proto__ を own キーとして扱う（通常のオブジェクトだと代入が捨てられ、知らない項目が見えなくなる）
  for (const k of Object.keys(raw)) if (k !== 'op' && k !== 'event_id') rest[k] = raw[k];
  const r = SCHEMA[op](rest);
  if (r.e) return { ok: false, ev: null, errors: [`${op}: ${r.e}`] };
  if (op === 'verdict') {
    const keys = r.v.verdicts.map((x) => `${x.kind}:${x.lineage}`);
    if (new Set(keys).size !== keys.length) return { ok: false, ev: null, errors: ['verdict: 同じ審査（種類と系統）の結果が2件ある'] };
    if (new Set(r.v.verdicts.map((x) => x.judge)).size !== r.v.verdicts.length) return { ok: false, ev: null, errors: ['verdict: 同じ審査者が2回出ている（1人の判定を2つに数えない）'] };
  }
  return { ok: true, ev: { op, event_id: id.v, ...r.v }, errors: [] };
}

/** 行為者の正規化と形の検査。{ ok, actor, errors } */
export function parseActor(raw) {
  if (!isObj(raw)) return { ok: false, actor: null, errors: ['行為者がオブジェクトでない'] };
  const r = objP({ role: tok(ROLE_RE), kind: enumP(...KINDS), id: tok(NAME_RE) })(raw);
  if (r.e) return { ok: false, actor: null, errors: [`行為者: ${r.e}`] };
  if (!ROLES.includes(r.v.role)) return { ok: false, actor: null, errors: ['行為者: 知らない役割'] };
  return { ok: true, actor: { role: r.v.role, kind: r.v.kind, id: r.v.id }, errors: [] };
}

// ---- 状態 ----
export function newState() {
  return { rules: RULES, count: 0, stopped: false, stop_reason: null, config: null, last_at: 0, ai_plans: 0, dep_total: 0,
    nodes: new Map(), order: [], seen: new Map(), hashes: [], covered: 0, epochs: 0, pure: true,
    final: new Map(), sources: new Map() }; // final: 置き換えられた節 → 最後の置き換え先（一度だけ更新。鎖をたどらない）
}
const defDigest = (d) => digest({ id: d.id, depends_on: d.depends_on, resources: d.resources, risk: d.risk ?? null, security_review: d.security_review === true });
function newNode(d, gen = 0) {
  return { id: d.id, depends_on: [...d.depends_on], resources: [...d.resources], risk: d.risk ?? null, security_review: d.security_review === true, def_digest: defDigest(d), gen,
    status: 'ready', approval: null, attempts: 0, returns: 0, extra_returns: 0, extra_attempts: 0, extra_unavailable: 0, annulled: 0, unavail: {}, lease_until: null, request: null,
    blocked_reason: null, superseded_by: null, worker: null };
}
const approvedNow = (n) => !!(n && n.approval && n.approval.def_digest === n.def_digest);
const eventDigest = (actor, ev) => digest({ actor, ev });
/** event_id の一意性の鍵は (役割, op, event_id)。行政が予測した id を先に使って、オーナーの同じ id の出来事を塞げない */
const seenKey = (actor, ev) => `${actor.role}|${ev.op}|${ev.event_id}`;
const cfgOf = (ctx) => (ctx.state && ctx.state.config) || DEFAULT_CONFIG;
const returnLimit = (n, cfg) => cfg.max_returns + n.extra_returns;
const attemptLimit = (n, cfg) => cfg.max_attempts + n.extra_attempts;
const unavailLimit = (n, cfg) => cfg.max_unavailable + n.extra_unavailable;
const requiredOf = (node, cfg) => {
  const r = cfg.judiciary.map((j) => `judge:${j.lineage}`);
  if (node.security_review) r.push(`security:${cfg.security_lineage}`);
  return r;
};

/** 依存の解決：置き換えられた節への依存は、置き換え先への依存として扱う（final は一度だけ更新した写し。鎖をたどらない） */
function resolveDep(st, extra, id) {
  const f = st.final.get(id) ?? id;
  return (extra && extra.get(f)) ?? f; // この plan で置き換えられる節（extra）への解決は、最後に1回だけ足す
}
/** taskgraph に渡す節の形。approved は「今の定義に結び付いた承認があるか」 */
function tgNodes(st, { extra = null, add = [], hideApproval = null } = {}) {
  const out = [];
  const redefined = add.length ? new Set(add.map((d) => d.id)) : null;
  for (const id of st.order) {
    if (redefined && redefined.has(id)) continue;
    const n = st.nodes.get(id);
    // 未統合の申請を持つ blocked の節（オーナーの判断待ち）は、範囲を占める（枠は使わない）。taskgraph には held として渡す
    const status = n.status === 'blocked' && n.request && !n.superseded_by ? 'held' : n.status;
    const o = { id, status, depends_on: n.depends_on.map((d) => resolveDep(st, extra, d)), resources: n.resources, approved: approvedNow(n) && !(hideApproval && hideApproval.has(id)) };
    if (n.risk) o.risk = n.risk;
    out.push(o);
  }
  for (const d of add) {
    const o = { id: d.id, status: 'ready', depends_on: d.depends_on.map((x) => resolveDep(st, extra, x)), resources: d.resources, approved: false };
    if (d.risk) o.risk = d.risk;
    out.push(o);
  }
  return out;
}

// ---- verdict の結果の決め方（SPEC §6・§7 の機械的な写し。決定論的） ----
const judgesOf = (verdicts) => verdicts.filter((v) => v.kind === 'judge');
const secOf = (verdicts) => verdicts.filter((v) => v.kind === 'security');
/** 必須の審査のどれかの結果がない、または UNAVAILABLE が1つでもある（司法の欠落。SPEC §6-5。判定ではない） */
export function judiciaryInsufficient(verdicts, required) {
  const have = new Map(verdicts.map((v) => [`${v.kind}:${v.lineage}`, v.verdict]));
  return verdicts.some((v) => v.verdict === 'UNAVAILABLE') || required.some((k) => !have.has(k));
}
const hasMajorSplit = (verdicts) => {
  const j = judgesOf(verdicts);
  return j.some((v) => v.verdict === 'APPROVED') && j.some((v) => v.verdict === 'CHANGES_REQUIRED') && j.some((v) => v.major === true);
};
const hasMinorSplit = (verdicts) => {
  const j = judgesOf(verdicts);
  return j.some((v) => v.verdict === 'APPROVED') && j.some((v) => v.verdict === 'CHANGES_REQUIRED') && !j.some((v) => v.major === true);
};
const securityFailed = (verdicts) => secOf(verdicts).some((v) => v.verdict === 'CHANGES_REQUIRED');
/**
 * @param {{ node, ev, cfg, at }} i  node は今の節、ev は正規化済みの verdict の出来事
 * @returns {{ kind, to, patch }}  kind: pass | pass_minor_disagreement | return | unavailable | blocked_returns | blocked_attempts | blocked_disagreement | blocked_unavailable
 */
export function decide({ node, ev, cfg, at }) {
  // 差し戻しの上限に達した票の申請は、司法を見ずに blocked（SPEC §5。gate-runner の MAX_RETURNS の前検査）
  if (node.returns >= returnLimit(node, cfg)) return { kind: 'blocked_returns', to: 'blocked', patch: { blocked_reason: 'returns_limit', lease_until: null } };
  // 差し戻し：作業員を起動し直す（試行に数える。夜間の代行と同じ）。試行の上限に達していれば blocked
  const back = () => (node.attempts >= attemptLimit(node, cfg)
    ? { kind: 'blocked_attempts', to: 'blocked', patch: { blocked_reason: 'attempts_exhausted', lease_until: null, returns: node.returns + 1 } }
    : { kind: 'return', to: 'in_progress', patch: { returns: node.returns + 1, attempts: node.attempts + 1, lease_until: at + cfg.lease_sec * 1000, request: null, blocked_reason: null } });
  // 監査の不合格・未実行は、司法が APPROVED でも合格にしない（SPEC §6-3）。未実行は差し戻し（judge.sh と同じ）
  if (ev.audits !== 'passed') return back();
  // 必須の審査の欠落・使えない審査者が1つでもあれば「司法が使えない」。同じ申請の指紋で通算に数える（別の申請を挟んでも戻らない）
  if (judiciaryInsufficient(ev.verdicts, requiredOf(node, cfg))) {
    const n = (node.unavail[ev.request] || 0) + 1;
    const unavail = { ...node.unavail, [ev.request]: n };
    if (n >= unavailLimit(node, cfg)) return { kind: 'blocked_unavailable', to: 'blocked', patch: { unavail, blocked_reason: 'judiciary_unavailable', lease_until: null } };
    return { kind: 'unavailable', to: 'review', patch: { unavail } };
  }
  // セキュリティ審査の不合格は、不一致の扱い・オーナーの裁定より先に差し戻す（裁定で通せない）
  if (securityFailed(ev.verdicts)) return back();
  if (hasMajorSplit(ev.verdicts)) return { kind: 'blocked_disagreement', to: 'blocked', patch: { blocked_reason: 'disagreement', lease_until: null } };
  const to = cfg.hold ? 'held' : 'merged';
  const j = judgesOf(ev.verdicts);
  if (j.length && j.every((v) => v.verdict === 'APPROVED')) return { kind: 'pass', to, patch: { lease_until: null } };
  // 重大でない指摘だけで分かれた判定：法律（governance.md §3.1 の 8・gate-runner）に合わせ、指摘を記録に残して合格にする
  if (hasMinorSplit(ev.verdicts)) return { kind: 'pass_minor_disagreement', to, patch: { lease_until: null } };
  return back();
}

const views = new WeakMap();
function view(ctx) {
  let v = views.get(ctx);
  if (!v) {
    const a = parseActor(ctx.actor); const e = parseEvent(ctx.event);
    v = { actor: a.ok ? a.actor : null, ev: e.ok ? e.ev : null, actorErrors: a.errors, evErrors: e.errors };
    views.set(ctx, v);
  }
  return v;
}
const tgMemo = new WeakMap();
/** この出来事の taskgraph 用の節の一覧（出来事ごとに1回だけ作る） */
function tgBase(ctx) { let n = tgMemo.get(ctx); if (!n) { n = tgNodes(ctx.state); tgMemo.set(ctx, n); } return n; }

/** 出来事の結果（状態をどう変えるか）。出来事が読めない・節がないときは null（その場合は他のガードが拒む） */
function computeResult(ctx) {
  const v = view(ctx);
  if (!v.ev) return null;
  const { ev } = v;
  const st = ctx.state;
  const cfg = cfgOf(ctx);
  const at = Number.isFinite(ctx.at) ? ctx.at : 0;
  const node = NODE_OPS.has(ev.op) ? st.nodes.get(ev.node) : undefined;
  if (NODE_OPS.has(ev.op) && !node) return null;
  switch (ev.op) {
    case 'config': { const { op: _o, event_id: _e, reason: _r, ...c } = ev; return { op: 'config', config: c }; }
    case 'clock_reset': return { op: 'clock_reset' };
    case 'plan': return { op: 'plan', add: ev.nodes, supersede: ev.supersede || [] };
    case 'approve': return { op: 'approve', node: ev.node, to: node.status, patch: { approval: { spec_digest: ev.spec_digest, policy_line: ev.policy_line, def_digest: ev.def_digest } } };
    case 'start': return { op: 'start', node: ev.node, to: 'in_progress', patch: { attempts: node.attempts + 1, lease_until: at + ev.lease_sec * 1000, worker: v.actor ? v.actor.id : null, request: null } };
    case 'submit': return { op: 'submit', node: ev.node, to: 'review', patch: { request: ev.request } };
    case 'verdict': { const d = decide({ node, ev, cfg, at }); return { op: 'verdict', node: ev.node, kind: d.kind, to: d.to, patch: d.patch }; }
    case 'release': return { op: 'release', node: ev.node, to: 'merged', patch: { lease_until: null } };
    case 'rule': return ev.decision === 'merge'
      ? { op: 'rule', node: ev.node, to: 'merged', patch: { blocked_reason: null, lease_until: null } }
      : { op: 'rule', node: ev.node, to: 'in_progress', patch: { returns: node.returns + 1, attempts: node.attempts + 1, lease_until: at + cfg.lease_sec * 1000, request: null, blocked_reason: null } };
    case 'unblock': return { op: 'unblock', node: ev.node, to: 'ready', patch: { extra_returns: node.extra_returns + (ev.extra_returns || 0), extra_attempts: node.extra_attempts + (ev.extra_attempts || 0),
      extra_unavailable: node.extra_unavailable + (ev.extra_unavailable || 0), blocked_reason: null, lease_until: null, request: null, worker: null } };
    case 'annul': return { op: 'annul', node: ev.node, to: node.status, patch: { returns: Math.max(0, node.returns - 1), annulled: node.annulled + 1 } };
    case 'expire': {
      const exhausted = node.attempts >= attemptLimit(node, cfg);
      return { op: 'expire', node: ev.node, to: exhausted ? 'blocked' : 'ready', patch: { lease_until: null, request: null, worker: null, blocked_reason: exhausted ? 'attempts_exhausted' : null } };
    }
    case 'stop': return { op: 'stop', flag: true };
    case 'resume': return { op: 'resume', flag: false };
    case 'epoch': return { op: 'epoch', covers: ev.covers };
    default: return null;
  }
}

const results = new WeakMap();
function resultOf(ctx) {
  if (Object.hasOwn(ctx, 'result') && ctx.result !== undefined) return ctx.result;
  if (!results.has(ctx)) { let r = null; try { r = computeResult(ctx); } catch { r = null; } results.set(ctx, r); }
  return results.get(ctx);
}
const nodeOf = (ctx, ev) => (ev && NODE_OPS.has(ev.op) ? ctx.state.nodes.get(ev.node) : undefined);
/** op → (前の状態 → 行ける後の状態)。approve・annul は状態を変えない（どの状態からでも、同じ状態のまま） */
const TRANSITIONS = {
  start: { ready: ['in_progress'] }, submit: { in_progress: ['review'] },
  verdict: { review: ['review', 'in_progress', 'held', 'merged', 'blocked'] },
  release: { held: ['merged'] }, rule: { blocked: ['merged', 'in_progress'] }, unblock: { blocked: ['ready'] },
  expire: { in_progress: ['ready', 'blocked'] },
};
/** 設定の変更が「緩める」か（上限を上げる・hold を外す・必須の審査を減らす・系統の縛りを外す）。締める変更はいつでも許す */
function loosens(oldC, newC) {
  if (newC.workers > oldC.workers || newC.max_attempts > oldC.max_attempts || newC.max_returns > oldC.max_returns || newC.max_unavailable > oldC.max_unavailable || newC.lease_sec > oldC.lease_sec) return true;
  if (oldC.hold && !newC.hold) return true;
  if (oldC.policy_line !== newC.policy_line) return true; // 法律の系統の付け替え（null との間も）は、それ自体を緩める変更として扱う
  const nj = new Set(newC.judiciary.map((j) => j.lineage));
  if (oldC.judiciary.some((j) => !nj.has(j.lineage))) return true;
  return oldC.security_lineage !== newC.security_lineage;
}

// ---- ガード ----------------------------------------------------------------
// ctx = { state, actor（生の申告）, event（生の出来事）, at（記録の時刻 ms）, replay?, result?（試験用の上書き） }
// 設定（規則の数値・同時の数・法律の系統・必須の審査）は ctx.state.config（記録の中の config の出来事）からだけ読む。
// 各ガードは、他のガードが通っていなくても落ちず、読めない入力では「該当なし」（null）を返す。形の違反は RS-EVENT-SHAPE・RS-ACTOR-SHAPE が止める。

const gp = (ctx) => { const v = view(ctx); return { v, ev: v.ev, node: nodeOf(ctx, v.ev), res: resultOf(ctx), cfg: cfgOf(ctx) }; };
const finalTo = (res) => !!res && (res.to === 'held' || res.to === 'merged');
const tgCtx = (ctx, ev, cfg) => ({ nodes: tgBase(ctx), batch: [ev.node], limits: { workers: ctx.state.config ? cfg.workers : undefined }, occupy: [...BUSY], slotStatuses: SLOT });

export const GUARDS = {
  // --- 出来事・行為者の形 ---
  'RS-EVENT-SHAPE': (ctx) => { const v = view(ctx); return v.ev ? null : `出来事の形が正しくない: ${v.evErrors.join(' / ')}`; },
  'RS-ACTOR-SHAPE': (ctx) => { const v = view(ctx); return v.actor ? null : `行為者の形が正しくない（正規化して許可リストに合わない）: ${v.actorErrors.join(' / ')}`; },
  'RS-ROLE-OP': (ctx) => {
    const { v, ev } = gp(ctx);
    if (!v.actor || !ev) return null;
    return ROLE_OPS[ev.op].includes(v.actor.role) ? null : `役割 ${v.actor.role} は ${ev.op} を起こせない（起こせる役割: ${ROLE_OPS[ev.op].join('/')}）`;
  },
  'RS-KIND-OP': (ctx) => {
    const { v, ev } = gp(ctx);
    if (!v.actor || !ev) return null;
    return KIND_OPS[ev.op].includes(v.actor.kind) ? null : `${v.actor.kind} は ${ev.op} を起こせない（起こせる種類: ${KIND_OPS[ev.op].join('/')}。行政の AI は司法と人の承認を迂回できない。INV-05）`;
  },
  'RS-EVENT-ID-UNIQUE': (ctx) => {
    const { v, ev } = gp(ctx);
    return ev && v.actor && ctx.state.seen.has(seenKey(v.actor, ev)) ? `event_id が使用済み（同じ役割・op の組で。同じ内容の二度目は効かず、違う内容での再利用は拒む）: ${ev.event_id}` : null;
  },
  'RS-TIME-FUTURE': (ctx) => {
    if (!Number.isSafeInteger(ctx.at) || ctx.at < 0) return '記録の時刻が読めない';
    const { ev } = gp(ctx);
    if (ev && ev.op === 'stop') return null; // 停止は、どんな時刻の状態でも通す（INV-04）
    return Number.isFinite(ctx.wall) && ctx.at > ctx.wall + TIME_FUTURE_MS ? '記録の時刻が追記する側の実時間より 5 分以上先（未来の時刻の行を入れさせない。オーナーは clock_reset で正せる）' : null;
  },
  // --- 設定 ---
  'RS-CONFIG-REQUIRED': (ctx) => { const { ev } = gp(ctx); return ev && ev.op !== 'config' && !ctx.state.config ? '記録に config（規則の数値・必須の審査の一覧）がない。config 以外のすべての出来事を拒む' : null; },
  'RS-CONFIG-TIGHTEN': (ctx) => {
    const { ev } = gp(ctx);
    const old = ctx.state.config;
    if (!ev || ev.op !== 'config' || !old) return null;
    const { op: _o, event_id: _e, reason: _r, ...c } = ev;
    if (!loosens(old, c)) return null;
    const busy = [...ctx.state.nodes.values()].filter((n) => BUSY.has(n.status)).map((n) => n.id);
    return busy.length ? `緩める変更（上限を上げる・hold を外す・必須の審査を減らす）は、作業中（in_progress・review・held）の節がないときだけ（作業中: ${busy.slice(0, 5).join(', ')}）` : null;
  },
  // --- 全体の状態 ---
  'RS-STOPPED': (ctx) => { const { ev } = gp(ctx); return ev && ctx.state.stopped && ev.op !== 'stop' && ev.op !== 'resume' && ev.op !== 'clock_reset' ? '停止中は stop・resume・clock_reset（オーナーが時刻を正すため。停止中に時計が進んでいると resume が通らない行き止まりを避ける）以外のすべての出来事を拒む（SPEC §8。INV-04）' : null; },
  'RS-STOP-STATE': (ctx) => {
    const { ev } = gp(ctx);
    if (!ev) return null;
    if (ev.op === 'stop' && ctx.state.stopped) return 'すでに停止中';
    if (ev.op === 'resume' && !ctx.state.stopped) return '停止中でないので再開できない';
    return null;
  },
  'RS-SIZE-LIMIT': (ctx) => {
    const { ev } = gp(ctx);
    if (!ev) return null;
    if (ctx.state.count >= MAX_EVENTS) return `出来事の数が上限 ${MAX_EVENTS} に達した`;
    if (ev.op === 'plan') {
      if (ctx.state.nodes.size + ev.nodes.length > MAX_NODES_TOTAL) return `節の数が上限 ${MAX_NODES_TOTAL} を超える`;
      const deps = ev.nodes.reduce((a, d) => a + d.depends_on.length, 0);
      if (ctx.state.dep_total + deps > MAX_DEPS_TOTAL) return `依存の総数が上限 ${MAX_DEPS_TOTAL} を超える`;
    }
    return null;
  },
  'RS-EVENT-QUOTA': (ctx) => {
    const { v, ev } = gp(ctx);
    if (!v.actor || !ev) return null;
    const owner = v.actor.role === 'owner' && v.actor.kind === 'human'; // 取り置きの枠は role と kind の両方で決める（kind: human を名乗る行政は使えない）
    if (!owner && ctx.state.count >= MAX_EVENTS - HUMAN_RESERVE) return `オーナー以外の出来事の枠が尽きた（残りの ${HUMAN_RESERVE} 件はオーナーのために取ってある）`;
    if (v.actor.role === 'executive' && ev.op === 'plan') {
      if (ctx.state.ai_plans >= MAX_AI_PLANS) return `行政（role: executive）の plan の回数が上限 ${MAX_AI_PLANS} に達した`;
      if (ctx.state.nodes.size + ev.nodes.length > MAX_NODES_TOTAL - HUMAN_NODE_RESERVE) return `行政が足せる節の数の上限（${MAX_NODES_TOTAL - HUMAN_NODE_RESERVE}。残りはオーナーのために取ってある）に達する`;
    }
    if (!owner && ev.op === 'plan' && ctx.state.nodes.size + ev.nodes.length > MAX_NODES_TOTAL - HUMAN_NODE_RESERVE) return `オーナー以外が足せる節の数の上限（${MAX_NODES_TOTAL - HUMAN_NODE_RESERVE}）に達する`;
    return null;
  },
  'RS-REASON': (ctx) => {
    const { ev } = gp(ctx);
    if (!ev || ev.reason !== undefined) return null;
    if (REASON_REQUIRED.has(ev.op)) return `${ev.op} は理由が要る（記録に残す）`;
    return ev.op === 'config' && ctx.state.config ? 'config の変更は理由が要る（最初の config を除く）' : null;
  },
  // --- 節と遷移 ---
  'RS-NODE-EXISTS': (ctx) => { const { ev, node } = gp(ctx); return ev && NODE_OPS.has(ev.op) && !node ? `節がない: ${ev.node}` : null; },
  'RS-FROZEN': (ctx) => {
    const { ev, node } = gp(ctx);
    if (!ev || !node) return null;
    return node.status === 'merged' || node.superseded_by ? `${node.status === 'merged' ? '統合済み' : '置き換え済み'}の節は動かない: ${node.id}` : null;
  },
  'RS-TRANSITION': (ctx) => {
    const { ev, node, res } = gp(ctx);
    if (!ev || !node) return null;
    const table = TRANSITIONS[ev.op];
    const allowed = table ? table[node.status] : [node.status]; // approve・annul は状態を変えない
    if (!allowed) return `${ev.op} は ${node.status} の節に起こせない`;
    if (res && !allowed.includes(res.to)) return `${ev.op}: ${node.status} → ${res.to} は許されない遷移`;
    return null;
  },
  'RS-MERGE-PATH': (ctx) => {
    const { ev, node, res, cfg } = gp(ctx);
    if (!ev || !res || res.to !== 'merged' || (node && node.status === 'merged')) return null; // すでに merged の節は RS-FROZEN が見る
    const pass = res.kind === 'pass' || res.kind === 'pass_minor_disagreement';
    const ok = (ev.op === 'verdict' && pass && cfg.hold !== true) || ev.op === 'release' || (ev.op === 'rule' && ev.decision === 'merge');
    return ok ? null : `merged になれる経路は verdict の合格（hold でないとき）・release・rule（merge）だけ（${ev.op}${res.kind ? `:${res.kind}` : ''}、hold=${cfg.hold}）`;
  },
  'RS-WORKER-BIND': (ctx) => {
    const { v, ev, node } = gp(ctx);
    if (!v.actor || !ev || ev.op !== 'submit' || !node) return null;
    return node.worker !== null && node.worker === v.actor.id ? null : `申請できるのは着手した行為者（${node.worker}）だけ`;
  },
  // --- plan ---
  'RS-PLAN-NONEMPTY': (ctx) => { const { ev } = gp(ctx); return ev && ev.op === 'plan' && ev.nodes.length === 0 ? '空の plan は拒む（記録を空の出来事で埋められない）' : null; },
  'RS-PLAN-APPEND-ONLY': (ctx) => {
    const { ev } = gp(ctx);
    if (!ev || ev.op !== 'plan') return null;
    const dup = ev.nodes.filter((d) => ctx.state.nodes.has(d.id)).map((d) => d.id);
    return dup.length ? `既存の節の依存・範囲を書き換えられない（追加だけ。書き換えは新しい節への置き換え）: ${dup.slice(0, 5).join(', ')}` : null;
  },
  'RS-PLAN-GRAPH': (ctx) => {
    const { ev } = gp(ctx);
    if (!ev || ev.op !== 'plan') return null;
    const extra = new Map((ev.supersede || []).map((p) => [p.old, p.new]));
    const g = buildGraph(tgNodes(ctx.state, { extra, add: ev.nodes }));
    return g.ok ? null : `壊れたグラフは拒む: ${g.errors.slice(0, 3).join(' / ')}`;
  },
  'RS-PLAN-SUPERSEDE': (ctx) => {
    const { v, ev } = gp(ctx);
    if (!ev || ev.op !== 'plan' || !ev.supersede) return null;
    const newIds = new Set(ev.nodes.map((d) => d.id));
    const olds = new Set(); const news = new Set();
    const human = !!v.actor && v.actor.role === 'owner' && v.actor.kind === 'human';
    for (const p of ev.supersede) {
      const o = ctx.state.nodes.get(p.old);
      if (!o) return `置き換える節がない: ${p.old}`;
      if (o.status === 'merged' || o.superseded_by) return `統合済み・置き換え済みの節は置き換えられない: ${p.old}`;
      if (o.gen + 1 > MAX_SUPERSEDE_CHAIN) return `置き換えの鎖が長すぎる（上限 ${MAX_SUPERSEDE_CHAIN}）: ${p.old}`;
      if ((o.status === 'held' || (o.status === 'blocked' && o.blocked_reason === 'disagreement')) && !human) return `オーナーの判断待ち（${o.status}）の節の置き換えはオーナーだけ（行政が判断の機会を消せない）: ${p.old}`;
      if (!newIds.has(p.new) || p.new === p.old) return `置き換え先はこの計画で新しく追加する別の節でなければならない: ${p.new}`;
      if (olds.has(p.old) || news.has(p.new)) return `置き換えの対応が重複している: ${p.old} → ${p.new}`;
      olds.add(p.old); news.add(p.new);
    }
    return null;
  },
  // --- approve・start ---
  'RS-APPROVAL-FRESH': (ctx) => { const { ev, node } = gp(ctx); return ev && ev.op === 'approve' && node && ev.def_digest !== node.def_digest ? '承認の指紋が節の今の定義の指紋と一致しない（承認の後に定義が変われば効かない。SPEC §4-5）' : null; },
  'RS-APPROVED': (ctx) => { const { ev, node } = gp(ctx); return ev && ev.op === 'start' && node && !approvedNow(node) ? `未承認（または承認の後に定義が変わった）節は start できない: ${node.id}` : null; },
  'RS-SPEC-DIGEST': (ctx) => {
    const { ev, node } = gp(ctx);
    return ev && ev.op === 'start' && node && node.approval && ev.spec_digest !== node.approval.spec_digest ? '着手の時の仕様の指紋が承認した指紋と違う（承認の後に仕様が変わった。SPEC §4-5）' : null;
  },
  'RS-POLICY-LINE': (ctx) => {
    const { ev, node, cfg } = gp(ctx);
    if (!ev || ev.op !== 'start' || !node || !node.approval) return null;
    return cfg.policy_line && node.approval.policy_line !== cfg.policy_line ? `承認の法律の系統（${node.approval.policy_line}）が今の系統（${cfg.policy_line}）と違う（SPEC §4-6）` : null;
  },
  'RS-DEPS-MERGED': (ctx) => {
    const { ev, node, cfg } = gp(ctx);
    if (!ev || ev.op !== 'start' || !node) return null;
    const r = tgCheck(tgCtx(ctx, ev, cfg), ['TG-DEPS-MERGED']);
    return r.ok ? null : r.violations[0].reason;
  },
  'RS-RESOURCE-DISJOINT': (ctx) => {
    const { ev, node, cfg } = gp(ctx);
    if (!ev || !node || !(ev.op === 'start' || ev.op === 'unblock' || (ev.op === 'rule' && ev.decision === 'return'))) return null;
    const r = tgCheck(tgCtx(ctx, ev, cfg), ['TG-RESOURCE-DISJOINT']); // 未統合の作業（in_progress・review・held）の全部と比べる
    return r.ok ? null : r.violations[0].reason;
  },
  'RS-WORKER-LIMIT': (ctx) => {
    const { ev, node, cfg } = gp(ctx);
    if (!ev || !node || !(ev.op === 'start' || (ev.op === 'rule' && ev.decision === 'return'))) return null;
    const r = tgCheck(tgCtx(ctx, ev, cfg), ['TG-WORKER-LIMIT']); // in_progress と review を数える（held は人の承認待ちで枠を使わない）
    return r.ok ? null : r.violations[0].reason;
  },
  'RS-ATTEMPTS': (ctx) => {
    const { ev, node, cfg } = gp(ctx);
    return ev && ev.op === 'start' && node && node.attempts >= attemptLimit(node, cfg) ? `着手の回数が上限に達した（${node.attempts} >= ${attemptLimit(node, cfg)}。INV-07）` : null;
  },
  'RS-LEASE-LIMIT': (ctx) => {
    const { ev, node, cfg } = gp(ctx);
    return ev && ev.op === 'start' && node && ev.lease_sec > cfg.lease_sec ? `lease_sec が config の上限（${cfg.lease_sec}）を超える（長い lease で範囲と枠を占めさせない）` : null;
  },
  'RS-EXPIRE-DUE': (ctx) => {
    const { ev, node } = gp(ctx);
    if (!ev || ev.op !== 'expire' || !node) return null;
    if (!Number.isFinite(node.lease_until) || !Number.isFinite(ctx.at)) return 'lease の期限・記録の時刻が読めない';
    return ctx.at >= node.lease_until ? null : '期限を過ぎていない（時刻は記録の at で判定する。申告の時刻は信用しない）';
  },
  // --- 申請・司法・統合 ---
  'RS-REQUEST-MATCH': (ctx) => {
    const { ev, node } = gp(ctx);
    if (!ev || !node || !['verdict', 'release', 'rule'].includes(ev.op)) return null;
    return node.request && ev.request === node.request ? null : '申請の指紋が今の申請と一致しない（前の申請の結果の使い回しを拒む。SPEC §6-5・§8b-3）';
  },
  'RS-VERDICT-SET': (ctx) => {
    const { ev, node, cfg } = gp(ctx);
    if (!ev || ev.op !== 'verdict' || !node) return null;
    const req = new Set(requiredOf(node, cfg));
    const extra = ev.verdicts.map((x) => `${x.kind}:${x.lineage}`).filter((k) => !req.has(k));
    return extra.length ? `必須の審査の一覧にない審査（種類:系統）の結果がある: ${extra.join(', ')}（余分な審査者・知らない系統は拒む）` : null;
  },
  'RS-RULE-SCOPE': (ctx) => { const { ev, node } = gp(ctx); return ev && ev.op === 'rule' && node && node.blocked_reason !== 'disagreement' ? '裁定できるのは、判定が分かれて blocked になった節だけ（ほかは unblock）' : null; },
  'RS-PASS-AUDIT': (ctx) => { const { ev, res } = gp(ctx); return ev && ev.op === 'verdict' && finalTo(res) && ev.audits !== 'passed' ? `監査が ${ev.audits} のまま合格にできない（SPEC §6-3）` : null; },
  'RS-PASS-QUORUM': (ctx) => {
    const { ev, node, res, cfg } = gp(ctx);
    if (!ev || ev.op !== 'verdict' || !node || !finalTo(res)) return null;
    return judiciaryInsufficient(ev.verdicts, requiredOf(node, cfg)) ? '必須の審査の結果が足りない・使えない審査者がいるのに合格にできない（司法の欠落を合格とみなさない。SPEC §6-5。判例 G15・G19）' : null;
  },
  'RS-PASS-CONSENSUS': (ctx) => {
    const { ev, res } = gp(ctx);
    if (!ev || ev.op !== 'verdict' || !finalTo(res)) return null;
    if (securityFailed(ev.verdicts)) return 'セキュリティ審査が不合格のものは合格にできない';
    const j = judgesOf(ev.verdicts);
    if (j.length === 0) return '判定がない合格は認めない';
    if (j.every((x) => x.verdict === 'APPROVED')) return res.kind === 'pass' ? null : '全員が APPROVED の合格は kind: pass で記録する';
    if (hasMinorSplit(ev.verdicts)) return res.kind === 'pass_minor_disagreement' ? null : '重大でない指摘で分かれた合格は kind: pass_minor_disagreement として区別して記録する';
    return '全員が APPROVED でない判定（全員が差し戻し・重大な指摘で分かれた判定）では合格にできない';
  },
  'RS-SECURITY-FAIL': (ctx) => {
    const { ev, node, res, cfg } = gp(ctx);
    if (!ev || ev.op !== 'verdict' || !node || !res) return null;
    if (node.returns >= returnLimit(node, cfg) || ev.audits !== 'passed' || judiciaryInsufficient(ev.verdicts, requiredOf(node, cfg)) || !securityFailed(ev.verdicts)) return null;
    return res.kind === 'return' || res.kind === 'blocked_attempts' ? null : 'セキュリティ審査の不合格は、不一致・裁定より先に差し戻す（裁定で通せない）';
  },
  'RS-DISAGREE-BLOCK': (ctx) => {
    const { ev, node, res, cfg } = gp(ctx);
    if (!ev || ev.op !== 'verdict' || !node || !res) return null;
    if (node.returns >= returnLimit(node, cfg) || ev.audits !== 'passed' || judiciaryInsufficient(ev.verdicts, requiredOf(node, cfg)) || securityFailed(ev.verdicts) || !hasMajorSplit(ev.verdicts)) return null;
    return res.to === 'blocked' ? null : '重大な指摘で判定が分かれたら blocked（オーナーの裁定待ち。SPEC §6-4）';
  },
  'RS-RETURN-CAP': (ctx) => {
    const { ev, node, res, cfg } = gp(ctx);
    if (!ev || ev.op !== 'verdict' || !node || !res) return null;
    return node.returns >= returnLimit(node, cfg) && res.to !== 'blocked' ? `差し戻しが上限（${returnLimit(node, cfg)}）に達した票の申請は、司法を見ずに blocked（SPEC §5。INV-07）` : null;
  },
  'RS-ATTEMPTS-ON-RETURN': (ctx) => {
    const { ev, node, res, cfg } = gp(ctx);
    if (!ev || !node || !res || res.to !== 'in_progress' || (ev.op !== 'verdict' && ev.op !== 'rule')) return null;
    if (ev.op === 'verdict' && node.attempts >= attemptLimit(node, cfg)) return '試行の上限に達した票は、差し戻しで作業員を起動し直さず blocked にする';
    return res.patch && res.patch.attempts === node.attempts + 1 ? null : '差し戻しで in_progress に戻るときも、試行（attempts）に数える（夜間の代行と同じ）';
  },
  'RS-UNAVAILABLE-CAP': (ctx) => {
    const { ev, node, res, cfg } = gp(ctx);
    if (!ev || ev.op !== 'verdict' || !node || !res) return null;
    if (node.returns >= returnLimit(node, cfg) || ev.audits !== 'passed' || !judiciaryInsufficient(ev.verdicts, requiredOf(node, cfg))) return null;
    if (res.to === 'in_progress') return '司法が使えないことは判定ではない。差し戻しに数えない（SPEC §6-5）';
    const n = (node.unavail[ev.request] || 0) + 1;
    return n >= unavailLimit(node, cfg) && res.to !== 'blocked' ? `同じ申請の指紋で通算 ${unavailLimit(node, cfg)} 回、司法が使えなければ blocked（SPEC §6-5。INV-07）` : null;
  },
  // --- 人の操作 ---
  'RS-ANNUL-BOUND': (ctx) => { const { ev, node } = gp(ctx); return ev && ev.op === 'annul' && node && node.returns <= 0 ? '取り消せる差し戻しがない' : null; },
  'RS-UNBLOCK-PROGRESS': (ctx) => {
    const { ev, node, cfg } = gp(ctx);
    if (!ev || ev.op !== 'unblock' || !node) return null;
    const er = node.extra_returns + (ev.extra_returns || 0); const ea = node.extra_attempts + (ev.extra_attempts || 0);
    if (node.returns >= cfg.max_returns + er) return '再開しても差し戻しの上限で止まる（extra_returns を与えるか、annul で取り消す）。行き止まりを作らない';
    if (node.attempts >= cfg.max_attempts + ea) return '再開しても着手の上限で止まる（extra_attempts を与える）。行き止まりを作らない';
    return null;
  },
  'RS-EPOCH-COVERS': (ctx) => {
    const { ev } = gp(ctx);
    if (!ev || ev.op !== 'epoch') return null;
    const { count, last_hash: h } = ev.covers;
    const st = ctx.state;
    if (count > st.count) return '移行の記録が、まだない行を覆おうとしている';
    return h === (count === 0 ? 'genesis' : st.hashes[count - 1]) ? null : '移行の記録の last_hash が、覆う最後の行のハッシュと一致しない';
  },
};

/** 既定は全ガード。guardNames はアブレーション実験（bench）だけが絞る。ガードが例外を投げたら違反（fail-closed） */
export function check(ctx, guardNames = Object.keys(GUARDS)) {
  const violations = [];
  for (const g of guardNames) {
    if (!Object.hasOwn(GUARDS, g)) throw new Error(`未知のガード: ${g}`);
    let r;
    try { r = GUARDS[g](ctx || {}); } catch (e) { r = `検査が例外を投げた（拒否する）: ${String(e && e.message).slice(0, 80)}`; }
    if (r) violations.push({ guard: g, reason: r });
  }
  return { ok: violations.length === 0, violations };
}

/** 検査に渡す ctx を作る（試験・bench 用。apply・replay も同じ形を使う） */
export function makeCtx(state, actor, event, o = {}) {
  return { state, actor, event, at: o.at ?? state.last_at, wall: o.wall, replay: !!o.replay, ...(o.result !== undefined ? { result: o.result } : {}) };
}

// ---- 状態への反映（ガードを全部通った後だけ） ----
const PATCH_KEYS = new Set(['approval', 'attempts', 'lease_until', 'worker', 'request', 'returns', 'blocked_reason', 'unavail', 'extra_returns', 'extra_attempts', 'extra_unavailable', 'annulled']);
function reduce(st, actor, ev, res, at) {
  st.count += 1;
  st.last_at = at;
  st.seen.set(seenKey(actor, ev), eventDigest(actor, ev));
  switch (res.op) {
    case 'config': {
      const old = st.config;
      st.config = res.config;
      // 法律の系統が変わったら、それまでの承認は効かない（系統を戻しても古い承認が復活しない）
      if (old && old.policy_line !== res.config.policy_line) for (const n of st.nodes.values()) if (n.status !== 'merged') n.approval = null;
      return;
    }
    case 'clock_reset': return;
    case 'plan':
      if (actor.role === 'executive') st.ai_plans += 1;
      for (const d of res.add) { st.nodes.set(d.id, newNode(d)); st.order.push(d.id); st.dep_total += d.depends_on.length; }
      for (const p of res.supersede) {
        const o = st.nodes.get(p.old);
        o.status = 'blocked'; o.blocked_reason = 'superseded'; o.superseded_by = p.new; o.lease_until = null;
        st.nodes.get(p.new).gen = o.gen + 1;
        // 置き換えの解決を一度だけ更新する（old と、old に解決されていた節のすべてを新しい置き換え先に付け替える）
        const ids = [p.old, ...(st.sources.get(p.old) || [])];
        for (const id of ids) st.final.set(id, p.new);
        st.sources.delete(p.old);
        st.sources.set(p.new, [...(st.sources.get(p.new) || []), ...ids]);
      }
      return;
    case 'stop': st.stopped = true; st.stop_reason = ev.reason ?? null; return;
    case 'resume': st.stopped = false; st.stop_reason = null; return;
    case 'epoch': st.epochs += 1; st.covered = Math.max(st.covered, res.covers.count); return;
    default: {
      const n = st.nodes.get(res.node);
      for (const k of Object.keys(res.patch)) if (PATCH_KEYS.has(k)) n[k] = res.patch[k];
      n.status = res.to;
    }
  }
}

/** 1つの出来事を検査して、通れば state に反映する（メモリ上の処理。記録の書き出しは含まない） */
function step(st, actorRaw, eventRaw, o) {
  const ctx = makeCtx(st, actorRaw, eventRaw, o);
  const r = check(ctx, o.guardNames);
  if (!r.ok) return { ok: false, violations: r.violations };
  const v = view(ctx);
  const res = resultOf(ctx);
  if (!v.ev || !v.actor || !res) return { ok: false, violations: [{ guard: 'RS-EVENT-SHAPE', reason: '結果を作れない（拒否する）' }] };
  reduce(st, v.actor, v.ev, res, ctx.at);
  return { ok: true, actor: v.actor, ev: v.ev, res };
}

// ---- 再生 ----
const bad = (r, why) => new Refused('bad_record', `seq ${r && r.seq}：${why}`);
// 移行の記録に覆われた古い版の行は、構造の検査だけで受け入れる
const STRUCTURAL = ['RS-EVENT-SHAPE', 'RS-EVENT-ID-UNIQUE', 'RS-NODE-EXISTS', 'RS-TRANSITION'];
const ROW_META = new Set(['type', 'rules', 'actor', 'seq', 'at', 'prev', 'hash']);

function coveredCount(records, rules) {
  let n = 0;
  records.forEach((r, i) => {
    if (!isObj(r) || r.op !== 'epoch' || r.rules !== rules || !isObj(r.covers)) return;
    const a = parseActor(r.actor);
    if (!a.ok || a.actor.role !== 'owner' || a.actor.kind !== 'human') return;
    const c = r.covers.count;
    if (!Number.isSafeInteger(c) || c < 0 || c > i) return;
    if (r.covers.last_hash !== (c === 0 ? 'genesis' : records[c - 1].hash)) return;
    n = Math.max(n, c);
  });
  return n;
}

/** 前の再生の状態 st を使い回して、残りの行だけを再生してよいか（先頭の st.count 行のハッシュが今の鎖と同じで、古い版・移行の行がない） */
export function canResume(st, records) {
  if (!st || st.pure !== true || !Number.isSafeInteger(st.count) || st.count > records.length) return false;
  if (st.count === 0) return true;
  const r = records[st.count - 1];
  return !!r && typeof r.hash === 'string' && r.hash === st.hashes[st.count - 1];
}

/**
 * 記録の全行から状態を作り直す。今の版の行は、その時点の状態で全ガードに通し（偽の行を採らない）、通らなければ Refused('bad_record')。
 * 古い規則の版の行は、移行の記録（epoch）に覆われるときだけ構造の検査で受ける。
 * @param {{ rules?: string, pendingEpoch?: boolean, guardNames?: string[], resume?: object }} [o] rules は試験で版を差し替える。pendingEpoch は epoch を書く直前の検査だけが使う。
 *   resume は前の再生の状態（canResume で確かめたもの）で、残りの行だけを再生する
 */
export function replay(records, o = {}) {
  const rules = o.rules || RULES;
  const st = o.resume || newState();
  st.rules = rules;
  const base = o.guardNames || Object.keys(GUARDS);
  const covered = o.pendingEpoch ? records.length : coveredCount(records, rules);
  for (let i = st.count; i < records.length; i += 1) {
    const r = records[i];
    if (!isObj(r) || r.type !== RECORD_TYPE || typeof r.op !== 'string' || !OPS.includes(r.op)) throw bad(r, '知らない行');
    const current = r.rules === rules;
    if (!current && i >= covered) throw bad(r, `規則の版が今（${rules}）と違う（${String(r.rules)}）。古い版の行を受け入れるにはオーナーの移行の記録（epoch）が要る`);
    const event = {};
    for (const k of Object.keys(r)) if (!ROW_META.has(k)) event[k] = r[k];
    const raw = Date.parse(r.at);
    if (!Number.isSafeInteger(raw)) throw bad(r, '時刻が読めない');
    const at = r.op === 'clock_reset' ? raw : Math.max(raw, st.last_at); // 記録の上の今は、それまでの行の at の最大値（行の at が戻っていても拒まない）。clock_reset だけが戻せる
    const res = step(st, r.actor, event, { at, replay: true, guardNames: current ? base : STRUCTURAL });
    if (!res.ok) throw bad(r, `規則に合わない行（${res.violations.slice(0, 3).map((x) => `${x.guard}: ${x.reason}`).join(' / ')}）`);
    if (typeof r.hash !== 'string') throw bad(r, 'hash がない');
    st.hashes.push(r.hash);
    // 記録された行為者・項目は、正規化した形と同じであること（別の綴りで書かれた行を、同じとみなして黙って通さない）
    if (current && (canonical(r.actor) !== canonical(res.actor) || canonical(event) !== canonical(res.ev))) throw bad(r, '行為者・項目の綴りが正規化した形と違う');
    if (!current || r.op === 'epoch') st.pure = false;
  }
  return st;
}

// ---- 公開の窓口 ----
function deepFreeze(v) { if (v && typeof v === 'object' && !Object.isFrozen(v)) { Object.freeze(v); for (const k of Object.keys(v)) deepFreeze(v[k]); } return v; }
/** 入口の写し：JSON として一度だけ写して凍結する（toJSON・getter で検査と記録を食い違わせない）。写せなければ null */
function snapshot(v) { if (v === undefined) return undefined; try { const s = JSON.stringify(v); return s === undefined ? null : deepFreeze(JSON.parse(s)); } catch { return null; } }
const clone = (v) => JSON.parse(JSON.stringify(v));
class Dup extends Error {}

function nodeView(n) { return clone({ ...n, approved: approvedNow(n) }); }
function publicState(st) {
  const nodes = {};
  for (const id of st.order) nodes[id] = nodeView(st.nodes.get(id));
  return { rules: st.rules, count: st.count, stopped: st.stopped, epochs: st.epochs, covered: st.covered, config: st.config ? clone(st.config) : null, order: [...st.order], nodes };
}

function summaryOf(st) {
  const by = Object.fromEntries(STATUSES.map((s) => [s, 0]));
  const reasons = {}; const awaiting = [];
  for (const id of st.order) {
    const n = st.nodes.get(id);
    by[n.status] += 1;
    if (n.status === 'blocked' && n.blocked_reason) reasons[n.blocked_reason] = (reasons[n.blocked_reason] || 0) + 1;
    if (!approvedNow(n) && n.status !== 'merged' && !n.superseded_by) awaiting.push(id);
  }
  // 理由の本文・指紋は出さない（SPEC §7-5 の状態の写しの規律）。出すのは件数・種類・節の id と、約束だけのものの印
  const lineages = st.config ? new Set(st.config.judiciary.map((j) => j.lineage)).size : 0;
  return { rules: st.rules, events: st.count, stopped: st.stopped, configured: !!st.config, nodes: st.order.length, by_status: by, blocked_reasons: reasons, awaiting_approval: awaiting.sort(),
    single_lineage_judiciary: !!st.config && lineages < 2 };
}

function nextOf(st) {
  if (!st.config) return { stopped: false, start: [], recommend: null, waiting: [], error: ['記録に config がない（config 以外のすべての出来事を拒む）'] };
  if (st.stopped) return { stopped: true, start: [], recommend: null, waiting: [], note: '停止中（resume まで着手しない）' };
  const cfg = st.config;
  const own = new Map(); // 着手の上限・法律の系統で外す節 → 理由
  for (const id of st.order) {
    const n = st.nodes.get(id);
    if (n.status !== 'ready' || !approvedNow(n)) continue;
    if (n.attempts >= attemptLimit(n, cfg)) own.set(id, 'attempts_exhausted');
    else if (cfg.policy_line && n.approval.policy_line !== cfg.policy_line) own.set(id, 'policy_line_mismatch');
  }
  const g = buildGraph(tgNodes(st, { hideApproval: new Set(own.keys()) }));
  if (!g.ok) return { stopped: false, start: [], recommend: null, waiting: [], error: g.errors };
  const limits = { workers: cfg.workers };
  const opts = { occupy: [...BUSY], slotStatuses: SLOT };
  const sched = schedule(g.graph, limits, opts);
  const start = sched.batches.length ? [...sched.batches[0]] : [];
  const chosen = new Set(start);
  const waiting = [];
  for (const nr of tgReady(g.graph).not_ready) {
    const n = st.nodes.get(nr.id);
    if (n.status === 'merged' || n.superseded_by) continue;
    waiting.push({ id: nr.id, reasons: nr.reasons.map((r) => (r === 'unapproved' && own.has(nr.id) ? own.get(nr.id) : (r === 'status_held' && n.status === 'blocked' ? 'blocked' : r))) });
  }
  for (const [id, why] of Object.entries(sched.reasons)) if (id !== '_limits' && !chosen.has(id) && st.nodes.has(id)) waiting.push({ id, reasons: [why] });
  waiting.sort((a, b) => (a.id < b.id ? -1 : 1));
  return { stopped: false, start, recommend: recommend(g.graph, limits, opts), waiting, slots: sched.slots };
}

const refusal = (violations) => {
  const x = new Refused('guard', violations.slice(0, 3).map((v) => `${v.guard}: ${v.reason}`).join(' / '));
  x.violations = violations;
  return x;
};

function openRunWith(file, nowFn, lockWaitMs) {
  let cur = null;
  let cache = null; // 再生した状態の使い回し。canResume（先頭の count 行のハッシュが今の鎖と同じ・古い版や移行の行がない）のときだけ続きから再生する
  const ch = openChain(file, { now: () => cur, lockWaitMs });
  function rebuild(records, pendingEpoch = false) {
    const c = cache;
    cache = null;
    return replay(records, !pendingEpoch && canResume(c, records) ? { resume: c } : { pendingEpoch });
  }

  function apply(actor, event) {
    const a = snapshot(actor); const e = snapshot(event);
    const pa = parseActor(a); const pe = parseEvent(e);
    let body = { type: 'unwritten' };
    if (pa.ok && pe.ok) { const { op, event_id, ...fields } = pe.ev; body = { type: RECORD_TYPE, rules: RULES, op, event_id, actor: pa.actor, ...fields }; }
    let out = null; let applied = null;
    const wall = Date.now();
    try {
      const rec = ch.append(body, (records) => {
        // 時刻はロックの中で決める。直前までの最大値より前なら、拒まず最大値をそのまま使う（進めない）
        const t = nowFn();
        const raw = Date.parse(t);
        if (typeof t !== 'string' || !Number.isSafeInteger(raw)) throw new Refused('bad_time', 'now が読めない時刻を返した');
        const st = rebuild(records, pe.ok && pe.ev.op === 'epoch');
        applied = st;
        if (pa.ok && pe.ok && st.seen.get(seenKey(pa.actor, pe.ev)) === eventDigest(pa.actor, pe.ev)) throw new Dup();
        const reset = pe.ok && pe.ev.op === 'clock_reset';
        const at = reset ? raw : Math.max(raw, st.last_at);
        cur = at === raw ? t : new Date(at).toISOString();
        const r = step(st, a, e, { at, wall });
        if (!r.ok) throw refusal(r.violations);
        out = { node: r.res.node ? nodeView(st.nodes.get(r.res.node)) : null, kind: r.res.kind || null, to: r.res.to || null };
      });
      applied.hashes.push(rec.hash);
      cache = applied;
      return { ok: true, duplicate: false, seq: rec.seq, at: rec.at, ...out };
    } catch (x) {
      if (x instanceof Dup) { cache = applied; return { ok: true, duplicate: true }; }
      throw x;
    }
  }
  const load = () => { const st = rebuild(ch.read()); cache = st; return st; };
  return {
    file,
    apply,
    state: () => publicState(load()),
    verify() {
      const v = ch.verify();
      if (!v.ok) return v;
      try { const st = replay(ch.read()); return { ok: true, count: v.count, events: st.count, rules: st.rules }; } catch (x) {
        if (x instanceof Refused) return { ok: false, code: x.code, detail: x.detail };
        throw x;
      }
    },
    next: () => nextOf(load()),
    summary: () => summaryOf(load()),
  };
}

/**
 * 実行（run）の記録を開く。設定（規則の数値・同時の数・法律の系統・必須の審査）は記録の中の config の出来事からだけ読む。
 * 開く側の申告で決まるものはない（opt は lockWaitMs だけ。ほかの項目は拒む）。時計は chain の nowIso。
 * @param {string} file 記録のファイル（JSONL。chain.mjs）
 * @param {{ lockWaitMs?: number }} [opt]
 */
export function openRun(file, opt = {}) {
  if (!isObj(opt) || Object.keys(opt).some((k) => k !== 'lockWaitMs')) throw new Refused('bad_option', 'openRun が受けるのは lockWaitMs だけ（設定は記録の config の出来事で決める。時計の差し替えは openRunForTest）');
  return openRunWith(file, nowIso, opt.lockWaitMs);
}
/**
 * 【試験専用】時計（now）を差し替えて開く入口。配置するプロセスから呼ばない。
 * 入口があること自体が限界：export しているので誰でも呼べる。守っているのは、(1) 未来の時刻の行を RS-TIME-FUTURE が拒む（実時間は Date.now）、
 * (2) 記録の上の今は最大値で戻らない、(3) オーナーが clock_reset で正せる、の3つだけ。
 * 入口を残した理由：ファイルを使う試験が時計を制御する必要があり、コードの上で「試験のときだけ」を守る手段がない（import.meta・呼び出し元では守れない）。
 */
export function unsafeOpenRunWithClock(file, opt = {}) {
  return openRunWith(file, opt.now || nowIso, opt.lockWaitMs);
}

/**
 * ファイルを使わないメモリ上の実行（試験・bench 用。記録の鎖はない。同じガード・同じ遷移）。
 * 最初に、オーナーの config の出来事を DEFAULT_CONFIG に opt.config を重ねて入れる（opt.noConfig なら入れない）。
 */
export function memoryRun(opt = {}) {
  const st = newState();
  let t = Date.parse(opt.start || '2026-01-01T00:00:00+09:00');
  const rows = []; // 書き出し用（bench が記録のファイルを速く作るために使う）
  const owner = { role: 'owner', kind: 'human', id: 'azuki' };
  const api = {
    st, rows,
    tick(ms) { t += ms; },
    now: () => t,
    apply(actor, event) {
      const a = snapshot(actor); const e = snapshot(event);
      const pa = parseActor(a); const pe = parseEvent(e);
      if (pa.ok && pe.ok && st.seen.get(seenKey(pa.actor, pe.ev)) === eventDigest(pa.actor, pe.ev)) return { ok: true, duplicate: true };
      const at = pe.ok && pe.ev.op === 'clock_reset' ? t : Math.max(t, st.last_at);
      const r = step(st, a, e, { at, wall: opt.wall, guardNames: opt.guardNames });
      if (!r.ok) throw refusal(r.violations);
      st.hashes.push(sha256(canonical({ n: st.count, id: r.ev.event_id })));
      const { op, event_id, ...fields } = r.ev;
      rows.push({ at: new Date(at).toISOString(), body: { type: RECORD_TYPE, rules: RULES, op, event_id, actor: r.actor, ...fields } });
      return { ok: true, duplicate: false, kind: r.res.kind || null, to: r.res.to || null };
    },
    state: () => publicState(st), next: () => nextOf(st), summary: () => summaryOf(st),
  };
  if (!opt.noConfig) api.apply(owner, { op: 'config', event_id: 'config-0', ...clone(DEFAULT_CONFIG), ...(opt.config || {}) });
  return api;
}
