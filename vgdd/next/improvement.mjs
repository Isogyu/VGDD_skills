// 統治された改善提案の記録（起草段階の試作。法律ではない）
//
// AI は自分たちの規則・手順・編成の改善を「提案」できるが、「採用」はできない。提案によって権限が無断で広がらない。
// これを LLM を使わない決定論的な検査（GUARDS）で強制する。記録は追記専用の鎖つき記録（lib/chain.mjs）の上の状態機械。
//
// 状態（1提案につき）：proposed → evaluated → reviewed → adopted → rolled_back
//   どの未決の状態からも withdrawn（提案者）・rejected（オーナー）。終わった提案（rolled_back・rejected・withdrawn）は動かない。
//   amend（提案者による中身の差し替え）は状態を proposed に戻し、指紋（digest）を変える。前の指紋に結び付いた評価・審査は効かなくなる。
//
// CHANGES_REQUIRED（審査の差し戻し）の扱い（F4）：
//   - 自動では rejected にしない（司法に提案を消す権限を与えない。オーナーが reject するか、提案者が amend・withdraw する）
//   - 差し戻しは提案の id に残る。amend で版を変えても、差し戻した審査者（同じ id）が今の版に APPROVED を出すまで採用できない
//   - 再提案は前の提案の未解消の差し戻しを引き継ぐ。引き継ぐのは (a) 同じ指紋の提案（提案者を問わない）と
//     (b) 同じ提案者・同じ tier・同じ target の提案。取り下げても引き継ぎは消えない
//   - オーナーが却下（rejected）した提案と同じ指紋の再提案は受けない（中身を変えて出し直す。差し戻しは (b) で引き継ぐ）
//   - 引き継ぎの鍵（N1）：同じ指紋なら系統を問わず。同じ系統（id ではなく lineage）の提案者なら、target の鍵（paths は小文字の
//     各パス、ほかは「名前=値」）が1つでも重なれば引き継ぐ。tier は鍵にしない。重なりで引き継ぐので巻き込みは広い（同じファイルに
//     触れる別の提案も止まる）。その出口として、オーナーだけが理由つきで差し戻しを解ける（dismissChangesRequired。N2）。
//     引き継ぎの元で一度解けば、そこから引き継いだ提案にも及ぶ。未決の提案の今の版への差し戻しは解けない（amend・reject で扱う）
//   - 限界：target も中身も変えた別の提案として出し直すことは、機械では同じ提案と見分けられない
//
// 部品が保証すること：記録された行為者（actor）の組み合わせと入力が規則に合うときだけ遷移する。入力と行為者は入口で一度だけ
//   JSON として写して凍結し、検査と記録の両方にその写しを使う（F8）。記録を読むたびに各行をその時点の状態で再びガードに通し、
//   通らない行があれば全操作を拒む（F9。鎖を作り直して足した行も拒む）。鎖が壊れていれば全操作を拒む。
//
// 保証できないこと（限界）：
//   - 行為者が本物であること（なりすましでないこと）。actor は呼び出し側の申告で、この部品は確かめられない。
//     本物であることは「記録を行政が書けない保護領域（Z3 と同じ扱い）に置き、オーナー側のプロセスだけがこの関数を呼ぶ」配置で
//     強制する前提（未配線）。行政の AI がこの関数を直接呼べる配置では、kind: 'human', role: 'owner' を名乗るだけで採用できる。
//   - 評価の証拠（conformance の数）は評価者の申告で、ここでは試験を再実行しない。評価者を AI 以外（スクリプト・人）に限るのが精一杯。
//   - 検証器の変更の種類（target.change）と対象のパス（target.paths）は提案者の宣言で、中身との一致は機械で確かめない。
//     パスを宣言しない低い階層の提案（playbook など）に法律の中身を書かれても見分けられない。
//   - 法律の提案の files（表以外のファイルの中身）の意味は読まない（表を書き換えるスクリプトを files に書かれても見分けない。
//     そのような提案は常に full_legislative に回る）。
//   - 再生（replay）で確かめ直せないのは、時点に依る事実：その時の権限の表（IM-LAW-BASELINE）・法律の系統（IM-POLICY-LINE）・
//     未決の数の上限（IM-OPEN-LIMIT。設定が後で変わりうる）。これらは書く時だけ確かめる。代わりに再生では、法律の採用が直前に
//     採用された法律の新版（または移行の記録が持つ表の指紋）から始まることを確かめる（N4）。記録の中で起点のない最初の法律の採用は
//     確かめられず、状態の adoption.baseline に 'unverified' の印を残し、verify() の unverified_law_baselines に出す。
//   - 移行の記録（epoch）に覆われた古い版の行は、遷移の表と鎖だけを確かめる（役割の規則は確かめ直さない）。オーナーは移行の前に
//     古い行を自分で確かめる責任を負う。
//   - 審査者の判定の正しさ（LLM）は保証しない。系統の違う審査者を求めるのは同じ見落としへの備えで、見落としがないことの保証ではない。
//   - 記録のファイルと head を一緒に差し替えられる者（オーナーの権限）は、今の規則に合う行を作って足せる（今の版の行で規則に合わない
//     ものは再生で拒む。ただし上の時点に依る3つのガードは除く）。

import { openChain, digest, canonical, Refused } from './lib/chain.mjs';
import { authorityDelta, routeFor } from './authority-delta.mjs';
import { parseActor, normActor, isOwner as vocabIsOwner, isJudicialRole, normLineage, differentLineage, policyLineOf as vocabPolicyLineOf, isPolicyLine, ROLES, ROLE_TABLE, refusal } from './lib/vocab.mjs';

export const RECORD_TYPE = 'vgdd.improvement.v1';
export const TIERS = ['experience', 'playbook', 'composition', 'law', 'verifier', 'constitution'];
/** 審査者になれる役割（vocab の表で判定する司法。完全一致） */
/** 審査者になれる役割：vocab の表で判定する司法で、権限の表（capabilities.json）にある役割（in_capabilities）だけ。codex_security は権限の表に足す改正の後 */
export const JUDICIAL_ROLES = Object.freeze(ROLES.filter((r) => isJudicialRole(r) && ROLE_TABLE[r].in_capabilities === true));
/** 評価の証拠を出せる役割：裁判所の執行のスクリプト（gate_runner。適合性テストを動かす）と人のオーナー */
export const EVALUATOR_ROLES = Object.freeze(['gate_runner', 'owner']);
export const DEFAULT_MAX_OPEN = 5;
const OPS = ['propose', 'amend', 'evaluate', 'review', 'adopt', 'reject', 'withdraw', 'rollback', 'dismiss_cr', 'epoch'];
/**
 * 規則の版（N5）。ガードの規則を変えるたびに上げる。各行に rules として記録する。
 * 再生は今の版の行を全ガードで確かめ、古い版の行（版の印のない行は im.v1 とみなす）は、その後にオーナーの移行の記録（op: 'epoch'）が
 * あってそれに覆われるときだけ、構造の検査（遷移の表・id の順番・鎖）だけで状態に入れる。覆われない古い版の行は bad_record。
 * 限界：鎖を書ける者（オーナーの権限）は、古い版の印を付けた偽の行を移行の記録の前に作り直せる（鎖の限界と同じ根）。
 */
export const RULES = 'im.v4';
// im.v4：別系統の要求を「採用の時に、提案者と別の系統の司法の APPROVED が 1 つ以上」に変えた（IM-CROSS-LINEAGE）。評価者は gate_runner と
//   人のオーナーだけ（IM-EVALUATOR-ROLE）。審査者は権限の表にある司法だけ。再生で記録の行為者が正規形であることを確かめる。
// im.v3：行為者・系統・司法の役割・法律の系統は lib/vocab.mjs の語彙。各行に設定の写し（cfg: { max_open }）を持ち、写しが開く側の設定と違う
//   今の版の行は、移行の記録（epoch）に覆われるまで再生で拒む（開き方で過去の行の扱いを変えない）。今の権限の表と法律の系統は「設定」でなく
//   書く時の事実（法律そのもの）なので、開く側の引数のまま（再生で確かめない。REPLAY_SKIP）。
const OPEN = new Set(['proposed', 'evaluated', 'reviewed']);
const VERDICTS = new Set(['APPROVED', 'CHANGES_REQUIRED']);
export const CAPS_PATH = 'vgdd/kernel/capabilities.json';

// 対象のパスと、それを扱ってよい階層（小文字にそろえたパスに当て、最初に当たった規則を使う）。どれにも当たらないパスは階層を問わない
const PATH_RULES = [
  { re: /^vgdd\/kernel\/spec\.md$/, tiers: ['constitution'] },
  { re: /^vgdd\/conformance\//, tiers: ['verifier', 'constitution'] },
  { re: /^(claude\.md$|vgdd\/|\.claude\/|\.github\/|docs\/requirements\.md$)/, tiers: ['law', 'constitution'] },
];

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const nonEmpty = (s, max = 4000) => typeof s === 'string' && s.trim().length > 0 && s.length <= max;
const isCount = (n) => Number.isSafeInteger(n) && n >= 0;
const canon = (v) => { try { return canonical(v); } catch { return null; } };
const clone = (v) => (v === undefined ? undefined : JSON.parse(JSON.stringify(v)));
function deepFreeze(v) { if (v && typeof v === 'object' && !Object.isFrozen(v)) { Object.freeze(v); for (const k of Object.keys(v)) deepFreeze(v[k]); } return v; }
/** 入口の写し：JSON として一度だけ写して凍結する（toJSON・getter・Proxy で検査と記録を食い違わせない。F8）。写せなければ null */
function snapshot(v) { if (v === undefined) return undefined; try { const s = JSON.stringify(v); return s === undefined ? null : deepFreeze(JSON.parse(s)); } catch { return null; } }

// ---- パス（F3） ----
// 1つの要素は ASCII の英数字と . _ - だけ（NFC・NFD の違い、似た字、末尾の空白、制御文字を通さない）。
// '.'・'..'・'.' で終わる要素・空の要素（先頭・末尾・連続の '/'）・絶対パス・バックスラッシュは拒む。
// 照合は小文字にそろえて行う（macOS の既定のファイルシステムは大文字小文字を区別しない）。
const SEG_RE = /^[A-Za-z0-9._-]+$/;
/** パスの検査。正しければ照合用の小文字の形、読めなければ null */
export function normalizePath(p) {
  if (typeof p !== 'string' || p.length === 0 || p.length > 512) return null;
  const segs = p.split('/');
  if (segs.some((s) => !SEG_RE.test(s) || s === '.' || s === '..' || s.endsWith('.'))) return null;
  return segs.join('/').toLowerCase();
}
export function tiersAllowedForPath(p) { const n = normalizePath(p); if (!n) return []; const r = PATH_RULES.find((x) => x.re.test(n)); return r ? r.tiers : TIERS; }

/** 提案の指紋。rationale（提案者の説明）は含めない */
export function proposalDigest(p) {
  return digest({ title: p.title, tier: p.tier, target: p.target, content: p.content, capabilities: p.capabilities ?? null });
}

/**
 * 法律の提案の中身の形（F2）：content は { capabilities: <capabilities.new と同じ表>, files?: { <表以外のパス>: 文字列 } } だけ。
 * 適用される表は capabilities.new だけで、content の表と食い違いを作れない。target.paths は {表} ∪ files のパスと一致する。
 * @returns 違反の理由、または null
 */
export function lawContentProblem(p) {
  const c = p.content;
  if (!isObj(c)) return 'law の content は { capabilities, files? } の形でなければならない';
  const extra = Object.keys(c).filter((k) => k !== 'capabilities' && k !== 'files');
  if (extra.length) return `law の content に知らない項目：${extra.join('、')}`;
  if (!isObj(p.capabilities) || canon(c.capabilities) === null || canon(c.capabilities) !== canon(p.capabilities.new)) return 'content.capabilities が capabilities.new と一致しない（適用される表は1つだけ）';
  const files = c.files === undefined ? {} : c.files;
  if (!isObj(files)) return 'content.files がオブジェクトでない';
  const keys = new Set();
  for (const [k, v] of Object.entries(files)) {
    const n = normalizePath(k);
    if (!n) return `content.files のパスが読めない：${k}`;
    if (n === CAPS_PATH) return '権限の表は content.files でなく content.capabilities で変える';
    if (keys.has(n)) return `content.files のパスが重複（大文字小文字の違いを含む）：${k}`;
    if (typeof v !== 'string') return `content.files[${k}] が文字列でない`;
    keys.add(n);
  }
  const want = new Set([CAPS_PATH, ...keys]);
  const paths = isObj(p.target) && Array.isArray(p.target.paths) ? p.target.paths.map(normalizePath) : null;
  if (!paths || paths.includes(null) || new Set(paths).size !== paths.length || paths.length !== want.size || !paths.every((x) => want.has(x))) {
    return `target.paths が中身のパス（${[...want].join('、')}）と一致しない`;
  }
  return null;
}

/** 経路。law は権限の差分で決め、表の外のファイルを含めば full_legislative。constitution は常に、verifier は add 以外で full */
export function routeForProposal(p) {
  const full = (reasons, delta = null) => ({ ...routeFor({ class: 'indeterminate' }), reasons, delta });
  if (p.tier === 'constitution') return full(['憲法の変更は常に full_legislative']);
  if (p.tier === 'verifier') {
    if (p.target && p.target.change === 'add') return { ...routeFor({ class: 'tightening' }), reasons: ['検証器への追加だけ（単調）'], delta: null };
    return full([`検証器の変更が add でない（${p.target && p.target.change}）`]);
  }
  if (p.tier === 'law') {
    const caps = p.capabilities || {};
    const delta = authorityDelta(caps.old, caps.new);
    const r = routeFor(delta);
    const reasons = [`権限の差分：${delta.class}`];
    const bad = lawContentProblem(p);
    if (bad) return full([...reasons, `中身の形が読めない（${bad}）`], delta);
    const files = Object.keys(p.content.files || {});
    if (r.lane === 'standard' && files.length) return full([...reasons, `表（${CAPS_PATH}）以外のファイル（${files.length}件）を含む法律の変更は差分を機械で分類できない`], delta);
    return { ...r, reasons, delta };
  }
  return { ...routeFor({ class: 'neutral' }), reasons: [`${p.tier} の変更`], delta: null };
}

/** 審査者に渡す入力（機械的に組み立てる）。提案者の rationale と評価者の notes は入れない（SPEC §6-1 と同じ考え方） */
export function reviewInput(state) {
  return {
    schema: 'vgdd.improvement.review_input.v1',
    id: state.id, digest: state.digest, title: state.title, tier: state.tier, target: state.target, content: state.content,
    capabilities: state.capabilities ?? null,
    route: { lane: state.route.lane, requires: state.route.requires, reasons: state.route.reasons },
    authority_delta: state.route.delta ? { class: state.route.delta.class, changes: state.route.delta.changes } : null,
    evaluations: state.evaluations.filter((e) => e.digest === state.digest).map((e) => ({ conformance: e.evidence.conformance })),
    // 前の版・前の提案で差し戻した審査者（審査者が前の指摘の有無を知るため。今の版の審査では変わらないので、入力の指紋が安定する）
    prior_changes_required: priorCR(state),
  };
}
export const reviewInputDigest = (state) => digest(reviewInput(state));

// ---- 状態の補助 ----
// id の照合は NFKC・小文字にそろえる（大文字小文字・全角の違いで別人を装わせない）
const norm = (v) => String(v).normalize('NFKC').trim().toLowerCase();
/** 行為者の id・系統は vocab で正規化した形で比べる（読めない行為者は undefined。IM-ACTOR-SHAPE が拒む） */
const idOf = (a) => { const x = normActor(a); return x ? x.id : undefined; };
const lineageOf = (a) => { const x = normActor(a); return x ? x.lineage : undefined; };
/**
 * 差し戻しを引き継ぐかを決める target の鍵（N1）：paths は normalizePath（小文字）した各パス、ほかの最上位の文字列・数の項目は
 * 「名前=値」（NFKC・trim・小文字）。順序・大文字小文字・余分な項目では外れない。change（add 等）は鍵にしない。
 */
function targetKeys(t) {
  const k = new Set();
  if (!isObj(t)) return k;
  if (Array.isArray(t.paths)) for (const x of t.paths) { const n = normalizePath(x); if (n) k.add(`path:${n}`); }
  for (const [key, v] of Object.entries(t)) if (key !== 'paths' && key !== 'change' && (typeof v === 'string' || typeof v === 'number')) k.add(`${norm(key)}=${norm(v)}`);
  return k;
}
const overlaps = (a, b) => { for (const x of a) if (b.has(x)) return true; return false; };
const curEvals = (p) => p.evaluations.filter((e) => e.digest === p.digest);
const curReviews = (p) => p.reviews.filter((r) => r.digest === p.digest);
const isOwner = vocabIsOwner;
const shrinkExempt = (p) => p.tier === 'verifier' && p.target && p.target.change !== 'add';
/** 前の版で差し戻した審査者と、前の提案から引き継いだ差し戻しの審査者（今の版の審査に依らない） */
function priorCR(p) {
  const s = new Set(p.inheritedCR || []);
  for (const r of p.reviews) if (r.verdict === 'CHANGES_REQUIRED' && r.digest !== p.digest) s.add(idOf(r.actor));
  return [...s].sort();
}
const freshApproved = (p) => { const want = reviewInputDigest(p); return curReviews(p).filter((r) => r.verdict === 'APPROVED' && r.review_input_digest === want); };
/** 未解消の差し戻しを出した審査者の id（引き継ぎを含む）。同じ審査者が今の版・今の入力に APPROVED を出し、今の版に差し戻しがなければ解消 */
/**
 * オーナーがこの審査者の差し戻しを解いたか（N2）。この提案で直接解いたか、この提案自身の差し戻しでなく引き継いだだけなら、
 * 引き継ぎの元のすべてで解かれていれば解けたとみなす（元で一度解けば、そこから引き継いだ提案にも及ぶ）。
 * 元で差し戻した審査者がその後に承認しても、引き継ぎ先には及ぼさない（承認したのは別の中身）
 */
function dismissedFor(p, id, byId) {
  if ((p.dismissedCR || []).includes(id)) return true;
  if (p.reviews.some((r) => r.verdict === 'CHANGES_REQUIRED' && idOf(r.actor) === id)) return false;
  const src = (p.inheritedFrom || {})[id];
  return !!(byId && Array.isArray(src) && src.length && src.every((sid) => { const q = byId.get(sid); return !!q && dismissedFor(q, id, byId); }));
}
/** @param byId 提案の id → 状態（引き継ぎの元での解除を辿る。なければこの提案の中だけで見る） */
export function unresolvedCR(p, byId = null) {
  const all = new Set(priorCR(p));
  const crNow = new Set(curReviews(p).filter((r) => r.verdict === 'CHANGES_REQUIRED').map((r) => idOf(r.actor)));
  for (const id of crNow) all.add(id);
  const fresh = new Set(freshApproved(p).map((r) => idOf(r.actor)));
  // オーナーが解いた差し戻し（N2）。未決の提案では今の版への差し戻しは解けない（amend・reject で扱う）。終わった提案では引き継ぎの元を断つために解ける
  const canDismiss = (id) => dismissedFor(p, id, byId) && (!crNow.has(id) || !OPEN.has(p.status));
  return [...all].filter((id) => !canDismiss(id) && (crNow.has(id) || !fresh.has(id))).sort();
}
const evidenceOk = (e) => {
  const c = isObj(e) && isObj(e.evidence) && e.evidence.conformance;
  if (!isObj(c)) return false;
  for (const k of ['before', 'after']) { const x = c[k]; if (!isObj(x) || !isCount(x.total) || !isCount(x.passed) || x.passed > x.total) return false; }
  const n = c.new_cases_fail_on_before;
  return n === undefined || n === null || (isCount(n) && n <= c.after.total);
};

/** 記録の1行を、検査に渡す入力の形に戻す */
function inputOf(r) {
  switch (r.op) {
    case 'propose': case 'amend': return isObj(r.proposal) ? { ...r.proposal, ...(isObj(r.rationale) ? { rationale: r.rationale.text } : {}) } : null;
    case 'evaluate': return { digest: r.digest, evidence: r.evidence };
    case 'review': return { digest: r.digest, verdict: r.verdict, findings: r.findings, review_input_digest: r.review_input_digest };
    case 'adopt': return { digest: r.digest, policy_line: r.policy_line };
    case 'withdraw': return r.reason === undefined || r.reason === null ? {} : { reason: r.reason };
    case 'dismiss_cr': return { reviewer: r.reviewer, reason: r.reason };
    default: return { reason: r.reason };
  }
}

function apply(m, r) {
  let s = m.get(r.id);
  if (r.op === 'propose') {
    // 引き継ぎ（N1）：(a) 同じ指紋の提案は系統を問わず、(b) 同じ系統の提案者で target の鍵が1つでも重なる提案（tier は問わない）
    const from = {};
    const keys = targetKeys(r.proposal.target); const lin = lineageOf(r.actor);
    for (const q of m.values()) {
      const linked = q.digest === r.digest || (lineageOf(q.proposer) === lin && overlaps(targetKeys(q.target), keys));
      if (linked) for (const id of unresolvedCR(q, m)) (from[id] ||= []).push(q.id);
    }
    s = { id: r.id, proposer: r.actor, status: 'proposed', evaluations: [], reviews: [], adoption: null, closed: null, history: [], inheritedCR: Object.keys(from).sort(), inheritedFrom: from, dismissedCR: [] };
    m.set(r.id, s);
  }
  s.history.push({ seq: r.seq, op: r.op, actor: r.actor, at: r.at });
  switch (r.op) {
    case 'propose': case 'amend':
      Object.assign(s, clone(r.proposal), { digest: r.digest, rationale: r.rationale ?? null, status: 'proposed' });
      s.route = routeForProposal(s); // 記録した経路を信じず、記録した中身から決め直す
      break;
    case 'evaluate': s.evaluations.push({ actor: r.actor, digest: r.digest, evidence: r.evidence, seq: r.seq }); s.status = 'evaluated'; break;
    case 'review': s.reviews.push({ actor: r.actor, digest: r.digest, verdict: r.verdict, findings: r.findings, review_input_digest: r.review_input_digest, seq: r.seq }); s.status = 'reviewed'; break;
    case 'adopt': s.adoption = { actor: r.actor, digest: r.digest, policy_line: r.policy_line, seq: r.seq }; s.status = 'adopted'; break;
    case 'rollback': s.closed = { op: r.op, actor: r.actor, reason: r.reason, seq: r.seq }; s.status = 'rolled_back'; break;
    case 'reject': s.closed = { op: r.op, actor: r.actor, reason: r.reason, seq: r.seq }; s.status = 'rejected'; break;
    case 'withdraw': s.closed = { op: r.op, actor: r.actor, reason: r.reason ?? null, seq: r.seq }; s.status = 'withdrawn'; break;
    case 'dismiss_cr': s.dismissedCR = [...new Set([...(s.dismissedCR || []), norm(r.reviewer)])].sort(); (s.dismissals ||= []).push({ reviewer: norm(r.reviewer), actor: r.actor, reason: r.reason, seq: r.seq }); break;
  }
}
const nextIdOf = (m) => `IMP-${String(m.size + 1).padStart(4, '0')}`;

// 再生で確かめ直さないガード（時点に依る事実。書く時だけ確かめる）：その時の権限の表・法律の系統・未決の数の上限の設定
const REPLAY_SKIP = new Set(['IM-CHAIN-INTACT', 'IM-LAW-BASELINE', 'IM-POLICY-LINE', 'IM-OPEN-LIMIT']);
const REPLAY_CONFIG = Object.freeze({ maxOpen: Infinity, currentCaps: null, policyLine: null });
const bad = (r, why) => new Refused('bad_record', `seq ${r && r.seq}：${why}`);

/** 移行の記録が覆う行の数（書かれた順に、今の版・オーナー・末尾のハッシュの一致を確かめたものだけ） */
function coveredCount(records) {
  let n = 0;
  records.forEach((r, i) => {
    if (!isObj(r) || r.op !== 'epoch' || r.rules !== RULES || !isOwner(r.actor) || !isObj(r.covers)) return;
    const c = r.covers.count;
    if (!Number.isSafeInteger(c) || c < 0 || c > i) return;
    if (r.covers.last_hash !== (c === 0 ? 'genesis' : records[c - 1].hash)) return;
    n = Math.max(n, c);
  });
  return n;
}

/**
 * 記録の全行から提案の状態を組み立てる。今の版（RULES）の行は、その時点の状態で再びガードに通し（F9）、
 * 知らない行・規則に合わない行・記録した id や指紋が組み立て直したものと違う行があれば Refused('bad_record')（fail-closed）。
 * 法律の採用は、直前に採用された法律の新版（または移行の記録が持つ表の指紋）から始まっていなければならない（N4）。
 * 記録の中で最初の法律の採用は起点を確かめられないので、状態に baseline: 'unverified' の印を残す。
 * @param {{ pendingEpoch?: boolean }} [o] 移行の記録を書く直前の検査だけが使う（今ある全行を、書こうとする移行の記録が覆うとみなす）
 */
export function replay(records, o = {}) {
  const cfgNow = cfgCopy(o.config || {});
  const m = new Map();
  const guards = Object.keys(GUARDS).filter((g) => !REPLAY_SKIP.has(g));
  const covered = o.pendingEpoch ? records.length : coveredCount(records);
  let lawHead = null; // 直前に採用された法律の新版の指紋
  m.meta = { unverified_law_baselines: [] };
  records.forEach((r, i) => {
    if (!isObj(r) || r.type !== RECORD_TYPE || !OPS.includes(r.op) || typeof r.id !== 'string') throw bad(r, '知らない行');
    const current = r.rules === RULES;
    if (!current && i >= covered) throw bad(r, `規則の版が今（${RULES}）と違う（${r.rules ?? '印なし＝im.v1'}）。古い版の行を受け入れるにはオーナーの移行の記録（epoch）が要る`);
    if (current && r.op !== 'epoch' && i >= covered && canonical(r.cfg ?? null) !== canonical(cfgNow)) throw bad(r, '設定の写し（cfg）が開く側の設定と違う（別の設定で開いている）。受け入れるにはオーナーの移行の記録（epoch）が要る');
    if (r.op === 'epoch') {
      if (current) {
        const res = check(contextOf(m, { ok: true }, 'epoch', r.actor, null, { reason: r.reason }, REPLAY_CONFIG), guards);
        if (!res.ok) throw bad(r, res.violations.map((v) => v.guard).join('・'));
        if (canonical(r.actor ?? null) !== canonical(normActor(r.actor))) throw bad(r, '行為者の綴りが正規化した形と違う');
        const c = isObj(r.covers) ? r.covers.count : null;
        if (!Number.isSafeInteger(c) || c !== i || r.covers.last_hash !== (c === 0 ? 'genesis' : records[c - 1].hash)) throw bad(r, '移行の記録の覆う範囲が、その前の行と一致しない');
      }
      if (isObj(r.covers) && typeof r.covers.capabilities_digest === 'string') lawHead = r.covers.capabilities_digest;
      return;
    }
    if ((r.op === 'propose' || r.op === 'amend') && (!isObj(r.proposal) || typeof r.digest !== 'string')) throw bad(r, '提案の中身の形');
    if ((r.op === 'propose' || r.op === 'amend') && !(r.rationale === null || r.rationale === undefined || (isObj(r.rationale) && typeof r.rationale.text === 'string' && r.rationale.untrusted === true))) throw bad(r, 'rationale の形');
    const ctx = contextOf(m, { ok: true }, r.op, r.actor, r.op === 'propose' ? null : r.id, inputOf(r), REPLAY_CONFIG);
    // 古い版の行は構造（遷移の表）だけ。今の版の行は全ガード
    const res = check(ctx, current ? guards : ['IM-TRANSITION']);
    if (!res.ok) throw bad(r, res.violations.map((v) => v.guard).join('・'));
    if (r.op === 'propose' && r.id !== nextIdOf(m)) throw bad(r, 'id が順番と違う');
    // 記録された行為者は正規形でなければならない（別の綴り（全角・大文字）の行を、同じとみなして黙って通さない。runstate と同じ）
    if (current && canonical(r.actor ?? null) !== canonical(normActor(r.actor))) throw bad(r, '行為者の綴りが正規化した形と違う');
    if (current && (r.op === 'propose' || r.op === 'amend') && (!ctx.candidate || r.digest !== ctx.candidate.digest)) throw bad(r, '指紋が中身と一致しない');
    if (r.op === 'adopt' && ctx.proposal && ctx.proposal.tier === 'law') {
      const caps = ctx.proposal.capabilities || {};
      const oldD = canon(caps.old) === null ? null : digest(caps.old); const newD = canon(caps.new) === null ? null : digest(caps.new);
      if (current && lawHead !== null && oldD !== lawHead) throw bad(r, '法律の採用の旧版が、直前に採用された法律の新版（記録の起点）と一致しない');
      apply(m, r);
      m.get(r.id).adoption.baseline = lawHead === null ? 'unverified' : 'chained';
      if (lawHead === null) m.meta.unverified_law_baselines.push(r.id);
      lawHead = newD;
      return;
    }
    apply(m, r);
  });
  return m;
}

// 採用の有効性（INV-06 と同じ考え方）。公開するのは記録を読み直す im.adoptionValid(id) だけ（F5 の残り：古い写しを有効と見ない）
function adoptionValidState(state, currentPolicyLine) {
  if (!isPolicyLine(currentPolicyLine) || !isObj(state)) return false;
  return state.status === 'adopted' && isObj(state.adoption) && state.adoption.policy_line === currentPolicyLine && state.adoption.digest === state.digest;
}
const issue = (s) => deepFreeze(clone(s));

/** 権限の表（kernel_version）から法律の系統（pN.N）を取る（lib/vocab.mjs の policyLineOf）。読めなければ null */
export const policyLineOf = (caps) => (isObj(caps) ? vocabPolicyLineOf(caps) : null);
/** 行に残す設定の写し（im.v3） */
export const cfgCopy = (config) => ({ max_open: Number.isSafeInteger(config.maxOpen) ? config.maxOpen : DEFAULT_MAX_OPEN });

// ---- 文脈（ctx）の組み立て。状態を書かない ----

function readConfig(opt) {
  let caps = null;
  try { caps = typeof opt.currentCapabilities === 'function' ? opt.currentCapabilities() : (opt.currentCapabilities ?? null); } catch { caps = null; }
  const policyLine = opt.policyLine ?? policyLineOf(caps);
  return { maxOpen: Number.isSafeInteger(opt.maxOpenPerActor) && opt.maxOpenPerActor >= 0 ? opt.maxOpenPerActor : DEFAULT_MAX_OPEN, currentCaps: caps, policyLine: policyLine ?? null };
}

function candidateOf(input, prev) {
  if (!isObj(input)) return null;
  const c = { title: input.title, tier: prev ? prev.tier : input.tier, target: clone(input.target), content: clone(input.content), capabilities: clone(input.capabilities) };
  if (!TIERS.includes(c.tier) || !isObj(c.target) || canon(c) === null) return null;
  try { return { ...c, digest: proposalDigest(c), route: routeForProposal(c) }; } catch { return null; }
}

function contextOf(m, chain, op, actor, id, input, config) {
  const proposal = id && m.has(id) ? m.get(id) : null;
  const candidate = op === 'propose' || op === 'amend' ? candidateOf(input, op === 'amend' ? proposal : null) : null;
  return { op, actor, id, input, proposal, candidate, proposals: [...m.values()], chain, config };
}

/**
 * 遷移の検査に渡す文脈。actor と input は入口の写し（JSON として写して凍結）にそろえる。
 * 鎖が壊れている・再生できない（bad_record）ときは chain.ok=false で proposals は空。
 * ctx = { op, actor, id, input, proposal（今の状態）| null, candidate（propose・amend の新しい中身）| null, proposals, chain, config }
 */
export function buildContext({ records, chain = { ok: true }, op, actor, id = null, input = {}, config }) {
  let m = new Map(); let ch = chain;
  if (ch.ok) { try { m = replay(records, { pendingEpoch: op === 'epoch', config }); } catch (e) { if (!(e instanceof Refused)) throw e; ch = { ok: false, code: e.code, detail: e.detail }; } }
  return contextOf(m, ch, op, snapshot(actor), id, snapshot(input), config);
}

// ---- ガード ----

const cur = (ctx) => ctx.proposal;
const byIdOf = (ctx) => new Map((ctx.proposals || []).map((p) => [p.id, p]));

function inputShape(ctx) {
  const i = ctx.input;
  if (!isObj(i)) return '入力がオブジェクトでない（JSON として写せない値を含む）';
  switch (ctx.op) {
    case 'propose': case 'amend': {
      if (!nonEmpty(i.title, 300)) return 'title が空・長すぎる';
      if (ctx.op === 'propose' && !TIERS.includes(i.tier)) return `tier が ${TIERS.join('・')} のどれでもない`;
      if (ctx.op === 'amend' && i.tier !== undefined && ctx.proposal && i.tier !== ctx.proposal.tier) return 'amend で tier は変えられない（新しく提案する）';
      const tier = ctx.op === 'amend' ? (ctx.proposal && ctx.proposal.tier) : i.tier;
      if (!isObj(i.target)) return 'target がオブジェクトでない';
      if (i.target.paths !== undefined && (!Array.isArray(i.target.paths) || !i.target.paths.length || !i.target.paths.every((p) => normalizePath(p)))) return 'target.paths が相対パス（ASCII の英数字と . _ - の要素）の配列でない';
      if (!(typeof i.content === 'string' || isObj(i.content) || Array.isArray(i.content)) || canon(i.content) === null) return 'content が文字列か JSON でない';
      if (i.rationale !== undefined && !nonEmpty(i.rationale)) return 'rationale が文字列でない・長すぎる';
      if (tier === 'law') { if (!isObj(i.capabilities) || !isObj(i.capabilities.old) || !isObj(i.capabilities.new)) return 'law の提案には capabilities の { old, new } が要る'; }
      else if (i.capabilities !== undefined) return 'capabilities は law の提案だけが持てる';
      if (tier === 'verifier' && !['add', 'modify', 'remove'].includes(i.target.change)) return 'verifier の提案は target.change（add・modify・remove）の宣言が要る';
      if (!ctx.candidate) return '提案の中身を正規形にできない';
      return null;
    }
    case 'evaluate': {
      if (typeof i.digest !== 'string') return 'digest がない';
      const c = isObj(i.evidence) && i.evidence.conformance;
      if (!isObj(c)) return 'evidence.conformance がない';
      for (const k of ['before', 'after']) {
        const x = c[k];
        if (!isObj(x) || !isCount(x.total) || !isCount(x.passed)) return `conformance.${k} の total・passed が0以上の整数でない`;
        if (x.passed > x.total) return `conformance.${k} の passed が total を超える（自己申告の水増し）`;
      }
      const n = c.new_cases_fail_on_before;
      if (n !== null && n !== undefined && (!isCount(n) || n > c.after.total)) return 'new_cases_fail_on_before が0以上 after.total 以下の整数か null でない';
      if (i.evidence.notes !== undefined && typeof i.evidence.notes !== 'string') return 'notes が文字列でない';
      return null;
    }
    case 'review':
      if (typeof i.digest !== 'string' || typeof i.review_input_digest !== 'string') return 'digest・review_input_digest がない';
      if (!VERDICTS.has(i.verdict)) return 'verdict が APPROVED・CHANGES_REQUIRED でない';
      if (!Array.isArray(i.findings) || canon(i.findings) === null) return 'findings が配列でない';
      return null;
    case 'adopt': return typeof i.digest === 'string' && typeof i.policy_line === 'string' ? null : 'digest・policy_line がない';
    case 'reject': case 'rollback': return nonEmpty(i.reason) ? null : 'reason（理由）が要る';
    case 'withdraw': return i.reason === undefined || nonEmpty(i.reason) ? null : 'reason が文字列でない';
    case 'dismiss_cr': return nonEmpty(i.reviewer, 200) && nonEmpty(i.reason) ? null : 'reviewer（解く差し戻しの審査者の id）と reason（理由）が要る';
    case 'epoch': return nonEmpty(i.reason) ? null : 'reason（移行の理由）が要る';
    default: return `知らない操作 ${ctx.op}`;
  }
}

/** 採用の時に、記録された今の版の評価の形を確かめ直す（F8）。形が違えば理由 */
const evalsShapeProblem = (p) => (curEvals(p).every(evidenceOk) ? null : '記録された評価の証拠の形が違う（数でない値を含む）');

/** 名前 → (ctx) => null | string（違反の理由） */
export const GUARDS = {
  // 記録の鎖が無傷で、全行が規則どおりに再生できること（壊れていれば何もしない）
  'IM-CHAIN-INTACT': (ctx) => (ctx.chain && ctx.chain.ok ? null : `記録の鎖が壊れている・再生できない（${ctx.chain && ctx.chain.code}）`),
  // 行為者の形：kind は human・ai・script、lineage は人なら 'human'、AI・スクリプトなら 'human' 以外
  // 行為者の形（vocab）：役割は表の名前で種類が合う。lineage は人なら human、スクリプトなら script、AI なら知っている AI の系統（別名は拒む）
  'IM-ACTOR-SHAPE': (ctx) => { const a = parseActor(ctx.actor); return a.ok ? null : `行為者が vocab の形でない：${a.errors[0]}`; },
  // 操作ごとの入力の形（自己申告の数の矛盾、JSON として写せない値を含む）
  'IM-INPUT-SHAPE': (ctx) => inputShape(ctx),
  // 状態機械：終わった提案は動かない。rollback は採用済みだけ、それ以外は未決だけ
  'IM-TRANSITION': (ctx) => {
    if (ctx.op === 'propose' || ctx.op === 'epoch') return null;
    const p = cur(ctx);
    if (!p) return `提案 ${ctx.id} がない`;
    if (ctx.op === 'dismiss_cr') {
      // 解けるのは前の版・前の提案の未解消の差し戻しだけ（今の版への差し戻しは amend か reject で扱う）。終わった提案の上でも解ける（引き継ぎの元を断つ）
      const crNow = new Set(curReviews(p).filter((r) => r.verdict === 'CHANGES_REQUIRED').map((r) => idOf(r.actor)));
      const who = isObj(ctx.input) && typeof ctx.input.reviewer === 'string' ? norm(ctx.input.reviewer) : null;
      return who && unresolvedCR(p, byIdOf(ctx)).includes(who) && (!crNow.has(who) || !OPEN.has(p.status)) ? null : `解ける未解消の差し戻しがない（${who}。未決の提案の今の版への差し戻しは amend か reject で扱う）`;
    }
    if (ctx.op === 'rollback') return p.status === 'adopted' ? null : `採用されていない提案は取り消せない（${p.status}）`;
    return OPEN.has(p.status) ? null : `${p.status} の提案に ${ctx.op} はできない`;
  },
  // 採用できるのは人のオーナーだけ（AI・スクリプトは採用できない）
  'IM-ADOPT-HUMAN-OWNER': (ctx) => (ctx.op !== 'adopt' || isOwner(ctx.actor) ? null : `採用は人のオーナーだけ（${ctx.actor && ctx.actor.kind}/${ctx.actor && ctx.actor.role}）`),
  // reject・rollback はオーナーだけ。提案者は自分の提案を reject できない（withdraw だけ）
  'IM-OWNER-DECIDES': (ctx) => {
    if (!['reject', 'rollback', 'dismiss_cr', 'epoch'].includes(ctx.op)) return null;
    if (!isOwner(ctx.actor)) return `${ctx.op} は人のオーナーだけ`;
    if ((ctx.op === 'reject' || ctx.op === 'dismiss_cr') && cur(ctx) && idOf(cur(ctx).proposer) === idOf(ctx.actor)) return '自分の提案は reject できない（withdraw を使う）';
    return null;
  },
  // amend・withdraw は提案者だけ
  'IM-PROPOSER-ACTIONS': (ctx) => {
    if ((ctx.op !== 'amend' && ctx.op !== 'withdraw') || !cur(ctx)) return null;
    return idOf(cur(ctx).proposer) === idOf(ctx.actor) ? null : `${ctx.op} は提案者だけ`;
  },
  // 提案・評価・審査・採用を別の id に分ける（同じ審査者の同じ版の二度目の審査も認めない）
  'IM-SEPARATION-OF-DUTIES': (ctx) => {
    const p = cur(ctx); const me = idOf(ctx.actor);
    if (!p) return null;
    const proposer = idOf(p.proposer);
    const evaluators = curEvals(p).map((e) => idOf(e.actor)); const reviewers = curReviews(p).map((r) => idOf(r.actor));
    if (ctx.op === 'evaluate' && me === proposer) return '提案者は自分の提案を評価できない';
    if (ctx.op === 'review') {
      if (me === proposer) return '提案者は自分の提案を審査できない';
      if (evaluators.includes(me)) return '評価者は同じ提案を審査できない';
      if (reviewers.includes(me)) return '同じ審査者は同じ版を二度審査できない';
    }
    if (ctx.op === 'adopt' && [proposer, ...evaluators, ...reviewers].includes(me)) return '採用者は提案・評価・審査に関わっていてはならない';
    return null;
  },
  // 評価の証拠は AI 以外（適合性テストを動かすスクリプト・人）が出す
  // 評価の証拠を出せるのは、裁判所の執行のスクリプト（gate_runner）と人のオーナーだけ（AI・行政の代行・回収・書記のスクリプトは出せない。
  // experience の feedback・trace の link と同じく裁判所の側に限る）
  'IM-EVALUATOR-ROLE': (ctx) => {
    if (ctx.op !== 'evaluate') return null;
    const a = normActor(ctx.actor);
    if (!a) return null; // 形は IM-ACTOR-SHAPE
    return (a.role === 'gate_runner' && a.kind === 'script') || isOwner(a) ? null : `評価の証拠を出せるのは gate_runner（script）か人のオーナーだけ（${a.role}・${a.kind} は出せない）`;
  },
  // 審査者は司法の役割
  'IM-JUDICIAL-REVIEWER': (ctx) => {
    if (ctx.op !== 'review') return null;
    const a = normActor(ctx.actor) || {};
    return JUDICIAL_ROLES.includes(a.role) && a.kind !== 'script' ? null : `審査は権限の表にある司法の役割（${JUDICIAL_ROLES.join('・')}）だけ`;
  },
  // 採用の時の要求（im.v4）：今の版・今の入力に、提案者と別の系統の司法の APPROVED が 1 つ以上要る（tier によらず例外なし。同系統の見落とし・共謀への備え）。
  // 同じ系統の司法も審査はできる（例：Claude の提案の憲法審査は claude の constitutional_review）が、この要求を満たす数には入らない。
  // CHANGES_REQUIRED は系統を問わず効く（IM-ADOPT-REQUIRES-APPROVAL・IM-CR-STICKY）。系統は vocab の知っている系統で比べ、司法の系統は役割で決まる。
  // im.v3 までは「審査者は全員が提案者と別の系統」で、正直な同系統の憲法審査を拒み、系統を偽った申告だけが通る誘因になっていた
  'IM-CROSS-LINEAGE': (ctx) => {
    if (ctx.op !== 'adopt' || !cur(ctx)) return null;
    const pl = lineageOf(cur(ctx).proposer);
    const fresh = freshApproved(cur(ctx));
    if (fresh.length === 0) return null; // APPROVED が 1 つもないことは IM-ADOPT-REQUIRES-APPROVAL が見る
    return fresh.some((r) => differentLineage(lineageOf(r.actor), pl)) ? null : `提案者（${pl}）と別の系統の司法の APPROVED が今の版にない（同じ系統の審査だけでは採用できない）`;
  },
  // 評価・審査・採用は提案の今の指紋に結び付ける
  'IM-DIGEST-BOUND': (ctx) => {
    if (!['evaluate', 'review', 'adopt'].includes(ctx.op) || !cur(ctx)) return null;
    return isObj(ctx.input) && ctx.input.digest === cur(ctx).digest ? null : '指紋が提案の今の版と一致しない（すり替え・古い版）';
  },
  // 審査の入力は機械が組み立てたもの（提案者の説明・評価者の注記を含まない）でなければならない
  'IM-REVIEW-INPUT-CANONICAL': (ctx) => {
    if (ctx.op !== 'review' || !cur(ctx)) return null;
    return isObj(ctx.input) && ctx.input.review_input_digest === reviewInputDigest(cur(ctx)) ? null : '審査の入力が機械の組み立てた入力と違う（説明などが混ざっている）';
  },
  // 採用には今の版の評価が要る（記録された証拠の形も確かめ直す）
  'IM-ADOPT-REQUIRES-EVAL': (ctx) => {
    if (ctx.op !== 'adopt' || !cur(ctx)) return null;
    return curEvals(cur(ctx)).length ? evalsShapeProblem(cur(ctx)) : '今の版の評価がない';
  },
  // 採用には今の版への APPROVED（評価が加わる前の古い審査は数えない）が要り、今の版に CHANGES_REQUIRED が一つもないこと
  'IM-ADOPT-REQUIRES-APPROVAL': (ctx) => {
    if (ctx.op !== 'adopt' || !cur(ctx)) return null;
    const p = cur(ctx);
    if (curReviews(p).some((r) => r.verdict === 'CHANGES_REQUIRED')) return '今の版に CHANGES_REQUIRED の審査がある';
    return freshApproved(p).length ? null : '今の版・今の評価に対する APPROVED の審査がない';
  },
  // 差し戻しは版を変えても・出し直しても残る。差し戻した審査者が今の版に APPROVED を出すまで採用できない（F4）
  'IM-CR-STICKY': (ctx) => {
    if (ctx.op !== 'adopt' || !cur(ctx)) return null;
    const unresolved = unresolvedCR(cur(ctx), byIdOf(ctx));
    return unresolved.length ? `差し戻した審査者（${unresolved.join('、')}）の今の版への APPROVED がない（前の版・前の提案の差し戻しが未解消）` : null;
  },
  // オーナーが却下した提案と同じ指紋の再提案は受けない（F4）
  'IM-NO-RESUBMIT-REJECTED': (ctx) => {
    if (ctx.op !== 'propose' || !ctx.candidate) return null;
    const q = ctx.proposals.find((x) => x.status === 'rejected' && x.digest === ctx.candidate.digest);
    return q ? `却下された提案 ${q.id} と同じ中身の再提案` : null;
  },
  // 回帰がない（合格の数が減らない。検証器の削除の提案では失敗の数が増えない）
  'IM-NO-REGRESSION': (ctx) => {
    if (ctx.op !== 'adopt' || !cur(ctx)) return null;
    const p = cur(ctx);
    const bad = evalsShapeProblem(p); if (bad) return bad;
    for (const e of curEvals(p)) {
      const { before: b, after: a } = e.evidence.conformance;
      if (shrinkExempt(p) ? a.total - a.passed > b.total - b.passed : a.passed < b.passed) return `回帰がある（合格 ${b.passed}/${b.total} → ${a.passed}/${a.total}）`;
    }
    return null;
  },
  // 試験の数を減らさない（失敗する試験を消して合格率を上げる水増しを防ぐ）。検証器の remove・modify の提案だけは full_legislative の下で例外
  'IM-NO-TEST-SHRINK': (ctx) => {
    if (ctx.op !== 'adopt' || !cur(ctx) || shrinkExempt(cur(ctx))) return null;
    const bad = evalsShapeProblem(cur(ctx)); if (bad) return bad;
    const e = curEvals(cur(ctx)).find((x) => x.evidence.conformance.after.total < x.evidence.conformance.before.total);
    return e ? `試験の数が減っている（${e.evidence.conformance.before.total} → ${e.evidence.conformance.after.total}）` : null;
  },
  // 足した試験は前の版で落ちること（空回りの試験の追加を通さない。SPEC §11）。検証器の add では必須、
  // ほかの提案でも試験の数が増えていれば必須（null は不可）。試験の数が増えない提案（手順の変更など）には求めない（F7）
  'IM-NONVACUOUS-TESTS': (ctx) => {
    if (ctx.op !== 'adopt' || !cur(ctx)) return null;
    const p = cur(ctx);
    const bad = evalsShapeProblem(p); if (bad) return bad;
    const verifierAdd = p.tier === 'verifier' && p.target && p.target.change === 'add';
    for (const e of curEvals(p)) {
      const c = e.evidence.conformance; const added = c.after.total - c.before.total;
      if (verifierAdd && added <= 0) return '検証器の add なのに試験の数が増えていない';
      if ((verifierAdd || added > 0) && !(isCount(c.new_cases_fail_on_before) && c.new_cases_fail_on_before >= 1)) return `足した試験が前の版で1件も落ちない・確かめていない（new_cases_fail_on_before=${c.new_cases_fail_on_before}）`;
    }
    return null;
  },
  // full_legislative の提案は、今の版への APPROVED の憲法審査を経ていなければ採用できない
  'IM-FULL-LEGISLATIVE': (ctx) => {
    if (ctx.op !== 'adopt' || !cur(ctx)) return null;
    const p = cur(ctx);
    if (p.route.lane !== 'full_legislative') return null;
    return freshApproved(p).some((r) => r.actor && r.actor.role === 'constitutional_review') ? null : `full_legislative の提案に憲法審査の APPROVED がない（${p.route.reasons.join('・')}）`;
  },
  // 法律の提案の中身は { capabilities: <新版と同じ表>, files? } で、パスの宣言と一致する（適用される表を1つにする。F2）
  'IM-LAW-CONTENT-BOUND': (ctx) => {
    if ((ctx.op !== 'propose' && ctx.op !== 'amend') || !ctx.candidate || ctx.candidate.tier !== 'law') return null;
    return lawContentProblem(ctx.candidate);
  },
  // 法律の提案の旧版は、今効いている権限の表と同じでなければならない（旧版を偽って緩和を中立に見せない）。採用の時にも確かめ直す
  'IM-LAW-BASELINE': (ctx) => {
    const tier = ctx.op === 'propose' ? (ctx.input || {}).tier : cur(ctx) && cur(ctx).tier;
    if (tier !== 'law' || !['propose', 'amend', 'adopt'].includes(ctx.op)) return null;
    const old = ctx.op === 'adopt' ? (cur(ctx).capabilities || {}).old : ((ctx.input || {}).capabilities || {}).old;
    if (!isObj(ctx.config.currentCaps)) return '今の権限の表が設定されていない（法律の提案は扱えない）';
    return canon(old) !== null && canon(old) === canon(ctx.config.currentCaps) ? null : '旧版が今の権限の表と一致しない（偽りの旧版・古い基準）';
  },
  // 宣言した対象のパスを、その階層で扱ってよいこと（法律のファイルを playbook と称して出さない。大文字小文字を区別しない。F3）
  'IM-TIER-PATHS': (ctx) => {
    if (ctx.op !== 'propose' && ctx.op !== 'amend') return null;
    const i = ctx.input || {}; const tier = ctx.op === 'amend' ? cur(ctx) && cur(ctx).tier : i.tier;
    const paths = isObj(i.target) && Array.isArray(i.target.paths) ? i.target.paths : [];
    const bad = paths.filter((x) => !tiersAllowedForPath(x).includes(tier));
    return bad.length ? `${tier} の提案で扱えないパス：${bad.slice(0, 3).join('、')}` : null;
  },
  // 1つの AI・スクリプトが同時に出せる未決の提案の数に上限（オーナーの承認待ちを溢れさせない）
  'IM-OPEN-LIMIT': (ctx) => {
    if (ctx.op !== 'propose' || !isObj(ctx.actor) || ctx.actor.kind === 'human') return null;
    const n = ctx.proposals.filter((p) => idOf(p.proposer) === idOf(ctx.actor) && OPEN.has(p.status)).length;
    return n < ctx.config.maxOpen ? null : `未決の提案が上限（${ctx.config.maxOpen}）に達している`;
  },
  // 採用は今の法律の系統に結び付ける（INV-06）
  'IM-POLICY-LINE': (ctx) => {
    if (ctx.op !== 'adopt') return null;
    const line = ctx.config.policyLine;
    if (!isPolicyLine(line)) return '今の法律の系統が分からない（採用できない）';
    return isObj(ctx.input) && ctx.input.policy_line === line ? null : `policy_line が今の系統（${line}）と違う`;
  },
};

/** 既定は全ガード。guardNames はアブレーション実験（bench）だけが絞る。状態を書かない */
export function check(ctx, guardNames = Object.keys(GUARDS)) {
  const violations = [];
  for (const g of guardNames) {
    const fn = GUARDS[g];
    if (!Object.hasOwn(GUARDS, g)) { violations.push({ guard: g, reason: '知らないガード名' }); continue; }
    let r; try { r = fn(ctx); } catch (e) { r = `検査の失敗：${e && e.message}`; }
    if (r) violations.push({ guard: g, reason: r });
  }
  return { ok: violations.length === 0, violations };
}

// ---- 記録を開く ----

/**
 * 改善提案の記録を開く。
 * @param {string} file 記録のファイル（JSONL）。行政が書けない保護領域に置く前提（未配線）
 * @param {{ now?, lockWaitMs?, maxOpenPerActor?: number, currentCapabilities?: object | (() => object), policyLine?: string }} [opt]
 *   currentCapabilities：今効いている権限の表（法律の提案の旧版の照合と、法律の系統の既定値に使う）
 */
export function openImprovements(file, opt = {}) {
  const chain = openChain(file, { now: opt.now, lockWaitMs: opt.lockWaitMs });
  const config = () => readConfig(opt);

  // 状態を書く唯一の経路。追記の検査（ロックの中）で、渡された行の全体から文脈を作り、全ガードを通す。検査と記録は同じ写し（ctx）を使う
  function guarded(op, actor, id, input, makeBody) {
    const body = { type: RECORD_TYPE, op };
    chain.append(body, (records) => {
      const ctx = buildContext({ records, op, actor, id, input, config: config() });
      const r = check(ctx); // 全ガード（絞らない）
      if (!r.ok) throw refusal(r.violations);
      const nid = id ?? (op === 'epoch' ? `EPOCH-${records.filter((x) => x.op === 'epoch').length + 1}` : `IMP-${String(ctx.proposals.length + 1).padStart(4, '0')}`);
      Object.assign(body, { id: nid, rules: RULES, cfg: cfgCopy(ctx.config), actor: normActor(ctx.actor) }, makeBody(ctx, records));
    });
    return op === 'epoch' ? clone(body) : get(body.id);
  }
  const proposalBody = (ctx) => {
    const c = ctx.candidate; const i = ctx.input;
    return {
      proposal: { title: c.title, tier: c.tier, target: c.target, content: c.content, ...(c.capabilities ? { capabilities: c.capabilities } : {}) },
      digest: c.digest,
      route: { lane: c.route.lane, requires: c.route.requires, reasons: c.route.reasons },
      authority_delta: c.route.delta ? { class: c.route.delta.class, summary: c.route.delta.summary, changes: c.route.delta.changes } : null,
      // 提案者の説明はデータ。指紋にも審査の入力にも入れない
      rationale: i.rationale === undefined ? null : { text: i.rationale, untrusted: true, excluded_from: ['digest', 'review_input'] },
    };
  };

  function state() { return replay(chain.read(), { config: config() }); }
  function get(id) { const s = state().get(id); return s ? issue(s) : null; }

  return {
    file,
    propose: (actor, input) => guarded('propose', actor, null, input, proposalBody),
    amend: (actor, id, input) => guarded('amend', actor, id, input, proposalBody),
    evaluate: (actor, id, input) => guarded('evaluate', actor, id, input, ({ input: i }) => ({ digest: i.digest, evidence: clone(i.evidence) })),
    review: (actor, id, input) => guarded('review', actor, id, input, ({ input: i }) => ({ digest: i.digest, verdict: i.verdict, findings: clone(i.findings), review_input_digest: i.review_input_digest })),
    adopt: (actor, id, input) => guarded('adopt', actor, id, input, ({ input: i }) => ({ digest: i.digest, policy_line: i.policy_line })),
    reject: (actor, id, input) => guarded('reject', actor, id, input, ({ input: i }) => ({ reason: i.reason })),
    withdraw: (actor, id, input = {}) => guarded('withdraw', actor, id, input, ({ input: i }) => (i.reason === undefined ? {} : { reason: i.reason })),
    rollback: (actor, id, input) => guarded('rollback', actor, id, input, ({ input: i }) => ({ reason: i.reason })),
    /** オーナーが、前の版・前の提案から残った差し戻しを解く（N2。審査者の交代・系統の衝突で行き止まりになったときの人の出口）。理由は必須で記録に残る */
    dismissChangesRequired: (actor, id, input) => guarded('dismiss_cr', actor, id, input, ({ input: i }) => ({ reviewer: norm(i.reviewer), reason: i.reason })),
    /** オーナーの移行の記録（N5）。今ある全行を覆い、古い版の規則で書かれた行を構造の検査だけで受け入れる。今の表の指紋を法律の起点として持つ */
    epoch: (actor, input) => guarded('epoch', actor, null, input, ({ input: i, config: cfg }, records) => ({
      reason: i.reason,
      covers: { count: records.length, last_hash: records.length ? records[records.length - 1].hash : 'genesis', capabilities_digest: isObj(cfg.currentCaps) ? digest(cfg.currentCaps) : null },
    })),
    get,
    list: () => [...state().values()].map(issue),
    /** 記録を読み直して、採用が今の法律の系統で有効か（取り消し・系統の変更を反映する） */
    adoptionValid: (id, line = config().policyLine) => adoptionValidState(state().get(id), line),
    /** 審査者に渡す入力（rationale を含まない）と、その指紋 */
    reviewInputFor: (id) => { const s = state().get(id); if (!s) throw new Refused('not_found', id); return { input: reviewInput(s), digest: reviewInputDigest(s) }; },
    /** 状態を書かずに文脈を作る（bench・事前確認用）。鎖が壊れている・再生できなければ chain.ok=false の文脈を返す */
    contextFor: (op, actor, id, input) => {
      let records = []; let ch = { ok: true };
      try { records = chain.read(); } catch (e) { if (!(e instanceof Refused)) throw e; ch = { ok: false, code: e.code, detail: e.detail }; }
      return buildContext({ records, chain: ch, op, actor, id, input, config: config() });
    },
    verify: () => { const v = chain.verify(); if (!v.ok) return v; try { const m = replay(chain.read(), { config: config() }); return { ...v, unverified_law_baselines: m.meta.unverified_law_baselines }; } catch (e) { if (!(e instanceof Refused)) throw e; return { ok: false, code: e.code, detail: e.detail }; } },
  };
}
