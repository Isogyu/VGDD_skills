// 共通の語彙（起草段階の試作。法律ではない）
//
// vgdd/next の部品（runstate・trace・experience・improvement・team・domain・bridge）が共有する名前と形の正本。
// 役割・行為者・系統・票の ID・指紋・時刻・結論の名前・拒否の形・法律の系統は、ここだけで決める。部品は独自の正規表現や一覧を持たない。
// 純関数と定数だけ（ファイルを開かない。時刻・乱数を使わない）。
//
// 方針（共通仕様の「独立した審査で学んだこと」1〜3）：
//   - 文字列は NFKC・前後の空白を落とし（役割・系統・行為者の id は小文字にもそろえ）、決まった形の許可リストに合うものだけを受ける。
//   - 表にない名前は「使えない」（null）。部分一致で推し量らない。呼び出し側は null を拒む（fail-closed）。
//   - 票の ID は宣言の形 { prefix, digits: [最小, 最大] } で照合する。大文字小文字は畳まない（書いたとおり）。
//
// 保証できないこと：
//   - 行為者・系統は申告である。ここが確かめるのは、名前が表にあり、役割と種類（human・ai・script）が表と合うことまで。
//     本物かどうか（なりすましでないこと、本当にその系統のモデルか）は確かめられない。
//   - 司法・立法補佐の役割（lineage_fixed）の系統は表の系統に縛る。行政の役割（executive_head・worker・tester）の系統は、知っている AI の系統で
//     あることだけを確かめる（codex の作業員を名乗れる）。どちらも申告で、本当にその系統のモデルかは確かめられない。

import { Refused } from './chain.mjs';

// ---------------------------------------------------------------------------
// 役割
// ---------------------------------------------------------------------------

/** 権力（SPEC §2）。sovereign は主権者（オーナー）、clerical は決めない処理（書記・回収・取り込み） */
export const BRANCHES = Object.freeze(['sovereign', 'legislative', 'executive', 'judicial', 'clerical']);
/** 行為者の種類。役割の表の kind は、これに 'ai+script'（どちらでも可）を加えたもの */
export const KINDS = Object.freeze(['human', 'ai', 'script']);
const ROLE_KINDS = new Set([...KINDS, 'ai+script']);

/**
 * 役割の表（正本）。名前は capabilities.json の roles を正とする（checkAgainstCapabilities で照合する）。
 *   branch：属する権力。kind：種類（capabilities.json の kind と同じ値）。lineage：既定の系統（ai は編成案の型の系統。人・スクリプトは固定）。
 *   lineage_fixed：系統が役割で決まっているか（true なら、行為者の申告の系統は表の系統と一致しなければならない。省略すれば表の値で補う）。
 *     司法の役割は起動の仕方で系統が決まる（judge・constitutional_review は claude -p、codex_judge・codex_security は codex exec。capabilities.json の
 *     identity）。立法補佐も別のアカウントの Claude。行政の役割（executive_head・worker・tester）は起動する定義しだいなので決めない。
 *   in_capabilities：権限の表（capabilities.json）にある役割か。false のものは「権限の表にまだない役割」（下）。
 *
 * gate_runner は裁判所の執行（Judicial Integration Gate）で、branch は judicial だが判定はしない（kind: script）。
 *   isJudicialRole は「判定する司法」（branch: judicial かつ kind が script でない）だけを true にし、isCourtSide は gate_runner も含める。
 *
 * 権限の表にまだない役割（配線の改正で capabilities.json の roles に足す候補。足すまでは vocab の中だけで使う）：
 *   - codex_security：Codex の系統のセキュリティ審査（司法）。今の Kernel では judge-codex.sh の mode: security として codex_judge の
 *     起動の中で動き、役割として分かれていない。runstate の kind: 'security' の審査と、trace の判定の種類 codex-security に当たる。
 *     分けて持つのは、司法の独立の判定（経験を渡さない・審査者になれる）を、名前の部分一致でなく表で決めるため。
 *   - reaper：期限の切れた着手（lease）を回収するスクリプト（runstate の expire）。今の Kernel にはない（lease の考え方がない）。
 *   - trace_importer：Kernel の記録から追跡のつながりを取り込むスクリプト（trace.linksFromEvidence の結果を書く）。今の Kernel にはない。
 *   これらを足すのは、権限の表の改正（法律の改正）に当たる。足したら in_capabilities を true にする。
 */
export const ROLE_TABLE = Object.freeze(Object.fromEntries(Object.entries({
  owner: { branch: 'sovereign', kind: 'human', lineage: 'human', in_capabilities: true },
  legislative_assistant: { branch: 'legislative', kind: 'ai', lineage: 'claude', in_capabilities: true, lineage_fixed: true },
  executive_head: { branch: 'executive', kind: 'ai', lineage: 'claude', in_capabilities: true },
  worker: { branch: 'executive', kind: 'ai', lineage: 'claude', in_capabilities: true },
  tester: { branch: 'executive', kind: 'ai', lineage: 'claude', in_capabilities: true },
  judge: { branch: 'judicial', kind: 'ai', lineage: 'claude', in_capabilities: true, lineage_fixed: true },
  codex_judge: { branch: 'judicial', kind: 'ai', lineage: 'codex', in_capabilities: true, lineage_fixed: true },
  constitutional_review: { branch: 'judicial', kind: 'ai', lineage: 'claude', in_capabilities: true, lineage_fixed: true },
  gate_runner: { branch: 'judicial', kind: 'script', lineage: 'script', in_capabilities: true },
  night_runner: { branch: 'executive', kind: 'script', lineage: 'script', in_capabilities: true },
  scribe: { branch: 'clerical', kind: 'ai+script', lineage: null, in_capabilities: true },
  // ---- 権限の表にまだない役割（上の説明） ----
  codex_security: { branch: 'judicial', kind: 'ai', lineage: 'codex', in_capabilities: false, lineage_fixed: true },
  reaper: { branch: 'clerical', kind: 'script', lineage: 'script', in_capabilities: false },
  trace_importer: { branch: 'clerical', kind: 'script', lineage: 'script', in_capabilities: false },
}).map(([k, v]) => [k, Object.freeze(v)])));
export const ROLES = Object.freeze(Object.keys(ROLE_TABLE));
/** 権限の表にまだない役割の名前 */
export const ROLES_NOT_IN_CAPABILITIES = Object.freeze(ROLES.filter((r) => !ROLE_TABLE[r].in_capabilities));

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const nfLow = (x) => (typeof x === 'string' && x.length <= 200 ? x.normalize('NFKC').trim().toLowerCase() : null);
const NAME_RE = /^[a-z][a-z0-9_]{0,39}$/;

/** 役割名の正規化。NFKC・trim・小文字化の後、^[a-z][a-z0-9_]{0,39}$ に合い、表にある名前だけを返す。それ以外は null */
export function normRole(x) {
  const s = nfLow(x);
  return s !== null && NAME_RE.test(s) && Object.hasOwn(ROLE_TABLE, s) ? s : null;
}
/** 役割の表の行（凍結）か null */
export const roleInfo = (role) => { const r = normRole(role); return r ? ROLE_TABLE[r] : null; };
/** 属する権力か null */
export const branchOf = (role) => { const i = roleInfo(role); return i ? i.branch : null; };
/** 判定する司法の役割か（表で branch: judicial かつ kind が script でないものだけ。完全一致。表にない名前は false。呼び出し側は表にない名前を拒む） */
export const isJudicialRole = (role) => { const i = roleInfo(role); return !!i && i.branch === 'judicial' && i.kind !== 'script'; };
/** 裁判所の側か（判定する司法と、裁判所の執行 gate_runner） */
export const isCourtSide = (role) => { const i = roleInfo(role); return !!i && i.branch === 'judicial'; };

/**
 * 役割の表と capabilities.json の roles を照合する。食い違いの一覧（空なら一致）。
 * 見ること：権限の表の役割がすべて vocab にあり in_capabilities が true か、kind が同じか。vocab で in_capabilities が true の役割が表にあるか。
 * @returns {{ role: string, problem: string }[]}
 */
export function checkAgainstCapabilities(caps) {
  const out = [];
  const roles = isObj(caps) && isObj(caps.roles) ? caps.roles : null;
  if (!roles) return [{ role: '*', problem: 'capabilities.json の roles がオブジェクトでない' }];
  for (const [name, r] of Object.entries(roles)) {
    if (!Object.hasOwn(ROLE_TABLE, name)) { out.push({ role: name, problem: '権限の表にある役割が vocab の表にない' }); continue; }
    const v = ROLE_TABLE[name];
    if (!v.in_capabilities) out.push({ role: name, problem: '権限の表にあるのに vocab では in_capabilities: false' });
    if (!isObj(r) || r.kind !== v.kind) out.push({ role: name, problem: `kind が違う（権限の表 ${isObj(r) ? String(r.kind) : '?'}、vocab ${v.kind}）` });
  }
  for (const name of ROLES) if (ROLE_TABLE[name].in_capabilities && !Object.hasOwn(roles, name)) out.push({ role: name, problem: 'vocab で in_capabilities: true だが権限の表にない' });
  return out;
}

// ---------------------------------------------------------------------------
// 系統
// ---------------------------------------------------------------------------

/**
 * 知っている系統の一覧。ここにない系統は拒む（'anthropic'・'openai' のような別名で、別の系統を装えない）。
 * 系統を足すのは、この一覧の変更（＝法律の改正）に当たる。human は人、script はスクリプトだけが名乗れる。
 */
export const LINEAGES = Object.freeze(['claude', 'codex', 'human', 'script']);
/** AI が名乗れる系統 */
export const AI_LINEAGES = Object.freeze(LINEAGES.filter((l) => l !== 'human' && l !== 'script'));
/** 系統名の正規化。NFKC・trim・小文字化の後 ^[a-z][a-z0-9_]{0,39}$（ハイフンは不可）に合い、知っている系統だけ。それ以外は null */
export function normLineage(x) {
  const s = nfLow(x);
  return s !== null && NAME_RE.test(s) && LINEAGES.includes(s) ? s : null;
}
/** 2つの系統が、どちらも知っている系統で、互いに違うか（片方でも読めなければ false） */
export function differentLineage(a, b) {
  const x = normLineage(a); const y = normLineage(b);
  return x !== null && y !== null && x !== y;
}

// ---------------------------------------------------------------------------
// 行為者
// ---------------------------------------------------------------------------

const ACTOR_ID_RE = /^[a-z0-9][a-z0-9_.-]{0,63}$/;
const ACTOR_KEYS = new Set(['role', 'kind', 'id', 'lineage']);

/**
 * 行為者の正規化と検査。{ ok, actor, errors }。actor は { role, kind, id, lineage }（全部品が同じ形を受け、同じ形で記録する）。
 *   - 欄は role・kind・id・lineage だけ（ほかは拒む。lineage は省略可）
 *   - role は表にある名前。kind は human・ai・script で、役割の表の kind と合うこと（ai+script の役割はどちらでも可）
 *   - id は NFKC・trim・小文字化の後 ^[a-z0-9][a-z0-9_.-]{0,63}$
 *   - lineage は、human なら 'human'、script なら 'script'（省略すれば補う）、ai なら AI の系統（claude・codex）。
 *     役割の表で系統が決まっている役割（lineage_fixed）は、表の系統だけ（省略すれば補う）。それ以外の ai は必須
 */
export function parseActor(x) {
  const errors = [];
  if (!isObj(x)) return { ok: false, actor: null, errors: ['行為者がオブジェクトでない'] };
  for (const k of Object.keys(x)) if (!ACTOR_KEYS.has(k)) errors.push(`行為者に知らない欄: ${String(k).slice(0, 40)}`);
  const role = normRole(x.role);
  if (!role) errors.push(`役割が表にない: ${String(x.role).slice(0, 40)}`);
  const kind = typeof x.kind === 'string' && KINDS.includes(x.kind) ? x.kind : null;
  if (!kind) errors.push('kind が human・ai・script のどれでもない');
  const idN = nfLow(x.id);
  const id = idN !== null && ACTOR_ID_RE.test(idN) ? idN : null;
  if (!id) errors.push('id が ^[a-z0-9][a-z0-9_.-]{0,63}$ でない');
  if (role && kind) {
    const rk = ROLE_TABLE[role].kind;
    if (rk !== kind && !(rk === 'ai+script' && (kind === 'ai' || kind === 'script'))) errors.push(`役割 ${role} の種類は ${rk}（${kind} は名乗れない）`);
  }
  let lineage = null;
  if (kind === 'human' || kind === 'script') {
    lineage = x.lineage === undefined ? kind : normLineage(x.lineage);
    if (lineage !== kind) { errors.push(`${kind} の lineage は '${kind}' だけ`); lineage = null; }
  } else if (kind === 'ai') {
    const fixed = role && ROLE_TABLE[role].lineage_fixed === true ? ROLE_TABLE[role].lineage : null;
    lineage = x.lineage === undefined ? fixed : normLineage(x.lineage);
    if (lineage === null) errors.push(`ai の lineage は必須で、知っている AI の系統（${AI_LINEAGES.join('・')}）のどれか`);
    else if (!AI_LINEAGES.includes(lineage)) { errors.push(`ai は lineage '${lineage}' を名乗れない`); lineage = null; }
    else if (fixed !== null && lineage !== fixed) { errors.push(`役割 ${role} の系統は ${fixed} に決まっている（${lineage} は名乗れない。系統の偽りで別系統の審査を装わせない）`); lineage = null; }
  }
  if (errors.length) return { ok: false, actor: null, errors };
  return { ok: true, actor: { role, kind, id, lineage }, errors: [] };
}
/** 正規化した行為者か null */
export const normActor = (x) => parseActor(x).actor;
/** 行為者の id（と、判定の項目の審査者の名前）の正規化。NFKC・trim・小文字化の後 ^[a-z0-9][a-z0-9_.-]{0,63}$。合わなければ null */
export function normActorId(x) { const s = nfLow(x); return s !== null && ACTOR_ID_RE.test(s) ? s : null; }
/** 同じ行為者か（正規化して role・kind・id・lineage が全部同じ） */
export function sameActor(a, b) {
  const x = normActor(a); const y = normActor(b);
  return !!x && !!y && x.role === y.role && x.kind === y.kind && x.id === y.id && x.lineage === y.lineage;
}
/** 人のオーナーか（role が owner かつ kind が human。正規化して確かめる） */
export function isOwner(actor) { const a = normActor(actor); return !!a && a.role === 'owner' && a.kind === 'human'; }

// ---------------------------------------------------------------------------
// 票（仕事の単位）の ID
// ---------------------------------------------------------------------------

/** 既定の票の ID の宣言：T- と 3〜4 桁（今の Kernel の T-NNN） */
export const DEFAULT_WORK_ITEM = Object.freeze({ prefix: 'T-', digits: Object.freeze([3, 4]) });
const PREFIX_RE = /^[A-Za-z][A-Za-z0-9._-]{0,15}$/;
const isInt = (n, lo, hi) => Number.isSafeInteger(n) && n >= lo && n <= hi;
/** 票の ID の宣言 { prefix, digits: [最小, 最大] } の検査と写し。読めなければ null（欄は prefix・digits だけ。digits は 1〜12） */
export function parseWorkItemSpec(spec) {
  if (!isObj(spec) || Object.keys(spec).some((k) => k !== 'prefix' && k !== 'digits')) return null;
  const { prefix, digits } = spec;
  if (typeof prefix !== 'string' || !PREFIX_RE.test(prefix)) return null;
  if (!Array.isArray(digits) || digits.length !== 2 || !isInt(digits[0], 1, 12) || !isInt(digits[1], 1, 12) || digits[0] > digits[1]) return null;
  return { prefix, digits: [digits[0], digits[1]] };
}
/**
 * 票の ID の宣言から照合の関数を作る（線形時間。正規表現は利用者から受けない）。宣言が読めなければ null。
 * 照合は書いたとおり（大文字小文字・全角を畳まない。T-101 と t-101 は別物で、宣言に合わない方を拒む）
 */
export function makeWorkItemId(spec = DEFAULT_WORK_ITEM) {
  const s = parseWorkItemSpec(spec);
  if (!s) return null;
  const { prefix, digits: [lo, hi] } = s;
  const fn = (id) => {
    if (typeof id !== 'string' || !id.startsWith(prefix)) return false;
    const n = id.length - prefix.length;
    if (n < lo || n > hi) return false;
    for (let i = prefix.length; i < id.length; i += 1) { const c = id.charCodeAt(i); if (c < 48 || c > 57) return false; }
    return true;
  };
  fn.spec = Object.freeze({ prefix, digits: Object.freeze([lo, hi]) });
  return fn;
}
/** 既定の宣言の照合 */
export const isDefaultWorkItemId = makeWorkItemId(DEFAULT_WORK_ITEM);
/** 2 つの宣言が同じか */
export function sameWorkItemSpec(a, b) {
  const x = parseWorkItemSpec(a); const y = parseWorkItemSpec(b);
  return !!x && !!y && x.prefix === y.prefix && x.digits[0] === y.digits[0] && x.digits[1] === y.digits[1];
}
/**
 * 要件の ID（A1、R-12、FR-1.2 の形。大文字だけ）。runstate の節の requirements と trace の requirement が同じ形を使う。
 * 票と違って領域パックで宣言しない（要件の表の書き方は領域によらない前提。変えるには vocab の改正）
 */
const REQUIREMENT_RE = /^[A-Z][A-Z0-9]{0,11}(?:[.-][A-Z0-9]{1,12}){0,3}$/;
export const isRequirementId = (x) => typeof x === 'string' && x.length <= 64 && REQUIREMENT_RE.test(x);

// ---------------------------------------------------------------------------
// 指紋と参照
// ---------------------------------------------------------------------------

const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const GIT_SHA = /^[0-9a-f]{40}$/;
/** 指紋の形：sha256: と 64 桁の小文字の 16 進 */
export const isDigest = (x) => typeof x === 'string' && DIGEST_RE.test(x);
/** 記録の行の hash（chain.mjs。接頭辞なしの 64 桁の 16 進） */
export const isLineHash = (x) => typeof x === 'string' && HEX64.test(x);
/** 64 桁の 16 進（記録の行の hash）を指紋の形にする。読めなければ null */
export const asDigest = (hex) => (typeof hex === 'string' && HEX64.test(hex) ? `sha256:${hex}` : null);
/** Git のコミット（40 桁の小文字の 16 進） */
export const isGitSha = (x) => typeof x === 'string' && GIT_SHA.test(x);
/** 申請・統合の参照：40 桁の 16 進（Git）か sha256: 形（Git でない領域）の 2 形だけ */
export const isArtifactRef = (x) => isGitSha(x) || isDigest(x);
/** 参照の先頭 12 桁（判定・監査の id に使う。Kernel の判定ファイル名の head と同じ桁数）。読めなければ null */
export const refHead12 = (x) => (isGitSha(x) ? x.slice(0, 12) : isDigest(x) ? x.slice(7, 19) : null);

// ---------------------------------------------------------------------------
// 審査の種類・判定と監査の id
// ---------------------------------------------------------------------------

/** runstate の判定の項目の種類（judge：通常の審査、security：セキュリティ審査） */
export const REVIEW_KINDS = Object.freeze(['judge', 'security']);
/**
 * 審査の種類（trace の判定の id に入る mode）と、役割・runstate の（種類, 系統）の対応。1 か所だけに持つ。
 * codex-ux は今の Kernel の judge-codex.sh の mode にあるが、対応する役割も runstate の種類もない（取り込みだけ）。
 */
export const REVIEW_MODES = Object.freeze([
  Object.freeze({ mode: 'judge', role: 'judge', kind: 'judge', lineage: 'claude' }),
  Object.freeze({ mode: 'codex-judge', role: 'codex_judge', kind: 'judge', lineage: 'codex' }),
  Object.freeze({ mode: 'codex-security', role: 'codex_security', kind: 'security', lineage: 'codex' }),
  Object.freeze({ mode: 'codex-ux', role: null, kind: null, lineage: 'codex' }),
]);
export const MODE_NAMES = Object.freeze(REVIEW_MODES.map((m) => m.mode));
/** runstate の（種類, 系統）→ 審査の種類（mode）。対応がなければ null（例：security と claude） */
export function reviewModeOf(kind, lineage) {
  const m = REVIEW_MODES.find((x) => x.kind !== null && x.kind === kind && x.lineage === normLineage(lineage));
  return m ? m.mode : null;
}
/** 審査の種類 → 役割（なければ null） */
export const roleOfMode = (mode) => { const m = REVIEW_MODES.find((x) => x.mode === mode); return m ? m.role : null; };

const MODE_ALT = MODE_NAMES.map((m) => m.replace(/-/g, '\\-')).join('|');
const VERDICT_ID_RE = new RegExp(`^VRD-([0-9a-f]{12})-(${MODE_ALT})(?:-([0-9a-f]{8}))?$`);
const AUDIT_ID_RE = /^AUD-([0-9a-f]{12})(?:-([0-9a-f]{8}))?$/;
const FINDING_LABEL_RE = /^[a-z0-9][a-z0-9_-]{0,31}$/;
/** 判定の id：VRD-<申請の先頭 12 桁>-<審査の種類>[-<判定の記録の指紋の先頭 8 桁>]。{ head, mode, short } か null */
export function parseVerdictId(x) { const m = typeof x === 'string' ? VERDICT_ID_RE.exec(x) : null; return m ? { head: m[1], mode: m[2], short: m[3] ?? null } : null; }
export const isVerdictId = (x) => parseVerdictId(x) !== null;
/** 監査の id：AUD-<申請の先頭 12 桁>[-<指紋の先頭 8 桁>]。{ head, short } か null */
export function parseAuditId(x) { const m = typeof x === 'string' ? AUDIT_ID_RE.exec(x) : null; return m ? { head: m[1], short: m[2] ?? null } : null; }
export const isAuditId = (x) => parseAuditId(x) !== null;
/** 判定の id を作る（digest があれば先頭 8 桁を付ける）。作れなければ null */
export function verdictId(request, mode, dg = null) {
  const h = refHead12(request);
  if (!h || !MODE_NAMES.includes(mode) || (dg !== null && !isDigest(dg))) return null;
  return `VRD-${h}-${mode}${dg ? `-${dg.slice(7, 15)}` : ''}`;
}
/** 監査の id を作る。作れなければ null */
export function auditId(request, dg = null) {
  const h = refHead12(request);
  if (!h || (dg !== null && !isDigest(dg))) return null;
  return `AUD-${h}${dg ? `-${dg.slice(7, 15)}` : ''}`;
}
/** 指摘への参照：<判定の id>#<ラベル>（ラベルは ^[a-z0-9][a-z0-9_-]{0,31}$）。{ verdict, label } か null */
export function parseFindingRef(x) {
  if (typeof x !== 'string' || x.length > 128) return null;
  const i = x.indexOf('#');
  if (i < 0) return null;
  const v = x.slice(0, i); const label = x.slice(i + 1);
  return isVerdictId(v) && FINDING_LABEL_RE.test(label) ? { verdict: v, label } : null;
}
export const isFindingRef = (x) => parseFindingRef(x) !== null;

// ---------------------------------------------------------------------------
// 結論の名前
// ---------------------------------------------------------------------------

/** 判定の結論 */
export const VERDICTS = Object.freeze(['APPROVED', 'CHANGES_REQUIRED', 'UNAVAILABLE']);
/** 監査の結論 */
export const AUDIT_RESULTS = Object.freeze(['passed', 'failed', 'not_run']);
/** 仕事の単位の状態（SPEC §5） */
export const STATUSES = Object.freeze(['ready', 'in_progress', 'review', 'held', 'merged', 'blocked']);

// ---------------------------------------------------------------------------
// 時刻
// ---------------------------------------------------------------------------

const TS_RE = /^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:\d\d)$/;
const daysIn = (y, m) => new Date(Date.UTC(y, m, 0)).getUTCDate();
function tsParts(s) {
  const m = typeof s === 'string' && s.length <= 40 ? TS_RE.exec(s) : null;
  if (!m) return null;
  const [, y, mo, d, h, mi, se, frac, tz] = m;
  const Y = Number(y); const M = Number(mo); const D = Number(d); const H = Number(h); const I = Number(mi); const S = Number(se);
  if (M < 1 || M > 12 || D < 1 || D > daysIn(Y, M) || H > 23 || I > 59 || S > 59) return null;
  let off = 0;
  if (tz !== 'Z') {
    const oh = Number(tz.slice(1, 3)); const om = Number(tz.slice(4, 6));
    if (oh > 14 || om > 59) return null;
    off = (tz[0] === '-' ? -1 : 1) * (oh * 60 + om);
  }
  const ms = Date.UTC(Y, M - 1, D, H, I, S, frac ? Number(frac.padEnd(3, '0').slice(0, 3)) : 0) - off * 60000;
  return Number.isFinite(ms) ? ms : null;
}
/**
 * 時差つきの ISO 8601 の時刻 → ミリ秒（読めなければ null）。秒まで必須、小数秒は任意、時差は Z か ±HH:MM だけ。
 * 時差なし（環境で解釈が変わる）・+0900（コロンなし）・秒なしは受けない。全部品はこれだけを使う。
 */
export const parseTs = (x) => tsParts(x);
export const isTs = (x) => tsParts(x) !== null;
/**
 * 今の Kernel の記録の時刻（date +%Y-%m-%dT%H:%M:%S%z の形。時差が +0900）を、vocab の形（+09:00）に写す。読めなければ null。
 * Kernel の記録を取り込む関数（trace.linksFromEvidence）だけが使う。部品の記録には、写した後の形だけを書く。
 */
export function kernelTsToIso(x) {
  if (typeof x !== 'string') return null;
  if (isTs(x)) return x;
  const m = /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)([+-]\d\d)(\d\d)$/.exec(x);
  if (!m) return null;
  const iso = `${m[1]}${m[2]}:${m[3]}`;
  return isTs(iso) ? iso : null;
}

// ---------------------------------------------------------------------------
// 法律の系統
// ---------------------------------------------------------------------------

const POLICY_LINE_RE = /^p(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/;
const KERNEL_VERSION_RE = /^(p(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))\.(?:0|[1-9]\d*)[a-z]?$/;
/** 法律の系統の形（pN.N） */
export const isPolicyLine = (x) => typeof x === 'string' && POLICY_LINE_RE.test(x);
/** 法律の版（'p0.4.15'）または権限の表（kernel_version を持つ）から法律の系統（'p0.4'）を取る。読めなければ null */
export function policyLineOf(v) {
  const s = isObj(v) ? v.kernel_version : v;
  const m = typeof s === 'string' ? KERNEL_VERSION_RE.exec(s) : null;
  return m ? m[1] : null;
}

// ---------------------------------------------------------------------------
// 拒否の形
// ---------------------------------------------------------------------------

/**
 * 状態を書く関数の拒否。全部品で Refused('guard_violation') と e.violations = [{ guard, reason }]。
 * 純関数の検査（validateTeam・validateDomainPack・check）は例外を投げず { ok, violations } を返す。
 */
export function refusal(violations) {
  const list = Array.isArray(violations) ? violations.map((v) => ({ guard: String(v.guard), reason: String(v.reason) })) : [];
  const e = new Refused('guard_violation', list.slice(0, 3).map((v) => `${v.guard}: ${v.reason}`).join(' / '));
  e.violations = list;
  return e;
}
