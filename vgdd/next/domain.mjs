// 領域パックの宣言と検査（起草段階の試作。法律ではない）
//
// 統治の核（役割の分離・承認・司法・証跡・停止・予算）と、業務ごとの部分を分けるための宣言の形と検査。
// 領域パックは JSON の宣言で、核を弱められない。この検査は宣言の形と内容を見るだけで、
// パックの内容どおりに Kernel が動くこと（gate-runner の配線）は保証しない。
//
// 方針（審査 B-F5〜B-F7・B-F16 の判例）: 禁止リスト（「この名前・この文字はだめ」）ではなく、
// **決まった形だけを受ける許可リスト**で検査する。許可リストを広げる（例: 監査に使える実行ファイルを増やす）ことは
// 領域パックの側ではできず、この統治の核の側の一覧（このファイル）を改める＝法律の改正に当たる。
// 各階層の欄も許可リストで検査し、未知の欄は違反（fail-closed）。検査は例外を投げず、投げたら違反にする。
//
// 保証しないこと:
//   - 宣言した audits・lifecycle の段を実際に実行する仕組みは、この試作にはない
//   - 監査の command が宣言どおり決定論的か・実在するかは検査しない（形と実行ファイルの許可リストだけ）。
//     許可した npm・node は、package.json や指定のスクリプトの中身で任意のコードを動かせる。
//     それを抑えるのは sandbox（宣言が true であることだけ検査し、実際の sandbox の強制はこの検査の外）
//   - 許可した npm・node の引数のうち `--prefix`・`--script-shell`・`--userconfig`・`--node-options`・`--workspace`・
//     任意の script 名は、宣言の検査では止めていない。実際の強制は sandbox に依る
//   - 誤検出がある（厳しい側）: `-c`・`-r`・`-p` を含む正当な引数（例: 別のツールの `-p`）と、`./` で始まる
//     スクリプトのパス（`./tools/x.mjs`）は拒まれる。パックの側で書き方を変える
//   - 司法の入力名は許可リストで固定するが、名前が正しくても中身が行政の説明でないことは、この検査では確かめない

import { parsePattern } from './taskgraph.mjs';
import { parseWorkItemSpec } from './lib/vocab.mjs';

export const SCHEMA = 'vgdd.domain-pack.v1';

// 各階層で受ける欄（許可リスト）
const TOP_FIELDS = ['schema', 'id', 'title', 'work_item', 'artifact', 'lifecycle', 'audits', 'judiciary', 'protected', 'disclosures'];
const FIELDS = {
  work_item: ['id', 'store', 'spec_sections', 'resource_field'],
  artifact: ['kind', 'integrate'],
  stage: ['stage', 'produces', 'gate', 'status'],
  audit: ['id', 'command', 'required', 'sandbox'],
  judiciary: ['categories', 'min_judges', 'distinct_lineage', 'inputs'],
};
// 統治の核の側の欄。どの階層にあっても違反（大文字小文字は区別しない）
const FORBIDDEN_FIELDS = ['roles', 'capabilities', 'budget', 'stop', 'permissions', 'approvals', 'owner', 'hooks', 'kernel', 'limits', 'policy', 'invariants', 'sandbox_policy'];
const ARTIFACT_KINDS = ['git-tree', 'document-set', 'dataset'];
const INTEGRATES = ['git-ff-merge', 'publish-copy', 'manual'];
const GATES = ['approval', 'judicial', 'none'];
const STAGE_STATUS = ['implemented', 'not_implemented'];

// 司法の入力に使える名前の許可リスト（SPEC §6-1: 機械が集める差分・受け入れ条件・決定論的な監査の結果だけ）。
//   開発:   diff（コードの差分）, acceptance（票の受け入れ条件）, requirements（要件の行）, audit_results（決定論的な監査の結果）
//   文書:   document_diff（文書の差分）, source_list（出典の一覧）, source_excerpts（出典から機械が切り出した抜粋）
// 行政の説明（作業員の報告・コミットの本文・会話・理由づけ）に当たるものは、名前を何にしても入れない。
export const JUDGE_INPUTS = ['diff', 'acceptance', 'requirements', 'audit_results', 'document_diff', 'source_list', 'source_excerpts'];
// 司法の指摘の分類の許可リスト（vgdd/agents/judge.md の category に、文書の例のための citation・overclaim を足した）
export const JUDGE_CATEGORIES = ['requirement', 'correctness', 'security', 'test', 'protected_path', 'input', 'citation', 'overclaim'];
const MAX_JUDGES = 5;

// 監査に使える実行ファイル（許可リスト。今の 2 つの例のパックで実際に要るものだけ。パスを含む形は不可）。
// 増やすには、このファイル（統治の核の側）を改める。
export const AUDIT_EXECUTABLES = ['npm', 'node'];
const NPM_SUBCOMMANDS = ['ci', 'run', 'test'];
// 引数に現れてはならない評価・実行のフラグ（-e -c -p -r --eval --print --require --import exec x など）
const EVAL_ARG = /^(--(eval|print|require|import|exec|loader|experimental-loader|input-type)|exec|x|dlx|npx|run-script)(=.*)?$/;
const SHORT_EVAL_ARG = /^-[a-z]*[ecprx][a-z]*$/;
// 引数の中に現れてはならない名前（シェル・インタプリタ・実行の中継）
const SHELL_NAMES = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'fish', 'csh', 'tcsh', 'cmd', 'powershell', 'pwsh', 'busybox', 'env', 'sudo', 'xargs', 'find', 'time', 'nohup', 'python', 'python3', 'perl', 'ruby', 'php', 'deno', 'bun', 'osascript', 'awk']);
const SCRIPT_PATH = /^[A-Za-z0-9_][A-Za-z0-9_./-]*\.(mjs|js|cjs)$/;

export const REQUIRED_PROTECTED = ['vgdd/**', 'vgdd/next/domains/**'];
export const NO_AUDIT_DISCLOSURE = 'このパックは決定論的な監査を持たない';

const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
const okStr = (x, max = 1000) => typeof x === 'string' && x.trim() !== '' && x.length <= max && !/\p{C}/u.test(x);
const strArr = (x, max) => Array.isArray(x) && x.length <= max && x.every((s) => okStr(s));
const implemented = (st) => isObj(st) && st.status !== 'not_implemented';
const stages = (p) => (Array.isArray(p.lifecycle) ? p.lifecycle.filter(isObj) : []);
const lc = (k) => String(k).toLowerCase();

/** どの階層にある欄名も集める（反復。作業量の上限つき） */
function allKeys(root) {
  const out = [];
  const seen = new Set();
  const stack = [root];
  let budget = 20000;
  while (stack.length && budget-- > 0) {
    const x = stack.pop();
    if (x === null || typeof x !== 'object' || seen.has(x)) continue;
    seen.add(x);
    if (Array.isArray(x)) { for (const v of x) stack.push(v); continue; }
    for (const k of Object.keys(x)) { out.push(k); stack.push(x[k]); }
  }
  return out;
}

// 票の ID は vocab の宣言の形 { prefix, digits: [最小, 最大] }（正規表現は受けない。照合は vocab の makeWorkItemId で線形時間）。
// runstate の config.work_item・trace の ticketId・experience の workItem に、そのまま渡せる（bridge.workItemFromDomainPack）。
// 旧版の id_pattern（正規表現の許可リストの方式）は廃止した（未知の欄として違反）。
export function workItemIdProblem(spec) {
  return parseWorkItemSpec(spec) ? null : '票の ID の宣言 { prefix: ^[A-Za-z][A-Za-z0-9._-]{0,15}$, digits: [最小, 最大]（各 1〜12、最小 ≦ 最大） } でない（ほかの欄は不可）';
}

function commandProblem(cmd) {
  if (!Array.isArray(cmd) || cmd.length === 0 || cmd.length > 16) return 'command は 1〜16 個の引数の配列でなければならない（シェルの文字列は不可）';
  if (cmd.some((a) => typeof a !== 'string' || a === '' || a.length > 256 || /\p{C}/u.test(a))) return 'command に文字列でない・空・長すぎる・制御文字を含む引数がある';
  const exe = cmd[0];
  if (!AUDIT_EXECUTABLES.includes(exe)) return `実行ファイル ${JSON.stringify(exe)} は許可リスト（${AUDIT_EXECUTABLES.join(', ')}）にない。増やすのは統治の核の側の一覧の改正`;
  if (exe === 'npm' && !NPM_SUBCOMMANDS.includes(cmd[1])) return `npm の副命令は ${NPM_SUBCOMMANDS.join('・')} だけ`;
  if (exe === 'node') {
    const s = cmd[1];
    if (typeof s !== 'string' || !SCRIPT_PATH.test(s) || s.split('/').includes('..')) return 'node の第 1 引数は相対パスのスクリプト（.mjs・.js・.cjs）でなければならない（-e などの評価は不可）';
  }
  for (const a of cmd.slice(1)) {
    const t = a.trim().toLowerCase();
    if (EVAL_ARG.test(t) || SHORT_EVAL_ARG.test(t)) return `評価・実行のフラグ ${JSON.stringify(a)} は使えない`;
    const base = t.split(/[\\/]/).pop().replace(/\.exe$/, '');
    if (SHELL_NAMES.has(base) || SHELL_NAMES.has(t)) return `引数にシェル・インタプリタ・実行の中継の名前がある: ${JSON.stringify(a)}`;
  }
  return null;
}

const FINDERS = {
  'DP-SHAPE': (p) => {
    if (!isObj(p)) return ['領域パックがオブジェクトでない'];
    const o = [];
    if (p.schema !== SCHEMA) o.push(`schema が ${SCHEMA} でない`);
    if (typeof p.id !== 'string' || !/^[a-z][a-z0-9-]{0,63}$/.test(p.id)) o.push('id が小文字・数字・ハイフンの文字列（64 字以内）でない');
    if (!okStr(p.title, 200)) o.push('title がない');
    const w = p.work_item;
    if (!isObj(w)) o.push('work_item がオブジェクトでない');
    else {
      if (!isObj(w.id)) o.push('work_item.id が票の ID の宣言（オブジェクト）でない');
      const st = parsePattern(w.store);
      if (!st || st.type !== 'literal') o.push('work_item.store が相対パス（ワイルドカードなし）でない');
      if (!strArr(w.spec_sections, 16) || w.spec_sections.length === 0) o.push('work_item.spec_sections が文字列の配列（1〜16 個）でない');
      if (typeof w.resource_field !== 'string' || !/^[a-z][a-z_]{0,39}$/.test(w.resource_field)) o.push('work_item.resource_field が小文字と _ の文字列でない');
    }
    const a = p.artifact;
    if (!isObj(a) || !ARTIFACT_KINDS.includes(a.kind) || !INTEGRATES.includes(a.integrate)) o.push('artifact の形が違う（kind・integrate は列挙の値だけ）');
    if (!Array.isArray(p.lifecycle) || p.lifecycle.length === 0 || p.lifecycle.length > 32) o.push('lifecycle が 1〜32 個の配列でない');
    else {
      const names = new Set();
      for (const st of p.lifecycle) {
        if (!isObj(st) || !okStr(st.stage, 100) || !okStr(st.produces, 300) || !GATES.includes(st.gate)) { o.push(`lifecycle の段の形が違う: ${isObj(st) ? String(st.stage) : String(st)}`); continue; }
        if (st.status !== undefined && !STAGE_STATUS.includes(st.status)) o.push(`段 ${st.stage} の status が不正: ${String(st.status)}`);
        if (names.has(st.stage)) o.push(`段の名前が重複している: ${st.stage}`);
        names.add(st.stage);
      }
    }
    if (!Array.isArray(p.audits) || p.audits.length > 16) o.push('audits が 16 個以内の配列でない');
    else {
      const ids = new Set();
      for (const au of p.audits) {
        if (!isObj(au) || typeof au.id !== 'string' || !/^[a-z][a-z0-9-]{0,39}$/.test(au.id)) { o.push('audits の項目の id が小文字・数字・ハイフンの文字列でない'); continue; }
        if (ids.has(au.id)) o.push(`監査の id が重複している: ${au.id}`);
        ids.add(au.id);
        if (typeof au.required !== 'boolean') o.push(`監査 ${au.id}: required が真偽値でない`);
        if (typeof au.sandbox !== 'boolean') o.push(`監査 ${au.id}: sandbox が真偽値でない`);
      }
    }
    const j = p.judiciary;
    if (!isObj(j) || !Array.isArray(j.categories) || !Number.isInteger(j.min_judges) || typeof j.distinct_lineage !== 'boolean' || !Array.isArray(j.inputs)) o.push('judiciary の形が違う（categories・min_judges・distinct_lineage・inputs）');
    if (!strArr(p.protected, 64)) o.push('protected が文字列の配列（64 個以内）でない');
    if (!strArr(p.disclosures, 64) || p.disclosures.length === 0) o.push('disclosures が文字列の配列（1〜64 個）でない');
    return o;
  },
  'DP-FORBIDDEN-FIELD': (p) => {
    if (!isObj(p)) return [];
    return [...new Set(allKeys(p).filter((k) => FORBIDDEN_FIELDS.includes(lc(k))))].map((k) => `統治の核の欄 "${k}" をパックが持っている（役割・権限・予算・停止は領域パックの外。どの階層でも不可）`);
  },
  'DP-UNKNOWN-FIELD': (p) => {
    if (!isObj(p)) return [];
    const o = [];
    const bad = (obj, allowed, where) => {
      for (const k of Object.keys(obj)) if (!allowed.includes(k) && !FORBIDDEN_FIELDS.includes(lc(k))) o.push(`未知の欄: ${where}${k}（fail-closed）`);
    };
    bad(p, TOP_FIELDS, '');
    if (isObj(p.work_item)) bad(p.work_item, FIELDS.work_item, 'work_item.');
    if (isObj(p.artifact)) bad(p.artifact, FIELDS.artifact, 'artifact.');
    if (isObj(p.judiciary)) bad(p.judiciary, FIELDS.judiciary, 'judiciary.');
    if (Array.isArray(p.lifecycle)) p.lifecycle.forEach((s, i) => { if (isObj(s)) bad(s, FIELDS.stage, `lifecycle[${i}].`); });
    if (Array.isArray(p.audits)) p.audits.forEach((s, i) => { if (isObj(s)) bad(s, FIELDS.audit, `audits[${i}].`); });
    return o;
  },
  'DP-JUDICIARY-ON': (p) => {
    const j = isObj(p) && p.judiciary;
    if (!isObj(j)) return [];
    const o = [];
    if (Number.isInteger(j.min_judges) && (j.min_judges < 1 || j.min_judges > MAX_JUDGES)) o.push(`judiciary.min_judges が 1〜${MAX_JUDGES} でない（司法を無効にできない）`);
    if (Array.isArray(j.categories)) {
      if (j.categories.length === 0) o.push('judiciary.categories が空');
      const badc = j.categories.filter((c) => !JUDGE_CATEGORIES.includes(c));
      if (badc.length) o.push(`judiciary.categories に許可リストにない分類がある: ${badc.map(String).slice(0, 3).join(', ')}`);
    }
    if (typeof j.distinct_lineage === 'boolean' && j.distinct_lineage !== true) o.push('judiciary.distinct_lineage が true でない（同系統モデルの共謀・同じ見落としへの備えを外せない）');
    if (Array.isArray(p.lifecycle) && !stages(p).some((s) => implemented(s) && s.gate === 'judicial')) o.push('司法の関門（gate: judicial）を持つ実装済みの段が 1 つもない');
    return o;
  },
  'DP-JUDGE-INPUT': (p) => {
    const j = isObj(p) && p.judiciary;
    if (!isObj(j) || !Array.isArray(j.inputs)) return [];
    const o = [];
    if (j.inputs.length === 0) o.push('司法の入力が空（司法が何も見ずに判定することになる）');
    for (const i of j.inputs) if (!JUDGE_INPUTS.includes(i)) o.push(`司法の入力 ${JSON.stringify(i)} は許可リスト（${JUDGE_INPUTS.join(', ')}）にない（行政の説明は入れられない。SPEC §6-1）`);
    return o;
  },
  'DP-GATE-BEFORE-INTEGRATE': (p) => {
    if (!isObj(p) || !Array.isArray(p.lifecycle)) return [];
    const impl = stages(p).filter(implemented);
    if (impl.length === 0) return ['実装済み（関門を持つ）の段が 1 つもない'];
    const last = impl[impl.length - 1];
    return last.gate === 'judicial' || last.gate === 'approval' ? [] : [`成果物を確定させる最後の段 ${last.stage} の gate が none（統合の前の関門を消せない）`];
  },
  'DP-HUMAN-APPROVAL': (p) => {
    if (!isObj(p) || !Array.isArray(p.lifecycle)) return [];
    return stages(p).some((s) => implemented(s) && s.gate === 'approval') ? [] : ['人の承認（gate: approval）を持つ実装済みの段が 1 つもない'];
  },
  'DP-HONEST-STAGE': (p) => {
    if (!isObj(p) || !Array.isArray(p.lifecycle)) return [];
    return stages(p).filter((s) => s.status === 'not_implemented' && s.gate !== 'none').map((s) => `段 ${s.stage} は not_implemented なのに gate が ${s.gate}（持たない関門を持つと主張している）`);
  },
  'DP-AUDIT-SHELL': (p) => {
    if (!isObj(p) || !Array.isArray(p.audits)) return [];
    const o = [];
    for (const a of p.audits) {
      if (!isObj(a)) continue; // 形は DP-SHAPE が見る
      const r = commandProblem(a.command);
      if (r) o.push(`監査 ${String(a.id)}: ${r}`);
    }
    return o;
  },
  'DP-AUDIT-SANDBOX': (p) => {
    if (!isObj(p) || !Array.isArray(p.audits)) return [];
    return p.audits.filter((a) => isObj(a) && a.sandbox !== true).map((a) => `監査 ${String(a.id)}: sandbox が true でない（作業員の書いたコードを sandbox の外で動かしうる。許可した実行ファイルの安全は sandbox に依る）`);
  },
  'DP-DISCLOSE-NO-AUDIT': (p) => {
    if (!isObj(p) || !Array.isArray(p.audits) || !Array.isArray(p.disclosures)) return [];
    if (p.audits.some((a) => isObj(a) && a.required === true && !commandProblem(a.command))) return [];
    return p.disclosures.some((d) => typeof d === 'string' && d.startsWith(NO_AUDIT_DISCLOSURE))
      ? [] : [`必須の決定論的な監査が 1 つもないのに、disclosures に「${NO_AUDIT_DISCLOSURE}」で始まる公開がない（約束だけのものは公開する。SPEC §1-3）`];
  },
  'DP-PROTECTED-CORE': (p) => {
    if (!isObj(p) || !Array.isArray(p.protected)) return [];
    const o = REQUIRED_PROTECTED.filter((r) => !p.protected.includes(r)).map((r) => `protected に統治の核のパス ${r} がない（パックが自分や核を書き換えられる構成にしない）`);
    for (const e of p.protected) if (!parsePattern(e)) o.push(`protected の ${JSON.stringify(e)} は扱える形（literal・dir/**・prefix*）でない（否定・.. ・先頭の / ・[?{}] は不可）`);
    return o;
  },
  'DP-WORK-ITEM-ID': (p) => {
    const spec = isObj(p) && isObj(p.work_item) && p.work_item.id;
    if (!isObj(spec)) return []; // 形は DP-SHAPE が見る
    const r = workItemIdProblem(spec);
    return r ? [`work_item.id ${JSON.stringify(spec).slice(0, 80)}: ${r}`] : [];
  },
};

export const GUARDS = Object.fromEntries(
  Object.entries(FINDERS).map(([n, f]) => [n, (ctx) => { const r = safe(f, ctx.pack); return r.length ? r.join(' / ') : null; }]),
);

/** 検査が例外を投げたら違反として返す（fail-closed） */
function safe(f, pack) {
  try { return f(pack); } catch (e) { return [`検査が例外を投げた（拒否する）: ${String(e && e.message).slice(0, 80)}`]; }
}

/** ctx = { pack }。既定は全ガード。guardNames は bench だけが絞る */
export function check(ctx, guardNames = Object.keys(GUARDS)) {
  const violations = [];
  for (const g of guardNames) {
    if (!FINDERS[g]) throw new Error(`未知のガード: ${g}`);
    for (const reason of safe(FINDERS[g], ctx && ctx.pack)) violations.push({ guard: g, reason });
  }
  return { ok: violations.length === 0, violations };
}

export function validateDomainPack(pack) {
  const { ok, violations } = check({ pack });
  const warnings = [];
  try {
    if (isObj(pack) && Array.isArray(pack.lifecycle)) {
      const ni = stages(pack).filter((s) => s.status === 'not_implemented');
      if (ni.length) warnings.push(`未実装の段（関門の数に数えない）: ${ni.map((s) => String(s.stage)).join(', ')}`);
    }
  } catch { /* 警告は補足。落とさない */ }
  return { ok, violations, warnings };
}
