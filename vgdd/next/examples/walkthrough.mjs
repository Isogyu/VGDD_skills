// 8 つの部品を 1 つの流れでつなぐ見本（起草段階の試作。法律ではない）
//
// 実行：node vgdd/next/examples/walkthrough.mjs   （終了コード 0。各段で何が起き、何が拒まれたかを日本語で出す）
// 試験：vgdd/next/test/integration.test.mjs が、ここで export する runWalkthrough を呼んで中身を確かめる。
//
// これは起草段階の試作の見本で、行為者は呼び出し側の申告であり、稼働中の Kernel にはつないでいない。
//
// 題材：3 つの票（T-101 と T-102 は独立、T-103 は両方に依存。T-102 は security_review つき）を、開発の領域パックで進める。
// 各段の出力を、次の段の入力に実際に使う。部品どうしの書式が合わない箇所は、この見本の側で値を変換し、
// 変換を adapt() で 1 件ずつ記録する（result.adaptations）。変換が要ること自体が、部品の間の食い違いである。
// 部品（vgdd/next/*.mjs・lib/）は 1 行も変えていない。

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { digest, sha256, openChain, Refused } from '../lib/chain.mjs';
import { validateDomainPack } from '../domain.mjs';
import { validateTeam, catalogFromCapabilities } from '../team.mjs';
import { buildGraph } from '../taskgraph.mjs';
import { openRun } from '../runstate.mjs';
import { openExperience } from '../experience.mjs';
import { openTrace } from '../trace.mjs';
import { openImprovements, policyLineOf, CAPS_PATH } from '../improvement.mjs';
import { authorityDelta, routeFor, formatDelta } from '../authority-delta.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const NEXT_DIR = path.resolve(HERE, '..');
export const CAPS_FILE = path.resolve(NEXT_DIR, '../kernel/capabilities.json');
export const PACK_FILE = path.resolve(NEXT_DIR, 'domains/software-dev.json');

/** 題材の票（票の ID は大文字。runstate の節の id は小文字だけなので、変換が要る） */
export const TICKETS = [
  { id: 'T-101', req: 'R-1', deps: [], resources: ['src/a/**'], security: false },
  { id: 'T-102', req: 'R-2', deps: [], resources: ['src/b/**'], security: true },
  { id: 'T-103', req: 'R-3', deps: ['T-101', 'T-102'], resources: ['src/c/**'], security: false },
];

const clone = (v) => JSON.parse(JSON.stringify(v));
const sha40 = (s) => sha256(s).slice(0, 40); // 申請・統合のコミットの代用（git の SHA は 40 桁）

/** 拒否の情報（Refused の code と、違反したガードの名前）を取り出す */
export function refusalOf(e) {
  // runstate・improvement・trace の Refused は violations（ガードごとの配列）を持つが、experience の Refused は持たない（message の文字列だけ）
  const hasViolations = Array.isArray(e && e.violations);
  const guards = hasViolations ? e.violations.map((v) => v.guard) : [...new Set(String((e && e.message) || '').match(/[A-Z]{2,}(?:-[A-Z0-9]+)+/g) || [])];
  return { code: e && e.code, guards, hasViolations, message: String((e && e.message) || e).slice(0, 200) };
}

/**
 * 流れの全体を動かす。dir は一時ディレクトリ（なければ os.tmpdir() の下に作る）。log(段, 文) は経過の出力。
 * 想定外（通るはずが拒まれた・拒まれるはずが通った）は例外で止める。
 * @returns 各段の結果（試験が検査する）
 */
export function runWalkthrough({ dir = null, log = () => {} } = {}) {
  const root = dir || fs.mkdtempSync(path.join(os.tmpdir(), 'vgdd-next-walk-'));
  fs.mkdirSync(root, { recursive: true });
  const files = { run: path.join(root, 'run.jsonl'), experience: path.join(root, 'experience.jsonl'), trace: path.join(root, 'trace.jsonl'), improvement: path.join(root, 'improvement.jsonl') };

  // ---- 変換の記録 ----
  const adaptations = [];
  const seenAdapt = new Map();
  /** 部品の書式に合わせて値を変えたときに呼ぶ。同じ (what, from) は 1 件にまとめる。変えた後の値を返す */
  function adapt(what, from, to, why) {
    const k = `${what}|${JSON.stringify(from)}`;
    if (!seenAdapt.has(k)) { const a = { what, from, to, why, count: 1 }; seenAdapt.set(k, a); adaptations.push(a); } else seenAdapt.get(k).count += 1;
    return to;
  }
  const refusals = [];
  /** 拒まれるはずの操作。通ったら例外。拒否を記録する */
  function mustRefuse(stage, label, fn) {
    try { fn(); } catch (e) {
      if (!(e instanceof Refused)) throw e;
      const r = { stage, label, ...refusalOf(e) };
      refusals.push(r);
      log(stage, `  拒まれた：${label} → ${r.guards.length ? r.guards.join('・') : r.code}`);
      return r;
    }
    throw new Error(`拒まれるはずが通った: ${label}`);
  }

  // ---- 行為者：同じ主体でも、部品ごとに受ける形と role の名前が違う ----
  const A = {
    runstate: {
      owner: { role: 'owner', kind: 'human', id: 'azuki' },
      head: { role: adapt('行政の長の役割名', 'executive_head（team の catalog・capabilities.json）', 'executive', 'runstate.mjs:76 ROLES は owner/executive/night_agent/court/reaper の 5 つだけ'), kind: 'ai', id: 'exec-head' },
      night: { role: adapt('夜間の代行の役割名', 'night_runner（team の catalog）', 'night_agent', 'runstate.mjs:76'), kind: 'script', id: 'night-runner' },
      court: { role: adapt('裁判所のスクリプトの役割名（runstate 用）', 'gate_runner（capabilities.json・trace・team）', 'court', 'runstate.mjs:76'), kind: 'script', id: 'court-script' },
    },
    experience: {
      owner: { role: 'owner', kind: 'human', id: 'azuki' },
      head: { role: 'executive_head', kind: 'ai', id: 'exec-head' }, // experience は role を自由に受ける（形だけ）
      court: { role: 'court', kind: 'script', id: 'court-script' },
    },
    improvement: {
      // lineage が必須。人は 'human'、人以外は 'human' 以外（experience・runstate は lineage を行為者に持たない／拒む）
      owner: { role: 'owner', kind: 'human', id: 'azuki', lineage: adapt('人の lineage', '（runstate・experience・trace の行為者に lineage はない）', 'human', 'improvement.mjs:441-447 IM-ACTOR-SHAPE') },
      head: { role: 'executive_head', kind: 'ai', id: 'exec-head', lineage: 'claude' },
      court: { role: 'court', kind: 'script', id: 'court-script', lineage: adapt('スクリプトの lineage', '（スクリプトに系統はない）', 'script', 'improvement.mjs:443 lineage が必須。human 以外なら何でもよい') },
      judgeCodex: { role: 'codex_judge', kind: 'ai', id: 'judge-codex', lineage: 'codex' },
      constClaude: { role: 'constitutional_review', kind: 'ai', id: 'const-review', lineage: 'claude' }, // 実際の憲法審査は Claude（capabilities.json の identity）
    },
    trace: {
      owner: { role: 'owner', kind: 'human', id: 'azuki' },
      head: { role: 'executive', kind: 'ai', id: 'exec-head' },
      court: { role: adapt('裁判所のスクリプトの役割名（trace 用）', 'court（runstate）', 'court_script', 'trace.mjs:140 SCRIPT_ROLES は gate_runner/release_script/trace_importer/court_script。court は不可'), kind: 'script', id: 'court-script' },
    },
  };

  // =====================================================================
  // 段 1　領域パック
  // =====================================================================
  const caps = JSON.parse(fs.readFileSync(CAPS_FILE, 'utf8'));
  const pack = JSON.parse(fs.readFileSync(PACK_FILE, 'utf8'));
  const packResult = validateDomainPack(pack);
  if (!packResult.ok) throw new Error(`領域パックが通らない: ${JSON.stringify(packResult.violations)}`);
  const idRe = new RegExp(pack.work_item.id_pattern);
  for (const t of TICKETS) if (!idRe.test(t.id)) throw new Error(`票の ID が領域パックの id_pattern に合わない: ${t.id}`);
  log(1, `領域パック ${pack.id} を検査：通った（警告 ${packResult.warnings.length} 件）。票の ID の形 ${pack.work_item.id_pattern}、範囲の欄 ${pack.work_item.resource_field}、司法 ${pack.judiciary.min_judges} 人以上・系統は別`);
  const policyLine = policyLineOf(caps); // 'p0.4'
  if (!policyLine) throw new Error('法律の系統が読めない');
  log(1, `  法律の系統：${caps.kernel_version} → ${policyLine}（improvement.policyLineOf。runstate・authority-delta は同じ書式を別々に持つ）`);

  // =====================================================================
  // 段 2　編成
  // =====================================================================
  const catalog = catalogFromCapabilities(caps);
  const WORK_TOOLS = ['Read', 'Edit', 'Write', 'Bash', 'Glob', 'Grep'];
  const ticketResources = TICKETS.flatMap((t) => t.resources);
  const teamPlan = {
    task: 'T-101・T-102・T-103 を進める',
    proposed_by: { role: 'executive_head', kind: 'ai', id: 'exec-head' },
    members: [
      { id: 'exec-head', template: 'executive_head', scope: { resources: ticketResources, tools: [...WORK_TOOLS, 'Agent'] } },
      { id: 'worker-1', template: 'worker', parent: 'exec-head', scope: { resources: ['src/a/**', 'src/c/**'], tools: WORK_TOOLS } },
      { id: 'worker-2', template: 'worker', parent: 'exec-head', scope: { resources: ['src/b/**'], tools: WORK_TOOLS } },
      { id: 'judge-claude', template: 'judge', scope: { resources: [], tools: [] } },
      // codex の security 審査は、team の catalog に役割がない（capabilities.json に codex_security がない）ので、codex_judge の 1 体が judge と security の両方を担う前提
      { id: 'judge-codex', template: adapt('codex の security 審査の役割', 'codex-security（trace の判定の種類・runstate の kind: security）', 'codex_judge', 'team の catalog（capabilities.json の roles）に security 専用の役割がない'), scope: { resources: [], tools: [] } },
    ],
  };
  /** 票の ID を runstate の節の id（小文字だけ）に写す。ここで変換が起きる */
  const nid = (t) => { adapt('票の ID（大文字 → 小文字）', 'T-NNN（領域パックの id_pattern・trace・experience の形）', 't-nnn', 'runstate.mjs:93 NODE_RE は小文字だけ。:40 のコメントが「大文字を含む票の id は呼び出し側で写す」と明記している'); return t.toLowerCase(); };
  const graphForTeam = buildGraph(TICKETS.map((t) => ({
    id: nid(t.id), status: 'ready', depends_on: t.deps.map(nid), resources: t.resources, approved: true,
  })));
  if (!graphForTeam.ok) throw new Error('taskgraph が通らない');
  const teamContext = {
    catalog,
    ticket: { resources: ticketResources },
    // team.limits.workers は「行政の member の総数（長を含む）」。runstate.config.workers は「同時に動かす作業の数」で、意味が違う（長 1 ＋ 作業員 2 ＝ 3、同時は 2）
    limits: { workers: 3, depth: 2, members_total: 16 },
    graph: graphForTeam.graph,
  };
  const teamResult = validateTeam(teamPlan, teamContext);
  if (!teamResult.ok) throw new Error(`編成案が通らない: ${JSON.stringify(teamResult.violations)}`);
  log(2, `編成案を検査：通った。requires_approval=${teamResult.requires_approval}、effect=${teamResult.effect}、警告 ${teamResult.warnings.length} 件`);
  const teamRefusal = validateTeam({ ...teamPlan, members: [...teamPlan.members, { id: 'court', template: 'gate_runner', scope: { resources: [], tools: [] } }] }, teamContext);
  if (teamRefusal.ok) throw new Error('裁判所を編成に入れた案が通った');
  log(2, `  拒まれた：裁判所（gate_runner）を編成に入れる案 → ${teamRefusal.violations.map((v) => v.guard).join('・')}`);
  refusals.push({ stage: 2, label: '裁判所（gate_runner）を編成に入れる案（team は例外でなく { ok:false, violations } を返す）', code: null, guards: teamRefusal.violations.map((v) => v.guard), hasViolations: true });

  // =====================================================================
  // 段 3　実行の記録
  // =====================================================================
  const run = openRun(files.run);
  let eid = 0;
  const rsApply = (actor, ev) => run.apply(actor, { event_id: `ev-${++eid}`, ...ev });
  rsApply(A.runstate.owner, {
    op: 'config', hold: false, max_attempts: 4, max_returns: 3, max_unavailable: 3, workers: 2, lease_sec: 21600,
    policy_line: policyLine,
    // 必須の審査は claude と codex の judge、security は codex。領域パックの judiciary（min_judges 2・別系統）からは自動で作られない（手で写す）
    judiciary: [{ kind: 'judge', lineage: 'claude' }, { kind: 'judge', lineage: 'codex' }], security_lineage: 'codex',
  });
  if (pack.judiciary.min_judges !== 2) throw new Error('領域パックの司法の数と config が合わない');
  log(3, 'オーナーが config を記録：必須の審査は claude と codex の judge、security は codex、同時 2、法律の系統 ' + policyLine);

  rsApply(A.runstate.head, {
    op: 'plan',
    nodes: TICKETS.map((t) => ({ id: nid(t.id), depends_on: t.deps.map(nid), resources: t.resources, ...(t.security ? { security_review: true } : {}) })),
  });
  log(3, `行政の長が plan：節 ${TICKETS.length} つ（resources は票の範囲。T-102 は security_review つき）。未承認で始まる`);

  const specDigest = {}; const approveHash = {};
  for (const t of TICKETS) {
    specDigest[t.id] = digest({ ticket: t.id, acceptance: `${t.req} を満たす`, files_allowed: t.resources }); // 仕様の指紋（Kernel の spec-digest に相当する値を作る）
    // def_digest は runstate が節の定義から内部で計算する値で、export されていない。state() の節から読み写す
    const def = run.state().nodes[nid(t.id)].def_digest;
    adapt('節の定義の指紋（approve の def_digest）', '（呼び出し側が計算できる関数は export されていない）', 'state().nodes[id].def_digest を読み写す', 'runstate.mjs:193 defDigest は非公開');
    rsApply(A.runstate.owner, { op: 'approve', node: nid(t.id), spec_digest: specDigest[t.id], policy_line: policyLine, def_digest: def });
  }
  log(3, 'オーナーが 3 節を approve（仕様の指紋と法律の系統に結び付く）');

  const next1 = run.next();
  if (JSON.stringify([...next1.start].sort()) !== JSON.stringify(['t-101', 't-102'])) throw new Error(`next() の着手の組が想定と違う: ${JSON.stringify(next1.start)}`);
  log(3, `next()：着手の組 ${next1.start.join('・')}、構成の勧め ${next1.recommend.topology}（作業員 ${next1.recommend.workers}）、待ち ${next1.waiting.map((w) => `${w.id}[${w.reasons.join(',')}]`).join(' ')}`);

  // =====================================================================
  // 段 4　経験（着手の前の取り出し。最初は空）
  // =====================================================================
  const exp = openExperience(files.experience);
  const retrieveFor = (task, text) => exp.retrieve({ audience: { role: 'worker', task }, query: { text, tags: ['test'], domain: pack.id }, limit: 5, maxChars: 3000 });
  const r101 = retrieveFor('T-101', '境界値 試験 入力の上限');
  const r102 = retrieveFor('T-102', '境界値 試験 入力の上限');
  if (r101.items.length || r102.items.length || r101.rendered !== '') throw new Error('最初の取り出しが空でない');
  log(4, `着手の前に、作業員の役割（worker）で経験を取り出した：T-101・T-102 とも空（searchKind=${r101.searchKind}）。作業員への指示に添える文字列は ''`);

  // =====================================================================
  // 段 5　申請と判定
  // =====================================================================
  const req = { 'T-101': [sha40('request:T-101:1'), sha40('request:T-101:2')], 'T-102': [sha40('request:T-102:1')], 'T-103': [sha40('request:T-103:1')] };
  const J = (kind, lineage, verdict, major = false) => ({ kind, judge: `${kind}-${lineage}`, lineage, verdict, major });

  rsApply(A.runstate.head, { op: 'start', node: 't-101', spec_digest: specDigest['T-101'], lease_sec: 3600 });
  rsApply(A.runstate.night, { op: 'start', node: 't-102', spec_digest: specDigest['T-102'], lease_sec: 3600 });
  log(5, 'T-101 は行政の長（昼）、T-102 は夜間の代行が着手。作業員 2 体は runstate の行為者になれないので、起こした側の id が worker として記録される');

  rsApply(A.runstate.head, { op: 'submit', node: 't-101', request: req['T-101'][0] });
  const v1 = rsApply(A.runstate.court, { op: 'verdict', node: 't-101', request: req['T-101'][0], audits: 'passed', verdicts: [J('judge', 'claude', 'CHANGES_REQUIRED'), J('judge', 'codex', 'CHANGES_REQUIRED', true)] });
  if (v1.kind !== 'return' || v1.to !== 'in_progress') throw new Error(`1 回目の判定が差し戻しでない: ${JSON.stringify(v1)}`);
  log(5, `T-101 を申請 → 裁判所のスクリプトが verdict を取り込み：claude も codex も CHANGES_REQUIRED（codex は重大）→ ${v1.kind}（in_progress に戻る。差し戻し ${v1.node.returns} 回）`);
  rsApply(A.runstate.head, { op: 'submit', node: 't-101', request: req['T-101'][1] });
  const v2 = rsApply(A.runstate.court, { op: 'verdict', node: 't-101', request: req['T-101'][1], audits: 'passed', verdicts: [J('judge', 'claude', 'APPROVED'), J('judge', 'codex', 'APPROVED')] });
  if (v2.kind !== 'pass' || v2.to !== 'merged') throw new Error('T-101 の再申請が合格でない');
  log(5, `T-101 を再申請 → ${v2.kind}（${v2.to}）`);

  rsApply(A.runstate.night, { op: 'submit', node: 't-102', request: req['T-102'][0] });
  const v3 = rsApply(A.runstate.court, { op: 'verdict', node: 't-102', request: req['T-102'][0], audits: 'passed', verdicts: [J('judge', 'claude', 'APPROVED'), J('judge', 'codex', 'APPROVED'), J('security', 'codex', 'APPROVED')] });
  if (v3.kind !== 'pass') throw new Error('T-102 が合格でない');
  log(5, `T-102 を夜間の代行が申請 → security 審査（codex）を含めて ${v3.kind}（${v3.to}）`);

  // =====================================================================
  // 段 6　経験の蓄積（T-103 の着手の前に、昇格した経験が引用の形で出る）
  // =====================================================================
  const rowsAfter5 = openChain(files.run).read(); // runstate は申請の指紋・承認の行の hash を公開の窓口で返さない。記録のファイルから読む
  adapt('runstate の記録の行', '（apply・state・summary は seq と at しか返さない）', 'openChain(file).read() で記録のファイルを直接読む', 'runstate.mjs:858 apply の戻り値に hash がない。差し戻された申請の指紋は state() から消える（:266 request: null）');
  const vrdId = (request, kind, lineage) => `VRD-${request.slice(0, 12)}-${modeOf(kind, lineage)}`;
  const modeOf = (kind, lineage) => {
    const m = { 'judge:claude': 'judge', 'judge:codex': 'codex-judge', 'security:codex': 'codex-security' }[`${kind}:${lineage}`];
    if (!m) throw new Error(`trace の判定の種類に写せない（${kind}:${lineage}）`);
    return adapt('判定の種類', `${kind}:${lineage}（runstate の verdicts）`, m, 'trace.mjs:82・733 は judge/codex-judge/codex-security/codex-ux の 4 つだけ。runstate の（種類, 系統）の組と対応する関数はない');
  };
  const expActor = A.experience.court;
  // 司法の指摘の本文と重さは runstate の記録にない（verdicts の項目は kind・judge・lineage・verdict・major だけ）。裁判所のスクリプトが判定のファイルから読む前提で、ここでは外から与える
  const findings = {
    t101: { text: '入力の上限の境界値（上限ちょうど・1 つ上）の試験がない。境界値の試験を先に書くこと', ref: `${vrdId(req['T-101'][0], 'judge', 'codex')}#finding-1`, task: 'T-101' },
    t102: { text: '入力の上限の直前の値の試験が薄い。境界値の試験を足すこと', ref: `${vrdId(req['T-102'][0], 'judge', 'codex')}#finding-2`, task: 'T-102' },
    t090: { text: '上限の境界値が未検証だった。境界値の試験を先に書くこと', ref: 'VRD-0123456789ab-codex-judge#finding-1', task: 'T-090' }, // 過去の票（この流れの外）の想定
  };
  adapt('出どころの ref', '（runstate に判定の id も指摘の番号もない）', '判定の id（trace の VRD-…）＋ #finding-N という規約を、見本の側で決めた', 'experience.mjs:84 REF_RE は書式だけ。実在は確かめない');
  const scope = { domain: pack.id, roles: ['worker'], tags: ['test', 'boundary'] };
  adapt('経験の領域（domain）', '領域パックの id（software-dev）', 'scope.domain と retrieve の query.domain に同じ文字列を入れる', 'experience.mjs:393 EX-SERVE は domain の完全一致。領域パックとの対応を確かめる関数はない');
  const refl = Object.values(findings).map((f) => exp.add(expActor, { text: f.text, scope, provenance: [{ kind: 'verdict_finding', ref: f.ref, task: f.task }] }));
  log(6, `T-101 の差し戻しの指摘から reflection を追加（出どころ＝判定の指摘。trust=${refl[0].trust}、status=${refl[0].status}）。T-102・過去の票 T-090 の指摘も追加`);
  const induced = exp.induce(expActor, { from: refl.map((x) => x.id), text: '境界値（上限ちょうど・1 つ上）の試験を、実装より先に書く', scope });
  const insp = exp.inspect(induced.id);
  const promoted = exp.promote(A.experience.owner, induced.id, { digest: insp.digest });
  log(6, `3 件の reflection（別々の票）から induce → ${induced.id}（candidate）。オーナーが昇格 → ${promoted.status}`);

  const r103 = retrieveFor('T-103', '境界値 試験 入力の上限');
  const first = r103.items[0];
  if (!first || first.id !== induced.id || first.status !== 'adopted') throw new Error('昇格した経験が先頭に出ない');
  if (!r103.rendered.includes('引用') || !r103.rendered.includes('```text') || !r103.rendered.includes(induced.id)) throw new Error('経験が引用の形で出ない');
  log(6, `T-103 の着手の前に retrieve：${r103.items.length} 件。先頭は ${first.id}（${first.trust}・${first.status}）。引用の囲みつきの文字列 ${r103.rendered.length} 字を作業員への指示に添える`);

  rsApply(A.runstate.head, { op: 'start', node: 't-103', spec_digest: specDigest['T-103'], lease_sec: 3600 });
  rsApply(A.runstate.head, { op: 'submit', node: 't-103', request: req['T-103'][0] });
  const v4 = rsApply(A.runstate.court, { op: 'verdict', node: 't-103', request: req['T-103'][0], audits: 'passed', verdicts: [J('judge', 'claude', 'APPROVED'), J('judge', 'codex', 'APPROVED')] });
  if (v4.kind !== 'pass') throw new Error('T-103 が合格でない');
  log(6, `T-103（T-101・T-102 の統合後に着手できた）→ ${v4.kind}（${v4.to}）`);
  const fb = exp.feedback(A.experience.court, { item_ids: [induced.id], outcome: 'helpful', evidence: { kind: 'verdict', ref: vrdId(req['T-103'][0], 'judge', 'claude'), task: 'T-103' } });
  log(6, `裁判所のスクリプトが feedback（helpful、証拠＝T-103 の判定）→ ${induced.id} の helpful=${fb[0].helpful}`);
  const judgeAsk = exp.retrieve({ audience: { role: 'judge', task: 'T-103' }, query: { text: '境界値', domain: pack.id } });
  if (!judgeAsk.refused || judgeAsk.items.length) throw new Error('司法の役割に経験が渡った');
  log(6, `  拒まれた：司法（judge）の役割への retrieve → 例外でなく { refused } で返る（${judgeAsk.refused.slice(0, 30)}…）`);
  refusals.push({ stage: 6, label: '司法（judge）の役割への経験の取り出し（retrieve は例外でなく { refused } を返す）', code: null, guards: ['EX-RETRIEVE-JUDGE'], hasViolations: false });

  // =====================================================================
  // 段 7　追跡
  // =====================================================================
  const rows = openChain(files.run).read();
  const rowOf = (op, node, request) => rows.find((r) => r.op === op && r.node === node && (request === undefined || r.request === request));
  const tr = openTrace(files.trace);
  const tw = (rel, from, to, evidence) => tr.link(A.trace.court, { rel, from, to, ...(evidence ? { evidence } : {}) });
  const traceTicket = (t) => ({ kind: 'ticket', id: t.id });
  const mergeSha = {}; const accId = {};
  const linkCount = { n: 0 };
  const twc = (...a) => { linkCount.n += 1; return tw(...a); };
  twc('derives', { kind: 'experience', id: refl[0].id }, { kind: 'verdict', id: vrdId(req['T-101'][0], 'judge', 'codex') });
  adapt('追跡の判定・監査の id', '（runstate の記録に判定の id も監査の id もない）', 'VRD-<申請の先頭 12 桁>-<種類>、AUD-<申請の先頭 12 桁>', 'trace.mjs:81-82 の書式。12 桁は Kernel の判定ファイル名の head（judge.sh）に合わせた');
  twc('satisfies', { kind: 'requirement', id: 'R-1' }, { kind: 'goal', id: 'G-1' });
  twc('satisfies', { kind: 'requirement', id: 'R-2' }, { kind: 'goal', id: 'G-1' });
  twc('satisfies', { kind: 'requirement', id: 'R-3' }, { kind: 'goal', id: 'G-1' });
  for (const t of TICKETS) {
    const node = t.id.toLowerCase();
    twc('satisfies', traceTicket(t), { kind: 'requirement', id: t.req });
    for (const d of t.deps) twc('depends_on', traceTicket(t), traceTicket({ id: d }));
    twc('specifies', { kind: 'spec', id: specDigest[t.id], digest: specDigest[t.id] }, traceTicket(t));
    const ap = rowOf('approve', node);
    approveHash[t.id] = `sha256:${ap.hash}`;
    adapt('承認の指紋', '記録の行の hash（接頭辞なしの 64 桁）', 'sha256: を付けた形', 'trace.mjs:71・78 の承認の id は sha256:<64桁>。runstate の行の hash は接頭辞なし');
    twc('approves', { kind: 'approval', id: approveHash[t.id], digest: approveHash[t.id] }, { kind: 'spec', id: specDigest[t.id], digest: specDigest[t.id] });
    for (const request of req[t.id]) {
      const sub = rowOf('submit', node, request);
      if (!sub) throw new Error(`runstate の記録に申請がない: ${request}`);
      const vd = rowOf('verdict', node, request);
      twc('implements', { kind: 'request', id: request }, { kind: 'spec', id: specDigest[t.id], digest: specDigest[t.id] }, { no_codex: false, security_required: t.security });
      twc('verifies', { kind: 'audit', id: `AUD-${request.slice(0, 12)}` }, { kind: 'request', id: request }, { result: vd.audits, at: vd.at });
      for (const v of vd.verdicts) twc('verifies', { kind: 'verdict', id: vrdId(request, v.kind, v.lineage) }, { kind: 'request', id: request }, { result: v.verdict, at: vd.at });
    }
    const finalReq = req[t.id][req[t.id].length - 1];
    mergeSha[t.id] = sha40(`merge:${t.id}`);
    adapt('統合のコミット', '（runstate の merged は SHA を持たない）', '40 桁の値を外から用意（git の HEAD に当たる）', 'runstate.mjs:319・trace.mjs:84 merge の id は 40 桁。runstate の記録に統合の SHA はない');
    twc('integrates', { kind: 'merge', id: mergeSha[t.id] }, { kind: 'request', id: finalReq });
    accId[t.id] = `ACC-${sha256(`acceptance:${mergeSha[t.id]}`).slice(0, 16)}`;
    twc('approves', { kind: 'acceptance', id: accId[t.id] }, { kind: 'merge', id: mergeSha[t.id] });
  }
  log(7, `裁判所のスクリプトが trace に ${linkCount.n} 本のつながりを書いた（要件→票→仕様の指紋→承認→申請→監査・判定→統合→受け入れ。runstate の記録の指紋・申請・判定を使用）`);

  const expected = { expectedRequirements: ['R-1', 'R-2', 'R-3'], expectedTickets: TICKETS.map((t) => t.id) };
  const cov = tr.coverage(expected);
  const gaps1 = tr.gaps(expected);
  const stageNames = ['ticket', 'spec', 'approval', 'request', 'audit', 'verdict', 'merge', 'acceptance'];
  for (const row of cov.rows) {
    const missing = stageNames.filter((s) => !row.stages[s]);
    if (missing.length) throw new Error(`${row.requirement} の段がそろわない: ${missing.join(',')}`);
  }
  const r1 = cov.rows.find((r) => r.requirement === 'R-1');
  if (r1.returned_requests !== 1 || r1.approved_requests !== 1) throw new Error('差し戻された 1 回目の申請が見えない');
  log(7, `coverage：3 つの要件とも 票・仕様・承認・申請・監査・判定・統合・受け入れ がそろう。R-1 は 申請 ${r1.requests} 件のうち 差し戻し ${r1.returned_requests}・承認 ${r1.approved_requests}`);
  const gapCodes1 = gaps1.gaps.map((g) => `${g.code}:${g.id.slice(0, 12)}`);
  log(7, `gaps：${gaps1.count} 件 ${gapCodes1.join('、')}（差し戻された 1 回目の申請が「差し戻し」として見える）`);

  const incident = { kind: 'incident', id: 'INC-001' };
  twc('caused_by', incident, { kind: 'merge', id: mergeSha['T-103'] });
  const gaps2 = tr.gaps(expected);
  const incGap = gaps2.gaps.find((g) => g.code === 'INCIDENT_NO_TICKET');
  if (!incGap) throw new Error('障害の対応の票がないことが gaps に出ない');
  const cov2 = tr.coverage(expected);
  log(7, `障害 INC-001（T-103 の統合に起因）を足した → gaps に ${incGap.code}（対応の票がない）。R-3 の障害 ${JSON.stringify(cov2.rows.find((r) => r.requirement === 'R-3').incidents)}`);

  // =====================================================================
  // 段 8　改善提案
  // =====================================================================
  const im = openImprovements(files.improvement, { currentCapabilities: caps });
  const playbook = im.propose(A.improvement.head, {
    title: '作業員の手順：境界値の試験を先に書く', tier: 'playbook', target: { name: 'worker-playbook' },
    content: { step: '実装の前に、上限ちょうど・1 つ上の境界値の試験を書く', derived_from: [induced.id] },
    rationale: `${refl[0].id}（T-101 の差し戻し）から`,
  });
  const GOOD = { before: { total: 100, passed: 100 }, after: { total: 102, passed: 102 }, new_cases_fail_on_before: 2 };
  const evalOf = (p) => im.evaluate(A.improvement.court, p.id, { digest: im.get(p.id).digest, evidence: { conformance: GOOD, notes: '足した 2 件は前の版で落ちる' } });
  const reviewOf = (p, who = A.improvement.judgeCodex, verdict = 'APPROVED') => im.review(who, p.id, { digest: im.get(p.id).digest, verdict, findings: [], review_input_digest: im.reviewInputFor(p.id).digest });
  evalOf(playbook);
  reviewOf(playbook);
  const adopted = im.adopt(A.improvement.owner, playbook.id, { digest: im.get(playbook.id).digest, policy_line: policyLine });
  if (adopted.status !== 'adopted' || !im.adoptionValid(playbook.id)) throw new Error('手順の改善が採用されない');
  log(8, `行政の長が ${playbook.id}（playbook）を提案 → 裁判所のスクリプトが評価（試験 ${GOOD.before.total}→${GOOD.after.total}、足した試験が前の版で落ちる ${GOOD.new_cases_fail_on_before} 件）→ codex の judge が審査 → オーナーが採用`);
  twc('derives', { kind: 'improvement', id: playbook.id }, { kind: 'experience', id: induced.id });
  adapt('改善提案の id と経験の id', 'IMP-0001・exp-000004（improvement・experience の書式）', 'そのまま trace に使える', 'trace.mjs:88-89 は両者の書式を取り込んである（変換不要の例）');

  const looser = clone(caps); looser.capabilities.find((c) => c.id === 'CAP-MAIN-INTEGRATE').allowed.push('worker');
  const dLoose = authorityDelta(caps, looser);
  const lawLoose = im.propose(A.improvement.head, { title: '作業員に main への統合を許す', tier: 'law', target: { paths: [CAPS_PATH] }, content: { capabilities: looser }, capabilities: { old: caps, new: looser } });
  evalOf(lawLoose); reviewOf(lawLoose);
  if (dLoose.class !== 'loosening' || lawLoose.route.lane !== 'full_legislative') throw new Error('緩める変更が緩めると分類されない');
  log(8, `法律の変更「作業員に main への統合を許す」→ authority-delta：${dLoose.class}、経路 ${routeFor(dLoose).lane}`);
  const adoptLoose = (id) => im.adopt(A.improvement.owner, id, { digest: im.get(id).digest, policy_line: policyLine });
  mustRefuse(8, '緩める法律の変更を、通常の審査（codex の judge）とオーナーの承認だけで採用', () => adoptLoose(lawLoose.id));
  mustRefuse(8, '憲法審査（実際は Claude 系統）の審査。提案者と同じ系統なので審査できない', () => reviewOf(im.get(lawLoose.id), A.improvement.constClaude));

  const tighter = clone(caps); tighter.capabilities.find((c) => c.id === 'CAP-MAIN-INTEGRATE').probes.push({ tool: 'Bash', command: 'git push --force origin HEAD:main' });
  const dTight = authorityDelta(caps, tighter);
  const lawTight = im.propose(A.improvement.head, { title: 'main への強制 push の probe を足す', tier: 'law', target: { paths: [CAPS_PATH] }, content: { capabilities: tighter }, capabilities: { old: caps, new: tighter } });
  im.evaluate(A.improvement.court, lawTight.id, { digest: im.get(lawTight.id).digest, evidence: { conformance: { before: { total: 50, passed: 50 }, after: { total: 51, passed: 51 }, new_cases_fail_on_before: 1 } } });
  reviewOf(lawTight);
  const adoptedTight = adoptLoose(lawTight.id);
  if (dTight.class !== 'tightening' || adoptedTight.status !== 'adopted') throw new Error('締める変更が通常の経路で採用されない');
  log(8, `締めるだけの変更（probe を足す）→ authority-delta：${dTight.class}、経路 ${routeFor(dTight).lane} → オーナーが採用（${adoptedTight.id}）`);

  // =====================================================================
  // 段 9　統治の確認
  // =====================================================================
  log(9, '行政の長が、自分の権限にない出来事を起こそうとする（すべて拒まれる）');
  rsApply(A.runstate.head, { op: 'plan', nodes: [{ id: 't-104', depends_on: [], resources: ['src/d/**'] }] });
  const headRs = (ev) => () => rsApply(A.runstate.head, ev);
  mustRefuse(9, 'runstate：行政の長が verdict', headRs({ op: 'verdict', node: 't-104', request: sha40('x'), audits: 'passed', verdicts: [J('judge', 'claude', 'APPROVED'), J('judge', 'codex', 'APPROVED')] }));
  mustRefuse(9, 'runstate：行政の長が approve', headRs({ op: 'approve', node: 't-104', spec_digest: specDigest['T-101'], policy_line: policyLine, def_digest: run.state().nodes['t-104'].def_digest }));
  mustRefuse(9, 'runstate：行政の長が release', headRs({ op: 'release', node: 't-104', request: sha40('x') }));
  mustRefuse(9, 'improvement：行政の長が採用', () => im.adopt(A.improvement.head, lawLoose.id, { digest: im.get(lawLoose.id).digest, policy_line: policyLine }));
  mustRefuse(9, 'experience：行政の長が昇格', () => exp.promote({ ...A.experience.head }, refl[0].id, { digest: exp.inspect(refl[0].id).digest }));
  mustRefuse(9, 'experience：行政の長が feedback', () => exp.feedback(A.experience.head, { item_ids: [induced.id], outcome: 'helpful', evidence: { kind: 'verdict', ref: 'x', task: 'T-103' } }));
  mustRefuse(9, 'trace：行政の長がつながりを記録', () => tr.link(A.trace.head, { rel: 'satisfies', from: { kind: 'ticket', id: 'T-103' }, to: { kind: 'requirement', id: 'R-9' } }));

  rsApply(A.runstate.owner, { op: 'approve', node: 't-104', spec_digest: digest({ ticket: 'T-104' }), policy_line: policyLine, def_digest: run.state().nodes['t-104'].def_digest });
  rsApply(A.runstate.owner, { op: 'stop', reason: '見本：停止の確認' });
  mustRefuse(9, 'runstate：停止中に start', headRs({ op: 'start', node: 't-104', spec_digest: digest({ ticket: 'T-104' }), lease_sec: 3600 }));
  rsApply(A.runstate.owner, { op: 'resume', reason: '見本：再開' });
  const st104 = rsApply(A.runstate.head, { op: 'start', node: 't-104', spec_digest: digest({ ticket: 'T-104' }), lease_sec: 3600 });
  log(9, `  オーナーが stop → start は拒まれた → オーナーが resume → start が通った（${st104.to}）`);

  const verify = { run: run.verify(), experience: exp.verify(), trace: tr.verify(), improvement: im.verify() };
  for (const [k, v] of Object.entries(verify)) if (!v.ok) throw new Error(`${k} の verify が ok でない: ${JSON.stringify(v)}`);
  log(9, `全部の記録の verify：run ${verify.run.count} 行・experience ${verify.experience.count} 行・trace ${verify.trace.count} 行・improvement ${verify.improvement.count} 行、すべて ok`);

  return {
    root, files, caps, pack, packResult, policyLine, catalog, teamPlan, teamResult, teamRefusal, teamContext,
    run, rows, specDigest, approveHash, req, mergeSha, accId, next1, v1, v2, v3, v4,
    exp, refl, induced, promoted, r101, r102, r103, fb, judgeAsk, findings,
    tr, cov, gaps1, gaps2, cov2, im, playbook, lawLoose, lawTight, dLoose, dTight, adoptedTight,
    verify, A, adaptations, refusals, modeOf, vrdId,
  };
}

// ---- 実行 ----
const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const out = (s) => process.stdout.write(`${s}\n`);
  out('これは起草段階の試作の見本で、行為者は呼び出し側の申告であり、稼働中の Kernel にはつないでいない。');
  out('8 つの部品（領域パック・編成・実行の記録・経験・追跡・改善提案・権限の差分・仕事のグラフ）を 1 つの流れでつなぐ。');
  out('');
  const titles = { 1: '領域パック', 2: '編成', 3: '実行の記録', 4: '経験の取り出し（着手の前）', 5: '申請と判定', 6: '経験の蓄積', 7: '追跡', 8: '改善提案', 9: '統治の確認' };
  let last = 0;
  const result = runWalkthrough({ log: (stage, s) => { if (stage !== last) { out(`\n■ 段 ${stage}　${titles[stage]}`); last = stage; } out(`  ${s}`); } });
  out('\n■ 部品の間の食い違いを埋めるために、この見本の側で変換した値');
  for (const a of result.adaptations) out(`  - ${a.what}：${typeof a.from === 'string' ? a.from : JSON.stringify(a.from)} → ${typeof a.to === 'string' ? a.to : JSON.stringify(a.to)}（${a.why}）${a.count > 1 ? ` ×${a.count}` : ''}`);
  out(`\n■ 拒まれた操作 ${result.refusals.length} 件`);
  for (const r of result.refusals) out(`  - 段 ${r.stage}：${r.label} → ${r.guards.join('・') || r.code}`);
  out('\n■ 参考：権限の差分の表示（作業員に main への統合を許す変更）');
  out(formatDelta(result.dLoose).split('\n').map((l) => `  ${l}`).join('\n'));
  out(`\n記録の置き場所（一時）：${result.root}`);
  out('完了。');
}
