// 8 つの部品を 1 つの流れでつなぐ見本（起草段階の試作。法律ではない）
//
// 実行：node vgdd/next/examples/walkthrough.mjs   （終了コード 0。各段で何が起き、何が拒まれたかを日本語で出す）
// 試験：vgdd/next/test/integration.test.mjs が、ここで export する runWalkthrough を呼んで中身を確かめる。
//
// これは起草段階の試作の見本で、行為者は呼び出し側の申告であり、稼働中の Kernel にはつないでいない。
//
// 題材：3 つの票（T-101 と T-102 は独立、T-103 は両方に依存。T-102 は security_review つき）を、開発の領域パックで進める。
// 各段の出力を、次の段の入力にそのまま使う。部品の間の値の受け渡しは共通の語彙（lib/vocab.mjs）とつなぎの純関数（lib/bridge.mjs）だけで行い、
// 見本の側で値を書き換えない。書き換えが要った箇所は adapt() で記録する（result.adaptations。共通の語彙への統一の後は 0 件になる）。
//
// 外から来る値（この見本が作る、Kernel の外の事実の代わり）：仕様の指紋、申請と統合の Git の SHA、判定の記録の指紋（id の 8 桁を付けない）、
// 指摘の本文、過去の票 T-090 の指摘、目標・要件の表、オーナーの受け入れの記録、障害。これらは変換でなく入力である。

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { digest, sha256, openChain, Refused } from '../lib/chain.mjs';
import { verdictId, auditId, reviewModeOf, policyLineOf, makeWorkItemId } from '../lib/vocab.mjs';
import { judiciaryFromDomainPack, protectedFromDomainPack, workItemFromDomainPack, linksFromRun, provenanceFromVerdict, feedbackFromRun } from '../lib/bridge.mjs';
import { validateDomainPack } from '../domain.mjs';
import { validateTeam, catalogFromCapabilities } from '../team.mjs';
import { buildGraph } from '../taskgraph.mjs';
import { openRun, defDigestOf } from '../runstate.mjs';
import { openExperience } from '../experience.mjs';
import { openTrace } from '../trace.mjs';
import { openImprovements, CAPS_PATH } from '../improvement.mjs';
import { authorityDelta, routeFor, formatDelta } from '../authority-delta.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const NEXT_DIR = path.resolve(HERE, '..');
export const CAPS_FILE = path.resolve(NEXT_DIR, '../kernel/capabilities.json');
export const PACK_FILE = path.resolve(NEXT_DIR, 'domains/software-dev.json');

/** 題材の票（票の ID は領域パックの work_item.id の宣言に合う形。全部品で同じ綴りを使う） */
export const TICKETS = [
  { id: 'T-101', req: 'R-1', deps: [], resources: ['src/a/**'], security: false },
  { id: 'T-102', req: 'R-2', deps: [], resources: ['src/b/**'], security: true },
  { id: 'T-103', req: 'R-3', deps: ['T-101', 'T-102'], resources: ['src/c/**'], security: false },
];

/** 行為者（全部品が同じオブジェクトを受ける。lib/vocab.mjs の { role, kind, id, lineage }） */
export const ACTORS = Object.freeze({
  owner: { role: 'owner', kind: 'human', id: 'azuki', lineage: 'human' },
  head: { role: 'executive_head', kind: 'ai', id: 'exec-head', lineage: 'claude' },
  night: { role: 'night_runner', kind: 'script', id: 'night-runner', lineage: 'script' },
  gate: { role: 'gate_runner', kind: 'script', id: 'gate-runner', lineage: 'script' },
  importer: { role: 'trace_importer', kind: 'script', id: 'trace-importer', lineage: 'script' },
  worker1: { role: 'worker', kind: 'ai', id: 'worker-1', lineage: 'claude' },
  worker2: { role: 'worker', kind: 'ai', id: 'worker-2', lineage: 'claude' },
  judgeCodex: { role: 'codex_judge', kind: 'ai', id: 'judge-codex', lineage: 'codex' },
  constClaude: { role: 'constitutional_review', kind: 'ai', id: 'const-review', lineage: 'claude' }, // 実際の憲法審査は Claude（capabilities.json の identity）
});

const clone = (v) => JSON.parse(JSON.stringify(v));
const sha40 = (s) => sha256(s).slice(0, 40); // 申請・統合のコミットの代用（git の SHA は 40 桁）

/** 拒否の情報（Refused の code と、違反したガードの名前）。全部品が Refused('guard_violation') と violations を返す */
export function refusalOf(e) {
  const hasViolations = Array.isArray(e && e.violations);
  return { code: e && e.code, guards: hasViolations ? e.violations.map((v) => v.guard) : [], hasViolations, message: String((e && e.message) || e).slice(0, 200) };
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
  const A = ACTORS;

  // ---- 変換の記録（共通の語彙に統一した後は使われない。食い違いが戻ったら、ここに記録して試験が気づく） ----
  const adaptations = [];
  // eslint-disable-next-line no-unused-vars
  const adapt = (what, from, to, why) => { adaptations.push({ what, from, to, why }); return to; };
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

  // =====================================================================
  // 段 1　領域パック → 実行の設定（bridge）
  // =====================================================================
  const caps = JSON.parse(fs.readFileSync(CAPS_FILE, 'utf8'));
  const pack = JSON.parse(fs.readFileSync(PACK_FILE, 'utf8'));
  const packResult = validateDomainPack(pack);
  if (!packResult.ok) throw new Error(`領域パックが通らない: ${JSON.stringify(packResult.violations)}`);
  const workItem = workItemFromDomainPack(pack).work_item;
  const isTicket = makeWorkItemId(workItem);
  for (const t of TICKETS) if (!isTicket(t.id)) throw new Error(`票の ID が領域パックの宣言に合わない: ${t.id}`);
  const jud = judiciaryFromDomainPack(pack);
  if (!jud.judiciary) throw new Error(`司法の設定を作れない: ${jud.reason}`);
  const prot = protectedFromDomainPack(pack).protected;
  const policyLine = policyLineOf(caps); // 'p0.4'
  if (!policyLine) throw new Error('法律の系統が読めない');
  log(1, `領域パック ${pack.id} を検査：通った。票の ID ${workItem.prefix} と ${workItem.digits.join('〜')} 桁、必須の審査 ${jud.judiciary.map((j) => j.lineage).join('・')}（security は ${jud.security_lineage}）、保護 ${prot.join('・')}。法律の系統 ${caps.kernel_version} → ${policyLine}`);

  // =====================================================================
  // 段 2　編成
  // =====================================================================
  const catalog = catalogFromCapabilities(caps);
  const WORK_TOOLS = ['Read', 'Edit', 'Write', 'Bash', 'Glob', 'Grep'];
  const ticketResources = TICKETS.flatMap((t) => t.resources);
  const teamPlan = {
    task: 'T-101・T-102・T-103 を進める',
    proposed_by: A.head,
    members: [
      { id: A.head.id, template: 'executive_head', scope: { resources: ticketResources, tools: [...WORK_TOOLS, 'Agent'] } },
      { id: A.worker1.id, template: 'worker', parent: A.head.id, scope: { resources: ['src/a/**', 'src/c/**'], tools: WORK_TOOLS } },
      { id: A.worker2.id, template: 'worker', parent: A.head.id, scope: { resources: ['src/b/**'], tools: WORK_TOOLS } },
      { id: 'judge-claude', template: 'judge', scope: { resources: [], tools: [] } },
      { id: A.judgeCodex.id, template: 'codex_judge', scope: { resources: [], tools: [] } },
    ],
  };
  const graphForTeam = buildGraph(TICKETS.map((t) => ({ id: t.id, status: 'ready', depends_on: t.deps, resources: t.resources, approved: true })));
  if (!graphForTeam.ok) throw new Error('taskgraph が通らない');
  // limits.concurrent_work は runstate の config.concurrent_work と同じ意味（同時に動かす作業員の数。行政の長は数えない）
  const teamContext = { catalog, ticket: { resources: ticketResources }, limits: { concurrent_work: 2, depth: 2, members_total: 16 }, graph: graphForTeam.graph };
  const teamResult = validateTeam(teamPlan, teamContext);
  if (!teamResult.ok) throw new Error(`編成案が通らない: ${JSON.stringify(teamResult.violations)}`);
  log(2, `編成案を検査：通った。requires_approval=${teamResult.requires_approval}、effect=${teamResult.effect}、同時の作業 ${teamContext.limits.concurrent_work}`);
  const teamRefusal = validateTeam({ ...teamPlan, members: [...teamPlan.members, { id: 'court', template: 'gate_runner', scope: { resources: [], tools: [] } }] }, teamContext);
  if (teamRefusal.ok) throw new Error('裁判所を編成に入れた案が通った');
  refusals.push({ stage: 2, label: '裁判所（gate_runner）を編成に入れる案（純関数の検査は { ok:false, violations } を返す）', code: null, guards: teamRefusal.violations.map((v) => v.guard), hasViolations: true });
  log(2, `  拒まれた：裁判所（gate_runner）を編成に入れる案 → ${teamRefusal.violations.map((v) => v.guard).join('・')}`);

  // =====================================================================
  // 段 3　実行の記録（設定は領域パックから bridge で作る）
  // =====================================================================
  const run = openRun(files.run);
  let eid = 0;
  const rsApply = (actor, ev) => run.apply(actor, { event_id: `ev-${++eid}`, ...ev });
  rsApply(A.owner, {
    op: 'config', hold: false, max_attempts: 4, max_returns: 3, max_unavailable: 3, concurrent_work: teamContext.limits.concurrent_work, lease_sec: 21600,
    policy_line: policyLine, judiciary: jud.judiciary, security_lineage: jud.security_lineage, work_item: workItem, protected: prot,
  });
  log(3, `オーナーが config を記録（judiciary・security_lineage・work_item・protected は領域パックから bridge で作った値）`);
  const planNodes = TICKETS.map((t) => ({ id: t.id, depends_on: t.deps, resources: t.resources, requirements: [t.req], ...(t.security ? { security_review: true } : {}) }));
  rsApply(A.head, { op: 'plan', nodes: planNodes });
  log(3, `行政の長が plan：節 ${TICKETS.length} つ（要件つき。T-102 は security_review つき）。未承認で始まる`);
  mustRefuse(3, 'runstate：保護された範囲（vgdd/**）を触る節の plan', () => rsApply(A.head, { op: 'plan', nodes: [{ id: 'T-109', depends_on: [], resources: ['vgdd/kernel/**'] }] }));

  const specDigest = {}; const approveHash = {};
  for (const t of TICKETS) {
    specDigest[t.id] = digest({ ticket: t.id, acceptance: `${t.req} を満たす`, files_allowed: t.resources }); // 仕様の指紋（Kernel の spec-digest に相当する外の値）
    const r = rsApply(A.owner, { op: 'approve', node: t.id, spec_digest: specDigest[t.id], policy_line: policyLine, def_digest: defDigestOf(planNodes.find((n) => n.id === t.id)) });
    approveHash[t.id] = r.digest; // 承認の行の指紋（sha256: ＋ 行の hash）。trace の承認の id にそのまま使う
  }
  log(3, 'オーナーが 3 節を approve（def_digest は defDigestOf で呼び出し側が計算。戻り値の digest が承認の指紋）');
  const next1 = run.next();
  if (JSON.stringify([...next1.start].sort()) !== JSON.stringify(['T-101', 'T-102'])) throw new Error(`next() の着手の組が想定と違う: ${JSON.stringify(next1.start)}`);
  log(3, `next()：着手の組 ${next1.start.join('・')}、構成の勧め ${next1.recommend.topology}、待ち ${next1.waiting.map((w) => `${w.id}[${w.reasons.join(',')}]`).join(' ')}`);

  // =====================================================================
  // 段 4　経験（着手の前の取り出し。最初は空）
  // =====================================================================
  const exp = openExperience(files.experience, { workItem });
  const retrieveFor = (task, text) => exp.retrieve({ audience: { role: 'worker', task }, query: { text, tags: ['test'], domain: pack.id }, limit: 5, maxChars: 3000 });
  const r101 = retrieveFor('T-101', '境界値 試験 入力の上限');
  const r102 = retrieveFor('T-102', '境界値 試験 入力の上限');
  if (r101.items.length || r102.items.length || r101.rendered !== '') throw new Error('最初の取り出しが空でない');
  log(4, `着手の前に作業員（worker）の役割で経験を取り出した：T-101・T-102 とも空（searchKind=${r101.searchKind}）`);

  // =====================================================================
  // 段 5　申請と判定（判定の refs と統合の参照を記録に残す）
  // =====================================================================
  const req = { 'T-101': [sha40('request:T-101:1'), sha40('request:T-101:2')], 'T-102': [sha40('request:T-102:1')], 'T-103': [sha40('request:T-103:1')] };
  const mergeSha = {};
  const J = (kind, lineage, verdict, major = false) => ({ kind, judge: `${kind}-${lineage}`, lineage, verdict, major });
  /** 裁判所のスクリプトが判定の記録から作る refs（判定の id は vocab の verdictId、指摘は <判定の id>#<ラベル>、監査は auditId） */
  const refsFor = (request, verdicts, findings = []) => ({
    verdicts: verdicts.map((v) => ({ kind: v.kind, lineage: v.lineage, id: verdictId(request, reviewModeOf(v.kind, v.lineage)) })),
    ...(findings.length ? { findings: findings.map(([kind, lineage, label]) => `${verdictId(request, reviewModeOf(kind, lineage))}#${label}`) } : {}),
    audit: { id: auditId(request) },
  });
  const verdict = (t, request, verdicts, findings = []) => {
    const merge = verdicts.every((v) => v.verdict === 'APPROVED') ? (mergeSha[t] = sha40(`merge:${t}`)) : undefined; // 合格なら裁判所が統合したコミット（外の値）
    return rsApply(A.gate, { op: 'verdict', node: t, request, audits: 'passed', verdicts, refs: refsFor(request, verdicts, findings), ...(merge ? { merge } : {}) });
  };

  rsApply(A.head, { op: 'start', node: 'T-101', spec_digest: specDigest['T-101'], lease_sec: 3600, assignee: A.worker1 });
  rsApply(A.night, { op: 'start', node: 'T-102', spec_digest: specDigest['T-102'], lease_sec: 3600, assignee: A.worker2 });
  log(5, 'T-101 は行政の長（昼）、T-102 は夜間の代行が着手。作業員は assignee として記録する（行為者にはしない）');
  rsApply(A.head, { op: 'submit', node: 'T-101', request: req['T-101'][0] });
  const v1 = verdict('T-101', req['T-101'][0], [J('judge', 'claude', 'CHANGES_REQUIRED'), J('judge', 'codex', 'CHANGES_REQUIRED', true)], [['judge', 'codex', 'finding-1']]);
  if (v1.kind !== 'return' || v1.to !== 'in_progress') throw new Error(`1 回目の判定が差し戻しでない: ${JSON.stringify(v1)}`);
  log(5, `T-101 を申請 → 裁判所のスクリプト（gate_runner）が verdict：claude も codex も CHANGES_REQUIRED → ${v1.kind}（差し戻し ${v1.node.returns} 回）`);
  rsApply(A.head, { op: 'submit', node: 'T-101', request: req['T-101'][1] });
  const v2 = verdict('T-101', req['T-101'][1], [J('judge', 'claude', 'APPROVED'), J('judge', 'codex', 'APPROVED')]);
  if (v2.kind !== 'pass' || v2.to !== 'merged') throw new Error('T-101 の再申請が合格でない');
  rsApply(A.night, { op: 'submit', node: 'T-102', request: req['T-102'][0] });
  const v3 = verdict('T-102', req['T-102'][0], [J('judge', 'claude', 'APPROVED'), J('judge', 'codex', 'APPROVED'), J('security', 'codex', 'APPROVED')], [['judge', 'codex', 'finding-2']]);
  if (v3.kind !== 'pass') throw new Error('T-102 が合格でない');
  log(5, `T-101 を再申請 → ${v2.kind}。T-102 は security 審査（codex）を含めて ${v3.kind}`);

  // =====================================================================
  // 段 6　経験の蓄積（出どころは verdict の refs から bridge で作る）
  // =====================================================================
  const rowsAfter5 = openChain(files.run).read();
  const firstVerdictRow = (t) => rowsAfter5.find((r) => r.op === 'verdict' && r.node === t && Array.isArray(r.refs && r.refs.findings));
  const findingText = { 'T-101': '入力の上限の境界値（上限ちょうど・1 つ上）の試験がない。境界値の試験を先に書くこと', 'T-102': '入力の上限の直前の値の試験が薄い。境界値の試験を足すこと' };
  const scope = { domain: pack.id, roles: ['worker'], tags: ['test', 'boundary'] };
  const refl = [];
  for (const t of ['T-101', 'T-102']) {
    const pv = provenanceFromVerdict(firstVerdictRow(t));
    if (!pv.provenance.length) throw new Error(`出どころを作れない: ${pv.reason}`);
    refl.push(exp.add(A.gate, { text: findingText[t], scope, provenance: pv.provenance }));
  }
  // 過去の票 T-090 の指摘（この流れの外の記録）
  refl.push(exp.add(A.gate, { text: '上限の境界値が未検証だった。境界値の試験を先に書くこと', scope, provenance: [{ kind: 'verdict_finding', ref: 'VRD-0123456789ab-codex-judge#finding-1', task: 'T-090' }] }));
  log(6, `判定の refs の指摘への参照から reflection を 3 件追加（trust=${refl[0].trust}、status=${refl[0].status}）`);
  const induced = exp.induce(A.gate, { from: refl.map((x) => x.id), text: '境界値（上限ちょうど・1 つ上）の試験を、実装より先に書く', scope });
  const promoted = exp.promote(A.owner, induced.id, { digest: exp.inspect(induced.id).digest });
  log(6, `3 件の reflection（別々の票）から induce → ${induced.id}。オーナーが昇格 → ${promoted.status}`);

  const r103 = retrieveFor('T-103', '境界値 試験 入力の上限');
  const first = r103.items[0];
  if (!first || first.id !== induced.id || first.status !== 'adopted') throw new Error('昇格した経験が先頭に出ない');
  if (!r103.rendered.includes('引用') || !r103.rendered.includes('```text')) throw new Error('経験が引用の形で出ない');
  log(6, `T-103 の着手の前に retrieve：${r103.items.length} 件。先頭は ${first.id}（${first.trust}・${first.status}）`);

  rsApply(A.head, { op: 'start', node: 'T-103', spec_digest: specDigest['T-103'], lease_sec: 3600, assignee: A.worker1 });
  rsApply(A.head, { op: 'submit', node: 'T-103', request: req['T-103'][0] });
  const v4 = verdict('T-103', req['T-103'][0], [J('judge', 'claude', 'APPROVED'), J('judge', 'codex', 'APPROVED')]);
  if (v4.kind !== 'pass') throw new Error('T-103 が合格でない');
  log(6, `T-103（T-101・T-102 の統合後に着手できた）→ ${v4.kind}`);
  const fbPlan = feedbackFromRun(openChain(files.run).read(), openChain(files.experience).read());
  const fbT103 = fbPlan.feedback.find((f) => f.evidence.task === 'T-103');
  if (!fbT103 || fbT103.outcome !== 'helpful') throw new Error(`T-103 の feedback の案が helpful でない: ${JSON.stringify(fbPlan)}`);
  const fb = exp.feedback(A.gate, { ...fbT103, item_ids: fbT103.item_ids.filter((id) => id === induced.id) });
  log(6, `bridge の feedbackFromRun（最初の判定 pass → helpful）→ 裁判所のスクリプトが feedback → ${induced.id} の helpful=${fb[0].helpful}`);
  const judgeAsk = exp.retrieve({ audience: { role: 'judge', task: 'T-103' }, query: { text: '境界値', domain: pack.id } });
  const securityAsk = exp.retrieve({ audience: { role: 'codex_security', task: 'T-102' }, query: { text: '境界値', domain: pack.id } });
  if (!judgeAsk.refused || judgeAsk.items.length || !securityAsk.refused || securityAsk.items.length) throw new Error('司法の役割に経験が渡った');
  refusals.push({ stage: 6, label: '司法（judge・codex_security）の役割への経験の取り出し（retrieve は例外でなく { refused, violations } を返す）', code: null, guards: judgeAsk.violations.map((v) => v.guard), hasViolations: true });
  log(6, '  拒まれた：司法（judge）と security の審査（codex_security）への retrieve → EX-RETRIEVE-JUDGE');

  // =====================================================================
  // 段 7　追跡（runstate の記録から bridge でつながりを作る）
  // =====================================================================
  const rows = openChain(files.run).read();
  const tr = openTrace(files.trace, { ticketId: workItem });
  const fromRun = linksFromRun(rows);
  const imported = tr.linkMany(A.importer, fromRun.links);
  if (imported.refused.length) throw new Error(`取り込めないつながりがある: ${JSON.stringify(imported.refused.slice(0, 3))}`);
  // 実行の記録の外の事実：目標と要件の表（企画）、オーナーの受け入れ
  const accId = {};
  const ownerLinks = [
    ...TICKETS.map((t) => ({ rel: 'satisfies', from: { kind: 'requirement', id: t.req }, to: { kind: 'goal', id: 'G-1' } })),
    ...TICKETS.map((t) => { accId[t.id] = `ACC-${sha256(`acceptance:${mergeSha[t.id]}`).slice(0, 16)}`; return { rel: 'approves', from: { kind: 'acceptance', id: accId[t.id] }, to: { kind: 'merge', id: mergeSha[t.id] } }; }),
    { rel: 'derives', from: { kind: 'experience', id: refl[0].id }, to: { kind: 'verdict', id: verdictId(req['T-101'][0], 'codex-judge') } },
  ];
  const own = tr.linkMany(A.owner, ownerLinks);
  if (own.refused.length) throw new Error(`オーナーのつながりが拒まれた: ${JSON.stringify(own.refused)}`);
  log(7, `runstate の記録から bridge.linksFromRun で ${fromRun.links.length} 本（skipped ${fromRun.skipped.length}）を取り込み、オーナーが目標・受け入れ・経験の ${ownerLinks.length} 本を書いた`);

  const expected = { expectedRequirements: TICKETS.map((t) => t.req), expectedTickets: TICKETS.map((t) => t.id) };
  const cov = tr.coverage(expected);
  const gaps1 = tr.gaps(expected);
  for (const row of cov.rows) {
    const missing = ['ticket', 'spec', 'approval', 'request', 'audit', 'verdict', 'merge', 'acceptance'].filter((s) => !row.stages[s]);
    if (missing.length) throw new Error(`${row.requirement} の段がそろわない: ${missing.join(',')}`);
  }
  const r1 = cov.rows.find((r) => r.requirement === 'R-1');
  if (r1.returned_requests !== 1 || r1.approved_requests !== 1) throw new Error('差し戻された 1 回目の申請が見えない');
  log(7, `coverage：3 つの要件とも全段がそろう。R-1 は申請 ${r1.requests} 件のうち 差し戻し ${r1.returned_requests}・承認 ${r1.approved_requests}。gaps ${gaps1.count} 件`);
  tr.link(A.owner, { rel: 'caused_by', from: { kind: 'incident', id: 'INC-001' }, to: { kind: 'merge', id: mergeSha['T-103'] } });
  const gaps2 = tr.gaps(expected);
  const cov2 = tr.coverage(expected);
  if (!gaps2.gaps.some((g) => g.code === 'INCIDENT_NO_TICKET')) throw new Error('障害の対応の票がないことが gaps に出ない');
  log(7, '障害 INC-001 を足した → gaps に INCIDENT_NO_TICKET');

  // =====================================================================
  // 段 8　改善提案
  // =====================================================================
  const im = openImprovements(files.improvement, { currentCapabilities: caps });
  const playbook = im.propose(A.head, {
    title: '作業員の手順：境界値の試験を先に書く', tier: 'playbook', target: { name: 'worker-playbook' },
    content: { step: '実装の前に、上限ちょうど・1 つ上の境界値の試験を書く', derived_from: [induced.id] }, rationale: `${refl[0].id}（T-101 の差し戻し）から`,
  });
  const GOOD = { before: { total: 100, passed: 100 }, after: { total: 102, passed: 102 }, new_cases_fail_on_before: 2 };
  const evalOf = (p, ev = GOOD) => im.evaluate(A.gate, p.id, { digest: im.get(p.id).digest, evidence: { conformance: ev } });
  const reviewOf = (p, who = A.judgeCodex) => im.review(who, p.id, { digest: im.get(p.id).digest, verdict: 'APPROVED', findings: [], review_input_digest: im.reviewInputFor(p.id).digest });
  const adoptOf = (id) => im.adopt(A.owner, id, { digest: im.get(id).digest, policy_line: policyLine });
  evalOf(playbook); reviewOf(playbook);
  const adopted = adoptOf(playbook.id);
  if (adopted.status !== 'adopted' || !im.adoptionValid(playbook.id)) throw new Error('手順の改善が採用されない');
  tr.link(A.owner, { rel: 'derives', from: { kind: 'improvement', id: playbook.id }, to: { kind: 'experience', id: induced.id } });
  log(8, `行政の長が ${playbook.id} を提案 → 裁判所のスクリプトが評価 → codex の judge が審査 → オーナーが採用`);

  const looser = clone(caps); looser.capabilities.find((c) => c.id === 'CAP-MAIN-INTEGRATE').allowed.push('worker');
  const dLoose = authorityDelta(caps, looser);
  const lawLoose = im.propose(A.head, { title: '作業員に main への統合を許す', tier: 'law', target: { paths: [CAPS_PATH] }, content: { capabilities: looser }, capabilities: { old: caps, new: looser } });
  evalOf(lawLoose); reviewOf(lawLoose);
  if (dLoose.class !== 'loosening' || lawLoose.route.lane !== 'full_legislative') throw new Error('緩める変更が緩めると分類されない');
  mustRefuse(8, '緩める法律の変更を、通常の審査（codex の judge）とオーナーの承認だけで採用', () => adoptOf(lawLoose.id));
  mustRefuse(8, '憲法審査（実際は Claude 系統）の審査。提案者と同じ系統なので審査できない', () => reviewOf(im.get(lawLoose.id), A.constClaude));
  mustRefuse(8, '同じ系統の別名（anthropic）を名乗る憲法審査', () => reviewOf(im.get(lawLoose.id), { ...A.constClaude, lineage: 'anthropic' }));
  const tighter = clone(caps); tighter.capabilities.find((c) => c.id === 'CAP-MAIN-INTEGRATE').probes.push({ tool: 'Bash', command: 'git push --force origin HEAD:main' });
  const dTight = authorityDelta(caps, tighter);
  const lawTight = im.propose(A.head, { title: 'main への強制 push の probe を足す', tier: 'law', target: { paths: [CAPS_PATH] }, content: { capabilities: tighter }, capabilities: { old: caps, new: tighter } });
  evalOf(lawTight, { before: { total: 50, passed: 50 }, after: { total: 51, passed: 51 }, new_cases_fail_on_before: 1 }); reviewOf(lawTight);
  const adoptedTight = adoptOf(lawTight.id);
  if (dTight.class !== 'tightening' || adoptedTight.status !== 'adopted') throw new Error('締める変更が通常の経路で採用されない');
  log(8, `法律の変更：緩める（${dLoose.class}・${routeFor(dLoose).lane}）は採用できず、締める（${dTight.class}）は採用された`);

  // =====================================================================
  // 段 9　統治の確認（同じ行為者のオブジェクトで、権限のない操作がすべて拒まれる）
  // =====================================================================
  rsApply(A.head, { op: 'plan', nodes: [{ id: 'T-104', depends_on: [], resources: ['src/d/**'] }] });
  const headRs = (ev) => () => rsApply(A.head, ev);
  mustRefuse(9, 'runstate：行政の長が verdict', headRs({ op: 'verdict', node: 'T-104', request: sha40('x'), audits: 'passed', verdicts: [J('judge', 'claude', 'APPROVED'), J('judge', 'codex', 'APPROVED')] }));
  mustRefuse(9, 'runstate：行政の長が approve', headRs({ op: 'approve', node: 'T-104', spec_digest: specDigest['T-101'], policy_line: policyLine, def_digest: run.state().nodes['T-104'].def_digest }));
  mustRefuse(9, 'runstate：行政の長が release', headRs({ op: 'release', node: 'T-104', request: sha40('x') }));
  mustRefuse(9, 'improvement：行政の長が採用', () => im.adopt(A.head, lawLoose.id, { digest: im.get(lawLoose.id).digest, policy_line: policyLine }));
  mustRefuse(9, 'experience：行政の長が昇格', () => exp.promote(A.head, refl[0].id, { digest: exp.inspect(refl[0].id).digest }));
  mustRefuse(9, 'experience：行政の長が feedback', () => exp.feedback(A.head, { item_ids: [induced.id], outcome: 'helpful', evidence: { kind: 'verdict', ref: 'x', task: 'T-103' } }));
  mustRefuse(9, 'experience：夜間の代行（スクリプト）が feedback', () => exp.feedback(A.night, { item_ids: [induced.id], outcome: 'helpful', evidence: { kind: 'verdict', ref: 'x', task: 'T-103' } }));
  mustRefuse(9, 'trace：行政の長がつながりを記録', () => tr.link(A.head, { rel: 'satisfies', from: { kind: 'ticket', id: 'T-103' }, to: { kind: 'requirement', id: 'R-9' } }));
  rsApply(A.owner, { op: 'approve', node: 'T-104', spec_digest: digest({ ticket: 'T-104' }), policy_line: policyLine, def_digest: run.state().nodes['T-104'].def_digest });
  rsApply(A.owner, { op: 'stop', reason: '見本：停止の確認' });
  mustRefuse(9, 'runstate：停止中に start', headRs({ op: 'start', node: 'T-104', spec_digest: digest({ ticket: 'T-104' }), lease_sec: 3600 }));
  rsApply(A.owner, { op: 'resume', reason: '見本：再開' });
  const st104 = rsApply(A.head, { op: 'start', node: 'T-104', spec_digest: digest({ ticket: 'T-104' }), lease_sec: 3600 });
  log(9, `  オーナーが stop → start は拒まれた → resume → start が通った（${st104.to}）`);

  const verify = { run: run.verify(), experience: exp.verify(), trace: tr.verify(), improvement: im.verify() };
  for (const [k, v] of Object.entries(verify)) if (!v.ok) throw new Error(`${k} の verify が ok でない: ${JSON.stringify(v)}`);
  log(9, `全部の記録の verify：run ${verify.run.count} 行・experience ${verify.experience.count} 行・trace ${verify.trace.count} 行・improvement ${verify.improvement.count} 行、すべて ok（experience も再生して確かめる）`);

  return {
    root, files, caps, pack, packResult, workItem, jud, prot, policyLine, catalog, teamPlan, teamResult, teamRefusal, teamContext,
    run, rows, specDigest, approveHash, req, mergeSha, accId, next1, v1, v2, v3, v4,
    exp, refl, induced, promoted, r101, r102, r103, fb, fbPlan, judgeAsk, securityAsk,
    tr, fromRun, cov, gaps1, gaps2, cov2, im, playbook, lawLoose, lawTight, dLoose, dTight, adoptedTight,
    verify, A, adaptations, refusals,
  };
}

// ---- 実行 ----
const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const out = (s) => process.stdout.write(`${s}\n`);
  out('これは起草段階の試作の見本で、行為者は呼び出し側の申告であり、稼働中の Kernel にはつないでいない。');
  out('8 つの部品（領域パック・編成・実行の記録・経験・追跡・改善提案・権限の差分・仕事のグラフ）を、共通の語彙とつなぎの関数で 1 つの流れにする。');
  const titles = { 1: '領域パック', 2: '編成', 3: '実行の記録', 4: '経験の取り出し（着手の前）', 5: '申請と判定', 6: '経験の蓄積', 7: '追跡', 8: '改善提案', 9: '統治の確認' };
  let last = 0;
  const result = runWalkthrough({ log: (stage, s) => { if (stage !== last) { out(`\n■ 段 ${stage}　${titles[stage]}`); last = stage; } out(`  ${s}`); } });
  out(`\n■ 部品の間で値を書き換えた箇所：${result.adaptations.length} 件`);
  for (const a of result.adaptations) out(`  - ${a.what}：${a.from} → ${a.to}（${a.why}）`);
  out(`\n■ 拒まれた操作 ${result.refusals.length} 件`);
  for (const r of result.refusals) out(`  - 段 ${r.stage}：${r.label} → ${r.guards.join('・') || r.code}`);
  out('\n■ 参考：権限の差分の表示（作業員に main への統合を許す変更）');
  out(formatDelta(result.dLoose).split('\n').map((l) => `  ${l}`).join('\n'));
  out(`\n記録の置き場所（一時）：${result.root}`);
  out('完了。');
}
