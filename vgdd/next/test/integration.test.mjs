// 結合の試験：vgdd/next の 8 つの部品が、共通の語彙（lib/vocab.mjs）とつなぎの純関数（lib/bridge.mjs）で 1 つの流れになるか（起草段階の試作）
//
// 前半：examples/walkthrough.mjs の流れを 1 回動かし、各段の出力が変換なしで次の段の入力に使われることを確かめる（adaptations は 0 件）。
// 後半：統一の前に「食い違い」として記録していた箇所（行為者・系統・ID と指紋・範囲・状態の名前・時刻・規則の版と設定・つながらない箇所・API）が、
//       今は解消していることを、部品を呼んで確かめる。統一の前の試験（記録の時点）の題を各試験の先頭に残す。
//       穴を塞いだもの（security の審査の役割への経験の漏れ、系統の別名、worker の役割の script による feedback、扱えない形の範囲、
//       保護された範囲の節、experience の verify）は判例として、直前の版（統一の前）で落ちることを確かめてある。

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import * as V from '../lib/vocab.mjs';
import * as B from '../lib/bridge.mjs';
import * as rsMod from '../runstate.mjs';
import { parseActor, parseEvent, DEFAULT_CONFIG, openRun, defDigestOf, memoryRun } from '../runstate.mjs';
import { openTrace, SCRIPT_ROLES, parseTs, check as trCheck, linksFromEvidence } from '../trace.mjs';
import { openExperience, isJudicialRole as exIsJudicial, check as exCheck } from '../experience.mjs';
import { openImprovements, JUDICIAL_ROLES as IM_JUDICIAL, check as imCheck, CAPS_PATH, policyLineOf as imPolicyLineOf } from '../improvement.mjs';
import { validateTeam, catalogFromCapabilities, normLineage as teamNormLineage } from '../team.mjs';
import { STATUSES } from '../taskgraph.mjs';
import { openChain, Refused } from '../lib/chain.mjs';
import { runWalkthrough, refusalOf, TICKETS, CAPS_FILE, PACK_FILE, ACTORS } from '../examples/walkthrough.mjs';

const dirs = [];
const scratch = () => { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'vgdd-next-int-')); dirs.push(d); return d; };
after(() => { for (const d of dirs) fs.rmSync(d, { recursive: true, force: true }); });

const caps = JSON.parse(fs.readFileSync(CAPS_FILE, 'utf8'));
const pack = JSON.parse(fs.readFileSync(PACK_FILE, 'utf8'));
const hex = (c, n) => c.repeat(n);
const SD = `sha256:${hex('a', 64)}`;
const A = ACTORS;
/** 例外（Refused）を { code, guards } にして返す。通ったら null */
const refused = (fn) => { try { fn(); return null; } catch (e) { if (!(e instanceof Refused)) throw e; return refusalOf(e); } };
const CFG = () => ({ ...JSON.parse(JSON.stringify(DEFAULT_CONFIG)), concurrent_work: 2, policy_line: 'p0.4' });
/** 1 つの節を review まで進めた実行の記録 */
function runToReview(dir, { protectedPaths = [], node = 'T-101', request = hex('a', 40) } = {}) {
  const run = openRun(path.join(dir, 'r.jsonl'));
  let n = 0; const go = (a, e) => run.apply(a, { event_id: `e${++n}`, ...e });
  go(A.owner, { op: 'config', ...CFG(), protected: protectedPaths });
  const def = { id: node, depends_on: [], resources: ['src/a/**'] };
  go(A.head, { op: 'plan', nodes: [def] });
  go(A.owner, { op: 'approve', node, spec_digest: SD, policy_line: 'p0.4', def_digest: defDigestOf(def) });
  go(A.head, { op: 'start', node, spec_digest: SD, lease_sec: 60 });
  go(A.head, { op: 'submit', node, request });
  return { run, go };
}
const J = (kind, lineage, verdict = 'APPROVED') => ({ kind, judge: `${kind}-${lineage}`, lineage, verdict, major: false });

// =====================================================================
// 前半：結合の流れ
// =====================================================================
describe('結合：3 つの票を開発の領域パックで進める（共通の語彙とつなぎの関数だけで、変換なしに通る）', () => {
  let W;
  before(() => { W = runWalkthrough({ dir: scratch() }); });

  it('段 1：領域パックが通り、票の ID の宣言・司法・保護の範囲が bridge で runstate の設定になる', () => {
    assert.equal(W.packResult.ok, true);
    assert.equal(W.pack.id, 'software-dev');
    assert.deepEqual(W.workItem, { prefix: 'T-', digits: [3, 4] });
    for (const t of TICKETS) assert.equal(V.makeWorkItemId(W.workItem)(t.id), true);
    assert.deepEqual(W.jud.judiciary, [{ kind: 'judge', lineage: 'claude' }, { kind: 'judge', lineage: 'codex' }]);
    assert.equal(W.jud.security_lineage, 'codex');
    assert.deepEqual(W.prot, [...pack.protected].sort());
    assert.equal(W.policyLine, 'p0.4');
  });

  it('段 2：編成案が通る（limits.concurrent_work は runstate と同じ意味）。catalog は権限の表の roles から作る。裁判所は編成に入れられない', () => {
    assert.equal(W.teamResult.ok, true);
    assert.equal(W.teamResult.requires_approval, true);
    assert.equal(W.teamResult.effect, 'none');
    assert.deepEqual(Object.keys(W.catalog).sort(), Object.keys(caps.roles).sort());
    assert.equal(W.teamContext.limits.concurrent_work, W.run.state().config.concurrent_work);
    assert.equal(W.teamRefusal.ok, false);
    assert.ok(W.teamRefusal.violations.some((v) => v.guard === 'TM-HUMAN-SEAT'));
  });

  it('段 3：config・plan・approve の後、next() が着手の組（T-101・T-102）と待ち（T-103）を返す。節の id は票の ID のまま', () => {
    assert.deepEqual([...W.next1.start].sort(), ['T-101', 'T-102']);
    assert.ok(['single', 'parallel', 'staged'].includes(W.next1.recommend.topology));
    assert.ok(W.next1.waiting.find((x) => x.id === 'T-103').reasons.every((r) => r.startsWith('waiting_dependency')));
    const first = W.rows[0];
    assert.equal(first.op, 'config');
    assert.deepEqual(first.actor, V.normActor(A.owner));
    assert.deepEqual(first.judiciary, [{ kind: 'judge', lineage: 'claude' }, { kind: 'judge', lineage: 'codex' }]);
    assert.equal(first.security_lineage, 'codex');
    const s = W.run.state();
    assert.equal(s.config.policy_line, 'p0.4');
    assert.deepEqual(s.config.work_item, { prefix: 'T-', digits: [3, 4] });
    assert.deepEqual(s.nodes['T-101'].requirements, ['R-1']);
    assert.equal(s.nodes['T-102'].security_review, true);
    assert.ok(W.refusals.some((r) => r.stage === 3 && r.guards.includes('RS-PROTECTED')));
  });

  it('段 4：着手した作業員が自分の行為者で取り出す（最初は空）。取り出しの行に行為者が残る', () => {
    for (const r of [W.r101, W.r102]) { assert.deepEqual(r.items, []); assert.equal(r.rendered, ''); assert.equal(r.searchKind, 'lexical'); }
    const rows = openChain(W.files.experience).read().filter((r) => r.op === 'retrieved');
    assert.ok(rows.length >= 2);
    for (const r of rows) assert.ok(V.sameActor(r.actor, A.worker1) || V.sameActor(r.actor, A.worker2));
  });

  it('段 5：T-101 は差し戻し → 再申請で合格、T-102 は security を含めて合格。作業員は assignee、統合の参照と申請の履歴が節に残る', () => {
    assert.equal(W.v1.kind, 'return');
    assert.equal(W.v1.to, 'in_progress');
    assert.equal(W.v1.node.returns, 1);
    assert.equal(W.v2.kind, 'pass');
    assert.equal(W.v3.kind, 'pass');
    const s = W.run.state();
    for (const id of ['T-101', 'T-102', 'T-103']) assert.equal(s.nodes[id].status, 'merged');
    const n = s.nodes['T-101'];
    assert.equal(n.returns, 1);
    assert.equal(n.attempts, 2, 'start の 1 回と、差し戻しでの作業員の起動し直し 1 回');
    assert.equal(n.merge, W.mergeSha['T-101']);
    assert.deepEqual(n.requests.map((x) => [x.request, x.kind]), [[W.req['T-101'][0], 'return'], [W.req['T-101'][1], 'pass']]);
    assert.deepEqual(s.nodes['T-102'].assignee, V.normActor(A.worker2));
    const sec = W.rows.find((r) => r.op === 'verdict' && r.node === 'T-102');
    assert.ok(sec.verdicts.some((v) => v.kind === 'security' && v.lineage === 'codex' && v.verdict === 'APPROVED'));
  });

  it('段 6：判定の refs の指摘への参照から reflection（bridge.provenanceFromVerdict）→ induce → 昇格 → T-103 の着手の後に引用の形で出る', () => {
    assert.equal(W.refl.length, 3);
    for (const r of W.refl) { assert.equal(r.layer, 'reflection'); assert.equal(r.trust, 'grounded'); assert.equal(r.provenance[0].kind, 'verdict_finding'); }
    assert.deepEqual(W.refl.map((r) => r.provenance[0].task), ['T-101', 'T-102', 'T-090']);
    assert.equal(W.refl[0].provenance[0].ref, `${V.verdictId(W.req['T-101'][0], 'codex-judge')}#finding-1`);
    assert.equal(W.induced.layer, 'experience');
    assert.equal(W.promoted.status, 'adopted');
    const top = W.r103.items[0];
    assert.equal(top.id, W.induced.id);
    assert.equal(top.status, 'adopted');
    assert.match(W.r103.rendered, /囲みの中は\*\*引用\*\*/);
    assert.ok(W.r103.rendered.includes('```text'));
    assert.ok(W.r103.rendered.includes(W.induced.text.normalize('NFKC')));
    assert.ok(W.r103.items.length >= 2, '候補のままの reflection も出る');
    assert.ok(W.r103.rendered.includes('未検証の仮説'));
  });

  it('段 6：経験が渡された票の判定から評価が付く（bridge.feedbackFromRun：着手から申請までの間の、着手した作業員の取り出しだけ）。司法と security には渡らない', () => {
    assert.equal(W.fb[0].helpful, 1);
    assert.equal(W.fb[0].harmful, 0);
    const f = W.fbPlan.feedback.find((x) => x.evidence.task === 'T-103');
    assert.equal(f.outcome, 'helpful');
    assert.ok(f.item_ids.includes(W.induced.id));
    assert.equal(W.exp.state().items.get(W.induced.id).helpful, 1);
    // 判定の後に、申告の票（T-101・最初は差し戻し）を指定して取り出しても、評価には数えない（E-1）
    assert.equal(W.lateFb.feedback.some((x) => x.evidence.task === 'T-101'), false);
    assert.ok(W.lateFb.skipped.some((x) => x.task === 'T-101' && /着手から申請までの間にない/.test(x.reason)));
    assert.ok(W.judgeAsk.refused && W.judgeAsk.items.length === 0 && W.judgeAsk.rendered === '');
    assert.ok(W.securityAsk.refused && W.securityAsk.items.length === 0);
  });

  it('段 7：bridge.linksFromRun で取り込んだつながりで、3 要件とも全段がそろい、障害はまだない。差し戻された 1 回目の申請が見える', () => {
    for (const row of W.cov.rows) {
      for (const k of ['ticket', 'spec', 'approval', 'request', 'audit', 'verdict', 'merge', 'acceptance']) assert.equal(row.stages[k], true, `${row.requirement}.${k}`);
      assert.equal(row.stages.incident, false);
    }
    assert.deepEqual(W.cov.rows.map((r) => r.requirement), ['R-1', 'R-2', 'R-3']);
    const r1 = W.cov.rows[0];
    assert.deepEqual([r1.requests, r1.returned_requests, r1.approved_requests], [2, 1, 1]);
    assert.equal(r1.verdict_basis, 'required_kinds');
    assert.equal(W.cov.rows[1].verdict_basis, 'required_kinds', 'T-102 は security_review つきで、必須の判定の種類に codex-security が入る');
    assert.equal(W.cov.integrity.ok, true);
    assert.deepEqual(W.fromRun.skipped, []);
  });

  it('段 7：gaps は差し戻された 1 回目の申請の 2 件だけ。障害を足すと「対応の票がない」が出て、R-3 の障害に数えられる', () => {
    const first = W.req['T-101'][0];
    assert.deepEqual(W.gaps1.gaps.map((g) => [g.code, g.kind, g.id]), [['REQUEST_CHANGES_REQUIRED', 'request', first], ['REQUEST_NOT_MERGED', 'request', first]]);
    assert.equal(W.gaps1.undetermined_count, 0);
    assert.deepEqual(W.gaps2.gaps.map((g) => g.code).sort(), ['INCIDENT_NO_TICKET', 'REQUEST_CHANGES_REQUIRED', 'REQUEST_NOT_MERGED']);
    assert.equal(W.gaps2.gaps.find((g) => g.code === 'INCIDENT_NO_TICKET').id, 'INC-001');
    assert.deepEqual(W.cov2.rows.find((r) => r.requirement === 'R-3').incidents, ['INC-001']);
    assert.deepEqual(W.cov2.rows.find((r) => r.requirement === 'R-1').incidents, []);
  });

  it('段 7：承認の指紋は apply の戻り値の digest と同じで、trace をたどると上流（要件・目標）と下流（仕様・承認・申請・統合・受け入れ）に同じ値で戻る', () => {
    const t = W.tr.trace({ kind: 'ticket', id: 'T-101' }, { direction: 'both' });
    assert.equal(t.found, true);
    const upKinds = new Set(t.up.nodes.map((n) => n.kind));
    assert.ok(upKinds.has('requirement') && upKinds.has('goal'));
    const ids = t.down.nodes.map((n) => n.id);
    for (const x of [W.specDigest['T-101'], W.approveHash['T-101'], ...W.req['T-101'], W.mergeSha['T-101'], W.accId['T-101']]) assert.ok(ids.includes(x), x);
    const row = W.rows.find((r) => r.op === 'approve' && r.node === 'T-101');
    assert.equal(W.approveHash['T-101'], V.asDigest(row.hash));
  });

  it('段 8：手順の改善は裁判所のスクリプトの評価・codex の審査・オーナーの採用で通る。経験から導いたことと試験の数の前後が残る', () => {
    const p = W.im.get(W.playbook.id);
    assert.equal(p.tier, 'playbook');
    assert.equal(p.status, 'adopted');
    assert.deepEqual(p.content.derived_from, [W.induced.id]);
    assert.equal(p.route.lane, 'standard');
    const ev = p.evaluations[0].evidence.conformance;
    assert.ok(ev.after.total > ev.before.total);
    assert.ok(ev.new_cases_fail_on_before >= 1);
    assert.deepEqual(p.reviews.map((r) => [r.actor.role, r.actor.lineage, r.verdict]), [['codex_judge', 'codex', 'APPROVED'], ['judge', 'claude', 'APPROVED']]); // im.v5：2 つの系統
    assert.deepEqual(p.evaluations[0].actor, V.normActor(A.gate));
    assert.equal(W.im.adoptionValid(p.id), true);
    const t = W.tr.trace({ kind: 'improvement', id: W.playbook.id }, { direction: 'up' });
    assert.ok(t.up.nodes.some((n) => n.kind === 'experience' && n.id === W.induced.id));
  });

  it('段 8（E-2）：Claude の提案者の緩める法律は、憲法審査なしでは採用できず、系統を偽る・別名の憲法審査は拒まれ、憲法審査（claude）＋ codex の judge ＋オーナーで正直に通る。締める変更は通常の経路', () => {
    assert.equal(W.dLoose.class, 'loosening');
    assert.equal(W.lawLoose.route.lane, 'full_legislative');
    const g8 = W.refusals.filter((r) => r.stage === 8).map((r) => r.guards);
    assert.ok(g8[0].includes('IM-FULL-LEGISLATIVE'));
    assert.ok(g8[1].includes('IM-ACTOR-SHAPE'), '系統を codex と偽る憲法審査');
    assert.ok(g8[2].includes('IM-ACTOR-SHAPE'), '別名 anthropic');
    const p = W.im.get(W.lawLoose.id);
    assert.equal(p.status, 'adopted');
    assert.deepEqual(p.reviews.map((r) => [r.actor.role, r.actor.lineage]).sort(), [['codex_judge', 'codex'], ['constitutional_review', 'claude']]);
    assert.equal(W.dTight.class, 'tightening');
    assert.equal(W.lawTight.route.lane, 'standard');
    assert.equal(W.im.get(W.lawTight.id).status, 'adopted');
  });

  it('段 9：同じ行為者のオブジェクトで、行政の長は verdict・approve・release・採用・昇格・feedback・つながりの記録をどれも起こせない', () => {
    const labels = W.refusals.filter((r) => r.stage === 9).map((r) => r.label);
    for (const needle of ['verdict', 'approve', 'release', '採用', '昇格', 'feedback', 'つながり']) assert.ok(labels.some((l) => l.includes(needle)), needle);
    const g = (needle) => W.refusals.find((r) => r.stage === 9 && r.label.includes(needle)).guards;
    assert.ok(g('verdict').includes('RS-ROLE-OP'));
    assert.ok(g('approve').includes('RS-ROLE-OP'));
    assert.ok(g('release').includes('RS-ROLE-OP'));
    assert.ok(g('採用').includes('IM-ADOPT-HUMAN-OWNER'));
    assert.deepEqual(g('昇格'), ['EX-PROMOTE-OWNER']);
    assert.deepEqual(g('行政の長が feedback'), ['EX-FEEDBACK-ACTOR']);
    assert.deepEqual(g('夜間の代行'), ['EX-FEEDBACK-ACTOR']);
    assert.deepEqual(g('つながり'), ['TR-WRITER-ALLOWED']);
  });

  it('段 9：停止の後は start が拒まれ、再開の後に続けられる。全部の記録の verify が ok（開き直しても同じ）', () => {
    assert.ok(W.refusals.some((r) => r.stage === 9 && r.guards.includes('RS-STOPPED')));
    assert.equal(W.run.state().stopped, false);
    assert.equal(W.run.state().nodes['T-104'].status, 'in_progress');
    for (const k of ['run', 'experience', 'trace', 'improvement']) assert.equal(W.verify[k].ok, true, k);
    assert.equal(openRun(W.files.run).verify().ok, true);
    assert.equal(openTrace(W.files.trace).verify().ok, true);
    assert.equal(openExperience(W.files.experience).verify().ok, true);
  });

  it('値の書き換え（adaptations）は 0 件。拒否はすべて Refused(guard_violation) と violations（純関数の検査と retrieve は戻り値の violations）', () => {
    assert.deepEqual(W.adaptations, []);
    for (const r of W.refusals) { assert.equal(r.hasViolations, true, r.label); assert.ok(r.guards.length > 0, r.label); }
    assert.ok(W.refusals.filter((r) => r.code !== null).every((r) => r.code === 'guard_violation'));
  });
});

// =====================================================================
// 後半：解消した食い違い
// =====================================================================
describe('解消：行為者の表し方（role・kind・id・lineage）', () => {
  it('（前：runstate は lineage を拒み improvement は必須）同じ行為者のオブジェクトを全部品が受け、同じ形で記録する', () => {
    const d = scratch();
    const { run } = runToReview(d);
    const rows = openChain(path.join(d, 'r.jsonl')).read();
    assert.deepEqual(rows.find((r) => r.op === 'plan').actor, V.normActor(A.head));
    const im = openImprovements(path.join(d, 'i.jsonl'), { currentCapabilities: caps });
    assert.equal(im.propose(A.head, { title: 't', tier: 'playbook', target: { name: 'x' }, content: 'c' }).proposer.lineage, 'claude');
    const t = openTrace(path.join(d, 't.jsonl'));
    assert.deepEqual(t.link(A.importer, { rel: 'satisfies', from: { kind: 'ticket', id: 'T-101' }, to: { kind: 'requirement', id: 'R-1' } }).actor, V.normActor(A.importer));
    const ex = openExperience(path.join(d, 'e.jsonl'));
    ex.add(A.gate, { text: 'abc', scope: { domain: 'software-dev', roles: ['worker'], tags: [] }, provenance: [{ kind: 'obs', ref: 'x', task: 'T-101' }] });
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(d, 'e.jsonl'), 'utf8').split('\n')[0]).actor, V.normActor(A.gate));
    assert.ok(run.state());
  });

  it('（前：役割の名前の一覧が部品ごとに違い、共通は owner だけ）役割の名前は vocab の表 1 つで、権限の表と食い違いがない', () => {
    assert.deepEqual(V.checkAgainstCapabilities(caps), []);
    for (const r of rsMod.ROLES) assert.ok(V.ROLES.includes(r), r);
    for (const r of SCRIPT_ROLES) assert.ok(V.ROLES.includes(r), r);
    for (const r of IM_JUDICIAL) assert.equal(V.isJudicialRole(r), true, r);
    const catalog = catalogFromCapabilities(caps);
    for (const r of Object.keys(catalog)) assert.ok(V.ROLES.includes(r), r);
    for (const old of ['executive', 'court', 'court_script', 'night_agent', 'release_script']) assert.equal(V.normRole(old), null, old);
  });

  it('（前：作業員は runstate の行為者になれず、起こした側の id が worker に入った）作業員は assignee として節に記録される', () => {
    const d = scratch();
    const run = openRun(path.join(d, 'r.jsonl'));
    run.apply(A.owner, { op: 'config', event_id: 'c1', ...CFG() });
    run.apply(A.head, { op: 'plan', event_id: 'p1', nodes: [{ id: 'T-101', depends_on: [], resources: ['a/**'] }] });
    run.apply(A.owner, { op: 'approve', event_id: 'a1', node: 'T-101', spec_digest: SD, policy_line: 'p0.4', def_digest: run.state().nodes['T-101'].def_digest });
    run.apply(A.head, { op: 'start', event_id: 's1', node: 'T-101', spec_digest: SD, lease_sec: 60, assignee: A.worker1 });
    const n = run.state().nodes['T-101'];
    assert.equal(n.started_by, 'exec-head');
    assert.deepEqual(n.assignee, V.normActor(A.worker1));
    assert.ok(refused(() => run.apply(A.worker1, { op: 'submit', event_id: 'u1', node: 'T-101', request: hex('a', 40) })).guards.includes('RS-ROLE-OP'), '作業員は申請しない（SPEC §2）');
  });

  it('（共通の限界のまま）行為者は申告で、行政の長が owner を名乗れば runstate は通す（README §5.1）', () => {
    const run = openRun(path.join(scratch(), 'r.jsonl'));
    run.apply({ role: 'owner', kind: 'human', id: 'exec-head' }, { op: 'config', event_id: 'c1', ...CFG() });
    assert.equal(run.state().config.policy_line, 'p0.4');
  });

  it('判例（前：experience は security の審査の役割を司法とみなさず経験を渡した）codex_security には渡らない', () => {
    const ex = openExperience(path.join(scratch(), 'e.jsonl'));
    ex.add(A.gate, { text: '入力検証の観点を確かめる', scope: { domain: 'software-dev', roles: ['worker'], tags: ['a'] }, provenance: [{ kind: 'verdict_finding', ref: 'VRD-aaaaaaaaaaaa-codex-security#f-1', task: 'T-101' }] });
    for (const role of ['codex_security', ' Codex_Security ', 'judge', 'codex_judge', 'constitutional_review', 'gate_runner']) {
      const got = ex.retrieve({ actor: A.worker1, audience: { role }, query: { text: '入力検証', domain: 'software-dev' } });
      assert.equal(got.items.length, 0, role); assert.ok(got.refused, role);
    }
    assert.equal(ex.retrieve({ actor: A.worker1, audience: { role: 'worker' }, query: { text: '入力検証', domain: 'software-dev' } }).items.length, 1);
    assert.ok(refused(() => ex.add(A.gate, { text: 'x', scope: { domain: 'software-dev', roles: ['codex_security'], tags: [] }, provenance: [{ kind: 'obs', ref: 'x', task: 'T-101' }] })).guards.includes('EX-SCOPE'));
  });

  it('（前：司法の判定は部分一致）判定は vocab の表の完全一致。表にない名前は司法かどうか推し量らず「使えない」として拒む', () => {
    assert.equal(exIsJudicial, V.isJudicialRole);
    for (const r of ['courtesy_bot', 'prejudice_check', 'court', 'judiciary']) {
      assert.equal(V.isJudicialRole(r), false, r);
      assert.ok(exCheck({ op: 'retrieve', audience: { role: r } }, ['EX-RETRIEVE-JUDGE']).violations.length === 1, r);
    }
  });

  it('判例（前：experience の feedback は kind: script なら role が worker でも通った）裁判所の側のスクリプト（gate_runner）だけ', () => {
    const ex = openExperience(path.join(scratch(), 'e.jsonl'));
    ex.add(A.gate, { text: 'abc', scope: { domain: 'software-dev', roles: ['worker'], tags: [] }, provenance: [{ kind: 'obs', ref: 'x', task: 'T-101' }] });
    const fb = (who) => () => ex.feedback(who, { item_ids: ['exp-000001'], outcome: 'helpful', evidence: { kind: 'verdict', ref: 'x1', task: 'T-101' } });
    assert.ok(refused(fb({ role: 'worker', kind: 'script', id: 'w' })).guards.includes('EX-FEEDBACK-ACTOR'));
    assert.deepEqual(refused(fb(A.night)).guards, ['EX-FEEDBACK-ACTOR']);
    assert.equal(fb(A.gate)()[0].helpful, 1);
  });
});

describe('解消：系統（lineage）の書式・正規化・別名', () => {
  it('（前：team はハイフン可・小文字化、runstate は不可・小文字化しない、trace は大文字不可）全部品が vocab の normLineage', () => {
    assert.equal(teamNormLineage, V.normLineage);
    assert.equal(V.normLineage(' Claude '), 'claude');
    for (const bad of ['open-ai', 'open_ai', 'gemini']) assert.equal(V.normLineage(bad), null, bad);
    const ev = (lineage) => parseEvent({ op: 'verdict', event_id: 'v1', node: 'T-101', request: hex('a', 40), audits: 'passed', verdicts: [{ kind: 'judge', judge: 'j', lineage, verdict: 'APPROVED', major: false }] }).ok;
    assert.equal(ev('open-ai'), false);
    assert.equal(ev('codex'), true);
  });

  it('（前：improvement は NFKC・小文字で比べ、runstate は別物として拒んだ）どの部品も Claude を claude にそろえて比べる', () => {
    const im = openImprovements(path.join(scratch(), 'i.jsonl'), { currentCapabilities: caps });
    const p = im.propose({ ...A.head, lineage: 'Claude' }, { title: 't', tier: 'playbook', target: { name: 'x' }, content: 'c' });
    im.evaluate(A.gate, p.id, { digest: p.digest, evidence: { conformance: { before: { total: 1, passed: 1 }, after: { total: 1, passed: 1 } } } });
    im.review({ role: 'judge', kind: 'ai', id: 'j', lineage: 'claude' }, p.id, { digest: p.digest, verdict: 'APPROVED', findings: [], review_input_digest: im.reviewInputFor(p.id).digest });
    // im.v5：同じ系統（Claude と claude は同じ）の審査だけでは、採用の時の 2 つの系統の要求を満たさない
    assert.deepEqual(refused(() => im.adopt(A.owner, p.id, { digest: p.digest, policy_line: 'p0.4' })).guards, ['IM-CROSS-LINEAGE']);
    assert.deepEqual(parseActor({ ...A.head, lineage: 'CLAUDE' }).actor.lineage, 'claude');
  });

  it('判例（前：improvement は claude の提案を anthropic の審査者が審査できた）知らない系統の別名は全部品で拒む', () => {
    const im = openImprovements(path.join(scratch(), 'i.jsonl'), { currentCapabilities: caps });
    const p = im.propose(A.head, { title: 't', tier: 'playbook', target: { name: 'x' }, content: 'c' });
    im.evaluate(A.gate, p.id, { digest: p.digest, evidence: { conformance: { before: { total: 1, passed: 1 }, after: { total: 1, passed: 1 } } } });
    const e = refused(() => im.review({ role: 'judge', kind: 'ai', id: 'j', lineage: 'anthropic' }, p.id, { digest: p.digest, verdict: 'APPROVED', findings: [], review_input_digest: im.reviewInputFor(p.id).digest }));
    assert.ok(e.guards.includes('IM-ACTOR-SHAPE'));
    assert.equal(im.get(p.id).status, 'evaluated');
    assert.equal(parseActor({ role: 'judge', kind: 'ai', id: 'j', lineage: 'anthropic' }).ok, false);
    const tv = validateTeam({ task: 'x', proposed_by: 'h', members: [{ id: 'w', template: 'worker', lineage: 'anthropic', scope: { resources: [], tools: [] } }, { id: 'k', template: 'codex_judge', scope: { resources: [], tools: [] } }] }, { catalog: catalogFromCapabilities(caps), ticket: { resources: [] }, limits: { concurrent_work: 4 } });
    assert.ok(tv.violations.some((v) => v.guard === 'TM-LINEAGE-HONEST'));
  });
});

describe('解消：ID と指紋の書式', () => {
  it('（前：領域パック・trace・experience は T-101、runstate は小文字だけ）同じ票の ID が全部品で通り、t-101 は全部品で拒む', () => {
    const plan = (id) => { const m = memoryRun(); try { m.apply(A.head, { op: 'plan', event_id: 'p', nodes: [{ id, depends_on: [], resources: ['a/**'] }] }); return true; } catch { return false; } };
    assert.equal(plan('T-101'), true);
    assert.equal(plan('t-101'), false);
    const d = scratch();
    const t = openTrace(path.join(d, 't.jsonl'));
    assert.equal(t.link(A.importer, { rel: 'satisfies', from: { kind: 'ticket', id: 'T-101' }, to: { kind: 'requirement', id: 'R-1' } }).seq, 1);
    assert.ok(refused(() => t.link(A.importer, { rel: 'satisfies', from: { kind: 'ticket', id: 't-101' }, to: { kind: 'requirement', id: 'R-2' } })).guards.includes('TR-ID-FORMAT'));
    const ex = openExperience(path.join(d, 'e.jsonl'));
    ex.add(A.gate, { text: 'abc', scope: { domain: 'software-dev', roles: ['worker'], tags: [] }, provenance: [{ kind: 'obs', ref: 'x', task: 'T-101' }] });
    assert.ok(refused(() => ex.add(A.gate, { text: 'abd', scope: { domain: 'software-dev', roles: ['worker'], tags: [] }, provenance: [{ kind: 'obs', ref: 'y', task: 't-101' }] })).guards.includes('EX-PROVENANCE'));
    assert.equal(V.makeWorkItemId(B.workItemFromDomainPack(pack).work_item)('T-101'), true);
  });

  it('（前：runstate の節の id は fix-login なども通り trace に写せなかった）runstate の節の id は宣言に合うものだけ', () => {
    for (const id of ['fix-login', 'T-1.2', 'T-12345', 'T-12']) {
      const m = memoryRun();
      assert.ok(refused(() => m.apply(A.head, { op: 'plan', event_id: 'p', nodes: [{ id, depends_on: [], resources: ['a/**'] }] })).guards.length > 0, id);
    }
  });

  it('（前：申請の参照が runstate は 7〜64 桁、trace は 40 桁だけ）両部品とも 40 桁の 16 進か sha256: 形の 2 形', () => {
    for (const q of [hex('a', 40), SD]) assert.equal(parseEvent({ op: 'submit', event_id: 'e1', node: 'T-101', request: q }).ok, true, q);
    for (const q of [hex('a', 12), hex('a', 7), hex('A', 40)]) assert.equal(parseEvent({ op: 'submit', event_id: 'e1', node: 'T-101', request: q }).ok, false, q);
    const t = openTrace(path.join(scratch(), 't.jsonl'));
    const tryReq = (id) => refused(() => t.link(A.importer, { rel: 'verifies', from: { kind: 'audit', id: V.auditId(hex('a', 40)) }, to: { kind: 'request', id } }));
    assert.equal(tryReq(hex('a', 40)), null);
    assert.ok(tryReq(hex('a', 12)).guards.includes('TR-ID-FORMAT'));
    const t2 = openTrace(path.join(scratch(), 't.jsonl'));
    assert.equal(t2.link(A.importer, { rel: 'verifies', from: { kind: 'audit', id: V.auditId(SD) }, to: { kind: 'request', id: SD } }).seq, 1);
  });

  it('（前：行の hash は接頭辞なし、trace の承認は sha256: つき）apply の戻り値の digest がそのまま trace の承認の id になる', () => {
    const d = scratch();
    const run = openRun(path.join(d, 'r.jsonl'));
    run.apply(A.owner, { op: 'config', event_id: 'c', ...CFG() });
    const def = { id: 'T-101', depends_on: [], resources: ['a/**'] };
    run.apply(A.head, { op: 'plan', event_id: 'p', nodes: [def] });
    const r = run.apply(A.owner, { op: 'approve', event_id: 'a', node: 'T-101', spec_digest: SD, policy_line: 'p0.4', def_digest: defDigestOf(def) });
    assert.equal(V.isDigest(r.digest), true);
    const t = openTrace(path.join(d, 't.jsonl'));
    assert.equal(t.link(A.importer, { rel: 'approves', from: { kind: 'approval', id: r.digest, digest: r.digest }, to: { kind: 'spec', id: SD, digest: SD } }).seq, 1);
  });

  it('（前：runstate の（種類, 系統）と trace の判定の種類の対応が表になかった）対応は vocab の REVIEW_MODES の 1 か所', () => {
    assert.equal(V.reviewModeOf('judge', 'claude'), 'judge');
    assert.equal(V.reviewModeOf('judge', 'codex'), 'codex-judge');
    assert.equal(V.reviewModeOf('security', 'codex'), 'codex-security');
    assert.equal(V.reviewModeOf('security', 'claude'), null);
    // runstate の config は、審査の種類に写せない系統を必須の審査にできない
    assert.equal(parseEvent({ op: 'config', event_id: 'c', ...CFG(), security_lineage: 'claude' }).ok, false);
  });

  it('（前：IMP-・exp- の書式は一致していた）改善提案と経験の id はそのまま trace に使える（変わらず）', () => {
    const W = runWalkthrough({ dir: scratch() });
    assert.match(W.playbook.id, /^IMP-\d{4}$/);
    assert.match(W.induced.id, /^exp-\d{6}$/);
    assert.ok(W.tr.trace({ kind: 'improvement', id: W.playbook.id }, { direction: 'up' }).up.nodes.some((n) => n.id === W.induced.id));
    assert.equal(V.isFindingRef(W.refl[0].provenance[0].ref), true, '指摘への参照の規約は vocab にある');
  });
});

describe('解消：範囲（resources）', () => {
  it('判例（前：runstate は扱えない形の範囲を plan で受け、他の節の着手を止め続けた）plan で拒む', () => {
    const m = memoryRun({ config: { concurrent_work: 2 } });
    const e = refused(() => m.apply(A.head, { op: 'plan', event_id: 'p', nodes: [{ id: 'T-101', depends_on: [], resources: ['src/[a]*'] }, { id: 'T-102', depends_on: [], resources: ['src/b/**'] }] }));
    assert.ok(e.guards.includes('RS-PLAN-RESOURCES'));
    assert.equal(m.state().order.length, 0);
  });

  it('判例（前：領域パックの protected を runstate が見ず、vgdd/kernel/** の節も plan に入った）protected に重なる節は拒む', () => {
    const prot = B.protectedFromDomainPack(pack).protected;
    const m = memoryRun({ config: { protected: prot } });
    for (const [i, res] of ['vgdd/kernel/**', 'vgdd/**', 'VGDD/x', '.claude/settings.json'].entries()) {
      assert.ok(refused(() => m.apply(A.head, { op: 'plan', event_id: `p-${i}`, nodes: [{ id: 'T-101', depends_on: [], resources: [res] }] })).guards.includes('RS-PROTECTED'), res);
    }
    assert.ok(refused(() => m.apply(A.owner, { op: 'plan', event_id: 'po', nodes: [{ id: 'T-101', depends_on: [], resources: ['vgdd/x'] }] })).guards.includes('RS-PROTECTED'), 'オーナーも');
    assert.equal(m.apply(A.head, { op: 'plan', event_id: 'ok', nodes: [{ id: 'T-101', depends_on: [], resources: ['src/**'] }] }).ok, true);
  });

  it('（前：team の limits.workers は長を含む総数、runstate の config.workers は同時の作業の数）同じ名前 concurrent_work で同じ意味', () => {
    const catalog = catalogFromCapabilities(caps);
    const m = (id, template, parent) => ({ id, template, ...(parent ? { parent } : {}), scope: { resources: [], tools: [] } });
    const plan = { task: 'x', proposed_by: 'h', members: [m('h', 'executive_head'), m('w1', 'worker', 'h'), m('w2', 'worker', 'h'), m('j', 'codex_judge')] };
    assert.equal(validateTeam(plan, { catalog, ticket: { resources: [] }, limits: { concurrent_work: 2 } }).ok, true, '長＋作業員 2 は同時 2');
    assert.ok(validateTeam(plan, { catalog, ticket: { resources: [] }, limits: { workers: 3 } }).violations.some((v) => v.guard === 'TM-CONTEXT-SHAPE'));
    assert.equal(Object.hasOwn(DEFAULT_CONFIG, 'workers'), false);
    assert.equal(DEFAULT_CONFIG.concurrent_work, 1);
  });
});

describe('解消：状態の名前・判定の結論の名前', () => {
  it('状態・判定・監査の名前は vocab の 1 か所（taskgraph・runstate・trace が同じ綴り）', () => {
    assert.equal(STATUSES, V.STATUSES);
    const W = runWalkthrough({ dir: scratch() });
    for (const n of Object.values(W.run.state().nodes)) assert.ok(V.STATUSES.includes(n.status));
    const vlinks = W.tr.state().links.filter((l) => l.rel === 'verifies' && l.to.id === W.req['T-101'][0]);
    assert.deepEqual(vlinks.map((l) => l.evidence.result).sort(), ['CHANGES_REQUIRED', 'CHANGES_REQUIRED', 'passed']);
  });

  it('（前：trace は結論の綴りの誤りを書く時に拒まず「不明」に倒した）書く時に拒む。improvement の審査は APPROVED・CHANGES_REQUIRED だけ（変わらず）', () => {
    const t = openTrace(path.join(scratch(), 't.jsonl'));
    const req = hex('a', 40);
    assert.ok(refused(() => t.link(A.importer, { rel: 'verifies', from: { kind: 'verdict', id: V.verdictId(req, 'judge') }, to: { kind: 'request', id: req }, evidence: { result: 'approved', at: '2026-11-14T09:00:00+09:00' } })).guards.includes('TR-INPUT-SHAPE'));
    assert.equal(t.link(A.importer, { rel: 'verifies', from: { kind: 'verdict', id: V.verdictId(req, 'judge') }, to: { kind: 'request', id: req }, evidence: { result: 'UNAVAILABLE', at: '2026-11-14T09:00:00+09:00' } }).seq, 1);
    const im = openImprovements(path.join(scratch(), 'i.jsonl'), { currentCapabilities: caps });
    const p = im.propose(A.head, { title: 't', tier: 'playbook', target: { name: 'x' }, content: 'c' });
    im.evaluate(A.gate, p.id, { digest: p.digest, evidence: { conformance: { before: { total: 1, passed: 1 }, after: { total: 1, passed: 1 } } } });
    assert.deepEqual(refused(() => im.review(A.judgeCodex, p.id, { digest: p.digest, verdict: 'UNAVAILABLE', findings: [], review_input_digest: im.reviewInputFor(p.id).digest })).guards, ['IM-INPUT-SHAPE']);
  });
});

describe('解消：時刻の書式', () => {
  it('記録の時刻（chain の at）は vocab の時刻の形で、全部の記録の行が parseTs で読める', () => {
    const W = runWalkthrough({ dir: scratch() });
    for (const f of ['run', 'trace', 'improvement', 'experience']) for (const r of openChain(W.files[f]).read()) assert.notEqual(V.parseTs(r.at), null, f);
  });

  it('（前：experience は +0900 を拒み trace は受けた）全部品が vocab の parseTs（+0900・時差なし・秒なしは null）', () => {
    assert.equal(parseTs, V.parseTs);
    const ex = openExperience(path.join(scratch(), 'e.jsonl'));
    const add = (expires_at) => refused(() => ex.add(A.gate, { text: 'abc', scope: { domain: 'software-dev', roles: ['worker'], tags: [] }, provenance: [{ kind: 'obs', ref: 'x', task: 'T-101' }], expires_at }));
    for (const bad of ['2027-01-01T00:00:00', '2027-01-01T00:00:00+0900']) assert.deepEqual(add(bad).guards, ['EX-EXPIRY']);
    assert.equal(add('2027-01-01T00:00:00+09:00'), null);
    assert.equal(V.parseTs('2026-11-14T09:00:00+0900'), null);
    assert.equal(V.kernelTsToIso('2026-11-14T09:00:00+0900'), '2026-11-14T09:00:00+09:00', 'Kernel の記録の +0900 は取り込みの関数だけが写す');
  });

  it('（前：trace の evidence.at は書く時に検査しなかった）書く時に拒む', () => {
    const t = openTrace(path.join(scratch(), 't.jsonl'));
    const r = refused(() => t.link(A.importer, { rel: 'verifies', from: { kind: 'verdict', id: V.verdictId(hex('a', 40), 'judge') }, to: { kind: 'request', id: hex('a', 40) }, evidence: { result: 'APPROVED', at: '2026-11-14 09:00' } }));
    assert.ok(r.guards.includes('TR-INPUT-SHAPE'));
  });
});

describe('解消：規則の版・epoch・設定の持ち方', () => {
  it('（前：experience だけ rules も epoch もなく type に操作名）全部の記録の行が type・rules・op を持ち、版は rs.v4・im.v5・tr.v4・ex.v2', () => {
    const W = runWalkthrough({ dir: scratch() });
    const first = (f) => openChain(W.files[f]).read()[0];
    assert.deepEqual([first('run').rules, first('run').op], ['rs.v4', 'config']); // 独立した審査 4 回目 R-1
    assert.equal(first('improvement').rules, 'im.v5'); // 独立した審査 4 回目 I-1
    assert.equal(first('trace').rules, 'tr.v4');
    const e = first('experience');
    assert.deepEqual([e.type, e.rules], ['vgdd.experience.v1', 'ex.v2']);
    assert.equal(e.op, 'add', '操作名は op に入る（空の取り出しは記録しないので、最初の行は reflection の追加）');
  });

  it('判例（前：experience の verify は鎖しか確かめず、別の設定で開くと過去の行の扱いが黙って変わった）verify は再生し、設定の写しの食い違いを出す', () => {
    const W = runWalkthrough({ dir: scratch() });
    const strict = openExperience(W.files.experience, { minSources: 5 });
    const v = strict.verify();
    assert.equal(v.ok, false);
    assert.ok(v.uncovered > 0);
    assert.ok(refused(() => strict.add(A.gate, { text: 'x', scope: { domain: 'software-dev', roles: ['worker'], tags: [] }, provenance: [{ kind: 'obs', ref: 'x', task: 'T-101' }] })).guards.includes('EX-RULES-VERSION'));
    assert.equal(openExperience(W.files.experience).verify().ok, true);
    strict.epoch(A.owner, { reason: '帰納の下限を 5 に締めた' });
    assert.equal(strict.verify().ok, true);
    assert.equal(strict.state().items.get(W.induced.id).status, 'adopted', '覆われた行は書いた時の設定で確かめる');
  });

  it('（前：trace の ticketId・improvement の上限は開く側の引数で記録に残らなかった）行に設定の写しを残し、別の設定で開くと気づく。runstate は記録の中の config（変わらず）', () => {
    const W = runWalkthrough({ dir: scratch() });
    const other = openTrace(W.files.trace, { ticketId: { prefix: 'X-', digits: [3, 3] } });
    assert.equal(other.verify().ok, false);
    assert.equal(openTrace(W.files.trace).verify().ok, true);
    assert.deepEqual(openChain(W.files.trace).read()[0].cfg, { ticket_id: { prefix: 'T-', digits: [3, 4] } });
    assert.equal(openImprovements(W.files.improvement, { currentCapabilities: caps, maxOpenPerActor: 9 }).verify().ok, false);
    assert.equal(openImprovements(W.files.improvement, { currentCapabilities: caps }).adoptionValid(W.playbook.id), true);
    assert.equal(openImprovements(W.files.improvement, { policyLine: 'p0.5' }).adoptionValid(W.playbook.id), false, '法律の系統は設定でなく今の法律（変われば採用は効かない。設計どおり）');
    assert.throws(() => openRun(W.files.run, { concurrent_work: 64 }), (e) => e instanceof Refused && e.code === 'bad_option');
  });

  it('（前：法律の系統の取り出しが 3 か所に別々）vocab の policyLineOf の 1 か所', () => {
    assert.equal(imPolicyLineOf(caps), V.policyLineOf(caps));
    assert.equal(V.policyLineOf(caps.kernel_version), 'p0.4');
    assert.equal(parseEvent({ op: 'approve', event_id: 'e1', node: 'T-101', spec_digest: SD, policy_line: 'p0.4.14', def_digest: SD }).ok, false, 'approve は pN.N だけ（policyLineOf で写して渡す）');
  });
});

describe('解消：つながらない箇所', () => {
  it('（前：apply は hash を返さず、差し戻された申請の指紋が state() から消え、def_digest は非公開）digest・申請の履歴・defDigestOf がある', () => {
    const W = runWalkthrough({ dir: scratch() });
    assert.ok(V.isDigest(W.v1.digest));
    assert.deepEqual(Object.keys(W.v1).sort(), ['at', 'digest', 'duplicate', 'kind', 'node', 'ok', 'seq', 'to']);
    const n = W.run.state().nodes['T-101'];
    assert.equal(n.requests[0].request, W.req['T-101'][0]);
    assert.equal(n.requests[0].kind, 'return');
    assert.notEqual(V.parseTs(n.requests[0].at), null);
    assert.equal(typeof rsMod.defDigestOf, 'function');
    assert.equal(defDigestOf(n), n.def_digest);
  });

  it('（前：verdict の記録に判定の id・指摘への参照・統合の参照を残す欄がなかった）refs と merge を記録に残し、bridge が使う', () => {
    const W = runWalkthrough({ dir: scratch() });
    const vd = W.rows.find((r) => r.op === 'verdict' && r.node === 'T-101');
    assert.ok(Array.isArray(vd.refs.verdicts) && vd.refs.findings.length === 1 && V.isAuditId(vd.refs.audit.id));
    assert.deepEqual(B.provenanceFromVerdict(vd).provenance, [{ kind: 'verdict_finding', ref: vd.refs.findings[0], task: 'T-101' }]);
    const pass = W.rows.find((r) => r.op === 'verdict' && r.node === 'T-101' && r.request === W.req['T-101'][1]);
    assert.equal(pass.merge, W.mergeSha['T-101']);
    // 統合の参照は merged になる出来事だけが持てる
    const { go } = runToReview(scratch());
    assert.ok(refused(() => go(A.gate, { op: 'verdict', node: 'T-101', request: hex('a', 40), audits: 'failed', verdicts: [J('judge', 'claude'), J('judge', 'codex')], merge: hex('b', 40) })).guards.includes('RS-MERGE-REF'));
  });

  it('（前：runstate の記録から trace のつながりを作る関数がなかった）bridge.linksFromRun は trace.linksFromEvidence と同じ戻り値の形で、そのまま書ける', () => {
    const W = runWalkthrough({ dir: scratch() });
    const out = B.linksFromRun(W.rows);
    const ev = linksFromEvidence({});
    for (const k of ['links', 'skipped']) { assert.ok(Array.isArray(out[k]), k); assert.ok(Array.isArray(ev[k]), k); }
    const t = openTrace(path.join(scratch(), 't.jsonl'));
    assert.deepEqual(t.linkMany(A.importer, out.links).refused, []);
    assert.deepEqual(linksFromEvidence({ approvals: W.rows.filter((r) => r.op === 'approve') }).links, [], 'Kernel の記録の取り込みは別の関数（変わらず）');
  });

  it('（前：領域パックの judiciary から config.judiciary を作る関数がなかった）bridge.judiciaryFromDomainPack', () => {
    assert.deepEqual(B.judiciaryFromDomainPack(pack).judiciary, DEFAULT_CONFIG.judiciary.map((j) => ({ ...j })));
    const three = structuredClone(pack); three.judiciary.min_judges = 3;
    const r = B.judiciaryFromDomainPack(three);
    assert.equal(r.judiciary, null);
    assert.match(r.reason, /系統/);
  });

  it('（前：codex の security 審査の役割が capabilities.json になく team に入れられない）vocab の表にはあるが、権限の表に足すまで編成には入れない（残した食い違い）', () => {
    assert.ok(V.ROLES_NOT_IN_CAPABILITIES.includes('codex_security'));
    assert.equal(Object.hasOwn(catalogFromCapabilities(caps), 'codex_security'), false);
    const v = validateTeam({ task: 'x', proposed_by: 'h', members: [{ id: 'h', template: 'executive_head', scope: { resources: [], tools: [] } }, { id: 'j', template: 'codex_judge', scope: { resources: [], tools: [] } }, { id: 's', template: 'codex_security', scope: { resources: [], tools: [] } }] }, { catalog: catalogFromCapabilities(caps), ticket: { resources: [] }, limits: { concurrent_work: 3 } });
    assert.ok(v.violations.some((x) => x.guard === 'TM-TEMPLATE-EXISTS'));
  });

  it('（前の限界 §5.3 の解消、E-2）Claude の提案者の緩める変更は、正直な憲法審査（claude）＋ codex の judge で採用できる。憲法審査が codex を名乗ると拒む', () => {
    const d = scratch();
    const loosen = structuredClone(caps);
    loosen.capabilities.find((c) => c.id === 'CAP-MAIN-INTEGRATE').allowed.push('worker');
    const runIt = (lineage) => {
      const im = openImprovements(path.join(d, `i-${lineage}.jsonl`), { currentCapabilities: caps });
      const p = im.propose(A.head, { title: 'x', tier: 'law', target: { paths: [CAPS_PATH] }, content: { capabilities: loosen }, capabilities: { old: caps, new: loosen } });
      im.evaluate(A.gate, p.id, { digest: p.digest, evidence: { conformance: { before: { total: 10, passed: 10 }, after: { total: 11, passed: 11 }, new_cases_fail_on_before: 1 } } });
      const rv = (who) => im.review(who, p.id, { digest: p.digest, verdict: 'APPROVED', findings: [], review_input_digest: im.reviewInputFor(p.id).digest });
      rv(A.judgeCodex);
      const cr = refused(() => rv({ ...A.constClaude, lineage }));
      return cr ? { cr, adopted: false } : { cr, adopted: im.adopt(A.owner, p.id, { digest: p.digest, policy_line: 'p0.4' }).status === 'adopted' };
    };
    assert.deepEqual(runIt('claude'), { cr: null, adopted: true });
    assert.ok(runIt('codex').cr.guards.includes('IM-ACTOR-SHAPE'), '系統を偽る申告は通らない（誘因が正しい向き）');
  });
});

describe('解消：API・拒否の出方', () => {
  it('（前：拒否の出方が 4 通り）状態を書く関数は全部品で Refused(guard_violation) と violations。純関数の検査は { ok, violations }、retrieve は { refused, violations }', () => {
    const d = scratch();
    const run = openRun(path.join(d, 'r.jsonl'));
    const e1 = (() => { try { run.apply(A.owner, { op: 'stop', event_id: 's', reason: 'x' }); } catch (e) { return e; } return null; })();
    const im = openImprovements(path.join(d, 'i.jsonl'), { currentCapabilities: caps });
    const e2 = (() => { try { im.adopt(A.head, 'IMP-0001', {}); } catch (e) { return e; } return null; })();
    const ex = openExperience(path.join(d, 'e.jsonl'));
    const e3 = (() => { try { ex.promote(A.head, 'exp-000001', {}); } catch (e) { return e; } return null; })();
    const t = openTrace(path.join(d, 't.jsonl'));
    const e4 = (() => { try { t.link(A.head, { rel: 'satisfies', from: { kind: 'ticket', id: 'T-101' }, to: { kind: 'requirement', id: 'R-1' } }); } catch (e) { return e; } return null; })();
    for (const e of [e1, e2, e3, e4]) { assert.equal(e.code, 'guard_violation'); assert.ok(Array.isArray(e.violations) && e.violations.length > 0); }
    assert.equal(validateTeam({ task: 'x', proposed_by: 'h', members: [] }, { catalog: {}, ticket: { resources: [] }, limits: { concurrent_work: 1 } }).ok, false);
    const r = ex.retrieve({ audience: { role: 'judge' } });
    assert.ok(r.refused && Array.isArray(r.violations) && r.items.length === 0);
  });

  it('retrieve の query.domain を省くと 0 件（変わらず。scope.domain との完全一致）', () => {
    const W = runWalkthrough({ dir: scratch() });
    assert.ok(W.exp.retrieve({ actor: A.worker1, audience: { role: 'worker', task: 'T-103' }, query: { text: '境界値', domain: 'software-dev' } }).items.length > 0);
    assert.deepEqual(W.exp.retrieve({ actor: A.worker1, audience: { role: 'worker', task: 'T-103' }, query: { text: '境界値' } }).items, []);
  });

  it('戻り値の形：runstate は { ok, seq, digest, node, kind, to }、improvement は提案の状態、experience は項目（feedback は配列）、trace はつながり', () => {
    const W = runWalkthrough({ dir: scratch() });
    assert.equal(W.v1.ok, true);
    assert.equal(Array.isArray(W.fb), true);
    assert.equal(typeof W.playbook.status, 'string');
  });

  it('同じ内容の出来事の再送は runstate では { ok:true, duplicate:true }（変わらず）', () => {
    const run = openRun(path.join(scratch(), 'r.jsonl'));
    const ev = { op: 'config', event_id: 'c1', ...CFG() };
    assert.equal(run.apply(A.owner, ev).duplicate, false);
    assert.deepEqual(run.apply(A.owner, ev), { ok: true, duplicate: true });
  });

  it('改善提案の check も同じ行為者のオブジェクトを受ける（行為者の形のガードだけで見て通る）', () => {
    assert.equal(imCheck({ actor: A.gate }, ['IM-ACTOR-SHAPE']).ok, true);
    assert.equal(trCheck({ op: 'link', actor: A.importer }, ['TR-ACTOR-SHAPE']).ok, true);
    assert.equal(exCheck({ op: 'add', actor: A.gate }, ['EX-ACTOR']).ok, true);
  });
});
