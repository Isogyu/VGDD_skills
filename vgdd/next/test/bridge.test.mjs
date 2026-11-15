// 部品の間をつなぐ純関数（lib/bridge.mjs）の試験
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import * as B from '../lib/bridge.mjs';
import * as V from '../lib/vocab.mjs';
import { openRun, DEFAULT_CONFIG, defDigestOf } from '../runstate.mjs';
import { openChain } from '../lib/chain.mjs';
import { openTrace } from '../trace.mjs';
import { openExperience } from '../experience.mjs';
import { PACK_FILE, ACTORS as A } from '../examples/walkthrough.mjs';

const pack = JSON.parse(fs.readFileSync(PACK_FILE, 'utf8'));
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'vgdd-next-'));
const SD = `sha256:${'a'.repeat(64)}`;
const J = (kind, lineage, verdict = 'APPROVED') => ({ kind, judge: `${kind}-${lineage}`, lineage, verdict, major: false });

/** 1 節の実行の記録（verdicts の列を順に取り込む） */
function mkRun(rounds, { refs = true, security = false } = {}) {
  const d = tmp(); const f = path.join(d, 'r.jsonl');
  const run = openRun(f);
  let n = 0; const go = (a, e) => run.apply(a, { event_id: `e${++n}`, ...e });
  go(A.owner, { op: 'config', ...JSON.parse(JSON.stringify(DEFAULT_CONFIG)), concurrent_work: 2, policy_line: 'p0.4' });
  const def = { id: 'T-101', depends_on: [], resources: ['src/a/**'], requirements: ['R-1'], ...(security ? { security_review: true } : {}) };
  go(A.head, { op: 'plan', nodes: [def] });
  go(A.owner, { op: 'approve', node: 'T-101', spec_digest: SD, policy_line: 'p0.4', def_digest: defDigestOf(def) });
  go(A.head, { op: 'start', node: 'T-101', spec_digest: SD, lease_sec: 60, assignee: A.worker1 });
  rounds.forEach((vs, i) => {
    const req = String(i + 1).repeat(40);
    go(A.head, { op: 'submit', node: 'T-101', request: req });
    const ok = vs.every((v) => v.verdict === 'APPROVED');
    go(A.gate, { op: 'verdict', node: 'T-101', request: req, audits: 'passed', verdicts: vs,
      ...(refs ? { refs: { verdicts: vs.map((v) => ({ kind: v.kind, lineage: v.lineage, id: V.verdictId(req, V.reviewModeOf(v.kind, v.lineage)) })), findings: [`${V.verdictId(req, 'judge')}#f-${i + 1}`], audit: { id: V.auditId(req) } } } : {}),
      ...(ok ? { merge: 'c'.repeat(40) } : {}) });
  });
  return { f, rows: openChain(f).read() };
}

test('judiciaryFromDomainPack：min_judges 2 → claude と codex、1 → codex、3 → 作れない（理由つき）。パックが通らなければ null', () => {
  assert.deepEqual(B.judiciaryFromDomainPack(pack), { judiciary: [{ kind: 'judge', lineage: 'claude' }, { kind: 'judge', lineage: 'codex' }], security_lineage: 'codex', reason: null });
  const one = structuredClone(pack); one.judiciary.min_judges = 1;
  assert.deepEqual(B.judiciaryFromDomainPack(one).judiciary, [{ kind: 'judge', lineage: 'codex' }]);
  const three = structuredClone(pack); three.judiciary.min_judges = 3;
  assert.equal(B.judiciaryFromDomainPack(three).judiciary, null);
  const bad = structuredClone(pack); bad.judiciary.distinct_lineage = false;
  assert.equal(B.judiciaryFromDomainPack(bad).judiciary, null);
  assert.match(B.judiciaryFromDomainPack(bad).reason, /DP-JUDICIARY-ON/);
});

test('protectedFromDomainPack・workItemFromDomainPack：runstate の config にそのまま入る。通らないパックは null', () => {
  assert.deepEqual(B.protectedFromDomainPack(pack).protected, ['.claude/**', 'vgdd/**', 'vgdd/next/domains/**']);
  assert.deepEqual(B.workItemFromDomainPack(pack).work_item, { prefix: 'T-', digits: [3, 4] });
  const bad = structuredClone(pack); bad.protected = ['src/**'];
  assert.equal(B.protectedFromDomainPack(bad).protected, null);
  assert.equal(B.workItemFromDomainPack(null).work_item, null);
});

test('linksFromRun：要件・仕様・承認・申請・判定・監査・統合のつながりを作り、trace がそのまま受ける', () => {
  const { rows } = mkRun([[J('judge', 'claude', 'CHANGES_REQUIRED'), J('judge', 'codex', 'CHANGES_REQUIRED')], [J('judge', 'claude'), J('judge', 'codex')]]);
  const out = B.linksFromRun(rows);
  const rels = out.links.map((l) => `${l.from.kind}-${l.rel}->${l.to.kind}`);
  for (const r of ['ticket-satisfies->requirement', 'spec-specifies->ticket', 'approval-approves->spec', 'request-implements->spec', 'verdict-verifies->request', 'audit-verifies->request', 'merge-integrates->request']) assert.ok(rels.includes(r), r);
  assert.equal(out.links.filter((l) => l.rel === 'implements').length, 2);
  const ap = out.links.find((l) => l.rel === 'approves');
  assert.equal(ap.from.id, V.asDigest(rows.find((r) => r.op === 'approve').hash));
  const t = openTrace(path.join(tmp(), 't.jsonl'));
  assert.deepEqual(t.linkMany(A.importer, out.links).refused, []);
  const row = t.coverage({ expectedRequirements: ['R-1'] }).rows[0];
  assert.deepEqual([row.requests, row.returned_requests, row.approved_requests], [2, 1, 1]);
});

test('linksFromRun：refs がなければ判定・監査の id を vocab で作り（basis: synthesized_id）、merge がなければ統合は作らず skipped に理由。記録が規則に合わなければ何も作らない', () => {
  const { rows } = mkRun([[J('judge', 'claude'), J('judge', 'codex')]], { refs: false });
  const out = B.linksFromRun(rows);
  assert.ok(out.links.some((l) => l.rel === 'verifies' && l.evidence.basis === 'synthesized_id'));
  const noMerge = rows.map((r) => r); // merge は合格の verdict に入っている
  assert.ok(B.linksFromRun(noMerge).links.some((l) => l.rel === 'integrates'));
  const forged = [...rows.slice(0, -1), { ...rows[rows.length - 1], audits: 'failed' }];
  const bad = B.linksFromRun(forged);
  assert.deepEqual(bad.links, []);
  assert.match(bad.skipped[0].reason, /規則に合わない/);
  assert.deepEqual(B.linksFromRun('x').links, []);
});

test('provenanceFromVerdict：refs.findings から経験の出どころ。refs がなければ空と理由', () => {
  const { rows } = mkRun([[J('judge', 'claude', 'CHANGES_REQUIRED'), J('judge', 'codex')]]);
  const vd = rows.find((r) => r.op === 'verdict');
  const p = B.provenanceFromVerdict(vd);
  assert.deepEqual(p.provenance, [{ kind: 'verdict_finding', ref: vd.refs.findings[0], task: 'T-101' }]);
  const ex = openExperience(path.join(tmp(), 'e.jsonl'));
  assert.equal(ex.add(A.gate, { text: '境界値', scope: { domain: 'software-dev', roles: ['worker'], tags: [] }, provenance: p.provenance }).trust, 'grounded');
  const { rows: r2 } = mkRun([[J('judge', 'claude'), J('judge', 'codex')]], { refs: false });
  assert.deepEqual(B.provenanceFromVerdict(r2.find((r) => r.op === 'verdict')), { provenance: [], reason: 'verdict の refs に指摘への参照（findings）がない' });
  assert.equal(B.provenanceFromVerdict(rows[0]).provenance.length, 0);
});

/** 取り出しの行（experience の retrieved）を作る。at は runstate の行の at（which の op の最初の行）から ms ずらす */
const retrievedAt = (rows, task, ids, { actor = A.worker1, which = 'start', shift = 0 } = {}) => {
  const r = rows.find((x) => x.op === which && x.node === task);
  const at = new Date(V.parseTs(r.at) + shift).toISOString();
  return { type: 'vgdd.experience.v1', op: 'retrieved', actor: V.normActor(actor), role: 'worker', task, item_ids: ids, at, seq: 1 };
};

test('審査4（feedbackFromRun の疑い）：取り出しの行も、経験の部品と同じ規則で 1 行ずつ確かめる。合わない行は数えず、理由を返す', () => {
  const run = mkRun([[J('judge', 'claude'), J('judge', 'codex')]]).rows;
  const ok = retrievedAt(run, 'T-101', ['exp-000001']);
  const cases = [
    ['司法の役割に渡した取り出し', { ...ok, role: 'judge' }],
    ['裁判所のスクリプトに渡した取り出し', { ...ok, role: 'gate_runner' }],
    ['表にない役割（全角の名前）に渡した取り出し', { ...ok, role: 'ｗｏｒｋｅｒ２' }],
    ['渡す先の役割がない取り出し', { ...ok, role: undefined }],
    ['行為者の綴りが正規形でない（大文字の id）', { ...ok, actor: { ...ok.actor, id: ok.actor.id.toUpperCase() } }],
    ['行為者の綴りが正規形でない（全角の役割）', { ...ok, actor: { ...ok.actor, role: 'ｗｏｒｋｅｒ' } }],
    ['司法の行為者の取り出し', { ...ok, actor: V.normActor({ role: 'judge', kind: 'ai', id: 'claude-judge-1' }) }],
    ['経験の記録の行でない（種類が違う）', { ...ok, type: 'vgdd.runstate.v1' }],
    ['項目の id が文字列でない', { ...ok, item_ids: [1] }],
  ];
  for (const [label, ev] of cases) {
    const out = B.feedbackFromRun(run, [ev]);
    assert.deepEqual(out.feedback, [], label);
    assert.ok(out.skipped.some((x) => /取り出しの行.*規則に合わない/.test(x.reason)), `${label}：${JSON.stringify(out.skipped)}`);
  }
  // 通す側：規則に合う行は数える（合わない行が混ざっても、合う行の評価は出る）
  const mixed = B.feedbackFromRun(run, [ok, { ...ok, role: 'judge', item_ids: ['exp-000009'] }]);
  assert.deepEqual(mixed.feedback.map((f) => f.item_ids), [['exp-000001']]);
});

test('feedbackFromRun：最初の判定が pass → helpful、return → harmful。判定がない・決められない票は出さない', () => {
  const passRun = mkRun([[J('judge', 'claude'), J('judge', 'codex')]]).rows;
  const fb = B.feedbackFromRun(passRun, [retrievedAt(passRun, 'T-101', ['exp-000002']), retrievedAt(passRun, 'T-101', ['exp-000001'], { which: 'submit' }), { ...retrievedAt(passRun, 'T-101', ['exp-000001']), task: 'T-999' }]);
  assert.deepEqual(fb.feedback, [{ item_ids: ['exp-000001', 'exp-000002'], outcome: 'helpful', evidence: { kind: 'verdict', ref: V.verdictId('1'.repeat(40), 'judge'), task: 'T-101' } }]);
  assert.deepEqual(fb.skipped.map((s) => s.task), ['T-999']);
  const retRun = mkRun([[J('judge', 'claude', 'CHANGES_REQUIRED'), J('judge', 'codex', 'CHANGES_REQUIRED')], [J('judge', 'claude'), J('judge', 'codex')]]).rows;
  assert.equal(B.feedbackFromRun(retRun, [retrievedAt(retRun, 'T-101', ['exp-000001'])]).feedback[0].outcome, 'harmful', '最初の判定（差し戻し）で決める');
  const noVerdict = mkRun([]).rows;
  const none = B.feedbackFromRun(noVerdict, [retrievedAt(noVerdict, 'T-101', ['exp-000001'])]);
  assert.deepEqual(none.feedback, []);
  assert.match(none.skipped[0].reason, /判定がない/);
  // 出した案は experience の feedback の入力として通る（裁判所のスクリプトが書く）
  const ex = openExperience(path.join(tmp(), 'e.jsonl'));
  ex.add(A.gate, { text: 'abc', scope: { domain: 'software-dev', roles: ['worker'], tags: [] }, provenance: [{ kind: 'obs', ref: 'x', task: 'T-101' }] });
  const one = B.feedbackFromRun(passRun, [retrievedAt(passRun, 'T-101', ['exp-000001'])]).feedback[0];
  assert.equal(ex.feedback(A.gate, one)[0].helpful, 1);
});

test('E-1 判例：申告の票だけでは評価しない。着手から申請までの間の、着手の行為者か assignee の取り出しだけを数える', () => {
  const retRun = mkRun([[J('judge', 'claude', 'CHANGES_REQUIRED'), J('judge', 'codex', 'CHANGES_REQUIRED')], [J('judge', 'claude'), J('judge', 'codex')]]).rows;
  const cases = [
    ['判定の後（申請の後）の取り出し', retrievedAt(retRun, 'T-101', ['exp-000001'], { which: 'verdict', shift: 1 }), /着手から申請までの間にない/],
    ['着手の前の取り出し', retrievedAt(retRun, 'T-101', ['exp-000001'], { shift: -1 }), /着手から申請までの間にない/],
    ['別の作業員の取り出し', retrievedAt(retRun, 'T-101', ['exp-000001'], { actor: A.worker2 }), /行為者/],
    ['行為者のない取り出し', { ...retrievedAt(retRun, 'T-101', ['exp-000001']), actor: undefined }, /行為者/],
    ['時刻の読めない取り出し', { ...retrievedAt(retRun, 'T-101', ['exp-000001']), at: '2026-11-14 09:00' }, /時刻が読めない/],
  ];
  for (const [label, ev, re] of cases) {
    const out = B.feedbackFromRun(retRun, [ev]);
    assert.deepEqual(out.feedback, [], label);
    assert.ok(out.skipped.some((x) => re.test(x.reason)), label);
  }
  // 陽性の対照：着手した行政の長・assignee の作業員、申請と同じ時刻
  for (const ev of [retrievedAt(retRun, 'T-101', ['exp-000001'], { actor: A.head }), retrievedAt(retRun, 'T-101', ['exp-000001'], { which: 'submit' })]) assert.equal(B.feedbackFromRun(retRun, [ev]).feedback.length, 1);
});

test('E-9：申請の履歴が上限で落ちた節（requests_dropped > 0）は、最初の判定が決まらないので評価を出さない', async () => {
  const R = await import('../runstate.mjs');
  const { rows } = mkRun([[J('judge', 'claude'), J('judge', 'codex')]]);
  const real = R.replay;
  const st = real(rows);
  st.nodes.get('T-101').requests_dropped = 1;
  // replay の結果の節に落とした数があるときの扱いを、bridge の規則の関数で確かめる（記録は 100 件を超える履歴を作るのが重いので、状態を直接作る）
  assert.equal(B.feedbackFromState(real(rows), rows, [retrievedAt(rows, 'T-101', ['exp-000001'])]).feedback.length, 1, '対照：落ちていなければ出す');
  const out = B.feedbackFromState(st, rows, [retrievedAt(rows, 'T-101', ['exp-000001'])]);
  assert.deepEqual(out.feedback, []);
  assert.match(out.skipped[0].reason, /落ちていて/);
});

test('B02・B04・B05・E-10：形の合わない指摘への参照は出どころにしない。統合の参照がない合格は統合のつながりを作らない。rule の return は裁定のつながりを作らない', () => {
  const { rows } = mkRun([[J('judge', 'claude'), J('judge', 'codex')]], { refs: true });
  const vd = rows.find((r) => r.op === 'verdict');
  assert.deepEqual(B.provenanceFromVerdict({ ...vd, refs: { ...vd.refs, findings: ['bogus#1', 'VRD-x#y'] } }).provenance, []);
  assert.equal(B.provenanceFromVerdict(vd, { records: rows }).provenance.length, 1);
  assert.match(B.provenanceFromVerdict({ ...vd, hash: 'f'.repeat(64) }, { records: rows }).reason, /記録の中にない/);
  // merge のない合格（runstate は merge を任意で受ける）
  const d = tmp(); const run = openRun(path.join(d, 'r.jsonl'));
  let n = 0; const go = (a, e) => run.apply(a, { event_id: `e${++n}`, ...e });
  go(A.owner, { op: 'config', ...JSON.parse(JSON.stringify(DEFAULT_CONFIG)), concurrent_work: 2, policy_line: 'p0.4' });
  const def = { id: 'T-101', depends_on: [], resources: ['src/a/**'] };
  go(A.head, { op: 'plan', nodes: [def] });
  go(A.owner, { op: 'approve', node: 'T-101', spec_digest: SD, policy_line: 'p0.4', def_digest: defDigestOf(def) });
  go(A.head, { op: 'start', node: 'T-101', spec_digest: SD, lease_sec: 60 });
  go(A.head, { op: 'submit', node: 'T-101', request: '1'.repeat(40) });
  go(A.gate, { op: 'verdict', node: 'T-101', request: '1'.repeat(40), audits: 'passed', verdicts: [J('judge', 'claude'), J('judge', 'codex', 'CHANGES_REQUIRED')].map((v, i) => ({ ...v, major: i === 1 })) });
  go(A.owner, { op: 'rule', node: 'T-101', request: '1'.repeat(40), decision: 'return', reason: 'やり直す' });
  go(A.head, { op: 'submit', node: 'T-101', request: '2'.repeat(40) });
  go(A.gate, { op: 'verdict', node: 'T-101', request: '2'.repeat(40), audits: 'passed', verdicts: [J('judge', 'claude'), J('judge', 'codex')] });
  const l2 = B.linksFromRun(openChain(path.join(d, 'r.jsonl')).read());
  assert.equal(l2.links.filter((l) => l.rel === 'integrates').length, 0, '統合の参照がなければ統合のつながりを作らない');
  assert.equal(l2.links.filter((l) => l.from.kind === 'ruling').length, 0, 'rule の return は裁定の承認のつながりを作らない');
  // hold の世界：オーナーの release に merge がなければ、統合のつながりを作らず skipped に理由
  const d3 = tmp(); const r3 = openRun(path.join(d3, 'r.jsonl'));
  let k = 0; const g3 = (a, e) => r3.apply(a, { event_id: `h${++k}`, ...e });
  g3(A.owner, { op: 'config', ...JSON.parse(JSON.stringify(DEFAULT_CONFIG)), hold: true, concurrent_work: 2, policy_line: 'p0.4' });
  g3(A.head, { op: 'plan', nodes: [def] });
  g3(A.owner, { op: 'approve', node: 'T-101', spec_digest: SD, policy_line: 'p0.4', def_digest: defDigestOf(def) });
  g3(A.head, { op: 'start', node: 'T-101', spec_digest: SD, lease_sec: 60 });
  g3(A.head, { op: 'submit', node: 'T-101', request: '3'.repeat(40) });
  g3(A.gate, { op: 'verdict', node: 'T-101', request: '3'.repeat(40), audits: 'passed', verdicts: [J('judge', 'claude'), J('judge', 'codex')] });
  g3(A.owner, { op: 'release', node: 'T-101', request: '3'.repeat(40) });
  const l3 = B.linksFromRun(openChain(path.join(d3, 'r.jsonl')).read());
  assert.equal(l3.links.filter((l) => l.rel === 'integrates').length, 0);
  assert.ok(l3.skipped.some((x) => /merge/.test(x.reason)));
});
