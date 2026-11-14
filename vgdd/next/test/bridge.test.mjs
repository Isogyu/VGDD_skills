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
  go(A.head, { op: 'start', node: 'T-101', spec_digest: SD, lease_sec: 60 });
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

test('feedbackFromRun：最初の判定が pass → helpful、return → harmful。判定がない・決められない票は出さない', () => {
  const retrieved = (task, ids) => ({ type: 'vgdd.experience.v1', op: 'retrieved', task, item_ids: ids });
  const passRun = mkRun([[J('judge', 'claude'), J('judge', 'codex')]]).rows;
  const fb = B.feedbackFromRun(passRun, [retrieved('T-101', ['exp-000002']), retrieved('T-101', ['exp-000001']), retrieved('T-999', ['exp-000001'])]);
  assert.deepEqual(fb.feedback, [{ item_ids: ['exp-000001', 'exp-000002'], outcome: 'helpful', evidence: { kind: 'verdict', ref: V.verdictId('1'.repeat(40), 'judge'), task: 'T-101' } }]);
  assert.deepEqual(fb.skipped.map((s) => s.task), ['T-999']);
  const retRun = mkRun([[J('judge', 'claude', 'CHANGES_REQUIRED'), J('judge', 'codex', 'CHANGES_REQUIRED')], [J('judge', 'claude'), J('judge', 'codex')]]).rows;
  assert.equal(B.feedbackFromRun(retRun, [retrieved('T-101', ['exp-000001'])]).feedback[0].outcome, 'harmful', '最初の判定（差し戻し）で決める');
  const none = B.feedbackFromRun(mkRun([]).rows, [retrieved('T-101', ['exp-000001'])]);
  assert.deepEqual(none.feedback, []);
  assert.match(none.skipped[0].reason, /判定がない/);
  // 出した案は experience の feedback の入力として通る（裁判所のスクリプトが書く）
  const ex = openExperience(path.join(tmp(), 'e.jsonl'));
  ex.add(A.gate, { text: 'abc', scope: { domain: 'software-dev', roles: ['worker'], tags: [] }, provenance: [{ kind: 'obs', ref: 'x', task: 'T-101' }] });
  const one = B.feedbackFromRun(passRun, [retrieved('T-101', ['exp-000001'])]).feedback[0];
  assert.equal(ex.feedback(A.gate, one)[0].helpful, 1);
});
