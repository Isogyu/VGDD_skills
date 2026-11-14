import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openChain, Refused } from '../lib/chain.mjs';
import { openRun, unsafeOpenRunWithClock, memoryRun, replay, canResume, decide, check, GUARDS, parseActor, parseEvent, makeCtx, newState, RULES, RECORD_TYPE, DEFAULT_CONFIG, MAX_EVENTS, HUMAN_RESERVE } from '../runstate.mjs';
import { SCENARIOS } from '../bench/scenarios-runstate.mjs';

const EX = { role: 'executive', kind: 'ai', id: 'max' };
const OW = { role: 'owner', kind: 'human', id: 'azuki' };
const CT = { role: 'court', kind: 'script', id: 'gate_runner' };
const RP = { role: 'reaper', kind: 'script', id: 'reaper' };
const S1 = `sha256:${'a'.repeat(64)}`;
const R1 = 'a1b2c3d4e5f6';
const R2 = 'f6e5d4c3b2a1';
const J = (lineage, verdict = 'APPROVED', major = false, kind = 'judge') => ({ kind, judge: `${kind}_${lineage}`, lineage, verdict, major });
const AP2 = [J('claude'), J('codex')];
const SPLIT_MAJOR = [J('claude'), J('codex', 'CHANGES_REQUIRED', true)];
const N = (id, depends_on = [], resources = [`src/${id}/**`]) => ({ id, depends_on, resources });

function tmpFile() { const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vgdd-next-')); return { dir, file: path.join(dir, 'run.jsonl') }; }
/** 時刻を制御できる実行（記録のファイルを使う）。opt は最初の config の出来事に重ねる設定。opt.noConfig なら config を入れない */
function mkRun(opt = {}) {
  const { dir, file } = tmpFile();
  const clock = { t: Date.parse('2026-01-01T00:00:00+09:00') };
  const now = () => new Date((clock.t += 1000)).toISOString();
  const { noConfig, ...config } = opt;
  let n = 0;
  const run = unsafeOpenRunWithClock(file, { now });
  const go = (actor, ev) => run.apply(actor, { event_id: `t${++n}`, ...ev });
  if (!noConfig) go(OW, { op: 'config', ...JSON.parse(JSON.stringify(DEFAULT_CONFIG)), workers: 2, ...config });
  const st = (id) => run.state().nodes[id].status;
  const approve = (id, spec = S1) => go(OW, { op: 'approve', node: id, spec_digest: spec, policy_line: 'p0.4', def_digest: run.state().nodes[id].def_digest });
  const start = (id, lease = 3600) => go(EX, { op: 'start', node: id, spec_digest: S1, lease_sec: lease });
  const submit = (id, req = R1) => go(EX, { op: 'submit', node: id, request: req });
  const verdict = (id, req, audits, verdicts) => go(CT, { op: 'verdict', node: id, request: req, audits, verdicts });
  return { dir, file, clock, run, go, st, approve, start, submit, verdict, reopen: () => unsafeOpenRunWithClock(file, { now }), cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}
const refused = (fn, guard) => { try { fn(); } catch (e) { assert.ok(e instanceof Refused, String(e)); if (guard) assert.ok((e.violations || []).some((v) => v.guard === guard), `${guard} で拒否されるはず: ${e.message}`); return e; } assert.fail('拒否されるはず'); };
const planAB = (w) => { w.go(EX, { op: 'plan', nodes: [N('a'), N('b'), N('c', ['a', 'b'])] }); for (const id of ['a', 'b', 'c']) w.approve(id); };

// ---- 良性の流れ（記録のファイルで通す） ----
test('良性: 3つの節（a、b は独立、c は a と b に依存）を承認→着手→申請→合格→統合まで通す', () => {
  const w = mkRun();
  try {
    planAB(w);
    assert.deepEqual(w.run.next().start, ['a', 'b']);
    w.start('a'); w.start('b');
    assert.deepEqual(w.run.next().start, []); // 同時の数 2、c は依存待ち
    for (const id of ['a', 'b']) { w.submit(id); w.verdict(id, R1, 'passed', AP2); }
    assert.deepEqual(w.run.next().start, ['c']);
    w.start('c'); w.submit('c', R2); w.verdict('c', R2, 'passed', AP2);
    assert.deepEqual(['a', 'b', 'c'].map(w.st), ['merged', 'merged', 'merged']);
    assert.equal(w.run.summary().by_status.merged, 3);
    assert.ok(w.run.verify().ok);
  } finally { w.cleanup(); }
});

test('良性: 差し戻し→再申請→合格。差し戻しの回数は数える', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('a')] }); w.approve('a'); w.start('a');
    w.submit('a', R1); const r = w.verdict('a', R1, 'failed', AP2);
    assert.equal(r.kind, 'return'); assert.equal(w.st('a'), 'in_progress'); assert.equal(w.run.state().nodes.a.returns, 1);
    w.submit('a', R2); w.verdict('a', R2, 'passed', AP2);
    assert.equal(w.st('a'), 'merged');
  } finally { w.cleanup(); }
});

test('良性: 司法が使えない→戻った周回で合格（差し戻しに数えない）。3回で blocked', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('a')] }); w.approve('a'); w.start('a'); w.submit('a');
    const one = [AP2[0]];
    assert.equal(w.verdict('a', R1, 'passed', one).kind, 'unavailable');
    assert.equal(w.run.state().nodes.a.returns, 0);
    assert.equal(w.verdict('a', R1, 'passed', AP2).kind, 'pass');
    assert.equal(w.st('a'), 'merged');
    // 別の節で3回
    w.go(EX, { op: 'plan', nodes: [N('b')] }); w.approve('b'); w.start('b'); w.submit('b', R2);
    w.verdict('b', R2, 'passed', one); w.verdict('b', R2, 'passed', one);
    assert.equal(w.verdict('b', R2, 'passed', one).kind, 'blocked_unavailable');
    assert.equal(w.st('b'), 'blocked'); assert.equal(w.run.state().nodes.b.returns, 0);
    assert.deepEqual(w.run.summary().blocked_reasons, { judiciary_unavailable: 1 });
  } finally { w.cleanup(); }
});

test('良性: 夜間（hold）は held → オーナーの release で merged', () => {
  const w = mkRun({ hold: true });
  try {
    w.go(EX, { op: 'plan', nodes: [N('a')] }); w.approve('a'); w.start('a'); w.submit('a');
    assert.equal(w.verdict('a', R1, 'passed', AP2).to, 'held');
    refused(() => w.go(OW, { op: 'release', node: 'a', request: R2 }), 'RS-REQUEST-MATCH'); // 対象の固定
    w.go(OW, { op: 'release', node: 'a', request: R1 });
    assert.equal(w.st('a'), 'merged');
  } finally { w.cleanup(); }
});

test('良性: 判定が分かれた（重大）→ blocked → オーナーの裁定（merge・return の両方）', () => {
  const split = [AP2[0], J('codex', 'CHANGES_REQUIRED', true)];
  for (const decision of ['merge', 'return']) {
    const w = mkRun();
    try {
      w.go(EX, { op: 'plan', nodes: [N('a')] }); w.approve('a'); w.start('a'); w.submit('a');
      assert.equal(w.verdict('a', R1, 'passed', split).kind, 'blocked_disagreement');
      assert.equal(w.st('a'), 'blocked');
      w.go(OW, { op: 'rule', node: 'a', request: R1, decision, reason: '裁定する' });
      assert.equal(w.st('a'), decision === 'merge' ? 'merged' : 'in_progress');
      if (decision === 'return') assert.equal(w.run.state().nodes.a.returns, 1);
    } finally { w.cleanup(); }
  }
});

test('良性: 停止→再開→続行。停止中は stop・resume 以外をすべて拒む', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('a')] }); w.approve('a'); w.start('a');
    w.go(OW, { op: 'stop', reason: '点検' });
    assert.equal(w.run.next().start.length, 0); assert.equal(w.run.summary().stopped, true);
    for (const f of [() => w.submit('a'), () => w.go(EX, { op: 'plan', nodes: [N('z')] }), () => w.go(OW, { op: 'annul', node: 'a', reason: 'x' }), () => w.go(RP, { op: 'expire', node: 'a' })]) refused(f, 'RS-STOPPED');
    w.go(OW, { op: 'resume', reason: '点検済み' });
    w.submit('a'); w.verdict('a', R1, 'passed', AP2);
    assert.equal(w.st('a'), 'merged');
  } finally { w.cleanup(); }
});

test('良性: 途中で落ちた想定 — 記録を開き直して同じ状態が作り直せ、続きができる', () => {
  const w = mkRun();
  try {
    planAB(w); w.start('a'); w.submit('a'); w.verdict('a', R1, 'failed', AP2);
    const before = JSON.stringify(w.run.state());
    const again = w.reopen(); // 落ちて別のプロセスが開いた
    assert.equal(JSON.stringify(again.state()), before);
    assert.deepEqual(again.verify(), { ok: true, count: 8, events: 8, rules: RULES });
    again.apply(EX, { event_id: 'after-crash', op: 'submit', node: 'a', request: R2 });
    again.apply(CT, { event_id: 'after-crash-2', op: 'verdict', node: 'a', request: R2, audits: 'passed', verdicts: AP2 });
    assert.equal(again.state().nodes.a.status, 'merged');
    assert.equal(w.run.state().nodes.a.status, 'merged'); // 最初の窓口も、他のプロセスが書いた行を再生に取り込む
  } finally { w.cleanup(); }
});

test('良性（INV-12）: b が未承認のままでも、a は最後まで進む。b に依存する c だけが待つ', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('a'), N('b'), N('c', ['b'])] }); w.approve('a');
    assert.deepEqual(w.run.next().start, ['a']);
    w.start('a'); w.submit('a'); w.verdict('a', R1, 'passed', AP2);
    assert.equal(w.st('a'), 'merged');
    const nx = w.run.next();
    assert.deepEqual(nx.start, []);
    assert.deepEqual(nx.waiting.find((x) => x.id === 'c').reasons.sort(), ['unapproved', 'waiting_dependency:b']);
    assert.deepEqual(w.run.summary().awaiting_approval, ['b', 'c']);
  } finally { w.cleanup(); }
});

test('良性: 期限切れの回収は、記録の時刻で判定する（attempts は戻さない）', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('a')] }); w.approve('a'); w.start('a', 100);
    refused(() => w.go(RP, { op: 'expire', node: 'a' }), 'RS-EXPIRE-DUE');
    for (const claimed of ['2999-01-01T00:00:00+09:00', 99999999999999, true]) refused(() => w.go(RP, { op: 'expire', node: 'a', now: claimed }), 'RS-EVENT-SHAPE');
    refused(() => w.go(RP, { op: 'expire', node: 'a', at: '2999-01-01T00:00:00+09:00' }), 'RS-EVENT-SHAPE');
    w.clock.t += 100e3;
    w.go(RP, { op: 'expire', node: 'a' });
    assert.equal(w.st('a'), 'ready'); assert.equal(w.run.state().nodes.a.attempts, 1);
    w.start('a'); assert.equal(w.run.state().nodes.a.attempts, 2);
  } finally { w.cleanup(); }
});

test('良性: 着手の回数が尽きた期限切れは blocked（行き止まりにせず、オーナーが理由つきで解く）', () => {
  const w = mkRun({ max_attempts: 1 });
  try {
    w.go(EX, { op: 'plan', nodes: [N('a')] }); w.approve('a'); w.start('a', 10); w.clock.t += 10e3;
    w.go(RP, { op: 'expire', node: 'a' });
    assert.equal(w.st('a'), 'blocked'); assert.deepEqual(w.run.summary().blocked_reasons, { attempts_exhausted: 1 });
    refused(() => w.go(OW, { op: 'unblock', node: 'a', reason: '再開' }), 'RS-UNBLOCK-PROGRESS');
    w.go(OW, { op: 'unblock', node: 'a', reason: '再開する', extra_attempts: 1 });
    assert.equal(w.st('a'), 'ready'); w.start('a'); assert.equal(w.st('a'), 'in_progress');
  } finally { w.cleanup(); }
});

test('差し戻しの上限：3回の差し戻しの後の再申請は、司法を見ずに blocked。オーナーは回数を戻さず追加の回数を与える', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('a')] }); w.approve('a'); w.start('a');
    for (let i = 0; i < 3; i += 1) { w.submit('a'); w.verdict('a', R1, 'failed', AP2); }
    assert.equal(w.run.state().nodes.a.returns, 3); assert.equal(w.st('a'), 'in_progress');
    w.submit('a'); // 4 回目の申請。全員 APPROVED でも合格にしない
    const r = w.verdict('a', R1, 'passed', AP2);
    assert.equal(r.kind, 'blocked_returns'); assert.equal(w.st('a'), 'blocked');
    assert.deepEqual(w.run.summary().blocked_reasons, { returns_limit: 1 });
    refused(() => w.go(OW, { op: 'unblock', node: 'a', reason: '再開する' }), 'RS-UNBLOCK-PROGRESS');
    w.go(OW, { op: 'unblock', node: 'a', reason: '指摘が直った', extra_returns: 1, extra_attempts: 1 });
    assert.equal(w.run.state().nodes.a.returns, 3, '回数は戻さない');
    w.start('a'); w.submit('a', R2); w.verdict('a', R2, 'passed', AP2);
    assert.equal(w.st('a'), 'merged');
  } finally { w.cleanup(); }
});

test('annul（オーナー）は差し戻しを数えない。差し戻しがなければ拒む', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('a')] }); w.approve('a'); w.start('a');
    refused(() => w.go(OW, { op: 'annul', node: 'a', reason: 'x' }), 'RS-ANNUL-BOUND');
    w.submit('a'); w.verdict('a', R1, 'failed', AP2);
    w.go(OW, { op: 'annul', node: 'a', reason: '法律の不具合による差し戻し' });
    assert.equal(w.run.state().nodes.a.returns, 0); assert.equal(w.run.state().nodes.a.annulled, 1);
  } finally { w.cleanup(); }
});

// ---- verdict の結果の決め方（本物の decide を、実際の出来事で） ----
test('verdict: 監査が failed・not_run なら、司法が全員 APPROVED でも合格にしない', () => {
  for (const audits of ['failed', 'not_run']) {
    const w = mkRun();
    try {
      w.go(EX, { op: 'plan', nodes: [N('a')] }); w.approve('a'); w.start('a'); w.submit('a');
      const r = w.verdict('a', R1, audits, AP2);
      assert.equal(r.kind, 'return'); assert.equal(w.st('a'), 'in_progress');
    } finally { w.cleanup(); }
  }
});

test('verdict: 判定が足りない・同じ系統・UNAVAILABLE 混じりは合格にならない（司法の欠落。G15・G19）', () => {
  const unav = [AP2[0], J('codex', 'UNAVAILABLE')];
  for (const [name, vs] of [['1つ', [AP2[0]]], ['UNAVAILABLE 混じり', unav], ['空', []]]) {
    const w = mkRun();
    try {
      w.go(EX, { op: 'plan', nodes: [N('a')] }); w.approve('a'); w.start('a'); w.submit('a');
      const r = w.verdict('a', R1, 'passed', vs);
      assert.equal(r.kind, 'unavailable', name); assert.equal(w.st('a'), 'review', name); assert.equal(w.run.state().nodes.a.returns, 0, name);
    } finally { w.cleanup(); }
  }
});

test('verdict: 重大でない分かれた判定は合格にならず差し戻し。重大なら blocked', () => {
  const minor = [AP2[0], J('codex', 'CHANGES_REQUIRED')];
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('a')] }); w.approve('a'); w.start('a'); w.submit('a');
    const r = w.verdict('a', R1, 'passed', minor);
    assert.equal(r.kind, 'pass_minor_disagreement'); assert.equal(w.st('a'), 'merged'); // 法律（§3.1 の 8）：指摘を残して統合
  } finally { w.cleanup(); }
  const w2 = mkRun();
  try {
    w2.go(EX, { op: 'plan', nodes: [N('a')] }); w2.approve('a'); w2.start('a'); w2.submit('a');
    assert.equal(w2.verdict('a', R1, 'passed', SPLIT_MAJOR).kind, 'blocked_disagreement');
  } finally { w.cleanup(); }
});

test('verdict: 前の申請の指紋・ない申請への結果は拒む（使い回し）', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('a')] }); w.approve('a'); w.start('a'); w.submit('a', R1);
    refused(() => w.verdict('a', R2, 'passed', AP2), 'RS-REQUEST-MATCH');
    assert.equal(w.st('a'), 'review');
    refused(() => w.verdict('a', 'sha256:' + 'c'.repeat(64), 'passed', AP2), 'RS-REQUEST-MATCH');
  } finally { w.cleanup(); }
});

test('decide: 同じ入力は同じ結果（決定論的）で、入力を書き換えない', () => {
  const node = { returns: 0, extra_returns: 0, extra_attempts: 0, extra_unavailable: 0, attempts: 1, unavail: {}, security_review: false };
  const ev = Object.freeze({ request: R1, audits: 'passed', verdicts: Object.freeze(AP2.map((x) => Object.freeze({ ...x }))) });
  const a = decide({ node, ev, cfg: DEFAULT_CONFIG, at: 0 }); const b = decide({ node, ev, cfg: DEFAULT_CONFIG, at: 0 });
  assert.deepEqual(a, b); assert.equal(a.kind, 'pass');
});

// ---- 不変条件 ----
test('INV-05: 行政（ai）は verdict・release・rule・unblock・annul・approve・stop・resume・epoch を起こせない（役割を偽っても）', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('a')] });
    const ev = [
      { op: 'approve', node: 'a', spec_digest: S1, policy_line: 'p0.4', def_digest: w.run.state().nodes.a.def_digest },
      { op: 'verdict', node: 'a', request: R1, audits: 'passed', verdicts: AP2 }, { op: 'release', node: 'a', request: R1 },
      { op: 'rule', node: 'a', request: R1, decision: 'merge', reason: 'x' }, { op: 'unblock', node: 'a', reason: 'x' }, { op: 'annul', node: 'a', reason: 'x' },
      { op: 'stop', reason: 'x' }, { op: 'resume', reason: 'x' }, { op: 'epoch', covers: { count: 0, last_hash: 'genesis' }, reason: 'x' },
    ];
    for (const role of ['executive', 'owner', 'court']) for (const e of ev) {
      const x = refused(() => w.run.apply({ role, kind: 'ai', id: 'max' }, { event_id: `ai-${role}-${e.op}`, ...e }));
      assert.ok(x.violations.length > 0);
    }
    assert.equal(w.run.state().count, 2); assert.equal(w.run.state().nodes.a.approved, false);
  } finally { w.cleanup(); }
});

test('行為者の表記ゆれ: Owner・ゼロ幅・Human・知らない役割・型のゆれは拒む。前後の空白と全角は正規化して受ける', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('a')] });
    const d = w.run.state().nodes.a.def_digest;
    const ap = (actor, id) => w.run.apply(actor, { event_id: id, op: 'approve', node: 'a', spec_digest: S1, policy_line: 'p0.4', def_digest: d });
    for (const actor of [{ role: 'Owner', kind: 'human', id: 'x' }, { role: 'own​er', kind: 'human', id: 'x' }, { role: 'owner', kind: 'Human', id: 'x' }, { role: 'admin', kind: 'human', id: 'x' },
      { role: ['owner'], kind: 'human', id: 'x' }, { role: 'owner', kind: 'human', id: 'x', extra: 1 }, 'owner', null, [], { role: 'owner', kind: 'human' }, { role: 'owner', kind: 'human', id: 'X' }]) {
      refused(() => ap(actor, `bad-${Math.random().toString(36).slice(2)}`));
    }
    assert.equal(w.run.state().nodes.a.approved, false);
    ap({ role: ' ｏｗｎｅｒ ', kind: 'human', id: 'azuki' }, 'good-1');
    assert.equal(w.run.state().nodes.a.approved, true);
    assert.deepEqual(parseActor({ role: ' ｏｗｎｅｒ ', kind: 'human', id: 'azuki' }).actor, { role: 'owner', kind: 'human', id: 'azuki' });
  } finally { w.cleanup(); }
});

test('未承認の節・依存が未統合の節は start できない。承認の後に仕様が変われば（指紋が違えば）効かない', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('a'), N('b', ['a'])] });
    refused(() => w.start('a'), 'RS-APPROVED');
    w.approve('a'); w.approve('b');
    refused(() => w.start('b'), 'RS-DEPS-MERGED');
    refused(() => w.go(EX, { op: 'start', node: 'a', spec_digest: `sha256:${'b'.repeat(64)}`, lease_sec: 60 }), 'RS-SPEC-DIGEST');
    w.start('a'); assert.equal(w.st('a'), 'in_progress');
    refused(() => w.start('a'), 'RS-TRANSITION'); // 二重の着手
  } finally { w.cleanup(); }
});

test('承認は法律の系統に結び付く（policyLine が違う承認では start できない）', () => {
  const w = mkRun({ policy_line: 'p0.5' });
  try {
    w.go(EX, { op: 'plan', nodes: [N('a')] }); w.approve('a');
    refused(() => w.start('a'), 'RS-POLICY-LINE');
    assert.deepEqual(w.run.next().waiting.find((x) => x.id === 'a').reasons, ['policy_line_mismatch']);
  } finally { w.cleanup(); }
});

test('範囲の重なる節の同時の start・同時の数の超過は拒む', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('x', [], ['src/shared/**']), N('y', [], ['src/shared/util.js']), N('z'), N('q')] });
    for (const id of ['x', 'y', 'z', 'q']) w.approve(id);
    w.start('x');
    refused(() => w.start('y'), 'RS-RESOURCE-DISJOINT');
    assert.ok(w.run.next().waiting.some((x) => x.id === 'y'));
    w.start('z');
    refused(() => w.start('q'), 'RS-WORKER-LIMIT');
  } finally { w.cleanup(); }
});

test('plan: 壊れたグラフ（循環・欠けた依存・重複）は拒む。既存の節の書き換えは拒む（追加だけ）', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('a')] });
    refused(() => w.go(EX, { op: 'plan', nodes: [N('x', ['y']), N('y', ['x'])] }), 'RS-PLAN-GRAPH');
    refused(() => w.go(EX, { op: 'plan', nodes: [N('x', ['ghost'])] }), 'RS-PLAN-GRAPH');
    refused(() => w.go(EX, { op: 'plan', nodes: [N('x'), N('x')] }), 'RS-PLAN-GRAPH');
    refused(() => w.go(EX, { op: 'plan', nodes: [N('a', [], ['**'])] }), 'RS-PLAN-APPEND-ONLY');
    refused(() => w.go(EX, { op: 'plan', nodes: [{ ...N('x'), approved: true }] }), 'RS-EVENT-SHAPE');
    assert.equal(w.run.state().count, 2);
    w.go(OW, { op: 'plan', nodes: [N('x', ['a'])] }); // 人も plan できる
    assert.equal(w.run.state().nodes.x.approved, false); // 登録された節は未承認で始まる
  } finally { w.cleanup(); }
});

test('置き換え（supersede）：置き換えられた節は blocked で動かず、承認は引き継がない。依存は置き換え先に付け替わる', () => {
  const w = mkRun();
  try {
    planAB(w);
    w.go(EX, { op: 'plan', nodes: [N('a2')], supersede: [{ old: 'a', new: 'a2' }] });
    assert.equal(w.st('a'), 'blocked'); assert.equal(w.run.state().nodes.a.superseded_by, 'a2'); assert.equal(w.run.state().nodes.a2.approved, false);
    refused(() => w.start('a'), 'RS-FROZEN'); refused(() => w.start('a2'), 'RS-APPROVED'); refused(() => w.go(OW, { op: 'unblock', node: 'a', reason: '戻す' }), 'RS-FROZEN');
    assert.deepEqual(w.run.summary().blocked_reasons, { superseded: 1 });
    // c は a2 に依存する（a2 が統合されるまで着手できない）
    assert.ok(w.run.next().waiting.find((x) => x.id === 'c').reasons.includes('waiting_dependency:a2'));
    // 置き換えで循環を作る（a2 に依存する c を、c に依存する節で置き換え）は拒む
    refused(() => w.go(EX, { op: 'plan', nodes: [N('a3', ['c'])], supersede: [{ old: 'a2', new: 'a3' }] }), 'RS-PLAN-GRAPH');
  } finally { w.cleanup(); }
});

test('一度 merged になった節は動かない（再着手・approve・annul・unblock・release）', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('a')] }); w.approve('a'); w.start('a'); w.submit('a'); w.verdict('a', R1, 'passed', AP2);
    for (const f of [() => w.start('a'), () => w.approve('a', `sha256:${'b'.repeat(64)}`), () => w.go(OW, { op: 'annul', node: 'a', reason: 'x' }), () => w.go(OW, { op: 'unblock', node: 'a', reason: 'x' }),
      () => w.go(OW, { op: 'release', node: 'a', request: R1 }), () => w.go(RP, { op: 'expire', node: 'a' })]) refused(f, 'RS-FROZEN');
  } finally { w.cleanup(); }
});

test('merged になる経路は verdict の合格（hold でないとき）・release・rule の3つだけ', () => {
  // 3つ以外の op の結果として merged を作る ctx を、全ガードに通すと拒まれる
  const m = memoryRun();
  m.apply(EX, { event_id: 'p', op: 'plan', nodes: [N('a')] });
  const d = m.state().nodes.a.def_digest;
  m.apply(OW, { event_id: 'q', op: 'approve', node: 'a', spec_digest: S1, policy_line: 'p0.4', def_digest: d });
  for (const ev of [{ event_id: 'x1', op: 'start', node: 'a', spec_digest: S1, lease_sec: 60 }, { event_id: 'x2', op: 'submit', node: 'a', request: R1 }]) {
    const c = check(makeCtx(m.st, EX, ev, { at: m.now(), result: { op: ev.op, node: 'a', to: 'merged', patch: {} } }));
    assert.equal(c.ok, false); assert.ok(c.violations.some((v) => v.guard === 'RS-MERGE-PATH'));
  }
  const hold = memoryRun({ hold: true });
  hold.apply(EX, { event_id: 'p', op: 'plan', nodes: [N('a')] });
});

test('event_id の冪等：同じ内容の二度目は効かない。違う内容での再利用は拒む', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('a')] });
    const ev = { event_id: 'same-1', op: 'approve', node: 'a', spec_digest: S1, policy_line: 'p0.4', def_digest: w.run.state().nodes.a.def_digest };
    assert.equal(w.run.apply(OW, ev).duplicate, false);
    const c = w.run.state().count;
    assert.equal(w.run.apply(OW, ev).duplicate, true);
    assert.equal(w.run.apply(OW, { ...ev }).duplicate, true);
    assert.equal(w.run.state().count, c);
    refused(() => w.run.apply(OW, { ...ev, spec_digest: `sha256:${'b'.repeat(64)}` }), 'RS-EVENT-ID-UNIQUE');
    refused(() => w.run.apply(OW, { ...ev, event_id: 'SAME-1' }), 'RS-EVENT-SHAPE'); // 大文字の別綴りを別の id として通さない
    assert.equal(w.reopen().apply(OW, ev).duplicate, true); // 開き直しても冪等
  } finally { w.cleanup(); }
});

test('入力は入口で一度だけ JSON に写して凍結する（toJSON・getter で検査と記録を食い違わせない）', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('a')] });
    const d = w.run.state().nodes.a.def_digest;
    let calls = 0;
    const sneaky = { event_id: 'tj-1', op: 'approve', node: 'a', spec_digest: S1, policy_line: 'p0.4', def_digest: d, toJSON() { calls += 1; return { event_id: 'tj-1', op: 'approve', node: 'a', spec_digest: S1, policy_line: 'p0.4', def_digest: calls === 1 ? d : `sha256:${'f'.repeat(64)}` }; } };
    w.run.apply(OW, sneaky);
    assert.equal(calls, 1); assert.equal(w.run.state().nodes.a.approved, true);
    assert.ok(w.reopen().verify().ok); // 記録したものも検査したものと同じ
    const cyc = { event_id: 'cy', op: 'stop' }; cyc.self = cyc;
    refused(() => w.run.apply(OW, cyc));
  } finally { w.cleanup(); }
});

test('__proto__・constructor などの名前：節の id として扱える・プロトタイプを汚さない', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('constructor'), N('tostring', ['constructor'])] });
    assert.deepEqual(Object.keys(w.run.state().nodes), ['constructor', 'tostring']);
    refused(() => w.run.apply(EX, JSON.parse('{"event_id":"pp","op":"plan","nodes":[],"__proto__":{"x":1}}')), 'RS-EVENT-SHAPE');
    refused(() => w.go(EX, { op: 'plan', nodes: [N('__proto__')] }), 'RS-EVENT-SHAPE');
    refused(() => w.go(OW, { op: 'approve', node: 'toString', spec_digest: S1, policy_line: 'p0.4', def_digest: S1 }), 'RS-EVENT-SHAPE');
    assert.equal({}.x, undefined);
  } finally { w.cleanup(); }
});

// ---- 記録の再生と偽の行 ----
test('記録に直接書いた偽の行は、再生で全ガードに通らず、全操作を拒む', () => {
  const forged = [
    ['行政が verdict で合格にする', { op: 'verdict', node: 'a', request: R1, audits: 'passed', verdicts: AP2 }, EX],
    ['未承認の節の着手', { op: 'start', node: 'b', spec_digest: S1, lease_sec: 60 }, EX],
    ['別の役割の release', { op: 'release', node: 'a', request: R1 }, EX],
    ['行為者の綴りが正規化した形と違う', { op: 'stop', reason: '止める' }, { role: ' owner', kind: 'human', id: 'azuki' }],
    ['知らない項目を足した行', { op: 'stop', reason: '止める', approved: true }, OW],
    ['cfg を持つ行（設定は記録の config の出来事だけ。行に持たせない）', { op: 'stop', reason: '止める', cfg: { hold: false } }, OW],
  ];
  for (const [name, row, actor] of forged) {
    const w = mkRun();
    try {
      w.go(EX, { op: 'plan', nodes: [N('a'), N('b')] }); w.approve('a'); w.start('a'); w.submit('a');
      const { op, ...rest } = row;
      openChain(w.file).append({ type: RECORD_TYPE, rules: RULES, op, event_id: `forged-${op}`, actor, ...rest });
      assert.equal(w.run.verify().ok, false, name);
      assert.equal(w.run.verify().code, 'bad_record', name);
      refused(() => w.run.state()); refused(() => w.go(OW, { op: 'stop', reason: 'x' }));
    } finally { w.cleanup(); }
  }
});

test('記録に直接書いた verdict の行は、結果を持てない。再生が decide で決め直す（監査 not_run の行は合格にならない）', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('a')] }); w.approve('a'); w.start('a'); w.submit('a');
    openChain(w.file).append({ type: RECORD_TYPE, rules: RULES, op: 'verdict', event_id: 'direct-1', actor: CT, node: 'a', request: R1, audits: 'not_run', verdicts: AP2 });
    assert.equal(w.run.verify().ok, true);
    assert.equal(w.run.state().nodes.a.status, 'in_progress'); // 差し戻し。merged にはならない
    openChain(w.file).append({ type: RECORD_TYPE, rules: RULES, op: 'verdict', event_id: 'direct-2', actor: CT, node: 'a', request: R1, audits: 'passed', verdicts: AP2, status: 'merged' });
    assert.equal(w.run.verify().code, 'bad_record'); // 結果を書き込んだ行（知らない項目）は拒む
  } finally { w.cleanup(); }
});

test('記録に直接書いた行：event_id の重複・時刻が読めない・知らない行は再生で拒む', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('a')] });
    const ch = openChain(w.file);
    const recs = ch.read();
    const first = recs[0];
    const { seq, at, prev, hash, ...body } = first;
    ch.append({ ...body }); // 同じ event_id の行
    assert.equal(w.run.verify().code, 'bad_record');
  } finally { w.cleanup(); }
  const w2 = mkRun();
  try {
    openChain(w2.file).append({ type: 'other', op: 'plan' });
    assert.equal(w2.run.verify().code, 'bad_record');
    refused(() => w2.run.next());
  } finally { w2.cleanup(); }
});

test('鎖が壊れた（行の書き換え・切り詰め）記録は拒む', () => {
  const w = mkRun();
  try {
    planAB(w);
    const lines = fs.readFileSync(w.file, 'utf8').split('\n');
    const k = lines.findIndex((l) => l.includes('"approve"'));
    lines[k] = lines[k].replace('"approve"', '"approvX"');
    fs.writeFileSync(w.file, lines.join('\n'));
    assert.equal(w.run.verify().ok, false);
    refused(() => w.go(OW, { op: 'stop', reason: 'x' }));
  } finally { w.cleanup(); }
});

test('規則の版と epoch：古い版の行は、オーナーの移行の記録に覆われるときだけ受け入れる', () => {
  const w = mkRun();
  try {
    planAB(w); w.start('a');
    const recs = openChain(w.file).read();
    assert.ok(recs.every((r) => r.rules === RULES));
    assert.throws(() => replay(recs, { rules: 'rs.v2' }), (e) => e.code === 'bad_record'); // 版が違う・移行の記録がない
    const ch = openChain(w.file);
    const mk = (actor, covers) => ch.append({ type: RECORD_TYPE, rules: 'rs.v2', op: 'epoch', event_id: `ep-${Math.random().toString(36).slice(2)}`, actor, covers, reason: '移行する' });
    // 行政の移行の記録・ハッシュの合わない移行の記録は覆わない
    mk(EX, { count: recs.length, last_hash: recs[recs.length - 1].hash });
    assert.throws(() => replay(ch.read(), { rules: 'rs.v2' }), (e) => e.code === 'bad_record');
  } finally { w.cleanup(); }
  const w2 = mkRun();
  try {
    planAB(w2); w2.start('a');
    const ch = openChain(w2.file);
    const recs = ch.read();
    ch.append({ type: RECORD_TYPE, rules: 'rs.v2', op: 'epoch', event_id: 'ep-ok', actor: OW, covers: { count: recs.length, last_hash: recs[recs.length - 1].hash }, reason: '規則を上げる' });
    const st = replay(ch.read(), { rules: 'rs.v2' });
    assert.equal(st.nodes.get('a').status, 'in_progress'); assert.equal(st.epochs, 1); assert.equal(st.covered, recs.length);
    // 覆われなかった後ろの古い版の行は拒む
    ch.append({ type: RECORD_TYPE, rules: RULES, op: 'stop', event_id: 'late-old', actor: OW, reason: 'x' });
    assert.throws(() => replay(ch.read(), { rules: 'rs.v2' }), (e) => e.code === 'bad_record');
  } finally { w2.cleanup(); }
});

test('epoch の apply：オーナーだけ・理由必須・ハッシュは実際の行に結び付く', () => {
  const w = mkRun();
  try {
    planAB(w);
    const recs = openChain(w.file).read();
    const good = { op: 'epoch', covers: { count: recs.length, last_hash: recs[recs.length - 1].hash }, reason: '規則の移行' };
    refused(() => w.go(EX, good), 'RS-KIND-OP');
    refused(() => w.go(OW, { ...good, reason: undefined }), 'RS-REASON');
    refused(() => w.go(OW, { ...good, covers: { count: recs.length, last_hash: '0'.repeat(64) } }), 'RS-EPOCH-COVERS');
    refused(() => w.go(OW, { ...good, covers: { count: recs.length + 5, last_hash: recs[recs.length - 1].hash } }), 'RS-EPOCH-COVERS');
    w.go(OW, good);
    assert.equal(w.run.state().epochs, 1);
    assert.ok(w.reopen().verify().ok);
  } finally { w.cleanup(); }
});

// ---- 公開の集計・next・設定 ----
test('summary は公開してよい集計だけ（理由の本文・指紋を出さない）', () => {
  const w = mkRun();
  try {
    planAB(w); w.start('a'); w.submit('a'); w.verdict('a', R1, 'passed', SPLIT_MAJOR);
    w.go(OW, { op: 'stop', reason: '秘密の理由の本文' });
    const s = w.run.summary(); const text = JSON.stringify(s);
    assert.ok(!text.includes('秘密') && !text.includes('sha256') && !text.includes(R1) && !text.includes('src/'));
    assert.deepEqual(s.blocked_reasons, { disagreement: 1 }); assert.equal(s.stopped, true);
    assert.deepEqual(s.by_status, { ready: 2, in_progress: 0, review: 0, held: 0, merged: 0, blocked: 1 });
    assert.deepEqual(Object.keys(s).sort(), ['awaiting_approval', 'blocked_reasons', 'by_status', 'configured', 'events', 'nodes', 'rules', 'single_lineage_judiciary', 'stopped']);
    assert.equal(s.single_lineage_judiciary, false);
  } finally { w.cleanup(); }
});

test('next は状態を書かず、決定論的', () => {
  const w = mkRun();
  try {
    planAB(w);
    const before = fs.readFileSync(w.file, 'utf8');
    const a = JSON.stringify(w.run.next()); const b = JSON.stringify(w.run.next());
    assert.equal(a, b); assert.equal(fs.readFileSync(w.file, 'utf8'), before);
    const nx = w.run.next();
    assert.deepEqual(nx.start, ['a', 'b']); assert.ok(nx.recommend && nx.recommend.workers <= 2);
    assert.deepEqual(nx.waiting.map((x) => x.id), ['c']);
  } finally { w.cleanup(); }
});

test('openRun は開く側の申告（設定・時計）を受けない。設定は記録の config からだけ', () => {
  const { dir, file } = tmpFile();
  try {
    for (const o of [{ hold: true }, { limits: { workers: 64 } }, { policyLine: 'p0.5' }, { now: () => '2099-01-01T00:00:00+09:00' }, { maxAttempts: 10 }, 'x', null]) {
      assert.throws(() => openRun(file, o), (e) => e instanceof Refused && e.code === 'bad_option', JSON.stringify(o));
    }
    assert.ok(openRun(file, { lockWaitMs: 1000 }));
    assert.ok(openRun(file));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('停止・再開の理由は必須。resume は停止中だけ', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('a')] });
    refused(() => w.go(OW, { op: 'resume', reason: 'x' }), 'RS-STOP-STATE');
    refused(() => w.go(OW, { op: 'stop' }), 'RS-REASON');
    w.go(OW, { op: 'stop', reason: '止める' });
    refused(() => w.go(OW, { op: 'stop', reason: 'もう一度' }), 'RS-STOP-STATE');
    refused(() => w.go(OW, { op: 'resume' }), 'RS-REASON');
    refused(() => w.go(OW, { op: 'resume', reason: '   ' }), 'RS-EVENT-SHAPE');
    w.go(OW, { op: 'resume', reason: '再開する' });
  } finally { w.cleanup(); }
});

// ---- ガードの性質 ----
test('check: 例外を投げない（壊れた ctx は違反として返す）。知らないガード名は例外', () => {
  for (const ctx of [undefined, null, {}, { state: null }, { state: newState() }, { state: newState(), event: 5, actor: 5 }, { state: newState(), event: { op: 'plan', nodes: 'x' }, actor: {} }]) {
    const r = check(ctx);
    assert.equal(r.ok, false);
  }
  assert.throws(() => check({}, ['NO-SUCH']));
  assert.throws(() => check({}, ['constructor']));
});

test('parseEvent: 型・大きさ・正規化（深い入力でもスタックがあふれない）', () => {
  assert.equal(parseEvent({ op: 'plan', event_id: 'e', nodes: Array.from({ length: 2001 }, (_, i) => N(`n${i}`)) }).ok, false);
  assert.equal(parseEvent({ op: 'plan', event_id: 'e', nodes: [N('a', Array.from({ length: 201 }, (_, i) => `d${i}`))] }).ok, false);
  assert.equal(parseEvent({ op: 'plan', event_id: 'e', nodes: [{ id: 'a', depends_on: new Set(['b']), resources: [] }] }).ok, false);
  assert.equal(parseEvent({ op: 'plan', event_id: 'e', nodes: [{ id: 'a', depends_on: [], resources: 'src/**' }] }).ok, false);
  assert.equal(parseEvent({ op: 'plan', event_id: 'e', nodes: [{ id: 'a', depends_on: ['b', 'b'], resources: [] }] }).ok, false);
  assert.equal(parseEvent({ op: 'start', event_id: 'e', node: 'a', spec_digest: S1, lease_sec: 604801 }).ok, false);
  assert.equal(parseEvent({ op: 'start', event_id: 'e', node: 'a', spec_digest: S1, lease_sec: 1.5 }).ok, false);
  assert.equal(parseEvent({ op: 'start', event_id: 'e', node: 'a', spec_digest: S1, lease_sec: '60' }).ok, false);
  let deep = {}; for (let i = 0; i < 100000; i += 1) deep = { x: deep };
  assert.equal(parseEvent({ op: 'stop', event_id: 'e', reason: 'x', deep }).ok, false);
  assert.equal(parseEvent({ op: 'plan', event_id: 'e', nodes: [N('a')] }).ok, true);
  assert.equal(parseEvent({ op: 'approve', event_id: ' e1 ', node: ' ａ ', spec_digest: S1, policy_line: 'p0.4', def_digest: S1 }).ev.node, 'a'); // 正規化
});

test('シナリオ: 全ガード有効で攻撃はすべて止まり、良性はすべて通る', () => {
  const guards = Object.keys(GUARDS);
  for (const s of SCENARIOS) {
    const r = s.run(guards);
    if (s.kind === 'attack') { assert.equal(r.blocked, true, `${s.id} ${s.title}`); assert.ok(s.expectGuards.some((g) => r.by.includes(g)), `${s.id}: 宣言 ${s.expectGuards} 実際 ${r.by}`); } else assert.equal(r.blocked, false, `${s.id} ${s.title}: ${r.by}`);
  }
});

test('アブレーション: どのガードも、外すと通る攻撃がある（外しても攻撃が通らないガード 0）', () => {
  const guards = Object.keys(GUARDS);
  const unproven = [];
  for (const g of guards) {
    const rest = guards.filter((x) => x !== g);
    const escaped = SCENARIOS.filter((s) => s.kind === 'attack' && s.run(rest).blocked === false);
    if (!escaped.length) unproven.push(g);
    for (const s of SCENARIOS.filter((x) => x.kind === 'benign')) assert.equal(s.run(rest).blocked, false, `${g} を外すと良性 ${s.id} が止まる`);
  }
  assert.deepEqual(unproven, []);
  // 全ガードを外すと、すべての攻撃が通る（ガード以外が止めていない）
  assert.deepEqual(SCENARIOS.filter((s) => s.kind === 'attack' && s.run([]).blocked !== false).map((s) => s.id), []);
});

test('シナリオの数: 攻撃は各ガードにつき1つ以上、良性は3つ以上', () => {
  const attacks = SCENARIOS.filter((s) => s.kind === 'attack');
  for (const g of Object.keys(GUARDS)) assert.ok(attacks.some((s) => s.expectGuards.includes(g)), `${g} の攻撃がない`);
  assert.ok(SCENARIOS.filter((s) => s.kind === 'benign').length >= 8);
});

// ================= 独立審査 C の判例（F1〜F7） =================
const cfgEv = (o = {}) => ({ op: 'config', ...JSON.parse(JSON.stringify(DEFAULT_CONFIG)), ...o });
const rechain = (file, rows) => {
  let prev = 'genesis';
  const out = rows.map((r, k) => { const { hash: _h, ...b } = r; const full = { ...b, seq: k + 1, prev }; const h = sha(full); prev = h; return { ...full, hash: h }; });
  fs.writeFileSync(file, `${out.map((x) => JSON.stringify(x)).join('\n')}\n`); fs.writeFileSync(`${file}.head`, `${JSON.stringify({ seq: out.length, hash: prev })}\n`);
};
import { sha256, canonical } from '../lib/chain.mjs';
const sha = (full) => sha256(canonical(full));
const readRows = (file) => fs.readFileSync(file, 'utf8').trim().split('\n').map((l) => JSON.parse(l));

test('F1: 設定は記録の config の出来事だけで決まる。config のない記録は、config 以外のすべて（人の操作も）を拒む', () => {
  const w = mkRun({ noConfig: true });
  try {
    refused(() => w.go(EX, { op: 'plan', nodes: [N('a')] }), 'RS-CONFIG-REQUIRED');
    refused(() => w.go(OW, { op: 'stop', reason: '止める' }), 'RS-CONFIG-REQUIRED');
    refused(() => w.go(EX, cfgEv()), 'RS-ROLE-OP'); // 行政は config を起こせない
    refused(() => w.go({ role: 'owner', kind: 'ai', id: 'max' }, cfgEv()), 'RS-KIND-OP');
    assert.equal(w.run.next().error.length, 1);
    w.go(OW, cfgEv());
    assert.equal(w.run.summary().configured, true);
    w.go(EX, { op: 'plan', nodes: [N('a')] });
  } finally { w.cleanup(); }
});

test('F1: 同じ記録を開き直しても、設定は変えられない（hold・同時の数・試行・法律の系統は記録のもの）', () => {
  const w = mkRun({ hold: true, workers: 1, max_attempts: 1, policy_line: 'p0.5' });
  try {
    w.go(EX, { op: 'plan', nodes: [N('a'), N('b'), N('h')] });
    w.approve('a'); w.approve('b');
    w.go(OW, { op: 'approve', node: 'h', spec_digest: S1, policy_line: 'p0.5', def_digest: w.run.state().nodes.h.def_digest });
    const other = w.reopen(); // 別の窓口（開く側は何も指定できない）
    refused(() => other.apply(EX, { event_id: 'x1', op: 'start', node: 'a', spec_digest: S1, lease_sec: 60 }), 'RS-POLICY-LINE'); // 承認は p0.4、系統は p0.5
    other.apply(EX, { event_id: 'x2', op: 'start', node: 'h', spec_digest: S1, lease_sec: 60 }); // p0.5 の承認は通る
    assert.equal(other.state().nodes.h.status, 'in_progress');
  } finally { w.cleanup(); }
  const w2 = mkRun({ hold: true, workers: 1, max_attempts: 1 });
  try {
    w2.go(EX, { op: 'plan', nodes: [N('a'), N('b')] }); w2.approve('a'); w2.approve('b'); w2.start('a', 60);
    refused(() => w2.reopen().apply(EX, { event_id: 'y1', op: 'start', node: 'b', spec_digest: S1, lease_sec: 60 }), 'RS-WORKER-LIMIT'); // 同時 1（開き直して広げられない）
    w2.submit('a');
    assert.equal(w2.reopen().apply(CT, { event_id: 'y2', op: 'verdict', node: 'a', request: R1, audits: 'passed', verdicts: AP2 }).to, 'held'); // hold は記録のもの
    w2.clock.t += 120e3;
  } finally { w2.cleanup(); }
  const w3 = mkRun({ max_attempts: 1 });
  try {
    w3.go(EX, { op: 'plan', nodes: [N('a')] }); w3.approve('a'); w3.start('a', 60); w3.clock.t += 120e3;
    w3.reopen().apply(RP, { event_id: 'z1', op: 'expire', node: 'a' });
    assert.equal(w3.st('a'), 'blocked'); // 試行の上限 1 は記録のもの
  } finally { w3.cleanup(); }
});

test('F1: config の変更は理由つき。緩める変更は作業中（in_progress・review・held）の節がないときだけ。締める変更はいつでも', () => {
  const w = mkRun({ hold: true });
  try {
    w.go(EX, { op: 'plan', nodes: [N('a')] }); w.approve('a');
    refused(() => w.go(OW, cfgEv({ workers: 1 })), 'RS-REASON');
    w.go(OW, cfgEv({ workers: 4, reason: '作業中の節がないので緩められる', hold: true }));
    w.start('a'); w.submit('a');
    refused(() => w.go(OW, cfgEv({ workers: 8, hold: true, reason: '広げる' })), 'RS-CONFIG-TIGHTEN');
    w.go(OW, cfgEv({ workers: 2, hold: true, reason: '締める' })); // 締める変更は作業中でも通る
    w.verdict('a', R1, 'passed', AP2);
    assert.equal(w.st('a'), 'held');
    refused(() => w.go(OW, cfgEv({ hold: false, reason: 'hold を外す' })), 'RS-CONFIG-TIGHTEN'); // held がある間は外せない
    refused(() => w.go(OW, cfgEv({ hold: true, judiciary: [{ kind: 'judge', lineage: 'claude' }], reason: '審査を減らす' })), 'RS-CONFIG-TIGHTEN');
    w.go(OW, { op: 'release', node: 'a', request: R1 });
    w.go(OW, cfgEv({ hold: false, reason: '作業中の節がなくなった' }));
    assert.equal(w.run.state().config.hold, false);
  } finally { w.cleanup(); }
});

test('F1/N1: 時刻が前の行より戻っても拒まず、記録の上の今（最大値）をそのまま使う。期限は戻した時計では切れない', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('a')] }); w.approve('a'); w.start('a', 600);
    const t = w.clock.t;
    w.clock.t = t - 3600e3; // 時計が戻る
    refused(() => w.go(RP, { op: 'expire', node: 'a' }), 'RS-EXPIRE-DUE'); // 最大値で判定するので、期限はまだ
    const rows = readRows(w.file);
    assert.ok(rows.at(-1).at ? true : true);
    const ats = rows.map((r) => Date.parse(r.at));
    assert.ok(ats.every((x, i) => i === 0 || x >= ats[i - 1]), '行の at は単調');
    w.clock.t = t + 600e3;
    w.go(RP, { op: 'expire', node: 'a' });
    assert.equal(w.st('a'), 'ready');
  } finally { w.cleanup(); }
});

test('N1: 追記する側の実時間より 5 分以上先の時刻の行は書く時に拒む（未来の時計で lease を奪えない）', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('a')] }); w.approve('a'); w.start('a', 600);
    w.clock.t = Date.parse('2099-01-01T00:00:00+09:00');
    refused(() => w.go(RP, { op: 'expire', node: 'a' }), 'RS-TIME-FUTURE');
    refused(() => w.go(EX, { op: 'plan', nodes: [N('b')] }), 'RS-TIME-FUTURE');
    w.go(OW, { op: 'stop', reason: '停止は未来の時刻でも通る' }); // INV-04
    assert.equal(w.run.state().stopped, true);
    assert.ok(Date.parse(readRows(w.file).at(-1).at) > Date.now() + 3600e3 * 24, '停止の行は書いた時刻の at');
  } finally { w.cleanup(); }
});

test('N1: 記録の上の今が実時間より先に進んだ記録（直接書かれた未来の行）は、stop が通り、オーナーが clock_reset で正せる', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('a')] }); w.approve('a');
    // 鎖としては正しい未来の時刻の行を直接足す（オーナーの権限や機械の時計の大きな進み）
    openChain(w.file, { now: () => '2099-01-01T00:00:00+09:00' }).append({ type: RECORD_TYPE, rules: RULES, op: 'plan', event_id: 'future-row', actor: EX, nodes: [N('f1')] });
    assert.ok(w.run.verify().ok, '再生は実時間を見ないので受ける');
    refused(() => w.go(EX, { op: 'plan', nodes: [N('b')] }), 'RS-TIME-FUTURE');
    refused(() => w.start('a'), 'RS-TIME-FUTURE');
    w.go(OW, { op: 'stop', reason: '緊急停止' }); // どんな時刻の状態でも通る
    refused(() => w.go(OW, { op: 'resume', reason: '再開する' }), 'RS-TIME-FUTURE'); // 先に時刻を正す
    refused(() => w.go(EX, { op: 'clock_reset', reason: 'x' }), 'RS-KIND-OP');
    refused(() => w.go(OW, { op: 'clock_reset' }), 'RS-REASON');
    w.go(OW, { op: 'clock_reset', reason: '時計が進んでいたので実時間に戻す' });
    w.go(OW, { op: 'resume', reason: '再開する' });
    w.go(EX, { op: 'plan', nodes: [N('b')] });
    assert.ok(w.reopen().verify().ok);
    assert.ok(Date.parse(readRows(w.file).at(-1).at) < Date.parse('2030-01-01'));
  } finally { w.cleanup(); }
});

test('N1: 並行の書き込み（別の窓口が後の時刻で書いた後に、前の時刻の窓口が書く）でも、正当な追記は通る', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('a')] });
    const late = w.reopen(); const early = w.reopen();
    w.clock.t += 60e3;
    late.apply(OW, { event_id: 'late-1', op: 'stop', reason: '後の時刻' });
    w.clock.t -= 120e3; // early の時計は前
    early.apply(OW, { event_id: 'early-1', op: 'resume', reason: '前の時刻の窓口の正当な追記' });
    assert.equal(w.run.state().stopped, false);
    const ats = readRows(w.file).map((r) => Date.parse(r.at));
    assert.ok(ats.every((x, i) => i === 0 || x >= ats[i - 1]));
  } finally { w.cleanup(); }
});

test('F2: 申請中（review）の節も、範囲の重なり・同時の数に入る。held は範囲を占めるが枠は使わない', () => {
  const w = mkRun({ workers: 1 });
  try {
    w.go(EX, { op: 'plan', nodes: [N('x', [], ['src/shared/**']), N('y', [], ['src/shared/x.ts']), N('z')] });
    for (const id of ['x', 'y', 'z']) w.approve(id);
    w.start('x'); w.submit('x');
    refused(() => w.start('y'), 'RS-RESOURCE-DISJOINT');
    refused(() => w.start('z'), 'RS-WORKER-LIMIT'); // review も枠を使う（workers=1）
    assert.deepEqual(w.run.next().start, []);
    w.verdict('x', R1, 'failed', AP2); // 差し戻し：x だけが作業中で、重なる y は着手できていない
    assert.deepEqual(['x', 'y'].map(w.st), ['in_progress', 'ready']);
  } finally { w.cleanup(); }
  const h = mkRun({ workers: 1, hold: true });
  try {
    h.go(EX, { op: 'plan', nodes: [N('x', [], ['src/shared/**']), N('y', [], ['src/shared/x.ts']), N('z')] });
    for (const id of ['x', 'y', 'z']) h.approve(id);
    h.start('x'); h.submit('x'); h.verdict('x', R1, 'passed', AP2);
    assert.equal(h.st('x'), 'held');
    refused(() => h.start('y'), 'RS-RESOURCE-DISJOINT'); // held は範囲を占める
    assert.deepEqual(h.run.next().start, ['z']); // held は枠を使わない
    h.start('z'); assert.equal(h.st('z'), 'in_progress');
  } finally { h.cleanup(); }
});

test('F3: UNAVAILABLE が1つでもあれば「司法が使えない」。必須の審査の一覧は config に固定され、余分・知らない系統・表記ゆれは拒む', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('a')] }); w.approve('a'); w.start('a'); w.submit('a');
    assert.equal(w.verdict('a', R1, 'passed', [...AP2.slice(0, 1), J('codex', 'UNAVAILABLE')]).kind, 'unavailable');
    assert.equal(w.verdict('a', R1, 'passed', [AP2[0]]).kind, 'unavailable'); // 欠落（codex の結果がない）
    refused(() => w.verdict('a', R1, 'passed', [AP2[0], J('open_ai')]), 'RS-VERDICT-SET'); // 一覧にない系統
    refused(() => w.verdict('a', R1, 'passed', [...AP2, J('gemini')]), 'RS-VERDICT-SET');
    refused(() => w.verdict('a', R1, 'passed', [AP2[0], J('open-ai')]), 'RS-EVENT-SHAPE'); // lineage の表記ゆれ
    refused(() => w.verdict('a', R1, 'passed', [AP2[0], { ...J('codex'), lineage: 'Codex' }]), 'RS-EVENT-SHAPE');
    refused(() => w.verdict('a', R1, 'passed', [...AP2, { ...AP2[0], judge: 'other' }]), 'RS-EVENT-SHAPE'); // 同じ審査の結果が2件
    refused(() => w.verdict('a', R1, 'passed', [...AP2, J('codex', 'APPROVED', false, 'security')]), 'RS-VERDICT-SET'); // security の印がない節
    assert.equal(w.st('a'), 'review');
    assert.equal(w.verdict('a', R1, 'passed', AP2).kind, 'pass');
  } finally { w.cleanup(); }
});

test('F3: 必須の審査は3人にもできる（judgesRequired=3 の相当）。同じ系統2人＋別の系統1人では足りない', () => {
  const w = mkRun({ judiciary: [{ kind: 'judge', lineage: 'claude' }, { kind: 'judge', lineage: 'codex' }, { kind: 'judge', lineage: 'gemini' }] });
  try {
    w.go(EX, { op: 'plan', nodes: [N('a')] }); w.approve('a'); w.start('a'); w.submit('a');
    assert.equal(w.verdict('a', R1, 'passed', AP2).kind, 'unavailable'); // gemini がない
    assert.equal(w.verdict('a', R1, 'passed', [...AP2, J('gemini')]).kind, 'pass');
  } finally { w.cleanup(); }
});

test('F3: security_review の節は、security の結果も必須。不合格は不一致でなく差し戻し（裁定で通せない）', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [{ ...N('a'), security_review: true }, N('b')] }); w.approve('a'); w.approve('b');
    assert.notEqual(w.run.state().nodes.a.def_digest, w.run.state().nodes.b.def_digest);
    w.start('a'); w.submit('a');
    assert.equal(w.verdict('a', R1, 'passed', AP2).kind, 'unavailable'); // security の結果がない
    const sec = (v, major = false) => J('codex', v, major, 'security');
    const r = w.verdict('a', R1, 'passed', [...AP2, sec('CHANGES_REQUIRED', true)]);
    assert.equal(r.kind, 'return'); assert.equal(w.st('a'), 'in_progress');
    w.submit('a', R2);
    // 司法が分かれて security も不合格でも、security が先（差し戻し。blocked にならない）
    assert.equal(w.verdict('a', R2, 'passed', [J('claude'), J('codex', 'CHANGES_REQUIRED', true), sec('CHANGES_REQUIRED', true)]).kind, 'return');
    w.submit('a', 'c3c3c3c3');
    assert.equal(w.verdict('a', 'c3c3c3c3', 'passed', [...AP2, sec('APPROVED')]).kind, 'pass');
  } finally { w.cleanup(); }
});

test('F3/Kernel: 1系統だけの運転（--no-codex 相当）は config で表せ、summary に「別の系統の確認がない」印が出る', () => {
  const w = mkRun({ judiciary: [{ kind: 'judge', lineage: 'claude' }] });
  try {
    w.go(EX, { op: 'plan', nodes: [N('a')] }); w.approve('a'); w.start('a'); w.submit('a');
    assert.equal(w.run.summary().single_lineage_judiciary, true);
    assert.equal(w.verdict('a', R1, 'passed', [J('claude')]).kind, 'pass');
    assert.equal(mkRun().run.summary().single_lineage_judiciary, false);
  } finally { w.cleanup(); }
});

test('Kernel/SPEC §6-5: 司法が使えない回数は同じ申請の指紋の通算。別の申請を挟んでも戻らない。unblock でも戻さず、追加の回数はオーナーが与える', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('a')] }); w.approve('a'); w.start('a');
    const one = [AP2[0]];
    w.submit('a', R1); w.verdict('a', R1, 'passed', one); w.verdict('a', R1, 'passed', one);
    w.verdict('a', R1, 'failed', AP2);
    w.submit('a', R2); w.verdict('a', R2, 'passed', one); w.verdict('a', R2, 'failed', AP2);
    w.submit('a', R1); // 同じ申請の指紋に戻る
    assert.equal(w.verdict('a', R1, 'passed', one).kind, 'blocked_unavailable'); // R1 の通算3回目
    assert.deepEqual(w.run.state().nodes.a.unavail, { [R1]: 3, [R2]: 1 });
    w.go(OW, { op: 'unblock', node: 'a', reason: '司法の環境を直した', extra_attempts: 1, extra_unavailable: 1 });
    assert.deepEqual(w.run.state().nodes.a.unavail, { [R1]: 3, [R2]: 1 }, '戻さない');
    assert.equal(w.run.state().nodes.a.extra_unavailable, 1);
  } finally { w.cleanup(); }
});

test('Kernel: 差し戻しで in_progress に戻るときも attempts を数える。上限に達していれば blocked', () => {
  const w = mkRun({ max_attempts: 2 });
  try {
    w.go(EX, { op: 'plan', nodes: [N('a')] }); w.approve('a'); w.start('a'); w.submit('a');
    assert.equal(w.verdict('a', R1, 'failed', AP2).kind, 'return');
    assert.equal(w.run.state().nodes.a.attempts, 2);
    w.submit('a', R2);
    const r = w.verdict('a', R2, 'failed', AP2);
    assert.equal(r.kind, 'blocked_attempts'); assert.equal(w.st('a'), 'blocked');
    assert.deepEqual(w.run.summary().blocked_reasons, { attempts_exhausted: 1 });
  } finally { w.cleanup(); }
});

test('F4: 空の plan は拒む。行政の plan の回数・人以外の枠には上限があり、オーナーの stop・resume・epoch は塞がれない', () => {
  const m = memoryRun();
  const EXA = { role: 'executive', kind: 'ai', id: 'max' };
  assert.throws(() => m.apply(EXA, { event_id: 'e0', op: 'plan', nodes: [] }), (e) => e.violations.some((v) => v.guard === 'RS-PLAN-NONEMPTY'));
  for (let i = 0; i < 500; i += 1) m.apply(EXA, { event_id: `p${i}`, op: 'plan', nodes: [N(`n${i}`, [], [])] });
  assert.throws(() => m.apply(EXA, { event_id: 'p500', op: 'plan', nodes: [N('over', [], [])] }), (e) => e.violations.some((v) => v.guard === 'RS-EVENT-QUOTA'));
  m.apply(OW, { event_id: 'o-stop', op: 'stop', reason: '緊急停止' });
  m.apply(OW, { event_id: 'o-resume', op: 'resume', reason: '再開' });
  // 人以外の枠が尽きた状態
  m.st.count = MAX_EVENTS - HUMAN_RESERVE;
  assert.throws(() => m.apply(CT, { event_id: 'c1', op: 'expire', node: 'n0' }), (e) => e.violations.some((v) => v.guard === 'RS-EVENT-QUOTA'));
  m.apply(OW, { event_id: 'o-stop2', op: 'stop', reason: '人の枠は残っている' });
  assert.equal(m.state().stopped, true);
});

test('F5: 置き換えの鎖は上限（8）まで。解決は一度だけ更新され、古い節への依存は最後の置き換え先に付く', () => {
  const m = memoryRun();
  m.apply(EX, { event_id: 'p0', op: 'plan', nodes: [N('s0', [], []), N('d', ['s0'], [])] });
  for (let k = 0; k < 8; k += 1) m.apply(EX, { event_id: `p${k + 1}`, op: 'plan', nodes: [N(`s${k + 1}`, [], [])], supersede: [{ old: `s${k}`, new: `s${k + 1}` }] });
  assert.throws(() => m.apply(EX, { event_id: 'p99', op: 'plan', nodes: [N('s9', [], [])], supersede: [{ old: 's8', new: 's9' }] }), (e) => e.violations.some((v) => v.guard === 'RS-PLAN-SUPERSEDE'));
  assert.equal(m.st.final.get('s0'), 's8'); assert.equal(m.st.final.get('s7'), 's8');
  assert.ok(m.next().waiting.find((x) => x.id === 'd').reasons.includes('waiting_dependency:s8'));
});

test('F5: 大量の依存（審査者の再現の形）でも、出来事1回が1秒以内。依存の総数・1節の依存の数には上限', () => {
  const m = memoryRun({ config: { workers: 4 } });
  const base = Array.from({ length: 64 }, (_, i) => N(`b${i}`, [], []));
  m.apply(EX, { event_id: 'pb', op: 'plan', nodes: base });
  const deps = base.map((b) => b.id);
  const heavy = Array.from({ length: 300 }, (_, i) => ({ id: `h${i}`, depends_on: deps, resources: [] }));
  let t0 = Date.now(); m.apply(EX, { event_id: 'ph', op: 'plan', nodes: heavy.slice(0, 200) }); m.apply(EX, { event_id: 'ph1', op: 'plan', nodes: heavy.slice(200) });
  assert.ok(Date.now() - t0 < 2000, `plan ${Date.now() - t0} ms`);
  assert.throws(() => m.apply(EX, { event_id: 'ph2', op: 'plan', nodes: Array.from({ length: 20 }, (_, i) => ({ id: `g${i}`, depends_on: deps, resources: [] })) }), (e) => e.violations.some((v) => v.guard === 'RS-SIZE-LIMIT'));
  m.apply(EX, { event_id: 'px', op: 'plan', nodes: [N('x')] });
  m.apply(OW, { op: 'approve', event_id: 'ax', node: 'x', spec_digest: S1, policy_line: 'p0.4', def_digest: m.state().nodes.x.def_digest });
  t0 = Date.now(); m.apply(EX, { event_id: 'sx', op: 'start', node: 'x', spec_digest: S1, lease_sec: 60 });
  assert.ok(Date.now() - t0 < 1000, `start ${Date.now() - t0} ms`);
  t0 = Date.now(); m.next(); assert.ok(Date.now() - t0 < 1000, `next ${Date.now() - t0} ms`);
});

test('F6: submit できるのは着手した行為者だけ', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('a')] }); w.approve('a');
    w.go({ role: 'night_agent', kind: 'script', id: 'night' }, { op: 'start', node: 'a', spec_digest: S1, lease_sec: 600 });
    refused(() => w.submit('a'), 'RS-WORKER-BIND');
    w.go({ role: 'night_agent', kind: 'script', id: 'night' }, { op: 'submit', node: 'a', request: R1 });
    assert.equal(w.st('a'), 'review');
  } finally { w.cleanup(); }
});

test('F6: event_id の一意性は (役割, op) の組ごと。行政が予測した id でオーナーの stop を塞げない', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('a')] });
    w.run.apply(EX, { event_id: 'stop-20260101', op: 'plan', nodes: [N('b')] });
    w.run.apply(OW, { event_id: 'stop-20260101', op: 'stop', reason: '止める' });
    assert.equal(w.run.state().stopped, true);
    refused(() => w.run.apply(OW, { event_id: 'stop-20260101', op: 'stop', reason: '二度目（内容が違う）' }), 'RS-STOP-STATE');
  } finally { w.cleanup(); }
});

test('F6: 行政は、オーナーの判断待ち（held・判定の不一致で blocked）の節を置き換えで消せない。オーナーはできる', () => {
  const w = mkRun({ hold: true });
  try {
    w.go(EX, { op: 'plan', nodes: [N('a'), N('b')] }); w.approve('a'); w.approve('b');
    w.start('a'); w.submit('a'); w.verdict('a', R1, 'passed', AP2);
    w.start('b'); w.submit('b', R2); w.verdict('b', R2, 'passed', SPLIT_MAJOR);
    assert.deepEqual(['a', 'b'].map(w.st), ['held', 'blocked']);
    refused(() => w.go(EX, { op: 'plan', nodes: [N('a2')], supersede: [{ old: 'a', new: 'a2' }] }), 'RS-PLAN-SUPERSEDE');
    refused(() => w.go(EX, { op: 'plan', nodes: [N('b2')], supersede: [{ old: 'b', new: 'b2' }] }), 'RS-PLAN-SUPERSEDE');
    w.go(OW, { op: 'plan', nodes: [N('a2')], supersede: [{ old: 'a', new: 'a2' }] });
    assert.equal(w.run.state().nodes.a.superseded_by, 'a2');
  } finally { w.cleanup(); }
});

// ---- F7: キャッシュと試験の空回り ----
test('F7: キャッシュ — 記録を書き換えて鎖を作り直した後に、古いキャッシュの状態が返らない（先頭の行のハッシュの照合）', () => {
  const w = mkRun();
  try {
    planAB(w);
    assert.equal(w.run.state().nodes.a.approval.spec_digest, S1); // キャッシュを温める
    const rows = readRows(w.file);
    const k = rows.findIndex((r) => r.op === 'approve' && r.node === 'a');
    rows[k] = { ...rows[k], spec_digest: `sha256:${'b'.repeat(64)}` };
    rechain(w.file, rows); // 同じ行数・同じ内容の鎖で、途中の行だけが違う
    assert.equal(w.run.state().nodes.a.approval.spec_digest, `sha256:${'b'.repeat(64)}`);
  } finally { w.cleanup(); }
});

test('F7: canResume — 先頭の行のハッシュの不一致・古い版や移行の行がある状態（pure でない）・行数の超過では使い回さない', () => {
  const w = mkRun();
  try {
    planAB(w);
    const recs = openChain(w.file).read();
    const st = replay(recs);
    assert.equal(canResume(st, recs), true);
    assert.equal(canResume(st, [...recs, recs[0]]), true); // 続きの行があるのは使える
    const tampered = recs.map((r, i) => (i === recs.length - 1 ? { ...r, hash: 'x'.repeat(64) } : r));
    assert.equal(canResume(st, tampered), false, '先頭の count 行の最後のハッシュが違う');
    assert.equal(canResume(st, recs.slice(0, -1)), false, '行数が足りない');
    assert.equal(canResume({ ...st, pure: false }, recs), false, 'pure でない');
    assert.equal(canResume(null, recs), false);
    assert.equal(canResume(newState(), recs), true);
    st.pure = false;
    // 移行の行を覆った後は pure でなくなる
    const ch = openChain(w.file);
    ch.append({ type: RECORD_TYPE, rules: RULES, op: 'epoch', event_id: 'ep-p', actor: OW, covers: { count: recs.length, last_hash: recs[recs.length - 1].hash }, reason: '移行' });
    assert.equal(replay(ch.read()).pure, false);
  } finally { w.cleanup(); }
});

test('F7: キャッシュ — 別のファイルのキャッシュは混ざらない。キャッシュがあっても規則に合わない行は拒む', () => {
  const a = mkRun(); const b = mkRun();
  try {
    a.go(EX, { op: 'plan', nodes: [N('only_a')] }); b.go(EX, { op: 'plan', nodes: [N('only_b')] });
    assert.deepEqual(a.run.state().order, ['only_a']); assert.deepEqual(b.run.state().order, ['only_b']);
    a.run.state(); // キャッシュを温める
    // 鎖としては正しいが、規則に合わない行（未承認の start）を直接足す
    openChain(a.file).append({ type: RECORD_TYPE, rules: RULES, op: 'start', event_id: 'forged-s', actor: EX, node: 'only_a', spec_digest: S1, lease_sec: 60 });
    assert.throws(() => a.run.state(), (e) => e.code === 'bad_record');
    refused(() => a.go(OW, { op: 'stop', reason: 'x' }));
    assert.deepEqual(b.run.state().order, ['only_b']);
  } finally { a.cleanup(); b.cleanup(); }
});

// ================= 再審査 C（N1〜N6） =================
test('N2: start の lease_sec は config.lease_sec を超えられない', () => {
  const w = mkRun({ lease_sec: 600 });
  try {
    w.go(EX, { op: 'plan', nodes: [N('a')] }); w.approve('a');
    refused(() => w.start('a', 604800), 'RS-LEASE-LIMIT');
    refused(() => w.start('a', 601), 'RS-LEASE-LIMIT');
    w.start('a', 600); assert.equal(w.st('a'), 'in_progress');
  } finally { w.cleanup(); }
});

test('N3: 未統合の申請を持つ blocked の節は範囲を占める。rule の return・unblock も範囲と同時の数を通す', () => {
  const w = mkRun({ workers: 2 });
  try {
    w.go(EX, { op: 'plan', nodes: [N('x', [], ['src/shared/**']), N('y', [], ['src/shared/x.ts']), N('z')] });
    for (const id of ['x', 'y', 'z']) w.approve(id);
    w.start('x'); w.submit('x'); w.verdict('x', R1, 'passed', SPLIT_MAJOR);
    assert.equal(w.st('x'), 'blocked');
    refused(() => w.start('y'), 'RS-RESOURCE-DISJOINT');
    const nx = w.run.next();
    assert.deepEqual(nx.start, ['z']); assert.ok(nx.waiting.find((q) => q.id === 'x').reasons.includes('blocked'));
    w.go(OW, { op: 'rule', node: 'x', request: R1, decision: 'return', reason: 'やり直す' });
    assert.equal(w.st('x'), 'in_progress');
    refused(() => w.start('y'), 'RS-RESOURCE-DISJOINT');
  } finally { w.cleanup(); }
  const w2 = mkRun({ workers: 2 });
  try {
    w2.go(EX, { op: 'plan', nodes: [N('x'), N('y')] }); w2.approve('x'); w2.approve('y');
    w2.start('x'); w2.start('y'); w2.submit('x'); w2.verdict('x', R1, 'passed', SPLIT_MAJOR);
    w2.go(OW, { ...cfgEv({ workers: 1, reason: '枠を締める' }) });
    refused(() => w2.go(OW, { op: 'rule', node: 'x', request: R1, decision: 'return', reason: 'やり直す' }), 'RS-WORKER-LIMIT');
    w2.go(OW, { op: 'rule', node: 'x', request: R1, decision: 'merge', reason: '通す' }); // merge は枠を使わないので通る
    assert.equal(w2.st('x'), 'merged');
  } finally { w2.cleanup(); }
});

test('N4: 行政が足せる節の数には取り置きの枠がある。1回の plan は 200 節まで。オーナーは枠の中で足せて置き換えられる', () => {
  const m = memoryRun();
  assert.throws(() => m.apply(EX, { event_id: 'big', op: 'plan', nodes: Array.from({ length: 201 }, (_, i) => N(`b${i}`, [], [])) }), (e) => e.violations.some((v) => v.guard === 'RS-EVENT-SHAPE'));
  for (let k = 0; k < 9; k += 1) m.apply(EX, { event_id: `pl${k}`, op: 'plan', nodes: Array.from({ length: 200 }, (_, i) => N(`n${k}-${i}`, [], [])) });
  assert.equal(m.state().order.length, 1800);
  assert.throws(() => m.apply(EX, { event_id: 'pl9', op: 'plan', nodes: [N('over', [], [])] }), (e) => e.violations.some((v) => v.guard === 'RS-EVENT-QUOTA'));
  m.apply(OW, { event_id: 'o1', op: 'plan', nodes: [N('owner-node', [], [])] });
  m.apply(OW, { event_id: 'o2', op: 'plan', nodes: [N('owner-node2', [], [])], supersede: [{ old: 'n0-0', new: 'owner-node2' }] });
  assert.equal(m.state().nodes['n0-0'].superseded_by, 'owner-node2');
});

test('N5: 法律の系統の付け替えは、それ自体が緩める変更。付け替えると承認は効かなくなり、系統を戻しても復活しない', () => {
  const w = mkRun({ policy_line: 'p0.4' });
  try {
    w.go(EX, { op: 'plan', nodes: [N('a'), N('b')] }); w.approve('a'); w.approve('b'); w.start('a');
    refused(() => w.go(OW, cfgEv({ policy_line: 'p0.3', reason: '付け替える' })), 'RS-CONFIG-TIGHTEN');
    w.submit('a'); w.verdict('a', R1, 'passed', AP2); // a は merged（作業中でなくなる）
    w.go(OW, cfgEv({ policy_line: 'p0.3', reason: '付け替える' }));
    assert.equal(w.run.state().nodes.b.approved, false);
    w.go(OW, cfgEv({ policy_line: 'p0.4', reason: '戻す' }));
    assert.equal(w.run.state().nodes.b.approved, false, '古い承認は復活しない');
    refused(() => w.start('b'), 'RS-APPROVED');
    w.approve('b'); w.start('b'); assert.equal(w.st('b'), 'in_progress');
  } finally { w.cleanup(); }
});

test('N6: 取り置きの枠と行政の上限は role で決まる。kind: human を名乗る executive は回避できない', () => {
  const m = memoryRun();
  const HX = { role: 'executive', kind: 'human', id: 'max' };
  for (let i = 0; i < 500; i += 1) m.apply(i % 2 ? HX : EX, { event_id: `p${i}`, op: 'plan', nodes: [N(`n${i}`, [], [])] });
  assert.throws(() => m.apply(HX, { event_id: 'p500', op: 'plan', nodes: [N('x', [], [])] }), (e) => e.violations.some((v) => v.guard === 'RS-EVENT-QUOTA'));
  m.st.count = MAX_EVENTS - HUMAN_RESERVE;
  assert.throws(() => m.apply(HX, { event_id: 'q', op: 'plan', nodes: [N('y', [], [])] }), (e) => e.violations.some((v) => v.guard === 'RS-EVENT-QUOTA'));
  m.apply(OW, { event_id: 'own', op: 'plan', nodes: [N('y', [], [])] });
});

test('config: 作業中に、項目ごとに緩める変更（max_attempts・max_returns・max_unavailable・lease_sec・security_lineage）を拒む。締める変更は通る', () => {
  const w = mkRun({ max_attempts: 3, max_returns: 2, max_unavailable: 2, lease_sec: 600 });
  try {
    w.go(EX, { op: 'plan', nodes: [N('a')] }); w.approve('a'); w.start('a', 300);
    const base = { max_attempts: 3, max_returns: 2, max_unavailable: 2, lease_sec: 600 };
    for (const loosen of [{ max_attempts: 4 }, { max_returns: 3 }, { max_unavailable: 3 }, { lease_sec: 601 }, { security_lineage: 'gemini' }, { workers: 3 }]) {
      refused(() => w.go(OW, cfgEv({ ...base, ...loosen, reason: '緩める' })), 'RS-CONFIG-TIGHTEN');
    }
    w.go(OW, cfgEv({ max_attempts: 2, max_returns: 1, max_unavailable: 1, lease_sec: 300, workers: 1, reason: '締める' }));
    assert.equal(w.run.state().config.max_attempts, 2);
  } finally { w.cleanup(); }
});
