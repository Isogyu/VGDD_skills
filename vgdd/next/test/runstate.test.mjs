import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openChain, Refused } from '../lib/chain.mjs';
import { openRun, unsafeOpenRunWithClock, memoryRun, replay, canResume, decide, check, GUARDS, parseActor, parseEvent, makeCtx, newState, RULES, RECORD_TYPE, DEFAULT_CONFIG, MAX_EVENTS, HUMAN_RESERVE, defDigestOf } from '../runstate.mjs';
import { SCENARIOS } from '../bench/scenarios-runstate.mjs';

const EX = { role: 'executive_head', kind: 'ai', id: 'max', lineage: 'claude' };
const OW = { role: 'owner', kind: 'human', id: 'azuki' };
const CT = { role: 'gate_runner', kind: 'script', id: 'gate_runner' };
const RP = { role: 'reaper', kind: 'script', id: 'reaper' };
// 記録に直接書く行の行為者は、正規化した形（vocab の { role, kind, id, lineage }）で書く（再生が綴りの違いを拒むため）
const OWN = parseActor(OW).actor;
const CTN = parseActor(CT).actor;
const S1 = `sha256:${'a'.repeat(64)}`;
const R1 = 'a1b2c3d4e5f6'.padEnd(40, '0'); // 申請の指紋（Git の 40 桁）
const R2 = 'f6e5d4c3b2a1'.padEnd(40, '0');
const J = (lineage, verdict = 'APPROVED', major = false, kind = 'judge') => ({ kind, judge: `${kind}_${lineage}`, lineage, verdict, major });
const AP2 = [J('claude'), J('codex')];
const SPLIT_MAJOR = [J('claude'), J('codex', 'CHANGES_REQUIRED', true)];
const N = (id, depends_on = [], resources = [`src/${id}/**`]) => ({ id, depends_on, resources });
/** 生成する節の id（config の票の ID の宣言の既定：T- と 3〜4 桁） */
const T = (i) => `T-${String(i).padStart(4, '0')}`;

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
  if (!noConfig) go(OW, { op: 'config', ...JSON.parse(JSON.stringify(DEFAULT_CONFIG)), concurrent_work: 2, ...config });
  const st = (id) => run.state().nodes[id].status;
  const approve = (id, spec = S1) => go(OW, { op: 'approve', node: id, spec_digest: spec, policy_line: 'p0.4', def_digest: run.state().nodes[id].def_digest });
  const start = (id, lease = 3600) => go(EX, { op: 'start', node: id, spec_digest: S1, lease_sec: lease });
  const submit = (id, req = R1) => go(EX, { op: 'submit', node: id, request: req });
  const verdict = (id, req, audits, verdicts) => go(CT, { op: 'verdict', node: id, request: req, audits, verdicts });
  return { dir, file, clock, run, go, st, approve, start, submit, verdict, reopen: () => unsafeOpenRunWithClock(file, { now }), cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}
const refused = (fn, guard) => { try { fn(); } catch (e) { assert.ok(e instanceof Refused, String(e)); if (guard) assert.ok((e.violations || []).some((v) => v.guard === guard), `${guard} で拒否されるはず: ${e.message}`); return e; } assert.fail('拒否されるはず'); };
const planAB = (w) => { w.go(EX, { op: 'plan', nodes: [N('T-001'), N('T-002'), N('T-003', ['T-001', 'T-002'])] }); for (const id of ['T-001', 'T-002', 'T-003']) w.approve(id); };
const cfgEv = (o = {}) => ({ op: 'config', ...JSON.parse(JSON.stringify(DEFAULT_CONFIG)), ...o });

// ---- 良性の流れ（記録のファイルで通す） ----
test('良性: 3つの節（a、b は独立、c は a と b に依存）を承認→着手→申請→合格→統合まで通す', () => {
  const w = mkRun();
  try {
    planAB(w);
    assert.deepEqual(w.run.next().start, ['T-001', 'T-002']);
    w.start('T-001'); w.start('T-002');
    assert.deepEqual(w.run.next().start, []); // 同時の数 2、c は依存待ち
    for (const id of ['T-001', 'T-002']) { w.submit(id); w.verdict(id, R1, 'passed', AP2); }
    assert.deepEqual(w.run.next().start, ['T-003']);
    w.start('T-003'); w.submit('T-003', R2); w.verdict('T-003', R2, 'passed', AP2);
    assert.deepEqual(['T-001', 'T-002', 'T-003'].map(w.st), ['merged', 'merged', 'merged']);
    assert.equal(w.run.summary().by_status.merged, 3);
    assert.ok(w.run.verify().ok);
  } finally { w.cleanup(); }
});

test('良性: 差し戻し→再申請→合格。差し戻しの回数は数える', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001')] }); w.approve('T-001'); w.start('T-001');
    w.submit('T-001', R1); const r = w.verdict('T-001', R1, 'failed', AP2);
    assert.equal(r.kind, 'return'); assert.equal(w.st('T-001'), 'in_progress'); assert.equal(w.run.state().nodes['T-001'].returns, 1);
    w.submit('T-001', R2); w.verdict('T-001', R2, 'passed', AP2);
    assert.equal(w.st('T-001'), 'merged');
  } finally { w.cleanup(); }
});

test('良性: 司法が使えない→戻った周回で合格（差し戻しに数えない）。3回で blocked', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001')] }); w.approve('T-001'); w.start('T-001'); w.submit('T-001');
    const one = [AP2[0]];
    assert.equal(w.verdict('T-001', R1, 'passed', one).kind, 'unavailable');
    assert.equal(w.run.state().nodes['T-001'].returns, 0);
    assert.equal(w.verdict('T-001', R1, 'passed', AP2).kind, 'pass');
    assert.equal(w.st('T-001'), 'merged');
    // 別の節で3回
    w.go(EX, { op: 'plan', nodes: [N('T-002')] }); w.approve('T-002'); w.start('T-002'); w.submit('T-002', R2);
    w.verdict('T-002', R2, 'passed', one); w.verdict('T-002', R2, 'passed', one);
    assert.equal(w.verdict('T-002', R2, 'passed', one).kind, 'blocked_unavailable');
    assert.equal(w.st('T-002'), 'blocked'); assert.equal(w.run.state().nodes['T-002'].returns, 0);
    assert.deepEqual(w.run.summary().blocked_reasons, { judiciary_unavailable: 1 });
  } finally { w.cleanup(); }
});

test('良性: 夜間（hold）は held → オーナーの release で merged', () => {
  const w = mkRun({ hold: true });
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001')] }); w.approve('T-001'); w.start('T-001'); w.submit('T-001');
    assert.equal(w.verdict('T-001', R1, 'passed', AP2).to, 'held');
    refused(() => w.go(OW, { op: 'release', node: 'T-001', request: R2 }), 'RS-REQUEST-MATCH'); // 対象の固定
    w.go(OW, { op: 'release', node: 'T-001', request: R1 });
    assert.equal(w.st('T-001'), 'merged');
  } finally { w.cleanup(); }
});

test('良性: 判定が分かれた（重大）→ blocked → オーナーの裁定（merge・return の両方）', () => {
  const split = [AP2[0], J('codex', 'CHANGES_REQUIRED', true)];
  for (const decision of ['merge', 'return']) {
    const w = mkRun();
    try {
      w.go(EX, { op: 'plan', nodes: [N('T-001')] }); w.approve('T-001'); w.start('T-001'); w.submit('T-001');
      assert.equal(w.verdict('T-001', R1, 'passed', split).kind, 'blocked_disagreement');
      assert.equal(w.st('T-001'), 'blocked');
      w.go(OW, { op: 'rule', node: 'T-001', request: R1, decision, reason: '裁定する' });
      assert.equal(w.st('T-001'), decision === 'merge' ? 'merged' : 'in_progress');
      if (decision === 'return') assert.equal(w.run.state().nodes['T-001'].returns, 1);
    } finally { w.cleanup(); }
  }
});

test('良性: 停止→再開→続行。停止中は stop・resume 以外をすべて拒む', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001')] }); w.approve('T-001'); w.start('T-001');
    w.go(OW, { op: 'stop', reason: '点検' });
    assert.equal(w.run.next().start.length, 0); assert.equal(w.run.summary().stopped, true);
    for (const f of [() => w.submit('T-001'), () => w.go(EX, { op: 'plan', nodes: [N('T-026')] }), () => w.go(OW, { op: 'annul', node: 'T-001', reason: 'x' }), () => w.go(RP, { op: 'expire', node: 'T-001' })]) refused(f, 'RS-STOPPED');
    w.go(OW, { op: 'resume', reason: '点検済み' });
    w.submit('T-001'); w.verdict('T-001', R1, 'passed', AP2);
    assert.equal(w.st('T-001'), 'merged');
  } finally { w.cleanup(); }
});

test('良性: 途中で落ちた想定 — 記録を開き直して同じ状態が作り直せ、続きができる', () => {
  const w = mkRun();
  try {
    planAB(w); w.start('T-001'); w.submit('T-001'); w.verdict('T-001', R1, 'failed', AP2);
    const before = JSON.stringify(w.run.state());
    const again = w.reopen(); // 落ちて別のプロセスが開いた
    assert.equal(JSON.stringify(again.state()), before);
    assert.deepEqual(again.verify(), { ok: true, count: 8, events: 8, rules: RULES });
    again.apply(EX, { event_id: 'after-crash', op: 'submit', node: 'T-001', request: R2 });
    again.apply(CT, { event_id: 'after-crash-2', op: 'verdict', node: 'T-001', request: R2, audits: 'passed', verdicts: AP2 });
    assert.equal(again.state().nodes['T-001'].status, 'merged');
    assert.equal(w.run.state().nodes['T-001'].status, 'merged'); // 最初の窓口も、他のプロセスが書いた行を再生に取り込む
  } finally { w.cleanup(); }
});

test('良性（INV-12）: b が未承認のままでも、a は最後まで進む。b に依存する c だけが待つ', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001'), N('T-002'), N('T-003', ['T-002'])] }); w.approve('T-001');
    assert.deepEqual(w.run.next().start, ['T-001']);
    w.start('T-001'); w.submit('T-001'); w.verdict('T-001', R1, 'passed', AP2);
    assert.equal(w.st('T-001'), 'merged');
    const nx = w.run.next();
    assert.deepEqual(nx.start, []);
    assert.deepEqual(nx.waiting.find((x) => x.id === 'T-003').reasons.sort(), ['unapproved', 'waiting_dependency:T-002']);
    assert.deepEqual(w.run.summary().awaiting_approval, ['T-002', 'T-003']);
  } finally { w.cleanup(); }
});

test('良性: 期限切れの回収は、記録の時刻で判定する（attempts は戻さない）', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001')] }); w.approve('T-001'); w.start('T-001', 100);
    refused(() => w.go(RP, { op: 'expire', node: 'T-001' }), 'RS-EXPIRE-DUE');
    for (const claimed of ['2999-01-01T00:00:00+09:00', 99999999999999, true]) refused(() => w.go(RP, { op: 'expire', node: 'T-001', now: claimed }), 'RS-EVENT-SHAPE');
    refused(() => w.go(RP, { op: 'expire', node: 'T-001', at: '2999-01-01T00:00:00+09:00' }), 'RS-EVENT-SHAPE');
    w.clock.t += 100e3;
    w.go(RP, { op: 'expire', node: 'T-001' });
    assert.equal(w.st('T-001'), 'ready'); assert.equal(w.run.state().nodes['T-001'].attempts, 1);
    w.start('T-001'); assert.equal(w.run.state().nodes['T-001'].attempts, 2);
  } finally { w.cleanup(); }
});

test('良性: 着手の回数が尽きた期限切れは blocked（行き止まりにせず、オーナーが理由つきで解く）', () => {
  const w = mkRun({ max_attempts: 1 });
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001')] }); w.approve('T-001'); w.start('T-001', 10); w.clock.t += 10e3;
    w.go(RP, { op: 'expire', node: 'T-001' });
    assert.equal(w.st('T-001'), 'blocked'); assert.deepEqual(w.run.summary().blocked_reasons, { attempts_exhausted: 1 });
    refused(() => w.go(OW, { op: 'unblock', node: 'T-001', reason: '再開' }), 'RS-UNBLOCK-PROGRESS');
    w.go(OW, { op: 'unblock', node: 'T-001', reason: '再開する', extra_attempts: 1 });
    assert.equal(w.st('T-001'), 'ready'); w.start('T-001'); assert.equal(w.st('T-001'), 'in_progress');
  } finally { w.cleanup(); }
});

test('差し戻しの上限：3回の差し戻しの後の再申請は、司法を見ずに blocked。オーナーは回数を戻さず追加の回数を与える', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001')] }); w.approve('T-001'); w.start('T-001');
    for (let i = 0; i < 3; i += 1) { w.submit('T-001'); w.verdict('T-001', R1, 'failed', AP2); }
    assert.equal(w.run.state().nodes['T-001'].returns, 3); assert.equal(w.st('T-001'), 'in_progress');
    w.submit('T-001'); // 4 回目の申請。全員 APPROVED でも合格にしない
    const r = w.verdict('T-001', R1, 'passed', AP2);
    assert.equal(r.kind, 'blocked_returns'); assert.equal(w.st('T-001'), 'blocked');
    assert.deepEqual(w.run.summary().blocked_reasons, { returns_limit: 1 });
    refused(() => w.go(OW, { op: 'unblock', node: 'T-001', reason: '再開する' }), 'RS-UNBLOCK-PROGRESS');
    w.go(OW, { op: 'unblock', node: 'T-001', reason: '指摘が直った', extra_returns: 1, extra_attempts: 1 });
    assert.equal(w.run.state().nodes['T-001'].returns, 3, '回数は戻さない');
    w.start('T-001'); w.submit('T-001', R2); w.verdict('T-001', R2, 'passed', AP2);
    assert.equal(w.st('T-001'), 'merged');
  } finally { w.cleanup(); }
});

test('annul（オーナー）は差し戻しを数えない。差し戻しがなければ拒む', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001')] }); w.approve('T-001'); w.start('T-001');
    refused(() => w.go(OW, { op: 'annul', node: 'T-001', reason: 'x' }), 'RS-ANNUL-BOUND');
    w.submit('T-001'); w.verdict('T-001', R1, 'failed', AP2);
    w.go(OW, { op: 'annul', node: 'T-001', reason: '法律の不具合による差し戻し' });
    assert.equal(w.run.state().nodes['T-001'].returns, 0); assert.equal(w.run.state().nodes['T-001'].annulled, 1);
  } finally { w.cleanup(); }
});

// ---- verdict の結果の決め方（本物の decide を、実際の出来事で） ----
test('verdict: 監査が failed・not_run なら、司法が全員 APPROVED でも合格にしない', () => {
  for (const audits of ['failed', 'not_run']) {
    const w = mkRun();
    try {
      w.go(EX, { op: 'plan', nodes: [N('T-001')] }); w.approve('T-001'); w.start('T-001'); w.submit('T-001');
      const r = w.verdict('T-001', R1, audits, AP2);
      assert.equal(r.kind, 'return'); assert.equal(w.st('T-001'), 'in_progress');
    } finally { w.cleanup(); }
  }
});

test('verdict: 判定が足りない・同じ系統・UNAVAILABLE 混じりは合格にならない（司法の欠落。G15・G19）', () => {
  const unav = [AP2[0], J('codex', 'UNAVAILABLE')];
  for (const [name, vs] of [['1つ', [AP2[0]]], ['UNAVAILABLE 混じり', unav], ['空', []]]) {
    const w = mkRun();
    try {
      w.go(EX, { op: 'plan', nodes: [N('T-001')] }); w.approve('T-001'); w.start('T-001'); w.submit('T-001');
      const r = w.verdict('T-001', R1, 'passed', vs);
      assert.equal(r.kind, 'unavailable', name); assert.equal(w.st('T-001'), 'review', name); assert.equal(w.run.state().nodes['T-001'].returns, 0, name);
    } finally { w.cleanup(); }
  }
});

test('verdict: 重大でない分かれた判定は合格にならず差し戻し。重大なら blocked', () => {
  const minor = [AP2[0], J('codex', 'CHANGES_REQUIRED')];
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001')] }); w.approve('T-001'); w.start('T-001'); w.submit('T-001');
    const r = w.verdict('T-001', R1, 'passed', minor);
    assert.equal(r.kind, 'pass_minor_disagreement'); assert.equal(w.st('T-001'), 'merged'); // 法律（§3.1 の 8）：指摘を残して統合
  } finally { w.cleanup(); }
  const w2 = mkRun();
  try {
    w2.go(EX, { op: 'plan', nodes: [N('T-001')] }); w2.approve('T-001'); w2.start('T-001'); w2.submit('T-001');
    assert.equal(w2.verdict('T-001', R1, 'passed', SPLIT_MAJOR).kind, 'blocked_disagreement');
  } finally { w.cleanup(); }
});

test('verdict: 前の申請の指紋・ない申請への結果は拒む（使い回し）', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001')] }); w.approve('T-001'); w.start('T-001'); w.submit('T-001', R1);
    refused(() => w.verdict('T-001', R2, 'passed', AP2), 'RS-REQUEST-MATCH');
    assert.equal(w.st('T-001'), 'review');
    refused(() => w.verdict('T-001', 'sha256:' + 'c'.repeat(64), 'passed', AP2), 'RS-REQUEST-MATCH');
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
    w.go(EX, { op: 'plan', nodes: [N('T-001')] });
    const ev = [
      { op: 'approve', node: 'T-001', spec_digest: S1, policy_line: 'p0.4', def_digest: w.run.state().nodes['T-001'].def_digest },
      { op: 'verdict', node: 'T-001', request: R1, audits: 'passed', verdicts: AP2 }, { op: 'release', node: 'T-001', request: R1 },
      { op: 'rule', node: 'T-001', request: R1, decision: 'merge', reason: 'x' }, { op: 'unblock', node: 'T-001', reason: 'x' }, { op: 'annul', node: 'T-001', reason: 'x' },
      { op: 'stop', reason: 'x' }, { op: 'resume', reason: 'x' }, { op: 'epoch', covers: { count: 0, last_hash: 'genesis' }, reason: 'x' },
    ];
    // 行政の長は役割（RS-ROLE-OP）で、owner・gate_runner を名乗る ai は役割と種類の不一致（RS-ACTOR-SHAPE）で止まる
    for (const role of ['executive_head', 'owner', 'gate_runner']) for (const e of ev) {
      const x = refused(() => w.run.apply({ role, kind: 'ai', id: 'max', lineage: 'claude' }, { event_id: `ai-${role}-${e.op}`, ...e }), role === 'executive_head' ? 'RS-ROLE-OP' : 'RS-ACTOR-SHAPE');
      assert.ok(x.violations.length > 0);
    }
    assert.equal(w.run.state().count, 2); assert.equal(w.run.state().nodes['T-001'].approved, false);
  } finally { w.cleanup(); }
});

// rs.v2：vocab は役割・id を小文字にそろえて受ける（Owner・X は owner・x）。大文字の代わりに、NFKC で畳まれない似た文字（キリル文字の о）と、id の中の空白で示す
test('行為者の表記ゆれ: キリル文字の似た文字・ゼロ幅・Human・知らない役割・型のゆれ・id の空白は拒む。前後の空白・全角・大文字は正規化して受ける', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001')] });
    const d = w.run.state().nodes['T-001'].def_digest;
    const ap = (actor, id) => w.run.apply(actor, { event_id: id, op: 'approve', node: 'T-001', spec_digest: S1, policy_line: 'p0.4', def_digest: d });
    for (const actor of [{ role: 'оwner', kind: 'human', id: 'x' }, { role: 'own​er', kind: 'human', id: 'x' }, { role: 'owner', kind: 'Human', id: 'x' }, { role: 'admin', kind: 'human', id: 'x' },
      { role: ['owner'], kind: 'human', id: 'x' }, { role: 'owner', kind: 'human', id: 'x', extra: 1 }, 'owner', null, [], { role: 'owner', kind: 'human' }, { role: 'owner', kind: 'human', id: 'x y' }, { role: 'owner', kind: 'human', id: 'x', lineage: 'claude' }]) {
      refused(() => ap(actor, `bad-${Math.random().toString(36).slice(2)}`));
    }
    assert.equal(w.run.state().nodes['T-001'].approved, false);
    ap({ role: ' ｏｗｎｅｒ ', kind: 'human', id: 'azuki' }, 'good-1');
    assert.equal(w.run.state().nodes['T-001'].approved, true);
    assert.deepEqual(parseActor({ role: ' ｏｗｎｅｒ ', kind: 'human', id: 'azuki' }).actor, { role: 'owner', kind: 'human', id: 'azuki', lineage: 'human' });
    assert.deepEqual(parseActor({ role: 'Owner', kind: 'human', id: 'AZUKI' }).actor, { role: 'owner', kind: 'human', id: 'azuki', lineage: 'human' }); // 大文字は小文字にそろえる
    assert.deepEqual(parseActor(EX).actor, { role: 'executive_head', kind: 'ai', id: 'max', lineage: 'claude' });
    assert.equal(parseActor({ role: 'executive_head', kind: 'ai', id: 'max' }).ok, false, 'ai の lineage は必須');
  } finally { w.cleanup(); }
});

test('未承認の節・依存が未統合の節は start できない。承認の後に仕様が変われば（指紋が違えば）効かない', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001'), N('T-002', ['T-001'])] });
    refused(() => w.start('T-001'), 'RS-APPROVED');
    w.approve('T-001'); w.approve('T-002');
    refused(() => w.start('T-002'), 'RS-DEPS-MERGED');
    refused(() => w.go(EX, { op: 'start', node: 'T-001', spec_digest: `sha256:${'b'.repeat(64)}`, lease_sec: 60 }), 'RS-SPEC-DIGEST');
    w.start('T-001'); assert.equal(w.st('T-001'), 'in_progress');
    refused(() => w.start('T-001'), 'RS-TRANSITION'); // 二重の着手
  } finally { w.cleanup(); }
});

test('承認は法律の系統に結び付く（policyLine が違う承認では start できない）', () => {
  const w = mkRun({ policy_line: 'p0.5' });
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001')] }); w.approve('T-001');
    refused(() => w.start('T-001'), 'RS-POLICY-LINE');
    assert.deepEqual(w.run.next().waiting.find((x) => x.id === 'T-001').reasons, ['policy_line_mismatch']);
  } finally { w.cleanup(); }
});

test('範囲の重なる節の同時の start・同時の数の超過は拒む', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-024', [], ['src/shared/**']), N('T-025', [], ['src/shared/util.js']), N('T-026'), N('T-017')] });
    for (const id of ['T-024', 'T-025', 'T-026', 'T-017']) w.approve(id);
    w.start('T-024');
    refused(() => w.start('T-025'), 'RS-RESOURCE-DISJOINT');
    assert.ok(w.run.next().waiting.some((x) => x.id === 'T-025'));
    w.start('T-026');
    refused(() => w.start('T-017'), 'RS-WORKER-LIMIT');
  } finally { w.cleanup(); }
});

test('plan: 壊れたグラフ（循環・欠けた依存・重複）は拒む。既存の節の書き換えは拒む（追加だけ）', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001')] });
    refused(() => w.go(EX, { op: 'plan', nodes: [N('T-024', ['T-025']), N('T-025', ['T-024'])] }), 'RS-PLAN-GRAPH');
    refused(() => w.go(EX, { op: 'plan', nodes: [N('T-024', ['T-999'])] }), 'RS-PLAN-GRAPH');
    refused(() => w.go(EX, { op: 'plan', nodes: [N('T-024'), N('T-024')] }), 'RS-PLAN-GRAPH');
    refused(() => w.go(EX, { op: 'plan', nodes: [N('T-001', [], ['src/**'])] }), 'RS-PLAN-APPEND-ONLY');
    refused(() => w.go(EX, { op: 'plan', nodes: [{ ...N('T-024'), approved: true }] }), 'RS-EVENT-SHAPE');
    assert.equal(w.run.state().count, 2);
    w.go(OW, { op: 'plan', nodes: [N('T-024', ['T-001'])] }); // 人も plan できる
    assert.equal(w.run.state().nodes['T-024'].approved, false); // 登録された節は未承認で始まる
  } finally { w.cleanup(); }
});

test('置き換え（supersede）：置き換えられた節は blocked で動かず、承認は引き継がない。依存は置き換え先に付け替わる', () => {
  const w = mkRun();
  try {
    planAB(w);
    w.go(EX, { op: 'plan', nodes: [N('T-012')], supersede: [{ old: 'T-001', new: 'T-012' }] });
    assert.equal(w.st('T-001'), 'blocked'); assert.equal(w.run.state().nodes['T-001'].superseded_by, 'T-012'); assert.equal(w.run.state().nodes['T-012'].approved, false);
    refused(() => w.start('T-001'), 'RS-FROZEN'); refused(() => w.start('T-012'), 'RS-APPROVED'); refused(() => w.go(OW, { op: 'unblock', node: 'T-001', reason: '戻す' }), 'RS-FROZEN');
    assert.deepEqual(w.run.summary().blocked_reasons, { superseded: 1 });
    // c は a2 に依存する（a2 が統合されるまで着手できない）
    assert.ok(w.run.next().waiting.find((x) => x.id === 'T-003').reasons.includes('waiting_dependency:T-012'));
    // 置き換えで循環を作る（a2 に依存する c を、c に依存する節で置き換え）は拒む
    refused(() => w.go(EX, { op: 'plan', nodes: [N('T-013', ['T-003'])], supersede: [{ old: 'T-012', new: 'T-013' }] }), 'RS-PLAN-GRAPH');
  } finally { w.cleanup(); }
});

test('一度 merged になった節は動かない（再着手・approve・annul・unblock・release）', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001')] }); w.approve('T-001'); w.start('T-001'); w.submit('T-001'); w.verdict('T-001', R1, 'passed', AP2);
    for (const f of [() => w.start('T-001'), () => w.approve('T-001', `sha256:${'b'.repeat(64)}`), () => w.go(OW, { op: 'annul', node: 'T-001', reason: 'x' }), () => w.go(OW, { op: 'unblock', node: 'T-001', reason: 'x' }),
      () => w.go(OW, { op: 'release', node: 'T-001', request: R1 }), () => w.go(RP, { op: 'expire', node: 'T-001' })]) refused(f, 'RS-FROZEN');
  } finally { w.cleanup(); }
});

test('merged になる経路は verdict の合格（hold でないとき）・release・rule の3つだけ', () => {
  // 3つ以外の op の結果として merged を作る ctx を、全ガードに通すと拒まれる
  const m = memoryRun();
  m.apply(EX, { event_id: 'p', op: 'plan', nodes: [N('T-001')] });
  const d = m.state().nodes['T-001'].def_digest;
  m.apply(OW, { event_id: 'q', op: 'approve', node: 'T-001', spec_digest: S1, policy_line: 'p0.4', def_digest: d });
  for (const ev of [{ event_id: 'x1', op: 'start', node: 'T-001', spec_digest: S1, lease_sec: 60 }, { event_id: 'x2', op: 'submit', node: 'T-001', request: R1 }]) {
    const c = check(makeCtx(m.st, EX, ev, { at: m.now(), result: { op: ev.op, node: 'T-001', to: 'merged', patch: {} } }));
    assert.equal(c.ok, false); assert.ok(c.violations.some((v) => v.guard === 'RS-MERGE-PATH'));
  }
  const hold = memoryRun({ hold: true });
  hold.apply(EX, { event_id: 'p', op: 'plan', nodes: [N('T-001')] });
});

test('event_id の冪等：同じ内容の二度目は効かない。違う内容での再利用は拒む', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001')] });
    const ev = { event_id: 'same-1', op: 'approve', node: 'T-001', spec_digest: S1, policy_line: 'p0.4', def_digest: w.run.state().nodes['T-001'].def_digest };
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
    w.go(EX, { op: 'plan', nodes: [N('T-001')] });
    const d = w.run.state().nodes['T-001'].def_digest;
    let calls = 0;
    const sneaky = { event_id: 'tj-1', op: 'approve', node: 'T-001', spec_digest: S1, policy_line: 'p0.4', def_digest: d, toJSON() { calls += 1; return { event_id: 'tj-1', op: 'approve', node: 'T-001', spec_digest: S1, policy_line: 'p0.4', def_digest: calls === 1 ? d : `sha256:${'f'.repeat(64)}` }; } };
    w.run.apply(OW, sneaky);
    assert.equal(calls, 1); assert.equal(w.run.state().nodes['T-001'].approved, true);
    assert.ok(w.reopen().verify().ok); // 記録したものも検査したものと同じ
    const cyc = { event_id: 'cy', op: 'stop' }; cyc.self = cyc;
    refused(() => w.run.apply(OW, cyc));
  } finally { w.cleanup(); }
});

// rs.v2：節の id は票の ID の宣言（T- と 3〜4 桁）に合うものだけなので、__proto__・constructor などの名前は節の id として受けない（RS-WORK-ITEM-ID）。
// プロトタイプを汚さないこと（__proto__ の項目を知らない項目として拒む・ない節は RS-NODE-EXISTS）は、そのまま確かめる
test('__proto__・constructor などの名前：節の id として受けない（票の ID の宣言に合わない）・プロトタイプを汚さない', () => {
  const w = mkRun();
  try {
    refused(() => w.go(EX, { op: 'plan', nodes: [N('constructor'), N('tostring', ['constructor'])] }), 'RS-WORK-ITEM-ID');
    refused(() => w.go(EX, { op: 'plan', nodes: [N('__proto__')] }), 'RS-WORK-ITEM-ID');
    w.go(EX, { op: 'plan', nodes: [N('T-001'), N('T-002', ['T-001'])] });
    assert.deepEqual(Object.keys(w.run.state().nodes), ['T-001', 'T-002']);
    assert.equal(Object.getPrototypeOf(w.run.state().nodes), Object.prototype);
    refused(() => w.run.apply(EX, JSON.parse('{"event_id":"pp","op":"plan","nodes":[],"__proto__":{"x":1}}')), 'RS-EVENT-SHAPE');
    refused(() => w.go(OW, { op: 'approve', node: 'toString', spec_digest: S1, policy_line: 'p0.4', def_digest: S1 }), 'RS-NODE-EXISTS');
    refused(() => w.go(OW, cfgEv({ work_item: { prefix: '__proto__', digits: [3, 4] }, reason: '宣言を替える' })), 'RS-EVENT-SHAPE');
    assert.equal({}.x, undefined);
  } finally { w.cleanup(); }
});

// ---- 記録の再生と偽の行 ----
test('記録に直接書いた偽の行は、再生で全ガードに通らず、全操作を拒む', () => {
  const forged = [
    ['行政が verdict で合格にする', { op: 'verdict', node: 'T-001', request: R1, audits: 'passed', verdicts: AP2 }, EX],
    ['未承認の節の着手', { op: 'start', node: 'T-002', spec_digest: S1, lease_sec: 60 }, EX],
    ['別の役割の release', { op: 'release', node: 'T-001', request: R1 }, EX],
    ['行為者の綴りが正規化した形と違う', { op: 'stop', reason: '止める' }, { role: ' owner', kind: 'human', id: 'azuki' }],
    ['知らない項目を足した行', { op: 'stop', reason: '止める', approved: true }, OW],
    ['cfg を持つ行（設定は記録の config の出来事だけ。行に持たせない）', { op: 'stop', reason: '止める', cfg: { hold: false } }, OW],
  ];
  for (const [name, row, actor] of forged) {
    const w = mkRun();
    try {
      w.go(EX, { op: 'plan', nodes: [N('T-001'), N('T-002')] }); w.approve('T-001'); w.start('T-001'); w.submit('T-001');
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
    w.go(EX, { op: 'plan', nodes: [N('T-001')] }); w.approve('T-001'); w.start('T-001'); w.submit('T-001');
    openChain(w.file).append({ type: RECORD_TYPE, rules: RULES, op: 'verdict', event_id: 'direct-1', actor: CTN, node: 'T-001', request: R1, audits: 'not_run', verdicts: AP2 });
    assert.equal(w.run.verify().ok, true);
    assert.equal(w.run.state().nodes['T-001'].status, 'in_progress'); // 差し戻し。merged にはならない
    openChain(w.file).append({ type: RECORD_TYPE, rules: RULES, op: 'verdict', event_id: 'direct-2', actor: CTN, node: 'T-001', request: R1, audits: 'passed', verdicts: AP2, status: 'merged' });
    assert.equal(w.run.verify().code, 'bad_record'); // 結果を書き込んだ行（知らない項目）は拒む
  } finally { w.cleanup(); }
});

test('記録に直接書いた行：event_id の重複・時刻が読めない・知らない行は再生で拒む', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001')] });
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
    planAB(w); w.start('T-001');
    const recs = openChain(w.file).read();
    assert.ok(recs.every((r) => r.rules === RULES));
    assert.throws(() => replay(recs, { rules: 'rs.v3' }), (e) => e.code === 'bad_record'); // 版が違う・移行の記録がない
    const ch = openChain(w.file);
    const mk = (actor, covers) => ch.append({ type: RECORD_TYPE, rules: 'rs.v3', op: 'epoch', event_id: `ep-${Math.random().toString(36).slice(2)}`, actor, covers, reason: '移行する' });
    // 行政の移行の記録・ハッシュの合わない移行の記録は覆わない
    mk(EX, { count: recs.length, last_hash: recs[recs.length - 1].hash });
    assert.throws(() => replay(ch.read(), { rules: 'rs.v3' }), (e) => e.code === 'bad_record');
  } finally { w.cleanup(); }
  const w2 = mkRun();
  try {
    planAB(w2); w2.start('T-001');
    const ch = openChain(w2.file);
    const recs = ch.read();
    ch.append({ type: RECORD_TYPE, rules: 'rs.v3', op: 'epoch', event_id: 'ep-ok', actor: OWN, covers: { count: recs.length, last_hash: recs[recs.length - 1].hash }, reason: '規則を上げる' });
    const st = replay(ch.read(), { rules: 'rs.v3' });
    assert.equal(st.nodes.get('T-001').status, 'in_progress'); assert.equal(st.epochs, 1); assert.equal(st.covered, recs.length);
    // 覆われなかった後ろの古い版の行は拒む
    ch.append({ type: RECORD_TYPE, rules: RULES, op: 'stop', event_id: 'late-old', actor: OW, reason: 'x' });
    assert.throws(() => replay(ch.read(), { rules: 'rs.v3' }), (e) => e.code === 'bad_record');
  } finally { w2.cleanup(); }
});

test('epoch の apply：オーナーだけ・理由必須・ハッシュは実際の行に結び付く', () => {
  const w = mkRun();
  try {
    planAB(w);
    const recs = openChain(w.file).read();
    const good = { op: 'epoch', covers: { count: recs.length, last_hash: recs[recs.length - 1].hash }, reason: '規則の移行' };
    refused(() => w.go(EX, good), 'RS-ROLE-OP');
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
    planAB(w); w.start('T-001'); w.submit('T-001'); w.verdict('T-001', R1, 'passed', SPLIT_MAJOR);
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
    assert.deepEqual(nx.start, ['T-001', 'T-002']); assert.ok(nx.recommend && nx.recommend.workers <= 2);
    assert.deepEqual(nx.waiting.map((x) => x.id), ['T-003']);
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
    w.go(EX, { op: 'plan', nodes: [N('T-001')] });
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
  assert.equal(parseEvent({ op: 'plan', event_id: 'e', nodes: Array.from({ length: 2001 }, (_, i) => N(T(i))) }).ok, false);
  assert.equal(parseEvent({ op: 'plan', event_id: 'e', nodes: [N('T-001', Array.from({ length: 201 }, (_, i) => T(5000 + i)))] }).ok, false);
  assert.equal(parseEvent({ op: 'plan', event_id: 'e', nodes: [{ id: 'T-001', depends_on: new Set(['T-002']), resources: [] }] }).ok, false);
  assert.equal(parseEvent({ op: 'plan', event_id: 'e', nodes: [{ id: 'T-001', depends_on: [], resources: 'src/**' }] }).ok, false);
  assert.equal(parseEvent({ op: 'plan', event_id: 'e', nodes: [{ id: 'T-001', depends_on: ['T-002', 'T-002'], resources: [] }] }).ok, false);
  assert.equal(parseEvent({ op: 'start', event_id: 'e', node: 'T-001', spec_digest: S1, lease_sec: 604801 }).ok, false);
  assert.equal(parseEvent({ op: 'start', event_id: 'e', node: 'T-001', spec_digest: S1, lease_sec: 1.5 }).ok, false);
  assert.equal(parseEvent({ op: 'start', event_id: 'e', node: 'T-001', spec_digest: S1, lease_sec: '60' }).ok, false);
  let deep = {}; for (let i = 0; i < 100000; i += 1) deep = { x: deep };
  assert.equal(parseEvent({ op: 'stop', event_id: 'e', reason: 'x', deep }).ok, false);
  assert.equal(parseEvent({ op: 'plan', event_id: 'e', nodes: [N('T-001')] }).ok, true);
  assert.equal(parseEvent({ op: 'approve', event_id: ' e1 ', node: ' Ｔ－００１ ', spec_digest: S1, policy_line: 'p0.4', def_digest: S1 }).ok, false); // rs.v2：節の id は書いたとおり（全角・前後の空白を畳まずに拒む）
  assert.equal(parseEvent({ op: 'approve', event_id: ' e1 ', node: 'T-001', spec_digest: S1, policy_line: 'p0.4', def_digest: S1 }).ev.event_id, 'e1'); // event_id は前後の空白を落とす
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
    refused(() => w.go(EX, { op: 'plan', nodes: [N('T-001')] }), 'RS-CONFIG-REQUIRED');
    refused(() => w.go(OW, { op: 'stop', reason: '止める' }), 'RS-CONFIG-REQUIRED');
    refused(() => w.go(EX, cfgEv()), 'RS-ROLE-OP'); // 行政は config を起こせない
    refused(() => w.go({ role: 'owner', kind: 'ai', id: 'max', lineage: 'claude' }, cfgEv()), 'RS-ACTOR-SHAPE');
    assert.equal(w.run.next().error.length, 1);
    w.go(OW, cfgEv());
    assert.equal(w.run.summary().configured, true);
    w.go(EX, { op: 'plan', nodes: [N('T-001')] });
  } finally { w.cleanup(); }
});

test('F1: 同じ記録を開き直しても、設定は変えられない（hold・同時の数・試行・法律の系統は記録のもの）', () => {
  const w = mkRun({ hold: true, concurrent_work: 1, max_attempts: 1, policy_line: 'p0.5' });
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001'), N('T-002'), N('T-008')] });
    w.approve('T-001'); w.approve('T-002');
    w.go(OW, { op: 'approve', node: 'T-008', spec_digest: S1, policy_line: 'p0.5', def_digest: w.run.state().nodes['T-008'].def_digest });
    const other = w.reopen(); // 別の窓口（開く側は何も指定できない）
    refused(() => other.apply(EX, { event_id: 'x1', op: 'start', node: 'T-001', spec_digest: S1, lease_sec: 60 }), 'RS-POLICY-LINE'); // 承認は p0.4、系統は p0.5
    other.apply(EX, { event_id: 'x2', op: 'start', node: 'T-008', spec_digest: S1, lease_sec: 60 }); // p0.5 の承認は通る
    assert.equal(other.state().nodes['T-008'].status, 'in_progress');
  } finally { w.cleanup(); }
  const w2 = mkRun({ hold: true, concurrent_work: 1, max_attempts: 1 });
  try {
    w2.go(EX, { op: 'plan', nodes: [N('T-001'), N('T-002')] }); w2.approve('T-001'); w2.approve('T-002'); w2.start('T-001', 60);
    refused(() => w2.reopen().apply(EX, { event_id: 'y1', op: 'start', node: 'T-002', spec_digest: S1, lease_sec: 60 }), 'RS-WORKER-LIMIT'); // 同時 1（開き直して広げられない）
    w2.submit('T-001');
    assert.equal(w2.reopen().apply(CT, { event_id: 'y2', op: 'verdict', node: 'T-001', request: R1, audits: 'passed', verdicts: AP2 }).to, 'held'); // hold は記録のもの
    w2.clock.t += 120e3;
  } finally { w2.cleanup(); }
  const w3 = mkRun({ max_attempts: 1 });
  try {
    w3.go(EX, { op: 'plan', nodes: [N('T-001')] }); w3.approve('T-001'); w3.start('T-001', 60); w3.clock.t += 120e3;
    w3.reopen().apply(RP, { event_id: 'z1', op: 'expire', node: 'T-001' });
    assert.equal(w3.st('T-001'), 'blocked'); // 試行の上限 1 は記録のもの
  } finally { w3.cleanup(); }
});

test('F1: config の変更は理由つき。緩める変更は作業中（in_progress・review・held）の節がないときだけ。締める変更はいつでも', () => {
  const w = mkRun({ hold: true });
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001')] }); w.approve('T-001');
    refused(() => w.go(OW, cfgEv({ concurrent_work: 1 })), 'RS-REASON');
    w.go(OW, cfgEv({ concurrent_work: 4, reason: '作業中の節がないので緩められる', hold: true }));
    w.start('T-001'); w.submit('T-001');
    refused(() => w.go(OW, cfgEv({ concurrent_work: 8, hold: true, reason: '広げる' })), 'RS-CONFIG-TIGHTEN');
    w.go(OW, cfgEv({ concurrent_work: 2, hold: true, reason: '締める' })); // 締める変更は作業中でも通る
    w.verdict('T-001', R1, 'passed', AP2);
    assert.equal(w.st('T-001'), 'held');
    refused(() => w.go(OW, cfgEv({ hold: false, reason: 'hold を外す' })), 'RS-CONFIG-TIGHTEN'); // held がある間は外せない
    refused(() => w.go(OW, cfgEv({ hold: true, judiciary: [{ kind: 'judge', lineage: 'claude' }], reason: '審査を減らす' })), 'RS-CONFIG-TIGHTEN');
    w.go(OW, { op: 'release', node: 'T-001', request: R1 });
    w.go(OW, cfgEv({ hold: false, reason: '作業中の節がなくなった' }));
    assert.equal(w.run.state().config.hold, false);
  } finally { w.cleanup(); }
});

test('F1/N1: 時刻が前の行より戻っても拒まず、記録の上の今（最大値）をそのまま使う。期限は戻した時計では切れない', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001')] }); w.approve('T-001'); w.start('T-001', 600);
    const t = w.clock.t;
    w.clock.t = t - 3600e3; // 時計が戻る
    refused(() => w.go(RP, { op: 'expire', node: 'T-001' }), 'RS-EXPIRE-DUE'); // 最大値で判定するので、期限はまだ
    const rows = readRows(w.file);
    assert.ok(rows.at(-1).at ? true : true);
    const ats = rows.map((r) => Date.parse(r.at));
    assert.ok(ats.every((x, i) => i === 0 || x >= ats[i - 1]), '行の at は単調');
    w.clock.t = t + 600e3;
    w.go(RP, { op: 'expire', node: 'T-001' });
    assert.equal(w.st('T-001'), 'ready');
  } finally { w.cleanup(); }
});

test('N1: 追記する側の実時間より 5 分以上先の時刻の行は書く時に拒む（未来の時計で lease を奪えない）', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001')] }); w.approve('T-001'); w.start('T-001', 600);
    w.clock.t = Date.parse('2099-01-01T00:00:00+09:00');
    refused(() => w.go(RP, { op: 'expire', node: 'T-001' }), 'RS-TIME-FUTURE');
    refused(() => w.go(EX, { op: 'plan', nodes: [N('T-002')] }), 'RS-TIME-FUTURE');
    w.go(OW, { op: 'stop', reason: '停止は未来の時刻でも通る' }); // INV-04
    assert.equal(w.run.state().stopped, true);
    assert.ok(Date.parse(readRows(w.file).at(-1).at) > Date.now() + 3600e3 * 24, '停止の行は書いた時刻の at');
  } finally { w.cleanup(); }
});

test('N1: 記録の上の今が実時間より先に進んだ記録（直接書かれた未来の行）は、stop が通り、オーナーが clock_reset で正せる', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001')] }); w.approve('T-001');
    // 鎖としては正しい未来の時刻の行を直接足す（オーナーの権限や機械の時計の大きな進み）
    openChain(w.file, { now: () => '2099-01-01T00:00:00+09:00' }).append({ type: RECORD_TYPE, rules: RULES, op: 'plan', event_id: 'future-row', actor: EX, nodes: [N('T-061')] });
    assert.ok(w.run.verify().ok, '再生は実時間を見ないので受ける');
    refused(() => w.go(EX, { op: 'plan', nodes: [N('T-002')] }), 'RS-TIME-FUTURE');
    refused(() => w.start('T-001'), 'RS-TIME-FUTURE');
    w.go(OW, { op: 'stop', reason: '緊急停止' }); // どんな時刻の状態でも通る
    refused(() => w.go(OW, { op: 'resume', reason: '再開する' }), 'RS-TIME-FUTURE'); // 先に時刻を正す
    refused(() => w.go(EX, { op: 'clock_reset', reason: 'x' }), 'RS-ROLE-OP');
    refused(() => w.go(OW, { op: 'clock_reset' }), 'RS-REASON');
    w.go(OW, { op: 'clock_reset', reason: '時計が進んでいたので実時間に戻す' });
    w.go(OW, { op: 'resume', reason: '再開する' });
    w.go(EX, { op: 'plan', nodes: [N('T-002')] });
    assert.ok(w.reopen().verify().ok);
    assert.ok(Date.parse(readRows(w.file).at(-1).at) < Date.parse('2030-01-01'));
  } finally { w.cleanup(); }
});

test('N1: 並行の書き込み（別の窓口が後の時刻で書いた後に、前の時刻の窓口が書く）でも、正当な追記は通る', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001')] });
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
  const w = mkRun({ concurrent_work: 1 });
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-024', [], ['src/shared/**']), N('T-025', [], ['src/shared/x.ts']), N('T-026')] });
    for (const id of ['T-024', 'T-025', 'T-026']) w.approve(id);
    w.start('T-024'); w.submit('T-024');
    refused(() => w.start('T-025'), 'RS-RESOURCE-DISJOINT');
    refused(() => w.start('T-026'), 'RS-WORKER-LIMIT'); // review も枠を使う（concurrent_work=1）
    assert.deepEqual(w.run.next().start, []);
    w.verdict('T-024', R1, 'failed', AP2); // 差し戻し：x だけが作業中で、重なる y は着手できていない
    assert.deepEqual(['T-024', 'T-025'].map(w.st), ['in_progress', 'ready']);
  } finally { w.cleanup(); }
  const h = mkRun({ concurrent_work: 1, hold: true });
  try {
    h.go(EX, { op: 'plan', nodes: [N('T-024', [], ['src/shared/**']), N('T-025', [], ['src/shared/x.ts']), N('T-026')] });
    for (const id of ['T-024', 'T-025', 'T-026']) h.approve(id);
    h.start('T-024'); h.submit('T-024'); h.verdict('T-024', R1, 'passed', AP2);
    assert.equal(h.st('T-024'), 'held');
    refused(() => h.start('T-025'), 'RS-RESOURCE-DISJOINT'); // held は範囲を占める
    assert.deepEqual(h.run.next().start, ['T-026']); // held は枠を使わない
    h.start('T-026'); assert.equal(h.st('T-026'), 'in_progress');
  } finally { h.cleanup(); }
});

test('F3: UNAVAILABLE が1つでもあれば「司法が使えない」。必須の審査の一覧は config に固定され、余分・知らない系統・表記ゆれは拒む', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001')] }); w.approve('T-001'); w.start('T-001'); w.submit('T-001');
    assert.equal(w.verdict('T-001', R1, 'passed', [...AP2.slice(0, 1), J('codex', 'UNAVAILABLE')]).kind, 'unavailable');
    assert.equal(w.verdict('T-001', R1, 'passed', [AP2[0]]).kind, 'unavailable'); // 欠落（codex の結果がない）
    // rs.v2：知らない系統（open_ai・gemini）は vocab の系統の一覧になく、形の検査で止まる（一覧にある系統の余分は RS-VERDICT-SET。下の security と次の試験）
    refused(() => w.verdict('T-001', R1, 'passed', [AP2[0], J('open_ai')]), 'RS-EVENT-SHAPE'); // 一覧にない系統
    refused(() => w.verdict('T-001', R1, 'passed', [...AP2, J('gemini')]), 'RS-EVENT-SHAPE');
    refused(() => w.verdict('T-001', R1, 'passed', [AP2[0], J('open-ai')]), 'RS-EVENT-SHAPE'); // lineage の表記ゆれ
    // rs.v2：vocab は系統の大文字（Codex）を小文字にそろえて受けるので、表記ゆれはゼロ幅文字入りで示す
    refused(() => w.verdict('T-001', R1, 'passed', [AP2[0], { ...J('codex'), lineage: 'co​dex' }]), 'RS-EVENT-SHAPE');
    // 審査者の名前は、正規化した行為者の id の形で書いたものだけ（大文字・空白は拒む）
    refused(() => w.verdict('T-001', R1, 'passed', [AP2[0], { ...J('codex'), judge: 'Judge_codex' }]), 'RS-EVENT-SHAPE');
    refused(() => w.verdict('T-001', R1, 'passed', [AP2[0], { ...J('codex'), judge: 'judge codex' }]), 'RS-EVENT-SHAPE');
    refused(() => w.verdict('T-001', R1, 'passed', [...AP2, { ...AP2[0], judge: 'other' }]), 'RS-EVENT-SHAPE'); // 同じ審査の結果が2件
    refused(() => w.verdict('T-001', R1, 'passed', [...AP2, J('codex', 'APPROVED', false, 'security')]), 'RS-VERDICT-SET'); // security の印がない節
    assert.equal(w.st('T-001'), 'review');
    assert.equal(w.verdict('T-001', R1, 'passed', AP2).kind, 'pass');
  } finally { w.cleanup(); }
});

// rs.v2：審査の系統は vocab の審査の種類に写せるもの（judge は claude・codex、security は codex）だけなので、3つ目の系統（gemini）は config に書けない。
// 「必須の審査の数は config で決まる」ことを、[claude] だけの config と [claude, codex] の config の違いで確かめる
test('F3: 必須の審査の一覧は config で決まる（[claude] だけ・[claude, codex]）。知らない系統は config に書けない。同じ系統2人は別の系統の代わりにならない', () => {
  const w = mkRun({ noConfig: true });
  try {
    refused(() => w.go(OW, cfgEv({ judiciary: [{ kind: 'judge', lineage: 'claude' }, { kind: 'judge', lineage: 'codex' }, { kind: 'judge', lineage: 'gemini' }] })), 'RS-EVENT-SHAPE');
    refused(() => w.go(OW, cfgEv({ security_lineage: 'claude' })), 'RS-EVENT-SHAPE'); // security は codex だけが審査の種類に写せる
    w.go(OW, cfgEv({ concurrent_work: 2 }));
    w.go(EX, { op: 'plan', nodes: [N('T-001')] }); w.approve('T-001'); w.start('T-001'); w.submit('T-001');
    refused(() => w.verdict('T-001', R1, 'passed', [J('claude'), { ...J('claude'), judge: 'judge_claude_2' }]), 'RS-EVENT-SHAPE'); // 同じ系統2人
    assert.equal(w.verdict('T-001', R1, 'passed', [J('claude')]).kind, 'unavailable'); // codex がない
    assert.equal(w.verdict('T-001', R1, 'passed', AP2).kind, 'pass');
  } finally { w.cleanup(); }
  const one = mkRun({ judiciary: [{ kind: 'judge', lineage: 'claude' }] });
  try {
    one.go(EX, { op: 'plan', nodes: [N('T-001')] }); one.approve('T-001'); one.start('T-001'); one.submit('T-001');
    refused(() => one.verdict('T-001', R1, 'passed', AP2), 'RS-VERDICT-SET'); // 一覧にない（codex の）審査の結果は余分
    assert.equal(one.verdict('T-001', R1, 'passed', [J('claude')]).kind, 'pass');
  } finally { one.cleanup(); }
});

test('F3: security_review の節は、security の結果も必須。不合格は不一致でなく差し戻し（裁定で通せない）', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [{ ...N('T-001'), security_review: true }, N('T-002')] }); w.approve('T-001'); w.approve('T-002');
    assert.notEqual(w.run.state().nodes['T-001'].def_digest, w.run.state().nodes['T-002'].def_digest);
    w.start('T-001'); w.submit('T-001');
    assert.equal(w.verdict('T-001', R1, 'passed', AP2).kind, 'unavailable'); // security の結果がない
    const sec = (v, major = false) => J('codex', v, major, 'security');
    const r = w.verdict('T-001', R1, 'passed', [...AP2, sec('CHANGES_REQUIRED', true)]);
    assert.equal(r.kind, 'return'); assert.equal(w.st('T-001'), 'in_progress');
    w.submit('T-001', R2);
    // 司法が分かれて security も不合格でも、security が先（差し戻し。blocked にならない）
    assert.equal(w.verdict('T-001', R2, 'passed', [J('claude'), J('codex', 'CHANGES_REQUIRED', true), sec('CHANGES_REQUIRED', true)]).kind, 'return');
    const R3 = 'c3'.repeat(20);
    w.submit('T-001', R3);
    assert.equal(w.verdict('T-001', R3, 'passed', [...AP2, sec('APPROVED')]).kind, 'pass');
  } finally { w.cleanup(); }
});

test('F3/Kernel: 1系統だけの運転（--no-codex 相当）は config で表せ、summary に「別の系統の確認がない」印が出る', () => {
  const w = mkRun({ judiciary: [{ kind: 'judge', lineage: 'claude' }] });
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001')] }); w.approve('T-001'); w.start('T-001'); w.submit('T-001');
    assert.equal(w.run.summary().single_lineage_judiciary, true);
    assert.equal(w.verdict('T-001', R1, 'passed', [J('claude')]).kind, 'pass');
    assert.equal(mkRun().run.summary().single_lineage_judiciary, false);
  } finally { w.cleanup(); }
});

test('Kernel/SPEC §6-5: 司法が使えない回数は同じ申請の指紋の通算。別の申請を挟んでも戻らない。unblock でも戻さず、追加の回数はオーナーが与える', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001')] }); w.approve('T-001'); w.start('T-001');
    const one = [AP2[0]];
    w.submit('T-001', R1); w.verdict('T-001', R1, 'passed', one); w.verdict('T-001', R1, 'passed', one);
    w.verdict('T-001', R1, 'failed', AP2);
    w.submit('T-001', R2); w.verdict('T-001', R2, 'passed', one); w.verdict('T-001', R2, 'failed', AP2);
    w.submit('T-001', R1); // 同じ申請の指紋に戻る
    assert.equal(w.verdict('T-001', R1, 'passed', one).kind, 'blocked_unavailable'); // R1 の通算3回目
    assert.deepEqual(w.run.state().nodes['T-001'].unavail, { [R1]: 3, [R2]: 1 });
    w.go(OW, { op: 'unblock', node: 'T-001', reason: '司法の環境を直した', extra_attempts: 1, extra_unavailable: 1 });
    assert.deepEqual(w.run.state().nodes['T-001'].unavail, { [R1]: 3, [R2]: 1 }, '戻さない');
    assert.equal(w.run.state().nodes['T-001'].extra_unavailable, 1);
  } finally { w.cleanup(); }
});

test('Kernel: 差し戻しで in_progress に戻るときも attempts を数える。上限に達していれば blocked', () => {
  const w = mkRun({ max_attempts: 2 });
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001')] }); w.approve('T-001'); w.start('T-001'); w.submit('T-001');
    assert.equal(w.verdict('T-001', R1, 'failed', AP2).kind, 'return');
    assert.equal(w.run.state().nodes['T-001'].attempts, 2);
    w.submit('T-001', R2);
    const r = w.verdict('T-001', R2, 'failed', AP2);
    assert.equal(r.kind, 'blocked_attempts'); assert.equal(w.st('T-001'), 'blocked');
    assert.deepEqual(w.run.summary().blocked_reasons, { attempts_exhausted: 1 });
  } finally { w.cleanup(); }
});

test('F4: 空の plan は拒む。行政の plan の回数・人以外の枠には上限があり、オーナーの stop・resume・epoch は塞がれない', () => {
  const m = memoryRun();
  const EXA = { role: 'executive_head', kind: 'ai', id: 'max', lineage: 'claude' };
  assert.throws(() => m.apply(EXA, { event_id: 'e0', op: 'plan', nodes: [] }), (e) => e.violations.some((v) => v.guard === 'RS-PLAN-NONEMPTY'));
  for (let i = 0; i < 500; i += 1) m.apply(EXA, { event_id: `p${i}`, op: 'plan', nodes: [N(T(i), [], [])] });
  assert.throws(() => m.apply(EXA, { event_id: 'p500', op: 'plan', nodes: [N(T(500), [], [])] }), (e) => e.violations.some((v) => v.guard === 'RS-EVENT-QUOTA'));
  m.apply(OW, { event_id: 'o-stop', op: 'stop', reason: '緊急停止' });
  m.apply(OW, { event_id: 'o-resume', op: 'resume', reason: '再開' });
  // 人以外の枠が尽きた状態
  m.st.count = MAX_EVENTS - HUMAN_RESERVE;
  assert.throws(() => m.apply(CT, { event_id: 'c1', op: 'expire', node: T(0) }), (e) => e.violations.some((v) => v.guard === 'RS-EVENT-QUOTA'));
  m.apply(OW, { event_id: 'o-stop2', op: 'stop', reason: '人の枠は残っている' });
  assert.equal(m.state().stopped, true);
});

test('F5: 置き換えの鎖は上限（8）まで。解決は一度だけ更新され、古い節への依存は最後の置き換え先に付く', () => {
  const m = memoryRun();
  m.apply(EX, { event_id: 'p0', op: 'plan', nodes: [N(T(200), [], []), N('T-004', [T(200)], [])] });
  for (let k = 0; k < 8; k += 1) m.apply(EX, { event_id: `p${k + 1}`, op: 'plan', nodes: [N(T(201 + k), [], [])], supersede: [{ old: T(200 + k), new: T(201 + k) }] });
  assert.throws(() => m.apply(EX, { event_id: 'p99', op: 'plan', nodes: [N(T(209), [], [])], supersede: [{ old: T(208), new: T(209) }] }), (e) => e.violations.some((v) => v.guard === 'RS-PLAN-SUPERSEDE'));
  assert.equal(m.st.final.get(T(200)), T(208)); assert.equal(m.st.final.get(T(207)), T(208));
  assert.ok(m.next().waiting.find((x) => x.id === 'T-004').reasons.includes(`waiting_dependency:${T(208)}`));
});

test('F5: 大量の依存（審査者の再現の形）でも、出来事1回が1秒以内。依存の総数・1節の依存の数には上限', () => {
  const m = memoryRun({ config: { concurrent_work: 4 } });
  const base = Array.from({ length: 64 }, (_, i) => N(T(1000 + i), [], []));
  m.apply(EX, { event_id: 'pb', op: 'plan', nodes: base });
  const deps = base.map((b) => b.id);
  const heavy = Array.from({ length: 300 }, (_, i) => ({ id: T(2000 + i), depends_on: deps, resources: [] }));
  let t0 = Date.now(); m.apply(EX, { event_id: 'ph', op: 'plan', nodes: heavy.slice(0, 200) }); m.apply(EX, { event_id: 'ph1', op: 'plan', nodes: heavy.slice(200) });
  assert.ok(Date.now() - t0 < 2000, `plan ${Date.now() - t0} ms`);
  assert.throws(() => m.apply(EX, { event_id: 'ph2', op: 'plan', nodes: Array.from({ length: 20 }, (_, i) => ({ id: T(3000 + i), depends_on: deps, resources: [] })) }), (e) => e.violations.some((v) => v.guard === 'RS-SIZE-LIMIT'));
  m.apply(EX, { event_id: 'px', op: 'plan', nodes: [N('T-024')] });
  m.apply(OW, { op: 'approve', event_id: 'ax', node: 'T-024', spec_digest: S1, policy_line: 'p0.4', def_digest: m.state().nodes['T-024'].def_digest });
  t0 = Date.now(); m.apply(EX, { event_id: 'sx', op: 'start', node: 'T-024', spec_digest: S1, lease_sec: 60 });
  assert.ok(Date.now() - t0 < 1000, `start ${Date.now() - t0} ms`);
  t0 = Date.now(); m.next(); assert.ok(Date.now() - t0 < 1000, `next ${Date.now() - t0} ms`);
});

test('F6: submit できるのは着手した行為者だけ', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001')] }); w.approve('T-001');
    w.go({ role: 'night_runner', kind: 'script', id: 'night' }, { op: 'start', node: 'T-001', spec_digest: S1, lease_sec: 600 });
    refused(() => w.submit('T-001'), 'RS-WORKER-BIND');
    w.go({ role: 'night_runner', kind: 'script', id: 'night' }, { op: 'submit', node: 'T-001', request: R1 });
    assert.equal(w.st('T-001'), 'review');
  } finally { w.cleanup(); }
});

test('F6: event_id の一意性は (役割, op) の組ごと。行政が予測した id でオーナーの stop を塞げない', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001')] });
    w.run.apply(EX, { event_id: 'stop-20260101', op: 'plan', nodes: [N('T-002')] });
    w.run.apply(OW, { event_id: 'stop-20260101', op: 'stop', reason: '止める' });
    assert.equal(w.run.state().stopped, true);
    refused(() => w.run.apply(OW, { event_id: 'stop-20260101', op: 'stop', reason: '二度目（内容が違う）' }), 'RS-STOP-STATE');
  } finally { w.cleanup(); }
});

test('F6: 行政は、オーナーの判断待ち（held・判定の不一致で blocked）の節を置き換えで消せない。オーナーはできる', () => {
  const w = mkRun({ hold: true });
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001'), N('T-002')] }); w.approve('T-001'); w.approve('T-002');
    w.start('T-001'); w.submit('T-001'); w.verdict('T-001', R1, 'passed', AP2);
    w.start('T-002'); w.submit('T-002', R2); w.verdict('T-002', R2, 'passed', SPLIT_MAJOR);
    assert.deepEqual(['T-001', 'T-002'].map(w.st), ['held', 'blocked']);
    refused(() => w.go(EX, { op: 'plan', nodes: [N('T-012')], supersede: [{ old: 'T-001', new: 'T-012' }] }), 'RS-PLAN-SUPERSEDE');
    refused(() => w.go(EX, { op: 'plan', nodes: [N('T-022')], supersede: [{ old: 'T-002', new: 'T-022' }] }), 'RS-PLAN-SUPERSEDE');
    w.go(OW, { op: 'plan', nodes: [N('T-012')], supersede: [{ old: 'T-001', new: 'T-012' }] });
    assert.equal(w.run.state().nodes['T-001'].superseded_by, 'T-012');
  } finally { w.cleanup(); }
});

// ---- F7: キャッシュと試験の空回り ----
test('F7: キャッシュ — 記録を書き換えて鎖を作り直した後に、古いキャッシュの状態が返らない（先頭の行のハッシュの照合）', () => {
  const w = mkRun();
  try {
    planAB(w);
    assert.equal(w.run.state().nodes['T-001'].approval.spec_digest, S1); // キャッシュを温める
    const rows = readRows(w.file);
    const k = rows.findIndex((r) => r.op === 'approve' && r.node === 'T-001');
    rows[k] = { ...rows[k], spec_digest: `sha256:${'b'.repeat(64)}` };
    rechain(w.file, rows); // 同じ行数・同じ内容の鎖で、途中の行だけが違う
    assert.equal(w.run.state().nodes['T-001'].approval.spec_digest, `sha256:${'b'.repeat(64)}`);
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
    ch.append({ type: RECORD_TYPE, rules: RULES, op: 'epoch', event_id: 'ep-p', actor: OWN, covers: { count: recs.length, last_hash: recs[recs.length - 1].hash }, reason: '移行' });
    assert.equal(replay(ch.read()).pure, false);
  } finally { w.cleanup(); }
});

test('F7: キャッシュ — 別のファイルのキャッシュは混ざらない。キャッシュがあっても規則に合わない行は拒む', () => {
  const a = mkRun(); const b = mkRun();
  try {
    a.go(EX, { op: 'plan', nodes: [N('T-001')] }); b.go(EX, { op: 'plan', nodes: [N('T-002')] });
    assert.deepEqual(a.run.state().order, ['T-001']); assert.deepEqual(b.run.state().order, ['T-002']);
    a.run.state(); // キャッシュを温める
    // 鎖としては正しいが、規則に合わない行（未承認の start）を直接足す
    openChain(a.file).append({ type: RECORD_TYPE, rules: RULES, op: 'start', event_id: 'forged-s', actor: EX, node: 'T-001', spec_digest: S1, lease_sec: 60 });
    assert.throws(() => a.run.state(), (e) => e.code === 'bad_record');
    refused(() => a.go(OW, { op: 'stop', reason: 'x' }));
    assert.deepEqual(b.run.state().order, ['T-002']);
  } finally { a.cleanup(); b.cleanup(); }
});

// ================= 再審査 C（N1〜N6） =================
test('N2: start の lease_sec は config.lease_sec を超えられない', () => {
  const w = mkRun({ lease_sec: 600 });
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001')] }); w.approve('T-001');
    refused(() => w.start('T-001', 604800), 'RS-LEASE-LIMIT');
    refused(() => w.start('T-001', 601), 'RS-LEASE-LIMIT');
    w.start('T-001', 600); assert.equal(w.st('T-001'), 'in_progress');
  } finally { w.cleanup(); }
});

test('N3: 未統合の申請を持つ blocked の節は範囲を占める。rule の return・unblock も範囲と同時の数を通す', () => {
  const w = mkRun({ concurrent_work: 2 });
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-024', [], ['src/shared/**']), N('T-025', [], ['src/shared/x.ts']), N('T-026')] });
    for (const id of ['T-024', 'T-025', 'T-026']) w.approve(id);
    w.start('T-024'); w.submit('T-024'); w.verdict('T-024', R1, 'passed', SPLIT_MAJOR);
    assert.equal(w.st('T-024'), 'blocked');
    refused(() => w.start('T-025'), 'RS-RESOURCE-DISJOINT');
    const nx = w.run.next();
    assert.deepEqual(nx.start, ['T-026']); assert.ok(nx.waiting.find((q) => q.id === 'T-024').reasons.includes('blocked'));
    w.go(OW, { op: 'rule', node: 'T-024', request: R1, decision: 'return', reason: 'やり直す' });
    assert.equal(w.st('T-024'), 'in_progress');
    refused(() => w.start('T-025'), 'RS-RESOURCE-DISJOINT');
  } finally { w.cleanup(); }
  const w2 = mkRun({ concurrent_work: 2 });
  try {
    w2.go(EX, { op: 'plan', nodes: [N('T-024'), N('T-025')] }); w2.approve('T-024'); w2.approve('T-025');
    w2.start('T-024'); w2.start('T-025'); w2.submit('T-024'); w2.verdict('T-024', R1, 'passed', SPLIT_MAJOR);
    w2.go(OW, { ...cfgEv({ concurrent_work: 1, reason: '枠を締める' }) });
    refused(() => w2.go(OW, { op: 'rule', node: 'T-024', request: R1, decision: 'return', reason: 'やり直す' }), 'RS-WORKER-LIMIT');
    w2.go(OW, { op: 'rule', node: 'T-024', request: R1, decision: 'merge', reason: '通す' }); // merge は枠を使わないので通る
    assert.equal(w2.st('T-024'), 'merged');
  } finally { w2.cleanup(); }
});

test('N4: 行政が足せる節の数には取り置きの枠がある。1回の plan は 200 節まで。オーナーは枠の中で足せて置き換えられる', () => {
  const m = memoryRun();
  assert.throws(() => m.apply(EX, { event_id: 'big', op: 'plan', nodes: Array.from({ length: 201 }, (_, i) => N(T(1000 + i), [], [])) }), (e) => e.violations.some((v) => v.guard === 'RS-EVENT-SHAPE'));
  for (let k = 0; k < 9; k += 1) m.apply(EX, { event_id: `pl${k}`, op: 'plan', nodes: Array.from({ length: 200 }, (_, i) => N(T(k * 200 + i), [], [])) });
  assert.equal(m.state().order.length, 1800);
  assert.throws(() => m.apply(EX, { event_id: 'pl9', op: 'plan', nodes: [N(T(1800), [], [])] }), (e) => e.violations.some((v) => v.guard === 'RS-EVENT-QUOTA'));
  m.apply(OW, { event_id: 'o1', op: 'plan', nodes: [N(T(1900), [], [])] });
  m.apply(OW, { event_id: 'o2', op: 'plan', nodes: [N(T(1901), [], [])], supersede: [{ old: T(0), new: T(1901) }] });
  assert.equal(m.state().nodes[T(0)].superseded_by, T(1901));
});

test('N5: 法律の系統の付け替えは、それ自体が緩める変更。付け替えると承認は効かなくなり、系統を戻しても復活しない', () => {
  const w = mkRun({ policy_line: 'p0.4' });
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001'), N('T-002')] }); w.approve('T-001'); w.approve('T-002'); w.start('T-001');
    refused(() => w.go(OW, cfgEv({ policy_line: 'p0.3', reason: '付け替える' })), 'RS-CONFIG-TIGHTEN');
    w.submit('T-001'); w.verdict('T-001', R1, 'passed', AP2); // a は merged（作業中でなくなる）
    w.go(OW, cfgEv({ policy_line: 'p0.3', reason: '付け替える' }));
    assert.equal(w.run.state().nodes['T-002'].approved, false);
    w.go(OW, cfgEv({ policy_line: 'p0.4', reason: '戻す' }));
    assert.equal(w.run.state().nodes['T-002'].approved, false, '古い承認は復活しない');
    refused(() => w.start('T-002'), 'RS-APPROVED');
    w.approve('T-002'); w.start('T-002'); assert.equal(w.st('T-002'), 'in_progress');
  } finally { w.cleanup(); }
});

// rs.v2：役割と種類の対応は vocab が決める（executive_head は ai だけ）。kind: human を名乗る行政の長は、RS-ACTOR-SHAPE が入口で止める
// （rs.v1 では RS-EVENT-QUOTA が role で数えて止めていた）。行政の上限と取り置きの枠は、正しい名乗りの行政の長で確かめる
test('N6: 取り置きの枠と行政の上限は role で決まる。kind: human を名乗る executive_head は行為者の形で拒む', () => {
  const m = memoryRun();
  const HX = { role: 'executive_head', kind: 'human', id: 'max' };
  assert.throws(() => m.apply(HX, { event_id: 'hx0', op: 'plan', nodes: [N(T(0), [], [])] }), (e) => e.violations.some((v) => v.guard === 'RS-ACTOR-SHAPE'));
  for (let i = 0; i < 500; i += 1) m.apply(EX, { event_id: `p${i}`, op: 'plan', nodes: [N(T(i), [], [])] });
  assert.throws(() => m.apply(EX, { event_id: 'p500', op: 'plan', nodes: [N('T-024', [], [])] }), (e) => e.violations.some((v) => v.guard === 'RS-EVENT-QUOTA'));
  assert.throws(() => m.apply(HX, { event_id: 'p501', op: 'plan', nodes: [N('T-024', [], [])] }), (e) => e.violations.some((v) => v.guard === 'RS-ACTOR-SHAPE'));
  m.st.count = MAX_EVENTS - HUMAN_RESERVE;
  assert.throws(() => m.apply(CT, { event_id: 'q', op: 'expire', node: T(0) }), (e) => e.violations.some((v) => v.guard === 'RS-EVENT-QUOTA'));
  assert.throws(() => m.apply(HX, { event_id: 'q', op: 'plan', nodes: [N('T-025', [], [])] }), (e) => e.violations.some((v) => v.guard === 'RS-ACTOR-SHAPE'));
  m.apply(OW, { event_id: 'own', op: 'plan', nodes: [N('T-025', [], [])] });
});

test('config: 作業中に、項目ごとに緩める変更（max_attempts・max_returns・max_unavailable・lease_sec・concurrent_work・protected・work_item）を拒む。security_lineage の付け替えは形で拒む。締める変更は通る', () => {
  const w = mkRun({ max_attempts: 3, max_returns: 2, max_unavailable: 2, lease_sec: 600, protected: ['vgdd/**'] });
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001')] }); w.approve('T-001'); w.start('T-001', 300);
    const base = { max_attempts: 3, max_returns: 2, max_unavailable: 2, lease_sec: 600, protected: ['vgdd/**'] };
    // rs.v2：security_lineage は codex だけが審査の種類に写せるので、別の系統への付け替え（gemini・claude）は緩める変更の前に形の検査で拒む
    for (const lineage of ['gemini', 'claude']) refused(() => w.go(OW, cfgEv({ ...base, security_lineage: lineage, reason: '緩める' })), 'RS-EVENT-SHAPE');
    for (const loosen of [{ max_attempts: 4 }, { max_returns: 3 }, { max_unavailable: 3 }, { lease_sec: 601 }, { concurrent_work: 3 }, { protected: [] }, { work_item: { prefix: 'T-', digits: [3, 5] } }]) {
      refused(() => w.go(OW, cfgEv({ ...base, ...loosen, reason: '緩める' })), 'RS-CONFIG-TIGHTEN');
    }
    w.go(OW, cfgEv({ max_attempts: 2, max_returns: 1, max_unavailable: 1, lease_sec: 300, concurrent_work: 1, protected: ['vgdd/**', 'docs/**'], reason: '締める' }));
    assert.equal(w.run.state().config.max_attempts, 2);
  } finally { w.cleanup(); }
});

// ================= rs.v2：共通の語彙（lib/vocab.mjs）への移行で足したガード・項目 =================
const M1 = '0123456789abcdef0123456789abcdef01234567'; // 統合の参照（Git の 40 桁）
const h12 = R1.slice(0, 12);
const goodRefs = () => ({ verdicts: [{ kind: 'judge', lineage: 'claude', id: `VRD-${h12}-judge` }, { kind: 'judge', lineage: 'codex', id: `VRD-${h12}-codex-judge` }], findings: [`VRD-${h12}-codex-judge#f1`], audit: { id: `AUD-${h12}` } });

test('rs.v2 RS-WORK-ITEM-ID: 節の id は config の票の ID の宣言（既定は T- と 3〜4 桁、書いたとおり）に合うものだけ', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001')] });
    for (const id of ['t-101', 'T-01', 'T-10000', 'TASK-101', 'Т-101', 'T-١٠١', 'T-1a1', 'T101']) refused(() => w.go(EX, { op: 'plan', nodes: [N(id)] }), 'RS-WORK-ITEM-ID');
    refused(() => w.go(EX, { op: 'plan', nodes: [N('T-101', ['t-001'])] }), 'RS-WORK-ITEM-ID'); // 依存の id
    refused(() => w.go(EX, { op: 'plan', nodes: [N('t-012')], supersede: [{ old: 'T-001', new: 't-012' }] }), 'RS-WORK-ITEM-ID'); // 置き換え先の id
    // 全角は畳まずに入口（RS-EVENT-SHAPE）で拒む。陽性の対照：3 桁・4 桁は通る
    refused(() => w.go(EX, { op: 'plan', nodes: [{ id: 'Ｔ－１０２', depends_on: [], resources: ['src/t102/**'] }] }), 'RS-EVENT-SHAPE');
    w.go(EX, { op: 'plan', nodes: [N('T-101'), N('T-9999', ['T-101'])] });
    w.go(EX, { op: 'plan', nodes: [{ id: 'T-102', depends_on: [], resources: ['src/t102/**'] }] });
    assert.deepEqual(w.run.state().order, ['T-001', 'T-101', 'T-9999', 'T-102']);
  } finally { w.cleanup(); }
  const j = mkRun({ work_item: { prefix: 'JOB-', digits: [2, 2] } });
  try {
    refused(() => j.go(EX, { op: 'plan', nodes: [N('T-101')] }), 'RS-WORK-ITEM-ID'); // 宣言が替われば既定の形も通らない
    j.go(EX, { op: 'plan', nodes: [N('JOB-12')] });
    assert.deepEqual(j.run.state().order, ['JOB-12']);
    refused(() => j.go(OW, cfgEv({ work_item: { prefix: 'T-', digits: [0, 4] }, reason: '読めない宣言' })), 'RS-EVENT-SHAPE'); // 宣言の形（digits は 1〜12）
  } finally { j.cleanup(); }
});

test('rs.v2 RS-PLAN-RESOURCES: 範囲は taskgraph が扱える形（literal・dir/**・prefix*）だけ', () => {
  const w = mkRun();
  try {
    for (const r of ['src/[a]*', 'src/?', '../x', 'src/a/../b', 'src/*.js', '**', 'src/{a,b}', '/abs', 'src/']) refused(() => w.go(EX, { op: 'plan', nodes: [N('T-101', [], [r])] }), 'RS-PLAN-RESOURCES');
    assert.equal(w.run.state().order.length, 0);
    w.go(EX, { op: 'plan', nodes: [N('T-101', [], ['src/a/**', 'src/b*', 'README.md'])] });
    assert.deepEqual(w.run.state().nodes['T-101'].resources, ['README.md', 'src/a/**', 'src/b*']);
  } finally { w.cleanup(); }
});

test('rs.v2 RS-PROTECTED: 保護された範囲（config.protected）と重なる節は、行政もオーナーも計画に入れられない', () => {
  const w = mkRun({ protected: ['vgdd/**'] });
  try {
    for (const r of ['vgdd/kernel/**', 'vgdd/**', 'VGDD/x', 'vgdd', 'vgd*']) refused(() => w.go(EX, { op: 'plan', nodes: [N('T-101', [], ['src/ok/**', r])] }), 'RS-PROTECTED');
    refused(() => w.go(OW, { op: 'plan', nodes: [N('T-101', [], ['vgdd/kernel/hooks/guard.sh'])] }), 'RS-PROTECTED');
    w.go(EX, { op: 'plan', nodes: [N('T-101', [], ['src/ok/**', 'docs/vgdd.md'])] }); // 陽性の対照：重ならない範囲
    assert.deepEqual(w.run.state().order, ['T-101']);
    refused(() => w.go(OW, cfgEv({ protected: ['src/[x]*'], reason: '扱えない形の保護' })), 'RS-EVENT-SHAPE'); // 保護の範囲も扱える形だけ
  } finally { w.cleanup(); }
  const free = mkRun(); // 保護がなければ同じ節は入る
  try { free.go(EX, { op: 'plan', nodes: [N('T-101', [], ['vgdd/kernel/**'])] }); assert.deepEqual(free.run.state().order, ['T-101']); } finally { free.cleanup(); }
});

test('rs.v2 RS-MERGE-REF: 統合の参照（merge）は merged になる出来事（合格の verdict・release・rule の merge）だけが持てる', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001'), N('T-002')] }); w.approve('T-001'); w.approve('T-002');
    w.start('T-001'); w.submit('T-001');
    refused(() => w.go(CT, { op: 'verdict', node: 'T-001', request: R1, audits: 'failed', verdicts: AP2, merge: M1 }), 'RS-MERGE-REF'); // 差し戻し
    refused(() => w.go(CT, { op: 'verdict', node: 'T-001', request: R1, audits: 'passed', verdicts: [AP2[0]], merge: M1 }), 'RS-MERGE-REF'); // 司法が使えない
    refused(() => w.go(CT, { op: 'verdict', node: 'T-001', request: R1, audits: 'passed', verdicts: AP2, merge: 'abc' }), 'RS-EVENT-SHAPE'); // 参照の形
    assert.equal(w.st('T-001'), 'review');
    const r = w.go(CT, { op: 'verdict', node: 'T-001', request: R1, audits: 'passed', verdicts: AP2, merge: M1 });
    assert.equal(r.to, 'merged'); assert.equal(w.run.state().nodes['T-001'].merge, M1);
    // 判定の分かれ → rule：return に merge は付けられず、merge の裁定には付けられる
    w.start('T-002'); w.submit('T-002', R2); w.verdict('T-002', R2, 'passed', SPLIT_MAJOR);
    refused(() => w.go(OW, { op: 'rule', node: 'T-002', request: R2, decision: 'return', reason: 'やり直す', merge: M1 }), 'RS-MERGE-REF');
    w.go(OW, { op: 'rule', node: 'T-002', request: R2, decision: 'merge', reason: '通す', merge: M1 });
    assert.equal(w.run.state().nodes['T-002'].merge, M1);
    assert.ok(w.reopen().verify().ok);
  } finally { w.cleanup(); }
  const h = mkRun({ hold: true });
  try {
    h.go(EX, { op: 'plan', nodes: [N('T-001')] }); h.approve('T-001'); h.start('T-001'); h.submit('T-001');
    refused(() => h.go(CT, { op: 'verdict', node: 'T-001', request: R1, audits: 'passed', verdicts: AP2, merge: M1 }), 'RS-MERGE-REF'); // held はまだ統合でない
    h.verdict('T-001', R1, 'passed', AP2);
    h.go(OW, { op: 'release', node: 'T-001', request: R1, merge: M1 });
    assert.equal(h.st('T-001'), 'merged'); assert.equal(h.run.state().nodes['T-001'].merge, M1);
  } finally { h.cleanup(); }
});

test('rs.v2 defDigestOf: state() の節から計算した指紋は節の def_digest と同じで、その指紋で承認できる', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [{ ...N('T-001', [], ['src/b/**', 'src/a/**']), risk: 'high', security_review: true, requirements: ['R-2', 'A1'] }] });
    const n = w.run.state().nodes['T-001'];
    assert.equal(defDigestOf(n), n.def_digest);
    assert.equal(defDigestOf({ id: 'T-001', depends_on: [], resources: ['src/a/**', 'src/b/**'], risk: 'high', security_review: true, requirements: ['A1', 'R-2'] }), n.def_digest, '並べ替えに依らない');
    assert.notEqual(defDigestOf({ ...n, requirements: ['A1'] }), n.def_digest, '要件が変われば指紋も変わる');
    w.go(OW, { op: 'approve', node: 'T-001', spec_digest: S1, policy_line: 'p0.4', def_digest: defDigestOf(n) });
    assert.equal(w.run.state().nodes['T-001'].approved, true);
    assert.deepEqual(w.run.state().nodes['T-001'].requirements, ['A1', 'R-2']);
    refused(() => w.go(EX, { op: 'plan', nodes: [{ ...N('T-002'), requirements: ['r-1'] }] }), 'RS-EVENT-SHAPE'); // 要件の ID は大文字の形だけ
  } finally { w.cleanup(); }
});

test('rs.v2 申請の履歴: 差し戻した申請の指紋・結果の種類・時刻が残る（司法が使えない周回は残さない）。apply は digest と時刻を返す', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001')] }); w.approve('T-001'); w.start('T-001'); w.submit('T-001', R1);
    w.verdict('T-001', R1, 'passed', [AP2[0]]); // 使えない：履歴に入れない
    assert.deepEqual(w.run.state().nodes['T-001'].requests, []);
    const r = w.verdict('T-001', R1, 'failed', AP2);
    assert.deepEqual(Object.keys(r).sort(), ['at', 'digest', 'duplicate', 'kind', 'node', 'ok', 'seq', 'to']);
    assert.match(r.digest, /^sha256:[0-9a-f]{64}$/);
    assert.equal(r.kind, 'return'); assert.equal(r.node.status, 'in_progress');
    const n = w.run.state().nodes['T-001'];
    assert.deepEqual(n.requests, [{ request: R1, kind: 'return', at: r.at }]);
    assert.equal(n.request, null); assert.equal(n.requests_dropped, 0); assert.equal(n.started_by, 'max');
    w.submit('T-001', R2); const p = w.verdict('T-001', R2, 'passed', AP2);
    assert.deepEqual(w.run.state().nodes['T-001'].requests.map((x) => [x.request, x.kind, x.at]), [[R1, 'return', r.at], [R2, 'pass', p.at]]);
    const m = memoryRun();
    const mr = m.apply(EX, { event_id: 'p', op: 'plan', nodes: [N('T-001')] });
    assert.deepEqual(Object.keys(mr).sort(), ['digest', 'duplicate', 'kind', 'ok', 'to']);
  } finally { w.cleanup(); }
});

test('rs.v2 判定の参照（refs）: 判定の項目と食い違う参照（審査の種類・申請の先頭 12 桁・指摘の指す判定）は形の検査で拒む', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001')] }); w.approve('T-001'); w.start('T-001'); w.submit('T-001', R1);
    const v = (refs) => w.go(CT, { op: 'verdict', node: 'T-001', request: R1, audits: 'passed', verdicts: AP2, refs });
    const g = goodRefs();
    const bad = [
      ['審査の種類が違う（claude の判定に codex-judge の id）', { ...g, verdicts: [{ ...g.verdicts[0], id: `VRD-${h12}-codex-judge` }, g.verdicts[1]], findings: [] }],
      ['申請の先頭 12 桁が違う', { ...g, verdicts: [{ ...g.verdicts[0], id: `VRD-${R2.slice(0, 12)}-judge` }, g.verdicts[1]] }],
      ['指摘が refs.verdicts にない判定を指す', { ...g, findings: [`VRD-${h12}-codex-security#f1`] }],
      ['判定の項目にない審査（security）の参照', { ...g, verdicts: [...g.verdicts, { kind: 'security', lineage: 'codex', id: `VRD-${h12}-codex-security` }] }],
      ['監査の id の先頭 12 桁が違う', { ...g, audit: { id: `AUD-${R2.slice(0, 12)}` } }],
      ['判定の id の指紋の 8 桁と digest が合わない', { ...g, verdicts: [{ ...g.verdicts[0], id: `VRD-${h12}-judge-0badc0de`, digest: `sha256:${'1'.repeat(64)}` }, g.verdicts[1]], findings: [] }],
      ['知らない項目', { ...g, extra: 1 }],
    ];
    for (const [name, refs] of bad) {
      const e = refused(() => v(refs), 'RS-EVENT-SHAPE');
      assert.equal(e.code, 'guard_violation', name);
    }
    assert.equal(w.st('T-001'), 'review');
    // 陽性の対照：食い違いのない参照は通り、記録に残る
    v(g);
    assert.equal(w.st('T-001'), 'merged');
    assert.ok(w.reopen().verify().ok);
  } finally { w.cleanup(); }
});

test('rs.v2 start の assignee: 作業員（worker・tester）の行為者を記録する。ほかの役割・形の違う行為者は拒む。権限は与えない', () => {
  const w = mkRun();
  try {
    w.go(EX, { op: 'plan', nodes: [N('T-001'), N('T-002')] }); w.approve('T-001'); w.approve('T-002');
    const st0 = { op: 'start', node: 'T-001', spec_digest: S1, lease_sec: 600 };
    for (const assignee of [{ role: 'owner', kind: 'human', id: 'azuki' }, { role: 'worker', kind: 'ai', id: 'w1' }, { role: 'worker', kind: 'human', id: 'w1' }, { role: 'judge', kind: 'ai', id: 'j', lineage: 'claude' }, 'w1']) {
      refused(() => w.go(EX, { ...st0, assignee }), 'RS-EVENT-SHAPE');
    }
    w.go(EX, { ...st0, assignee: { role: 'Worker', kind: 'ai', id: 'W1', lineage: 'codex' } });
    const n = w.run.state().nodes['T-001'];
    assert.deepEqual(n.assignee, { role: 'worker', kind: 'ai', id: 'w1', lineage: 'codex' });
    assert.equal(n.started_by, 'max');
    w.go(EX, { op: 'start', node: 'T-002', spec_digest: S1, lease_sec: 600, assignee: { role: 'tester', kind: 'ai', id: 't1', lineage: 'claude' } });
    // 作業員は行為者として出来事を起こせない（役割の表にあっても、この部品の役割でない）
    refused(() => w.go({ role: 'worker', kind: 'ai', id: 'w1', lineage: 'codex' }, { op: 'submit', node: 'T-001', request: R1 }), 'RS-ROLE-OP');
    assert.ok(w.reopen().verify().ok);
  } finally { w.cleanup(); }
});
