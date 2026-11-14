import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { validateTeam, check, GUARDS, catalogFromCapabilities } from '../team.mjs';
import { buildGraph } from '../taskgraph.mjs';
import { SCENARIOS, CATALOG } from '../bench/scenarios-team.mjs';

const ctx = (o = {}) => ({
  catalog: CATALOG,
  ticket: { resources: ['src/**'], risk: 'low' },
  limits: { concurrent_work: 2, depth: 2 },
  required: { judicial_min: 1, judicial_distinct_lineage: true },
  ...o,
});
const W = (id, res = ['src/a/**']) => ({ id, template: 'worker', lineage: 'claude', scope: { resources: res, tools: ['Read'] } });
const J = { id: 'j', template: 'codex_judge', lineage: 'codex', scope: { resources: [], tools: [] } };

test('catalogFromCapabilities: 型と branch、表にない役割は使えない（陰性）', () => {
  const caps = JSON.parse(fs.readFileSync(new URL('../../kernel/capabilities.json', import.meta.url), 'utf8'));
  assert.equal(CATALOG.worker.branch, 'executive');
  assert.equal(CATALOG.codex_judge.branch, 'judicial');
  assert.equal(CATALOG.owner.kind, 'human');
  assert.equal(CATALOG.worker.may_delegate, false);
  assert.equal(CATALOG.judge.may_delegate, false);
  const c2 = catalogFromCapabilities({ roles: { ...caps.roles, mystery: { kind: 'ai' } } });
  assert.equal(c2.mystery.usable, false);
  const r = validateTeam({ task: 't', proposed_by: 'executive_head', members: [{ id: 'm', template: 'mystery', scope: { resources: [], tools: [] } }, J] }, ctx({ catalog: c2 }));
  assert.equal(r.ok, false);
  assert.ok(r.violations.some((v) => v.guard === 'TM-TEMPLATE-EXISTS'));
});

test('validateTeam: 良性の編成は ok（陽性）', () => {
  const r = validateTeam({ task: 't', proposed_by: 'executive_head', members: [W('w1'), J] }, ctx());
  assert.equal(r.ok, true, JSON.stringify(r.violations));
  assert.deepEqual(r.violations, []);
});

test('requires_approval（B-F4）: 常に true。plan の中身（proposed_by: owner 等）では false にならない', () => {
  const plan = (pb) => ({ task: 't', proposed_by: pb, members: [W('w1'), J] });
  for (const pb of ['executive_head', 'owner', 'Owner', { id: 'owner' }, { id: 'owner', kind: 'human' }, { id: 'ai-pm', kind: 'human', role: 'owner' }, 'unknown', null]) {
    assert.equal(validateTeam(plan(pb), ctx()).requires_approval, true, JSON.stringify(pb));
  }
  assert.equal(validateTeam(plan('owner'), ctx({ proposer: { kind: 'ai', role: 'owner' } })).requires_approval, true);
  assert.equal(validateTeam(plan('owner'), ctx({ proposer: { kind: 'human', role: 'worker' } })).requires_approval, true);
  assert.equal(validateTeam(plan('executive_head'), ctx()).effect, 'none');
  // 検査に落ちた編成にも付く
  assert.equal(validateTeam({ task: 't', proposed_by: 'executive_head', members: [W('w1')] }, ctx()).requires_approval, true);
  // 陽性の対照: 呼び出し側が認証した人のオーナーが渡したときだけ false（それでも効力は与えない）
  const r = validateTeam(plan('whatever'), ctx({ proposer: { kind: 'human', role: 'owner', id: 'azuki' } }));
  assert.equal(r.requires_approval, false);
  assert.equal(r.effect, 'none');
});

test('違反には member が付く', () => {
  const r = validateTeam({ task: 't', proposed_by: 'executive_head', members: [W('w1', ['lib/**']), J] }, ctx());
  assert.equal(r.violations.find((v) => v.guard === 'TM-SCOPE-RESOURCES').member, 'w1');
});

test('司法は委任できず委任されない（行政の長の子・司法の子とも）', () => {
  const h = { id: 'h', template: 'executive_head', lineage: 'claude', scope: { resources: ['src/**'], tools: ['Read', 'Agent'] } };
  const r1 = validateTeam({ task: 't', proposed_by: 'x', members: [h, { ...J, parent: 'h' }] }, ctx());
  assert.ok(r1.violations.some((v) => v.guard === 'TM-JUDICIAL-INDEPENDENT'));
  const r2 = validateTeam({ task: 't', proposed_by: 'x', members: [J, { ...W('w1'), parent: 'j' }] }, ctx());
  assert.ok(r2.violations.some((v) => v.guard === 'TM-DELEG-ALLOWED'));
  assert.ok(r2.violations.some((v) => v.guard === 'TM-JUDICIAL-INDEPENDENT'));
});

test('司法の系統: 系統の申告がなければ違いを確かめられず違反（fail-closed）', () => {
  const noLin = { id: 'w1', template: 'worker', scope: { resources: ['src/a/**'], tools: [] } };
  const r = validateTeam({ task: 't', proposed_by: 'x', members: [{ ...noLin, lineage: undefined }, { id: 'j', template: 'codex_judge', scope: { resources: [], tools: [] } }] }, ctx({ catalog: { ...CATALOG, worker: { ...CATALOG.worker, lineage: undefined } } }));
  assert.ok(r.violations.some((v) => v.guard === 'TM-JUDICIARY-LINEAGE'));
  // required で系統の違いを求めなければ通る
  const r2 = validateTeam({ task: 't', proposed_by: 'x', members: [W('w1'), { id: 'j', template: 'judge', lineage: 'claude', scope: { resources: [], tools: [] } }] }, ctx({ required: { judicial_distinct_lineage: false } }));
  assert.equal(r2.ok, true);
});

test('warnings: single を勧める票で行政が 2 体以上なら理由つきで警告（違反ではない）', () => {
  const g = buildGraph([{ id: 'A', status: 'ready', depends_on: [], resources: ['src/a/**'], approved: true }, { id: 'B', status: 'ready', depends_on: ['A'], resources: ['src/a/**'], approved: true }]).graph;
  const plan = { task: 't', proposed_by: 'x', members: [W('w1', ['src/a/**']), W('w2', ['src/b/**']), J] };
  const r = validateTeam(plan, ctx({ graph: g }));
  assert.equal(r.ok, true);
  assert.equal(r.warnings.length, 1);
  assert.match(r.warnings[0].reason, /single/);
  // 並列が妥当な票では警告しない
  const g2 = buildGraph([{ id: 'A', status: 'ready', depends_on: [], resources: ['src/a/**'], approved: true }, { id: 'B', status: 'ready', depends_on: [], resources: ['src/b/**'], approved: true }]).graph;
  assert.equal(validateTeam(plan, ctx({ graph: g2 })).warnings.length, 0);
  // 単一の作業員なら警告しない
  assert.equal(validateTeam({ ...plan, members: [W('w1'), J] }, ctx({ graph: g })).warnings.length, 0);
});

test('plan が壊れていても落ちず、拒否する', () => {
  for (const bad of [null, {}, { members: 'x' }, 'plan']) {
    const r = validateTeam(bad, ctx());
    assert.equal(r.ok, false);
  }
  assert.equal(validateTeam({ task: 't', proposed_by: 'x', members: [W('w1'), J] }, {}).ok, false);
});

test('GUARDS: 各ガードが単独で止める（陰性）', () => {
  for (const name of Object.keys(GUARDS)) {
    const sc = SCENARIOS.filter((s) => s.kind === 'attack' && s.expectGuards.includes(name));
    assert.ok(sc.length >= 1, `${name} の攻撃シナリオがない`);
    for (const s of sc) assert.ok(s.run([name]).blocked, `${s.id} が ${name} で止まらない`);
  }
});

test('シナリオ: attack は全ガードで止まり、benign は通る', () => {
  assert.ok(SCENARIOS.filter((s) => s.kind === 'benign').length >= 3);
  for (const s of SCENARIOS) {
    const r = s.run(Object.keys(GUARDS));
    if (s.kind === 'attack') {
      assert.equal(r.blocked, true, s.id);
      for (const g of s.expectGuards) assert.ok(r.by.includes(g), `${s.id}: ${g}`);
    } else assert.equal(r.blocked, false, `${s.id}: ${r.by}`);
  }
});

test('check: 未知のガード名は例外', () => {
  assert.throws(() => check({ plan: {}, context: {} }, ['NOPE']));
});

// ---- 審査 B の判例 ------------------------------------------------------------

import { covers } from '../taskgraph.mjs';
import { normLineage } from '../team.mjs';

test('B-F1: 票の範囲 src/** は src* を含まない。子の範囲も親を超えられない', () => {
  assert.equal(covers('src/**', 'src*'), false);
  const bad = validateTeam({ task: 't', proposed_by: 'x', members: [W('w1', ['src*']), J] }, ctx());
  assert.ok(bad.violations.some((v) => v.guard === 'TM-SCOPE-RESOURCES'));
  const good = validateTeam({ task: 't', proposed_by: 'x', members: [W('w1', ['src/a*']), J] }, ctx());
  assert.equal(good.ok, true, JSON.stringify(good.violations));
});

test('B-F3: 系統は正規化して比べる。catalog が知っていれば plan の申告で上書きできない', () => {
  assert.equal(normLineage(' Claude '), 'claude');
  for (const bad of [{}, 0, null, undefined, '', 'co dex', '1abc', 'x'.repeat(41), ['claude']]) assert.equal(normLineage(bad), null, JSON.stringify(bad));
  const mk = (wl, jl, jt = 'judge') => ({ task: 't', proposed_by: 'x', members: [{ ...W('w1'), lineage: wl }, { id: 'j', template: jt, lineage: jl, scope: { resources: [], tools: [] } }] });
  // 表記ゆれで同系統を別系統に見せる抜け道（Claude / 空白 / 型の系統の上書き）
  for (const [wl, jl] of [['Claude', undefined], [' claude', undefined], ['claude', 'codex'], ['CLAUDE', 'Codex']]) {
    const r = validateTeam(mk(wl, jl), ctx());
    assert.equal(r.ok, false, `${wl}/${jl}`);
  }
  assert.ok(validateTeam(mk({}, undefined), ctx()).violations.some((v) => v.guard === 'TM-LINEAGE-HONEST'));
  assert.ok(validateTeam(mk('claude', 'codex'), ctx()).violations.some((v) => v.guard === 'TM-LINEAGE-HONEST'));
  // 陽性の対照: 本物の別系統の司法は通る（申告が型と同じなら表記ゆれがあっても可）
  assert.equal(validateTeam(mk('Claude', 'CODEX', 'codex_judge'), ctx()).ok, true);
  assert.equal(validateTeam(mk(undefined, undefined, 'codex_judge'), ctx()).ok, true);
  // catalog に系統のない型は申告を受ける（許可された形のときだけ）
  const c2 = { ...CATALOG, worker: { ...CATALOG.worker, lineage: undefined } };
  const p2 = { task: 't', proposed_by: 'x', members: [{ ...W('w1'), lineage: 'Gemini' }, { id: 'j', template: 'codex_judge', scope: { resources: [], tools: [] } }] };
  // 共通の語彙：知らない系統（Gemini）は申告として受けない
  assert.ok(validateTeam(p2, ctx({ catalog: c2 })).violations.some((v) => v.guard === 'TM-LINEAGE-HONEST'));
  p2.members[0].lineage = ' CLAUDE ';
  assert.equal(validateTeam(p2, ctx({ catalog: c2 })).ok, true);
  p2.members[0].lineage = 'codex';
  assert.equal(validateTeam(p2, ctx({ catalog: c2 })).ok, false);
});

test('B-F13: context の値は型を検査する（司法ゼロ・NaN・undefined・文字列の false）', () => {
  const plan0 = { task: 't', proposed_by: 'x', members: [W('w1')] };
  for (const req of [{ judicial_min: undefined }, { judicial_min: null }, { judicial_min: NaN }, { judicial_min: 0 }, { judicial_min: '1' }, { judicial_min: 1.5 }]) {
    const r = validateTeam(plan0, ctx({ required: req }));
    assert.equal(r.ok, false, JSON.stringify(req));
    assert.ok(r.violations.some((v) => v.guard === 'TM-JUDICIARY-PRESENT'), JSON.stringify(req)); // 司法ゼロは必ず止まる
  }
  const plan1 = { task: 't', proposed_by: 'x', members: [W('w1'), J] };
  assert.ok(validateTeam(plan1, ctx({ required: { judicial_distinct_lineage: 'false' } })).violations.some((v) => v.guard === 'TM-CONTEXT-SHAPE'));
  for (const lim of [{ concurrent_work: 2.5 }, { concurrent_work: NaN }, { concurrent_work: '2' }, { concurrent_work: 2, depth: -1 }, { concurrent_work: 2, members_total: 0 }, null]) assert.equal(validateTeam(plan1, ctx({ limits: lim })).ok, false, JSON.stringify(lim));
  assert.equal(validateTeam(plan1, ctx({ ticket: {} })).ok, false);
  assert.equal(validateTeam(plan1, ctx({ catalog: null })).ok, false);
  // 陽性の対照
  assert.equal(validateTeam(plan1, ctx({ required: { judicial_min: undefined } })).ok, true, 'undefined は既定（1）で補う');
  assert.equal(validateTeam(plan1, ctx({ required: { judicial_min: 1, judicial_distinct_lineage: true } })).ok, true);
});

test('B-F13: member の総数に上限（既定 16）。行政以外も数える', () => {
  const many = (n) => ({ task: 't', proposed_by: 'x', members: [W('w1'), ...Array.from({ length: n }, (_, i) => ({ ...J, id: `j${i}` }))] });
  const r = validateTeam(many(5000), ctx());
  assert.ok(r.violations.some((v) => v.guard === 'TM-MEMBER-LIMIT'));
  assert.equal(validateTeam(many(15), ctx()).ok, true); // 合計 16
  assert.equal(validateTeam(many(16), ctx()).ok, false);
  assert.equal(validateTeam(many(16), ctx({ limits: { concurrent_work: 2, depth: 2, members_total: 32 } })).ok, true);
});

test('B-F13: 大きな plan でも線形の時間で終わる（深さ・循環の検査）', () => {
  const ms = [{ ...J }];
  for (let i = 0; i < 20000; i++) ms.push({ id: 'h' + i, template: 'executive_head', lineage: 'claude', parent: i ? 'h' + (i - 1) : null, scope: { resources: ['src/a'], tools: ['Read'] } });
  const t = Date.now();
  const r = validateTeam({ task: 't', proposed_by: 'x', members: ms }, ctx({ limits: { concurrent_work: 1000, depth: 2, members_total: 64 } }));
  assert.ok(Date.now() - t < 5000, `所要 ${Date.now() - t}ms`);
  assert.ok(r.violations.some((v) => v.guard === 'TM-MEMBER-LIMIT'));
  const cyc = Array.from({ length: 3000 }, (_, i) => ({ id: 'c' + i, template: 'executive_head', lineage: 'claude', parent: 'c' + ((i + 1) % 3000), scope: { resources: ['src/a'], tools: ['Read'] } }));
  const t2 = Date.now();
  const r2 = validateTeam({ task: 't', proposed_by: 'x', members: cyc }, ctx({ limits: { concurrent_work: 1e9 } }));
  assert.ok(Date.now() - t2 < 5000);
  assert.ok(r2.violations.some((v) => v.guard === 'TM-DELEG-CYCLE'));
});

test('検査は例外を投げず違反にする（壊れた入力）', () => {
  const evil = { task: 't', proposed_by: 'x', get members() { throw new Error('boom'); } };
  assert.doesNotThrow(() => validateTeam(evil, ctx()));
  assert.equal(validateTeam(evil, ctx()).ok, false);
});

test('語彙：limits.concurrent_work は作業員（worker・tester）の数で、行政の長は数えず 1 体まで。旧名 workers は受けない', () => {
  const H = { id: 'h', template: 'executive_head', lineage: 'claude', scope: { resources: ['src/**'], tools: ['Read', 'Agent'] } };
  const plan = (ms) => ({ task: 't', proposed_by: 'x', members: [...ms, J] });
  assert.equal(validateTeam(plan([H, W('w1', ['src/a/**']), W('w2', ['src/b/**'])]), ctx({ limits: { concurrent_work: 2 } })).ok, true, '長＋作業員 2 は同時 2 に収まる');
  assert.ok(validateTeam(plan([W('w1', ['src/a/**']), W('w2', ['src/b/**']), W('w3', ['src/c/**'])]), ctx({ limits: { concurrent_work: 2 } })).violations.some((v) => v.guard === 'TM-WORKER-LIMIT'));
  assert.ok(validateTeam(plan([H, { ...H, id: 'h2' }]), ctx({ limits: { concurrent_work: 2 } })).violations.some((v) => v.guard === 'TM-WORKER-LIMIT'));
  assert.ok(validateTeam(plan([W('w1')]), ctx({ limits: { workers: 2 } })).violations.some((v) => v.guard === 'TM-CONTEXT-SHAPE' && /concurrent_work/.test(v.reason)));
  // 系統の別名は受けない
  assert.ok(validateTeam(plan([{ ...W('w1'), lineage: 'anthropic' }]), ctx()).violations.some((v) => v.guard === 'TM-LINEAGE-HONEST'));
});
