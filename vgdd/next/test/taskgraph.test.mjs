import test from 'node:test';
import assert from 'node:assert/strict';
import { buildGraph, metrics, ready, schedule, recommend, check, GUARDS, covers, overlap, parsePattern, resourcesOverlap, THRESHOLDS, MAX_NODES } from '../taskgraph.mjs';
import { SCENARIOS } from '../bench/scenarios-taskgraph.mjs';

const N = (id, o = {}) => ({ id, status: 'ready', depends_on: [], resources: [`src/${id}/**`], approved: true, ...o });
const G = (nodes) => {
  const r = buildGraph(nodes);
  assert.ok(r.ok, JSON.stringify(r.errors));
  return r.graph;
};

test('buildGraph: 循環・欠けた依存・重複・自己依存は errors（陰性）', () => {
  assert.equal(buildGraph([N('A', { depends_on: ['B'] }), N('B', { depends_on: ['A'] })]).ok, false);
  assert.equal(buildGraph([N('A', { depends_on: ['A'] })]).ok, false);
  assert.equal(buildGraph([N('A', { depends_on: ['Z'] })]).ok, false);
  assert.equal(buildGraph([N('A'), N('A')]).ok, false);
  assert.equal(buildGraph([N('A', { status: 'done' })]).ok, false);
  assert.equal(buildGraph('x').ok, false);
  assert.equal(buildGraph([N('A', { depends_on: ['B'] }), N('B', { depends_on: ['A'] })]).graph, undefined);
});

test('buildGraph: 正しいグラフは ok（陽性）', () => {
  assert.equal(buildGraph([N('A'), N('B', { depends_on: ['A'] })]).ok, true);
  assert.equal(buildGraph([]).ok, true);
});

test('metrics: 幅・深さ・結合・競合', () => {
  const g = G([N('A'), N('B'), N('C', { depends_on: ['A', 'B'] }), N('D', { resources: ['src/A/x'] })]);
  const m = metrics(g);
  assert.equal(m.n, 4);
  assert.equal(m.edges, 2);
  assert.equal(m.width, 3); // 層 1 に A,B,D
  assert.equal(m.depth, 2);
  assert.equal(m.coupling, 2 / 6);
  assert.equal(m.conflicts, 1); // A(src/A/**) と D(src/A/x) は依存なしで重なる
  assert.equal(metrics(G([N('A')])).coupling, 0);
});

test('metrics: 依存のある節の resources の重なりは競合に数えない', () => {
  const g = G([N('A', { resources: ['x/**'] }), N('B', { depends_on: ['A'], resources: ['x/y'] })]);
  assert.equal(metrics(g).conflicts, 0);
});

test('ready: 理由つき', () => {
  const g = G([
    N('A', { status: 'merged' }),
    N('B', { depends_on: ['A'] }),
    N('C', { approved: false }),
    N('D', { depends_on: ['E'] }),
    N('E', { status: 'blocked' }),
    N('F', { depends_on: ['C'] }),
  ]);
  const r = ready(g);
  assert.deepEqual(r.ready, ['B']);
  const why = Object.fromEntries(r.not_ready.map((x) => [x.id, x.reasons]));
  assert.deepEqual(why.C, ['unapproved']);
  assert.deepEqual(why.D, ['blocked_dependency:E']);
  assert.deepEqual(why.E, ['blocked']);
  assert.deepEqual(why.F, ['waiting_dependency:C']);
});

test('INV-12: 未承認・blocked の節は、依存しない節の着手を妨げない', () => {
  const g = G([N('A', { approved: false }), N('B', { status: 'blocked' }), N('C', { depends_on: ['A'] }), N('D', { depends_on: ['B'] }), N('E')]);
  const s = schedule(g, { workers: 3 });
  assert.deepEqual(s.batches, [['E']]);
  // 待つのは依存する節だけ
  const why = Object.fromEntries(ready(g).not_ready.map((x) => [x.id, x.reasons]));
  assert.ok(why.C && why.D);
  assert.equal(why.E, undefined);
});

test('schedule: resources が重なる節は同じ組に入れない。先の id を優先（決定論的）', () => {
  const g = G([N('B', { resources: ['a/**'] }), N('A', { resources: ['a/x'] }), N('C')]);
  const s1 = schedule(g, { workers: 3 });
  assert.deepEqual(s1.batches, [['A', 'C']]);
  assert.match(s1.reasons.B, /resource_conflict:A/);
  assert.deepEqual(schedule(g, { workers: 3 }), s1);
});

test('schedule: 同時の数の上限・作業中の分を差し引く', () => {
  const g = G([N('A'), N('B'), N('C')]);
  assert.deepEqual(schedule(g, { workers: 2 }).batches, [['A', 'B']]);
  assert.equal(schedule(g, { workers: 2 }).reasons.C, 'worker_limit');
  const g2 = G([N('A', { status: 'in_progress' }), N('B'), N('C')]);
  assert.deepEqual(schedule(g2, { workers: 2 }).batches, [['B']]);
  assert.deepEqual(schedule(g2, { workers: 1 }).batches, []);
});

test('schedule: limits が不正なら 1 とみなす（fail-closed 寄り）', () => {
  const g = G([N('A'), N('B')]);
  assert.deepEqual(schedule(g, {}).batches, [['A']]);
  assert.deepEqual(schedule(g, { workers: 'many' }).batches, [['A']]);
});

test('recommend: 既定は single。理由と閾値（未校正の明記）を返す', () => {
  const r = recommend(G([N('A'), N('B', { depends_on: ['A'] })]), { workers: 4 });
  assert.equal(r.topology, 'single');
  assert.equal(r.workers, 1);
  assert.ok(r.reasons.length >= 2);
  assert.equal(r.thresholds.calibrated_for_vgdd, false);
  assert.match(r.reasons.join(' '), /校正していない/);
  assert.equal(THRESHOLDS.theta_omega, 0.5);
});

test('recommend: 重ならない 2 節・workers>=2・高リスクなし → parallel、workers は上限以下', () => {
  const g = G([N('A'), N('B'), N('C')]);
  const r = recommend(g, { workers: 2 });
  assert.equal(r.topology, 'parallel');
  assert.equal(r.workers, 2);
  assert.equal(recommend(g, { workers: 9 }).workers, 3);
});

test('recommend: workers=1 なら並列にしない（上限を広げない）', () => {
  const r = recommend(G([N('A'), N('B')]), { workers: 1 });
  assert.equal(r.topology, 'single');
  assert.ok(r.workers <= 1);
});

test('recommend: 高リスクを含めば parallel にしない', () => {
  const r = recommend(G([N('A', { risk: 'high' }), N('B')]), { workers: 4 });
  assert.equal(r.topology, 'single');
});

test('recommend: 重なる resources は parallel にしない', () => {
  const r = recommend(G([N('A', { resources: ['s/**'] }), N('B', { resources: ['s/x'] })]), { workers: 4 });
  assert.equal(r.topology, 'single');
});

test('recommend: depth>=2 かつ width>=2 は staged。workers は上限を超えない', () => {
  const g = G([N('A'), N('B'), N('C'), N('D', { depends_on: ['A', 'B', 'C'] })]);
  const r = recommend(g, { workers: 2 });
  assert.equal(r.topology, 'staged');
  assert.ok(r.workers <= 2);
  assert.equal(recommend(g, { workers: 1 }).topology, 'single');
});

test('recommend: どんな入力でも workers は limits.workers 以下', () => {
  for (let w = 0; w <= 5; w++) {
    const g = G([N('A'), N('B'), N('C'), N('D'), N('E', { depends_on: ['A'] })]);
    assert.ok(recommend(g, { workers: w }).workers <= w);
  }
});

test('グロブ: covers / overlap', () => {
  assert.equal(covers('src/**', 'src/a/b.js'), true);
  assert.equal(covers('src/**', 'lib/a.js'), false);
  assert.equal(covers('src/*', 'src/a.js'), true);
  assert.equal(covers('src/*', 'src/a/b.js'), false);
  assert.equal(covers('a/b.js', 'a/b.js'), true);
  assert.equal(covers('src/**/x', 'src/a/x'), null);
  assert.equal(covers('../x', 'x'), null);
  assert.equal(overlap('src/a.js', 'src/b.js'), false);
  assert.equal(overlap('src/**', 'src/b.js'), true);
  assert.equal(overlap('a/**/x', 'b/y'), true); // 扱えない形は重なる
});

test('GUARDS: 各ガードが単独で止める（陰性）', () => {
  for (const [name] of Object.entries(GUARDS)) {
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

test('check: 未知のガード名は例外（黙って通さない）', () => {
  assert.throws(() => check({ nodes: [], batch: [], limits: { workers: 1 } }, ['NOPE']));
});

// ---- 審査 B の判例 ------------------------------------------------------------

test('B-F1: covers の表（literal・deep・star の全組み合わせ）', () => {
  const T = [
    // outer, inner, 期待
    ['a/b', 'a/b', true], ['a/b', 'a/c', false], ['a/b', 'a/**', false], ['a/b', 'a/b*', false],
    ['src/**', 'src/x', true], ['src/**', 'src', true], ['src/**', 'srcx', false], ['src/**', 'src/**', true], ['src/**', 'src/a/**', true], ['src/**', 'srcx/**', false],
    ['src/**', 'src*', false], ['src/**', 'src/*', true], ['src/**', 'src/a*', true], ['src/**', 'srcx*', false], ['src/a/**', 'src/**', false],
    ['src/*', 'src/a', true], ['src/*', 'src/a/b', false], ['src/*', 'src/**', false], ['src/*', 'src/a*', true], ['src/*', 'src/a/*', false], ['src/*', 'src*', false],
    ['src*', 'src', true], ['src*', 'srcx', true], ['src*', 'src/x', false], ['src*', 'srcx*', true], ['src*', 'src/*', false], ['src*', 'src/**', false],
  ];
  for (const [o, i, want] of T) assert.equal(covers(o, i), want, `covers(${o}, ${i})`);
  assert.equal(covers('src/**', 'src*'), false, '審査の再現: src/** は src* を含まない（srcx/ や src-secret に一致するため）');
});

// 実際の文字列の一致と突き合わせる性質の試験（小さな語彙で候補のパスを総当たり）
const matches = (pt, s) => (pt.type === 'literal' ? s === pt.base
  : pt.type === 'deep' ? s === pt.base || s.startsWith(pt.base + '/')
    : s.startsWith(pt.base) && !s.slice(pt.base.length).includes('/'));
function strings(max, alphabet = ['a', 'b', '/']) {
  let cur = [''];
  const all = [''];
  for (let n = 0; n < max; n++) { cur = cur.flatMap((x) => alphabet.map((c) => x + c)); all.push(...cur); }
  return all;
}
test('B-F1: covers は実際の一致と突き合わせて正しい（健全性：true なら inner の一致はすべて outer に一致）', () => {
  const cands = strings(6).filter((s) => s !== '' && !s.startsWith('/') && !s.endsWith('/') && !s.includes('//'));
  const pats = [];
  for (const s of strings(3)) {
    if (s === '' || s.startsWith('/') || s.includes('//')) { if (s === '') pats.push('*'); continue; }
    if (!s.endsWith('/')) { pats.push(s); pats.push(s + '/**'); }
    pats.push(s + '*');
  }
  let trues = 0;
  for (const o of pats) for (const i of pats) {
    const po = parsePattern(o);
    const pi = parsePattern(i);
    assert.ok(po && pi, `${o} / ${i} が扱える形のはず`);
    const mi = cands.filter((c) => matches(pi, c));
    const brute = mi.every((c) => matches(po, c));
    const got = covers(o, i);
    if (got === true) { trues++; assert.ok(brute, `誤り: covers(${o}, ${i}) が true だが、含まれない文字列がある`); }
    // 完全性（候補の範囲で反例があれば false）
    if (!brute) assert.equal(got, false, `covers(${o}, ${i}) は false のはず`);
  }
  assert.ok(trues > 50, '真の組が十分にある');
});
test('B-F1: overlap は実際の一致と突き合わせて健全（false なら共通の一致する文字列がない）', () => {
  const cands = strings(6).filter((s) => s !== '' && !s.startsWith('/') && !s.endsWith('/') && !s.includes('//'));
  const pats = [];
  for (const s of strings(3)) {
    if (s === '' || s.startsWith('/') || s.includes('//')) { if (s === '') pats.push('*'); continue; }
    if (!s.endsWith('/')) { pats.push(s); pats.push(s + '/**'); }
    pats.push(s + '*');
  }
  for (const a of pats) for (const b of pats) {
    const pa = parsePattern(a);
    const pb = parsePattern(b);
    const common = cands.some((c) => matches(pa, c) && matches(pb, c));
    if (common) assert.equal(overlap(a, b), true, `overlap(${a}, ${b}) は true のはず`);
  }
});

test('B-F15: parsePattern は表記ゆれ・制御文字・NFD を扱えない形にする', () => {
  for (const bad of ['src//x', 'src/x/', 'src\\x', 'src/\u200bx', 'src/\u0000x', '/abs', 'a/../b', 'a/./b', ' a', 'a ', '', '**', 'a/**/b', 'a[1]', '!a', '?a', 'a{b}']) assert.equal(parsePattern(bad), null, JSON.stringify(bad));
  for (const ok of ['src/x', 'src/**', 'src/*', 'src*', 'a b/c', 'caf\u00e9/x']) assert.ok(parsePattern(ok), ok);
});
test('B-F15: overlap は大文字小文字を区別せず、扱えない形は重なる。包含は文字どおり', () => {
  assert.equal(overlap('src/x', 'Src/x'), true);
  assert.equal(overlap('src/x', 'src//x'), true);
  assert.equal(overlap('src/x', 'src/y'), false);
  assert.equal(covers('src/**', 'SRC/x'), false);
  assert.equal(resourcesOverlap(['a/b'], 'not-an-array'), true);
});

test('B-F2: check は生の nodes の形を必ず検査する（fail-closed）', () => {
  const blocked = N('a', { status: 'blocked' });
  for (const dep of ['a', null, undefined, 1, new Set(['a']), { 0: 'a' }]) {
    const r = check({ nodes: [blocked, N('b', { depends_on: dep })], batch: ['b'], limits: { workers: 2 } });
    assert.equal(r.ok, false, String(dep));
    assert.ok(r.violations.some((v) => v.guard === 'TG-NODE-SHAPE'), String(dep));
  }
  // 数値の id の循環
  assert.equal(check({ nodes: [{ ...N('x'), id: 1, depends_on: [2] }, { ...N('y'), id: 2, depends_on: [1] }], batch: [], limits: { workers: 1 } }).ok, false);
  // buildGraph も同じ形の検査
  assert.equal(buildGraph([{ ...N('x'), id: 1 }]).ok, false);
  assert.equal(buildGraph([N('a', { depends_on: 'b' }), N('b')]).ok, false);
  // 陽性の対照
  assert.equal(check({ nodes: [N('a', { status: 'merged' }), N('b', { depends_on: ['a'] })], batch: ['b'], limits: { workers: 1 } }).ok, true);
});

test('B-F14: 深い鎖でもスタックがあふれず、例外を投げない（反復）', () => {
  const mk = (n) => {
    const ns = [];
    for (let i = 0; i < n; i++) ns.push(N('n' + String(n - i).padStart(6, '0'), { depends_on: i ? ['n' + String(n - i + 1).padStart(6, '0')] : [], resources: [`r/${i}`] }));
    return ns;
  };
  const r = buildGraph(mk(MAX_NODES));
  assert.equal(r.ok, true);
  assert.equal(metrics(r.graph).depth, MAX_NODES);
  assert.doesNotThrow(() => recommend(r.graph, { workers: 4 }));
  for (const n of [MAX_NODES + 1, 5000, 20000]) {
    let b;
    assert.doesNotThrow(() => { b = buildGraph(mk(n)); });
    assert.equal(b.ok, false);
    assert.match(b.errors[0], /上限/);
  }
  assert.doesNotThrow(() => check({ nodes: mk(20000), batch: [], limits: { workers: 1 } }));
});

test('B-F14: 幅の大きいグラフでも recommend が現実的な時間で終わる', () => {
  const ns = [];
  for (let i = 0; i < MAX_NODES; i++) ns.push(N('n' + i, { resources: [`r${i}/a`, `r${i}/b`, `shared${i % 7}/x`] }));
  const g = buildGraph(ns).graph;
  const t = Date.now();
  const rec = recommend(g, { workers: 4 });
  assert.ok(Date.now() - t < 10000, `所要 ${Date.now() - t}ms`);
  assert.ok(rec.workers <= 4);
  // 全部が同じ資源を指す最悪の形でも、作業量の上限で終わる
  const ws = Array.from({ length: MAX_NODES }, (_, i) => N('w' + i, { resources: ['same/**'] }));
  const t2 = Date.now();
  const m = metrics(buildGraph(ws).graph);
  assert.ok(Date.now() - t2 < 10000, `所要 ${Date.now() - t2}ms`);
  assert.ok(m.conflicts > 0);
});

test('N1: TG-RESOURCE-DISJOINT は大きな組でも速い（2000 節 × 64 resources）。重なりは見つけ、作業量の上限を超えたら違反', () => {
  const mk = (n, f) => Array.from({ length: n }, (_, i) => N('n' + i, { resources: Array.from({ length: 64 }, (_, j) => f(i, j)) }));
  const ns = mk(2000, (i, j) => `d${i}/f${j}`);
  const batch = ns.map((n) => n.id);
  let t = Date.now();
  let r = check({ nodes: ns, batch, limits: { workers: 5 } }, ['TG-RESOURCE-DISJOINT']);
  assert.equal(r.ok, true);
  assert.ok(Date.now() - t < 5000, `所要 ${Date.now() - t}ms`);
  // 全 guard でも（WORKER-LIMIT が先に拒む形でも）重なりの検査が遅くならない
  t = Date.now();
  r = check({ nodes: ns, batch, limits: { workers: 5 } });
  assert.ok(Date.now() - t < 5000);
  assert.ok(r.violations.some((v) => v.guard === 'TG-WORKER-LIMIT'));
  // 1 組だけ重なる（最後の節が先頭の節の resource と同じ）
  const ns2 = mk(2000, (i, j) => `d${i}/f${j}`);
  ns2[1999].resources[63] = 'd0/f0';
  r = check({ nodes: ns2, batch, limits: { workers: 5000 } }, ['TG-RESOURCE-DISJOINT']);
  assert.equal(r.ok, false);
  assert.match(r.violations[0].reason, /n0×n1999|n1999×n0/);
  // 全節が同じ resources: 重なりを見つけて終わる
  t = Date.now();
  r = check({ nodes: mk(2000, () => 'same/**'), batch, limits: { workers: 5000 } }, ['TG-RESOURCE-DISJOINT']);
  assert.equal(r.ok, false);
  assert.ok(Date.now() - t < 5000);
  // 作業量の上限: 前置の関係が連鎖する literal（重なりは見つからないが走査が多い）
  const chain = Array.from({ length: 2000 }, (_, i) => N('c' + i, { resources: Array.from({ length: 64 }, (_, j) => 'p'.repeat(1 + ((i * 64 + j) % 120)) + '/' + (i * 64 + j)) }));
  t = Date.now();
  r = check({ nodes: chain, batch: chain.map((n) => n.id), limits: { workers: 5000 } }, ['TG-RESOURCE-DISJOINT']);
  assert.ok(Date.now() - t < 10000, `所要 ${Date.now() - t}ms`);
  assert.ok(r.ok === true || r.violations.length === 1);
});

test('N2: NFD の名前（濁点つき）は NFC と同じものとして扱う。角かっこは扱えない形のまま', () => {
  const nfd = '\u304b\u3099/x.md'; // か + 濁点
  const nfc = '\u304c/x.md';
  assert.ok(parsePattern(nfd));
  assert.deepEqual(parsePattern(nfd), parsePattern(nfc));
  assert.equal(covers(nfc, nfd), true);
  assert.equal(covers('\u304b\u3099/**', nfc), true);
  assert.equal(overlap(nfd, nfc), true);
  assert.equal(overlap(nfd, '\u304e/x.md'), false);
  assert.equal(parsePattern('src/app/[id]/page.tsx'), null);
  assert.equal(parsePattern('a/\u200d/b'), null);
  assert.equal(overlap('src/app/[id]/page.tsx', 'zzz/x'), true);
});
