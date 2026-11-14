// taskgraph の攻撃・良性のシナリオ（起草段階の試作）
import { GUARDS, check } from '../taskgraph.mjs';

export const MODULE = 'taskgraph';
export { GUARDS };

const N = (id, o = {}) => ({ id, status: 'ready', depends_on: [], resources: [`src/${id}/**`], approved: true, ...o });
const run = (ctx) => (guardNames) => {
  const r = check(ctx, guardNames);
  return { blocked: !r.ok, by: r.violations.map((v) => v.guard) };
};

export const SCENARIOS = [
  { id: 'TG-A1', kind: 'attack', title: '依存が循環している', expectGuards: ['TG-ACYCLIC'],
    run: run({ nodes: [N('A', { depends_on: ['B'], status: 'merged' }), N('B', { depends_on: ['A'], status: 'merged' }), N('C')], batch: ['C'], limits: { workers: 2 } }) },
  { id: 'TG-A2', kind: 'attack', title: '自己依存の節', expectGuards: ['TG-ACYCLIC'],
    run: run({ nodes: [N('A', { depends_on: ['A'], status: 'merged' }), N('C')], batch: ['C'], limits: { workers: 2 } }) },
  { id: 'TG-A3', kind: 'attack', title: '存在しない依存', expectGuards: ['TG-DEP-EXISTS'],
    run: run({ nodes: [N('A', { depends_on: ['Z'], status: 'merged' }), N('C')], batch: ['C'], limits: { workers: 2 } }) },
  { id: 'TG-A4', kind: 'attack', title: 'id の重複（後の節で先の節をすり替える）', expectGuards: ['TG-ID-UNIQUE'],
    run: run({ nodes: [N('A', { status: 'merged' }), N('A', { status: 'merged', resources: ['other/**'] }), N('C')], batch: ['C'], limits: { workers: 2 } }) },
  { id: 'TG-A5', kind: 'attack', title: 'グラフにない節を着手の組に入れる', expectGuards: ['TG-BATCH-IN-GRAPH'],
    run: run({ nodes: [N('A')], batch: ['A', 'GHOST'], limits: { workers: 3 } }) },
  { id: 'TG-A6', kind: 'attack', title: 'blocked の節を着手の組に入れる', expectGuards: ['TG-READY-STATUS'],
    run: run({ nodes: [N('A', { status: 'blocked' })], batch: ['A'], limits: { workers: 2 } }) },
  { id: 'TG-A7', kind: 'attack', title: '未承認の節を着手の組に入れる', expectGuards: ['TG-APPROVED'],
    run: run({ nodes: [N('A', { approved: false })], batch: ['A'], limits: { workers: 2 } }) },
  { id: 'TG-A8', kind: 'attack', title: '依存が未統合（review）の節を着手の組に入れる', expectGuards: ['TG-DEPS-MERGED'],
    run: run({ nodes: [N('A', { status: 'review' }), N('B', { depends_on: ['A'] })], batch: ['B'], limits: { workers: 2 } }) },
  { id: 'TG-A9', kind: 'attack', title: 'resources が重なる 2 節の並列', expectGuards: ['TG-RESOURCE-DISJOINT'],
    run: run({ nodes: [N('A', { resources: ['src/shared/**'] }), N('B', { resources: ['src/shared/util.js'] })], batch: ['A', 'B'], limits: { workers: 3 } }) },
  { id: 'TG-A10', kind: 'attack', title: '同時の数が上限を超える', expectGuards: ['TG-WORKER-LIMIT'],
    run: run({ nodes: [N('A'), N('B'), N('C')], batch: ['A', 'B', 'C'], limits: { workers: 2 } }) },
  { id: 'TG-A11', kind: 'attack', title: '作業中の節の分を数えずに上限いっぱいまで起こす', expectGuards: ['TG-WORKER-LIMIT'],
    run: run({ nodes: [N('A', { status: 'in_progress' }), N('B'), N('C')], batch: ['B', 'C'], limits: { workers: 2 } }) },
  { id: 'TG-B1', kind: 'benign', title: '依存が統合済みの節 1 つを逐次に着手',
    run: run({ nodes: [N('A', { status: 'merged' }), N('B', { depends_on: ['A'] })], batch: ['B'], limits: { workers: 1 } }) },
  { id: 'TG-B2', kind: 'benign', title: 'resources が重ならない 2 節を並列に着手',
    run: run({ nodes: [N('A'), N('B')], batch: ['A', 'B'], limits: { workers: 2 } }) },
  { id: 'TG-B3', kind: 'benign', title: '未承認の節があっても、依存しない節は着手できる（INV-12）',
    run: run({ nodes: [N('A', { approved: false }), N('B', { status: 'blocked' }), N('C', { depends_on: ['A'] }), N('D')], batch: ['D'], limits: { workers: 2 } }) },
  { id: 'TG-B4', kind: 'benign', title: '空の組（着手できる節がない）は通る',
    run: run({ nodes: [N('A', { status: 'review' })], batch: [], limits: { workers: 1 } }) },
];

// ---- 審査 B の判例（B-F2・B-F14・B-F15）----------------------------------------
const A = (id, title, expectGuards, ctx) => SCENARIOS.push({ id, kind: 'attack', title, expectGuards, run: run(ctx) });
const lim = { workers: 3 };

// B-F2: 配列でない depends_on を「依存なし」として通す（fail-open）／形の壊れた節
const blockedA = N('a', { status: 'blocked' });
A('TG-A12', 'B-F2: depends_on が文字列（未統合の a への依存を隠す）', ['TG-NODE-SHAPE'], { nodes: [blockedA, N('b', { depends_on: 'a' })], batch: ['b'], limits: lim });
A('TG-A13', 'B-F2: depends_on が null', ['TG-NODE-SHAPE'], { nodes: [blockedA, N('b', { depends_on: null })], batch: ['b'], limits: lim });
A('TG-A14', 'B-F2: depends_on が Set', ['TG-NODE-SHAPE'], { nodes: [blockedA, N('b', { depends_on: new Set(['a']) })], batch: ['b'], limits: lim });
A('TG-A15', 'B-F2: 数値の id の循環（文字列の id だけを見る循環の検査をすり抜ける）', ['TG-NODE-SHAPE'],
  { nodes: [{ ...N('x'), id: 1, depends_on: [2] }, { ...N('y'), id: 2, depends_on: [1] }, N('c')], batch: ['c'], limits: lim });
A('TG-A16', 'B-F2: risk が列挙の外', ['TG-NODE-SHAPE'], { nodes: [N('a', { risk: 'extreme' })], batch: ['a'], limits: lim });
A('TG-A17', 'B-F2: resources が文字列（配列でない）', ['TG-NODE-SHAPE'], { nodes: [N('a', { resources: 'src/**' })], batch: ['a'], limits: lim });
A('TG-A18', 'B-F2: status が大文字（Ready）', ['TG-NODE-SHAPE', 'TG-READY-STATUS'], { nodes: [N('a', { status: 'Ready' })], batch: ['a'], limits: lim });

// B-F14: 節の数の上限
A('TG-A19', 'B-F14: 節の数が上限（2000）を超える', ['TG-SIZE-LIMIT'],
  { nodes: Array.from({ length: 2001 }, (_, i) => N(`n${i}`)), batch: ['n0'], limits: lim });

// B-F15: resources の表記ゆれ（同じファイルを別の綴りで指して重なりを避ける）
const OV = (id, title, a, b) => A(id, title, ['TG-RESOURCE-DISJOINT'], { nodes: [N('A', { resources: [a] }), N('B', { resources: [b] })], batch: ['A', 'B'], limits: lim });
OV('TG-A20', 'B-F15: src/x と src//x', 'src/x', 'src//x');
OV('TG-A21', 'B-F15: src/x と src/x/', 'src/x', 'src/x/');
OV('TG-A22', 'B-F15: src/x と src\\x（バックスラッシュ）', 'src/x', 'src\\x');
OV('TG-A23', 'B-F15: src/x と Src/x（大文字小文字を区別しない FS）', 'src/x', 'Src/x');
OV('TG-A24', 'B-F15: NFC と NFD の同じ名前', 'café/x', 'café/x');
OV('TG-A25', 'B-F15: ゼロ幅文字を挟んだ名前', 'src/x', 'src/​x');
OV('TG-A26', 'B-F15: src/./x と src/x', 'src/./x', 'src/x');

SCENARIOS.push(
  { id: 'TG-B5', kind: 'benign', title: 'B-F15: 大文字小文字だけ違っても、別のディレクトリなら重ならない', run: run({ nodes: [N('A', { resources: ['src/a/**'] }), N('B', { resources: ['Lib/b/x.js'] })], batch: ['A', 'B'], limits: lim }) },
  { id: 'TG-B6', kind: 'benign', title: 'B-F2: 正しい形の節（risk つき）の組', run: run({ nodes: [N('A', { risk: 'low' }), N('B', { risk: 'mid', depends_on: [] })], batch: ['A', 'B'], limits: lim }) },
  { id: 'TG-B7', kind: 'benign', title: 'B-F14: 上限ちょうど（2000）の節の数は通る', run: run({ nodes: Array.from({ length: 2000 }, (_, i) => N(`n${i}`)), batch: ['n0', 'n1'], limits: lim }) },
);

SCENARIOS.push({ id: 'TG-B8', kind: 'benign', title: 'N2: NFD の濁点つきの名前でも、別の名前なら重ならない（日本語のファイル名）', run: run({ nodes: [N('A', { resources: ['\u304b\u3099/x.md'] }), N('B', { resources: ['\u304e/y.md'] })], batch: ['A', 'B'], limits: lim }) });
