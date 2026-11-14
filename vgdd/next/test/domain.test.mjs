import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { validateDomainPack, check, GUARDS, workItemIdProblem, JUDGE_INPUTS, AUDIT_EXECUTABLES } from '../domain.mjs';
import { SCENARIOS, base } from '../bench/scenarios-domain.mjs';

const load = (n) => JSON.parse(fs.readFileSync(new URL(`../domains/${n}.json`, import.meta.url), 'utf8'));

test('同梱の 2 つのパックが検査に通る（陽性）', () => {
  for (const n of ['software-dev', 'research-report']) {
    const r = validateDomainPack(load(n));
    assert.equal(r.ok, true, `${n}: ${JSON.stringify(r.violations)}`);
  }
});

test('software-dev: 関門を持たない段を not_implemented で区別し、関門の数に数えない', () => {
  const p = load('software-dev');
  const notImpl = p.lifecycle.filter((s) => s.status === 'not_implemented').map((s) => s.stage);
  assert.deepEqual(notImpl, ['企画', '設計', '運用', '保守', '廃止']);
  assert.ok(p.lifecycle.filter((s) => s.status === 'not_implemented').every((s) => s.gate === 'none'));
  assert.ok(validateDomainPack(p).warnings.some((w) => /未実装の段/.test(w)));
  // not_implemented の段にだけ approval があるパックは「人の承認なし」になる
  const q = structuredClone(p);
  for (const s of q.lifecycle) if (s.status !== 'not_implemented' && s.gate === 'approval') s.gate = 'judicial';
  assert.ok(check({ pack: q }).violations.some((v) => v.guard === 'DP-HUMAN-APPROVAL'));
});

test('research-report: 実在しない例であることを公開している', () => {
  const p = load('research-report');
  assert.ok(p.disclosures.some((d) => /実際に仕事を回したことはない/.test(d)));
  assert.ok(p.disclosures.some((d) => /実在しない/.test(d)));
});

test('司法を無効にするパックは違反（陰性）', () => {
  const p = base();
  p.judiciary.min_judges = 0;
  const r = validateDomainPack(p);
  assert.equal(r.ok, false);
  assert.ok(r.violations.some((v) => v.guard === 'DP-JUDICIARY-ON'));
});

test('関門のないパック（全段 none）は違反', () => {
  const p = base();
  for (const s of p.lifecycle) { s.gate = 'none'; }
  const r = validateDomainPack(p);
  assert.equal(r.ok, false);
  for (const g of ['DP-GATE-BEFORE-INTEGRATE', 'DP-HUMAN-APPROVAL', 'DP-JUDICIARY-ON']) assert.ok(r.violations.some((v) => v.guard === g), g);
});

test('行政の説明の入力名はゆれても止める（陰性）／正当な入力は止めない（陽性）', () => {
  for (const bad of ['worker_report', 'commit_message', 'conversation_log', 'rationale', 'Worker-Summary', 'self_assessment']) {
    const p = base();
    p.judiciary.inputs = ['diff', bad];
    assert.ok(check({ pack: p }).violations.some((v) => v.guard === 'DP-JUDGE-INPUT'), bad);
  }
  for (const ok of ['diff', 'acceptance', 'audit_results', 'document_diff', 'source_excerpts']) {
    const p = base();
    p.judiciary.inputs = [ok];
    assert.ok(!check({ pack: p }).violations.some((v) => v.guard === 'DP-JUDGE-INPUT'), ok);
  }
});

test('監査: シェルの文字列・sh -c は違反。sandbox が true でなければ違反（B-F16 で警告から違反に）', () => {
  const p = base();
  p.audits[0].command = 'npm ci';
  assert.ok(check({ pack: p }).violations.some((v) => v.guard === 'DP-AUDIT-SHELL'));
  const q = base();
  q.audits[0].command = ['/bin/bash', '-c', 'npm ci'];
  assert.ok(check({ pack: q }).violations.some((v) => v.guard === 'DP-AUDIT-SHELL'));
  const r = base();
  r.audits[0].sandbox = false;
  const v = validateDomainPack(r);
  assert.equal(v.ok, false);
  assert.ok(v.violations.some((x) => x.guard === 'DP-AUDIT-SANDBOX'));
});

test('決定論的な監査がなければ公開が必須。公開すれば通る', () => {
  const p = base();
  p.audits = [];
  assert.equal(validateDomainPack(p).ok, false);
  p.disclosures.push('このパックは決定論的な監査を持たない。約束だけの部分は人と司法に頼る');
  assert.equal(validateDomainPack(p).ok, true);
  const q = base();
  q.audits = [{ id: 'x', command: ['node', 'x.mjs'], required: false, sandbox: true }];
  assert.equal(validateDomainPack(q).ok, false, '必須でない監査だけでは公開が要る');
});

test('protected: vgdd/** を外すと違反', () => {
  const p = base();
  p.protected = ['vgdd/next/domains/**'];
  assert.ok(check({ pack: p }).violations.some((v) => v.guard === 'DP-PROTECTED-CORE'));
});

test('核の欄・未知の欄は違反（別のガード）', () => {
  for (const k of ['roles', 'capabilities', 'budget', 'stop']) {
    const p = base();
    p[k] = {};
    const r = check({ pack: p });
    assert.ok(r.violations.some((v) => v.guard === 'DP-FORBIDDEN-FIELD'), k);
    assert.ok(!r.violations.some((v) => v.guard === 'DP-UNKNOWN-FIELD'), k);
  }
  const p = base();
  p.extra = 1;
  assert.ok(check({ pack: p }).violations.some((v) => v.guard === 'DP-UNKNOWN-FIELD'));
});

test('票の ID の宣言（B-F16。語彙で正規表現の方式から宣言の形に替えた）: { prefix, digits } だけ。正規表現・範囲外・長すぎる・知らない欄は違反', () => {
  assert.equal(workItemIdProblem({ prefix: 'T-', digits: [3, 4] }), null);
  assert.equal(workItemIdProblem({ prefix: 'ABC-', digits: [3, 3] }), null);
  for (const bad of ['^T-[0-9]{3,4}$', null, {}, { prefix: '^(a+)+$', digits: [3, 4] }, { prefix: '(', digits: [1, 2] }, { prefix: 'T-', digits: [4, 3] }, { prefix: 'T-', digits: [0, 3] }, { prefix: 'T-', digits: [99, 99] }, { prefix: 'T-', digits: [3] }, { prefix: '', digits: [1, 2] }, { prefix: 'T-', digits: [1, 2], pattern: '.*' }, { prefix: '1-', digits: [1, 2] }]) assert.notEqual(workItemIdProblem(bad), null, JSON.stringify(bad));
  assert.equal(workItemIdProblem({ prefix: 'a'.repeat(80), digits: [1, 2] }) !== null, true);
  // 許可された構文は、どんな入力でも線形時間で終わる
  const re = new RegExp('^[0-9]{3,4}-[a-z]{1,10}$');
  const t = Date.now(); re.test('1'.repeat(10000) + '!'); assert.ok(Date.now() - t < 100);
});

test('壊れた入力でも落ちず拒否する（fail-closed）', () => {
  for (const bad of [null, undefined, 'x', [], 1, {}]) assert.equal(validateDomainPack(bad).ok, false);
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
  assert.throws(() => check({ pack: {} }, ['NOPE']));
});

// ---- 審査 B の判例 ------------------------------------------------------------

test('B-F5: 司法の入力は許可リスト。名前を変えた行政の説明は通らない', () => {
  for (const bad of ['report', 'summary', 'worker_output', 'commit_log', 'pr_description', 'worker.report', 'agent_statement', 'narrative', 'worker_report', 'Diff', 'diff ', 'author_comment', '']) {
    const p = base();
    p.judiciary.inputs = ['diff', bad];
    assert.ok(check({ pack: p }).violations.some((v) => v.guard === 'DP-JUDGE-INPUT'), JSON.stringify(bad));
  }
  for (const ok of JUDGE_INPUTS) {
    const p = base();
    p.judiciary.inputs = [ok];
    assert.ok(!check({ pack: p }).violations.some((v) => v.guard === 'DP-JUDGE-INPUT'), ok);
  }
  const p = base();
  p.judiciary.inputs = [];
  assert.ok(check({ pack: p }).violations.some((v) => v.guard === 'DP-JUDGE-INPUT'));
});

test('B-F6: protected は扱える形だけ。否定・.. ・先頭の / ・括弧は違反（核を外せない）', () => {
  for (const bad of ['!vgdd/**', '!**', '../x', '/abs/**', 'a[bc]', 'a?', '{a,b}', 'a//b', 'a/', ' a', 'vgdd/\u200b**']) {
    const p = base();
    p.protected.push(bad);
    assert.ok(check({ pack: p }).violations.some((v) => v.guard === 'DP-PROTECTED-CORE'), JSON.stringify(bad));
  }
  for (const ok of ['docs/laws/**', 'secrets*', 'config/prod.json']) {
    const p = base();
    p.protected.push(ok);
    assert.equal(validateDomainPack(p).ok, true, ok);
  }
});

test('B-F7: 監査の command は許可リスト（実行ファイル・副命令・評価フラグ・シェルの名前）', () => {
  assert.deepEqual(AUDIT_EXECUTABLES, ['npm', 'node']);
  const bad = [
    ['env', 'sh', '-c', 'x'], ['node', '-e', 'x'], ['node', '--eval=x'], ['node', '-p', '1'], ['node', '-r', './x.js', 'a.mjs'], ['python3', '-c', 'x'], ['npx', 'x'],
    ['npm', 'exec', '--', 'x'], ['npm', 'x'], ['npm', 'run-script', 'test'], ['npm', '-s', 'run', 'test'], ['find', '.', '-exec', 'sh'], ['sudo', 'npm', 'ci'], ['time', 'npm', 'ci'], ['xargs', 'npm'],
    ['busybox', 'sh'], ['bash.exe', '-c', 'x'], ['sh '], ['\u200bsh'], ['NPM', 'ci'], ['/usr/bin/npm', 'ci'], ['./node', 'a.mjs'], ['perl', '-e', 'x'], [], [''], [1], 'npm ci', null,
    ['npm', 'run', 'test', 'bash'], ['npm', 'run', 'test', '/bin/sh'], ['node', 'tools/a.mjs', '--eval=x'], ['node', '../a.mjs'], ['node', '/a.mjs'], ['node', 'a.txt'], ['npm', 'ci', '-pe'],
  ];
  for (const c of bad) {
    const p = base();
    p.audits = [{ id: 'x', command: c, required: true, sandbox: true }];
    const r = validateDomainPack(p);
    assert.equal(r.ok, false, JSON.stringify(c));
    assert.ok(r.violations.some((v) => v.guard === 'DP-AUDIT-SHELL' || v.guard === 'DP-SHAPE'), JSON.stringify(c));
  }
  for (const c of [['npm', 'ci', '--no-fund', '--no-audit'], ['npm', 'run', '-s', 'test'], ['npm', 'test'], ['node', 'tools/check.mjs'], ['node', 'tools/check.mjs', '--strict', '--max-chars', '20000']]) {
    const p = base();
    p.audits = [{ id: 'x', command: c, required: true, sandbox: true }];
    assert.equal(validateDomainPack(p).ok, true, JSON.stringify(c));
  }
});

test('B-F16: judiciary の弱体化（distinct_lineage false・巨大な min_judges・任意の categories）は違反', () => {
  const t = (f) => { const p = base(); f(p); return check({ pack: p }).violations.some((v) => v.guard === 'DP-JUDICIARY-ON'); };
  assert.ok(t((p) => { p.judiciary.distinct_lineage = false; }));
  assert.ok(t((p) => { p.judiciary.min_judges = 1000; }));
  assert.ok(t((p) => { p.judiciary.min_judges = 6; }));
  assert.ok(t((p) => { p.judiciary.categories = ['anything']; }));
  assert.ok(t((p) => { p.judiciary.categories = []; }));
  assert.ok(!t((p) => { p.judiciary.min_judges = 5; }));
});

test('B-F16: 入れ子の禁止の欄・未知の欄は、各階層の許可リストで違反', () => {
  const g = (f) => { const p = base(); f(p); return new Set(check({ pack: p }).violations.map((v) => v.guard)); };
  assert.ok(g((p) => { p.judiciary.roles = {}; }).has('DP-FORBIDDEN-FIELD'));
  assert.ok(g((p) => { p.audits[0].permissions = []; }).has('DP-FORBIDDEN-FIELD'));
  assert.ok(g((p) => { p.work_item.budget = 1; }).has('DP-FORBIDDEN-FIELD'));
  assert.ok(g((p) => { p.lifecycle[0].Hooks = []; }).has('DP-FORBIDDEN-FIELD'));
  assert.ok(g((p) => { p.Roles = {}; }).has('DP-FORBIDDEN-FIELD'));
  assert.ok(g((p) => { p.judiciary.extra = 1; }).has('DP-UNKNOWN-FIELD'));
  assert.ok(g((p) => { p.audits[0].timeout = 1; }).has('DP-UNKNOWN-FIELD'));
  assert.ok(g((p) => { p.artifact.x = 1; }).has('DP-UNKNOWN-FIELD'));
  assert.ok(g((p) => { p.lifecycle[0].x = 1; }).has('DP-UNKNOWN-FIELD'));
  assert.ok(g((p) => { p.work_item.x = 1; }).has('DP-UNKNOWN-FIELD'));
  // __proto__ を自前の欄に持つ JSON も未知の欄
  const q = JSON.parse(JSON.stringify(base()).replace('{', '{"__proto__":{"roles":{}},'));
  assert.equal(validateDomainPack(q).ok, false);
});

test('B-F16: どんな入力でも例外を投げず違反を返す', () => {
  const weird = [];
  const mutate = (f) => { const p = base(); f(p); weird.push(p); };
  mutate((p) => { p.audits[0].command = []; });
  mutate((p) => { p.audits = [null, 1, 'x', []]; });
  mutate((p) => { p.lifecycle = [null, 1, {}, []]; });
  mutate((p) => { p.judiciary = null; });
  mutate((p) => { p.judiciary.inputs = [null, {}, 1]; });
  mutate((p) => { p.judiciary.categories = [null, {}]; });
  mutate((p) => { p.protected = [null, 1, {}]; });
  mutate((p) => { p.work_item = []; });
  mutate((p) => { p.work_item.id = 5; });
  mutate((p) => { p.disclosures = [1, null]; });
  mutate((p) => { p.audits[0].command = [Symbol('x')]; });
  weird.push({ get schema() { throw new Error('boom'); } });
  const circ = base(); circ.self = circ; weird.push(circ);
  for (const p of weird) {
    let r;
    assert.doesNotThrow(() => { r = validateDomainPack(p); });
    assert.equal(r.ok, false);
    assert.doesNotThrow(() => check({ pack: p }));
  }
});

test('B-F16: 決定論的な監査がないときの公開は決まった文で始まる必要がある', () => {
  const p = base();
  p.audits = [];
  p.disclosures = ['決定論的な監査があるので、ないとは言えない'];
  assert.equal(validateDomainPack(p).ok, false);
  p.disclosures = ['このパックは決定論的な監査を持たない。人と司法に頼る'];
  assert.equal(validateDomainPack(p).ok, true);
});
