// 権限の差分（authority-delta.mjs）の試験。本物の vgdd/kernel/capabilities.json を1か所だけ変えた版で分類を確かめる
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { authorityDelta, routeFor, check, GUARDS, formatDelta } from '../authority-delta.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REAL = path.resolve(HERE, '../../kernel/capabilities.json');
const CLI = path.resolve(HERE, '../bin/authority-delta.mjs');
const caps = JSON.parse(fs.readFileSync(REAL, 'utf8'));
// 法律の版を決め打ちにしない（版が上がるたびに試験が落ちないように、今の版から作る）
const VER = /^p(\d+)\.(\d+)\.(\d+)$/.exec(caps.kernel_version);
assert.ok(VER && Number(VER[3]) >= 1, `kernel_version の形：${caps.kernel_version}`);
const VER_UP = `p${VER[1]}.${VER[2]}.${Number(VER[3]) + 1}`;
const VER_DOWN = `p${VER[1]}.${VER[2]}.${Number(VER[3]) - 1}`;
const VER_SUFFIX = `${caps.kernel_version}a`;
const mut = (fn) => { const c = structuredClone(caps); fn(c); return c; };
const cap = (c, id) => c.capabilities.find((x) => x.id === id);
const inv = (c, id) => c.invariants.find((x) => x.id === id);

test('同じものどうしは変更なし・neutral・standard', () => {
  const d = authorityDelta(caps, structuredClone(caps));
  assert.equal(d.class, 'neutral');
  assert.equal(d.changes.length, 0);
  assert.equal(routeFor(d).lane, 'standard');
  assert.ok(check({ oldCaps: caps, newCaps: caps }).ok);
});

// [題, 変更, 期待する全体の分類]
const CASES = [
  ['allowed に役割を足す', (c) => cap(c, 'CAP-LAW-WRITE').allowed.push('worker'), 'loosening'],
  ['allowed から役割を外す', (c) => { cap(c, 'CAP-EVIDENCE-READ').allowed = ['owner', 'gate_runner', 'night_runner']; }, 'tightening'],
  ['drafting に役割を足す', (c) => cap(c, 'CAP-LAW-WRITE').drafting.push('executive_head'), 'loosening'],
  ['drafting から役割を外す', (c) => { cap(c, 'CAP-LAW-WRITE').drafting = []; }, 'tightening'],
  ['expect の deny → allow', (c) => { cap(c, 'CAP-LAW-WRITE').expect.worker = 'allow'; }, 'loosening'],
  ['expect の allow → deny', (c) => { cap(c, 'CAP-MERGE-REQUEST').expect.executive_head = 'deny'; }, 'tightening'],
  ['expect から役割の項目が消える', (c) => { delete cap(c, 'CAP-LAW-WRITE').expect.tester; }, 'loosening'],
  ['expect に役割を deny で足す', (c) => { cap(c, 'CAP-AGENT-OTHER').expect.worker = 'deny'; }, 'tightening'],
  ['probe の expect の allow → deny', (c) => { cap(c, 'CAP-MAIN-INTEGRATE').probes[3].expect.executive_head = 'deny'; }, 'tightening'],
  ['probe の expect に allow の上書きを足す', (c) => { cap(c, 'CAP-MAIN-INTEGRATE').probes[0].expect = { executive_head: 'allow' }; }, 'loosening'],
  ['probe の allow の上書きを外す（権限の deny に戻る）', (c) => { delete cap(c, 'CAP-MAIN-INTEGRATE').probes[3].expect; }, 'tightening'],
  ['enforced_by の層を減らす', (c) => { cap(c, 'CAP-LAW-WRITE').enforced_by = ['permission', 'hook', 'gate']; }, 'loosening'],
  ['enforced_by の層を増やす', (c) => cap(c, 'CAP-LINK').enforced_by.push('sandbox'), 'tightening'],
  ['enforced_by に promise を足すだけ', (c) => cap(c, 'CAP-LINK').enforced_by.push('promise'), 'neutral'],
  ['enforced_by を promise だけにする', (c) => { cap(c, 'CAP-LINK').enforced_by = ['promise']; }, 'loosening'],
  ['enforced_by に layers にない層の名前', (c) => cap(c, 'CAP-LINK').enforced_by.push('magic'), 'indeterminate'],
  ['probe の削除', (c) => cap(c, 'CAP-LAW-WRITE').probes.pop(), 'loosening'],
  ['probe の追加', (c) => cap(c, 'CAP-LINK').probes.push({ tool: 'Bash', command: 'ln -sf a b' }), 'tightening'],
  ['probe の中身の書き換え（削除＋追加）', (c) => { cap(c, 'CAP-LINK').probes[0].command = 'ln -s x y'; }, 'loosening'],
  ['scenario_tests の削除', (c) => { cap(c, 'CAP-STOP').scenario_tests = cap(c, 'CAP-STOP').scenario_tests.filter((x) => x !== 'K1'); }, 'loosening'],
  ['scenario_tests の追加', (c) => cap(c, 'CAP-STOP').scenario_tests.push('K9'), 'tightening'],
  ['verified_by の削除', (c) => { delete cap(c, 'CAP-ENV-READ').verified_by; }, 'loosening'],
  ['verified_by の書き換え', (c) => { cap(c, 'CAP-ENV-READ').verified_by = '別の確かめ方'; }, 'loosening'],
  ['known_gaps の追加', (c) => cap(c, 'CAP-LINK').known_gaps = ['新しく見つけた穴'], 'neutral'],
  ['known_gaps の削除', (c) => { delete cap(c, 'CAP-MAIN-INTEGRATE').known_gaps; }, 'indeterminate'],
  ['capability の削除', (c) => { c.capabilities = c.capabilities.filter((x) => x.id !== 'CAP-GIT-CONFIG'); }, 'loosening'],
  ['capability の追加（人とスクリプトだけ、AI は deny）', (c) => c.capabilities.push({ id: 'CAP-NEW', title: '新しい禁止', allowed: ['owner', 'gate_runner'], enforced_by: ['hook'], probes: [{ tool: 'Write', file_path: '{self}/x' }], expect: { worker: 'deny', executive_head: 'deny' } }), 'tightening'],
  ['capability の追加（allowed が空）', (c) => c.capabilities.push({ id: 'CAP-NEW', title: '誰にも許さない', allowed: [], enforced_by: ['hook'] }), 'tightening'],
  ['capability の追加（AI に許す）', (c) => c.capabilities.push({ id: 'CAP-NEW', title: '新しい権限', allowed: ['worker'], enforced_by: ['hook'] }), 'loosening'],
  ['capability の追加（AI の判定が allow）', (c) => c.capabilities.push({ id: 'CAP-NEW', title: '新しい権限', allowed: ['owner'], enforced_by: ['hook'], expect: { worker: 'allow' } }), 'loosening'],
  ['capability の題の書き換え', (c) => { cap(c, 'CAP-LAW-WRITE').title = '法律を書き換える（vgdd/ だけ）'; }, 'indeterminate'],
  ['capability の note だけの変更', (c) => { cap(c, 'CAP-JUDGE').note = '説明の言い換え'; }, 'neutral'],
  ['capability に規則にない項目', (c) => { cap(c, 'CAP-LINK').exempt = ['worker']; }, 'indeterminate'],
  ['allowed に新旧どちらの roles にもない役割名', (c) => cap(c, 'CAP-LINK').allowed.push('ghost'), 'indeterminate'],
  ['AI の役割の追加', (c) => { c.roles.helper = { kind: 'ai', identity: '補助' }; }, 'loosening'],
  ['ai+script の役割の追加', (c) => { c.roles.helper = { kind: 'ai+script', identity: '補助' }; }, 'loosening'],
  ['スクリプトの役割の追加', (c) => { c.roles.cron = { kind: 'script', identity: '定期実行' }; }, 'indeterminate'],
  ['参照のない役割の削除', (c) => { delete c.roles.constitutional_review; }, 'tightening'],
  ['参照の残る役割の削除', (c) => { delete c.roles.scribe; }, 'indeterminate'],
  ['役割の kind の変更', (c) => { c.roles.judge.kind = 'human'; }, 'indeterminate'],
  ['役割の identity の変更', (c) => { c.roles.worker.identity = '別の識別'; }, 'indeterminate'],
  ['役割の hook_input の変更', (c) => { c.roles.worker.hook_input.agent_type = 'wrk'; }, 'indeterminate'],
  ['役割の note だけの変更', (c) => { c.roles.owner.note = '言い換え'; }, 'neutral'],
  ['不変条件の enforced → partial', (c) => { inv(c, 'INV-01').status = 'partial'; }, 'loosening'],
  ['不変条件の partial → not_applicable', (c) => { inv(c, 'INV-03').status = 'not_applicable'; }, 'loosening'],
  ['不変条件の partial → enforced（判例あり）', (c) => { inv(c, 'INV-03').status = 'enforced'; }, 'tightening'],
  ['不変条件の not_applicable → partial（判例なし）', (c) => { inv(c, 'INV-09').status = 'partial'; }, 'indeterminate'],
  ['不変条件の判例の削除', (c) => inv(c, 'INV-01').tests.pop(), 'loosening'],
  ['不変条件の判例の追加', (c) => inv(c, 'INV-01').tests.push('C1:CAP-LINK'), 'tightening'],
  ['不変条件の削除', (c) => { c.invariants = c.invariants.filter((x) => x.id !== 'INV-05'); }, 'loosening'],
  ['不変条件の追加', (c) => c.invariants.push({ id: 'INV-13', title: '新しい約束', status: 'partial', tests: ['X:1'], gaps: ['穴'] }), 'tightening'],
  ['不変条件の gaps の追加', (c) => inv(c, 'INV-03').gaps.push('新しい穴'), 'neutral'],
  ['不変条件の gaps の削除', (c) => { inv(c, 'INV-07').gaps = inv(c, 'INV-07').gaps.slice(1); }, 'indeterminate'],
  ['不変条件の reason の書き換え', (c) => { inv(c, 'INV-09').reason = '別の理由'; }, 'indeterminate'],
  ['不変条件の title の書き換え', (c) => { inv(c, 'INV-01').title = '行政 AI は原則として権限を拡張しない'; }, 'indeterminate'],
  ['layers の変更', (c) => { c.layers.hook = '別の意味'; }, 'indeterminate'],
  ['schema の変更', (c) => { c.schema = 'vgdd.capabilities.v2'; }, 'indeterminate'],
  ['kernel_version だけの変更', (c) => { c.kernel_version = VER_UP; }, 'neutral'],
  ['最上位の note だけの変更', (c) => { c.note = '言い換え'; }, 'neutral'],
  ['規則にない最上位の項目', (c) => { c.overrides = { worker: 'all' }; }, 'indeterminate'],
];

for (const [title, fn, want] of CASES) {
  test(`1か所の変更：${title} → ${want}`, () => {
    const d = authorityDelta(caps, mut(fn));
    assert.equal(d.class, want, formatDelta(d));
    assert.ok(d.changes.length >= 1);
    // 経路と、ガード（通常の経路に乗ってよいか）が食い違わない
    const lane = routeFor(d).lane;
    assert.equal(lane, want === 'loosening' || want === 'indeterminate' ? 'full_legislative' : 'standard');
    assert.equal(check({ oldCaps: caps, newCaps: mut(fn) }).ok, lane === 'standard');
  });
}

test('参照のない役割を探す前提：constitutional_review はどの capability にも出てこない', () => {
  assert.ok(!JSON.stringify(caps.capabilities).includes('constitutional_review'));
});

test('promise の印を、強制の層を足さずに外すのは indeterminate、層に置き換えるのは締める', () => {
  const withPromise = mut((c) => cap(c, 'CAP-LINK').enforced_by.push('promise'));
  assert.equal(authorityDelta(withPromise, caps).class, 'indeterminate');
  const replaced = mut((c) => { cap(c, 'CAP-LINK').enforced_by = ['hook', 'sandbox']; });
  assert.equal(authorityDelta(withPromise, replaced).class, 'tightening');
});

test('並べ替えだけなら変更なし', () => {
  const r = mut((c) => {
    c.capabilities.reverse(); c.invariants.reverse();
    for (const x of c.capabilities) {
      for (const k of ['allowed', 'drafting', 'enforced_by', 'probes', 'scenario_tests', 'known_gaps']) if (Array.isArray(x[k])) x[k].reverse();
      if (x.expect) x.expect = Object.fromEntries(Object.entries(x.expect).reverse());
    }
    for (const v of c.invariants) for (const k of ['tests', 'gaps']) if (Array.isArray(v[k])) v[k].reverse();
    c.roles = Object.fromEntries(Object.entries(c.roles).reverse());
  });
  const d = authorityDelta(caps, r);
  assert.equal(d.class, 'neutral');
  assert.equal(d.changes.length, 0);
});

test('壊れた入力は例外でなく indeterminate（理由つき）', () => {
  const broken = [
    null, [], 'x', 42,
    mut((c) => { c.capabilities = {}; }),
    mut((c) => { c.capabilities.push(structuredClone(c.capabilities[0])); }),
    mut((c) => { cap(c, 'CAP-LINK').expect.worker = 'maybe'; }),
    mut((c) => { cap(c, 'CAP-LINK').allowed = 'owner'; }),
    mut((c) => { delete cap(c, 'CAP-LINK').allowed; }),
    mut((c) => { c.invariants.push(structuredClone(c.invariants[0])); }),
    mut((c) => { inv(c, 'INV-01').status = 'mostly'; }),
    mut((c) => { c.roles.worker.kind = 'robot'; }),
    mut((c) => { cap(c, 'CAP-LINK').probes.push(structuredClone(cap(c, 'CAP-LINK').probes[0])); }),
    mut((c) => { delete c.roles; }),
  ];
  for (const b of broken) {
    for (const [o, n] of [[caps, b], [b, caps]]) {
      const d = authorityDelta(o, n);
      assert.equal(d.class, 'indeterminate');
      assert.equal(d.changes[0].category, 'malformed');
      assert.ok(d.changes[0].reason.length > 0);
      assert.equal(routeFor(d).lane, 'full_legislative');
    }
  }
  assert.equal(authorityDelta(mut((c) => { c.schema = 'other'; }), caps).class, 'indeterminate');
});

test('緩める変更と締める変更が混ざれば loosening', () => {
  const n = mut((c) => { cap(c, 'CAP-LINK').enforced_by.push('sandbox'); cap(c, 'CAP-LAW-WRITE').allowed.push('worker'); inv(c, 'INV-01').tests.push('C1:X'); });
  const d = authorityDelta(caps, n);
  assert.equal(d.class, 'loosening');
  assert.equal(d.summary.loosening, 1);
  assert.equal(d.summary.tightening, 2);
});

test('indeterminate と loosening が混ざれば indeterminate（区別して報告）', () => {
  const n = mut((c) => { cap(c, 'CAP-LAW-WRITE').allowed.push('worker'); delete cap(c, 'CAP-MAIN-INTEGRATE').known_gaps; });
  const d = authorityDelta(caps, n);
  assert.equal(d.class, 'indeterminate');
  assert.equal(d.summary.loosening, 1);
  assert.equal(d.summary.indeterminate, 1);
});

test('routeFor：どちらの経路でもオーナーの承認が要り、自動採用の値はない。読めない差分は full_legislative', () => {
  for (const cls of ['neutral', 'tightening', 'loosening', 'indeterminate']) {
    const r = routeFor({ class: cls });
    assert.ok(r.requires.includes('owner_approval'));
    assert.ok(['full_legislative', 'standard'].includes(r.lane));
  }
  assert.equal(routeFor({ class: 'loosening' }).lane, 'full_legislative');
  assert.ok(routeFor({ class: 'indeterminate' }).requires.includes('constitutional_review'));
  assert.equal(routeFor(null).lane, 'full_legislative');
  assert.equal(routeFor({ class: 'auto' }).lane, 'full_legislative');
});

test('ガード：それぞれ自分の種類の変更だけで止まる（直交）', () => {
  const only = (n, want) => {
    const r = check({ oldCaps: caps, newCaps: n });
    assert.deepEqual(r.violations.map((v) => v.guard), [want]);
  };
  only(null, 'AD-WELLFORMED');
  only(mut((c) => cap(c, 'CAP-LAW-WRITE').allowed.push('worker')), 'AD-NO-GRANT');
  only(mut((c) => { cap(c, 'CAP-LAW-WRITE').enforced_by = ['permission', 'hook', 'gate']; }), 'AD-ENFORCEMENT-NO-WEAKEN');
  only(mut((c) => cap(c, 'CAP-LAW-WRITE').probes.pop()), 'AD-VERIFIER-MONOTONE');
  only(mut((c) => { inv(c, 'INV-01').status = 'partial'; }), 'AD-INVARIANT-NO-DOWNGRADE');
  only(mut((c) => { delete cap(c, 'CAP-MAIN-INTEGRATE').known_gaps; }), 'AD-NO-INDETERMINATE');
  // 陽性の対照：締めるだけ・影響なしは全ガードを通る
  assert.ok(check({ oldCaps: caps, newCaps: mut((c) => cap(c, 'CAP-LINK').probes.push({ tool: 'Bash', command: 'ln a b' })) }).ok);
  assert.ok(check({ oldCaps: caps, newCaps: mut((c) => { c.kernel_version = VER_UP; }) }).ok);
  // 知らないガード名は違反として扱う
  assert.equal(check({ oldCaps: caps, newCaps: caps }, ['AD-NOPE']).ok, false);
  assert.equal(Object.keys(GUARDS).length, 6);
});

test('CLI：終了コードと要約・--json', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vgdd-next-'));
  const w = (name, v) => { const f = path.join(dir, name); fs.writeFileSync(f, typeof v === 'string' ? v : JSON.stringify(v)); return f; };
  const run = (...a) => spawnSync(process.execPath, [CLI, ...a], { encoding: 'utf8' });
  const old = w('old.json', caps);
  let r = run(old, w('same.json', caps));
  assert.equal(r.status, 0); assert.match(r.stdout, /影響なし/);
  r = run(old, w('tight.json', mut((c) => cap(c, 'CAP-LINK').enforced_by.push('sandbox'))));
  assert.equal(r.status, 0); assert.match(r.stdout, /締める/);
  r = run(old, w('loose.json', mut((c) => cap(c, 'CAP-LAW-WRITE').allowed.push('worker'))));
  assert.equal(r.status, 3); assert.match(r.stdout, /緩める/); assert.match(r.stdout, /AD-NO-GRANT/);
  r = run(old, w('ind.json', mut((c) => { c.layers.hook = 'x'; })));
  assert.equal(r.status, 4);
  r = run(old, w('broken.json', '{"schema":'));
  assert.equal(r.status, 65);
  r = run(old);
  assert.equal(r.status, 65);
  r = run(old, path.join(dir, 'missing.json'));
  assert.equal(r.status, 65);
  r = run(old, w('loose2.json', mut((c) => cap(c, 'CAP-LAW-WRITE').allowed.push('worker'))), '--json');
  assert.equal(r.status, 3);
  const j = JSON.parse(r.stdout);
  assert.equal(j.class, 'loosening'); assert.equal(j.route.lane, 'full_legislative'); assert.equal(j.standard_lane_check.ok, false);
  fs.rmSync(dir, { recursive: true, force: true });
});

// ---- 審査で見つかった抜け道の判例（F1・F6・F11・F12） ----

test('F1：kernel_version の系統の変更・下げ・形の崩れは indeterminate、同じ系統の版の上がりだけ neutral', () => {
  const v = (x) => authorityDelta(caps, mut((c) => { if (x === undefined) delete c.kernel_version; else c.kernel_version = x; })).class;
  assert.equal(v('p0.3.9'), 'indeterminate'); // 系統を戻す（無効になった承認が復活しうる）
  assert.equal(v('p0.5.0'), 'indeterminate'); // 系統の付け替え
  assert.equal(v('p9.9.0'), 'indeterminate');
  assert.equal(v(VER_DOWN), 'indeterminate'); // 同じ系統の中の下げ
  assert.equal(v('p0.4'), 'indeterminate');
  assert.equal(v(undefined), 'indeterminate');
  assert.equal(v(VER_UP), 'neutral');
  assert.equal(v(VER_SUFFIX), 'neutral');
  assert.equal(check({ oldCaps: caps, newCaps: mut((c) => { c.kernel_version = 'p0.3.9'; }) }).violations[0].guard, 'AD-NO-INDETERMINATE');
});

test('F6：AI の役割に allow を与える capability への probe の追加は loosening（実効の判定で見る）', () => {
  const a = authorityDelta(caps, mut((c) => cap(c, 'CAP-SRC-WRITE-OWN').probes.push({ tool: 'Write', file_path: '{main}/vgdd/hooks/policy.mjs' })));
  assert.equal(a.class, 'loosening'); assert.equal(a.changes[0].category, 'grant');
  assert.equal(authorityDelta(caps, mut((c) => cap(c, 'CAP-SPEC-DRAFT').probes.push({ tool: 'Write', file_path: '{main}/CLAUDE.md' }))).class, 'loosening');
  // 陽性の対照：AI の役割すべてを deny で上書きした probe の追加は締める
  const deny = { worker: 'deny', tester: 'deny', executive_head: 'deny' };
  assert.equal(authorityDelta(caps, mut((c) => cap(c, 'CAP-SRC-WRITE-OWN').probes.push({ tool: 'Write', file_path: '{main}/vgdd/hooks/x.mjs', expect: deny }))).class, 'tightening');
});

test('F11：プロトタイプの名前（constructor・toString・valueOf・__proto__）で分類が逆にならない', () => {
  const base = mut((c) => { c.roles.constructor = { kind: 'ai', identity: 'x', hook_input: { agent_type: 'constructor', cwd: '{wt}' } }; cap(c, 'CAP-LAW-WRITE').expect.constructor = 'deny'; });
  const removed = structuredClone(base); delete cap(removed, 'CAP-LAW-WRITE').expect.constructor;
  assert.equal(authorityDelta(base, removed).class, 'loosening');
  assert.equal(authorityDelta(caps, mut((c) => c.capabilities.push({ id: 'CAP-X', title: 't', allowed: ['toString', 'hasOwnProperty'], enforced_by: ['hook'] }))).class, 'indeterminate');
  assert.notEqual(authorityDelta(caps, mut((c) => { cap(c, 'CAP-LAW-WRITE').expect.valueOf = 'allow'; })).class, 'neutral');
  assert.equal(authorityDelta(caps, mut((c) => cap(c, 'CAP-LINK').enforced_by.push('toString'))).class, 'indeterminate');
  assert.equal(authorityDelta(caps, mut((c) => { c.invariants[0].status = 'constructor'; })).changes[0].category, 'malformed');
  const proto = JSON.parse(JSON.stringify(caps).replace('"id":"CAP-LINK"', '"__proto__":{"allowed":["worker"]},"id":"CAP-LINK"'));
  assert.equal(authorityDelta(caps, proto).class, 'indeterminate');
});

test('F12：適合性テストで実行されない probe・上書きは確かめ方に数えない（neutral）。allow の上書きは緩める', () => {
  const a = authorityDelta(caps, mut((c) => { cap(c, 'CAP-SPEC-ENACT').probes = [{ tool: 'Bash', command: 'true' }]; }));
  assert.equal(a.class, 'neutral'); assert.match(a.changes[0].reason, /実行されない/);
  const b = authorityDelta(caps, mut((c) => { cap(c, 'CAP-MAIN-INTEGRATE').probes[0].expect = { judge: 'deny' }; }));
  assert.equal(b.class, 'neutral'); assert.match(b.changes[0].reason, /実行されない/);
  assert.equal(authorityDelta(caps, mut((c) => { cap(c, 'CAP-MAIN-INTEGRATE').probes[0].expect = { judge: 'allow' }; })).class, 'loosening');
  // 陽性の対照：実行される役割の deny の上書きは締める
  assert.equal(authorityDelta(caps, mut((c) => { cap(c, 'CAP-MERGE-REQUEST').probes[0].expect = { executive_head: 'deny' }; })).class, 'tightening');
});

test('再審査：kernel_version の先頭の 0（p0.4.015）は形の崩れとして indeterminate', () => {
  assert.equal(authorityDelta(caps, mut((c) => { c.kernel_version = 'p0.4.015'; })).class, 'indeterminate');
  assert.equal(authorityDelta(caps, mut((c) => { c.kernel_version = 'p0.4.20'; })).class, 'neutral');
});
