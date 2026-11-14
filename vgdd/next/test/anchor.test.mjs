// 外部への固定（anchor.mjs）の試験：外に何も送らない部分。止めるべきものが止まり、通すべきものが通る（陽性の対照）
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Refused, canonical, sha256 } from '../lib/chain.mjs';
import * as MOD from '../anchor.mjs';
import {
  openAnchors, GUARDS, check, RULES, anchorOf, buildManifest, checkGrowth, compare, readSources, normalizeConfig, normSourceName, pathProblem,
  normReceipt, manifestProblem, replay, DEFAULT_LIMITS,
} from '../anchor.mjs';
import {
  A, tmp, rm, world, rechain, rechainAnchors, writePlain, writeDir, writeToolCalls, appendPlain, benchAnchor, SCENARIOS,
} from '../bench/scenarios-anchor.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const S = (c) => `sha256:${c.repeat(64).slice(0, 64)}`;
const refusedBy = (fn, guard) => {
  try { fn(); } catch (e) {
    assert.ok(e instanceof Refused, String(e));
    assert.equal(e.code, 'guard_violation');
    if (guard) assert.ok(e.violations.some((v) => v.guard === guard), `${guard} で止まるはず：${e.message}`);
    return e;
  }
  return assert.fail(`止まるはずが通った（${guard}）`);
};
function withWorld(fn, n = 20) { const dir = tmp(); try { return fn(world(dir, n), dir); } finally { rm(dir); } }
const srcOf = (res, name) => res.sources.find((s) => s.name === name);
const guardsOf = (v) => [...new Set(v.violations.map((x) => x.guard))];

// ---------------------------------------------------------------------------
test('この部品は外部のコマンドも通信も使わない（ソースに child_process・net・http・fetch・exec がない）', () => {
  const src = fs.readFileSync(path.join(HERE, '../anchor.mjs'), 'utf8');
  const code = src.split('\n').filter((l) => !l.trim().startsWith('//') && !l.trim().startsWith('*')).join('\n');
  for (const bad of ['child_process', 'node:net', 'node:http', 'node:https', 'node:dgram', 'node:dns', 'fetch(', 'execFile', 'spawn(', 'exec(', 'XMLHttpRequest']) assert.ok(!code.includes(bad), `${bad} を使っている`);
  const imports = [...src.matchAll(/from '([^']+)'/g)].map((m) => m[1]);
  assert.deepEqual(imports.sort(), ['./lib/chain.mjs', './lib/vocab.mjs', 'node:crypto', 'node:fs', 'node:path'].sort());
});

test('ガード：全ガードに名前があり、check は例外を投げず、知らないガード名は違反として返す', () => {
  assert.equal(Object.keys(GUARDS).length, 24);
  for (const [k, f] of Object.entries(GUARDS)) assert.equal(typeof f, 'function', k);
  const r = check({ op: 'snapshot' }, ['AN-NO-SUCH']);
  assert.equal(r.ok, false); assert.equal(r.violations[0].reason, '知らないガード名');
  assert.doesNotThrow(() => check(null));
  assert.doesNotThrow(() => check({}));
  assert.equal(check({ op: 'verify', findings: [] }).ok, true);
});

// ---------------------------------------------------------------------------
test('名前・パス・設定の許可リスト（NFKC・小文字化・重複・上限）', () => {
  assert.equal(normSourceName(' Tool_Calls '), 'tool_calls');
  assert.equal(normSourceName('ｔｏｏｌ_calls'), 'tool_calls');
  for (const bad of ['', 'a b', '_x', '9a', 'a-b', 'a'.repeat(41), null, 5, '__proto__', 'a\u200b']) assert.equal(normSourceName(bad), null, String(bad));
  assert.equal(normSourceName('constructor'), 'constructor');
  assert.equal(pathProblem('/a/b/c.jsonl'), null);
  for (const bad of ['a/b', './a', '/a/../b', '/a/./b', '/a//b', '/a/b/', '/', '', '/a\u0000b', '/ａ/b', 'C:\\x', null, 5]) assert.ok(pathProblem(bad), String(bad));
  const ok = normalizeConfig({ sources: [{ name: 'B', path: '/x/b', kind: 'plain' }, { name: 'a', path: '/x/a', kind: 'chained', scheme: 'ledger' }] });
  assert.equal(ok.ok, true); assert.deepEqual(ok.sources.map((s) => s.name), ['a', 'b']);
  const dup = normalizeConfig({ sources: [{ name: 'a', path: '/x/a', kind: 'plain' }, { name: 'Ａ', path: '/x/b', kind: 'plain' }] });
  assert.equal(dup.ok, false);
  assert.equal(normalizeConfig({ sources: [{ name: 'a', path: '/x/A', kind: 'plain' }, { name: 'b', path: '/x/a', kind: 'plain' }] }).ok, false, '大文字小文字だけ違う同じパス');
  assert.equal(normalizeConfig({ sources: [{ name: 'a', path: '/x/a', kind: 'chained' }] }).ok, false, 'chained に scheme が要る');
  assert.equal(normalizeConfig({ sources: [{ name: 'a', path: '/x/a', kind: 'plain', scheme: 'ledger' }] }).ok, false, 'plain に scheme は付けられない');
  assert.equal(normalizeConfig({ sources: [{ name: 'a', path: '/x/a', kind: 'plain', extra: 1 }] }).ok, false);
  assert.equal(normalizeConfig({ sources: 'x' }).ok, false);
  assert.equal(normalizeConfig({ sources: [], limits: { max_sources: 0 } }).ok, false);
  assert.equal(normalizeConfig({ sources: [], limits: { nosuch: 1 } }).ok, false);
  assert.equal(normalizeConfig({ sources: [], limits: { max_sources: 1.5 } }).ok, false);
  assert.equal(normalizeConfig(null).ok, false);
  assert.equal(normalizeConfig({ sources: [] }, '/x').ok, true, '記録が 1 つもない設定も許す');
  assert.equal(normalizeConfig({ sources: [{ name: 'a', path: '/x/anchors.jsonl.head', kind: 'plain' }] }, '/x/anchors.jsonl').ok, false);
});

// ---------------------------------------------------------------------------
test('manifest と anchor：形・決定性・nonce・正規形（キーの順序に依らない）', () => withWorld((w) => {
  const an = w.open(); const s = an.snapshot(A.runner);
  assert.match(s.anchor, /^sha256:[0-9a-f]{64}$/);
  const st = an.state(); const m = st.anchors[0].manifest;
  assert.equal(anchorOf(m), s.anchor);
  const rev = (v) => (Array.isArray(v) ? v.map(rev) : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).reverse().map((k) => [k, rev(v[k])])) : v);
  const reordered = rev(m);
  assert.notEqual(JSON.stringify(reordered), JSON.stringify(m));
  assert.equal(anchorOf(reordered), s.anchor, 'キーの順序に依らない');
  assert.equal(m.sources.length, 7);
  assert.deepEqual(m.sources.map((x) => x.name), [...m.sources.map((x) => x.name)].sort());
  assert.match(m.nonce, /^[0-9a-f]{64}$/); assert.equal(m.prev_manifest, null); assert.equal(m.v, 1);
  assert.equal(manifestProblem(m, s.anchor), null);
  assert.ok(manifestProblem({ ...m, extra: 1 }, s.anchor));
  assert.ok(manifestProblem({ ...m, nonce: 'zz' }, s.anchor));
  assert.ok(manifestProblem({ ...m, taken_at: 'yesterday' }, s.anchor));
  assert.ok(manifestProblem(m, S('0')), 'anchor が違う');
  const tc = m.sources.find((x) => x.name === 'tool_calls');
  assert.equal(tc.lines, 20); assert.equal(tc.chain.ok, true); assert.equal(tc.chain.lines_verified, 20); assert.equal(tc.bytes, fs.statSync(w.files.tool_calls).size);
  assert.equal(tc.prefix_sha256, `sha256:${sha256(fs.readFileSync(w.files.tool_calls, 'utf8'))}`, '先頭 bytes までの SHA-256');
  const lastLine = fs.readFileSync(w.files.tool_calls, 'utf8').split('\n').filter(Boolean).pop();
  assert.equal(tc.tail_sha256, `sha256:${sha256(lastLine)}`);
  const dir = m.sources.find((x) => x.name === 'verdicts');
  assert.equal(dir.count, 5); assert.equal(dir.entries[0][1], 'f');
  // nonce が違えば、同じ状態でも anchor は違う（辞書による照合を防ぐ）
  const a2 = w.open({ nonce: () => 'ab'.repeat(32) }).snapshot(A.runner);
  assert.notEqual(a2.anchor, s.anchor);
}));

test('記録の内容・件数・パスは anchor から分からない：externalView は anchor と時刻だけ', () => {
  const dir = tmp();
  try {
    const w = world(dir);
    // 目印の文字列を、名前・パス・内容に入れる
    const markDir = path.join(dir, 'SECRETDIR'); fs.mkdirSync(markDir);
    const f = path.join(markDir, 'SECRETFILE.jsonl'); fs.writeFileSync(f, '{"x":"SECRETCONTENT"}\n'.repeat(37));
    const an = w.open({ sources: [{ name: 'secretname', path: f, kind: 'plain' }] });
    const s = an.snapshot(A.runner);
    const v = an.externalView(s.anchor);
    assert.deepEqual(Object.keys(v).sort(), ['anchor', 'recorded_at', 'schema']);
    const text = JSON.stringify(v) + JSON.stringify(s.external);
    for (const mark of ['SECRET', 'secretname', 'secretfile', '37', 'jsonl', 'prefix', 'bytes', 'lines']) assert.ok(!text.toLowerCase().includes(mark.toLowerCase()), `${mark} が外に出る`);
    assert.equal(v.anchor, s.anchor); assert.ok(!Object.isExtensible(v));
    assert.deepEqual(Object.keys(s.external).sort(), ['anchor', 'recorded_at', 'schema']);
    refusedByCode(() => an.externalView(S('1')), 'unknown_anchor');
    refusedByCode(() => an.externalView(undefined), 'unknown_anchor');
    refusedByCode(() => an.externalView({ toString: () => s.anchor }), 'unknown_anchor');
  } finally { rm(dir); }
});
function refusedByCode(fn, code) { try { fn(); } catch (e) { assert.ok(e instanceof Refused); assert.equal(e.code, code); return; } assert.fail(`${code} で止まるはず`); }

test('記録が壊れている（鎖が破れた）ときは、externalView も出さない', () => withWorld((w) => {
  const an = w.open(); const s = an.snapshot(A.runner);
  const l = fs.readFileSync(w.anchorsFile, 'utf8').split('\n'); const o = JSON.parse(l[0]); o.at = 'x'; l[0] = JSON.stringify(o); fs.writeFileSync(w.anchorsFile, l.join('\n'));
  refusedByCode(() => an.externalView(s.anchor), 'record_unsound');
}));

// ---------------------------------------------------------------------------
test('良性：伸びただけなら、何度 snapshot しても、全部の anchor が全部の記録で一致する', () => withWorld((w) => {
  const an = w.open();
  for (let i = 0; i < 4; i += 1) { an.snapshot(A.runner); w.grow(3); }
  const r = an.snapshot(A.runner);
  assert.deepEqual(r.regressions, []); assert.equal(r.flagged, false);
  const v = an.verify();
  assert.equal(v.ok, true, JSON.stringify(v.findings)); assert.equal(v.anchors_checked, 5);
  for (const a of v.anchors) for (const s of a.sources) assert.equal(s.status, 'match', `${a.seq} ${s.name}`);
  assert.equal(v.receipts_verified, false);
  // 前の anchor との鎖
  const st = an.state();
  st.anchors.forEach((a, i) => assert.equal(a.manifest.prev_manifest, i ? st.anchors[i - 1].anchor : null));
}));

test('良性：判定のファイルが足されただけなら一致する。書き換えと削除は検出する', () => withWorld((w) => {
  const an = w.open(); an.snapshot(A.runner);
  writeDir(w.files.verdicts, 4, 'new');
  assert.equal(an.verify().ok, true);
  fs.writeFileSync(path.join(w.files.verdicts, 'VRD-v000.json'), '{"verdict":"APPROVED","i":0,"edited":1}');
  let v = an.verify(); assert.deepEqual(guardsOf(v), ['AN-DIR-ENTRIES']);
  assert.equal(srcOf(v.anchors[0], 'verdicts').status, 'entries_rewritten');
  fs.writeFileSync(path.join(w.files.verdicts, 'VRD-v000.json'), JSON.stringify({ verdict: 'APPROVED', i: 0 }));
  assert.equal(an.verify().ok, true, '元に戻せば一致する');
  fs.rmSync(path.join(w.files.verdicts, 'VRD-v001.json'));
  v = an.verify(); assert.equal(srcOf(v.anchors[0], 'verdicts').status, 'entries_deleted');
}));

test('良性：記録が 1 つもない最初の snapshot と、その後に記録ができたとき', () => {
  const dir = tmp();
  try {
    const p = path.join(dir, 'late.jsonl'); const d = path.join(dir, 'late-dir');
    const an = openAnchors(path.join(dir, 'anchors.jsonl'), { sources: [{ name: 'late', path: p, kind: 'plain' }, { name: 'ldir', path: d, kind: 'dir' }, { name: 'lcalls', path: path.join(dir, 'lc.jsonl'), kind: 'chained', scheme: 'tool_calls' }] });
    const s = an.snapshot(A.runner);
    assert.equal(s.flagged, false);
    const m = an.state().anchors[0].manifest;
    assert.ok(m.sources.every((x) => x.state === 'absent'));
    writePlain(p, 5); writeDir(d, 2); writeToolCalls(path.join(dir, 'lc.jsonl'), 3);
    assert.equal(an.verify().ok, true);
    const s2 = an.snapshot(A.runner);
    assert.deepEqual(s2.regressions, []);
    assert.equal(an.verify().ok, true);
    fs.rmSync(p); // ファイルごと消す
    const v = an.verify(); assert.deepEqual(guardsOf(v), ['AN-SOURCE-PRESENT']);
    const s3 = an.snapshot(A.runner); // 固定は行い、食い違いを知らせる
    assert.ok(s3.regressions.some((r) => r.name === 'late' && r.code === 'source_gone')); assert.equal(s3.flagged, true);
  } finally { rm(dir); }
});

// ---------------------------------------------------------------------------
test('今の仕組みで検出できない攻撃（鎖と head を作り直す）を、anchor が検出する：3 方式', () => {
  for (const [scheme, name, file] of [['tool_calls', 'tool_calls', 'tool_calls'], ['ledger', 'ledger', 'ledger'], ['chain', 'trace', 'trace']]) {
    withWorld((w) => {
      const an = w.open(); an.snapshot(A.runner); w.grow(3); an.snapshot(A.runner);
      rechain(scheme, w.files[file], (b) => { b[7].forged = 1; });
      // 今の仕組みの検証（鎖と head）は通る
      const r = readSources(w.sources.filter((s) => s.name === name))[0];
      assert.equal(r.chain.ok, true, `${scheme} の作り直した鎖は今の仕組みを通る`);
      const v = an.verify();
      assert.equal(v.ok, false); assert.deepEqual(guardsOf(v), ['AN-PREFIX-MATCH']);
      assert.ok(v.anchors.every((a) => srcOf(a, name).status === 'rewritten'), '全部の anchor で書き換えを検出');
      assert.ok(v.anchors.every((a) => a.sources.filter((s) => s.name !== name).every((s) => s.status === 'match')), '他の記録は一致');
    });
  }
});

test('鎖のある記録の方式：壊れ方を方式の規則で検出する（snapshot は壊れた旨を入れて固定し、知らせる）', () => {
  withWorld((w) => {
    // tool_calls：途中の行の本文を、鎖を作り直さずに書き換える
    const l = fs.readFileSync(w.files.tool_calls, 'utf8').split('\n'); l[3] = l[3].replace('tc 4', 'tc X'); fs.writeFileSync(w.files.tool_calls, l.join('\n'));
    const an = w.open(); const s = an.snapshot(A.runner);
    assert.equal(s.flagged, true); assert.deepEqual(s.broken_chains.map((b) => b.name), ['tool_calls']);
    assert.match(s.warnings.join(' '), /鎖が壊れている/);
    const m = an.state().anchors[0].manifest.sources.find((x) => x.name === 'tool_calls');
    assert.equal(m.chain.ok, false); assert.match(m.chain.code, /prev_hash 行5/);
    assert.equal(an.verify().ok, true, '壊れた状態もそのまま固定される（壊れた事実が証拠になる）');
  });
  const cases = [
    ['ledger', (w) => fs.rmSync(path.join(path.dirname(w.files.ledger), 'ledger.head')), 'head_missing'],
    ['ledger', (w) => fs.writeFileSync(path.join(path.dirname(w.files.ledger), 'ledger.head'), '{"seq":3,"hash":"00"}'), 'head_mismatch'],
    ['ledger', (w) => fs.writeFileSync(path.join(path.dirname(w.files.ledger), 'ledger.head'), 'not json'), 'head'],
    ['ledger', (w) => fs.appendFileSync(w.files.ledger, '{"incomplete":'), 'partial_tail'],
    ['trace', (w) => fs.rmSync(`${w.files.trace}.head`), 'head_missing'],
    ['trace', (w) => fs.writeFileSync(`${w.files.trace}.head`, JSON.stringify({ seq: 5, hash: 'ab' })), 'head_mismatch'],
    ['trace', (w) => fs.writeFileSync(`${w.files.trace}.head`, JSON.stringify({ seq: -1, hash: 'ab' })), 'head'],
    ['trace', (w) => { const t = fs.readFileSync(w.files.trace, 'utf8').split('\n'); t.splice(3, 0, ''); fs.writeFileSync(w.files.trace, t.join('\n')); }, 'empty_line'],
  ];
  for (const [name, tamper, code] of cases) {
    withWorld((w) => {
      tamper(w);
      const r = readSources(w.sources.filter((s) => s.name === name))[0];
      assert.equal(r.chain.ok, false, `${name} ${code}`); assert.equal(r.chain.code, code, `${name}`);
    });
  }
  // 陽性の対照：追記の途中（chain 方式で head の後ろに 1 行）は壊れとみなさない
  withWorld((w) => {
    const raw = fs.readFileSync(w.files.trace, 'utf8').split('\n').filter(Boolean); fs.appendFileSync(w.files.trace, `${raw[raw.length - 1]}\n`);
    const r = readSources(w.sources.filter((s) => s.name === 'trace'))[0];
    assert.equal(r.chain.ok, true); assert.equal(r.lines, 21);
  });
});

test('regressions：伸びただけでない食い違いは、固定した上で記録して知らせる（黙って上書きしない）', () => withWorld((w) => {
  const an = w.open(); an.snapshot(A.runner);
  const t = fs.readFileSync(w.files.rulings, 'utf8').split('\n').filter(Boolean); fs.writeFileSync(w.files.rulings, `${t.slice(0, 10).join('\n')}\n`);
  rechain('tool_calls', w.files.tool_calls, (b) => { b[2].forged = 1; });
  fs.rmSync(path.join(w.files.verdicts, 'VRD-v001.json'));
  const s = an.snapshot(A.runner);
  assert.equal(s.flagged, true);
  const codes = s.regressions.map((r) => `${r.name}:${r.code}`).sort();
  assert.deepEqual(codes, ['rulings:truncated', 'tool_calls:rewritten', 'verdicts:entry_deleted']);
  assert.deepEqual(an.state().anchors[1].regressions.map((r) => r.code).sort(), ['entry_deleted', 'rewritten', 'truncated']);
  // 古い anchor も、新しい anchor も、今の記録とは合わない（固定は消えない）
  const v = an.verify(); assert.equal(v.ok, false);
  assert.equal(srcOf(v.anchors[0], 'rulings').status, 'truncated');
}));

test('checkGrowth・compare・buildManifest は純関数：読み取りの結果だけで動く', () => withWorld((w) => {
  const offs = { tool_calls: [], rulings: [] };
  const r1 = readSources(w.sources, DEFAULT_LIMITS, offs);
  const m1 = buildManifest(r1, null, 'a'.repeat(64), RULES, { takenAt: '2026-11-14T00:00:00Z' });
  assert.deepEqual(m1.regressions, []); assert.equal(m1.prev_manifest, null);
  const sz = m1.sources.find((s) => s.name === 'rulings').bytes;
  w.grow(2);
  const offsOf = (m) => Object.fromEntries(m.sources.filter((s) => s.kind !== 'dir').map((s) => [s.name, [s.bytes]]));
  void sz;
  const r2 = readSources(w.sources, DEFAULT_LIMITS, offsOf(m1));
  assert.deepEqual(checkGrowth(m1, r2), [], '伸びただけ');
  const m2 = buildManifest(r2, m1, 'b'.repeat(64), RULES, { takenAt: '2026-11-14T00:00:01Z' });
  assert.equal(m2.prev_manifest, anchorOf(m1));
  assert.equal(compare(m1, r2).ok, true);
  // 位置の指紋がない読み取りは、確かめられないとして食い違いに数える（fail-closed）
  const r3 = readSources(w.sources, DEFAULT_LIMITS, {});
  assert.ok(checkGrowth(m1, r3).some((g) => g.code === 'unverifiable'));
  assert.equal(compare(m1, r3).ok, false);
  assert.throws(() => buildManifest(null, null, 'a'.repeat(64)), Refused);
  assert.throws(() => buildManifest([{ name: 1 }], null, 'a'.repeat(64)), Refused);
  assert.deepEqual(checkGrowth(null, r1), []); assert.deepEqual(checkGrowth({}, r1), []);
}));

test('書き換えの範囲の絞り込み：一致する最後の anchor の位置から、変わった anchor の位置の間', () => withWorld((w) => {
  const an = w.open(); an.snapshot(A.runner); w.grow(3); an.snapshot(A.runner); w.grow(3); an.snapshot(A.runner);
  const ms = an.state().anchors.map((a) => a.manifest.sources.find((s) => s.name === 'rulings').bytes);
  const b = fs.readFileSync(w.files.rulings); b[ms[0] + 5] = b[ms[0] + 5] === 0x78 ? 0x79 : 0x78; fs.writeFileSync(w.files.rulings, b); // 1 番目と 2 番目の anchor の間
  const v = an.verify();
  const st = v.anchors.map((a) => srcOf(a, 'rulings'));
  assert.equal(st[0].status, 'match');
  assert.equal(st[1].status, 'rewritten'); assert.deepEqual(st[1].changed_between, [ms[0], ms[1]]); assert.equal(st[1].ok_up_to, ms[0]);
  assert.equal(st[2].status, 'rewritten'); assert.equal(st[2].ok_up_to, ms[0]);
}));

test('upTo：指定の anchor までを照合する。知らない anchor は違反', () => withWorld((w) => {
  const an = w.open(); const a1 = an.snapshot(A.runner); w.grow(3); const a2 = an.snapshot(A.runner);
  assert.equal(an.verify({ upTo: a1.anchor }).anchors_checked, 1);
  assert.equal(an.verify({ upTo: a2.anchor }).anchors_checked, 2);
  const bad = an.verify({ upTo: S('7') }); assert.equal(bad.ok, false); assert.equal(bad.anchors_checked, 0);
  fs.writeFileSync(w.files.spec_approvals, ''); // 後の anchor でだけ見える書き換え
  assert.equal(an.verify({ upTo: a1.anchor }).ok, false); // 先頭 bytes が空になるので 1 番目でも切り詰めとして見える
}));

// ---------------------------------------------------------------------------
test('snapshot の読み方：未完成の最後の行は数えない。追記が間に入っても、開いた時点の内容で一貫する', () => withWorld((w) => {
  const size0 = fs.statSync(w.files.rulings).size;
  fs.appendFileSync(w.files.rulings, '{"partial":');
  let an = w.open(); an.snapshot(A.runner);
  let m = an.state().anchors[0].manifest.sources.find((s) => s.name === 'rulings');
  assert.equal(m.bytes, size0); assert.equal(m.partial_tail, true); assert.equal(m.lines, 20);
  fs.appendFileSync(w.files.rulings, '1}\n');
  an.snapshot(A.runner);
  m = an.state().anchors[1].manifest.sources.find((s) => s.name === 'rulings');
  assert.equal(m.partial_tail, false); assert.equal(m.lines, 21); assert.ok(m.bytes > size0);
  assert.equal(an.verify().ok, true);
  // snapshot の最中の追記：読み取りの後（時刻を取る時）に追記が入る
  let hook = () => { appendPlain(w.files.rulings, 5, 'racing'); fs.appendFileSync(w.files.tool_calls, '{"racing":1}\n'); };
  const beforeSize = fs.statSync(w.files.rulings).size;
  an = w.open({ now: () => { if (hook) { const h = hook; hook = null; h(); } return new Date(Date.UTC(2026, 10, 14, 1, 0, 0)).toISOString(); } });
  an.snapshot(A.runner);
  m = an.state().anchors[2].manifest.sources.find((s) => s.name === 'rulings');
  assert.equal(m.bytes, beforeSize, '開いた時点の大きさまでしか数えない');
  assert.equal(an.verify().ok, true, '追記された分は含まない固定でも照合は通る');
  const a4 = an.snapshot(A.runner);
  assert.deepEqual(a4.regressions.map((r) => r.code).filter((c) => c !== 'chain_broken'), []);
}));

test('記号リンクは固定しない：対象が記号リンク・祖先が記号リンク・通常のファイルでない', () => withWorld((w, dir) => {
  const real = `${w.files.rulings}.real`; fs.renameSync(w.files.rulings, real); fs.symlinkSync(real, w.files.rulings);
  refusedBy(() => w.open().snapshot(A.runner), 'AN-NO-SYMLINK');
  fs.rmSync(w.files.rulings); fs.renameSync(real, w.files.rulings);
  w.open().snapshot(A.runner); // 戻せば通る（陽性の対照）
  const link = path.join(dir, 'ln'); fs.symlinkSync(path.dirname(w.files.rulings), link);
  const an = w.open({ sources: [{ name: 'viaanc', path: path.join(link, 'rulings.jsonl'), kind: 'plain' }] });
  refusedBy(() => an.snapshot(A.runner), 'AN-NO-SYMLINK');
  const odd = path.join(dir, 'asdir.jsonl'); fs.mkdirSync(odd);
  refusedBy(() => w.open({ sources: [{ name: 'odd', path: odd, kind: 'plain' }] }).snapshot(A.runner), 'AN-NO-SYMLINK');
  // dir：中の記号リンクは種類 l として記録され、元が通常のファイルだった anchor では検出される
  const d = path.join(dir, 'dd'); writeDir(d, 2); fs.symlinkSync(w.files.rulings, path.join(d, 'VRD-link.json'));
  const an2 = openAnchors(path.join(dir, 'a2.jsonl'), { sources: [{ name: 'dd', path: d, kind: 'dir' }] });
  an2.snapshot(A.runner);
  assert.deepEqual(an2.state().anchors[0].manifest.sources[0].entries.map((e) => e[1]), ['l', 'f', 'f']);
}));

test('大きさの上限：記録の大きさ・dir のファイル数・合計・再生中の巨大な行', () => withWorld((w, dir) => {
  refusedBy(() => w.open({ limits: { maxSourceBytes: 500 } }).snapshot(A.runner), 'AN-SIZE-LIMIT');
  refusedBy(() => w.open({ limits: { maxDirFiles: 4 } }).snapshot(A.runner), 'AN-SIZE-LIMIT');
  refusedBy(() => w.open({ limits: { maxTotalBytes: 3000 } }).snapshot(A.runner), 'AN-SIZE-LIMIT');
  refusedBy(() => w.open({ limits: { maxSources: 3 } }).snapshot(A.runner), 'AN-SOURCES-ALLOWLIST');
  // 上限を超える行（鎖のある記録）は壊れとして固定される（読み飛ばして先に進む）
  const f = path.join(dir, 'big.jsonl'); const fd = fs.openSync(f, 'w'); fs.writeSync(fd, `${'a'.repeat(17 * 1024 * 1024)}\n{"x":1}\n`); fs.closeSync(fd);
  const r = readSources([{ name: 'big', path: f, kind: 'chained', scheme: 'tool_calls' }])[0];
  assert.equal(r.state, 'ok'); assert.equal(r.chain.ok, false); assert.equal(r.chain.code, 'line_too_long'); assert.equal(r.lines, 2);
}));

test('多数のファイル・大きな記録：上限の中で現実的な時間に終わる', () => {
  const dir = tmp();
  try {
    const d = path.join(dir, 'many'); fs.mkdirSync(d);
    for (let i = 0; i < 4000; i += 1) fs.writeFileSync(path.join(d, `VRD-${String(i).padStart(5, '0')}.json`), `{"i":${i}}`);
    const an = openAnchors(path.join(dir, 'a.jsonl'), { sources: [{ name: 'many', path: d, kind: 'dir' }] });
    const t0 = Date.now(); an.snapshot(A.runner); const t1 = Date.now(); assert.equal(an.verify().ok, true); const t2 = Date.now();
    assert.ok(t1 - t0 < 15000 && t2 - t1 < 15000, `dir 4000 件：snapshot ${t1 - t0}ms、verify ${t2 - t1}ms`);
    for (let i = 4000; i < 5001; i += 1) fs.writeFileSync(path.join(d, `VRD-${String(i).padStart(5, '0')}.json`), `{"i":${i}}`);
    refusedBy(() => an.snapshot(A.runner), 'AN-SIZE-LIMIT');
    const b = benchAnchor(4, { anchors: 20 });
    assert.equal(b.verify_ok, true); assert.equal(b.anchors_checked, 20);
    assert.ok(b.snapshot_ms < 20000 && b.verify_ms < 10000, JSON.stringify(b));
  } finally { rm(dir); }
});

// ---------------------------------------------------------------------------
test('書き込みの規則：行為者・役割・入力。拒否の形は guard_violation と violations', () => withWorld((w) => {
  const an = w.open();
  for (const who of [A.worker, A.judge, A.assistant, A.exec, A.night]) { const e = refusedBy(() => an.snapshot(who), 'AN-WRITER-ROLE'); assert.ok(Array.isArray(e.violations)); }
  refusedBy(() => an.snapshot({ ...A.worker, role: 'Ｗorker' }), 'AN-WRITER-ROLE');
  refusedBy(() => an.snapshot({ ...A.runner, kind: 'ai' }), 'AN-ACTOR-SHAPE');
  refusedBy(() => an.snapshot({ role: 'owner', kind: 'ai', id: 'x', lineage: 'claude' }), 'AN-ACTOR-SHAPE');
  refusedBy(() => an.snapshot(null), 'AN-ACTOR-SHAPE');
  refusedBy(() => an.snapshot('owner'), 'AN-ACTOR-SHAPE');
  refusedBy(() => an.epoch(A.runner, { reason: 'x' }), 'AN-OWNER-ONLY');
  refusedBy(() => an.epoch(A.worker, { reason: 'x' }), 'AN-OWNER-ONLY');
  assert.equal(an.state().rows, 0, '拒んだものは何も書かない');
  // 陽性の対照
  an.snapshot(A.runner); an.snapshot(A.owner); an.snapshot({ ...A.runner, role: ' GATE_RUNNER ', id: 'Gate-Runner' });
  assert.equal(an.state().rows, 3);
  assert.deepEqual(JSON.parse(fs.readFileSync(w.anchorsFile, 'utf8').split('\n')[2]).actor, { role: 'gate_runner', kind: 'script', id: 'gate-runner', lineage: 'script' }, '記録は正規形');
}));

test('入口の写し：検査した行為者と記録する行為者は同じ（toJSON・getter で食い違わせない）', () => withWorld((w) => {
  const an = w.open();
  const sneaky = { ...A.runner, toJSON() { return A.worker; } };
  refusedBy(() => an.snapshot(sneaky), 'AN-WRITER-ROLE');
  let n = 0; const flip = { role: 'gate_runner', kind: 'script', id: 'gate-runner', lineage: 'script', get note() { return n++; } };
  refusedBy(() => an.snapshot(flip), 'AN-ACTOR-SHAPE'); // 知らない欄
  const loop = {}; loop.self = loop;
  refusedBy(() => an.snapshot(loop), 'AN-ACTOR-SHAPE');
  const rec = { role: 'gate_runner', kind: 'script', id: 'gate-runner', lineage: 'script' };
  const s = an.snapshot(rec); rec.role = 'worker'; // 後から変えても記録は変わらない
  assert.equal(JSON.parse(fs.readFileSync(w.anchorsFile, 'utf8').split('\n')[0]).actor.role, 'gate_runner'); assert.ok(s.anchor);
}));

test('receipt：結び付けられるが、中身は検証しない。書式・実在・重複を拒む', () => withWorld((w) => {
  const an = w.open(); const s1 = an.snapshot(A.runner); w.grow(1); const s2 = an.snapshot(A.runner);
  const ok = { anchor: s1.anchor, method: 'rfc3161', ref: 'tsa:freetsa/2026-11-14T00:00:00Z.tsr', digest: S('c'), note: '最初の証拠' };
  const r = an.attachReceipt(A.runner, ok);
  assert.equal(r.receipt_verified, false); assert.equal(r.verification, 'not_performed'); assert.match(r.notice, /検証しない/);
  refusedBy(() => an.attachReceipt(A.runner, ok), 'AN-RECEIPT-DUP');
  refusedBy(() => an.attachReceipt(A.runner, { ...ok, ref: 'TSA:FREETSA/2026-11-14T00:00:00Z.TSR', digest: S('d') }), 'AN-RECEIPT-DUP');
  refusedBy(() => an.attachReceipt(A.runner, { ...ok, ref: 'other:x', anchor: s2.anchor }), 'AN-RECEIPT-DUP'); // 同じ digest を別の anchor に
  refusedBy(() => an.attachReceipt(A.runner, { ...ok, anchor: S('9'), digest: S('e') }), 'AN-RECEIPT-ANCHOR');
  for (const bad of [{ ref: '../x' }, { ref: 'a b' }, { ref: '' }, { ref: 'x'.repeat(300) }, { ref: 'https://u:p@h/x' }, { ref: 'a//b' }, { method: 'pigeon' }, { method: 'RFC3161 x' }, { digest: 'abc' }, { digest: S('A') }, { note: 'x'.repeat(501) }, { note: 'a\nb' }]) {
    refusedBy(() => an.attachReceipt(A.runner, { ...ok, ref: 'ok:1', digest: S('f'), anchor: s2.anchor, ...bad }), 'AN-RECEIPT-FORMAT');
  }
  refusedBy(() => an.attachReceipt(A.runner, { ...ok, ref: 'ok:2', digest: S('1'), extra: 1 }), 'AN-INPUT-SHAPE');
  refusedBy(() => an.attachReceipt(A.runner, 'x'), 'AN-INPUT-SHAPE');
  refusedBy(() => an.attachReceipt(A.runner, { ...ok, ref: 7 }), 'AN-INPUT-SHAPE');
  refusedBy(() => an.attachReceipt(A.worker, { ...ok, ref: 'ok:3', digest: S('2') }), 'AN-WRITER-ROLE');
  // 正規化：method は大文字でも通り、記録は小文字。ref は NFKC
  const r2 = an.attachReceipt(A.owner, { anchor: s2.anchor, method: ' OpenTimestamps ', ref: 'ｏｔｓ:a2.ots', digest: S('3') });
  assert.equal(r2.method, 'opentimestamps'); assert.equal(r2.ref, 'ots:a2.ots');
  const v = an.verify();
  assert.deepEqual(v.with_receipt.sort(), [s1.anchor, s2.anchor].sort()); assert.deepEqual(v.without_receipt, []);
  assert.equal(v.ok, true); assert.equal(v.receipts_verified, false);
  assert.match(v.notes.join(' '), /検証しない/);
  assert.equal(normReceipt({ ...ok }).value.method, 'rfc3161');
  const st = an.state(); assert.equal(st.anchors[0].receipts.length, 1); assert.equal(st.anchors[1].receipts.length, 1);
}));

test('receipt がない anchor と、ある anchor を分けて返す', () => withWorld((w) => {
  const an = w.open(); const s1 = an.snapshot(A.runner); const s2 = an.snapshot(A.runner);
  an.attachReceipt(A.runner, { anchor: s2.anchor, method: 'git', ref: 'git:refs/tags/a2', digest: S('5') });
  const v = an.verify(); assert.deepEqual(v.with_receipt, [s2.anchor]); assert.deepEqual(v.without_receipt, [s1.anchor]);
}));

// ---------------------------------------------------------------------------
test('設定の写しと対象を減らす変更：食い違いはオーナーの epoch まで止まり、減らすのは drops だけ', () => withWorld((w, dir) => {
  const an = w.open(); an.snapshot(A.runner);
  const reduced = w.sources.filter((s) => s.name !== 'rulings');
  const r = w.open({ sources: reduced });
  refusedBy(() => r.snapshot(A.runner), 'AN-CFG-COPY');
  refusedBy(() => r.snapshot(A.runner), 'AN-SOURCE-SHRINK');
  refusedBy(() => r.attachReceipt(A.runner, { anchor: an.state().anchors[0].anchor, method: 'git', ref: 'git:r', digest: S('6') }), 'AN-CFG-COPY');
  refusedBy(() => r.epoch(A.runner, { reason: 'x', drops: ['rulings'] }), 'AN-OWNER-ONLY');
  refusedBy(() => r.epoch(A.owner, { reason: 'x', drops: ['nosuch'] }), 'AN-DROPS-VALID');
  refusedBy(() => an.epoch(A.owner, { reason: 'x', drops: ['rulings'] }), 'AN-DROPS-VALID'); // まだ設定にある
  refusedBy(() => r.epoch(A.owner, { reason: '  ' }), 'AN-INPUT-SHAPE');
  // drops なしの epoch は設定の写しを受け入れるだけ。その後も対象を外すことは許されない
  r.epoch(A.owner, { reason: '設定の変更を確認した' });
  refusedBy(() => r.snapshot(A.runner), 'AN-SOURCE-SHRINK');
  r.epoch(A.owner, { reason: '裁定の記録は別の方式に移す', drops: ['rulings'] });
  assert.deepEqual(r.state().drop_allowed, ['rulings']);
  const s = r.snapshot(A.runner); assert.equal(s.flagged, false);
  assert.deepEqual(r.state().drop_allowed, []);
  assert.equal(r.verify().anchors.length, 2);
  // 元の設定で開き直すと、また食い違う（写しは新しい設定）
  refusedBy(() => w.open().snapshot(A.runner), 'AN-CFG-COPY');
  // 外した名前を、許可なしにもう一度外すことはできない（許可は 1 回で消える）
  const again = w.open({ sources: reduced });
  again.snapshot(A.runner);
  const reduced2 = reduced.filter((x) => x.name !== 'spec_approvals');
  const r2 = w.open({ sources: reduced2 });
  r2.epoch(A.owner, { reason: '承認の記録の扱いを変える' });
  refusedBy(() => r2.snapshot(A.runner), 'AN-SOURCE-SHRINK');
  // 上限の変更も設定の変更
  refusedBy(() => w.open({ sources: reduced, limits: { maxDirFiles: 100 } }).snapshot(A.runner), 'AN-CFG-COPY');
}));

test('規則の版（epoch）：古い版の行はオーナーの epoch に覆われるまで書き込みを止める', () => withWorld((w) => {
  const an = w.open(); an.snapshot(A.runner); an.snapshot(A.runner);
  rechainAnchors(w.anchorsFile, (rows) => { rows[0].rules = 'an.v0'; });
  refusedBy(() => w.open().snapshot(A.runner), 'AN-RULES-VERSION');
  const v = w.open().verify(); assert.deepEqual(v.record.rules_uncovered, [1]);
  refusedBy(() => w.open().epoch(A.runner, { reason: 'x' }), 'AN-OWNER-ONLY');
  w.open().epoch(A.owner, { reason: 'an.v0 の行を受け入れる' });
  assert.doesNotThrow(() => w.open().snapshot(A.runner));
  assert.equal(w.open().verify().ok, true);
  assert.equal(w.open().state().epochs.length, 1);
  assert.equal(JSON.parse(fs.readFileSync(w.anchorsFile, 'utf8').split('\n')[3]).rules, RULES);
}));

test('再生：記録に直接書かれた偽の行を採らない。epoch に覆われれば受け入れとして分けて返す', () => withWorld((w) => {
  const an = w.open(); an.snapshot(A.runner); an.snapshot(A.runner);
  rechainAnchors(w.anchorsFile, (rows) => { rows[0] = { ...rows[0], actor: A.worker }; });
  const v = an.verify(); assert.equal(v.ok, false); assert.deepEqual(guardsOf(v), ['AN-REPLAY-CLEAN']);
  assert.equal(v.record.problems[0].guard, 'AN-WRITER-ROLE');
  refusedBy(() => an.snapshot(A.runner), 'AN-REPLAY-CLEAN');
  an.epoch(A.owner, { reason: '偽の行を確認した上で受け入れる' });
  an.snapshot(A.runner);
  const v2 = an.verify(); assert.equal(v2.ok, true); assert.equal(v2.record.accepted_problems.length > 0, true);
  // 偽の receipt（存在しない anchor・重複）は状態に入らない
  rechainAnchors(w.anchorsFile, (rows) => { rows.push({ type: 'vgdd.anchor.v1', op: 'receipt', rules: RULES, cfg: rows[0].cfg, actor: A.runner, anchor: S('8'), method: 'git', ref: 'git:x', digest: S('4'), note: '' }); });
  const st = an.state(); assert.ok(st.problems.some((p) => p.guard === 'AN-RECEIPT-ANCHOR'));
  assert.equal(st.anchors.every((a) => a.receipts.length === 0), true);
  // 知らない行・型の違う行
  rechainAnchors(w.anchorsFile, (rows) => { rows.push({ type: 'other' }); rows.push({ type: 'vgdd.anchor.v1', op: 'nosuch' }); });
  assert.ok(an.state().problems.length >= 2);
  assert.doesNotThrow(() => replay([null, 5, 'x', [], {}], {}));
}));

test('anchor の記録そのものの改ざん：行を消す・書き換える（鎖で検出）／作り直すと検出できない（限界）', () => withWorld((w) => {
  const an = w.open(); const a1 = an.snapshot(A.runner); w.grow(3); const a2 = an.snapshot(A.runner);
  const backup = fs.readFileSync(w.anchorsFile, 'utf8'); const headBackup = fs.readFileSync(`${w.anchorsFile}.head`, 'utf8');
  // 末尾の行を消す（head が残る）
  fs.writeFileSync(w.anchorsFile, backup.split('\n').slice(0, 1).join('\n') + '\n');
  let v = an.verify(); assert.equal(v.ok, false); assert.ok(guardsOf(v).includes('AN-CHAIN-INTACT'));
  // 記録と head を一緒に差し戻す（最後の anchor を消す）：局所では検出できない
  fs.writeFileSync(`${w.anchorsFile}.head`, JSON.stringify({ seq: 1, hash: JSON.parse(backup.split('\n')[0]).hash }) + '\n');
  v = an.verify(); assert.equal(v.ok, true, '【限界】最後の anchor の行を head ごと削っても、局所では検出できない');
  assert.equal(v.anchors_checked, 1);
  // 外部が保持する anchor の値があれば検出できる
  v = an.verify({ pinned: [a1.anchor, a2.anchor] }); assert.equal(v.ok, false); assert.deepEqual(guardsOf(v), ['AN-PINNED-PRESENT']);
  assert.equal(an.verify({ pinned: [a1.anchor] }).ok, true);
  assert.equal(an.verify({ pinned: [] }).ok, true);
  assert.equal(an.verify({ pinned: 'x' }).ok, false);
  assert.equal(an.verify({ pinned: ['nothash'] }).ok, false);
  fs.writeFileSync(w.anchorsFile, backup); fs.writeFileSync(`${w.anchorsFile}.head`, headBackup);
  assert.equal(an.verify({ pinned: [a1.anchor, a2.anchor] }).ok, true);
  // 全部（記録の本体と anchor の記録と head）を一緒に作り直す
  rechain('tool_calls', w.files.tool_calls, (b) => { b[4].forged = 1; });
  fs.rmSync(w.anchorsFile); fs.rmSync(`${w.anchorsFile}.head`);
  const an2 = w.open(); an2.snapshot(A.runner);
  v = an2.verify(); assert.equal(v.ok, true, '【限界】全部を一緒に作り直す改ざんは、外部の証拠がなければ局所では検出できない');
  v = an2.verify({ pinned: [a1.anchor, a2.anchor] }); assert.equal(v.ok, false); assert.deepEqual(guardsOf(v), ['AN-PINNED-PRESENT']);
  assert.match(v.notes.join(' '), /外部の証拠/);
}));

test('anchor の記録を丸ごと消す（head も）と局所では検出できないが、head だけ残せば鎖の破れとして検出する', () => withWorld((w) => {
  const an = w.open(); an.snapshot(A.runner);
  fs.rmSync(w.anchorsFile);
  const v = an.verify(); assert.equal(v.ok, false); assert.ok(guardsOf(v).includes('AN-CHAIN-INTACT'));
  fs.rmSync(`${w.anchorsFile}.head`);
  assert.equal(an.verify().ok, true); assert.equal(an.verify().anchors_checked, 0);
}));

// ---------------------------------------------------------------------------
test('開き直しても同じ状態が作り直せる。state は読み取り専用の写し', () => withWorld((w) => {
  const an = w.open(); an.snapshot(A.runner); w.grow(2); an.snapshot(A.runner);
  an.attachReceipt(A.runner, { anchor: an.state().anchors[0].anchor, method: 'witness', ref: 'w:1', digest: S('7') });
  an.epoch(A.owner, { reason: '確認' });
  const a = an.state(); const b = w.open().state();
  assert.deepEqual(a, b);
  assert.ok(Object.isFrozen(a)); assert.ok(Object.isFrozen(a.anchors[0].manifest));
  assert.equal(w.open().verify().ok, true);
  assert.equal(a.epochs.length, 1); assert.equal(a.config_matches, true);
}));

test('名前に constructor・tostring などを使っても、プロトタイプの値を引かない', () => {
  const dir = tmp();
  try {
    const p1 = path.join(dir, 'c.jsonl'); const p2 = path.join(dir, 'h.jsonl'); writePlain(p1, 3); writePlain(p2, 3);
    const src = [{ name: 'constructor', path: p1, kind: 'plain' }, { name: 'hasownproperty', path: p2, kind: 'plain' }];
    const an = openAnchors(path.join(dir, 'a.jsonl'), { sources: src });
    an.snapshot(A.runner); appendPlain(p1, 2); an.snapshot(A.runner);
    assert.equal(an.verify().ok, true);
    appendPlain(p2, 1); fs.writeFileSync(p2, fs.readFileSync(p2, 'utf8').replace('"pl"', '"xx"')); assert.equal(an.verify().ok, false);
    assert.equal(openAnchors(path.join(dir, 'b.jsonl'), { sources: [{ name: '__proto__', path: p1, kind: 'plain' }] }).contextFor('snapshot', A.runner).state.rows, 0);
    refusedBy(() => openAnchors(path.join(dir, 'b.jsonl'), { sources: [{ name: '__proto__', path: p1, kind: 'plain' }] }).snapshot(A.runner), 'AN-SOURCES-ALLOWLIST');
  } finally { rm(dir); }
});

test('設定が読めないときは何も書かない（fail-closed）。anchor の記録のパスが相対なら開けない', () => withWorld((w) => {
  refusedBy(() => w.open({ sources: null }).snapshot(A.runner), 'AN-SOURCES-ALLOWLIST');
  refusedBy(() => w.open({ sources: [{ name: 'x', path: 'rel', kind: 'plain' }] }).snapshot(A.runner), 'AN-PATH-SAFE');
  assert.throws(() => openAnchors('relative/anchors.jsonl', { sources: [] }), Refused);
  assert.throws(() => openAnchors('/a/../b.jsonl', { sources: [] }), Refused);
  assert.equal(w.open({ sources: [] }).snapshot(A.runner).flagged, false, '記録が 1 つもない設定');
}));

test('性能の実測：1 回の読みで全部の anchor の時点の指紋を計算する（anchor が 100 個でも全量は 1 回しか読まない）', () => {
  const b = benchAnchor(8, { anchors: 100 });
  assert.equal(b.anchors_checked, 100); assert.equal(b.verify_ok, true);
  assert.ok(b.bytes > 7 * 1024 * 1024);
  assert.ok(b.verify_ms < 8000, `verify ${b.verify_ms}ms`);
});

test('シナリオ：全ガードで攻撃はすべて止まり、良性はすべて通る（bench と同じ判定）', () => {
  const all = Object.keys(GUARDS);
  for (const s of SCENARIOS) {
    const r = s.run(all);
    if (s.kind === 'attack') { assert.equal(r.blocked, true, `${s.id} ${s.title}`); assert.ok(s.expectGuards.some((g) => r.by.includes(g)), `${s.id} 宣言と違うガード ${r.by}`); } else assert.equal(r.blocked, false, `${s.id} ${s.title} ${r.by}`);
  }
  const attacks = SCENARIOS.filter((s) => s.kind === 'attack'); const benign = SCENARIOS.filter((s) => s.kind === 'benign');
  assert.ok(attacks.length >= 24 && benign.length >= 3);
  for (const g of all) assert.ok(attacks.some((s) => s.expectGuards.includes(g)), `${g} を試す攻撃がある`);
  // アブレーション：各ガードを外すと、そのガードを宣言した攻撃のどれかが通る
  for (const g of all) {
    const rest = all.filter((x) => x !== g);
    assert.ok(attacks.some((s) => s.run(rest).blocked === false), `${g} は必要（外すと通る攻撃がある）`);
  }
});

test('ガードの純度：snapshot の文脈に対して、検査は状態を書かず例外を投げない', () => withWorld((w) => {
  const an = w.open(); const ctx = an.contextFor('snapshot', A.runner);
  const before = fs.existsSync(w.anchorsFile);
  assert.equal(check(ctx).ok, true); assert.equal(fs.existsSync(w.anchorsFile), before);
  assert.equal(an.state().rows, 0);
  for (const bad of [null, undefined, 5, 'x', [], { op: 'snapshot', state: 5 }, { op: 'receipt', input: null }, { op: 'epoch', input: { drops: 'x' } }]) assert.doesNotThrow(() => check(bad));
  assert.equal(canonical(anchorOf({ a: 1 })).startsWith('"sha256:'), true);
}));
