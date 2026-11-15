// 追記専用の鎖（lib/chain.mjs）の試験：途中で落ちた跡の復旧、取り残しのロック、fsync の順序、既存の挙動
// 落ちた状態は、ファイルを直接いじって作る（ロックの引き継ぎだけ、実際に子プロセスを起こして殺す）
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { openChain, Refused, canonical, sha256 } from '../lib/chain.mjs';
import { openImprovements } from '../improvement.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CHAIN_URL = new URL('../lib/chain.mjs', import.meta.url).href;
const AT = '2026-11-15T09:00:00+09:00';
const caps = JSON.parse(fs.readFileSync(path.resolve(HERE, '../../kernel/capabilities.json'), 'utf8'));

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'vgdd-next-'));
function fresh(opt = {}) {
  const dir = tmp(); const file = path.join(dir, 'c.jsonl');
  return { dir, file, c: openChain(file, { now: () => AT, lockWaitMs: 300, ...opt }) };
}
const fill = (c, n) => { for (let i = 0; i < n; i += 1) c.append({ type: 't', i }); };
const readText = (f) => fs.readFileSync(f, 'utf8');
const headOf = (file) => JSON.parse(readText(`${file}.head`));
/** 鎖として正しい次の行（本体 body を、前の行 rows の後ろにつなぐ） */
function nextRow(rows, body = { type: 't', i: 'next' }) {
  const full = { ...body, seq: rows.length + 1, at: AT, prev: rows.length ? rows[rows.length - 1].hash : 'genesis' };
  return { ...full, hash: sha256(canonical(full)) };
}
const writeHeadRaw = (file, seq, hash) => fs.writeFileSync(`${file}.head`, `${JSON.stringify({ seq, hash })}\n`);
/** 記録のフォルダの全ファイルの内容（変更・増減の検出用） */
function snapshotDir(dir) {
  const o = {};
  for (const n of fs.readdirSync(dir).sort()) { const p = path.join(dir, n); o[n] = fs.statSync(p).isDirectory() ? 'DIR' : fs.readFileSync(p, 'utf8'); }
  return o;
}
const brokenCode = (fn) => { try { fn(); } catch (e) { assert.ok(e instanceof Refused, String(e)); return e; } assert.fail('止まるはずが通った'); };
const files = (dir, re) => fs.readdirSync(dir).filter((n) => re.test(n));

// ---- 既存の挙動 ----

test('普通の追記・読み取り・検証：連番・prev・hash がつながり、head が最後を指す。列挙されない recovered は空', () => {
  const { c, file } = fresh();
  const r1 = c.append({ type: 't', a: 1 });
  const r2 = c.append({ type: 't', a: 2 });
  assert.equal(r1.seq, 1); assert.equal(r1.prev, 'genesis'); assert.equal(r2.prev, r1.hash);
  assert.deepEqual(r2.recovered, []);
  assert.ok(!Object.keys(r2).includes('recovered'));
  assert.ok(!JSON.stringify(r2).includes('recovered'));
  assert.deepEqual(c.read().map((x) => x.seq), [1, 2]);
  assert.deepEqual(c.verify(), { ok: true, count: 2 });
  assert.deepEqual(headOf(file), { seq: 2, hash: r2.hash });
  assert.deepEqual(c.recoveries(), []);
});

test('空の記録：ファイルがなくても verify は通り、read は空。何も作らない', () => {
  const { c, dir } = fresh();
  assert.deepEqual(c.read(), []);
  assert.deepEqual(c.verify(), { ok: true, count: 0 });
  assert.deepEqual(fs.readdirSync(dir), []);
});

test('最初の追記：行より先に空の記録と head（seq 0）を置き、そのあと行と head が進む', () => {
  const { c, file, dir } = fresh();
  c.append({ type: 't' });
  assert.deepEqual(files(dir, /./).sort(), ['c.jsonl', 'c.jsonl.head']);
  assert.equal(headOf(file).seq, 1);
});

test('check の口：投げれば追記しない。ロックの中で今の全行を渡す', () => {
  const { c, file } = fresh();
  fill(c, 2);
  const before = readText(file);
  assert.throws(() => c.append({ type: 't' }, (records) => { assert.equal(records.length, 2); throw new Refused('no', 'x'); }), /no/);
  assert.equal(readText(file), before);
  assert.equal(c.append({ type: 't' }, (records) => assert.equal(records.length, 2)).seq, 3);
});

test('予約のキー・本体の型の拒否', () => {
  const { c } = fresh();
  for (const k of ['seq', 'at', 'prev', 'hash']) assert.equal(brokenCode(() => c.append({ [k]: 1 })).code, 'bad_body');
  for (const b of [null, [], 'x', 3]) assert.equal(brokenCode(() => c.append(b)).code, 'bad_body');
  assert.deepEqual(c.read(), []);
});

test('書き込み中の読み取り：head の後ろの1行（完全でも書きかけでも）は読まない。2行以上は破損', () => {
  const { c, file } = fresh();
  fill(c, 2);
  const rows = c.read();
  fs.appendFileSync(file, `${JSON.stringify(nextRow(rows))}\n`);
  assert.deepEqual(c.read().map((x) => x.seq), [1, 2]);
  fs.appendFileSync(file, `${JSON.stringify(nextRow([...rows, nextRow(rows)], { type: 't' }))}\n`);
  assert.equal(brokenCode(() => c.read()).code, 'chain_broken');
  const f2 = fresh(); fill(f2.c, 2);
  fs.appendFileSync(f2.file, '{"seq":3,"at"');
  assert.deepEqual(f2.c.read().map((x) => x.seq), [1, 2]);
});

test('読み取り専用のフォルダでも read・verify は通る（ロックも書き込みも要らない）', { skip: process.getuid && process.getuid() === 0 }, () => {
  const { c, dir } = fresh();
  fill(c, 3);
  fs.chmodSync(dir, 0o555);
  try {
    const ro = openChain(path.join(dir, 'c.jsonl'));
    assert.equal(ro.read().length, 3);
    assert.deepEqual(ro.verify(), { ok: true, count: 3 });
    assert.throws(() => ro.append({ type: 't' }), (e) => e.code === 'EACCES'); // 書き手は書けない（読み手とは別）
  } finally { fs.chmodSync(dir, 0o755); }
});

// ---- 形1：行は書けたが head が古い ----

test('形1：head が1行ぶん古い → 次の追記で head が進み、新しい行もその後ろに入る。復旧の記録が残る', () => {
  const { c, file, dir } = fresh();
  fill(c, 3);
  const rows = c.read();
  const lost = nextRow(rows, { type: 't', i: 'lost' });
  fs.appendFileSync(file, `${JSON.stringify(lost)}\n`);
  assert.equal(c.verify().pending, 'roll_forward');
  assert.equal(c.read().length, 3); // 読み手は復旧しない
  assert.equal(headOf(file).seq, 3);
  assert.deepEqual(c.recoveries(), []);
  const r = c.append({ type: 't', i: 'new' });
  assert.equal(r.seq, 5); assert.equal(r.prev, lost.hash);
  assert.deepEqual(r.recovered.map((e) => [e.kind, e.seq, e.hash]), [['roll_forward', 4, lost.hash]]);
  assert.deepEqual(c.read().map((x) => x.seq), [1, 2, 3, 4, 5]);
  assert.deepEqual(headOf(file), { seq: 5, hash: r.hash });
  const log = c.recoveries();
  assert.equal(log.length, 1);
  assert.equal(log[0].kind, 'roll_forward'); assert.equal(log[0].pid, process.pid); assert.equal(log[0].at, AT);
  assert.equal(c.verify().pending, undefined);
  assert.deepEqual(files(dir, /torn|stale|\.lock$/), []);
});

test('形1：最初の追記の途中で落ちた（head は seq 0）。同じく進む', () => {
  const { c, file } = fresh();
  c.append({ type: 't' });
  fs.writeFileSync(file, ''); writeHeadRaw(file, 0, 'genesis');
  fs.appendFileSync(file, `${JSON.stringify(nextRow([]))}\n`);
  assert.equal(c.verify().pending, 'roll_forward');
  assert.equal(c.append({ type: 't' }).seq, 2);
});

test('形1：recoverCheck が拒めば進めず chain_broken。何も書き換えない。受け入れれば進む', () => {
  const dir = tmp(); const file = path.join(dir, 'c.jsonl');
  const calls = [];
  const c = openChain(file, { now: () => AT, recoverCheck: (before, row) => { calls.push([before.length, row.seq]); return row.i !== 'bad'; } });
  fill(c, 2);
  fs.appendFileSync(file, `${JSON.stringify(nextRow(c.read(), { type: 't', i: 'bad' }))}\n`);
  const snap = snapshotDir(dir);
  const e = brokenCode(() => c.append({ type: 't' }));
  assert.equal(e.code, 'chain_broken'); assert.match(e.detail, /recover_rejected/);
  assert.deepEqual(snapshotDir(dir), snap);
  assert.deepEqual(calls, [[2, 3]]);
  // 受け入れる行なら進む
  const ok = tmp(); const f2 = path.join(ok, 'c.jsonl');
  const c2 = openChain(f2, { now: () => AT, recoverCheck: () => true });
  fill(c2, 2); fs.appendFileSync(f2, `${JSON.stringify(nextRow(c2.read()))}\n`);
  assert.equal(c2.append({ type: 't' }).seq, 4);
  // true 以外（undefined・truthy・例外）は拒否
  for (const rc of [() => undefined, () => 1, () => { throw new Error('x'); }]) {
    const d = tmp(); const f = path.join(d, 'c.jsonl');
    const cc = openChain(f, { now: () => AT, recoverCheck: rc });
    fill(cc, 1); fs.appendFileSync(f, `${JSON.stringify(nextRow(cc.read()))}\n`);
    const s = snapshotDir(d);
    assert.equal(brokenCode(() => cc.append({ type: 't' })).code, 'chain_broken');
    assert.deepEqual(snapshotDir(d), s);
  }
});

// ---- 形2：行が途中まで ----

for (const [name, cut] of [['1バイト', (s) => s.slice(0, 1)], ['途中まで', (s) => s.slice(0, 40)], ['改行の直前まで', (s) => s]]) {
  test(`形2：末尾の書きかけ（${name}）→ 退避されて切り詰められ、追記が通る`, () => {
    const { c, file, dir } = fresh();
    fill(c, 3);
    const good = readText(file);
    const partial = cut(JSON.stringify(nextRow(c.read(), { type: 't', i: 'torn' })));
    fs.appendFileSync(file, partial);
    assert.equal(c.verify().pending, 'discard_torn');
    assert.deepEqual(c.read().length, 3);
    const r = c.append({ type: 't', i: 'new' });
    assert.equal(r.seq, 4);
    assert.ok(readText(file).startsWith(good));
    assert.equal(c.verify().count, 4);
    const t = files(dir, /\.torn-/);
    assert.equal(t.length, 1);
    assert.equal(readText(path.join(dir, t[0])), partial);
    assert.deepEqual(r.recovered.map((e) => [e.kind, e.seq, e.torn_file, e.torn_bytes, e.torn_sha256]), [['discard_torn', 3, t[0], Buffer.byteLength(partial), sha256(Buffer.from(partial))]]);
    assert.deepEqual(c.recoveries().map((e) => e.kind), ['discard_torn']);
  });
}

test('形2：復旧の最中に落ちた（退避は書けたが切り詰めの前）→ 次の追記で入り直せる。退避は重複するが記録に残る', () => {
  const { c, file, dir } = fresh();
  fill(c, 2);
  const partial = '{"seq":3,"at":"x';
  fs.appendFileSync(file, partial);
  fs.writeFileSync(`${file}.torn-0-1`, partial); // 前回の途中まで
  const r = c.append({ type: 't' });
  assert.equal(r.seq, 3);
  assert.equal(c.verify().count, 3);
  assert.equal(files(dir, /\.torn-/).length, 2);
});

test('形2：書きかけに非 UTF-8 のバイトがあっても退避は同じバイト列', () => {
  const { c, file, dir } = fresh();
  fill(c, 1);
  const bytes = Buffer.from([0x7b, 0xff, 0xfe, 0x80]);
  fs.appendFileSync(file, bytes);
  c.append({ type: 't' });
  const t = files(dir, /\.torn-/);
  assert.deepEqual(fs.readFileSync(path.join(dir, t[0])), bytes);
});

test('形1+形2が同時（head が古く、完全な1行の後ろに書きかけ）：復旧せず止める。何も書き換えない', () => {
  const { c, file, dir } = fresh();
  fill(c, 2);
  const rows = c.read();
  const l3 = nextRow(rows);
  fs.appendFileSync(file, `${JSON.stringify(l3)}\n${JSON.stringify(nextRow([...rows, l3])).slice(0, 20)}`);
  const snap = snapshotDir(dir);
  assert.equal(brokenCode(() => c.append({ type: 't' })).code, 'chain_broken');
  assert.deepEqual(snapshotDir(dir), snap);
});

// ---- 止めるべき形（陰性の対照：復旧が改ざんを通す穴になっていない） ----

function stopCases() {
  // [名前, (file, rows) => 壊す]
  const lines = (file) => readText(file).split('\n').filter(Boolean);
  const put = (file, ls) => fs.writeFileSync(file, `${ls.join('\n')}\n`);
  return [
    ['head より後ろに2行', (file, rows) => { const a = nextRow(rows); fs.appendFileSync(file, `${JSON.stringify(a)}\n${JSON.stringify(nextRow([...rows, a]))}\n`); }],
    ['後ろの1行の prev が合わない', (file, rows) => fs.appendFileSync(file, `${JSON.stringify((() => { const f = { type: 't', seq: 4, at: AT, prev: 'sha-x' }; return { ...f, hash: sha256(canonical(f)) }; })())}\n`)],
    ['後ろの1行の seq が合わない', (file, rows) => fs.appendFileSync(file, `${JSON.stringify((() => { const f = { type: 't', seq: 9, at: AT, prev: rows[2].hash }; return { ...f, hash: sha256(canonical(f)) }; })())}\n`)],
    ['後ろの1行の hash が合わない', (file, rows) => fs.appendFileSync(file, `${JSON.stringify({ ...nextRow(rows), hash: 'f'.repeat(64) })}\n`)],
    ['後ろの1行が JSON でない', (file) => fs.appendFileSync(file, 'not json\n')],
    ['head より行が少ない（切り詰め）', (file) => put(file, lines(file).slice(0, 2))],
    ['head のハッシュが末尾の行と違う', (file, rows) => writeHeadRaw(file, 3, 'e'.repeat(64))],
    ['途中の行の書き換え', (file) => { const ls = lines(file); const o = JSON.parse(ls[1]); o.i = 'tampered'; ls[1] = JSON.stringify(o); put(file, ls); }],
    ['途中の行の書き換え＋後ろに完全な1行', (file, rows) => { const ls = lines(file); const o = JSON.parse(ls[1]); o.i = 'tampered'; ls[1] = JSON.stringify(o); put(file, [...ls, JSON.stringify(nextRow(rows))]); }],
    ['head がない', (file) => fs.rmSync(`${file}.head`)],
    ['head が空', (file) => fs.writeFileSync(`${file}.head`, '')],
    ['head が壊れた JSON', (file) => fs.writeFileSync(`${file}.head`, '{"seq":3,')],
    ['head の型が違う', (file) => fs.writeFileSync(`${file}.head`, '{"seq":"3","hash":1}\n')],
    ['空行がある', (file) => { const ls = lines(file); fs.writeFileSync(file, `${ls[0]}\n\n${ls.slice(1).join('\n')}\n`); }],
    ['head がなく、最後の1行だけ残して切り詰めた', (file) => { fs.rmSync(`${file}.head`); put(file, lines(file).slice(0, 1)); }],
    ['head を消し、末尾を切り詰め、書きかけを足した', (file) => { fs.rmSync(`${file}.head`); put(file, lines(file).slice(0, 2)); fs.appendFileSync(file, '{"x"'); }],
    ['書きかけだが、その前が head と合わない', (file) => { put(file, lines(file).slice(0, 2)); fs.appendFileSync(file, '{"x"'); }],
    ['記録がない', (file) => fs.rmSync(file)],
    ['記録が通常のファイルでない', (file) => { fs.rmSync(file); fs.mkdirSync(file); }],
  ];
}
for (const [name, mutate] of stopCases()) {
  test(`止める：${name} → chain_broken のまま、記録・head・フォルダを書き換えない`, () => {
    const { c, file, dir } = fresh();
    fill(c, 3);
    mutate(file, c.read());
    const snap = snapshotDir(dir);
    const e = brokenCode(() => c.append({ type: 't', i: 'x' }));
    assert.equal(e.code, 'chain_broken', e.message);
    assert.deepEqual(snapshotDir(dir), snap);
    assert.deepEqual(files(dir, /torn|stale|recovery/), []);
    assert.equal(c.recoveries().length, 0);
  });
}

// ---- 攻撃の想定 ----

test('攻撃：鎖として正しい偽の行を足す → 形1として head は進むが、部品の再生のガードがその行を拒む（improvement）', () => {
  const dir = tmp(); const file = path.join(dir, 'improvements.jsonl');
  const AI = { role: 'executive_head', kind: 'ai', id: 'claude-exec-1', lineage: 'claude' };
  const OWNER = { role: 'owner', kind: 'human', id: 'owner', lineage: 'human' };
  const im = openImprovements(file, { currentCapabilities: caps, now: () => AT });
  const input = { title: '作業員の手順の改善', tier: 'playbook', target: { name: 'worker-playbook' }, content: '手順3：試験を先に書く' };
  const p = im.propose(AI, input);
  const ch = openChain(file);
  const rows = ch.read();
  const adoptedByForgery = () => { try { return im.get(p.id).status === 'adopted'; } catch { return false; } };
  // 偽の行A：形が合わない（再生が「知らない行」として拒む）。偽の行B：形は正しいが、評価も審査もなく、AI が人のオーナーを名乗って採用
  const shapes = [
    { type: 'improvement', op: 'adopt', id: p.id, digest: p.digest, policy_line: 'p0.4', actor: OWNER, rules: 'im.v1' },
    { type: rows[0].type, op: 'adopt', id: p.id, rules: rows[0].rules, cfg: rows[0].cfg, actor: OWNER, digest: p.digest, policy_line: 'p0.4' },
  ];
  for (const body of shapes) {
    const d2 = tmp(); const f2 = path.join(d2, 'improvements.jsonl');
    const im2 = openImprovements(f2, { currentCapabilities: caps, now: () => AT });
    const p2 = im2.propose(AI, input);
    const ch2 = openChain(f2);
    fs.appendFileSync(f2, `${JSON.stringify(nextRow(ch2.read(), { ...body, id: p2.id, digest: p2.digest }))}\n`);
    assert.equal(ch2.verify().pending, 'roll_forward');
    // 次の書き込み：head は追いつく（復旧は鎖の上の話）が、部品は状態に入れない（再生が拒む）か、書き込みを止める
    let threw = null;
    try { im2.propose(AI, { ...input, title: '別の提案' }); } catch (e) { threw = e; }
    assert.equal(headOf(f2).seq, 2, '形1の復旧で head は追いつく');
    let adopted = false;
    try { adopted = im2.get(p2.id).status === 'adopted' || im2.adoptionValid(p2.id, 'p0.4') === true; } catch { adopted = false; }
    assert.equal(adopted, false, '偽の採用が状態に入った');
    assert.ok(threw !== null || im2.list().length === 1, '偽の行のあとに、別の提案が通常どおり増えてはいけない');
  }
  assert.ok(!adoptedByForgery());
});

test('攻撃（recoverCheck を持つ記録）：規則に合わない偽の行は、head を進める前に拒まれて書き込みが止まる', () => {
  const dir = tmp(); const file = path.join(dir, 'c.jsonl');
  const c = openChain(file, { now: () => AT, recoverCheck: (before, row) => row.type === 't' });
  fill(c, 2);
  fs.appendFileSync(file, `${JSON.stringify(nextRow(c.read(), { type: 'forged' }))}\n`);
  assert.equal(brokenCode(() => c.append({ type: 't' })).code, 'chain_broken');
  assert.equal(headOf(file).seq, 2);
  assert.deepEqual(c.recoveries(), []);
});

// ---- repairHead ----

test('repairHead：期待の値が合えば head を作り直す。復旧の記録に理由が残る', () => {
  const { c, file } = fresh();
  fill(c, 3);
  const last = c.read()[2];
  for (const damage of [() => fs.rmSync(`${file}.head`), () => fs.writeFileSync(`${file}.head`, ''), () => fs.writeFileSync(`${file}.head`, '{"seq"')]) {
    damage();
    assert.equal(brokenCode(() => c.append({ type: 't' })).code, 'chain_broken');
    assert.deepEqual(c.repairHead({ reason: 'anchor の控えと照合した', expect: { seq: 3, hash: last.hash } }), { seq: 3, hash: last.hash });
    assert.deepEqual(c.verify(), { ok: true, count: 3 });
  }
  const log = c.recoveries().filter((e) => e.kind === 'repair_head');
  assert.equal(log.length, 3); assert.equal(log[0].reason, 'anchor の控えと照合した'); assert.equal(log[0].head_state, 'absent'); assert.equal(log[1].head_state, 'bad');
  assert.equal(c.append({ type: 't' }).seq, 4);
});

test('repairHead：値が合わない・値なし・理由なし・head が正常・途中の行が壊れている・書きかけの末尾 は直さず、何も書かない', () => {
  const { c, file, dir } = fresh();
  fill(c, 3);
  const last = c.read()[2];
  fs.rmSync(`${file}.head`);
  const snap = snapshotDir(dir);
  const refuse = (arg, code) => { assert.equal(brokenCode(() => c.repairHead(arg)).code, code); assert.deepEqual(snapshotDir(dir), snap); };
  refuse(undefined, 'bad_repair');
  refuse({ reason: 'r' }, 'bad_repair');
  refuse({ expect: { seq: 3, hash: last.hash } }, 'bad_repair');
  refuse({ reason: ' ', expect: { seq: 3, hash: last.hash } }, 'bad_repair');
  refuse({ reason: 'r', expect: { seq: 3 } }, 'bad_repair');
  refuse({ reason: 'r', expect: { seq: '3', hash: last.hash } }, 'bad_repair');
  refuse({ reason: 'r', expect: { seq: 3, hash: 'a'.repeat(64) } }, 'repair_refused');
  refuse({ reason: 'r', expect: { seq: 2, hash: last.hash } }, 'repair_refused');
  refuse({ reason: 'r', expect: { seq: 2, hash: c.read ? last.prev : '' } }, 'repair_refused'); // 末尾を1つ前にずらす（切り詰めを通さない）
  // 書きかけの末尾
  fs.appendFileSync(file, '{"seq"');
  const s2 = snapshotDir(dir);
  assert.equal(brokenCode(() => c.repairHead({ reason: 'r', expect: { seq: 3, hash: last.hash } })).code, 'repair_refused');
  assert.deepEqual(snapshotDir(dir), s2);
  // 途中の行が壊れている
  const ls = readText(file).split('\n').filter(Boolean).slice(0, 3); const o = JSON.parse(ls[1]); o.i = 'x'; ls[1] = JSON.stringify(o);
  fs.writeFileSync(file, `${ls.join('\n')}\n`);
  const s3 = snapshotDir(dir);
  assert.equal(brokenCode(() => c.repairHead({ reason: 'r', expect: { seq: 3, hash: last.hash } })).code, 'repair_refused');
  assert.deepEqual(snapshotDir(dir), s3);
  // head が正常
  const { c: c2, file: f2 } = fresh(); fill(c2, 2);
  assert.equal(brokenCode(() => c2.repairHead({ reason: 'r', expect: { seq: 2, hash: c2.read()[1].hash } })).code, 'repair_refused');
  void f2;
});

test('repairHead：空の記録（head だけ消えた）も、期待が seq 0・genesis のときだけ', () => {
  const { c, file } = fresh();
  fill(c, 1); fs.writeFileSync(file, ''); fs.rmSync(`${file}.head`);
  assert.equal(brokenCode(() => c.repairHead({ reason: 'r', expect: { seq: 1, hash: 'a' } })).code, 'repair_refused');
  assert.deepEqual(c.repairHead({ reason: 'r', expect: { seq: 0, hash: 'genesis' } }), { seq: 0, hash: 'genesis' });
  assert.equal(c.append({ type: 't' }).seq, 1);
});

// ---- ロック ----

function deadPid() { const r = spawnSync(process.execPath, ['-e', '0']); return r.pid; }
const lockOf = (file) => `${file}.lock`;
function plantLock(file, owner, ageMs = 0) {
  const l = lockOf(file); fs.mkdirSync(l, { recursive: true });
  if (owner !== null) fs.writeFileSync(path.join(l, 'owner'), typeof owner === 'string' ? owner : JSON.stringify(owner));
  if (ageMs) { const t = new Date(Date.now() - ageMs); fs.utimesSync(l, t, t); }
}

test('ロック：持ち主の pid が同じホストで死んでいれば引き継ぐ。復旧の記録に lock_takeover が残る', () => {
  const { c, file, dir } = fresh();
  plantLock(file, { pid: deadPid(), host: os.hostname(), started: AT, token: 'x' });
  const r = c.append({ type: 't' });
  assert.equal(r.seq, 1);
  assert.deepEqual(r.recovered.map((e) => [e.kind, e.reason, e.owner.host]), [['lock_takeover', 'dead_owner', os.hostname()]]);
  assert.deepEqual(c.recoveries().map((e) => e.kind), ['lock_takeover']);
  assert.deepEqual(files(dir, /\.lock/), []); // 解放され、退避の古いフォルダも残らない
});

test('ロック：引き継がない場合（pid が生きている・ホストが違う・持ち主の情報が読めない・形が違う・新しい空のロック）は lock_busy', () => {
  const cases = [
    ['生きている pid', { pid: process.pid, host: os.hostname() }],
    ['親の pid（生きている）', { pid: process.ppid, host: os.hostname() }],
    ['ホストが違う', { pid: deadPid(), host: `${os.hostname()}-other` }],
    ['JSON でない', 'garbage'],
    ['pid が0', { pid: 0, host: os.hostname() }],
    ['pid が負', { pid: -1, host: os.hostname() }],
    ['pid が文字列', { pid: String(deadPid()), host: os.hostname() }],
    ['host がない', { pid: deadPid() }],
    ['新しい空のロック', null],
  ];
  for (const [name, owner] of cases) {
    const { c, file, dir } = fresh({ lockWaitMs: 120 });
    plantLock(file, owner);
    const before = snapshotDir(dir);
    assert.equal(brokenCode(() => c.append({ type: 't' })).code, 'lock_busy', name);
    assert.deepEqual(snapshotDir(dir), before, name);
    assert.deepEqual(c.recoveries(), [], name);
  }
});

test('ロック：作られて久しい空のロックは引き継ぐ。持ち主の情報がなく中身のあるロックは引き継がない', () => {
  const { c, file } = fresh({ staleEmptyLockMs: 5000 });
  plantLock(file, null, 60000);
  const r = c.append({ type: 't' });
  assert.equal(r.recovered[0].kind, 'lock_takeover'); assert.equal(r.recovered[0].reason, 'empty_lock');
  const o = fresh({ lockWaitMs: 100, staleEmptyLockMs: 5000 });
  plantLock(o.file, null, 60000); fs.writeFileSync(path.join(lockOf(o.file), 'something'), 'x');
  assert.equal(brokenCode(() => o.c.append({ type: 't' })).code, 'lock_busy');
});

test('ロック：追記が終わればロックは残らず、引き継がれた後の古い持ち主は他人のロックを消さない', () => {
  const { c, file } = fresh();
  c.append({ type: 't' });
  assert.ok(!fs.existsSync(lockOf(file)));
  // 自分の check の中で、ロックが他人のものに入れ替わった（引き継がれた）場合
  const stolen = { pid: process.pid, host: os.hostname(), token: 'someone-else' };
  c.append({ type: 't' }, () => { fs.writeFileSync(path.join(lockOf(file), 'owner'), JSON.stringify(stolen)); });
  assert.ok(fs.existsSync(lockOf(file)));
  assert.equal(JSON.parse(readText(path.join(lockOf(file), 'owner'))).token, 'someone-else');
});

const holder = (file, mode) => `
import { openChain } from ${JSON.stringify(CHAIN_URL)};
const c = openChain(${JSON.stringify(file)}, { lockWaitMs: 5000 });
c.append({ type: 'hold' }, () => { process.stdout.write('held\\n'); ${mode === 'sleep' ? 'Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 60000);' : ''} });
`;
function startHolder(file) {
  const child = spawn(process.execPath, ['--input-type=module', '-e', holder(file, 'sleep')], { stdio: ['ignore', 'pipe', 'inherit'] });
  return new Promise((resolve, reject) => {
    child.stdout.once('data', () => resolve(child));
    child.once('error', reject);
    child.once('exit', () => reject(new Error('holder exited')));
  });
}
const exited = (child) => new Promise((r) => (child.exitCode !== null || child.signalCode !== null ? r() : child.once('exit', r)));

test('ロック（子プロセス）：ロックを持ったまま殺されれば引き継ぐ。生きている間は引き継がない', async () => {
  const { c, file } = fresh({ lockWaitMs: 200 });
  fill(c, 1);
  const child = await startHolder(file);
  try {
    assert.equal(brokenCode(() => c.append({ type: 't' })).code, 'lock_busy'); // 生きている
    assert.ok(JSON.parse(readText(path.join(lockOf(file), 'owner'))).pid === child.pid);
    child.kill('SIGKILL'); await exited(child);
    const r = c.append({ type: 't', after: 'kill' });
    assert.equal(r.seq, 2);
    assert.equal(r.recovered[0].kind, 'lock_takeover'); assert.equal(r.recovered[0].owner.pid, child.pid);
    assert.equal(c.verify().count, 2);
  } finally { child.kill('SIGKILL'); }
});

test('ロック（子プロセス）：複数が同時に引き継ごうとしても、全部の行が鎖としてつながる', async () => {
  const { c, file } = fresh({ lockWaitMs: 20000 });
  fill(c, 1);
  const child = await startHolder(file);
  child.kill('SIGKILL'); await exited(child);
  const N = 4; const M = 15;
  const script = `
import { openChain } from ${JSON.stringify(CHAIN_URL)};
const c = openChain(${JSON.stringify(file)}, { lockWaitMs: 30000 });
for (let i = 0; i < ${M}; i += 1) c.append({ type: 'w', who: process.pid, i });
`;
  const kids = Array.from({ length: N }, () => spawn(process.execPath, ['--input-type=module', '-e', script], { stdio: ['ignore', 'inherit', 'inherit'] }));
  const codes = await Promise.all(kids.map((k) => new Promise((r) => k.once('exit', r))));
  assert.deepEqual(codes, Array(N).fill(0));
  assert.deepEqual(c.verify(), { ok: true, count: 1 + N * M });
  const takeovers = c.recoveries().filter((e) => e.kind === 'lock_takeover');
  assert.equal(takeovers.length, 1, '引き継ぎはちょうど1回');
  assert.ok(!fs.existsSync(lockOf(file)));
});

test('並行の追記（子プロセス）：ロックなしの競合がなく、全部の行が鎖としてつながる', async () => {
  const { c, file } = fresh({ lockWaitMs: 20000 });
  const script = `
import { openChain } from ${JSON.stringify(CHAIN_URL)};
const c = openChain(${JSON.stringify(file)}, { lockWaitMs: 30000 });
for (let i = 0; i < 20; i += 1) c.append({ type: 'w', who: process.pid, i });
`;
  const kids = Array.from({ length: 4 }, () => spawn(process.execPath, ['--input-type=module', '-e', script], { stdio: ['ignore', 'inherit', 'inherit'] }));
  const codes = await Promise.all(kids.map((k) => new Promise((r) => k.once('exit', r))));
  assert.deepEqual(codes, Array(4).fill(0));
  assert.deepEqual(c.verify(), { ok: true, count: 80 });
  assert.deepEqual(c.recoveries(), []);
});

// ---- 書き込みの順序（fsync） ----

test('書き込みの順序：行の fsync → head の一時ファイルの fsync → rename → 親フォルダの fsync。最初の追記は親フォルダも先に fsync', () => {
  const { c, file, dir } = fresh();
  const log = [];
  const orig = { open: fs.openSync, fsync: fs.fsyncSync, rename: fs.renameSync };
  const fdName = new Map();
  fs.openSync = (p, ...a) => { const fd = orig.open(p, ...a); fdName.set(fd, path.basename(String(p))); return fd; };
  fs.fsyncSync = (fd) => { log.push(`fsync:${fdName.get(fd)}`); return orig.fsync(fd); };
  fs.renameSync = (a, b) => { log.push(`rename:${path.basename(a)}>${path.basename(b)}`); return orig.rename(a, b); };
  try { c.append({ type: 't' }); log.push('--'); c.append({ type: 't' }); } finally { Object.assign(fs, { openSync: orig.open, fsyncSync: orig.fsync, renameSync: orig.rename }); }
  const dn = path.basename(dir);
  const [first, second] = log.join(' ').split(' -- ');
  assert.equal(first, [`fsync:c.jsonl`, `fsync:${dn}`, 'fsync:c.jsonl.head.tmp', 'rename:c.jsonl.head.tmp>c.jsonl.head', `fsync:${dn}`, 'fsync:c.jsonl', 'fsync:c.jsonl.head.tmp', 'rename:c.jsonl.head.tmp>c.jsonl.head', `fsync:${dn}`].join(' '));
  assert.equal(second, ['fsync:c.jsonl', 'fsync:c.jsonl.head.tmp', 'rename:c.jsonl.head.tmp>c.jsonl.head', `fsync:${dn}`].join(' '));
  void file;
});

test('親フォルダの fsync が対応していない旨のエラー（EINVAL）は許して続け、それ以外（EIO）は投げる', () => {
  const origFsync = fs.fsyncSync; const origOpen = fs.openSync; const origClose = fs.closeSync;
  const dirs = new Set();
  const run = (code) => {
    const { c, dir } = fresh();
    fs.openSync = (p, ...a) => { const fd = origOpen(p, ...a); if (String(p) === dir) dirs.add(fd); return fd; };
    fs.fsyncSync = (fd) => { if (dirs.has(fd)) { const e = new Error(code); e.code = code; throw e; } return origFsync(fd); };
    fs.closeSync = (fd) => { dirs.delete(fd); return origClose(fd); };
    try { return c.append({ type: 't' }); } finally { fs.fsyncSync = origFsync; fs.openSync = origOpen; fs.closeSync = origClose; dirs.clear(); }
  };
  assert.equal(run('EINVAL').seq, 1);
  assert.throws(() => run('EIO'), (e) => e.code === 'EIO');
});

// ---- 独立した審査（4 回目）の発見 C-1〜C-6・L-1 と、変異の試験の生き残り ----

test('C-1：toJSON を持つ値・疎な配列・BigInt は not_canonical で拒み、何も書かない。記録はその後も使える', () => {
  const { c, file, dir } = fresh();
  fill(c, 1);
  const snap = snapshotDir(dir);
  const sparse = [1]; sparse[2] = 3;
  const withToJSON = { toJSON: () => 'x', a: 1 };
  for (const body of [{ type: 't', when: new Date(0) }, { type: 't', xs: sparse }, { type: 't', o: withToJSON }, { type: 't', n: 1n }, { type: 't', nested: { d: new Date(0) } }]) {
    const e = brokenCode(() => c.append(body));
    assert.equal(e.code, 'not_canonical', e.message);
    assert.deepEqual(snapshotDir(dir), snap);
  }
  assert.deepEqual(c.verify(), { ok: true, count: 1 });
  assert.equal(c.append({ type: 't' }).seq, 2);
  void file;
});

test('C-1（通す側）：JSON として同じに戻る値（undefined の欄、配列の中の undefined、-0、日本語・絵文字・制御文字）は通り、書いた行がそのまま読める', () => {
  const { c, file } = fresh();
  const r = c.append({ type: 't', skip: undefined, xs: [1, undefined, 3], z: -0, s: 'あ😀\u0001 ', big: 1e21, nested: { k: [{}] } });
  assert.deepEqual(r.xs, [1, null, 3]);
  assert.ok(!('skip' in r));
  const line = readText(file).trim();
  assert.equal(line, JSON.stringify(r));
  assert.deepEqual(c.verify(), { ok: true, count: 1 });
  assert.deepEqual(c.read()[0], r);
});

test('C-2：.head.tmp の記号リンクはたどらず、リンク先を書き換えない。unsafe_file で止め、head も進めない', { skip: process.platform === 'win32' }, () => {
  const { c, file } = fresh();
  fill(c, 1);
  const victim = path.join(tmp(), 'victim.txt'); fs.writeFileSync(victim, 'IMPORTANT\n');
  fs.symlinkSync(victim, `${file}.head.tmp`);
  const e = brokenCode(() => c.append({ type: 't' }));
  assert.equal(e.code, 'unsafe_file', e.message);
  assert.equal(e.detail, 'c.jsonl.head.tmp: not_regular');
  assert.equal(readText(victim), 'IMPORTANT\n');
  assert.equal(headOf(file).seq, 1);
});

test('C-2（競合）：lstat の後に記号リンクが置かれても、開くときにたどらない（O_NOFOLLOW）。lstat と開いたものが違えば止める', { skip: process.platform === 'win32' }, () => {
  // lstat の時点では無かった recovery.jsonl が、開く直前に記号リンクとして現れる
  {
    const { c, file } = fresh();
    fill(c, 1);
    const victim = path.join(tmp(), 'victim.txt'); fs.writeFileSync(victim, 'IMPORTANT\n');
    fs.appendFileSync(file, '{"torn');
    const rec = `${file}.recovery.jsonl`;
    const oOpen = fs.openSync; let planted = false;
    fs.openSync = function (p, ...a) { if (!planted && String(p) === rec) { planted = true; fs.symlinkSync(victim, rec); } return oOpen.call(fs, p, ...a); };
    let e;
    try { e = brokenCode(() => c.append({ type: 't' })); } finally { fs.openSync = oOpen; }
    assert.ok(planted);
    assert.equal(e.code, 'unsafe_file'); assert.equal(e.detail, 'c.jsonl.recovery.jsonl: symlink');
    assert.equal(readText(victim), 'IMPORTANT\n');
  }
  // lstat の後に、通常のファイルが別の通常のファイルに差し替えられる
  {
    const { c, file } = fresh();
    fill(c, 1);
    const rec = `${file}.recovery.jsonl`;
    fs.writeFileSync(rec, '');
    fs.appendFileSync(file, '{"torn');
    const oOpen = fs.openSync; let swapped = false;
    fs.openSync = function (p, ...a) { if (!swapped && String(p) === rec) { swapped = true; fs.writeFileSync(`${rec}.new`, 'other\n'); fs.renameSync(`${rec}.new`, rec); } return oOpen.call(fs, p, ...a); };
    let e;
    try { e = brokenCode(() => c.append({ type: 't' })); } finally { fs.openSync = oOpen; }
    assert.ok(swapped);
    assert.equal(e.code, 'unsafe_file'); assert.equal(e.detail, 'c.jsonl.recovery.jsonl: changed_while_opening');
    assert.equal(readText(rec), 'other\n');
  }
});

test('C-2（通す側）：前に落ちて残った通常のファイルの .head.tmp は消して書き直す', () => {
  const { c, file } = fresh();
  fill(c, 1);
  fs.writeFileSync(`${file}.head.tmp`, '{"seq":9');
  assert.equal(c.append({ type: 't' }).seq, 2);
  assert.ok(!fs.existsSync(`${file}.head.tmp`));
  assert.deepEqual(c.verify(), { ok: true, count: 2 });
});

test('C-2：.recovery.jsonl・本体の記号リンクとハードリンクはたどらず、リンク先に追記しない', { skip: process.platform === 'win32' }, () => {
  // 復旧の記録が記号リンク（形2の復旧を起こす）
  {
    const { c, file } = fresh();
    fill(c, 1);
    const victim = path.join(tmp(), 'victim.txt'); fs.writeFileSync(victim, 'IMPORTANT\n');
    fs.appendFileSync(file, '{"torn');
    fs.symlinkSync(victim, `${file}.recovery.jsonl`);
    const e = brokenCode(() => c.append({ type: 't' }));
    assert.equal(e.code, 'unsafe_file'); assert.equal(e.detail, 'c.jsonl.recovery.jsonl: not_regular'); // 開く前の lstat で止める（O_NOFOLLOW は二重の守り）
    assert.equal(readText(victim), 'IMPORTANT\n');
    assert.throws(() => c.recoveries(), (x) => x.code === 'unsafe_file');
  }
  // 復旧の記録がハードリンク
  {
    const { c, file } = fresh();
    fill(c, 1);
    const victim = path.join(tmp(), 'victim.txt'); fs.writeFileSync(victim, 'IMPORTANT\n');
    fs.appendFileSync(file, '{"torn');
    fs.linkSync(victim, `${file}.recovery.jsonl`);
    assert.equal(brokenCode(() => c.append({ type: 't' })).code, 'unsafe_file');
    assert.equal(readText(victim), 'IMPORTANT\n');
  }
  // 本体がハードリンク（追記がリンク先にも入る）
  {
    const { c, file } = fresh();
    fill(c, 1);
    const other = path.join(tmp(), 'other.jsonl');
    fs.linkSync(file, other);
    const before = readText(other);
    assert.equal(brokenCode(() => c.append({ type: 't' })).code, 'unsafe_file');
    assert.equal(readText(other), before);
  }
  // 本体がハードリンクで、書きかけの末尾がある（形2の切り詰めがリンク先も切り詰める）
  {
    const { c, file } = fresh();
    fill(c, 1);
    fs.appendFileSync(file, '{"torn');
    const other = path.join(tmp(), 'other.jsonl');
    fs.linkSync(file, other);
    const before = readText(other);
    const e = brokenCode(() => c.append({ type: 't' }));
    assert.equal(e.code, 'unsafe_file'); assert.equal(e.detail, 'c.jsonl: hardlink');
    assert.equal(readText(other), before);
  }
  // 記録のフォルダ自身が記号リンク
  {
    const real = tmp(); const linkDir = path.join(tmp(), 'linked');
    fs.symlinkSync(real, linkDir);
    const c = openChain(path.join(linkDir, 'c.jsonl'), { now: () => AT, lockWaitMs: 300 });
    assert.equal(brokenCode(() => c.append({ type: 't' })).code, 'unsafe_file');
    assert.deepEqual(fs.readdirSync(real), []);
  }
});

test('C-2（通す側）：通常のファイルの .recovery.jsonl には追記し、復旧が通る', () => {
  const { c, file } = fresh();
  fill(c, 1);
  fs.writeFileSync(`${file}.recovery.jsonl`, '');
  fs.appendFileSync(file, '{"torn');
  assert.equal(c.append({ type: 't' }).seq, 2);
  assert.deepEqual(c.recoveries().map((x) => x.kind), ['discard_torn']);
});

test('C-3：head がなく行がある記録は、読み手も head_missing で止める（1 行でも）。両方が空なら新しい記録', () => {
  const { c, file } = fresh();
  fill(c, 3);
  fs.rmSync(`${file}.head`);
  const first = readText(file).split('\n')[0];
  fs.writeFileSync(file, `${first}\n`);
  assert.deepEqual(c.verify(), { ok: false, code: 'chain_broken', detail: 'head_missing' });
  assert.equal(brokenCode(() => c.read()).detail, 'head_missing');
  assert.equal(brokenCode(() => c.append({ type: 't' })).detail, 'head_missing');
  // head がなく、書きかけの 1 行だけ
  fs.writeFileSync(file, '{"seq":1');
  assert.equal(c.verify().detail, 'head_missing');
  // 通す側：最初の追記の途中（空の本体を置いた後、head の前）で落ちた形は、空の記録として読める
  fs.writeFileSync(file, '');
  assert.deepEqual(c.verify(), { ok: true, count: 0 });
});

test('C-4：head の後ろの完全な 1 行が鎖につながらないとき、読み手は pending: unrecoverable を返す。書き手は止まる', () => {
  const { c, file } = fresh();
  fill(c, 1);
  fs.appendFileSync(file, '{"junk":1}\n');
  assert.deepEqual(c.verify(), { ok: true, count: 1, pending: 'unrecoverable' });
  assert.equal(brokenCode(() => c.append({ type: 't' })).code, 'chain_broken');
  // 通す側：鎖としてつながる 1 行は roll_forward のまま
  const f2 = fresh(); fill(f2.c, 1);
  fs.appendFileSync(f2.file, `${JSON.stringify(nextRow(f2.c.read()))}\n`);
  assert.equal(f2.c.verify().pending, 'roll_forward');
});

test('C-5：check が渡された配列を変えても、prev と seq は変わらず、鎖は壊れない', () => {
  const { c } = fresh();
  fill(c, 2);
  const r = c.append({ type: 't' }, (rs) => { rs.pop(); rs.length = 0; });
  assert.equal(r.seq, 3);
  assert.deepEqual(c.verify(), { ok: true, count: 3 });
  const r2 = c.append({ type: 't' }, (rs) => { rs.push({ hash: 'x' }); });
  assert.equal(r2.seq, 4); assert.equal(r2.prev, r.hash);
  assert.deepEqual(c.verify(), { ok: true, count: 4 });
});

test('C-6：重複したキー・空白・エスケープの違いなど、書いたとおりの綴りでない行は鎖が通らない（not_canonical_line）', () => {
  const variants = [
    ['重複したキー', (l) => l.replace('{', '{"verdict":"allow",')],
    ['空白を足した', (l) => l.replace(':', ': ')],
    ['文字をエスケープした', (l) => l.replace('"type"', '"\\u0074ype"')],
  ];
  for (const [name, change] of variants) {
    const { c, file } = fresh();
    c.append({ type: 't', verdict: 'deny' });
    const line = readText(file).trim();
    fs.writeFileSync(file, `${change(line)}\n`);
    assert.deepEqual(JSON.parse(change(line)).verdict, 'deny', name);
    assert.deepEqual(c.verify(), { ok: false, code: 'chain_broken', detail: 'not_canonical_line' }, name);
    assert.equal(brokenCode(() => c.append({ type: 't' })).code, 'chain_broken', name);
  }
  // head の後ろの 1 行が書いたとおりの綴りでなければ、形1の復旧の対象にしない
  const { c, file } = fresh();
  fill(c, 1);
  const row = nextRow(c.read());
  fs.appendFileSync(file, `${JSON.stringify(row).replace('{', '{"type":"forged",')}\n`);
  assert.equal(c.verify().pending, 'unrecoverable');
  assert.equal(brokenCode(() => c.append({ type: 't' })).code, 'chain_broken');
});

test('L-1：ロックの持ち主の情報を書けなかったとき、ロックを消さずに投げる（確かめられない他人のロックに触らない）', () => {
  const { c, file } = fresh();
  const orig = fs.writeFileSync;
  let planted = false;
  fs.writeFileSync = function (p, ...a) {
    if (!planted && String(p) === path.join(lockOf(file), 'owner')) {
      planted = true;
      // 止まっている間に、別の者が空のロックを引き継いで持ち主の情報を書いた
      orig.call(fs, p, JSON.stringify({ pid: process.pid, host: os.hostname(), token: 'other' }));
    }
    return orig.call(fs, p, ...a);
  };
  try {
    assert.throws(() => c.append({ type: 't' }), (e) => e.code === 'EEXIST');
  } finally { fs.writeFileSync = orig; }
  assert.ok(fs.existsSync(lockOf(file)), '他人のロックを消した');
  assert.equal(JSON.parse(readText(path.join(lockOf(file), 'owner'))).token, 'other');
});

test('変異 #0：seq だけが違う行（prev とハッシュは正しい）を止める', () => {
  const { c, file } = fresh();
  fill(c, 3);
  const rows = c.read();
  const r2 = (() => { const { hash, ...b } = rows[1]; const f = { ...b, seq: 7 }; return { ...f, hash: sha256(canonical(f)) }; })();
  const r3 = (() => { const { hash, ...b } = rows[2]; const f = { ...b, prev: r2.hash }; return { ...f, hash: sha256(canonical(f)) }; })();
  fs.writeFileSync(file, `${[rows[0], r2, r3].map((r) => JSON.stringify(r)).join('\n')}\n`);
  writeHeadRaw(file, 3, r3.hash);
  assert.deepEqual(c.verify(), { ok: false, code: 'chain_broken', detail: 'seq 2' });
});

test('変異 #7：head のハッシュが末尾と合わない記録には、復旧（退避・切り詰め・head を進める）で手を入れない', () => {
  for (const [name, add] of [
    ['書きかけの末尾', (file) => fs.appendFileSync(file, '{"x"')],
    ['鎖につながる完全な 1 行', (file, rows) => fs.appendFileSync(file, `${JSON.stringify(nextRow(rows))}\n`)],
  ]) {
    const { c, file, dir } = fresh();
    fill(c, 3);
    const rows = c.read();
    writeHeadRaw(file, 3, 'e'.repeat(64));
    add(file, rows);
    const snap = snapshotDir(dir);
    assert.equal(brokenCode(() => c.append({ type: 't' })).code, 'chain_broken', name);
    assert.deepEqual(snapshotDir(dir), snap, name);
    assert.deepEqual(c.recoveries(), [], name);
  }
});

test('変異 #2・#4・#23・#18：止める理由の文字列（head_missing・truncated_line・empty_line・torn_tail）', () => {
  // #2：書き手は head がない記録を head_missing で止める
  { const { c, file } = fresh(); fill(c, 3); fs.rmSync(`${file}.head`); assert.equal(brokenCode(() => c.append({ type: 't' })).detail, 'head_missing'); }
  // #4：読み手は、head が指す最後の行の改行が欠けた記録を truncated_line で止める
  { const { c, file } = fresh(); fill(c, 3); fs.writeFileSync(file, readText(file).slice(0, -1)); assert.deepEqual(c.verify(), { ok: false, code: 'chain_broken', detail: 'truncated_line' }); }
  // #23：空行（読み手・書き手）
  {
    const { c, file } = fresh(); fill(c, 3);
    const ls = readText(file).split('\n').filter(Boolean);
    fs.writeFileSync(file, `${ls[0]}\n\n${ls.slice(1).join('\n')}\n`);
    assert.equal(c.verify().detail, 'empty_line');
    assert.equal(brokenCode(() => c.append({ type: 't' })).detail, 'empty_line');
  }
  // #18：repairHead は書きかけの末尾を torn_tail で止める（行として完全でも改行がなければ）
  {
    const { c, file } = fresh(); fill(c, 3); const last = c.read()[2];
    fs.rmSync(`${file}.head`); fs.writeFileSync(file, readText(file).slice(0, -1));
    assert.equal(brokenCode(() => c.repairHead({ reason: 'r', expect: { seq: 3, hash: last.hash } })).detail, 'torn_tail');
  }
});

test('変異 #25：引き継ぎの確かめの後、rename の前にロックが入れ替わったら、入れ替わったロックを動かさない', () => {
  const { c, file } = fresh({ lockWaitMs: 150 });
  plantLock(file, { pid: deadPid(), host: os.hostname(), started: AT, token: 'dead' });
  const live = JSON.stringify({ pid: process.pid, host: os.hostname(), token: 'live' });
  const oRead = fs.readFileSync; const oRename = fs.renameSync;
  let swapped = false; const renamed = [];
  fs.readFileSync = function (p, ...a) {
    const out = oRead.call(fs, p, ...a);
    if (!swapped && String(p) === path.join(lockOf(file), 'owner')) {
      swapped = true; // 死んだ持ち主を読んだ直後に、別の者が引き継いで生きたロックを置いた
      fs.rmSync(lockOf(file), { recursive: true, force: true });
      fs.mkdirSync(lockOf(file)); fs.writeFileSync(path.join(lockOf(file), 'owner'), live);
    }
    return out;
  };
  fs.renameSync = function (a, b) { renamed.push(String(a)); return oRename.call(fs, a, b); };
  try {
    assert.equal(brokenCode(() => c.append({ type: 't' })).code, 'lock_busy');
  } finally { fs.readFileSync = oRead; fs.renameSync = oRename; }
  assert.ok(swapped);
  assert.ok(!renamed.includes(lockOf(file)), '生きたロックを rename した');
  assert.equal(readText(path.join(lockOf(file), 'owner')), live);
});

test('変異 #26：rename の直前にロックが入れ替わり、生きたロックを動かしてしまったら、元に戻して引き継がない', () => {
  const { c, file } = fresh({ lockWaitMs: 150 });
  plantLock(file, { pid: deadPid(), host: os.hostname(), started: AT, token: 'dead' });
  const live = JSON.stringify({ pid: process.pid, host: os.hostname(), token: 'live' });
  const oRename = fs.renameSync;
  let swapped = false;
  fs.renameSync = function (a, b) {
    if (!swapped && String(a) === lockOf(file)) {
      swapped = true;
      fs.rmSync(lockOf(file), { recursive: true, force: true });
      fs.mkdirSync(lockOf(file)); fs.writeFileSync(path.join(lockOf(file), 'owner'), live);
    }
    return oRename.call(fs, a, b);
  };
  try {
    assert.equal(brokenCode(() => c.append({ type: 't' })).code, 'lock_busy');
  } finally { fs.renameSync = oRename; }
  assert.ok(swapped);
  assert.equal(readText(path.join(lockOf(file), 'owner')), live, '生きたロックが戻っていない');
  assert.deepEqual(c.recoveries(), []);
});

// ---- 性能 ----

for (const n of [100, 2000]) {
  test(`性能：${n} 件の記録での追記1回の時間（報告用。大きく悪化していないこと）`, () => {
    const { c } = fresh();
    for (let i = 0; i < n; i += 1) c.append({ type: 'bench', i, payload: 'x'.repeat(120) });
    const ts = [];
    for (let k = 0; k < 5; k += 1) { const t0 = process.hrtime.bigint(); c.append({ type: 'bench', i: -1, payload: 'x'.repeat(120) }); ts.push(Number(process.hrtime.bigint() - t0) / 1e6); }
    ts.sort((a, b) => a - b);
    const med = ts[2];
    console.log(`# 追記1回（${n} 件）：中央値 ${med.toFixed(1)} ms`);
    assert.ok(med < 500, `${med} ms`);
  });
}
