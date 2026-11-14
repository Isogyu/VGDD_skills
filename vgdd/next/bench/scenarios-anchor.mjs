// 外部への固定（anchor）の攻撃と良性のシナリオ。
// 一時ディレクトリに見本の記録（tool_calls・ledger・chain.mjs の記録・承認・裁定・チェックポイント・判定の集まり）を作り、
// snapshot の後に手を加え、verifyContext（照合の発見）や contextFor（状態を書かない書き込みの文脈）を check(ctx, guardNames) で確かめる。
// 文脈は 1 回だけ作って使い回す（同期）。ネットワークには出ない。
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { openChain, canonical, sha256 } from '../lib/chain.mjs';
import { openAnchors, check, anchorOf, RULES } from '../anchor.mjs';

export const MODULE = 'anchor';
export { GUARDS } from '../anchor.mjs';

// ---------------------------------------------------------------------------
// 行為者
// ---------------------------------------------------------------------------
export const A = {
  runner: { role: 'gate_runner', kind: 'script', id: 'gate-runner', lineage: 'script' },
  owner: { role: 'owner', kind: 'human', id: 'owner', lineage: 'human' },
  worker: { role: 'worker', kind: 'ai', id: 'claude-worker-1', lineage: 'claude' },
  exec: { role: 'executive_head', kind: 'ai', id: 'claude-exec-1', lineage: 'claude' },
  judge: { role: 'judge', kind: 'ai', id: 'claude-judge-1', lineage: 'claude' },
  assistant: { role: 'legislative_assistant', kind: 'ai', id: 'claude-assistant-1', lineage: 'claude' },
  night: { role: 'night_runner', kind: 'script', id: 'night-runner', lineage: 'script' },
};

// ---------------------------------------------------------------------------
// 見本の記録を作る道具（試験からも使う）
// ---------------------------------------------------------------------------
export const tmp = () => fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'vgdd-next-')));
export const rm = (d) => fs.rmSync(d, { recursive: true, force: true });
const sh = (s) => crypto.createHash('sha256').update(s).digest('hex');
const AT = '2026-11-14T09:00:00+09:00';

/** tool_calls の方式：各行が前の行の文字列の SHA-256 を prev_hash に持つ */
export function writeToolCalls(file, n, mark = 'tc') {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, '');
  appendToolCalls(file, n, mark);
}
export function appendToolCalls(file, n, mark = 'tc') {
  const text = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
  const lines = text.split('\n').filter(Boolean);
  let prev = lines.length ? `sha256:${sh(lines[lines.length - 1])}` : 'sha256:genesis';
  let out = '';
  for (let i = 0; i < n; i += 1) {
    const seq = lines.length + i + 1;
    const line = JSON.stringify({ event_id: `evt-${String(seq).padStart(6, '0')}`, seq, prev_hash: prev, type: 'tool_call', operation: 'Read', note: `${mark} ${seq} ${'x'.repeat(60)}` });
    out += `${line}\n`; prev = `sha256:${sh(line)}`;
  }
  fs.appendFileSync(file, out);
}
/** ledger の方式：hash は JSON.stringify(本体) の SHA-256、ledger.head に最後の番号とハッシュ */
export function writeLedger(file, n, mark = 'lg') {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, ''); fs.rmSync(path.join(path.dirname(file), 'ledger.head'), { force: true });
  appendLedger(file, n, mark);
}
export function appendLedger(file, n, mark = 'lg') {
  const head = path.join(path.dirname(file), 'ledger.head');
  const lines = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map(JSON.parse);
  let prev = lines.length ? lines[lines.length - 1].hash : 'genesis'; let seq = lines.length; let out = '';
  for (let i = 0; i < n; i += 1) {
    seq += 1;
    const full = { type: 'begin', run_id: `${mark}-${seq}`, tokens: seq * 10, seq, at: AT, prev };
    const hash = sh(JSON.stringify(full));
    out += `${JSON.stringify({ ...full, hash })}\n`; prev = hash;
  }
  fs.appendFileSync(file, out); fs.writeFileSync(head, `${JSON.stringify({ seq, hash: prev })}\n`);
}
/** 試作の鎖つき記録（chain.mjs） */
export function writeChainRec(file, n, mark = 'ch') {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  appendChainRec(file, n, mark);
}
export function appendChainRec(file, n, mark = 'ch') {
  const c = openChain(file, { now: () => AT });
  const have = c.read().length;
  for (let i = 0; i < n; i += 1) c.append({ type: 'x', mark, i: have + i, pad: 'y'.repeat(40) });
}
/** 鎖のない追記の記録 */
export function writePlain(file, n, mark = 'pl') {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, '');
  appendPlain(file, n, mark);
}
export function appendPlain(file, n, mark = 'pl') {
  const have = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).length;
  let out = ''; for (let i = 0; i < n; i += 1) out += `${JSON.stringify({ n: have + i + 1, mark, ts: AT })}\n`;
  fs.appendFileSync(file, out);
}
/** 判定のファイルの集まり */
export function writeDir(dir, n, mark = 'v') {
  fs.mkdirSync(dir, { recursive: true });
  for (let i = 0; i < n; i += 1) fs.writeFileSync(path.join(dir, `VRD-${mark}${String(i).padStart(3, '0')}.json`), JSON.stringify({ verdict: 'APPROVED', i }));
}

/** 行を書き換えて、その後ろの鎖を全部作り直す（今の仕組みでは検出できない攻撃）。fn(bodies) で本体の配列を変える。head も作り直す */
export function rechain(scheme, file, fn) {
  const lines = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean);
  if (scheme === 'tool_calls') {
    const objs = lines.map(JSON.parse); fn(objs);
    let prev = 'sha256:genesis'; let out = '';
    objs.forEach((o, i) => { o.seq = i + 1; o.prev_hash = prev; const l = JSON.stringify(o); out += `${l}\n`; prev = `sha256:${sh(l)}`; });
    fs.writeFileSync(file, out); return;
  }
  const strip = ({ seq, at, prev, hash, ...b }) => ({ b, at }); // eslint-disable-line no-unused-vars
  const items = lines.map(JSON.parse).map(strip); const bodies = items.map((x) => x.b); fn(bodies);
  let prev = 'genesis'; let out = ''; let last = 'genesis';
  bodies.forEach((b, i) => {
    const full = { ...b, seq: i + 1, at: items[i] ? items[i].at : AT, prev };
    const hash = scheme === 'ledger' ? sh(JSON.stringify(full)) : sha256(canonical(full));
    out += `${JSON.stringify({ ...full, hash })}\n`; prev = hash; last = hash;
  });
  fs.writeFileSync(file, out);
  const headFile = scheme === 'ledger' ? path.join(path.dirname(file), 'ledger.head') : `${file}.head`;
  fs.writeFileSync(headFile, `${JSON.stringify({ seq: bodies.length, hash: last })}\n`);
}

/** 標準の見本一式。tool_calls・ledger・trace（chain）・承認・裁定・チェックポイント・判定の集まり */
export function world(dir, n = 20) {
  const f = (x) => path.join(dir, x);
  const files = {
    tool_calls: f('z3/evidence/tool_calls.jsonl'), ledger: f('z3/budget/ledger.jsonl'), trace: f('z3/trace.jsonl'),
    spec_approvals: f('z3/spec_approvals.jsonl'), rulings: f('z3/rulings.jsonl'), checkpoints: f('z3/evidence/checkpoints.jsonl'), verdicts: f('z3/verdicts'),
  };
  writeToolCalls(files.tool_calls, n); writeLedger(files.ledger, n); writeChainRec(files.trace, n);
  writePlain(files.spec_approvals, n); writePlain(files.rulings, n); writePlain(files.checkpoints, n); writeDir(files.verdicts, 5);
  const sources = [
    { name: 'tool_calls', path: files.tool_calls, kind: 'chained', scheme: 'tool_calls' },
    { name: 'ledger', path: files.ledger, kind: 'chained', scheme: 'ledger' },
    { name: 'trace', path: files.trace, kind: 'chained', scheme: 'chain' },
    { name: 'spec_approvals', path: files.spec_approvals, kind: 'plain' },
    { name: 'rulings', path: files.rulings, kind: 'plain' },
    { name: 'checkpoints', path: files.checkpoints, kind: 'plain' },
    { name: 'verdicts', path: files.verdicts, kind: 'dir' },
  ];
  let tick = 0; let nonceN = 0;
  const now = () => new Date(Date.UTC(2026, 10, 14, 0, 0, tick++)).toISOString();
  const nonce = () => sh(`nonce-${nonceN++}`);
  const anchorsFile = f('anchors/anchors.jsonl');
  const open = (o = {}) => openAnchors(anchorsFile, { sources, now, nonce, ...o });
  const grow = (k = 3) => {
    appendToolCalls(files.tool_calls, k); appendLedger(files.ledger, k); appendChainRec(files.trace, k);
    appendPlain(files.spec_approvals, k); appendPlain(files.rulings, k); appendPlain(files.checkpoints, k);
  };
  return { dir, files, sources, anchorsFile, open, now, grow };
}

/** anchors の記録の行を鎖ごと作り直す（記録と head を一緒に差し替える攻撃） */
export function rechainAnchors(file, fn) {
  const items = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map(JSON.parse);
  const rows = items.map(({ seq, prev, hash, ...r }) => r); // eslint-disable-line no-unused-vars
  const out = fn(rows) || rows;
  let prev = 'genesis'; let text = ''; let last = 'genesis';
  out.forEach((r, i) => { const full = { ...r, seq: i + 1, prev }; const hash = sha256(canonical(full)); text += `${JSON.stringify({ ...full, hash })}\n`; prev = hash; last = hash; });
  fs.writeFileSync(file, text); fs.writeFileSync(`${file}.head`, `${JSON.stringify({ seq: out.length, hash: last })}\n`);
}

// ---------------------------------------------------------------------------
// シナリオ
// ---------------------------------------------------------------------------

/** build(dir, w) → ctx（照合や書き込みの文脈）。作った一時ディレクトリは文脈を作った後に消す（文脈は記憶の中だけで検査される） */
function scenario(id, kind, title, expectGuards, build) {
  let ctx = null;
  const make = () => { const dir = tmp(); try { return build(dir, world(dir)); } finally { rm(dir); } };
  return { id, kind, title, expectGuards, run: (guardNames) => { ctx = ctx || make(); const r = check(ctx, guardNames); return { blocked: !r.ok, by: r.violations.map((v) => v.guard) }; } };
}
/** 2 回 snapshot（間に追記）してから tamper(w) し、照合の文脈を返す */
const detect = (tamper, { snaps = 2, verifyOpt } = {}) => (dir, w) => {
  const an = w.open();
  an.snapshot(A.runner);
  for (let i = 1; i < snaps; i += 1) { w.grow(3); an.snapshot(A.runner); }
  tamper(w, an);
  return an.verifyContext(verifyOpt);
};
const lineOf = (file, i) => fs.readFileSync(file, 'utf8').split('\n')[i];
const setLine = (file, i, text) => { const l = fs.readFileSync(file, 'utf8').split('\n'); l[i] = text; fs.writeFileSync(file, l.join('\n')); };
const flipAt = (file, off) => { const b = fs.readFileSync(file); b[off] = b[off] === 0x78 ? 0x79 : 0x78; fs.writeFileSync(file, b); };
const R2 = ['AN-PREFIX-MATCH', 'AN-NOT-TRUNCATED'];
const PM = ['AN-PREFIX-MATCH'];
const SRC = (n, p, k = 'plain', s) => ({ name: n, path: p, kind: k, ...(s ? { scheme: s } : {}) });

const REC = {
  tool_calls: (w) => w.files.tool_calls, ledger: (w) => w.files.ledger, trace: (w) => w.files.trace,
};
const rechainOf = (name) => (w, fn) => rechain(name === 'tool_calls' ? 'tool_calls' : name === 'ledger' ? 'ledger' : 'chain', REC[name](w), fn);

export const SCENARIOS = [
  // ---- 攻撃：対象の記録（検出は照合で行う） ----
  ...['tool_calls', 'ledger', 'trace'].map((nm, k) => scenario(`AN-A${k + 1}`, 'attack', `鎖のある記録（${nm}）の途中の行を書き換え、後ろの鎖と head を全部作り直す`, PM,
    detect((w) => rechainOf(nm)(w, (b) => { b[4].tamper = 'x'; })))),
  scenario('AN-A4', 'attack', '鎖のある記録の最初の行を書き換えて鎖を作り直す（tool_calls）', PM, detect((w) => rechain('tool_calls', w.files.tool_calls, (b) => { b[0].note = 'forged'; }))),
  scenario('AN-A5', 'attack', 'anchor の時点の末尾の行（最後の行）を同じ長さで書き換えて鎖を作り直す（ledger）', PM, detect((w) => rechain('ledger', w.files.ledger, (b) => { b[b.length - 1].type = 'bogin'; }), { snaps: 1 })),
  scenario('AN-A6', 'attack', '末尾の 1 行を切り詰める（tool_calls）', ['AN-NOT-TRUNCATED'], detect((w) => {
    const t = fs.readFileSync(w.files.tool_calls, 'utf8').split('\n').filter(Boolean); fs.writeFileSync(w.files.tool_calls, `${t.slice(0, -1).join('\n')}\n`);
  }, { snaps: 1 })),
  scenario('AN-A7', 'attack', '末尾を切り詰め、head も合わせて作り直す（ledger。今の仕組みでは検出できない）', ['AN-NOT-TRUNCATED'], detect((w) => {
    rechain('ledger', w.files.ledger, (b) => { b.length -= 4; });
  }, { snaps: 1 })),
  scenario('AN-A8', 'attack', '途中の行を 1 行抜いて鎖を作り直す（anchor の後に追記があり、大きさは anchor の時点より大きいまま）', R2, detect((w) => {
    rechain('tool_calls', w.files.tool_calls, (b) => { b.splice(6, 1); });
  })),
  scenario('AN-A9', 'attack', '行を入れ替える（chain 方式。後ろの鎖と head を作り直す）', PM, detect((w) => {
    rechain('chain', w.files.trace, (b) => { const t = b[2]; b[2] = b[3]; b[3] = t; });
  })),
  scenario('AN-A10', 'attack', '1 バイトだけ変える（先頭）', PM, detect((w) => flipAt(w.files.spec_approvals, 3), { snaps: 1 })),
  scenario('AN-A11', 'attack', '1 バイトだけ変える（途中）', PM, detect((w) => flipAt(w.files.spec_approvals, Math.floor(fs.statSync(w.files.spec_approvals).size / 2) | 1), { snaps: 1 })),
  scenario('AN-A12', 'attack', '1 バイトだけ変える（anchor の時点の末尾の直前）', PM, detect((w, an) => {
    const bytes = an.state().anchors[0].manifest.sources.find((s) => s.name === 'rulings').bytes; flipAt(w.files.rulings, bytes - 3);
  }, { snaps: 1 })),
  scenario('AN-A13', 'attack', '鎖のない記録（承認）の途中の行を書き換える（同じ長さ）', PM, detect((w) => setLine(w.files.spec_approvals, 5, lineOf(w.files.spec_approvals, 5).replace('"pl"', '"xx"')), { snaps: 1 })),
  scenario('AN-A14', 'attack', '鎖のない記録（裁定）の途中の行を消す', R2, detect((w) => {
    const l = fs.readFileSync(w.files.rulings, 'utf8').split('\n'); l.splice(5, 1); fs.writeFileSync(w.files.rulings, l.join('\n'));
  })),
  scenario('AN-A15', 'attack', 'チェックポイントの記録の行を消す', R2, detect((w) => {
    const l = fs.readFileSync(w.files.checkpoints, 'utf8').split('\n'); l.splice(2, 1); fs.writeFileSync(w.files.checkpoints, l.join('\n'));
  })),
  scenario('AN-A16', 'attack', '記録のファイルごと消す', ['AN-SOURCE-PRESENT'], detect((w) => fs.rmSync(w.files.spec_approvals), { snaps: 1 })),
  scenario('AN-A17', 'attack', '記録を空にする', ['AN-NOT-TRUNCATED'], detect((w) => fs.writeFileSync(w.files.rulings, ''), { snaps: 1 })),
  scenario('AN-A18', 'attack', '別の内容に差し替える（同じ大きさ以上）', PM, detect((w) => fs.writeFileSync(w.files.rulings, `${'{"forged":true}\n'.repeat(2000)}`), { snaps: 1 })),
  scenario('AN-A19', 'attack', '記号リンクに差し替える', ['AN-SOURCE-PRESENT'], detect((w) => {
    const real = `${w.files.rulings}.real`; fs.writeFileSync(real, fs.readFileSync(w.files.rulings)); fs.rmSync(w.files.rulings); fs.symlinkSync(real, w.files.rulings);
  }, { snaps: 1 })),
  scenario('AN-A20', 'attack', '判定のファイルを 1 つ書き換える', ['AN-DIR-ENTRIES'], detect((w) => fs.writeFileSync(path.join(w.files.verdicts, 'VRD-v002.json'), '{"verdict":"APPROVED","forged":1}'), { snaps: 1 })),
  scenario('AN-A21', 'attack', '判定のファイルを 1 つ消す', ['AN-DIR-ENTRIES'], detect((w) => fs.rmSync(path.join(w.files.verdicts, 'VRD-v001.json')), { snaps: 1 })),
  scenario('AN-A22', 'attack', '判定の集まりのディレクトリごと消す', ['AN-SOURCE-PRESENT'], detect((w) => fs.rmSync(w.files.verdicts, { recursive: true }), { snaps: 1 })),
  scenario('AN-A23', 'attack', '判定のファイルを記号リンクに差し替える', ['AN-DIR-ENTRIES'], detect((w) => {
    const p = path.join(w.files.verdicts, 'VRD-v003.json'); const c = fs.readFileSync(p); fs.rmSync(p); fs.writeFileSync(`${p}.real`, c); fs.symlinkSync(`${p}.real`, p);
  }, { snaps: 1 })),
  // ---- 攻撃：anchor の記録そのもの ----
  scenario('AN-A24', 'attack', 'anchor の記録の行の時刻を書き換える（鎖は作り直さない）', ['AN-CHAIN-INTACT'], detect((w) => {
    const f = w.anchorsFile; const l = fs.readFileSync(f, 'utf8').split('\n'); const o = JSON.parse(l[0]); o.at = '2020-01-01T00:00:00+09:00'; l[0] = JSON.stringify(o); fs.writeFileSync(f, l.join('\n'));
  })),
  scenario('AN-A25', 'attack', 'anchor の行を消す（鎖は作り直さない）', ['AN-CHAIN-INTACT'], detect((w) => {
    const l = fs.readFileSync(w.anchorsFile, 'utf8').split('\n'); l.splice(0, 1); fs.writeFileSync(w.anchorsFile, l.join('\n'));
  })),
  scenario('AN-A26', 'attack', 'anchor の記録の manifest を書き換え、鎖と head を作り直す（anchor の値はそのまま）', ['AN-MANIFEST-DIGEST'], detect((w) => {
    rechainAnchors(w.anchorsFile, (rows) => { rows[0].manifest.sources[0].bytes = 1; });
  })),
  scenario('AN-A27', 'attack', '途中の anchor の行を抜き、鎖と head を作り直す', ['AN-ANCHOR-LINK'], detect((w) => {
    rechainAnchors(w.anchorsFile, (rows) => { rows.splice(1, 1); });
  }, { snaps: 3 })),
  scenario('AN-A28', 'attack', 'AI の役割（worker）が書いた anchor の行を、鎖を作り直して差し込む', ['AN-REPLAY-CLEAN'], detect((w, an) => {
    rechainAnchors(w.anchorsFile, (rows) => { rows[1] = { ...rows[1], actor: A.worker }; });
  })),
  scenario('AN-A29', 'attack', '記録の本体を書き換えて作り直し、anchor の記録も全部作り直す（外部が保持する anchor の値があれば検出できる）', ['AN-PINNED-PRESENT'], (dir, w) => {
    const an = w.open(); const first = an.snapshot(A.runner); w.grow(3); const second = an.snapshot(A.runner);
    // 書き換え：本体を作り直し、anchor の記録を消して、新しい状態から snapshot をやり直す
    rechain('tool_calls', w.files.tool_calls, (b) => { b[4].tamper = 'x'; });
    fs.rmSync(w.anchorsFile); fs.rmSync(`${w.anchorsFile}.head`);
    const an2 = w.open(); an2.snapshot(A.runner);
    return an2.verifyContext({ pinned: [first.anchor, second.anchor] });
  }),
  // ---- 攻撃：書き込み（ガード）。照合でなく書き込みの文脈で止める ----
  scenario('AN-A30', 'attack', '裁判所のスクリプトが、都合の悪い記録を対象から外して snapshot する（オーナーの epoch が設定の変更だけを受け入れた後）', ['AN-SOURCE-SHRINK'], (dir, w) => {
    w.open().snapshot(A.runner);
    const reduced = w.sources.filter((s) => s.name !== 'rulings');
    w.open({ sources: reduced }).epoch(A.owner, { reason: '設定の変更を受け入れる（drops なし）' });
    return w.open({ sources: reduced }).contextFor('snapshot', A.runner);
  }),
  scenario('AN-A31', 'attack', '設定を変えて開く（パスを別のファイルにすり替える。オーナーの epoch まで止まる）', ['AN-CFG-COPY'], (dir, w) => {
    w.open().snapshot(A.runner);
    const other = path.join(dir, 'other.jsonl'); writePlain(other, 20);
    const swapped = w.sources.map((s) => (s.name === 'rulings' ? { ...s, path: other } : s));
    return w.open({ sources: swapped }).contextFor('snapshot', A.runner);
  }),
  scenario('AN-A32', 'attack', '設定を変えて開く（記録を足す。対象を増やす変更も写しと食い違えば止まる）', ['AN-CFG-COPY'], (dir, w) => {
    w.open().snapshot(A.runner);
    const extra = path.join(dir, 'held.jsonl'); writePlain(extra, 3);
    const an0 = w.open(); const last = an0.state().anchors[0].anchor;
    return w.open({ sources: [...w.sources, SRC('held', extra)] }).contextFor('receipt', A.runner, { anchor: last, method: 'git', ref: 'git:refs/tags/a', digest: `sha256:${'b'.repeat(64)}` });
  }),
  ...[['worker', A.worker], ['judge', A.judge], ['legislative_assistant', A.assistant], ['executive_head', A.exec], ['night_runner（スクリプトだが裁判所の側でない）', A.night]]
    .map(([label, who], k) => scenario(`AN-A${33 + k}`, 'attack', `${label} が snapshot を書く`, ['AN-WRITER-ROLE'], (dir, w) => w.open().contextFor('snapshot', who))),
  scenario('AN-A38', 'attack', 'AI の役割（judge）が receipt を書く', ['AN-WRITER-ROLE'], (dir, w) => {
    const an = w.open(); const s = an.snapshot(A.runner);
    return an.contextFor('receipt', A.judge, { anchor: s.anchor, method: 'git', ref: 'git:refs/tags/a1', digest: `sha256:${'c'.repeat(64)}` });
  }),
  scenario('AN-A39', 'attack', '表記ゆれ：全角・大文字の役割名で AI の役割（worker）を名乗る', ['AN-WRITER-ROLE'], (dir, w) => w.open().contextFor('snapshot', { ...A.worker, role: ' ＷＯＲＫＥＲ ' })),
  scenario('AN-A40', 'attack', 'gate_runner を ai の種類で名乗る（役割の表と種類が合わない）', ['AN-ACTOR-SHAPE'], (dir, w) => w.open().contextFor('snapshot', { role: 'gate_runner', kind: 'ai', id: 'gate-runner', lineage: 'claude' })),
  scenario('AN-A41', 'attack', '役割が表にない行為者が snapshot を書く', ['AN-ACTOR-SHAPE'], (dir, w) => w.open().contextFor('snapshot', { role: 'auditor', kind: 'human', id: 'x' })),
  scenario('AN-A42', 'attack', '裁判所のスクリプト（gate_runner）が epoch を書く', ['AN-OWNER-ONLY'], (dir, w) => w.open().contextFor('epoch', A.runner, { reason: '移行' })),
  scenario('AN-A43', 'attack', 'AI の役割（assistant）が epoch を書く（表記ゆれの種類）', ['AN-OWNER-ONLY'], (dir, w) => w.open().contextFor('epoch', A.assistant, { reason: '移行' })),
  scenario('AN-A44', 'attack', 'snapshot に入力（記録の指定）を渡す', ['AN-INPUT-SHAPE'], (dir, w) => w.open().contextFor('snapshot', A.runner, { sources: [] })),
  scenario('AN-A45', 'attack', 'receipt に知らない欄を足す', ['AN-INPUT-SHAPE'], (dir, w) => {
    const an = w.open(); const s = an.snapshot(A.runner);
    return an.contextFor('receipt', A.runner, { anchor: s.anchor, method: 'git', ref: 'git:refs/tags/a1', digest: `sha256:${'c'.repeat(64)}`, verified: true });
  }),
  scenario('AN-A46', 'attack', 'receipt の ref が文字列でない（型のゆれ）', ['AN-INPUT-SHAPE'], (dir, w) => {
    const an = w.open(); const s = an.snapshot(A.runner);
    return an.contextFor('receipt', A.runner, { anchor: s.anchor, method: 'git', ref: 12345, digest: `sha256:${'c'.repeat(64)}` });
  }),
  scenario('AN-A47', 'attack', 'epoch に理由がない', ['AN-INPUT-SHAPE'], (dir, w) => w.open().contextFor('epoch', A.owner, { reason: '  ' })),
  scenario('AN-A48', 'attack', '記録の名前が書式に合わない（大文字・記号）', ['AN-SOURCES-ALLOWLIST'], (dir, w) => w.open({ sources: [SRC('Bad-Name!', w.files.rulings)] }).contextFor('snapshot', A.runner)),
  scenario('AN-A49', 'attack', 'kind が許可リストにない', ['AN-SOURCES-ALLOWLIST'], (dir, w) => w.open({ sources: [{ name: 'x', path: w.files.rulings, kind: 'glob' }] }).contextFor('snapshot', A.runner)),
  scenario('AN-A50', 'attack', '正規化すると同じ名前の記録が 2 つある（全角と半角）', ['AN-SOURCES-ALLOWLIST'], (dir, w) => w.open({ sources: [SRC('rulings', w.files.rulings), SRC('ｒulings', w.files.checkpoints)] }).contextFor('snapshot', A.runner)),
  scenario('AN-A51', 'attack', '記録の数が上限を超える', ['AN-SOURCES-ALLOWLIST'], (dir, w) => w.open({ limits: { maxSources: 2 } }).contextFor('snapshot', A.runner)),
  scenario('AN-A52', 'attack', '相対パスを指定する', ['AN-PATH-SAFE'], (dir, w) => w.open({ sources: [SRC('rulings', 'z3/rulings.jsonl')] }).contextFor('snapshot', A.runner)),
  scenario('AN-A53', 'attack', 'パスに .. を含める', ['AN-PATH-SAFE'], (dir, w) => w.open({ sources: [SRC('rulings', `${path.dirname(w.files.rulings)}/../z3/rulings.jsonl`)] }).contextFor('snapshot', A.runner)),
  scenario('AN-A54', 'attack', 'anchor の記録自身を対象にする', ['AN-PATH-SAFE'], (dir, w) => w.open({ sources: [SRC('self', w.anchorsFile)] }).contextFor('snapshot', A.runner)),
  scenario('AN-A55', 'attack', '対象の記録が記号リンクのまま snapshot を取ろうとする', ['AN-NO-SYMLINK'], (dir, w) => {
    const real = `${w.files.rulings}.real`; fs.renameSync(w.files.rulings, real); fs.symlinkSync(real, w.files.rulings);
    return w.open().contextFor('snapshot', A.runner);
  }),
  scenario('AN-A56', 'attack', '対象の記録の置き場所の祖先が記号リンク', ['AN-NO-SYMLINK'], (dir, w) => {
    const link = path.join(dir, 'linked'); fs.symlinkSync(path.dirname(w.files.rulings), link);
    return w.open({ sources: [SRC('rulings', path.join(link, 'rulings.jsonl'))] }).contextFor('snapshot', A.runner);
  }),
  scenario('AN-A57', 'attack', '1 つの記録が大きさの上限を超える', ['AN-SIZE-LIMIT'], (dir, w) => w.open({ limits: { maxSourceBytes: 1000 } }).contextFor('snapshot', A.runner)),
  scenario('AN-A58', 'attack', 'dir のファイル数が上限を超える', ['AN-SIZE-LIMIT'], (dir, w) => w.open({ limits: { maxDirFiles: 3 } }).contextFor('snapshot', A.runner)),
  scenario('AN-A59', 'attack', '記録の合計が上限を超える', ['AN-SIZE-LIMIT'], (dir, w) => w.open({ limits: { maxTotalBytes: 5000 } }).contextFor('snapshot', A.runner)),
  scenario('AN-A60', 'attack', '規則の版が違う古い行（オーナーの epoch に覆われていない）がある', ['AN-RULES-VERSION'], (dir, w) => {
    const an = w.open(); an.snapshot(A.runner);
    rechainAnchors(w.anchorsFile, (rows) => { rows[0].rules = 'an.v0'; });
    return w.open().contextFor('snapshot', A.runner);
  }),
  scenario('AN-A61', 'attack', 'anchor の記録の鎖が壊れている（時刻を書き換えた）状態で snapshot を書く', ['AN-CHAIN-INTACT'], (dir, w) => {
    const an = w.open(); an.snapshot(A.runner);
    const l = fs.readFileSync(w.anchorsFile, 'utf8').split('\n'); const o = JSON.parse(l[0]); o.at = '2020-01-01T00:00:00+09:00'; l[0] = JSON.stringify(o); fs.writeFileSync(w.anchorsFile, l.join('\n'));
    return w.open().contextFor('snapshot', A.runner);
  }),
  scenario('AN-A62', 'attack', '偽の行（AI の役割が書いた anchor）が記録にある状態で snapshot を書く', ['AN-REPLAY-CLEAN'], (dir, w) => {
    const an = w.open(); an.snapshot(A.runner); an.snapshot(A.runner);
    rechainAnchors(w.anchorsFile, (rows) => { rows[0] = { ...rows[0], actor: A.worker }; });
    return w.open().contextFor('snapshot', A.runner);
  }),
  scenario('AN-A63', 'attack', '候補の anchor が manifest の指紋と違う（検査した値と記録する値の食い違い）', ['AN-MANIFEST-DIGEST'], (dir, w) => {
    const ctx = w.open().contextFor('snapshot', A.runner); ctx.candidate = { manifest: ctx.candidate.manifest, anchor: `sha256:${'0'.repeat(64)}` }; return ctx;
  }),
  scenario('AN-A64', 'attack', '候補の manifest の前の anchor への鎖が違う', ['AN-ANCHOR-LINK'], (dir, w) => {
    const an = w.open(); an.snapshot(A.runner);
    const ctx = an.contextFor('snapshot', A.runner); const m = { ...ctx.candidate.manifest, prev_manifest: `sha256:${'f'.repeat(64)}` };
    ctx.candidate = { manifest: m, anchor: anchorOf(m) }; return ctx;
  }),
  scenario('AN-A65', 'attack', '記録にない anchor に証拠を結び付ける', ['AN-RECEIPT-ANCHOR'], (dir, w) => {
    const an = w.open(); an.snapshot(A.runner);
    return an.contextFor('receipt', A.runner, { anchor: `sha256:${'9'.repeat(64)}`, method: 'git', ref: 'git:refs/tags/a1', digest: `sha256:${'c'.repeat(64)}` });
  }),
  ...[['..を含む ref', { ref: 'git:../../etc/passwd' }], ['URL の認証情報を含む ref', { ref: 'https://u:p@host/x' }], ['許可リストにない method', { method: 'carrier-pigeon' }], ['digest の形が違う', { digest: 'sha256:xyz' }], ['note に制御文字', { note: 'a\u0000b' }]]
    .map(([label, patch], k) => scenario(`AN-A${66 + k}`, 'attack', `receipt の書式：${label}`, ['AN-RECEIPT-FORMAT'], (dir, w) => {
      const an = w.open(); const s = an.snapshot(A.runner);
      return an.contextFor('receipt', A.runner, { anchor: s.anchor, method: 'git', ref: 'git:refs/tags/a1', digest: `sha256:${'c'.repeat(64)}`, ...patch });
    })),
  scenario('AN-A71', 'attack', '同じ証拠を二重に登録する（ref の大文字小文字を変えても）', ['AN-RECEIPT-DUP'], (dir, w) => {
    const an = w.open(); const s = an.snapshot(A.runner);
    an.attachReceipt(A.runner, { anchor: s.anchor, method: 'git', ref: 'git:refs/tags/a1', digest: `sha256:${'c'.repeat(64)}` });
    return an.contextFor('receipt', A.runner, { anchor: s.anchor, method: 'GIT', ref: 'GIT:refs/tags/A1', digest: `sha256:${'d'.repeat(64)}` });
  }),
  scenario('AN-A72', 'attack', '同じ digest の証拠を別の anchor に結び付ける', ['AN-RECEIPT-DUP'], (dir, w) => {
    const an = w.open(); const s1 = an.snapshot(A.runner); w.grow(1); const s2 = an.snapshot(A.runner);
    an.attachReceipt(A.runner, { anchor: s1.anchor, method: 'git', ref: 'git:refs/tags/a1', digest: `sha256:${'c'.repeat(64)}` });
    return an.contextFor('receipt', A.runner, { anchor: s2.anchor, method: 'git', ref: 'git:refs/tags/a2', digest: `sha256:${'c'.repeat(64)}` });
  }),
  scenario('AN-A73', 'attack', 'epoch の drops に、前の固定にない名前を挙げる', ['AN-DROPS-VALID'], (dir, w) => {
    const an = w.open(); an.snapshot(A.runner);
    return an.contextFor('epoch', A.owner, { reason: '外す', drops: ['nosuch'] });
  }),
  scenario('AN-A74', 'attack', 'epoch の drops に、今の設定にまだある名前を挙げる', ['AN-DROPS-VALID'], (dir, w) => {
    const an = w.open(); an.snapshot(A.runner);
    return an.contextFor('epoch', A.owner, { reason: '外す', drops: ['rulings'] });
  }),

  // ---- 良性 ----
  scenario('AN-B1', 'benign', '記録が伸びただけ：何度 snapshot しても、全部の anchor が一致する', [], detect(() => {}, { snaps: 4 })),
  scenario('AN-B2', 'benign', '判定のファイルが足されただけなら一致する（足すのは正当）', [], detect((w) => writeDir(w.files.verdicts, 3, 'n'))),
  scenario('AN-B3', 'benign', '記録が 1 つもない最初の snapshot', [], (dir, w) => w.open({ sources: [SRC('rulings', path.join(dir, 'none.jsonl')), SRC('verdicts', path.join(dir, 'nodir'), 'dir')] }).contextFor('snapshot', A.runner)),
  scenario('AN-B4', 'benign', 'receipt の結び付け（ゲートを全部通る）', [], (dir, w) => {
    const an = w.open(); const s = an.snapshot(A.runner);
    return an.contextFor('receipt', A.runner, { anchor: s.anchor, method: 'opentimestamps', ref: 'ots:anchors/a1.ots', digest: `sha256:${'c'.repeat(64)}`, note: '未完成の受領票' });
  }),
  scenario('AN-B5', 'benign', 'オーナーの規則の移行（epoch）', [], (dir, w) => { const an = w.open(); an.snapshot(A.runner); return an.contextFor('epoch', A.owner, { reason: '規則の版の移行' }); }),
  scenario('AN-B6', 'benign', 'オーナーが snapshot を書く', [], (dir, w) => w.open().contextFor('snapshot', A.owner)),
  scenario('AN-B7', 'benign', '開き直しても同じ状態が作り直せ、照合が通る', [], (dir, w) => { w.open().snapshot(A.runner); w.grow(2); w.open().snapshot(A.runner); return w.open().verifyContext(); }),
  scenario('AN-B8', 'benign', '外部が保持する anchor の値が記録にある', [], (dir, w) => {
    const an = w.open(); const s = an.snapshot(A.runner); w.grow(2); an.snapshot(A.runner); return an.verifyContext({ pinned: [s.anchor] });
  }),
  scenario('AN-B9', 'benign', 'オーナーが drops で対象から外した後の snapshot', [], (dir, w) => {
    w.open().snapshot(A.runner);
    const reduced = w.sources.filter((s) => s.name !== 'rulings');
    w.open({ sources: reduced }).epoch(A.owner, { reason: '裁定の記録は別の方式に移した', drops: ['rulings'] });
    return w.open({ sources: reduced }).contextFor('snapshot', A.runner);
  }),
  scenario('AN-B10', 'benign', '最後の行が未完成（改行なし）の記録：その行は数えず、snapshot は通る', [], (dir, w) => {
    fs.appendFileSync(w.files.rulings, '{"partial":'); return w.open().contextFor('snapshot', A.runner);
  }),
  scenario('AN-B11', 'benign', '空のファイルも固定できる', [], (dir, w) => { fs.writeFileSync(w.files.rulings, ''); const an = w.open(); an.snapshot(A.runner); return an.verifyContext(); }),
];

// ---------------------------------------------------------------------------
// 性能
// ---------------------------------------------------------------------------

/**
 * 記録の合計が mb メガバイトのときの snapshot と verify の時間。
 * 構成：tool_calls 方式の鎖つき記録 1 つ（合計の 60%）、承認・裁定の記録（20%・20%）。anchors 個の anchor のうち、最初の anchors-1 個は小さい状態で取り、
 * 最後の 1 個を全量で取る（verify の費用は「1 回の読みで全部の位置の指紋を取る」ことで anchor の数にほぼ依らない。anchor の数だけ全量を取り直すと遅すぎるため）。
 */
export function benchAnchor(mb, { anchors = 100 } = {}) {
  const dir = tmp();
  try {
    const f = (x) => path.join(dir, x);
    const files = { tool_calls: f('z3/tool_calls.jsonl'), spec_approvals: f('z3/spec_approvals.jsonl'), rulings: f('z3/rulings.jsonl') };
    fs.mkdirSync(path.dirname(files.tool_calls), { recursive: true });
    writeToolCalls(files.tool_calls, 5); writePlain(files.spec_approvals, 5); writePlain(files.rulings, 5);
    const sources = [SRC('tool_calls', files.tool_calls, 'chained', 'tool_calls'), SRC('spec_approvals', files.spec_approvals), SRC('rulings', files.rulings)];
    let tick = 0;
    const an = openAnchors(f('anchors/anchors.jsonl'), { sources, now: () => new Date(Date.UTC(2026, 10, 14, 0, 0, tick++)).toISOString(), limits: { maxSourceBytes: 2 * 1024 ** 3 } });
    for (let i = 0; i < anchors - 1; i += 1) { appendToolCalls(files.tool_calls, 2, 'g'); appendPlain(files.rulings, 2, 'g'); an.snapshot(A.runner); }
    const total = mb * 1024 * 1024;
    // 大きな記録を高速に作る（鎖は正しく連なる）
    const t0 = performance.now();
    const fill = (file, share, kind) => {
      const fd = fs.openSync(file, 'a'); let written = fs.statSync(file).size; const target = written + Math.floor(total * share);
      let prev = null;
      if (kind === 'tc') { const lines = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean); prev = `sha256:${sh(lines[lines.length - 1])}`; var seq = lines.length; } // eslint-disable-line no-var
      let buf = '';
      while (written < target) {
        let line;
        if (kind === 'tc') { seq += 1; line = JSON.stringify({ event_id: `evt-${seq}`, seq, prev_hash: prev, type: 'tool_call', operation: 'Read', note: 'z'.repeat(200) }); prev = `sha256:${sh(line)}`; } else line = JSON.stringify({ n: written, ts: AT, pad: 'q'.repeat(180) });
        buf += `${line}\n`; written += line.length + 1;
        if (buf.length > (1 << 22)) { fs.writeSync(fd, buf); buf = ''; }
      }
      if (buf) fs.writeSync(fd, buf);
      fs.closeSync(fd);
    };
    fill(files.tool_calls, 0.6, 'tc'); fill(files.spec_approvals, 0.2, 'pl'); fill(files.rulings, 0.2, 'pl');
    const fillMs = performance.now() - t0;
    const t1 = performance.now(); const snap = an.snapshot(A.runner); const snapshotMs = performance.now() - t1;
    const t2 = performance.now(); const v = an.verify(); const verifyMs = performance.now() - t2;
    return { mb, anchors, bytes: Object.values(files).reduce((a, p) => a + fs.statSync(p).size, 0), snapshot_ms: Math.round(snapshotMs), verify_ms: Math.round(verifyMs), verify_ok: v.ok, anchors_checked: v.anchors_checked, snapshot_flagged: snap.flagged, fill_ms: Math.round(fillMs), rules: RULES };
  } finally { rm(dir); }
}
