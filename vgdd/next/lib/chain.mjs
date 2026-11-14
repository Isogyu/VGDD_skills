// 追記専用・ハッシュチェーンつきの記録（起草段階の試作。法律ではない）
//
// 予算の台帳（vgdd/scripts/ledger.mjs）の作りを、記録の種類に依らない部品として取り出したもの。
// 経験の記録・改善提案の記録など、新しい記録はこの部品の上に作る。
//
// 規則（ledger.mjs と同じ。SPEC §9 の台帳の規則を一般化）：
//   - 各行は { seq, at, prev, hash, ...body }。hash は hash を除く行の正規形（キーを並べ替えた JSON）の SHA-256
//   - 先頭の prev は 'genesis'。<file>.head に最後の番号とハッシュを置き、末尾の切り詰め・差し替えを検出する
//   - 追記は1つのロックの下で「読む → 鎖と head を確かめる → 追記 → fsync → head を更新」。読み取りはロックを取らず、head が指す行までを確かめる
//   - 読めない・鎖が合わない・head と食い違うときは Refused('chain_broken')（fail-closed。追記もしない）
//   - 取り残しのロックは自動では外さない（待っても取れなければ Refused('lock_busy')）
//
// 限界：同じ利用者の権限で書けるので、オーナーの権限を持つ者がファイルと head を一緒に差し替えることは検出しない
//       （SPEC §10・§12 と同じ。外部への固定はしていない）

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

export class Refused extends Error {
  constructor(code, detail = '') { super(detail ? `${code}: ${detail}` : code); this.code = code; this.detail = detail; }
}

export const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

/** キーを並べ替えた JSON。undefined は落とす。数は有限の数だけ（NaN・Infinity は拒む） */
export function canonical(v) {
  if (v === null || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (typeof v === 'number') { if (!Number.isFinite(v)) throw new Refused('not_canonical', 'number'); return JSON.stringify(v); }
  if (Array.isArray(v)) return `[${v.map((x) => canonical(x === undefined ? null : x)).join(',')}]`;
  if (typeof v === 'object') {
    const keys = Object.keys(v).filter((k) => v[k] !== undefined).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`;
  }
  throw new Refused('not_canonical', typeof v);
}

/** 対象の指紋（承認・評価を対象に結び付けるために使う。INV-06 と同じ考え方） */
export const digest = (v) => `sha256:${sha256(canonical(v))}`;

export const nowIso = () => new Date(Date.now() + 9 * 3600e3).toISOString().replace(/\.\d+Z$/, '+09:00');

const RESERVED = ['seq', 'at', 'prev', 'hash'];

/**
 * 記録を開く。
 * @param {string} file  記録のファイル（JSONL）
 * @param {{ now?: () => string, lockWaitMs?: number }} [opt]  now は試験用の時刻の差し替え
 */
export function openChain(file, opt = {}) {
  const now = opt.now || nowIso;
  const lockWaitMs = opt.lockWaitMs ?? 10000;
  const head = `${file}.head`;
  const lock = `${file}.lock`;

  function withLock(fn) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const deadline = Date.now() + lockWaitMs;
    for (;;) {
      try { fs.mkdirSync(lock); break; } catch (e) {
        if (e.code !== 'EEXIST') throw e;
        if (Date.now() > deadline) throw new Refused('lock_busy');
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
      }
    }
    try { return fn(); } finally { fs.rmSync(lock, { recursive: true, force: true }); }
  }

  // 全行を読み、鎖と head を確かめる。
  // strict（追記の中。ロックを持っている）：head より後ろに行があれば鎖の破損とする（前の追記が途中で落ちた跡。fail-closed）。
  // strict でない（読み手。ロックを取らない）：head を先に読み、先頭の head.seq 行だけを鎖として確かめる。
  //   head より後ろの1行は「書き込み中（行は書いたが head はまだ）」とみなして読まない。2行以上あれば破損とする（書き手は1つ）。
  function readRaw(strict) {
    let h = null;
    if (fs.existsSync(head)) {
      try { h = JSON.parse(fs.readFileSync(head, 'utf8')); } catch { throw new Refused('chain_broken', 'head'); }
      if (!h || !Number.isSafeInteger(h.seq) || h.seq < 0 || typeof h.hash !== 'string') throw new Refused('chain_broken', 'head');
    }
    if (!fs.existsSync(file)) { if (h) throw new Refused('chain_broken', 'missing'); return []; }
    if (!fs.lstatSync(file).isFile()) throw new Refused('chain_broken', 'not_file');
    const text = fs.readFileSync(file, 'utf8');
    let lines = text.split('\n');
    const complete = text.length === 0 || text.endsWith('\n');
    if (lines[lines.length - 1] === '') lines.pop();
    if (lines.some((l) => l === '')) throw new Refused('chain_broken', 'empty_line');
    const want = h ? h.seq : 0;
    if (strict) {
      if (!complete) throw new Refused('chain_broken', 'truncated_line');
      if (lines.length && !h) throw new Refused('chain_broken', 'head_missing');
      if (lines.length !== want) throw new Refused('chain_broken', 'head_mismatch');
    } else {
      // 読み手：head までの行がそろっていること。head より後ろは、書き込み中の1行（未完成でもよい）だけを許す
      if (lines.length < want) throw new Refused('chain_broken', 'head_mismatch');
      if (lines.length > want + 1) throw new Refused('chain_broken', lines.length && !h ? 'head_missing' : 'head_mismatch');
      if (lines.length === want && !complete) throw new Refused('chain_broken', 'truncated_line');
      lines = lines.slice(0, want);
    }
    const out = []; let prev = 'genesis';
    for (const line of lines) {
      let e; try { e = JSON.parse(line); } catch { throw new Refused('chain_broken', 'json'); }
      if (!e || typeof e !== 'object' || Array.isArray(e)) throw new Refused('chain_broken', 'shape');
      const { hash, ...body } = e;
      let w; try { w = sha256(canonical(body)); } catch { throw new Refused('chain_broken', 'canonical'); }
      if (body.prev !== prev || body.seq !== out.length + 1 || hash !== w) throw new Refused('chain_broken', `seq ${out.length + 1}`);
      out.push(e); prev = hash;
    }
    if (h && (out.length ? out[out.length - 1].hash : 'genesis') !== h.hash) throw new Refused('chain_broken', 'head_mismatch');
    return out;
  }

  /**
   * 1行を追記する。check(records) があれば、ロックの中で今の全行を渡して確かめる（遷移の検査。投げれば追記しない）。
   * @returns 追記した行
   */
  function append(body, check) {
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Refused('bad_body');
    for (const k of RESERVED) if (k in body) throw new Refused('bad_body', `reserved key ${k}`);
    return withLock(() => {
      const records = readRaw(true);
      if (check) check(records);
      const prev = records.length ? records[records.length - 1].hash : 'genesis';
      const full = { ...body, seq: records.length + 1, at: now(), prev };
      const hash = sha256(canonical(full));
      const rec = { ...full, hash };
      const fd = fs.openSync(file, 'a');
      try { fs.writeSync(fd, JSON.stringify(rec) + '\n'); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
      const tmp = `${head}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify({ seq: full.seq, hash }) + '\n'); fs.renameSync(tmp, head);
      return rec;
    });
  }

  /**
   * 全行を読み、鎖と head を確かめる。合わなければ Refused('chain_broken')。
   * ロックを取らない（読むだけの主体に書き込みの権限を求めない。読み手が落ちてもロックを取り残さない。独立レビュー F10・N3）。
   * 返すのは head が指す行まで。追記の途中の行は含まない
   */
  function read() { return readRaw(false); }

  /** 検証だけ。投げずに結果を返す */
  function verify() {
    try { const r = read(); return { ok: true, count: r.length }; } catch (e) {
      if (e instanceof Refused) return { ok: false, code: e.code, detail: e.detail };
      throw e;
    }
  }

  return { file, read, append, verify };
}
