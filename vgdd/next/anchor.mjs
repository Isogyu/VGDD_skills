// 外部への固定（anchor）の「外に何も送らない部分」（起草段階の試作。法律ではない）
//
// 今の記録は、同じ機械の管理者（オーナーの権限を得た者）が記録と末尾のハッシュ（head・チェックポイント）を一緒に書き換えれば検出できない
// （SPEC §10・§12）。この部品は、複数の記録の「その時点の状態」を 1 つの値（anchor。manifest の正規形の SHA-256）にまとめ、
// 後から、手元の記録が固定した時点の内容を含んでいる（書き換え・切り詰め・行の抜き取り・記録ごとの削除がない）ことを照合する。
// 外に出すのは anchor の値と記録の時刻だけ（externalView）。記録の名前・パス・件数・中身は、anchor からは分からない（nonce を含む）。
//
// 【この部品は、ネットワークに出ない】外部のコマンド（ots・openssl・git・curl）を呼ばず、外部のサービスへ何も送らない。
//   node:fs・node:path・node:crypto だけを使う。外へ送る部分（RFC 3161・OpenTimestamps・Git）は、後で別の者が作る。
//   この部品が用意する外への口は 2 つだけ：externalView（外に出してよい値）と attachReceipt（外から来た証拠を anchor に結び付けて記録する）。
//   **証拠（receipt）の中身は、この部品では検証しない**（戻り値にも receipt_verified: false と書く）。証拠の検証は外のアダプタの仕事。
//
// 記録の方式（鎖の規則は既存のものと同じ規則で、出どころの file:line を各検査の近くに書いた。既存のファイルは import しない：
//   verify-chain.mjs・ledger.mjs は import すると main の実行・プロセスの終了の副作用があるため）：
//   - tool_calls：vgdd/hooks/verify-chain.mjs（各行の prev_hash が前の行の文字列の SHA-256、seq が 1 からの連番。head はない）
//   - ledger：vgdd/scripts/ledger.mjs readLedger（hash は JSON.stringify(本体) の SHA-256、ledger.head が最後の番号とハッシュ）
//   - chain：vgdd/next/lib/chain.mjs readRaw（hash は canonical(本体) の SHA-256、<file>.head）。canonical は chain.mjs から import する
//
// 読み方の決まり：各ファイルは 1 回だけ開き（O_NOFOLLOW。lstat と fstat の ino・dev も照合）、開いた時点の大きさまでを読む。
//   読んでいる間に追記されても、開いた時点の先頭だけを数える。最後の行が改行で終わっていなければ、その未完成の行は数えない（bytes は最後の改行まで）。
//   記号リンクはたどらない。祖先のディレクトリが記号リンクのとき（realpath が違うとき）も読まない。
//
// 判断（理由）：
//   - 壊れた鎖：壊れている旨を manifest（chain.ok=false と code）に入れて固定し、戻り値の broken_chains と warnings で明確に知らせる。
//     壊れた事実も証拠になる。壊れた状態を固定することは「その状態の存在」を固定するだけで、正しさの保証ではない。
//   - 食い違い（regressions）：前の manifest と比べ、記録が伸びただけでなければ、manifest の regressions に入れて固定する（黙って上書きしない）。
//     戻り値の regressions と flagged でも知らせる。固定を拒むと、攻撃者が食い違いを作るだけで固定を止められるため。
//   - 対象を減らす：前の manifest にある記録が設定から消えたら、オーナーの epoch が drops にその名前を理由つきで挙げるまで、snapshot を拒む。
//     設定の変更自体も、行に残した設定の写し（cfg）と違えば、オーナーの epoch まで書き込みを止める。
//   - 読めない（記号リンク・通常のファイルでない・大きさの上限）：snapshot を拒む。それ以外の読み込みの失敗は、state: 'unreadable' を入れて固定する。
//   - verify は鎖を検証し直さない（先頭の bytes までの指紋が一致すれば、鎖の検証の結果も同じ）。全部の anchor の時点の指紋を 1 回の読みで計算する。
//
// 保証できないこと：
//   - **anchor の記録（<file> と <file>.head）と、対象の記録を、一緒に作り直す改ざんは、外部の証拠がなければ検出できない。**
//     これがこの部品の限界で、外への固定が要る理由。verify({ pinned }) に「外部が保持する anchor の値」を渡せば、記録にない値を検出できる
//     （pinned の出どころが本物か＝外部の証拠が本物かは、この部品では確かめない）。
//   - 固定した最新の anchor より後ろの追記・書き換え（次の固定までの窓）、固定の前の書き換え、固定を止めること、偽の記録を最初から固定すること、
//     記録されなかった操作は検出しない。固定は「その内容が存在した」ことだけを示す。
//   - 行為者が本物であること（actor は申告。lib/vocab.mjs と同じ）。この部品が確かめるのは、役割が表にあり、種類が合うことまで。
//   - tool_calls と checkpoints.jsonl の突き合わせ（verify-chain.mjs の checkpoint 照合）はしない。checkpoints.jsonl は鎖のない記録として指紋だけを固定する。
//   - ledger の head と本体の読み取りは、追記と競合しうる（head を先に読む）。2 行以上の追記が間に入ると、壊れていると誤って報告しうる（誤検出の側）。
//   - 祖先ディレクトリの記号リンクは拒む（realpath が違えば読まない）が、大文字小文字を区別しない FS の綴り違いも拒む（厳しい側）。
//   - 一時ファイルの作成・ロックは anchor の記録（chain.mjs）の仕組みのまま。取り残しのロックは自動では外さない。

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { openChain, digest, canonical, sha256, nowIso, Refused } from './lib/chain.mjs';
import { parseActor, normActor, isOwner, isDigest, isTs, asDigest, refusal } from './lib/vocab.mjs';

export const RECORD_TYPE = 'vgdd.anchor.v1';
/** 規則の版。ガードの規則を変えるたびに上げ、各行に記録する。古い版の行はオーナーの epoch に覆われるまで書き込みを止める */
export const RULES = 'an.v1';
export const MANIFEST_VERSION = 1;
export const KINDS = Object.freeze(['chained', 'plain', 'dir']);
export const SCHEMES = Object.freeze(['tool_calls', 'ledger', 'chain']);
export const RECEIPT_METHODS = Object.freeze(['rfc3161', 'opentimestamps', 'git', 'witness', 'other']);
/** anchor と receipt を書ける役割：裁判所の側のスクリプト（gate_runner）と人のオーナーだけ。AI の役割は書けない */
export const WRITER_ROLES = Object.freeze(['gate_runner', 'owner']);
const OPS = ['anchor', 'receipt', 'epoch'];

/** 大きさの上限の既定（設定の写しに残す）。開く側の引数で変えられるが、変えると写しと食い違い、オーナーの epoch まで書き込みを止める */
export const DEFAULT_LIMITS = Object.freeze({
  max_sources: 32, max_source_bytes: 1073741824, max_total_bytes: 2147483648,
  max_dir_files: 5000, max_dir_file_bytes: 16777216, max_line_bytes: 16777216,
});
const CHUNK = 4 * 1024 * 1024;
const HARD_LIMITS = Object.freeze({
  max_sources: [1, 64], max_source_bytes: [1, 4294967296], max_total_bytes: [1, 17179869184],
  max_dir_files: [1, 20000], max_dir_file_bytes: [1, 67108864], max_line_bytes: [CHUNK, 67108864],
});
const CAMEL = { maxSources: 'max_sources', maxSourceBytes: 'max_source_bytes', maxTotalBytes: 'max_total_bytes', maxDirFiles: 'max_dir_files', maxDirFileBytes: 'max_dir_file_bytes', maxLineBytes: 'max_line_bytes' };
const MAX_REGRESSIONS = 200;
const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;
const EMPTY = `sha256:${sha256('')}`;

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const canon = (v) => { try { return canonical(v); } catch { return null; } };
const nf = (x) => (typeof x === 'string' && x.length <= 400 ? x.normalize('NFKC').trim() : null);
const CTRL_RE = /[\u0000-\u001f\u007f]/;
function deepFreeze(v) { if (v && typeof v === 'object' && !Object.isFrozen(v)) { Object.freeze(v); for (const k of Object.keys(v)) deepFreeze(v[k]); } return v; }
/** 入口の写し：JSON として一度だけ写して凍結する（toJSON・getter・Proxy で検査と記録を食い違わせない）。写せなければ null */
function freezeCopy(v) { if (v === undefined) return undefined; try { const s = JSON.stringify(v); return s === undefined ? null : deepFreeze(JSON.parse(s)); } catch { return null; } }
const clone = (v) => (v === undefined ? undefined : JSON.parse(JSON.stringify(v)));
const hex64 = (s) => typeof s === 'string' && /^[0-9a-f]{64}$/.test(s);

// ---------------------------------------------------------------------------
// 設定（対象の記録の一覧と上限）
// ---------------------------------------------------------------------------

const NAME_RE = /^[a-z][a-z0-9_]{0,39}$/;
/** 記録の名前の正規化：NFKC・trim・小文字化の後 ^[a-z][a-z0-9_]{0,39}$ に合うものだけ。それ以外は null */
export function normSourceName(x) { const s = nf(x); const l = s === null ? null : s.toLowerCase(); return l !== null && NAME_RE.test(l) ? l : null; }

/** パスの構文の検査（ファイルを見ない）。読めなければ理由、正しければ null。絶対パスだけ・`..`・`.`・空の要素・制御文字・NFKC でない綴りを拒む */
export function pathProblem(p) {
  if (typeof p !== 'string' || p.length === 0 || p.length > 1024) return 'パスが文字列でない・空・長すぎる';
  if (CTRL_RE.test(p)) return 'パスに制御文字がある';
  if (!p.startsWith('/')) return '絶対パスでない';
  if (p.normalize('NFKC') !== p) return 'パスが NFKC の綴りでない';
  if (p === '/') return 'ルートは対象にできない';
  const segs = p.slice(1).split('/');
  if (segs.some((s) => s === '' || s === '.' || s === '..')) return 'パスに ..・.・空の要素（重なった /・末尾の /）がある';
  return null;
}

/**
 * 設定の検査と正規化。raw = { sources: [{ name, path, kind, scheme? }], limits?: { max_sources… } }。
 * 戻り値：{ ok, sources（名前順の正規形）, limits（全部の上限）, errors: { source: [], path: [], limit: [] } }
 */
export function normalizeConfig(raw, anchorsFile = null) {
  const errors = { source: [], path: [], limit: [] };
  const sources = [];
  const limits = { ...DEFAULT_LIMITS };
  const r = isObj(raw) ? raw : null;
  if (!r) errors.source.push('設定がオブジェクトでない');
  const lraw = r && r.limits !== undefined && r.limits !== null ? r.limits : {};
  if (!isObj(lraw)) errors.limit.push('limits がオブジェクトでない');
  else {
    for (const k of Object.keys(lraw)) {
      if (!Object.hasOwn(HARD_LIMITS, k)) { errors.limit.push(`知らない上限: ${String(k).slice(0, 40)}`); continue; }
      const v = lraw[k]; const [lo, hi] = HARD_LIMITS[k];
      if (!Number.isSafeInteger(v) || v < lo || v > hi) errors.limit.push(`${k} は ${lo}〜${hi} の整数`); else limits[k] = v;
    }
  }
  const list = r ? r.sources : null;
  if (!Array.isArray(list)) { if (r) errors.source.push('sources が配列でない'); } else if (list.length > limits.max_sources) errors.source.push(`対象の記録が多すぎる（${list.length} > ${limits.max_sources}）`);
  const names = new Set(); const paths = new Set();
  for (const s of Array.isArray(list) ? list.slice(0, 1000) : []) {
    if (!isObj(s)) { errors.source.push('記録の指定がオブジェクトでない'); continue; }
    for (const k of Object.keys(s)) if (!['name', 'path', 'kind', 'scheme'].includes(k)) errors.source.push(`記録の指定に知らない欄: ${String(k).slice(0, 40)}`);
    const name = normSourceName(s.name);
    if (!name) errors.source.push(`記録の名前が ^[a-z][a-z0-9_]{0,39}$ でない: ${String(s.name).slice(0, 40)}`);
    else if (names.has(name)) errors.source.push(`記録の名前が重複: ${name}`); else names.add(name);
    const kind = typeof s.kind === 'string' && KINDS.includes(s.kind) ? s.kind : null;
    if (!kind) errors.source.push(`kind が ${KINDS.join('・')} のどれでもない: ${String(s.kind).slice(0, 40)}`);
    let scheme = null;
    if (kind === 'chained') {
      scheme = typeof s.scheme === 'string' && SCHEMES.includes(s.scheme) ? s.scheme : null;
      if (!scheme) errors.source.push(`chained の記録には scheme（${SCHEMES.join('・')}）が要る`);
    } else if (kind && s.scheme !== undefined && s.scheme !== null) errors.source.push(`${kind} の記録に scheme は付けられない`);
    const pp = pathProblem(s.path);
    if (pp) errors.path.push(`${name || '?'}: ${pp}`);
    else {
      const key = s.path.toLowerCase();
      if (paths.has(key)) errors.path.push(`${name || '?'}: 同じパスを 2 つの名前で指定（大文字小文字を区別しない）`); else paths.add(key);
      if (anchorsFile && (s.path === anchorsFile || s.path === `${anchorsFile}.head` || s.path === `${anchorsFile}.lock`)) errors.path.push(`${name || '?'}: anchor の記録自身は対象にできない`);
    }
    if (name && kind && !pp && (kind !== 'chained' || scheme)) sources.push({ name, kind, scheme, path: s.path });
  }
  sources.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  const ok = errors.source.length + errors.path.length + errors.limit.length === 0 && r !== null;
  return { ok, sources: ok ? sources : [], limits, errors };
}
const cfgOf = (norm) => (norm.ok ? { sources: norm.sources.map((s) => ({ name: s.name, kind: s.kind, scheme: s.scheme, path: s.path })), limits: { ...norm.limits } } : null);

// ---------------------------------------------------------------------------
// 対象の記録を読む（1 回だけ開く。開いた時点の大きさまで）
// ---------------------------------------------------------------------------

/** 鎖のヘッダ（head）の読み取り。{ state: 'none' | 'bad' | 'ok', seq, hash }。出どころ：ledger.mjs:62-66、chain.mjs:75-79 */
function readHeadFile(headPath, scheme) {
  let st; try { st = fs.lstatSync(headPath); } catch (e) { return e.code === 'ENOENT' ? { state: 'none' } : { state: 'bad' }; }
  if (!st.isFile() || st.size > 4096) return { state: 'bad' };
  let h; try { h = JSON.parse(fs.readFileSync(headPath, 'utf8')); } catch { return { state: 'bad' }; }
  if (!isObj(h) || !Number.isSafeInteger(h.seq) || typeof h.hash !== 'string' || (scheme === 'chain' && h.seq < 0)) return { state: 'bad' };
  return { state: 'ok', seq: h.seq, hash: h.hash };
}
const headPathOf = (src) => (src.scheme === 'ledger' ? path.join(path.dirname(src.path), 'ledger.head') : src.scheme === 'chain' ? `${src.path}.head` : null);

/**
 * 方式ごとの鎖の検査器（流しで 1 行ずつ受ける）。line(Buffer | null) は完結した行（改行を除く）。null は長すぎて読めなかった行。
 * done({ complete, partial }) は { ok, code, lines_verified, head_seq, head_hash, last_hash } を返す。例外は投げない（壊れた、として返す）。
 */
function makeChecker(scheme, head) {
  let bad = null; let n = 0; let prev = null; let prevStr = null; let lastHash = null; let k = 0; let emptyLine = false;
  const want = scheme === 'chain' ? (head.state === 'ok' ? head.seq : 0) : 0;
  const fail = (code) => { if (!bad) bad = code; };
  function line(buf) {
    try {
      if (buf === null) { fail('line_too_long'); return; }
      if (scheme === 'tool_calls') {
        // verify-chain.mjs:104（空行は数えない）・:162-172（prev_hash は前の行の文字列の SHA-256 に 'sha256:'、最初は 'sha256:genesis'。seq は 1 からの連番）
        if (bad) return;
        const s = buf.toString('utf8'); if (s.length === 0) return;
        let rec; try { rec = JSON.parse(s); } catch { fail('json'); return; }
        if (!isObj(rec)) { fail('shape'); return; }
        const expected = prevStr === null ? 'sha256:genesis' : `sha256:${sha256(prevStr)}`;
        if (rec.prev_hash !== expected) { fail(`prev_hash 行${n + 1}`); return; }
        if (rec.seq !== n + 1) { fail(`seq 行${n + 1}`); return; }
        prevStr = s; n += 1;
      } else if (scheme === 'ledger') {
        // ledger.mjs:76-83（空行は読み飛ばす。hash は JSON.stringify(hash を除く本体) の SHA-256、prev は前の行の hash、最初は 'genesis'）
        if (bad) return;
        const s = buf.toString('utf8'); if (s.length === 0) return;
        let e; try { e = JSON.parse(s); } catch { fail('json'); return; }
        if (!isObj(e)) { fail('shape'); return; }
        const { hash, ...body } = e;
        if (body.prev !== (prev ?? 'genesis') || hash !== sha256(JSON.stringify(body))) { fail(`ledger 行${n + 1}`); return; }
        prev = hash; lastHash = hash; n += 1;
      } else {
        // chain.mjs:84-86（空行は壊れ）・:99-107（先頭の head.seq 行だけを鎖として確かめる。hash は canonical(本体) の SHA-256、seq は 1 からの連番）
        if (buf.length === 0) emptyLine = true;
        if (k < want && !bad && buf.length > 0) {
          let e; try { e = JSON.parse(buf.toString('utf8')); } catch { fail('json'); k += 1; return; }
          if (!isObj(e)) { fail('shape'); k += 1; return; }
          const { hash, ...body } = e;
          let w; try { w = sha256(canonical(body)); } catch { fail('canonical'); k += 1; return; }
          if (body.prev !== (prev ?? 'genesis') || body.seq !== k + 1 || hash !== w) { fail(`seq ${k + 1}`); k += 1; return; }
          prev = hash; lastHash = hash; n += 1;
        }
        k += 1;
      }
    } catch { fail('exception'); }
  }
  function done({ complete, partial }) {
    let code = bad;
    if (scheme === 'tool_calls') {
      // 未完成の最後の行は数えない（Kernel は数える。ここでは書き込み中の行を壊れと誤報しないために数えない）
    } else if (scheme === 'ledger') {
      // ledger.mjs:70-74・:85-88（未完成の末尾は壊れ。行があるのに head がない・head と本数・末尾のハッシュが違うのは壊れ）
      if (head.state === 'bad') code = 'head';
      else if (partial) code = code || 'partial_tail';
      else if (n > 0 && head.state === 'none') code = code || 'head_missing';
      else if (!code && head.state === 'ok' && (n !== head.seq || (lastHash ?? 'genesis') !== head.hash)) code = 'head_mismatch';
    } else {
      // chain.mjs:75-98・:108（head の後ろは書き込み中の 1 行だけ許す。構造 → 鎖 → 末尾の head の順に確かめる）
      const total = complete + (partial ? 1 : 0);
      let c = null;
      if (head.state === 'bad') c = 'head';
      else if (emptyLine) c = 'empty_line';
      else if (total < want) c = 'head_mismatch';
      else if (total > want + 1) c = total && head.state === 'none' ? 'head_missing' : 'head_mismatch';
      else if (total === want && partial) c = 'truncated_line';
      if (!c && bad) c = bad;
      if (!c && head.state === 'ok' && (lastHash ?? 'genesis') !== head.hash) c = 'head_mismatch';
      code = c;
    }
    const lastDigest = scheme === 'tool_calls' ? (prevStr === null ? null : `sha256:${sha256(prevStr)}`) : asDigest(lastHash);
    return { scheme, ok: code === null, code, lines_verified: n, head_seq: head.state === 'ok' ? head.seq : null, head_hash: head.state === 'ok' ? asDigest(head.hash) : null, last_hash: lastDigest };
  }
  return { line, done };
}

/**
 * 1 つのファイルを 1 回の読みで走査する。開いた時点の大きさ（size）までを読み、
 * 全体の指紋（最後の改行まで）・行数・指定した位置（offsets）までの指紋・末尾の行の指紋を返す。
 */
function scanFd(fd, size, offsets, checker, maxLine) {
  const h = crypto.createHash('sha256');
  const buf = Buffer.allocUnsafe(Math.max(1, Math.min(CHUNK, size)));
  const offs = [...new Set(offsets)].filter((o) => Number.isSafeInteger(o) && o > 0 && o <= size).sort((a, b) => a - b);
  const at = new Map();
  let hNl = null; let nlBytes = 0; let lines = 0; let lastNl = -1; let prevNl = -1;
  let pos = 0; let oi = 0; let carry = []; let carryLen = 0; let carryOver = false;
  while (pos < size) {
    const want = Math.min(buf.length, size - pos);
    const n = fs.readSync(fd, buf, 0, want, pos);
    if (n <= 0) throw new Error('short_read');
    const chunk = buf.subarray(0, n);
    let from = 0; let ls = 0; let lastLocal = -1;
    for (;;) {
      const i = chunk.indexOf(10, from);
      if (i < 0) break;
      lines += 1; prevNl = lastNl; lastNl = pos + i; lastLocal = i;
      if (checker) {
        if (carryOver || carryLen + (i - ls) > maxLine) { carryOver = false; carry = []; carryLen = 0; checker.line(null); } else {
          let lineBuf;
          if (carryLen === 0) lineBuf = chunk.subarray(ls, i);
          else { carry.push(Buffer.from(chunk.subarray(ls, i))); lineBuf = Buffer.concat(carry, carryLen + (i - ls)); carry = []; carryLen = 0; }
          checker.line(lineBuf);
        }
      }
      ls = i + 1; from = i + 1;
    }
    if (checker && ls < n) {
      if (carryOver || carryLen + (n - ls) > maxLine) { carryOver = true; carry = []; carryLen = 0; } else { carry.push(Buffer.from(chunk.subarray(ls, n))); carryLen += n - ls; }
    }
    const cuts = [];
    while (oi < offs.length && offs[oi] <= pos + n) { cuts.push([offs[oi] - pos, 1, offs[oi]]); oi += 1; }
    if (lastLocal >= 0) cuts.push([lastLocal + 1, 2, 0]);
    cuts.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
    let c = 0;
    for (const [cut, kind, off] of cuts) {
      if (cut > c) { h.update(chunk.subarray(c, cut)); c = cut; }
      if (kind === 1) at.set(off, `sha256:${h.copy().digest('hex')}`);
      else { hNl = h.copy(); nlBytes = pos + cut; }
    }
    if (c < n) h.update(chunk.subarray(c, n));
    pos += n;
  }
  // 末尾の行（最後の完全な行）の指紋
  let tail = null;
  if (lines > 0) {
    const th = crypto.createHash('sha256'); const start = prevNl + 1; let p = start; const tb = Buffer.allocUnsafe(1 << 20);
    while (p < lastNl) { const m = fs.readSync(fd, tb, 0, Math.min(tb.length, lastNl - p), p); if (m <= 0) throw new Error('short_read'); th.update(tb.subarray(0, m)); p += m; }
    tail = `sha256:${th.digest('hex')}`;
  }
  for (const o of offsets) if (o === 0) at.set(0, EMPTY);
  return { bytes: nlBytes, lines, prefix: hNl ? `sha256:${hNl.digest('hex')}` : EMPTY, tail, partial: size > nlBytes, complete: lines, at };
}

const unreadable = (src, reason, extra = {}) => ({ name: src.name, kind: src.kind, scheme: src.scheme ?? null, state: 'unreadable', reason, size: 0, bytes: 0, lines: 0, prefix: null, tail: null, partial_tail: false, chain: null, at: new Map(), ...extra });
const absent = (src, extra = {}) => ({ name: src.name, kind: src.kind, scheme: src.scheme ?? null, state: 'absent', reason: null, size: 0, bytes: 0, lines: 0, prefix: null, tail: null, partial_tail: false, chain: null, at: new Map(), ...extra });

/** 祖先のディレクトリが記号リンクでない（realpath が同じ）ことの確認。'ok' | 'absent' | 'bad' */
function parentCheck(p) {
  const dir = path.dirname(p);
  try { return fs.realpathSync(dir) === dir ? 'ok' : 'bad'; } catch (e) { return e.code === 'ENOENT' || e.code === 'ENOTDIR' ? 'absent' : 'bad'; }
}

/** 通常のファイルを記号リンクをたどらずに開く。{ fd, st } か { err: 理由 } か { missing: true } */
function openRegular(p, maxBytes) {
  const pc = parentCheck(p);
  if (pc === 'absent') return { missing: true };
  if (pc === 'bad') return { err: 'parent_symlink' };
  let st; try { st = fs.lstatSync(p); } catch (e) { return e.code === 'ENOENT' ? { missing: true } : { err: `io_${e.code || 'error'}` }; }
  if (st.isSymbolicLink()) return { err: 'symlink' };
  if (!st.isFile()) return { err: 'not_file' };
  if (st.size > maxBytes) return { err: 'too_large' };
  let fd;
  try { fd = fs.openSync(p, fs.constants.O_RDONLY | NOFOLLOW); } catch (e) { return { err: e.code === 'ELOOP' ? 'symlink' : `io_${e.code || 'error'}` }; }
  try {
    const f = fs.fstatSync(fd);
    if (!f.isFile() || f.ino !== st.ino || f.dev !== st.dev) { fs.closeSync(fd); return { err: 'changed_while_opening' }; }
    if (f.size > maxBytes) { fs.closeSync(fd); return { err: 'too_large' }; }
    return { fd, size: f.size };
  } catch (e) { try { fs.closeSync(fd); } catch { /* 閉じられなければそのまま */ } return { err: `io_${e.code || 'error'}` }; }
}

function readFileSource(src, limits, offsets, budget) {
  const o = openRegular(src.path, limits.max_source_bytes);
  const headP = src.kind === 'chained' ? headPathOf(src) : null;
  if (o.missing) {
    // 記録がないのに head だけがある（ledger・chain）のは壊れ（chain.mjs:80、ledger.mjs:68）
    const hd = headP ? readHeadFile(headP, src.scheme) : { state: 'none' };
    return absent(src, { chain: headP && hd.state !== 'none' ? { scheme: src.scheme, ok: false, code: 'file_missing', lines_verified: 0, head_seq: hd.state === 'ok' ? hd.seq : null, head_hash: hd.state === 'ok' ? asDigest(hd.hash) : null, last_hash: null } : null });
  }
  if (o.err) return unreadable(src, o.err);
  if (budget.used + o.size > limits.max_total_bytes) { fs.closeSync(o.fd); return unreadable(src, 'total_too_large'); }
  budget.used += o.size;
  try {
    const head = headP ? readHeadFile(headP, src.scheme) : { state: 'none' };
    const checker = src.kind === 'chained' ? makeChecker(src.scheme, head) : null;
    const r = scanFd(o.fd, o.size, offsets, checker, limits.max_line_bytes);
    const chain = checker ? checker.done({ complete: r.complete, partial: r.partial }) : null;
    return { name: src.name, kind: src.kind, scheme: src.scheme ?? null, state: 'ok', reason: null, size: o.size, bytes: r.bytes, lines: r.lines, prefix: r.prefix, tail: r.tail, partial_tail: r.partial, chain, at: r.at };
  } catch (e) { return unreadable(src, e && e.message === 'short_read' ? 'short_read' : `io_${(e && e.code) || 'error'}`); } finally { fs.closeSync(o.fd); }
}

const TYPE_OF = (st) => (st.isFile() ? 'f' : st.isSymbolicLink() ? 'l' : st.isDirectory() ? 'd' : 'o');
function readDirSource(src, limits, budget) {
  const pc = parentCheck(src.path);
  if (pc === 'absent') return absent(src, { count: 0, entries: [], entries_digest: digest([]) });
  if (pc === 'bad') return unreadable(src, 'parent_symlink', { count: 0, entries: [], entries_digest: digest([]) });
  let st; try { st = fs.lstatSync(src.path); } catch (e) { return e.code === 'ENOENT' ? absent(src, { count: 0, entries: [], entries_digest: digest([]) }) : unreadable(src, `io_${e.code || 'error'}`, { count: 0, entries: [], entries_digest: digest([]) }); }
  const bad = (r) => unreadable(src, r, { count: 0, entries: [], entries_digest: digest([]) });
  if (st.isSymbolicLink()) return bad('symlink');
  if (!st.isDirectory()) return bad('not_file');
  let names; try { names = fs.readdirSync(src.path); } catch (e) { return bad(`io_${e.code || 'error'}`); }
  if (names.length > limits.max_dir_files) return bad('too_many_files');
  names.sort();
  const entries = [];
  for (const nm of names) {
    const p = path.join(src.path, nm);
    let es; try { es = fs.lstatSync(p); } catch (e) { return bad(`io_${e.code || 'error'}`); }
    const type = TYPE_OF(es);
    if (type !== 'f') { entries.push([nm, type, null, null]); continue; }
    if (es.size > limits.max_dir_file_bytes) return bad('dir_file_too_large');
    if (budget.used + es.size > limits.max_total_bytes) return bad('total_too_large');
    budget.used += es.size;
    let fd; try { fd = fs.openSync(p, fs.constants.O_RDONLY | NOFOLLOW); } catch (e) { return bad(e.code === 'ELOOP' ? 'symlink' : `io_${e.code || 'error'}`); }
    try {
      const f = fs.fstatSync(fd);
      if (!f.isFile() || f.ino !== es.ino || f.dev !== es.dev) return bad('changed_while_opening');
      const hh = crypto.createHash('sha256'); const b = Buffer.allocUnsafe(Math.max(1, Math.min(1 << 20, f.size))); let pos = 0;
      while (pos < f.size) { const m = fs.readSync(fd, b, 0, Math.min(b.length, f.size - pos), pos); if (m <= 0) return bad('short_read'); hh.update(b.subarray(0, m)); pos += m; }
      entries.push([nm, 'f', f.size, `sha256:${hh.digest('hex')}`]);
    } catch (e) { return bad(`io_${(e && e.code) || 'error'}`); } finally { fs.closeSync(fd); }
  }
  return { name: src.name, kind: 'dir', scheme: null, state: 'ok', reason: null, size: 0, bytes: 0, lines: 0, prefix: null, tail: null, partial_tail: false, chain: null, at: new Map(), count: entries.length, entries, entries_digest: digest(entries) };
}

/**
 * 対象の記録を読む。offsets は { 名前: [位置…] }（その位置までの先頭の指紋を同じ 1 回の読みで計算する。verify が anchor の数だけ読み直さないための仕組み）。
 * ネットワークには出ない。戻り値は読み取りの結果の配列（名前順）
 */
export function readSources(sources, limits = DEFAULT_LIMITS, offsets = Object.create(null)) {
  const budget = { used: 0 };
  const out = [];
  for (const src of [...sources].sort((a, b) => (a.name < b.name ? -1 : 1))) {
    const offs = Object.hasOwn(offsets, src.name) && Array.isArray(offsets[src.name]) ? offsets[src.name] : [];
    out.push(src.kind === 'dir' ? readDirSource(src, limits, budget) : readFileSource(src, limits, offs, budget));
  }
  return out;
}

// ---------------------------------------------------------------------------
// manifest・anchor・比較（純関数）
// ---------------------------------------------------------------------------

const cap = (s, n = 200) => String(s).slice(0, n);
/** 読み取りの結果 → manifest の 1 つ分の記録 */
export function entryOfRead(r) {
  if (!isObj(r) || typeof r.name !== 'string' || !KINDS.includes(r.kind)) throw new Refused('bad_reads', '読み取りの結果の形');
  if (r.kind === 'dir') return { name: r.name, kind: 'dir', scheme: null, state: r.state, reason: r.reason ?? null, count: r.entries.length, entries_digest: r.entries_digest, entries: r.entries.map((e) => [...e]) };
  return {
    name: r.name, kind: r.kind, scheme: r.scheme ?? null, state: r.state, reason: r.reason ?? null,
    bytes: r.state === 'ok' ? r.bytes : 0, lines: r.state === 'ok' ? r.lines : 0,
    prefix_sha256: r.state === 'ok' ? r.prefix : null, tail_sha256: r.state === 'ok' ? r.tail : null, partial_tail: r.state === 'ok' ? r.partial_tail === true : false,
    chain: r.chain ? { ...r.chain } : null,
  };
}
const find = (list, name) => (Array.isArray(list) ? list.find((s) => s.name === name) : undefined);

/**
 * 前の manifest と比べて、記録が「伸びただけ」でない食い違い。[{ name, code, detail }]（名前・コード順）。
 * コード：source_gone・source_unreadable・kind_changed・truncated・lines_decreased・rewritten・unverifiable・chain_broken・entry_deleted・entry_rewritten・entry_type_changed。
 * 前にあった記録が設定から消えた場合は、ここでは扱わない（AN-SOURCE-SHRINK）。
 */
export function checkGrowth(prev, reads) {
  const out = [];
  if (!isObj(prev) || !Array.isArray(prev.sources)) return out;
  for (const p of prev.sources) {
    const r = Array.isArray(reads) ? reads.find((x) => x.name === p.name) : undefined;
    if (!r) continue;
    const add = (code, detail = '') => out.push({ name: p.name, code, detail: cap(detail) });
    if (r.kind !== p.kind) { add('kind_changed', `${p.kind} → ${r.kind}`); continue; }
    if (p.state !== 'ok') { if (r.chain && r.chain.ok === false && r.state === 'ok') add('chain_broken', r.chain.code); continue; }
    if (r.state === 'absent') { add('source_gone', '前はあった記録がない'); continue; }
    if (r.state === 'unreadable') { add('source_unreadable', r.reason); continue; }
    if (p.kind === 'dir') {
      const cur = new Map(r.entries.map((e) => [e[0], e]));
      const gone = []; const rew = []; const typ = [];
      for (const e of p.entries) {
        const c = cur.get(e[0]);
        if (!c) gone.push(e[0]); else if (c[1] !== e[1]) typ.push(e[0]); else if (e[1] === 'f' && (c[3] !== e[3] || c[2] !== e[2])) rew.push(e[0]);
      }
      if (gone.length) add('entry_deleted', `${gone.length}件: ${gone.slice(0, 3).join('、')}`);
      if (rew.length) add('entry_rewritten', `${rew.length}件: ${rew.slice(0, 3).join('、')}`);
      if (typ.length) add('entry_type_changed', `${typ.length}件: ${typ.slice(0, 3).join('、')}`);
      continue;
    }
    if (r.scheme !== (p.scheme ?? null)) { add('kind_changed', `scheme ${p.scheme} → ${r.scheme}`); continue; }
    if (r.size < p.bytes) add('truncated', `大きさ ${r.size} < 前の ${p.bytes}`);
    else if (r.bytes < p.bytes || r.lines < p.lines) add('lines_decreased', `bytes ${r.bytes}/${p.bytes}、lines ${r.lines}/${p.lines}`);
    else if (p.bytes > 0) {
      const got = r.at instanceof Map ? r.at.get(p.bytes) : undefined;
      if (got === undefined) add('unverifiable', '前の位置までの指紋が計算されていない');
      else if (got !== p.prefix_sha256) add('rewritten', `先頭 ${p.bytes} バイトの指紋が前と違う`);
    }
    if (r.chain && r.chain.ok === false && !(p.chain && p.chain.ok === false)) add('chain_broken', r.chain.code);
  }
  out.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : a.code < b.code ? -1 : a.code > b.code ? 1 : 0));
  return out;
}

/** manifest の正規形の指紋（anchor）。sha256: と 64 桁 */
export function anchorOf(manifest) { return digest(manifest); }

/**
 * manifest を作る（純関数）。prev は前の manifest か null（anchor どうしを鎖にする）。nonce は 64 桁の 16 進（推測を防ぐ乱数。固定の値として残る。判定は乱数に依らない）。
 * extra = { takenAt }。regressions は checkGrowth(prev, reads) を入れる
 */
export function buildManifest(reads, prev, nonce, rules = RULES, extra = {}) {
  if (!Array.isArray(reads)) throw new Refused('bad_reads', '配列でない');
  const sources = [...reads].sort((a, b) => (a.name < b.name ? -1 : 1)).map(entryOfRead);
  let reg = checkGrowth(prev, reads);
  if (reg.length > MAX_REGRESSIONS) reg = [...reg.slice(0, MAX_REGRESSIONS - 1), { name: '*', code: 'more', detail: `ほか ${reg.length - MAX_REGRESSIONS + 1} 件` }];
  return {
    v: MANIFEST_VERSION, rules, prev_manifest: prev ? anchorOf(prev) : null, nonce, taken_at: extra.takenAt ?? null,
    sources, regressions: reg,
  };
}

/** 今の読み取りの結果に対する、manifest の各記録の照合。status：match・rewritten・truncated・missing・unreadable・not_in_config・unverifiable・entries_deleted・entries_rewritten */
export function compare(manifest, reads) {
  const out = [];
  for (const s of manifest.sources) {
    const r = Array.isArray(reads) ? reads.find((x) => x.name === s.name) : undefined;
    const res = (status, detail = '', more = {}) => out.push({ name: s.name, kind: s.kind, status, detail, bytes: s.kind === 'dir' ? null : s.bytes, ...more });
    if (s.state === 'unreadable') { res('unverifiable', `固定の時点で読めなかった（${s.reason}）`); continue; }
    if (s.state === 'absent') { res('match', '固定の時点でなかった記録'); continue; }
    if (!r) { res('not_in_config', '設定にない記録は照合できない'); continue; }
    if (r.state === 'absent') { res('missing', '記録がない（削除）'); continue; }
    if (r.state === 'unreadable') { res('unreadable', `読めない（${r.reason}）`); continue; }
    if (r.kind !== s.kind || (s.kind === 'chained' && r.scheme !== s.scheme)) { res('rewritten', '記録の種類が違う'); continue; }
    if (s.kind === 'dir') {
      const cur = new Map(r.entries.map((e) => [e[0], e]));
      const gone = []; const rew = [];
      for (const e of s.entries) {
        const c = cur.get(e[0]);
        if (!c) gone.push(e[0]); else if (c[1] !== e[1] || (e[1] === 'f' && (c[3] !== e[3] || c[2] !== e[2]))) rew.push(e[0]);
      }
      if (gone.length) res('entries_deleted', `${gone.length}件: ${gone.slice(0, 3).join('、')}`);
      else if (rew.length) res('entries_rewritten', `${rew.length}件: ${rew.slice(0, 3).join('、')}`);
      else res('match', '');
      continue;
    }
    if (s.bytes === 0) { res('match', '固定の時点で空'); continue; }
    if (r.size < s.bytes) { res('truncated', `今の大きさ ${r.size} が固定の ${s.bytes} より小さい`); continue; }
    const got = r.at instanceof Map ? r.at.get(s.bytes) : undefined;
    if (got === undefined) res('unreadable', '照合の位置の指紋が計算されていない');
    else if (got !== s.prefix_sha256) res('rewritten', `先頭 ${s.bytes} バイトの指紋が違う`);
    else res('match', '');
  }
  return { ok: out.every((x) => x.status === 'match' || x.status === 'unverifiable'), sources: out };
}

// ---------------------------------------------------------------------------
// manifest の形の検査
// ---------------------------------------------------------------------------

const isNonNeg = (n) => Number.isSafeInteger(n) && n >= 0;
function sourceEntryProblem(s) {
  if (!isObj(s)) return '記録の項目がオブジェクトでない';
  const common = ['name', 'kind', 'scheme', 'state', 'reason'];
  const keys = new Set(s.kind === 'dir' ? [...common, 'count', 'entries_digest', 'entries'] : [...common, 'bytes', 'lines', 'prefix_sha256', 'tail_sha256', 'partial_tail', 'chain']);
  for (const k of Object.keys(s)) if (!keys.has(k)) return `知らない欄 ${cap(k, 40)}`;
  for (const k of keys) if (!Object.hasOwn(s, k)) return `欄 ${k} がない`;
  if (normSourceName(s.name) !== s.name) return '名前が正規形でない';
  if (!KINDS.includes(s.kind)) return 'kind';
  if (!['ok', 'absent', 'unreadable'].includes(s.state)) return 'state';
  if (s.reason !== null && typeof s.reason !== 'string') return 'reason';
  if (s.kind === 'dir') {
    if (s.scheme !== null || !isNonNeg(s.count) || !Array.isArray(s.entries) || s.entries.length !== s.count || !isDigest(s.entries_digest)) return 'dir の欄の形';
    let last = null;
    for (const e of s.entries) {
      if (!Array.isArray(e) || e.length !== 4 || typeof e[0] !== 'string' || e[0].length === 0 || e[0].length > 255 || !['f', 'l', 'd', 'o'].includes(e[1])) return 'dir の項目の形';
      if (e[1] === 'f' ? !(isNonNeg(e[2]) && isDigest(e[3])) : !(e[2] === null && e[3] === null)) return 'dir の項目の値';
      if (last !== null && !(last < e[0])) return 'dir の項目が名前順でない・重複';
      last = e[0];
    }
    return digest(s.entries) === s.entries_digest ? null : 'entries_digest が項目と合わない';
  }
  if (s.kind === 'chained' ? !SCHEMES.includes(s.scheme) : s.scheme !== null) return 'scheme';
  if (!isNonNeg(s.bytes) || !isNonNeg(s.lines) || typeof s.partial_tail !== 'boolean') return 'bytes・lines・partial_tail';
  if (s.state === 'ok') {
    if (!isDigest(s.prefix_sha256) || (s.lines > 0 ? !isDigest(s.tail_sha256) : s.tail_sha256 !== null)) return '指紋の形';
    if (s.bytes < s.lines) return 'bytes が lines より小さい';
  } else if (s.bytes !== 0 || s.lines !== 0 || s.prefix_sha256 !== null || s.tail_sha256 !== null) return 'ok でない記録に値がある';
  if (s.chain !== null) {
    const c = s.chain;
    if (s.kind !== 'chained' || !isObj(c) || c.scheme !== s.scheme || typeof c.ok !== 'boolean' || (c.ok ? c.code !== null : typeof c.code !== 'string') || !isNonNeg(c.lines_verified)) return 'chain の形';
    for (const k of ['head_hash', 'last_hash']) if (c[k] !== null && !isDigest(c[k])) return `chain.${k}`;
    if (c.head_seq !== null && !isNonNeg(c.head_seq)) return 'chain.head_seq';
  } else if (s.kind === 'chained' && s.state === 'ok') return 'chained の記録に chain がない';
  return null;
}
const MANIFEST_KEYS = ['v', 'rules', 'prev_manifest', 'nonce', 'taken_at', 'sources', 'regressions'];
/** manifest の形と anchor の一致の検査。違反の理由か null */
export function manifestProblem(manifest, anchor, cfgNames = null) {
  if (!isObj(manifest)) return 'manifest がオブジェクトでない';
  for (const k of Object.keys(manifest)) if (!MANIFEST_KEYS.includes(k)) return `manifest に知らない欄 ${cap(k, 40)}`;
  for (const k of MANIFEST_KEYS) if (!Object.hasOwn(manifest, k)) return `manifest に欄 ${k} がない`;
  if (manifest.v !== MANIFEST_VERSION) return 'manifest の版';
  if (typeof manifest.rules !== 'string' || manifest.rules.length > 40) return 'manifest.rules';
  if (!hex64(manifest.nonce)) return 'nonce が 64 桁の 16 進でない';
  if (!isTs(manifest.taken_at)) return 'taken_at が時刻の形でない';
  if (manifest.prev_manifest !== null && !isDigest(manifest.prev_manifest)) return 'prev_manifest の形';
  if (!Array.isArray(manifest.sources) || manifest.sources.length > 64) return 'sources';
  let last = null;
  for (const s of manifest.sources) {
    const p = sourceEntryProblem(s);
    if (p) return `${isObj(s) ? cap(s.name, 40) : '?'}: ${p}`;
    if (last !== null && !(last < s.name)) return '記録が名前順でない・重複';
    last = s.name;
  }
  if (!Array.isArray(manifest.regressions) || manifest.regressions.length > MAX_REGRESSIONS) return 'regressions';
  for (const g of manifest.regressions) if (!isObj(g) || typeof g.name !== 'string' || typeof g.code !== 'string' || typeof g.detail !== 'string' || g.name.length > 200 || g.code.length > 200 || g.detail.length > 200 || Object.keys(g).length !== 3) return 'regressions の項目';
  if (cfgNames && (cfgNames.length !== manifest.sources.length || cfgNames.some((n, i) => n !== manifest.sources[i].name))) return 'manifest の記録の一覧が設定の一覧と違う';
  const c = canon(manifest);
  if (c === null) return 'manifest を正規形にできない';
  return anchor === `sha256:${sha256(c)}` ? null : 'anchor が manifest の正規形の SHA-256 と一致しない';
}

// ---------------------------------------------------------------------------
// 証拠（receipt）の入力の正規化。中身の検証はしない
// ---------------------------------------------------------------------------

const REF_RE = /^[A-Za-z0-9][A-Za-z0-9._:/#+=~-]{0,255}$/;
/** receipt の入力の正規化。{ value: { anchor, method, ref, digest, note } | null, problems: [] }。ref は証拠の置き場所や ID（NFKC・trim。書式は許可リスト） */
export function normReceipt(input) {
  const problems = [];
  const i = isObj(input) ? input : {};
  const method = nf(i.method) === null ? null : nf(i.method).toLowerCase();
  if (!method || !RECEIPT_METHODS.includes(method)) problems.push(`method が ${RECEIPT_METHODS.join('・')} のどれでもない`);
  const ref = nf(i.ref);
  if (ref === null || !REF_RE.test(ref) || ref.includes('..') || ref.replace('://', ':').includes('//')) problems.push('ref の書式が違う（英数字と . _ : / # + = ~ - の 1〜256 文字。.. と // は不可）');
  if (!isDigest(i.digest)) problems.push('digest が sha256: と 64 桁の形でない');
  if (!isDigest(i.anchor)) problems.push('anchor が sha256: と 64 桁の形でない');
  const note = i.note === undefined || i.note === null ? '' : i.note;
  if (typeof note !== 'string' || note.length > 500 || CTRL_RE.test(note)) problems.push('note は 500 文字以内で制御文字を含まない文字列');
  if (problems.length) return { value: null, problems };
  return { value: { anchor: i.anchor, method, ref, digest: i.digest, note }, problems };
}
const receiptKey = (v) => `${v.anchor}|${v.method}|${v.ref.toLowerCase()}`;

// ---------------------------------------------------------------------------
// 再生
// ---------------------------------------------------------------------------

/** 移行の記録が覆う行の数（書かれた順に、今の版・オーナー・末尾のハッシュの一致を確かめたものだけ。improvement.mjs と同じ） */
function coveredCount(records) {
  let n = 0;
  records.forEach((r, i) => {
    if (!isObj(r) || r.op !== 'epoch' || r.rules !== RULES || !isOwner(r.actor) || !isObj(r.covers)) return;
    const c = r.covers.count;
    if (!Number.isSafeInteger(c) || c < 0 || c > i) return;
    if (r.covers.last_hash !== (c === 0 ? 'genesis' : records[c - 1].hash)) return;
    n = Math.max(n, c);
  });
  return n;
}
function inputOfRow(r) {
  if (r.op === 'anchor') return {};
  if (r.op === 'receipt') return { anchor: r.anchor, method: r.method, ref: r.ref, digest: r.digest, note: r.note };
  return { reason: r.reason, drops: r.drops };
}
const opOfRow = (op) => (op === 'anchor' ? 'snapshot' : op);
const namesOf = (m) => (isObj(m) && Array.isArray(m.sources) ? m.sources.map((s) => (isObj(s) ? s.name : null)).filter((x) => typeof x === 'string') : []);

/**
 * 記録の全行から状態を組み立てる。例外は投げず、問題を problems（{ seq, guard, reason }）に集める。
 * 今の版の行は、その時点の状態で再びガードに通す（記録に直接書かれた偽の行を採らない）。通らない行は問題として残る。
 * 問題のある anchor の行は、照合のために状態には入れるが、flagged を付ける。問題のある receipt・epoch は状態に入れない。
 * 移行の記録（epoch）に覆われる行の問題は accepted_problems に分ける（オーナーが見て受け入れたもの）。
 * @param {{ cfgCopy?: object | null, pendingEpoch?: boolean, file?: string | null }} [o]
 */
export function replay(records, o = {}) {
  const cfgNow = o.cfgCopy ?? null;
  const st = {
    rows: records.length, anchors: [], byAnchor: new Map(), receiptKeys: new Set(), receiptDigests: new Set(), epochs: [], dropAllowed: new Set(),
    problems: [], accepted_problems: [], rules_uncovered: [], cfg_mismatch: [], lastAnchor: null, lastManifest: null,
  };
  const covered = o.pendingEpoch ? records.length : coveredCount(records);
  let lastEpoch = null;
  records.forEach((r, i) => {
    const seq = isObj(r) && Number.isSafeInteger(r.seq) ? r.seq : i + 1;
    const prob = (guard, reason) => (i < covered ? st.accepted_problems : st.problems).push({ seq, guard, reason });
    if (!isObj(r) || r.type !== RECORD_TYPE || !OPS.includes(r.op)) { prob('AN-REPLAY-CLEAN', '知らない行'); return; }
    const current = r.rules === RULES;
    if (!current && i >= covered) st.rules_uncovered.push(seq);
    if (current && r.op !== 'epoch' && i >= covered && canon(r.cfg ?? null) !== canon(cfgNow)) st.cfg_mismatch.push(seq);
    // 最後の epoch が受け入れた設定も拘束する（epoch の直後に、別の設定で開いて書き込めてしまわないように）
    if (current && r.op === 'epoch') lastEpoch = { seq, cfg: r.cfg ?? null, ok: i >= covered };
    if (current && canon(r.actor ?? null) !== canon(normActor(r.actor))) prob('AN-ACTOR-SHAPE', '行為者の綴りが正規化した形と違う');
    const op = opOfRow(r.op);
    const rawCfg = isObj(r.cfg) ? r.cfg : null;
    const ctx = {
      op, actor: r.actor, input: inputOfRow(r), state: st, chain: { ok: true }, replayRow: true,
      config: { raw: rawCfg, norm: normalizeConfig(rawCfg, o.file ?? null), file: o.file ?? null },
      candidate: r.op === 'anchor' ? { manifest: r.manifest, anchor: r.anchor } : null,
      removed: r.op === 'anchor' && st.lastManifest ? namesOf(st.lastManifest).filter((n) => !namesOf(r.manifest).includes(n)) : [],
    };
    const res = check(ctx, current ? REPLAY_GUARDS : STRUCT_GUARDS);
    for (const v of res.violations) prob(v.guard, v.reason);
    if (current && rawCfg !== null && canon(rawCfg) !== canon(cfgOf(ctx.config.norm))) prob('AN-SOURCES-ALLOWLIST', 'cfg が正規形でない');
    if (r.op === 'anchor') {
      if (!isObj(r.manifest) || typeof r.anchor !== 'string') return;
      const entry = { seq, at: r.at, anchor: r.anchor, manifest: r.manifest, receipts: [], flagged: res.violations.length > 0 };
      st.anchors.push(entry); st.byAnchor.set(r.anchor, entry);
      st.lastAnchor = r.anchor; st.lastManifest = r.manifest;
      st.dropAllowed.clear(); // drops の許可は次の 1 回の固定にだけ効く（外した名前を後で足して、また外すには新しい epoch が要る）
    } else if (r.op === 'receipt') {
      if (res.violations.length) return;
      const v = normReceipt(inputOfRow(r)).value;
      if (!v) return;
      st.byAnchor.get(v.anchor).receipts.push({ seq, method: v.method, ref: v.ref, digest: v.digest, note: v.note });
      st.receiptKeys.add(receiptKey(v)); st.receiptDigests.add(v.digest);
    } else {
      const c = isObj(r.covers) ? r.covers.count : null;
      if (current && (!Number.isSafeInteger(c) || c !== i || r.covers.last_hash !== (c === 0 ? 'genesis' : records[c - 1].hash))) { prob('AN-REPLAY-CLEAN', '移行の記録の覆う範囲が、その前の行と一致しない'); return; }
      if (res.violations.length) return;
      const drops = Array.isArray(r.drops) ? r.drops.map(normSourceName).filter((x) => x !== null) : [];
      st.epochs.push({ seq, at: r.at, reason: r.reason, drops, actor: r.actor });
      for (const n of drops) st.dropAllowed.add(n);
    }
  });
  if (lastEpoch && canon(lastEpoch.cfg) !== canon(cfgNow) && !st.cfg_mismatch.includes(lastEpoch.seq)) st.cfg_mismatch.push(lastEpoch.seq);
  return st;
}

// ---------------------------------------------------------------------------
// ガード
// ---------------------------------------------------------------------------

const WRITE_OPS = ['snapshot', 'receipt', 'epoch'];
const W = (fn) => (ctx) => (ctx.op === 'verify' ? null : fn(ctx));
const fromFindings = (ctx, name) => {
  const f = (ctx.findings || []).filter((x) => x.guard === name);
  return f.length ? `${f.slice(0, 3).map((x) => x.reason).join(' / ')}${f.length > 3 ? `（ほか ${f.length - 3} 件）` : ''}` : null;
};
const V = (name, fn) => (ctx) => (ctx.op === 'verify' ? fromFindings(ctx, name) : fn ? fn(ctx) : null);
const stateOf = (ctx) => ctx.state || { problems: [], accepted_problems: [], rules_uncovered: [], cfg_mismatch: [], dropAllowed: new Set(), byAnchor: new Map(), receiptKeys: new Set(), receiptDigests: new Set(), lastAnchor: null, lastManifest: null };
const normNames = (arr) => (Array.isArray(arr) ? arr.map(normSourceName) : null);

function inputShapeProblem(ctx) {
  const i = ctx.input;
  switch (ctx.op) {
    case 'snapshot':
      if (i === undefined || (isObj(i) && Object.keys(i).length === 0)) return null;
      return 'snapshot に入力は取れない（記録の指定は開く側の設定）';
    case 'receipt': {
      if (!isObj(i)) return '入力がオブジェクトでない（JSON として写せない値を含む）';
      for (const k of Object.keys(i)) if (!['anchor', 'method', 'ref', 'digest', 'note'].includes(k)) return `知らない欄 ${cap(k, 40)}`;
      for (const k of ['anchor', 'method', 'ref', 'digest']) if (typeof i[k] !== 'string') return `${k} が文字列でない`;
      if (i.note !== undefined && typeof i.note !== 'string') return 'note が文字列でない';
      return null;
    }
    case 'epoch': {
      if (!isObj(i)) return '入力がオブジェクトでない（JSON として写せない値を含む）';
      for (const k of Object.keys(i)) if (!['reason', 'drops'].includes(k)) return `知らない欄 ${cap(k, 40)}`;
      if (typeof i.reason !== 'string' || i.reason.trim().length === 0 || i.reason.length > 2000) return 'reason（移行の理由）が要る（2000 文字以内）';
      if (i.drops !== undefined && (!Array.isArray(i.drops) || i.drops.length > 64 || i.drops.some((x) => typeof x !== 'string'))) return 'drops が文字列の配列でない';
      return null;
    }
    default: return `知らない操作 ${String(ctx.op).slice(0, 40)}`;
  }
}

/** 名前 → (ctx) => null | string（違反の理由。日本語）。W は書く操作、V は照合（verify）の発見。同じ名前が両方に効くものもある */
export const GUARDS = {
  // ---- 行為者・役割 ----
  // 行為者の形（vocab）。役割が表にない・種類が合わない・綴りが違うものは、役割のガードより前に、ここで止める
  'AN-ACTOR-SHAPE': W((ctx) => { const a = parseActor(ctx.actor); return a.ok ? null : `行為者が vocab の形でない：${a.errors[0]}`; }),
  // anchor と receipt を書けるのは、裁判所の側のスクリプト（gate_runner）と人のオーナーだけ。AI の役割（行政・司法・立法補佐）は書けない
  'AN-WRITER-ROLE': W((ctx) => {
    if (ctx.op !== 'snapshot' && ctx.op !== 'receipt') return null;
    const a = normActor(ctx.actor);
    if (!a) return null; // 形は AN-ACTOR-SHAPE
    return (a.role === 'gate_runner' && a.kind === 'script') || isOwner(a) ? null : `${ctx.op} を書けるのは gate_runner（script）か人のオーナーだけ（${a.role}・${a.kind} は書けない）`;
  }),
  // 規則の移行（epoch）と、対象を減らす許可（drops）は人のオーナーだけ
  'AN-OWNER-ONLY': W((ctx) => {
    if (ctx.op !== 'epoch') return null;
    const a = normActor(ctx.actor);
    if (!a) return null;
    return isOwner(a) ? null : `epoch は人のオーナーだけ（${a.role}・${a.kind} は書けない）`;
  }),
  // 操作ごとの入力の形（知らない欄・型・理由の欠け）
  'AN-INPUT-SHAPE': W((ctx) => inputShapeProblem(ctx)),
  // ---- 設定 ----
  // 対象の記録の名前・kind・scheme の許可リスト、重複、数、上限の値
  'AN-SOURCES-ALLOWLIST': W((ctx) => { const e = ctx.config && ctx.config.norm ? ctx.config.norm.errors : null; if (!e) return '設定を読めない'; const l = [...e.source, ...e.limit]; return l.length ? l.slice(0, 3).join(' / ') : null; }),
  // パスの検査（絶対パスだけ・.. を拒む・anchor の記録自身を対象にしない）
  'AN-PATH-SAFE': W((ctx) => { const e = ctx.config && ctx.config.norm ? ctx.config.norm.errors : null; if (!e) return null; return e.path.length ? e.path.slice(0, 3).join(' / ') : null; }),
  // 記号リンク・通常のファイルでない・祖先が記号リンクの記録は固定しない（たどらない）
  'AN-NO-SYMLINK': W((ctx) => {
    if (ctx.op !== 'snapshot' || !Array.isArray(ctx.reads)) return null;
    const bad = ctx.reads.filter((r) => r.state === 'unreadable' && ['symlink', 'not_file', 'parent_symlink', 'changed_while_opening'].includes(r.reason));
    return bad.length ? `記号リンクなど通常のファイルでない記録がある（${bad.slice(0, 3).map((r) => `${r.name}:${r.reason}`).join('、')}）` : null;
  }),
  // 大きさの上限（1 つの記録・合計・dir のファイル数と大きさ）を超えるものは固定を拒む
  'AN-SIZE-LIMIT': W((ctx) => {
    if (ctx.op !== 'snapshot' || !Array.isArray(ctx.reads)) return null;
    const bad = ctx.reads.filter((r) => r.state === 'unreadable' && ['too_large', 'too_many_files', 'total_too_large', 'dir_file_too_large'].includes(r.reason));
    return bad.length ? `大きさの上限を超えた記録がある（${bad.slice(0, 3).map((r) => `${r.name}:${r.reason}`).join('、')}）` : null;
  }),
  // 対象を減らす変更：前の manifest にあった記録が設定から消えるのは、オーナーの epoch が drops に挙げた名前だけ（裁判所のスクリプトは外せない）
  'AN-SOURCE-SHRINK': W((ctx) => {
    if (ctx.op !== 'snapshot') return null;
    const st = stateOf(ctx);
    const gone = (ctx.removed || []).filter((n) => !st.dropAllowed.has(n));
    return gone.length ? `前の固定にあった記録を対象から外せるのは、オーナーの epoch の drops だけ（${gone.slice(0, 3).join('、')}）` : null;
  }),
  // 行に残した設定の写し（cfg）と開く側の設定が違えば、オーナーの epoch まで書き込みを止める
  'AN-CFG-COPY': W((ctx) => {
    if (ctx.op !== 'snapshot' && ctx.op !== 'receipt') return null;
    if (ctx.replayRow) return null;
    const st = stateOf(ctx);
    if (ctx.cfgCopy === null || ctx.cfgCopy === undefined) return null; // 設定が読めないときは AN-SOURCES-ALLOWLIST・AN-PATH-SAFE が止める
    return st.cfg_mismatch.length ? `記録の設定の写し（cfg）が開く側の設定と違う（seq ${st.cfg_mismatch.slice(0, 5).join('・')}）。受け入れるにはオーナーの epoch が要る` : null;
  }),
  // 古い規則の版の行は、オーナーの移行の記録（epoch）に覆われるまで書き込みを止める
  'AN-RULES-VERSION': W((ctx) => {
    if (ctx.op === 'epoch' || ctx.replayRow) return null;
    const st = stateOf(ctx);
    return st.rules_uncovered.length ? `規則の版が今（${RULES}）と違う行がある（seq ${st.rules_uncovered.slice(0, 5).join('・')}）。受け入れるにはオーナーの epoch が要る` : null;
  }),
  // ---- anchor の記録そのもの ----
  // anchor の記録の鎖が無傷（chain.mjs の検証と head）。壊れていれば何も書かない。照合では「記録が書き換えられた」発見
  'AN-CHAIN-INTACT': (ctx) => {
    if (ctx.op === 'verify') return fromFindings(ctx, 'AN-CHAIN-INTACT');
    return ctx.chain && ctx.chain.ok ? null : `anchor の記録の鎖が壊れている（${ctx.chain && ctx.chain.code}）`;
  },
  // 記録の全行が今の規則どおりに再生できる（偽の行・規則に合わない行があれば書かない）。照合では、そのような行の発見
  'AN-REPLAY-CLEAN': (ctx) => {
    if (ctx.op === 'verify') return fromFindings(ctx, 'AN-REPLAY-CLEAN');
    if (ctx.replayRow) return null;
    const st = stateOf(ctx);
    return st.problems.length ? `記録に規則に合わない行がある（seq ${[...new Set(st.problems.map((p) => p.seq))].slice(0, 5).join('・')}：${st.problems[0].guard}）。受け入れるにはオーナーの epoch が要る` : null;
  },
  // anchor が manifest の正規形の SHA-256 と一致し、manifest の形が規則どおりで、記録の一覧が設定と同じ。照合では、記録の行の manifest・anchor の書き換えの発見
  'AN-MANIFEST-DIGEST': (ctx) => {
    if (ctx.op === 'verify') return fromFindings(ctx, 'AN-MANIFEST-DIGEST');
    if (ctx.op !== 'snapshot') return null;
    if (!ctx.candidate) return ctx.config && ctx.config.norm && ctx.config.norm.ok ? 'manifest を作れない（正規形にできない）' : null; // 設定が読めないときは設定のガードが止める
    const names = ctx.config && ctx.config.norm && ctx.config.norm.ok ? ctx.config.norm.sources.map((s) => s.name) : null;
    return manifestProblem(ctx.candidate.manifest, ctx.candidate.anchor, names);
  },
  // 前の anchor との鎖（prev_manifest）。照合では、途中の anchor の行を抜いた・差し替えた発見
  'AN-ANCHOR-LINK': (ctx) => {
    if (ctx.op === 'verify') return fromFindings(ctx, 'AN-ANCHOR-LINK');
    if (ctx.op !== 'snapshot') return null;
    if (!ctx.candidate || !isObj(ctx.candidate.manifest)) return null; // 形は AN-MANIFEST-DIGEST
    const want = stateOf(ctx).lastAnchor;
    return ctx.candidate.manifest.prev_manifest === want ? null : `prev_manifest が直前の anchor と違う（${want === null ? '最初のはず' : '直前は別の値'}）`;
  },
  // ---- receipt ----
  // 結び付ける anchor が記録にあること
  'AN-RECEIPT-ANCHOR': W((ctx) => {
    if (ctx.op !== 'receipt' || !isObj(ctx.input) || !isDigest(ctx.input.anchor)) return null; // 書式は AN-RECEIPT-FORMAT
    return stateOf(ctx).byAnchor.has(ctx.input.anchor) ? null : 'anchor が記録にない（知らない anchor に証拠は結び付けられない）';
  }),
  // method・ref・digest・note の書式（許可リスト）
  'AN-RECEIPT-FORMAT': W((ctx) => {
    if (ctx.op !== 'receipt' || !isObj(ctx.input) || ['anchor', 'method', 'ref', 'digest'].some((k) => typeof ctx.input[k] !== 'string')) return null; // 型は AN-INPUT-SHAPE
    const r = normReceipt(ctx.input);
    return r.problems.length ? r.problems.slice(0, 3).join(' / ') : null;
  }),
  // 同じ証拠の二重の登録を拒む（同じ anchor・method・ref、または同じ digest の証拠）
  'AN-RECEIPT-DUP': W((ctx) => {
    if (ctx.op !== 'receipt') return null;
    const r = normReceipt(ctx.input);
    if (!r.value) return null;
    const st = stateOf(ctx);
    if (st.receiptKeys.has(receiptKey(r.value))) return '同じ証拠（anchor・method・ref が同じ）がすでに結び付いている';
    return st.receiptDigests.has(r.value.digest) ? '同じ digest の証拠がすでに結び付いている（1 つの証拠は 1 つの anchor にだけ）' : null;
  }),
  // epoch の drops は、前の manifest にあって、今の設定にない名前だけ
  'AN-DROPS-VALID': W((ctx) => {
    if (ctx.op !== 'epoch' || !isObj(ctx.input) || !Array.isArray(ctx.input.drops)) return null;
    const names = normNames(ctx.input.drops);
    if (names.includes(null)) return 'drops の名前が正規形でない';
    if (new Set(names).size !== names.length) return 'drops に重複がある';
    const st = stateOf(ctx);
    const cfgNames = ctx.config && ctx.config.norm && ctx.config.norm.ok ? new Set(ctx.config.norm.sources.map((s) => s.name)) : new Set();
    const prev = new Set(namesOf(st.lastManifest));
    const bad = names.filter((n) => !prev.has(n) || cfgNames.has(n));
    return bad.length ? `drops にできるのは、前の固定にあり今の設定にない名前だけ（${bad.slice(0, 3).join('、')}）` : null;
  }),
  // ---- 照合（verify）の発見 ----
  // 固定した時点の先頭 bytes までの指紋が今も同じ（書き換え・行の入れ替え・1 バイトの変更・鎖の作り直しの検出）
  'AN-PREFIX-MATCH': V('AN-PREFIX-MATCH'),
  // 今の記録が固定した時点の大きさより小さくない（切り詰め・行の抜き取り・空にする）
  'AN-NOT-TRUNCATED': V('AN-NOT-TRUNCATED'),
  // 固定した記録が今もあり、読める（削除・読めない・記号リンクへの差し替え・設定から消えた）
  'AN-SOURCE-PRESENT': V('AN-SOURCE-PRESENT'),
  // dir のファイルが固定した時点と同じ指紋で残っている（足すのは正当。書き換えと削除は検出）
  'AN-DIR-ENTRIES': V('AN-DIR-ENTRIES'),
  // 外部が保持する anchor の値（pinned）が、記録にある（anchor の記録と head を一緒に作り直す改ざんは、外部の値がなければ検出できない）
  'AN-PINNED-PRESENT': V('AN-PINNED-PRESENT'),
};
/** 再生で確かめ直さないガード（時点に依る・環境に依るもの。ctx.replayRow で null を返すものも含む）。古い版の行は構造の検査だけ */
const REPLAY_EXCLUDE = new Set(['AN-CHAIN-INTACT', 'AN-REPLAY-CLEAN', 'AN-CFG-COPY', 'AN-RULES-VERSION', 'AN-NO-SYMLINK', 'AN-SIZE-LIMIT', 'AN-PREFIX-MATCH', 'AN-NOT-TRUNCATED', 'AN-SOURCE-PRESENT', 'AN-DIR-ENTRIES', 'AN-PINNED-PRESENT']);
const REPLAY_GUARDS = Object.keys(GUARDS).filter((g) => !REPLAY_EXCLUDE.has(g));
const STRUCT_GUARDS = ['AN-MANIFEST-DIGEST', 'AN-ANCHOR-LINK', 'AN-RECEIPT-ANCHOR', 'AN-RECEIPT-DUP'];

/** 既定は全ガード。guardNames はアブレーション実験（bench）だけが絞る。状態を書かない */
export function check(ctx, guardNames = Object.keys(GUARDS)) {
  const violations = [];
  for (const g of guardNames) {
    if (!Object.hasOwn(GUARDS, g)) { violations.push({ guard: g, reason: '知らないガード名' }); continue; }
    let r; try { r = GUARDS[g](ctx); } catch (e) { r = `検査の失敗：${e && e.message}`; }
    if (r) violations.push({ guard: g, reason: r });
  }
  return { ok: violations.length === 0, violations };
}

// ---------------------------------------------------------------------------
// 開く
// ---------------------------------------------------------------------------

const STATUS_GUARD = { rewritten: 'AN-PREFIX-MATCH', truncated: 'AN-NOT-TRUNCATED', missing: 'AN-SOURCE-PRESENT', unreadable: 'AN-SOURCE-PRESENT', not_in_config: 'AN-SOURCE-PRESENT', entries_deleted: 'AN-DIR-ENTRIES', entries_rewritten: 'AN-DIR-ENTRIES' };
const REPLAY_TO_VERIFY = { 'AN-MANIFEST-DIGEST': 'AN-MANIFEST-DIGEST', 'AN-ANCHOR-LINK': 'AN-ANCHOR-LINK' };
export const EXTERNAL_NOTE = 'receipt は外から来た記録で、この部品は中身（署名・時刻・包含の証明）を検証しない。検証は外のアダプタ（RFC 3161・OpenTimestamps・Git）の仕事';
export const LIMIT_NOTE = 'anchor の記録（<file> と <file>.head）と対象の記録を一緒に作り直す改ざんは、外部の証拠（pinned）がなければ検出できない';

/** 凍結した入口の写しを作る（actor・input）。写せなければ null */
function limitsSnake(l) { if (!isObj(l)) return l ?? {}; const o = {}; for (const [k, v] of Object.entries(l)) o[Object.hasOwn(CAMEL, k) ? CAMEL[k] : k] = v; return o; }

/**
 * anchor の記録を開く。
 * @param {string} file anchor の記録（JSONL。chain.mjs の鎖つき記録）の絶対パス
 * @param {{ sources: {name, path, kind, scheme?}[], limits?: object, now?: () => string, lockWaitMs?: number, nonce?: () => string }} opt
 *   sources：対象の記録の一覧（行に写しを残す。写しと違う設定で開くと、オーナーの epoch まで書き込みを止める）。nonce は試験用の差し替え
 */
export function openAnchors(file, opt = {}) {
  const fp = pathProblem(file);
  if (fp) throw new Refused('bad_file', fp);
  const chain = openChain(file, { now: opt.now, lockWaitMs: opt.lockWaitMs });
  const now = opt.now || nowIso;
  const newNonce = typeof opt.nonce === 'function' ? opt.nonce : () => crypto.randomBytes(32).toString('hex');
  const rawCfg = freezeCopy({ sources: opt.sources === undefined ? [] : opt.sources, limits: limitsSnake(opt.limits) });
  const norm = normalizeConfig(rawCfg, file);
  const cfgCopy = cfgOf(norm);
  const config = { raw: rawCfg, norm, file };

  /** 鎖つき記録を読む。壊れていれば chain.ok=false と、鎖を信じずに読み取れた行（照合のために使う） */
  function load() {
    try { return { records: chain.read(), chain: { ok: true } }; } catch (e) {
      if (!(e instanceof Refused)) throw e;
      return { records: readLenient(file), chain: { ok: false, code: e.code, detail: e.detail } };
    }
  }

  function offsetsOf(prevManifest) {
    const o = Object.create(null);
    if (prevManifest) for (const s of prevManifest.sources) if (s.kind !== 'dir' && s.state === 'ok' && s.bytes > 0) o[s.name] = [s.bytes];
    return o;
  }

  /** 状態を書かずに文脈を作る。snapshot は対象の記録を読んで候補の manifest を作る */
  function buildContext({ records, chain: ch, op, actor, input, pendingEpoch }) {
    const st = replay(records, { cfgCopy, pendingEpoch: pendingEpoch === true, file });
    const ctx = { op, actor: freezeCopy(actor), input: freezeCopy(input), state: st, chain: ch, config, cfgCopy };
    if (op === 'snapshot') {
      ctx.reads = norm.ok ? readSources(norm.sources, norm.limits, offsetsOf(st.lastManifest)) : [];
      ctx.removed = st.lastManifest ? namesOf(st.lastManifest).filter((n) => !norm.sources.some((s) => s.name === n)) : [];
      ctx.candidate = null;
      if (norm.ok) try {
        const manifest = buildManifest(ctx.reads, st.lastManifest, newNonce(), RULES, { takenAt: now() });
        ctx.candidate = { manifest, anchor: anchorOf(manifest) };
      } catch (e) { if (!(e instanceof Refused)) throw e; ctx.candidate = null; }
    }
    return ctx;
  }

  function guarded(op, actor, input, makeBody) {
    const body = { type: RECORD_TYPE, op: op === 'snapshot' ? 'anchor' : op };
    chain.append(body, (records) => {
      const ctx = buildContext({ records, chain: { ok: true }, op, actor, input, pendingEpoch: op === 'epoch' });
      const r = check(ctx); // 全ガード（絞らない）
      if (!r.ok) throw refusal(r.violations);
      Object.assign(body, { rules: RULES, cfg: clone(cfgCopy), actor: normActor(ctx.actor) }, makeBody(ctx, records));
    });
    return body;
  }
  const lastHash = (records) => (records.length ? records[records.length - 1].hash : 'genesis');

  function stateView() {
    const { records, chain: ch } = load();
    const st = replay(records, { cfgCopy, file });
    return deepFreeze(clone({
      rows: st.rows, chain_ok: ch.ok, chain_code: ch.ok ? null : ch.code,
      anchors: st.anchors.map((a) => ({ seq: a.seq, at: a.at, anchor: a.anchor, taken_at: a.manifest.taken_at, flagged: a.flagged, regressions: a.manifest.regressions, receipts: a.receipts, manifest: a.manifest })),
      epochs: st.epochs, drop_allowed: [...st.dropAllowed].sort(), last_anchor: st.lastAnchor,
      problems: st.problems, accepted_problems: st.accepted_problems, rules_uncovered: st.rules_uncovered, cfg_mismatch: st.cfg_mismatch,
      config_matches: st.cfg_mismatch.length === 0 && cfgCopy !== null,
    }));
  }

  /** 照合の発見を集める（読み取りは対象の記録ごとに 1 回。全部の anchor の位置の指紋を同時に計算する） */
  function analyze(o = {}) {
    const { records, chain: ch } = load();
    const st = replay(records, { cfgCopy, file });
    const findings = [];
    const notes = [EXTERNAL_NOTE, LIMIT_NOTE];
    if (!ch.ok) findings.push({ guard: 'AN-CHAIN-INTACT', reason: `anchor の記録の鎖が壊れている（${ch.code}）` });
    for (const p of st.problems) findings.push({ guard: Object.hasOwn(REPLAY_TO_VERIFY, p.guard) ? p.guard : 'AN-REPLAY-CLEAN', seq: p.seq, reason: `seq ${p.seq}（${p.guard}）：${p.reason}` });
    let sel = st.anchors;
    let unknownUpTo = false;
    if (o.upTo !== undefined) {
      const idx = st.anchors.findIndex((a) => a.anchor === o.upTo);
      if (idx < 0) { unknownUpTo = true; sel = []; } else sel = st.anchors.slice(0, idx + 1);
    }
    // 照合に要る読み取り（名前ごとの位置の一覧）
    const offs = Object.create(null); const need = new Set();
    for (const a of sel) for (const s of Array.isArray(a.manifest.sources) ? a.manifest.sources.filter((x) => isObj(x) && typeof x.name === 'string') : []) {
      need.add(s.name);
      if (s.kind !== 'dir' && s.state === 'ok' && s.bytes > 0) (offs[s.name] ||= []).push(s.bytes);
    }
    const cfgSources = norm.ok ? norm.sources.filter((s) => need.has(s.name)) : [];
    const reads = readSources(cfgSources, norm.limits, offs);
    const results = [];
    for (const a of sel) {
      let cmp;
      try { cmp = compare(a.manifest, reads); } catch { cmp = { ok: false, sources: [{ name: '*', kind: 'plain', status: 'unreadable', detail: 'manifest を照合できない', bytes: null }] }; }
      results.push({ seq: a.seq, at: a.at, anchor: a.anchor, flagged: a.flagged, receipts: a.receipts.length, sources: cmp.sources });
    }
    // 書き換えの範囲の絞り込み：同じ記録で一致した、より小さい bytes の anchor の位置まではそのまま（この区間のどこかが変わった）
    const matched = new Map();
    for (const r of results) for (const s of r.sources) if (s.status === 'match' && s.bytes !== null) (matched.get(s.name) || matched.set(s.name, []).get(s.name)).push(s.bytes);
    for (const r of results) {
      for (const s of r.sources) {
        if (s.status === 'rewritten' && s.bytes !== null) {
          const ok = (matched.get(s.name) || []).filter((b) => b < s.bytes);
          s.ok_up_to = ok.length ? Math.max(...ok) : 0;
          s.changed_between = [s.ok_up_to, s.bytes];
        }
        const g = STATUS_GUARD[s.status];
        if (g) findings.push({ guard: g, anchor: r.anchor, seq: r.seq, source: s.name, status: s.status, reason: `seq ${r.seq} の ${s.name}：${s.detail || s.status}` });
      }
    }
    // 外部が保持する値
    let pinnedChecked = 0;
    if (o.pinned !== undefined) {
      if (!Array.isArray(o.pinned) || o.pinned.length > 10000) findings.push({ guard: 'AN-PINNED-PRESENT', reason: 'pinned が配列でない・多すぎる' });
      else for (const p of o.pinned) {
        pinnedChecked += 1;
        if (!isDigest(p)) findings.push({ guard: 'AN-PINNED-PRESENT', reason: 'pinned に sha256: の形でない値がある' });
        else if (!st.byAnchor.has(p)) findings.push({ guard: 'AN-PINNED-PRESENT', reason: `外部が保持する anchor（${p.slice(0, 19)}…）が記録にない` });
      }
    }
    if (unknownUpTo) findings.push({ guard: 'AN-ANCHOR-LINK', reason: 'upTo の anchor が記録にない' });
    if (st.cfg_mismatch.length) notes.push('開く側の設定が記録の設定の写しと違う（書き込みは止まる。照合は開く側の設定の記録で行った）');
    const ctx = { op: 'verify', findings, state: st, chain: ch };
    const violations = check(ctx).violations;
    return {
      ctx,
      result: {
        ok: violations.length === 0 && findings.length === 0,
        anchors_checked: results.length, findings, violations,
        record: { chain_ok: ch.ok, chain_code: ch.ok ? null : ch.code, problems: st.problems, accepted_problems: st.accepted_problems, rules_uncovered: st.rules_uncovered, config_matches: st.cfg_mismatch.length === 0 && cfgCopy !== null },
        anchors: results,
        with_receipt: results.filter((r) => r.receipts > 0).map((r) => r.anchor),
        without_receipt: results.filter((r) => r.receipts === 0).map((r) => r.anchor),
        pinned_checked: pinnedChecked,
        receipts_verified: false,
        notes,
      },
    };
  }

  function assertSound() {
    const { records, chain: ch } = load();
    const st = replay(records, { cfgCopy, file });
    if (!ch.ok || st.problems.length) throw new Refused('record_unsound', 'anchor の記録が壊れている・規則に合わない行がある（外に出さない）');
    return st;
  }

  return {
    file,
    /** 対象の記録を読み、manifest と anchor を作って記録する。食い違い・壊れた鎖は固定した上で戻り値で知らせる */
    snapshot(actor) {
      const body = guarded('snapshot', actor, undefined, (ctx) => ({ manifest: clone(ctx.candidate.manifest), anchor: ctx.candidate.anchor }));
      const m = body.manifest;
      const broken = m.sources.filter((s) => s.chain && s.chain.ok === false).map((s) => ({ name: s.name, code: s.chain.code }));
      const unread = m.sources.filter((s) => s.state === 'unreadable').map((s) => ({ name: s.name, reason: s.reason }));
      const warnings = [];
      if (m.regressions.length) warnings.push(`前の固定から伸びただけでない食い違いが ${m.regressions.length} 件ある（regressions）`);
      if (broken.length) warnings.push(`鎖が壊れている記録がある（${broken.map((b) => b.name).join('、')}）。壊れた状態を固定した`);
      if (unread.length) warnings.push(`読めなかった記録がある（${unread.map((b) => b.name).join('、')}）`);
      return deepFreeze({ anchor: body.anchor, taken_at: m.taken_at, regressions: clone(m.regressions), broken_chains: broken, unreadable: unread, flagged: warnings.length > 0, warnings, external: { schema: 'vgdd.anchor.external.v1', anchor: body.anchor, recorded_at: m.taken_at } });
    },
    /** 外から来た証拠を anchor に結び付けて記録する。**証拠の中身は検証しない** */
    attachReceipt(actor, input) {
      const body = guarded('receipt', actor, input, (ctx) => ({ ...normReceipt(ctx.input).value }));
      return deepFreeze({ anchor: body.anchor, method: body.method, ref: body.ref, digest: body.digest, note: body.note, receipt_verified: false, verification: 'not_performed', notice: EXTERNAL_NOTE });
    },
    /** 手元の対象の記録を、記録にある全部の anchor（upTo まで）と照合する。receipt があるか・本物かは見ない */
    verify: (o = {}) => analyze(o).result,
    /** 外に出してよいものだけ：anchor の値と記録の時刻。manifest・件数・名前・パスは含めない。記録が壊れているときは出さない */
    externalView(anchor) {
      const st = assertSound();
      const a = typeof anchor === 'string' ? st.byAnchor.get(anchor) : undefined;
      if (!a) throw new Refused('unknown_anchor', '記録にない anchor');
      return deepFreeze({ schema: 'vgdd.anchor.external.v1', anchor: a.anchor, recorded_at: a.manifest.taken_at });
    },
    state: stateView,
    /** オーナーの移行の記録。今ある全行を覆い（古い版・設定の写しの食い違い・規則に合わない行を受け入れる）、drops の名前を対象から外すことを許す */
    epoch(actor, input) {
      guarded('epoch', actor, input, (ctx, records) => ({
        reason: ctx.input.reason, drops: (ctx.input.drops || []).map(normSourceName).sort(),
        covers: { count: records.length, last_hash: lastHash(records) },
      }));
      return deepFreeze({ ok: true, reason: input.reason });
    },
    /** 状態を書かずに文脈を作る（bench・事前確認用）。snapshot は対象の記録を読む */
    contextFor(op, actor, input) {
      const { records, chain: ch } = load();
      return buildContext({ records, chain: ch, op, actor, input, pendingEpoch: op === 'epoch' });
    },
    /** 照合の文脈（bench 用）。check(ctx, guardNames) に渡せる */
    verifyContext: (o = {}) => analyze(o).ctx,
  };
}

/** 鎖を信じずに、読み取れた行だけを返す（鎖が壊れた記録の照合用。大きすぎる・通常のファイルでなければ空） */
function readLenient(file) {
  try {
    const st = fs.lstatSync(file);
    if (!st.isFile() || st.size > 256 * 1024 * 1024) return [];
    const out = [];
    for (const l of fs.readFileSync(file, 'utf8').split('\n')) { if (!l) continue; try { out.push(JSON.parse(l)); } catch { /* 読めない行は飛ばす */ } }
    return out;
  } catch { return []; }
}
