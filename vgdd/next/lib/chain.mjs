// 追記専用・ハッシュチェーンつきの記録（起草段階の試作。法律ではない）
//
// 予算の台帳（vgdd/scripts/ledger.mjs）の作りを、記録の種類に依らない部品として取り出したもの。
// 経験の記録・改善提案の記録など、新しい記録はこの部品の上に作る。
//
// 規則（ledger.mjs と同じ。SPEC §9 の台帳の規則を一般化）：
//   - 各行は { seq, at, prev, hash, ...body }。hash は hash を除く行の正規形（キーを並べ替えた JSON）の SHA-256
//   - 先頭の prev は 'genesis'。<file>.head に最後の番号とハッシュを置き、末尾の切り詰め・差し替えを検出する
//   - 追記は1つのロックの下で「復旧の判定 → 読む → 鎖と head を確かめる → 追記 → fsync → head を一時ファイルに書く → fsync → rename → 親フォルダを fsync」。
//     読み取りはロックを取らず、何も書かず、head が指す行までを確かめる
//   - 読めない・鎖が合わない・head と食い違うときは Refused('chain_broken')（fail-closed。追記もしない）
//   - 落ちた跡として説明がつく2つの形だけ、追記の時に自動で復旧する（下の「復旧」）。それ以外は止める
//   - 取り残しのロックは、持ち主が「同じホストで、もう生きていない」と確かめられたときだけ引き継ぐ（下の「ロック」）。それ以外は待って Refused('lock_busy')
//
// 復旧（追記のロックの中だけ。読み取りは復旧しない）：
//   形1（行は書けたが head が古い）：head が指す行の後ろに、改行で終わる完全な行がちょうど1つあり、鎖として正しくつながる
//        （prev が head のハッシュ、seq が head.seq+1、hash が正規形の SHA-256）。呼び出し側の recoverCheck(recordsBefore, row) が true を返したときだけ head を進める。
//        recoverCheck を渡さない記録では、鎖として正しければ進める。この場合、規則に合わない行を拒むのは各部品の再生のガード
//        （全行を規則に通している）の役目で、復旧は「行を採用する」のではなく「head を、既にある行に追いつかせる」だけである。
//        攻撃者が鎖として正しい偽の行を足した場合も、head を一緒に書き換えた場合と同じ結果で、新しい力を与えない（ファイルを書ける者は元から行を足せる）。
//   形2（行が途中まで）：末尾が改行で終わらず、最後の改行までが head と一致する。書きかけの部分は `<file>.torn-<時刻>-<連番>` に写して fsync し、
//        最後の改行の位置まで切り詰めて fsync する。書きかけの行は head に入っていないので確定していない。
//   形1と形2が同時（head が古く、完全な行の後ろに書きかけ）は復旧しない。この実装の順序（head を進めてからでないと次の行を書かない）では
//        1回の落ち方で起きない形なので、説明のつかない形として止める（厳しい側）。
//   head がない・壊れている場合に、記録から head を作り直すことは自動ではしない。head は末尾の切り詰めを見つけるためにあり、
//        作り直せると「head を消して末尾を切り詰める」攻撃が通る。そのため、最初の追記では、行より先に空の記録と head（seq 0）を置く
//        （最初の追記の途中で落ちても形1・形2として扱え、head の作り直しが要らない）。人のオーナー用の repairHead は下にある。
//   復旧はすべて `<file>.recovery.jsonl`（鎖のない追記のファイル）に残す。行為の前に残す（落ちても、記録のない復旧は起きない。再試行で重複はありうる）。
//
// ロック：mkdir で取る。ロックのフォルダの中の `owner` に { pid, host, started, token } を置く。取れないとき、持ち主が同じホストで pid が
//   ESRCH（もう存在しない）なら、古いフォルダを一意の名前へ rename して（原子的）、新しく mkdir し直す。pid が生きている（pid の再利用を含む）・
//   ホストが違う・情報が読めないときは待って lock_busy。持ち主の情報を書く前に落ちた空のロックは、作られて staleEmptyLockMs（既定 30 秒）が過ぎたら引き継ぐ。
//   解放は、owner の token が自分のものと一致するときだけ（引き継がれた後に、他人のロックを消さない）。
//   「確かめてから rename」の間に別の者が引き継ぐ窓は、i-node の照合と rename 後の再確認で狭めているが、ゼロではない（限界）。
//   この判定は現在時刻と pid の生死に依る運用上の判定で、権限の判定ではない（ガバナンスの可否には使わない）。
//
// 耐久性の順序：行を追記 → fsync →（新しく作ったなら親フォルダを fsync）→ head の一時ファイルに書く → fsync → rename → 親フォルダを fsync。
//   どの時点で落ちても head は古い値か新しい値のどちらかで、空や半端にならない。残る形は形1と形2だけ。
//
// 限界：
//   - 同じ利用者の権限で書けるので、オーナーの権限を持つ者がファイルと head を一緒に差し替えることは検出しない（SPEC §10・§12 と同じ。外部への固定は anchor.mjs）
//   - macOS では Node の fsync がディスクのキャッシュまで届く F_FULLFSYNC かどうかを選べない（標準の fs にその口がない）。電源断の耐久は、OS・ディスクの実装に依る
//   - ローカルのディスクだけが前提。NFS などのネットワークのファイルシステムでは、mkdir のロック・rename の原子性・fsync の意味が保証されないことがある。使わない
//   - 親フォルダの fsync が対応していない環境（EINVAL・EISDIR・ENOTSUP）では、その旨のエラーだけを許して続ける。それ以外のエラーは投げる。
//     rename の後の親フォルダの fsync が失敗して投げた場合、head はすでに進んでいる（行は確定している）。呼び出し側は再試行せず、read() で確かめる
//   - 復旧の記録（recovery.jsonl）・退避のファイルそのものには鎖がない。消せば復旧の跡が消える（本体の鎖と head は影響を受けない）
//   - 途中の行が壊れた記録は、この部品では直せない。オーナーが、壊れたファイルと head を別名に退避し、残せる行を確かめたうえで新しく始める
//   - repairHead は呼び出した者を確かめない。行政の AI が呼べる場所に置かない（配置の側で、人のオーナーだけが呼べる経路にする）
//   - 書く側は記号リンクをたどらない（O_NOFOLLOW と lstat・fstat の照合。審査4 C-2）。本体・head の一時ファイル・recovery.jsonl・退避のファイルが
//     記号リンク・通常のファイルでない・ハードリンク（リンクの数が 1 でない）のとき、また記録のフォルダ自身が記号リンクのときは Refused('unsafe_file')。
//     祖先のフォルダの記号リンクは見ない（macOS の /var → /private/var のように、配置で普通にある）。祖先を差し替えられる者は、記録のフォルダごと差し替えられる
//   - 行は「書いたとおりの綴り」だけを受ける（JSON.stringify(解析した値) === 行。審査4 C-6）。重複したキー・空白・エスケープの違いは chain_broken（not_canonical_line）。
//     別の言語の解析器が違う意味で読む行を、鎖として通さないため。代わりに、ほかの道具で整形し直した記録は読めない
//   - 追記の本体は、JSON として写したときに同じ値に戻るものだけ（toJSON を持つ値・疎な配列・BigInt などは not_canonical。審査4 C-1）。
//     ハッシュと書く行は同じ写しから作る
//   - ロックの i-node の照合（tryTakeover）は、i-node の番号を再利用するファイルシステム（ext4 など）ですり抜けうる（審査4 L-2）。rename の後の
//     owner の照合で気付いて戻すが、戻すまでの間に3つ目のプロセスがロックを取れる。macOS（APFS）は番号を再利用しないので、ここでは確かめていない。Linux へ移すときに確かめる

import fs from 'node:fs';
import os from 'node:os';
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

/** 記録の時刻（日本時間・ミリ秒まで。別の鎖の行と前後を比べる bridge.feedbackFromRun のために、秒より細かく残す） */
export const nowIso = () => new Date(Date.now() + 9 * 3600e3).toISOString().replace(/Z$/, '+09:00');

const RESERVED = ['seq', 'at', 'prev', 'hash'];
const STALE_EMPTY_LOCK_MS = 30000;

// ---- ファイルの耐久化 ----

const DIR_FSYNC_UNSUPPORTED = new Set(['EINVAL', 'EISDIR', 'ENOTSUP', 'EOPNOTSUPP', ...(process.platform === 'win32' ? ['EPERM', 'EACCES'] : [])]);
/** 親フォルダの fsync（新しい項目・rename を耐久化する）。対応していない旨のエラーだけ許し、それ以外は投げる */
function fsyncDir(dir) {
  let fd;
  try { fd = fs.openSync(dir, 'r'); } catch (e) { if (DIR_FSYNC_UNSUPPORTED.has(e.code)) return; throw e; }
  try { fs.fsyncSync(fd); } catch (e) { if (!DIR_FSYNC_UNSUPPORTED.has(e.code)) throw e; } finally { fs.closeSync(fd); }
}
function writeAll(fd, data) {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
  let off = 0;
  while (off < buf.length) off += fs.writeSync(fd, buf, off, buf.length - off);
}
const C = fs.constants;
const NOFOLLOW = C.O_NOFOLLOW ?? 0;
/**
 * 書くために開く（記号リンクをたどらない。審査4 C-2）。開いた後に fstat で、通常のファイルで、リンクの数が 1 で、
 * 開く前の lstat と同じもの（あれば）であることを確かめる。合わなければ閉じて Refused('unsafe_file')。
 * @param {'append'|'rw'|'create'} mode append：なければ作って末尾に追記／rw：あるものを読み書き／create：新しく作る（あれば EEXIST）
 */
function openForWrite(p, mode) {
  let pre = null;
  try { pre = fs.lstatSync(p); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  if (pre && !pre.isFile()) throw new Refused('unsafe_file', `${path.basename(p)}: not_regular`);
  const flags = mode === 'append' ? C.O_WRONLY | C.O_APPEND | C.O_CREAT | NOFOLLOW
    : mode === 'rw' ? C.O_RDWR | NOFOLLOW
      : C.O_WRONLY | C.O_CREAT | C.O_EXCL | NOFOLLOW;
  let fd;
  try { fd = fs.openSync(p, flags, 0o644); } catch (e) {
    if (e.code === 'ELOOP' || e.code === 'EMLINK') throw new Refused('unsafe_file', `${path.basename(p)}: symlink`);
    throw e;
  }
  const st = fs.fstatSync(fd);
  if (!st.isFile() || st.nlink !== 1 || (pre && (pre.ino !== st.ino || pre.dev !== st.dev))) {
    fs.closeSync(fd);
    throw new Refused('unsafe_file', `${path.basename(p)}: ${!st.isFile() ? 'not_regular' : st.nlink !== 1 ? 'hardlink' : 'changed_while_opening'}`);
  }
  return { fd, created: !pre };
}
/** 追記して fsync。ファイルを新しく作ったなら親フォルダも fsync */
function appendDurable(file, data) {
  const { fd, created } = openForWrite(file, 'append');
  try { writeAll(fd, data); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  if (created) fsyncDir(path.dirname(file));
}
/** 読むために開く前の確認：あれば通常のファイルであること（記号リンクをたどって読まない） */
function regularOrAbsent(p) {
  let st; try { st = fs.lstatSync(p); } catch (e) { if (e.code === 'ENOENT') return false; throw e; }
  if (!st.isFile()) throw new Refused('unsafe_file', `${path.basename(p)}: not_regular`);
  return true;
}

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const countNl = (buf) => { let n = 0; let i = -1; while ((i = buf.indexOf(10, i + 1)) >= 0) n += 1; return n; };

/**
 * 行の並びを鎖として確かめて、行の配列を返す（壊れていれば Refused('chain_broken')）。空の並びは鎖として正しい。
 * @param {string[]} lines 完全な行（改行を除く）
 */
function verifyLines(lines) {
  const out = []; let prev = 'genesis';
  for (const line of lines) {
    let e; try { e = JSON.parse(line); } catch { throw new Refused('chain_broken', 'json'); }
    if (!isObj(e)) throw new Refused('chain_broken', 'shape');
    if (JSON.stringify(e) !== line) throw new Refused('chain_broken', 'not_canonical_line'); // 書いたとおりの綴りだけ（審査4 C-6）
    const { hash, ...body } = e;
    let w; try { w = sha256(canonical(body)); } catch { throw new Refused('chain_broken', 'canonical'); }
    if (body.prev !== prev || body.seq !== out.length + 1 || hash !== w) throw new Refused('chain_broken', `seq ${out.length + 1}`);
    out.push(e); prev = hash;
  }
  return out;
}
const lastHashOf = (rows) => (rows.length ? rows[rows.length - 1].hash : 'genesis');

/**
 * 記録を開く。
 * @param {string} file  記録のファイル（JSONL）
 * @param {{ now?: () => string, lockWaitMs?: number, staleEmptyLockMs?: number,
 *           recoverCheck?: (recordsBefore: object[], row: object) => boolean }} [opt]
 *   now は試験用の時刻の差し替え。
 *   recoverCheck：形1の復旧で、head を進める前に呼ぶ。復旧する行を除いた今の全行と、その行を渡す。true を返したときだけ進める
 *   （false・true 以外・例外は拒否。拒否なら chain_broken の recover_rejected のまま何も書かない）。渡さなければ、鎖として正しければ進める
 */
export function openChain(file, opt = {}) {
  const now = opt.now || nowIso;
  const lockWaitMs = opt.lockWaitMs ?? 10000;
  const staleEmptyLockMs = opt.staleEmptyLockMs ?? STALE_EMPTY_LOCK_MS;
  const recoverCheck = typeof opt.recoverCheck === 'function' ? opt.recoverCheck : null;
  const head = `${file}.head`;
  const lock = `${file}.lock`;
  const recoveryFile = `${file}.recovery.jsonl`;
  const dir = path.dirname(file);
  const host = os.hostname();

  // ---- 復旧の記録（鎖なし） ----
  function logRecovery(entry) {
    const e = { at: now(), ...entry, pid: process.pid };
    appendDurable(recoveryFile, JSON.stringify(e) + '\n');
    return e;
  }
  /** 復旧の記録を読む。読めない行は { kind: 'unreadable_line' } として見せる（黙って落とさない） */
  function recoveries() {
    const out = [];
    if (!regularOrAbsent(recoveryFile)) return [];
    for (const l of fs.readFileSync(recoveryFile, 'utf8').split('\n')) {
      if (l === '') continue;
      try { const e = JSON.parse(l); out.push(isObj(e) ? e : { kind: 'unreadable_line', raw: l.slice(0, 200) }); } catch { out.push({ kind: 'unreadable_line', raw: l.slice(0, 200) }); }
    }
    return out;
  }

  // ---- ロック ----
  /** 取り残しの可能性があるロックを、確かめられたときだけ原子的に外す。外したら true */
  function tryTakeover(events) {
    let st1; try { st1 = fs.lstatSync(lock); } catch { return false; }
    if (!st1.isDirectory()) return false;
    let raw = null;
    try { raw = fs.readFileSync(path.join(lock, 'owner'), 'utf8'); } catch (e) { if (e.code !== 'ENOENT') return false; }
    let reason; let owner = null;
    if (raw === null) {
      // 持ち主の情報を書く前に落ちた空のロック：一定時間が過ぎたものだけ
      let names; try { names = fs.readdirSync(lock); } catch { return false; }
      if (names.length !== 0 || Date.now() - st1.mtimeMs < staleEmptyLockMs) return false;
      reason = 'empty_lock';
    } else {
      try { owner = JSON.parse(raw); } catch { return false; }
      if (!isObj(owner) || !Number.isSafeInteger(owner.pid) || owner.pid <= 0 || typeof owner.host !== 'string' || owner.host !== host) return false;
      try { process.kill(owner.pid, 0); return false; } catch (e) { if (e.code !== 'ESRCH') return false; } // 生きている・権限がない（EPERM）は引き継がない
      reason = 'dead_owner';
    }
    // 確かめた後に別の者が入れ替えていないか（同じフォルダか）を、rename の直前にもう一度見る
    let st2; try { st2 = fs.lstatSync(lock); } catch { return false; }
    if (st2.ino !== st1.ino || st2.dev !== st1.dev) return false;
    const stale = `${lock}.stale-${process.pid}-${crypto.randomUUID()}`;
    try { fs.renameSync(lock, stale); } catch { return false; }
    // 動かしたものが確かめたものか（違えば、生きている者のロックを動かしてしまった。戻せるなら戻す）
    let same = false;
    try {
      const st3 = fs.lstatSync(stale);
      const raw3 = (() => { try { return fs.readFileSync(path.join(stale, 'owner'), 'utf8'); } catch { return null; } })();
      same = st3.ino === st1.ino && st3.dev === st1.dev && raw3 === raw;
    } catch { same = false; }
    if (!same) { try { if (!fs.existsSync(lock)) fs.renameSync(stale, lock); } catch { /* 戻せなければそのまま */ } return false; }
    fs.rmSync(stale, { recursive: true, force: true });
    events.push(logRecovery({ kind: 'lock_takeover', reason, owner: owner ? { pid: owner.pid, host: owner.host, started: owner.started ?? null } : null }));
    return true;
  }

  function withLock(fn) {
    fs.mkdirSync(dir, { recursive: true });
    // 記録のフォルダ自身が記号リンクなら書かない（審査4 C-2。祖先は見ない：冒頭の限界）
    if (!fs.lstatSync(dir).isDirectory()) throw new Refused('unsafe_file', 'dir: not_directory');
    const events = [];
    const deadline = Date.now() + lockWaitMs;
    const token = crypto.randomUUID();
    for (;;) {
      try { fs.mkdirSync(lock); break; } catch (e) {
        if (e.code !== 'EEXIST') throw e;
        if (tryTakeover(events)) continue;
        if (Date.now() > deadline) throw new Refused('lock_busy');
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
      }
    }
    const ownerFile = path.join(lock, 'owner');
    const mine = JSON.stringify({ pid: process.pid, host, started: new Date().toISOString(), token });
    // 書けなかったときは、ロックを消さずに投げる。mkdir の後に長く止まると、空のロックとして別の者に引き継がれていることがあり、
    // 自分のものと確かめられないロックに触らない（審査4 L-1）。自分の空のロックが残った場合は、staleEmptyLockMs の後に引き継がれる
    fs.writeFileSync(ownerFile, mine, { flag: 'wx' });
    try { return fn(events); } finally {
      // 引き継がれていたら（token が違う）他人のロックを消さない
      let cur = null; try { cur = JSON.parse(fs.readFileSync(ownerFile, 'utf8')); } catch { /* 読めなければ消さない */ }
      if (cur && cur.token === token) fs.rmSync(lock, { recursive: true, force: true });
    }
  }

  // ---- 読み ----
  function readHead() {
    if (!regularOrAbsent(head)) return null;
    let h; try { h = JSON.parse(fs.readFileSync(head, 'utf8')); } catch { throw new Refused('chain_broken', 'head'); }
    if (!h || !Number.isSafeInteger(h.seq) || h.seq < 0 || typeof h.hash !== 'string') throw new Refused('chain_broken', 'head');
    return h;
  }
  /** head を先に、次に本体を読む（本体は伸びるだけなので、この順なら読み手は head 以上の本体を見る） */
  function snapshot() {
    const h = readHead();
    if (!fs.existsSync(file)) return { h, buf: null };
    if (!fs.lstatSync(file).isFile()) throw new Refused('chain_broken', 'not_file');
    return { h, buf: fs.readFileSync(file) };
  }

  // 全行を読み、鎖と head を確かめる。{ out, pending } を返す。
  // strict（追記の中。ロックを持っている）：head より後ろに行があれば鎖の破損とする（復旧できない形はここで止まる。fail-closed）。
  // strict でない（読み手。ロックを取らない・何も書かない）：先頭の head.seq 行だけを鎖として確かめる。
  //   head より後ろの1行は「書き込み中（行は書いたが head はまだ）」とみなして読まない。2行以上あれば破損とする（書き手は1つ）。
  //   pending：その1行が、完全で鎖としてつながるなら 'roll_forward'、書きかけなら 'discard_torn'、それ以外は null。
  function readRaw(strict, snap = snapshot()) {
    const { h, buf } = snap;
    if (!buf) { if (h) throw new Refused('chain_broken', 'missing'); return { out: [], pending: null }; }
    const text = buf.toString('utf8');
    let lines = text.split('\n');
    const complete = text.length === 0 || text.endsWith('\n');
    if (lines[lines.length - 1] === '') lines.pop();
    if (lines.some((l) => l === '')) throw new Refused('chain_broken', 'empty_line');
    const want = h ? h.seq : 0;
    let extra = null;
    if (strict) {
      if (!complete) throw new Refused('chain_broken', 'truncated_line');
      if (lines.length && !h) throw new Refused('chain_broken', 'head_missing');
      if (lines.length !== want) throw new Refused('chain_broken', 'head_mismatch');
    } else {
      // 読み手：head までの行がそろっていること。head より後ろは、書き込み中の1行（未完成でもよい）だけを許す。
      // head がないのに行がある記録は、書き手と同じく head_missing（最初の追記は行より先に head を置くので、正常な落ち方では起きない。審査4 C-3）
      if (lines.length && !h) throw new Refused('chain_broken', 'head_missing');
      if (lines.length < want) throw new Refused('chain_broken', 'head_mismatch');
      if (lines.length > want + 1) throw new Refused('chain_broken', 'head_mismatch');
      if (lines.length === want && !complete) throw new Refused('chain_broken', 'truncated_line');
      if (lines.length === want + 1) extra = { line: lines[want], complete };
      lines = lines.slice(0, want);
    }
    const out = verifyLines(lines);
    if (h && lastHashOf(out) !== h.hash) throw new Refused('chain_broken', 'head_mismatch');
    let pending = null;
    if (extra && h) {
      // 書き手が自動で直せる形（roll_forward・discard_torn）か、直せずに止まり続ける形（unrecoverable。審査4 C-4）か
      if (!extra.complete) pending = 'discard_torn';
      else pending = candidateOf(extra.line, out) !== null ? 'roll_forward' : 'unrecoverable';
    }
    return { out, pending };
  }

  /** head の後ろの完全な1行が、鎖として正しくつながる行なら、その行（解いた形）。そうでなければ null */
  function candidateOf(line, before) {
    let e; try { e = JSON.parse(line); } catch { return null; }
    if (!isObj(e) || JSON.stringify(e) !== line) return null;
    const { hash, ...body } = e;
    let w; try { w = sha256(canonical(body)); } catch { return null; }
    if (body.prev !== lastHashOf(before) || body.seq !== before.length + 1 || hash !== w) return null;
    return e;
  }

  // ---- head の書き込み ----
  /** head を、一時ファイルに書く → fsync → rename → 親フォルダを fsync の順で置き換える */
  function writeHead(seq, hash) {
    const tmp = `${head}.tmp`;
    // 一時ファイルは新しく作る（O_EXCL・O_NOFOLLOW）。前に落ちて残った通常のファイルだけを消してから作り直す。記号リンクなどは消さずに止める（審査4 C-2）
    if (regularOrAbsent(tmp)) fs.unlinkSync(tmp);
    const { fd } = openForWrite(tmp, 'create');
    try { writeAll(fd, JSON.stringify({ seq, hash }) + '\n'); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    fs.renameSync(tmp, head);
    fsyncDir(dir);
  }
  /** 空の記録と空の head（seq 0）を置く。最初の追記の前に行う（行より先に head がある状態にする） */
  function initEmpty(snap) {
    if (!snap.buf) { appendDurable(file, ''); }
    writeHead(0, 'genesis');
  }

  // ---- 復旧（ロックの中だけ） ----
  /** 追記の前に見る価値のある跡があるか（普通の形なら、読み直さない） */
  function abnormal({ h, buf }) {
    if (!h || !buf) return false;
    return (buf.length > 0 && buf[buf.length - 1] !== 10) || countNl(buf) !== h.seq;
  }
  /** 復旧できる2つの形なら復旧して true。それ以外は何もせず false（このあと readRaw(true) が chain_broken で止める） */
  function recover(snap, events) {
    const { h, buf } = snap;
    const tornStart = buf.lastIndexOf(10) + 1;
    const tornLen = buf.length - tornStart;
    const completeText = buf.subarray(0, tornStart).toString('utf8');
    const lines = completeText === '' ? [] : completeText.slice(0, -1).split('\n');
    if (lines.some((l) => l === '')) return false;
    const extraN = lines.length - h.seq;
    if (extraN < 0 || extraN > 1) return false;
    if (extraN === 1 && tornLen > 0) return false; // 形1と形2が同時：説明のつかない形として止める
    if (extraN === 0 && tornLen === 0) return false;
    let before;
    try { before = verifyLines(lines.slice(0, h.seq)); } catch { return false; }
    if (lastHashOf(before) !== h.hash) return false;

    if (tornLen > 0) {
      // 形2：書きかけを退避 → 切り詰め
      const torn = buf.subarray(tornStart);
      const stamp = String(now()).replace(/[^0-9]/g, '').slice(0, 20) || '0';
      let tornPath; let fd = null;
      for (let n = 1; fd === null; n += 1) {
        tornPath = `${file}.torn-${stamp}-${n}`;
        try { fd = openForWrite(tornPath, 'create').fd; } catch (e) { if (e.code !== 'EEXIST') throw e; }
      }
      try { writeAll(fd, torn); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
      fsyncDir(dir);
      events.push(logRecovery({ kind: 'discard_torn', seq: h.seq, torn_file: path.basename(tornPath), torn_bytes: torn.length, torn_sha256: sha256(torn) }));
      const wfd = openForWrite(file, 'rw').fd;
      try { fs.ftruncateSync(wfd, tornStart); fs.fsyncSync(wfd); } finally { fs.closeSync(wfd); }
      return true;
    }
    // 形1：head を進める
    const row = candidateOf(lines[h.seq], before);
    if (row === null) return false;
    if (recoverCheck) {
      let ok = false; let why = '';
      try { ok = recoverCheck(structuredClone(before), structuredClone(row)) === true; } catch (e) { why = String(e && e.message).slice(0, 100); }
      if (!ok) throw new Refused('chain_broken', why ? `recover_rejected: ${why}` : 'recover_rejected');
    }
    events.push(logRecovery({ kind: 'roll_forward', seq: row.seq, hash: row.hash }));
    writeHead(row.seq, row.hash);
    return true;
  }

  const withEvents = (rec, events) => { Object.defineProperty(rec, 'recovered', { value: events, enumerable: false }); return rec; };

  /**
   * 1行を追記する。check(records) があれば、ロックの中で今の全行を渡して確かめる（遷移の検査。投げれば追記しない）。
   * 落ちた跡（形1・形2）があれば、鎖を確かめる前に復旧する（復旧の最中の落ち方も、次の追記で同じ判定に入り直せる）。
   * @returns 追記した行。列挙されない recovered（この呼び出しで行った復旧・ロックの引き継ぎの記録の配列）を持つ
   */
  function append(body, check) {
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Refused('bad_body');
    for (const k of RESERVED) if (k in body) throw new Refused('bad_body', `reserved key ${k}`);
    return withLock((events) => {
      let snap = snapshot();
      if (abnormal(snap) && recover(snap, events)) snap = snapshot();
      const records = readRaw(true, snap).out;
      // prev と seq は check の前に決める（check が渡された配列を変えても、鎖を壊さない。審査4 C-5）
      const prev = lastHashOf(records);
      const seq = records.length + 1;
      if (check) check(records);
      // ハッシュと書く行を、JSON として写した同じ値から作る。写すと値が変わる本体（toJSON を持つ値・疎な配列など）は拒む（審査4 C-1）
      const full = { ...body, seq, at: now(), prev };
      let wire;
      try { wire = JSON.parse(JSON.stringify(full)); } catch { throw new Refused('not_canonical', 'json'); }
      if (!isObj(wire) || canonical(wire) !== canonical(full)) throw new Refused('not_canonical', 'changes_when_serialized');
      if (!snap.h) initEmpty(snap); // 空の記録の最初の追記：先に head（seq 0）を置く
      const hash = sha256(canonical(wire));
      const rec = { ...wire, hash };
      const line = JSON.stringify(rec);
      if (JSON.stringify(JSON.parse(line)) !== line) throw new Refused('not_canonical', 'spelling'); // 読み手の綴りの検査（C-6）と同じ条件
      appendDurable(file, line + '\n'); // 行を追記して fsync（新規なら親フォルダも）
      writeHead(full.seq, hash);                      // 一時ファイル → fsync → rename → 親フォルダ fsync
      return withEvents(rec, events);
    });
  }

  /**
   * 全行を読み、鎖と head を確かめる。合わなければ Refused('chain_broken')。
   * ロックを取らない（読むだけの主体に書き込みの権限を求めない。読み手が落ちてもロックを取り残さない。独立レビュー F10・N3）。何も書かない（復旧もしない）。
   * 返すのは head が指す行まで。追記の途中の行は含まない
   */
  function read() { return readRaw(false).out; }

  /** 検証だけ。投げずに結果を返す。pending：復旧待ちの跡（'roll_forward' | 'discard_torn'）か、書き手が止まり続ける跡（'unrecoverable'：head の後ろに鎖につながらない完全な1行）。なければ欄を出さない（既存の戻り値の形を変えない）。読み手は復旧しない */
  function verify() {
    try { const r = readRaw(false); return { ok: true, count: r.out.length, ...(r.pending ? { pending: r.pending } : {}) }; } catch (e) {
      if (e instanceof Refused) return { ok: false, code: e.code, detail: e.detail };
      throw e;
    }
  }

  /**
   * 【人のオーナー専用】head がない・壊れている記録の head を、期待する末尾の値が合うときだけ作り直す。
   * expect はオーナーが別の場所の控えや anchor から得た末尾の { seq, hash }。値なしでは作り直せない。
   * 記録の鎖が全部正しく、末尾が expect と一致し、書きかけの末尾がないときだけ。head が正常な記録・途中の行が壊れた記録は直さない。
   * この関数は呼び出した者を確かめない（chain.mjs は行為者を知らない）。行政の AI が呼べる場所に置かない。
   * 復旧の記録に kind: 'repair_head' と理由を残す。
   * @returns { seq, hash }
   */
  function repairHead({ reason, expect } = {}) {
    const why = typeof reason === 'string' ? reason.normalize('NFKC').trim() : '';
    if (why.length < 1 || why.length > 500) throw new Refused('bad_repair', 'reason');
    if (!isObj(expect) || !Number.isSafeInteger(expect.seq) || expect.seq < 0 || typeof expect.hash !== 'string' || expect.hash === '') throw new Refused('bad_repair', 'expect');
    return withLock((events) => {
      let state = 'absent';
      if (regularOrAbsent(head)) { try { readHead(); state = 'ok'; } catch { state = 'bad'; } }
      if (state === 'ok') throw new Refused('repair_refused', 'head_ok');
      const snap = { h: null, buf: fs.existsSync(file) ? (fs.lstatSync(file).isFile() ? fs.readFileSync(file) : (() => { throw new Refused('repair_refused', 'not_file'); })()) : null };
      if (snap.buf && snap.buf.length > 0 && snap.buf[snap.buf.length - 1] !== 10) throw new Refused('repair_refused', 'torn_tail');
      const text = snap.buf ? snap.buf.toString('utf8') : '';
      const lines = text === '' ? [] : text.slice(0, -1).split('\n');
      if (lines.some((l) => l === '')) throw new Refused('repair_refused', 'empty_line');
      let rows; try { rows = verifyLines(lines); } catch { throw new Refused('repair_refused', 'chain_broken'); }
      if (rows.length !== expect.seq || lastHashOf(rows) !== expect.hash) throw new Refused('repair_refused', 'expect_mismatch');
      events.push(logRecovery({ kind: 'repair_head', reason: why, seq: expect.seq, hash: expect.hash, head_state: state }));
      if (!snap.buf) appendDurable(file, '');
      writeHead(expect.seq, expect.hash);
      return { seq: expect.seq, hash: expect.hash };
    });
  }

  return { file, read, append, verify, recoveries, repairHead };
}
