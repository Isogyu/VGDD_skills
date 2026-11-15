#!/usr/bin/env node
// VGDD Phase 1 — Policy Engine（PreToolUse / PostToolUse / PostToolUseFailure / PermissionDenied フック）
// policy_version: p0.4.0（本稼働。D-45〜D-47、OBS-012・OBS-013、誤検知の修正 OBS-014、Governance Kernel の停止 ADR-027）
//
// 役割：
//   1. PreToolUse：すべてのツール呼び出しの直前に動き、保護パスへの操作を拒否し、判定を証拠ストアに1行記録する（type: tool_call）
//   2. PostToolUse / PostToolUseFailure / PermissionDenied：実行の結果（成功／失敗／auto モードの拒否）を同じ証拠ストアに記録する
//      （type: outcome。tool_use_id で tool_call と結ぶ）。権限ルールの deny とこのフックの拒否には後続イベントがないため、
//      「allow なのに outcome がない」行は verify-chain.mjs で数える（記録と実際のずれの可視化）
//
// 置き場所：原本はリポジトリの vgdd/hooks/policy.mjs（審査員向けの参照用。vgdd/ は保護パス）。
//   実際に動かすのは ~/tsubuyaki-z3/hooks/policy.mjs（オーナーがコピー）。開発エージェントは z3 を読めない・書けない。
//
// settings.json の登録（4イベントとも同じスクリプト。onFailure: block、timeout 10）：
//   "hooks": { "PreToolUse": [{ "matcher": "*", "hooks": [{ "type": "command", "command": "node ~/tsubuyaki-z3/hooks/policy.mjs", "timeout": 10, "onFailure": "block" }] }],
//              "PostToolUse": [...同じ...], "PostToolUseFailure": [...同じ...], "PermissionDenied": [...同じ...] }
//
// p0.2.0 の変更点（p0.1.2 から）：
//   - 保護パスの判定を「どのリポジトリ（main でも worktree でも）でも、そのルートからの相対パス」で行う。
//     .claude/ はすべて保護。ただし .claude/worktrees/ だけ例外（Claude Code が worker の worktree を作る場所）。
//     例外の中（各 worktree）の .claude/ のコピー・CLAUDE.md・.github/・vgdd/・docs/tasks/_board.json はまた保護
//   - vgdd/**、docs/tasks/_board.json、merge-requests/done/** を保護パスに追加。merge-requests/*.json は行政の長（agent_type なし）だけが書ける
//   - main への統合の拒否：git merge、main 上での rebase/reset/cherry-pick、main の参照の書き換え（branch -f/-D main、update-ref）
//   - git commit の -m / -F の本文（ヒアドキュメントを含む）を照合の対象から外す（誤検知の対策）
//   - .claude/worktrees/<name>/ の下の通常パスは Bash の照合でも保護パスと見なさない
//   - 記録に hook_event・agent_id・agent_type・cwd を追加。git_branch・git_head は入力の cwd から .git を探して読む（worktree なら worktree のブランチ）
//   - OBS-013①：対象パスはシンボリックリンクを実体に解決（fs.realpathSync。ファイルがまだなければ存在する親を解決）してから判定。
//     Bash の ln は保護語の有無にかかわらず拒否
//   - OBS-013②：作業員の閉じ込め。agent_type が worker・tester、または cwd が .claude/worktrees/ の下にあるときは、
//     書き込みの対象（Edit・Write・Bash のリダイレクトや cp・mv の先、cd の先）が自分の worktree の中だけのときに許可する
//
// p0.2.1 の変更点（p0.2.0 から。OBS-014：S3 の初日に行政の長のセッションで実際に起きた誤検知4件。すべて「止まる側」の誤りで、記録は残っていた）：
//   ① 保護語の照合を「語の終わり」まで見る：vgdd・.github・preparation・event_records・merge-requests/done は、
//      直後が「/」か語の区切り（空白・引用符・; | & )・行末）のときだけ一致する。`docs/vgdd-status.md` の中の vgdd は一致しない
//   ② セグメントの分割（; && || |）を引用符の中では行わない。`grep -E 'a|b' file` は1つのセグメント
//   ③ リダイレクトの書き込み判定から `2>&1`・`>&2`・`>/dev/null`・`>/dev/stdout`・`>/dev/stderr` を除く（書き込み先ではない）。
//      作業員の閉じ込めでも /dev/ への出力を「外への書き込み」と見なさない
//   ④ `git merge` の拒否は `merge` の語が終わるところまで見る。`git merge-base` は読み取りとして扱う（READ_ONLY_HEAD にも追加）
//   ⑤ OBS-015①（立法補佐の点検）：空白なしのリダイレクト `echo x>.claude/s`・`cat a>>vgdd/x`・`printf x 1>CLAUDE.md` が通っていた
//      （保護語の直前の区切りに > が含まれず、閉じ込めのパス抽出も > の直後を拾わなかった）。
//      対策2つ：(a) リダイレクトの先（`>`・`>>`・`N>`・`&>` の直後の語）を取り出し、Edit/Write と同じ judgeWritePath（保護パス・閉じ込め）を直接かける
//      (b) 保護語の直前の区切りと、閉じ込め・リンク判定のパス抽出に > < | & ; ( を加える
//   変更しないもの：引用符の中の `>` は引き続き書き込みの気配と見なす（`sh -c "… > CLAUDE.md"` を止めるため）
//
// p0.4.0 の変更点（Governance Kernel。ADR-027・ADR-010、成立条件④）：
//   - 行政の長が main に直接コミットしてよいのは docs/ の下だけ（judgeHeadMainCommit。ステージと同じコマンドの git add を見る）
//   - Z3 に STOP があれば（オーナーが kernel-stop.sh で置く）、読み取りのツール（Read・Glob・Grep）以外のすべての操作を拒否する（Bash はすべて拒否）。
//     読み取りも通常の判定（Z3 の読み取り禁止など）を通す。再開は kernel-resume.sh（チェーン・git の設定・main を確かめてから）
//
// p0.4.15 の変更点（移植。別の名前の Z3・別の場所のリポジトリでも同じ強制を働かせる）：
//   - Bash の照合の Z3 の名前とグロブの疑いを、実際の Z3 の場所（VGDD_Z3_DIR）から作る（z3Tokens）。既定の配置では今までと同じ照合
//   - Z3 の名前が短すぎる・ありふれている、Z3 とリポジトリが入れ子、VGDD_Z3_DIR が相対パスなら、すべての操作を拒否する（fail-closed）
//   - リポジトリの外の読み取り専用（準備資料・作業記録）を Z3 の kernel.config.json から読む。なければ今までの2つ。読めない・形が違えば、すべて拒否
//   - 既定と違う場所の Z3 では、フックの登録で VGDD_Z3_DIR を渡す（vgdd-setup.mjs render-settings が書く）
//
// p0.4.16 の変更点（入れ子の起動。2026-11-14 に Claude Code の公式の文書で確かめた弱点。実機では確かめていない）：
//   - Bash のコマンドの中の claude・codex の CLI の起動を、どの役割からも拒む（judgeAgentCli。p0.4.10 の --agent worker|tester の拒否を広げた）。
//     入れ子の claude（--bare・--settings '{"disableAllHooks":true}'・-p）は外側の sandbox の中で動くが、このフックと予算の台帳を通らないため。
//     ほかの規則が通したコマンドにだけかける（既定の配置で、判定は止める側にだけ変わる）
//   - ユーザーの ~/.claude/CLAUDE.md（すべてのセッションに読まれる指示）への書き込みも、ユーザー設定として拒む
//
// 保証できないこと（README に明記する）：
//   - Bash の判定は文字列照合。パスの分割・変数展開・別名による回避は完全には防げない。書き込みは sandbox の denyWrite で補う
//   - 人が承認画面で「許可」を押した操作は止められない（記録は残る）
//   - このスクリプト自体を人が書き換えれば統制は外れる（z3 はオーナーだけが書ける）
//   - 権限ルールの deny で止まった呼び出しには後続イベントがなく、outcome の行が残らない

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';

const POLICY_VERSION = 'p0.4.16'; // OBS-013（リンクの実体で判定、作業員の閉じ込め）、OBS-014（誤検知4件の修正）、Kernel の停止（ADR-027）、移植（p0.4.15）、入れ子の起動の拒否（p0.4.16）を含む
const HOME = os.homedir();
const DEFAULT_Z3_NAME = 'tsubuyaki-z3';
const Z3 = process.env.VGDD_Z3_DIR || path.join(HOME, DEFAULT_Z3_NAME);
const EVIDENCE = process.env.VGDD_EVIDENCE_PATH || path.join(Z3, 'evidence', 'tool_calls.jsonl');
const GENESIS = 'sha256:genesis';
// p0.4.15：既定のリポジトリの場所（スクリプトの既定と同じ）。グロブの疑いの照合で、正当な兄弟のパスとして除く
const DEFAULT_REPO = path.join(HOME, 'tsubuyaki-worklog', 'app');

// ---- 移植（p0.4.15）：Z3 の名前と配置の検査、Kernel の設定（Z3 の kernel.config.json） ------------------------
// Z3 の名前は Bash の照合（名前と、先頭の4字によるグロブの疑い）に使う。短すぎる・ありふれた名前では照合が広すぎるか狭すぎるので、
//   フックは起動の時点ですべての操作を拒否する（fail-closed）。導入の道具（vgdd-setup.mjs の install・doctor）も同じ規則で拒む（同じ規則を写して持つ）
const Z3_NAME_MIN = 4;   // グロブの疑いに使う先頭の字数と同じ
const Z3_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const Z3_COMMON_NAMES = new Set(['z3', 'tmp', 'temp', 'home', 'data', 'var', 'etc', 'opt', 'usr', 'bin', 'lib', 'src', 'app', 'apps', 'test', 'tests', 'doc', 'docs',
  'work', 'root', 'users', 'library', 'desktop', 'documents', 'downloads', 'applications', 'private', 'volumes', 'system', 'public', 'evidence', 'hooks', 'kernel',
  'vgdd', 'backup', 'config', 'node_modules']);
function z3NameProblem(name) {
  if (typeof name !== 'string' || !Z3_NAME_RE.test(name)) return 'Z3 の名前に使えない文字がある（英数字と . _ - だけ。先頭は英数字）';
  if (name.length < Z3_NAME_MIN) return `Z3 の名前が短すぎる（${Z3_NAME_MIN} 文字以上）`;
  if (Z3_COMMON_NAMES.has(name.toLowerCase())) return 'Z3 の名前がありふれている（照合が広すぎるか狭すぎる）';
  return null;
}
// Z3 の場所（p0.4.15、審査 M2・m3）：ホームの下で、深さ 2 段まで（~/<名前> か ~/<段>/<名前>）。ホームからの相対の各段は
//   英数字と . _ - だけ（先頭は英数字。. と .. は不可）。深い場所では途中の段のグロブ（~/a/*/kern*）を照合しきれず、
//   使えない文字はシェルの注入やパスの解釈の違いの元になるため。設定の場所（VGDD_Z3_DIR のとおり）で見る（実体がリンクの先でも、その名前は別に確かめる）
const Z3_MAX_DEPTH = 2;
const PATH_SEG_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
/** ホームからの Z3 の相対パスの段の配列。ホームの外なら null */
function z3HomeSegs() {
  const z = path.resolve(Z3);
  for (const h of [...new Set([path.resolve(HOME), realish(HOME)])]) {
    const rel = path.relative(h, z);
    if (rel && !rel.startsWith('..') && !path.isAbsolute(rel)) return rel.split(path.sep);
  }
  return null;
}
/** Z3 の名前（設定の名前と実体の名前）・場所と、リポジトリとの入れ子を確かめる。問題があれば理由を返す */
function placementProblem(projectDir) {
  const env = process.env.VGDD_Z3_DIR;
  if (env && !path.isAbsolute(env)) return 'VGDD_Z3_DIR が絶対パスでない';
  for (const n of new Set([path.basename(path.resolve(Z3)), path.basename(realish(Z3))])) {
    const p = z3NameProblem(n);
    if (p) return p;
  }
  const segs = z3HomeSegs();
  if (!segs) return 'Z3 がホームの下にない';
  if (segs.length > Z3_MAX_DEPTH) return `Z3 がホームから ${Z3_MAX_DEPTH} 段より深い`;
  if (!segs.every((x) => PATH_SEG_RE.test(x))) return 'Z3 の場所の途中の段に使えない文字がある（英数字と . _ - だけ。先頭は英数字）';
  const z = realish(Z3); const r = realish(projectDir);
  if (isInside(z, r)) return 'Z3 がリポジトリ（プロジェクトの場所）の中にある';
  if (isInside(r, z)) return 'リポジトリ（プロジェクトの場所）が Z3 の中にある';
  return null;
}

// Kernel の設定（p0.4.15）。Z3 の中（オーナーだけが書ける場所）に置く。Z3 の外からは読まない（記号リンクはたどらない）。
//   ファイルがなければ、元の案件の既定（準備資料・作業記録）。読めない・形が違うときは、すべての操作を拒否する（fail-closed）。
//   extra_readonly_dirs は既定に**足す**（保護を減らせない）。readonly_dirs は既定を**置き換える**（保護を減らせる。別の案件で既定の2つを外すときだけ）。
//   どちらか一方だけを書ける（審査 m5）
const KERNEL_CONFIG = path.join(Z3, 'kernel.config.json');
const DEFAULT_READONLY_DIRS = ['../preparation', '../event_records'];
const READONLY_LABELS = { '../preparation': ['準備資料（リポジトリの外・読み取り専用）', '準備資料'], '../event_records': ['作業記録（リポジトリの外・読み取り専用）', '作業記録'] };
/** JSON の最上位のキーを、書いてある順にすべて返す（重複を見つけるため。JSON.parse は後勝ちで重複を消す）。走査できなければ null */
function topLevelKeys(text) {
  const keys = []; let depth = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      if (j >= text.length) return null;
      if (depth === 1) {
        let k = j + 1; while (k < text.length && /\s/.test(text[k])) k++;
        if (text[k] === ':') { try { keys.push(JSON.parse(text.slice(i, j + 1))); } catch { return null; } }
      }
      i = j; continue;
    }
    if (c === '{' || c === '[') depth++; else if (c === '}' || c === ']') depth--;
  }
  return keys;
}
function loadKernelConfig() {
  let text;
  let fd = null;
  try {
    fd = fs.openSync(KERNEL_CONFIG, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.size > 64 * 1024) return { error: 'kernel.config.json がファイルでないか大きすぎる' };
    text = fs.readFileSync(fd, 'utf8');
  } catch (e) {
    if (e && e.code === 'ENOENT') return { readonlyDirs: DEFAULT_READONLY_DIRS, source: 'default', replaced: false };
    if (e && e.code === 'ELOOP') return { error: 'kernel.config.json が記号リンク（たどらない）' };
    return { error: 'kernel.config.json を読めない' };
  } finally { if (fd !== null) try { fs.closeSync(fd); } catch { /* 閉じられなくても判定は上で決まっている */ } }
  let j;
  try { j = JSON.parse(text); } catch { return { error: 'kernel.config.json が JSON でない' }; }
  if (!j || typeof j !== 'object' || Array.isArray(j) || j.schema !== 'vgdd.kernel-config.v1') return { error: 'kernel.config.json の schema が vgdd.kernel-config.v1 でない' };
  const keys = topLevelKeys(text);
  if (!keys || new Set(keys).size !== keys.length) return { error: 'kernel.config.json に同じ項目が二度ある（または走査できない）' };
  if (Object.keys(j).some((k) => !['schema', 'extra_readonly_dirs', 'readonly_dirs'].includes(k))) return { error: 'kernel.config.json に知らない項目がある' };
  const hasExtra = Object.prototype.hasOwnProperty.call(j, 'extra_readonly_dirs'); const hasRepl = Object.prototype.hasOwnProperty.call(j, 'readonly_dirs');
  if (hasExtra === hasRepl) return { error: 'kernel.config.json には extra_readonly_dirs（足す）と readonly_dirs（置き換える）のどちらか一方だけを書く' };
  const d = hasExtra ? j.extra_readonly_dirs : j.readonly_dirs;
  if (!Array.isArray(d) || d.length > 32) return { error: 'kernel.config.json の読み取り専用の一覧が配列でない（または 32 を超える）' };
  for (const x of d) {
    if (typeof x !== 'string' || x.length === 0 || x.length > 200 || /[\u0000-\u001f\u007f*?[\]{}]/.test(x) || x.startsWith('~')) return { error: 'kernel.config.json の読み取り専用の一覧に形の違う項目がある（~ で始まる値も不可）' };
    const b = path.basename(x);
    if (!b || b === '.' || b === '..') return { error: 'kernel.config.json の読み取り専用の一覧に名前のない項目がある' };
  }
  return { readonlyDirs: hasExtra ? [...new Set([...DEFAULT_READONLY_DIRS, ...d])] : d, source: 'file', replaced: hasRepl };
}
let KCONF = { readonlyDirs: DEFAULT_READONLY_DIRS };
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');

// ---- 入力 -----------------------------------------------------------------

function readStdin() {
  return fs.readFileSync(0, 'utf8');
}

// ---- パスの実体（シンボリックリンクの解決。OBS-013①） -----------------------------

/** 絶対パスにしてシンボリックリンクを解決する。ファイルがまだなければ、存在する最も近い親を解決して残りを足す */
function realish(p) {
  const abs = path.resolve(p);
  try {
    return fs.realpathSync(abs);
  } catch { /* まだ存在しない */ }
  const parts = [];
  let dir = abs;
  for (let i = 0; i < 64; i++) {
    parts.unshift(path.basename(dir));
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
    try {
      return path.join(fs.realpathSync(dir), ...parts);
    } catch { /* さらに上へ */ }
  }
  return abs;
}

function isInside(target, dir) {
  const rel = path.relative(dir, target);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

// ---- リポジトリのルートと git の状態（cwd から .git を探す） -------------------

/** dir から上に向かって .git（ディレクトリまたは worktree の .git ファイル）を探し、ルートを返す */
function findRepoRoot(startDir) {
  let dir = path.resolve(startDir);
  for (let i = 0; i < 64; i++) {
    if (fs.existsSync(path.join(dir, '.git'))) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
  return null;
}

/** .git の実体（ディレクトリ）と、共通ディレクトリ（worktree なら main の .git）を返す */
function resolveGitDirs(root) {
  const dotGit = path.join(root, '.git');
  let gitDir = dotGit;
  if (fs.statSync(dotGit).isFile()) {
    const m = fs.readFileSync(dotGit, 'utf8').match(/^gitdir:\s*(.+)$/m);
    if (!m) return null;
    gitDir = path.resolve(root, m[1].trim());
  }
  let commonDir = gitDir;
  const cdFile = path.join(gitDir, 'commondir');
  if (fs.existsSync(cdFile)) commonDir = path.resolve(gitDir, fs.readFileSync(cdFile, 'utf8').trim());
  return { gitDir, commonDir };
}

/** 入力の cwd から、ブランチ名と HEAD（12桁）を読む。git は起動しない */
function gitState(cwd) {
  const out = { repo_root: null, branch: null, head: null, is_worktree: false };
  try {
    const root = findRepoRoot(cwd);
    if (!root) return out;
    out.repo_root = root;
    const dirs = resolveGitDirs(root);
    if (!dirs) return out;
    out.is_worktree = dirs.gitDir !== dirs.commonDir;
    const headTxt = fs.readFileSync(path.join(dirs.gitDir, 'HEAD'), 'utf8').trim();
    const ref = headTxt.match(/^ref:\s*(.+)$/);
    if (!ref) {
      out.branch = '(detached)';
      out.head = headTxt.slice(0, 12);
      return out;
    }
    out.branch = ref[1].replace(/^refs\/heads\//, '');
    for (const base of [dirs.gitDir, dirs.commonDir]) {
      const refFile = path.join(base, ref[1]);
      if (fs.existsSync(refFile)) {
        out.head = fs.readFileSync(refFile, 'utf8').trim().slice(0, 12);
        return out;
      }
    }
    const packed = path.join(dirs.commonDir, 'packed-refs');
    if (fs.existsSync(packed)) {
      const line = fs.readFileSync(packed, 'utf8').split('\n').find((l) => l.endsWith(' ' + ref[1]));
      if (line) out.head = line.slice(0, 12);
    }
  } catch { /* 読めないときは null のまま */ }
  return out;
}

// ---- 保護パス -------------------------------------------------------------

/**
 * リポジトリのルートからの相対パス（/ 区切り）が保護対象かを判定する。
 * .claude/ はすべて保護。ただし .claude/worktrees/<name>/ だけ例外で、その中は「中の相対パス」で再判定する
 * （worktree のルートに .git があれば findRepoRoot がそこを root にするので、通常はここに来る前に相対化される）。
 */
function isProtectedRel(rel) {
  const r = rel.replace(/\\/g, '/').replace(/^\.\//, '');
  if (r === '' || r === '.') return null;
  if (r === 'CLAUDE.md') return 'CLAUDE.md（開発エージェントの入口）';
  if (r === '.github' || r.startsWith('.github/')) return '.github（CI 定義）';
  if (r === 'vgdd' || r.startsWith('vgdd/')) return 'vgdd（法律のスクリプト・原本。変更は差分で提案し、オーナーが反映）';
  if (r === 'docs/tasks/_board.json') return 'docs/tasks/_board.json（gate-runner だけが書く）';
  // p0.4.3：Kernel の状態の写し（裁判所だけが書く。表示用で判断の根拠にしない）。一時ファイル（.tmp-*）も含む
  //   書き出しの一時ディレクトリと親の差し替えも止めるため、docs/governance/ を丸ごと保護する（summary.json もオーナーが書く。Codex の再監査 #3）
  if (r === 'docs/governance' || r.startsWith('docs/governance/')) return 'docs/governance（Kernel の状態の写し。裁判所とオーナーだけが書く）';
  if (r.startsWith('merge-requests/done/')) return 'merge-requests/done（gate-runner が処理済みの申請を置く）';
  if (r.startsWith('merge-requests/launch/done/')) return 'merge-requests/launch/done（起動の窓口が処理済みの申請を置く）';
  if (r === '.claude' || r.startsWith('.claude/')) {
    const wt = r.match(/^\.claude\/worktrees\/([^/]+)(?:\/(.*))?$/);
    if (!wt) return '.claude（権限ルール・フック登録・エージェント定義）';
    // 例外：worktree の中。中の相対パスで再判定（.claude/ のコピー等はまた保護）
    const inner = wt[2] ?? '';
    return inner ? isProtectedRel(inner) : null;
  }
  return null;
}

/** 絶対パスが「読み取りも禁止」の領域（Z3）か。リンクは実体で比べる */
function isNoReadAbs(absPath) {
  const p = realish(absPath);
  const z3 = realish(Z3);
  return isInside(p, z3);
}

/** 絶対パスが「リポジトリの外の読み取り専用」（準備資料・作業記録。p0.4.15 から Z3 の kernel.config.json で指定。なければこの2つ）か */
function isReadOnlyOutside(absPath, projectDir) {
  const p = path.resolve(absPath);
  for (const [dir, label] of KCONF.readonlyDirs.map((d) => [path.resolve(projectDir, d), (READONLY_LABELS[d] || [])[0] || '読み取り専用の領域（Kernel の設定 kernel.config.json の指定）'])) {
    const rel = path.relative(dir, p);
    if (rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel))) return label;
  }
  return null;
}

/** ユーザー設定（~/.claude など）。書き込み禁止 */
function isUserConfig(absPath) {
  const p = path.resolve(absPath);
  const targets = [
    [path.join(HOME, '.claude', 'settings.json'), 'ユーザー設定 ~/.claude/settings.json'],
    [path.join(HOME, '.claude', 'settings.local.json'), 'ユーザー設定 ~/.claude/settings.local.json'],
    [path.join(HOME, '.claude.json'), 'ユーザー設定 ~/.claude.json'],
    [path.join(HOME, '.claude', 'CLAUDE.md'), 'ユーザーの指示 ~/.claude/CLAUDE.md'],   // p0.4.16
  ];
  for (const [t, label] of targets) if (p === t) return label;
  for (const [d, label] of [
    [path.join(HOME, '.claude', 'hooks'), 'ユーザーのフック ~/.claude/hooks'],
    [path.join(HOME, '.claude', 'agents'), 'ユーザーのエージェント定義 ~/.claude/agents'],
    [path.join(HOME, '.claude', 'skills'), 'ユーザーのスキル ~/.claude/skills'],
    [path.join(HOME, '.claude', 'commands'), 'ユーザーのコマンド ~/.claude/commands'],
    [path.join(HOME, '.claude', 'rules'), 'ユーザーの規則 ~/.claude/rules'],
    [path.join(HOME, '.claude', 'output-styles'), 'ユーザーの出力スタイル ~/.claude/output-styles'],
  ]) {
    const rel = path.relative(d, p);
    if (rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel))) return label;
  }
  return null;
}

/**
 * 書き込み系ツールの対象パスを判定する。返り値は拒否理由（null なら許可）。
 * 1) Z3 → 拒否  2) リポジトリの外の読み取り専用 → 拒否  3) ユーザー設定 → 拒否
 * 4) リポジトリのルートからの相対パスで保護対象 → 拒否（main でも worktree でも同じ規則）
 * 5) merge-requests/*.json は行政の長（agent_type なし）だけ
 */
function judgeWritePath(rawPath, projectDir, agentType, confine) {
  const absPath = realish(rawPath); // リンクは実体で判定（OBS-013①）
  if (isNoReadAbs(absPath)) return 'Z3 保護領域（評価用テスト・正解ラベル・フック・証拠ストア）';
  const ro = isReadOnlyOutside(absPath, projectDir);
  if (ro) return ro;
  const uc = isUserConfig(absPath);
  if (uc) return uc;
  // 作業員の閉じ込め（OBS-013②）：自分の worktree の外には書けない
  if (confine) {
    if (!confine.root) return '作業員の cwd がリポジトリ（worktree）の中ではないため、書き込みを許可できない';
    if (!isInside(absPath, confine.root)) return `作業員（${confine.label}）は自分の worktree（${confine.root}）の外に書けない`;
  }
  const root = findRepoRoot(path.dirname(absPath)) || findRepoRoot(absPath) || projectDir;
  const rel = path.relative(root, absPath).replace(/\\/g, '/');
  if (rel.startsWith('..')) {
    // リポジトリの外：blockWritesOutsideWorkingDirectories に任せる。ここでは判定しない
    return null;
  }
  const prot = isProtectedRel(rel);
  if (prot) return prot;
  if (/^merge-requests\/[^/]+\.json$/.test(rel) && agentType) {
    return `merge-requests（統合の申請は行政の長だけが置ける。agent_type=${agentType} からは不可）`;
  }
  // p0.4.10：作業員の起動の申請（merge-requests/launch/T-NNN.json）も行政の長（agent_type なし）だけ。名前は票の ID の形だけ
  if (/^merge-requests\/launch\//.test(rel)) {
    if (agentType) return `merge-requests/launch（作業員の起動の申請は行政の長だけが置ける。agent_type=${agentType} からは不可）`;
    if (!/^merge-requests\/launch\/T-[0-9]{3,4}\.json$/.test(rel)) return 'merge-requests/launch（申請のファイル名は T-NNN.json だけ）';
  }
  return null;
}

// ---- Bash の判定 ----------------------------------------------------------

/**
 * 照合の前処理：
 *  - git commit の -m / --message / -F の本文（ヒアドキュメントを含む）を落とす（誤検知の対策。コミット本文は書き込みではない）
 *  - .claude/worktrees/<name>/ の下の通常パスを WT/ に置き換え、.claude の照合に当たらないようにする
 *    （WT/.claude/… や WT/CLAUDE.md はそのまま残るので保護される）
 */
function preprocessCommand(cmd) {
  let c = cmd;
  if (/(^|[\s;&|])git\s+commit\b/.test(c)) {
    // ヒアドキュメント本体（<<'EOF' … EOF）を落とす
    c = c.replace(/<<-?\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\1[^\n]*\n[\s\S]*?\n\2(?=\n|$)/g, '<<HEREDOC_BODY_REMOVED');
    // -m "…" / -m '…' / --message=… / --message "…"
    c = c.replace(/(\s(?:-m|--message)(?:=|\s+))("(?:[^"\\]|\\.)*"|'[^']*'|\S+)/g, '$1MSG');
  }
  c = c.replace(/\.claude\/worktrees\/[^/\s'"`]+\//g, 'WT/');
  return c;
}

// 保護パスを指していそうな語（文字列照合。回避の余地は残る）
// p0.2.1①：語の終わりまで見る。直後が「/」か語の区切り（空白・引用符・; | & )・行末）のときだけ一致する。
//   `docs/vgdd-status.md` の vgdd（直後が -）や `preparation_notes.md`（直後が _）は一致しない。
//   `.claude` は従来どおり（`.claude.json` も `.claude` の語として止める。安全側）
const END_OF_WORD = String.raw`(?=\/|[\s"'\x60;|&)]|$)`; // \x60 はバッククォート
// 語の直前の区切り。p0.2.1⑤：> < | & ; ( を加える（`echo x>.claude/s` の > の直後も語の始まり）
const START_OF_WORD = String.raw`(^|[\s"'\x60=/><|&;(])`;
const tok = (body) => new RegExp(START_OF_WORD + body + END_OF_WORD);
// p0.4.15：Z3 の名前の照合を、実際の Z3 の場所から作る（p0.4.14 までは tsubuyaki-z3 の直書きで、別の名前の Z3 では Bash の拒否が効かなかった）。
//   ①名前（設定の名前と実体の名前）がどこかに現れれば拒否（読み取りも）
//   ②グロブの疑い：Z3 の親の場所（~・$HOME・${HOME}・/Users/<名前>、絶対パス。ホームの形は Z3 の場所によらずいつも見る）の直後に、
//     Z3 の名前の先頭4字で始まる語があれば拒否。ただし正当な兄弟（今のプロジェクトと既定のリポジトリの場所の、親の直下の名前）は除く。
//     兄弟の名前が Z3 の名前の先頭と同じ（Z3 の名前が兄弟の名前で始まる）ときは、その兄弟を除かない（`~/<兄弟>*` が Z3 に展開されうるため）。
//   既定の配置（~/tsubuyaki-z3 と ~/tsubuyaki-worklog/app）では p0.4.14 までと同じ照合になる
//   p0.4.15 の審査（m2・m3・§12 の例）で強めた点：兄弟を除くのは、語（区切りまで）が兄弟そのものか兄弟の配下を指し、`..` の段を含まないときだけ
//   （`~/tsubuyaki-worklog/../tsub*`・`~/tsubuyaki-worklog*` は疑う）。ホームの形に `~<名前>`・引用符つきの `"$HOME"` を含め、
//   ホームの形と名前の間の `//`・`/./` も同じに見る。Z3 が 2 段目（~/<段>/<名前>）なら、途中の段のグロブ（~/*/<先頭4字>…）も疑う
function z3Tokens(projectDir, cwd, hasCd) {
  const zAbs = path.resolve(Z3); const zReal = realish(Z3);
  const names = [...new Set([path.basename(zAbs), path.basename(zReal)])];
  const toks = names.map((n) => ({ re: new RegExp(escapeRe(n)), noRead: true, label: 'Z3 保護領域' }));
  // ~ だけは p0.4.14 と同じく前の境目を見ない。~<名前> は語の始まりのときだけ（`git diff HEAD~1/…` を取り違えない。再審査 N4）
  const HOME_FORMS = [String.raw`(?:~|(?<=^|[\s"'\x60=/><|&;(])~[A-Za-z0-9._-]+)`, String.raw`"?\$HOME"?`, String.raw`"?\$\{HOME\}"?`, String.raw`\/Users\/[^/\s]+`];
  const homes = [...new Set([HOME, realish(HOME)])];
  const parents = [...new Set([path.dirname(zAbs), path.dirname(zReal)])];
  const anchors = new Set(HOME_FORMS);
  const segs = z3HomeSegs();
  if (segs && segs.length >= 2) for (const f of HOME_FORMS) anchors.add(`${f}(?:\\/[^/\\s]+){1,${segs.length - 1}}`);
  for (const parent of parents) {
    anchors.add(escapeRe(parent));
    for (const h of homes) {
      if (!isInside(parent, h) || parent === h) continue;
      const rel = escapeRe(path.relative(h, parent).split(path.sep).join('/'));
      for (const f of HOME_FORMS) anchors.add(`${f}\\/${rel}`);
    }
  }
  const siblings = new Set();
  for (const base of [...new Set([...homes, ...parents])]) {
    for (const r of [path.resolve(projectDir), realish(projectDir), DEFAULT_REPO]) {
      if (isInside(r, base) && r !== base) siblings.add(path.relative(base, r).split(path.sep)[0]);
    }
  }
  for (const n of names) {
    const prefix = n.slice(0, Z3_NAME_MIN);
    const sibs = [...siblings].filter((s) => s.length > prefix.length && s.startsWith(prefix) && !names.some((m) => m.startsWith(s)));
    const re = new RegExp(`(?:${[...anchors].join('|')})(?:\\/\\.?(?=\\/))*\\/${escapeRe(prefix)}`, 'g');
    // 兄弟として除くのは、語（空白・区切りまで。引用符やバックスラッシュも語に含める）が決まった文字（英数字と . _ / -）だけでできていて、
    //   文字列として正規化（a/b/.. → a）した結果が親へ出ず、兄弟そのものか兄弟の配下を指すときだけ。グロブ・中括弧・引用符・バックスラッシュ・$ を含む語は、
    //   展開すると .. になりうるので除かない（再審査 N1：`~/<兄弟>/{..,x}/tsub*`・`~/<兄弟>/.?/tsub*`・`~/<兄弟>/'..'/tsub*`）
    const excused = (str, at) => {
      const word = (/^[^\s;|&()<>]*/.exec(str.slice(at)) || [''])[0].replace(/["'\x60]+$/, '');   // 外側の引用の閉じだけは除く
      if (!/^[A-Za-z0-9._\/-]+$/.test(word)) return false;
      const norm = path.posix.normalize(word);
      if (norm === '..' || norm.startsWith('../')) return false;
      return sibs.some((x) => norm === x || norm === x + '/' || norm.startsWith(x + '/'));
    };
    toks.push({ re: { test: (str) => { re.lastIndex = 0; let m; while ((m = re.exec(str))) { if (!excused(str, m.index + m[0].length - prefix.length)) return true; } return false; } }, noRead: true, label: 'Z3 保護領域（グロブの疑い）' });
    toks.push({ re: { test: (str) => dotdotSuspect(str, prefix, zAbs, zReal, cwd, hasCd) }, noRead: true, label: 'Z3 保護領域（.. の後のグロブの疑い）' });
  }
  return toks;
}
/**
 * `..` の段を含む語が Z3 に届きうるか（再審査 N2）。語ごとに見る：
 *   ・コマンドに cd がなければ、語を今の cwd で解決し、文字列として正規化する。グロブ・中括弧・引用符・バックスラッシュ（展開で形が変わる文字）が
 *     なければ、正規化したパスが Z3 の中かだけを見る（`../lib/tsubuyaki.ts` は通る）。あれば、その文字の前までで決まるフォルダ D について、
 *     D が Z3 の親で、次の段の文字（展開の前まで）が4字以上で Z3 の名前の先頭と同じなら疑う。D が Z3 のさらに上なら、次の段が Z3 への途中の段と合いうり、
 *     残りに名前の先頭4字があれば疑う。展開で決まる部分に `..`・`.` で始まる段・中括弧があり、残りに先頭4字があれば疑う
 *   ・cd があれば（今の場所が決まらない）、`..` の並びの直後の段が先頭4字で始まるときだけ疑う（`../../tsub*`。`../lib/tsubuyaki.ts` は疑わない）
 */
function dotdotSuspect(str, prefix, zAbs, zReal, cwd, hasCd) {
  const words = str.split(/[\s;|&()<>]+/).map((w) => w.replace(/^[^=/~.$"']*=/, '')).filter((w) => /(^|\/)['"\\]*\.['"\\]*\.['"\\]*(\/|$)/.test(w));
  for (const w0 of words) {
    const w = w0.replace(/['"\\]/g, '');   // 引用符とバックスラッシュは取り除いた形が実際のパス（展開ではない）
    if (hasCd || !cwd) { if (new RegExp(`(?:^|\\/)(?:\\.\\.\\/)+${escapeRe(prefix)}`).test(w)) return true; continue; }
    let base; let rest;
    const hm = /^(~|\$HOME|\$\{HOME\})(\/.*)?$/.exec(w);
    if (hm) { base = HOME; rest = hm[2] || ''; } else if (w.startsWith('/')) { base = '/'; rest = w; } else if (w.startsWith('~')) return true; else { base = cwd; rest = '/' + w; }
    const k = rest.search(/[*?[\]{}$`]/);
    if (k === -1) { const p = path.resolve(base, '.' + rest); if (isInside(p, zAbs) || isInside(p, zReal)) return true; continue; }
    const lit = rest.slice(0, k); const cut = lit.lastIndexOf('/');
    const D = path.resolve(base, '.' + lit.slice(0, cut + 1)); const segLit = lit.slice(cut + 1); const after = rest.slice(cut + 1);
    for (const z of [zAbs, zReal]) {
      if (!isInside(z, D) || z === D) continue;
      const zr = path.relative(D, z).split(path.sep);
      if (zr.length === 1 ? segLit.length >= Z3_NAME_MIN && zr[0].startsWith(segLit) : zr[0].startsWith(segLit) && after.includes(prefix)) return true;
    }
    if (after.includes(prefix) && (/(^|\/)\.|[{}]/.test(after))) return true;
  }
  return false;
}
/** フックの Bash の照合に使う保護語の一覧（Z3 の場所と Kernel の設定から作る） */
function bashProtectedTokens(projectDir, cwd = null, hasCd = true) {
  const ro = KCONF.readonlyDirs.map((d) => ({ re: tok(String.raw`(\.\.\/)?` + escapeRe(path.basename(d))), noRead: false, label: (READONLY_LABELS[d] || [])[1] || '読み取り専用の領域（Kernel の設定の指定）' }));
  return [...z3Tokens(projectDir, cwd, hasCd), ...BASH_PROTECTED_TOKENS, ...ro];
}
const BASH_PROTECTED_TOKENS = [
  { re: new RegExp(START_OF_WORD + String.raw`\.claude(\/|\b)`), noRead: false, label: '.claude' },
  { re: /(~|\$HOME|\$\{HOME\}|\/Users\/[^/\s]+)\/\.claude(\/|\b)/, noRead: false, label: 'ユーザー設定 ~/.claude' },
  { re: /(~|\$HOME|\$\{HOME\}|\/Users\/[^/\s]+)\/\.claude\.json/, noRead: false, label: 'ユーザー設定 ~/.claude.json' },
  { re: /CLAUDE\.md/, noRead: false, label: 'CLAUDE.md' },
  { re: tok(String.raw`\.github`), noRead: false, label: '.github' },
  { re: tok(String.raw`vgdd`), noRead: false, label: 'vgdd（法律のスクリプト）' },
  { re: /docs\/tasks\/_board\.json/, noRead: false, label: 'docs/tasks/_board.json' },
  { re: /docs\/governance(?![\w.-])|kernel-(state|invariants)\.json/, noRead: false, label: 'docs/governance（Kernel の状態の写し）' },   // p0.4.3。p0.4.5：docs/governance.md（文書）を取り違えない
  { re: new RegExp(String.raw`merge-requests\/done` + END_OF_WORD), noRead: false, label: 'merge-requests/done' },
  { re: new RegExp(String.raw`merge-requests\/launch` + END_OF_WORD), noRead: false, label: 'merge-requests/launch（起動の申請は Write ツールで行政の長だけが置く。Bash では書かない）' },   // p0.4.10
  // 準備資料・作業記録（p0.4.14 までは ../preparation・../event_records の直書き）は、p0.4.15 から Kernel の設定から作る（bashProtectedTokens）
];

// 読み取り専用と見なすコマンドの先頭（各セグメントの先頭に一致すること）
// p0.2.1④：git の読み取り系に merge-base・describe・blame・cat-file・check-ignore・name-rev を追加
const READ_ONLY_HEAD = /^\s*(cat|ls|head|tail|wc|grep|rg|diff|stat|file|du|tree|find|jq|less|more|echo|printf|date|pwd|awk|cut|sort|uniq|tr|nl|column|sed\s+-n|git\s+(diff|status|log|show|ls-files|rev-parse|branch|remote|worktree\s+list|config\s+--get|config\s+user\.\w+|merge-base|describe|blame|cat-file|check-ignore|name-rev)|node\s+-e\s+["'][^"']*(?:console\.log|JSON\.parse|require\(['"]\.\/package)|python3?\s+-c\s+["'][^"']*json\.load|bash\s+-n|node\s+--check)/;

// 書き込みのリダイレクト（p0.2.1③）：`>`・`>>` のうち、`2>&1`・`>&2`（fd の合流）と /dev/null・/dev/stdout・/dev/stderr への出力は書き込みではない
const REDIRECT_WRITE = /(?<!<)>>?(?![&>])(?!\s*\/dev\/(?:null|stdout|stderr)\b)/;

// 書き込み・実行の気配があれば読み取り専用とは見なさない
// p0.2.1③：リダイレクトは REDIRECT_WRITE と同じ条件。p0.2.1④：git のサブコマンドは語の終わりまで見る（merge-base は merge ではない）
const WRITE_HINT = /(\bfind\b[^;|&]*\s-(delete|exec|execdir|ok|okdir)\b|\bsed\b[^;|&]*(?:[\/;'"\s]w\s+\S|[\/;'"\s]W\s+\S)|(?<!<)>>?(?![&>])(?!\s*\/dev\/(?:null|stdout|stderr)\b)|\btee\b|\bcp\b|\bmv\b|\brm\b|\bmkdir\b|\btouch\b|\bchmod\b|\bchown\b|\bln\b|\binstall\b|\brsync\b|\btruncate\b|\bdd\b|\bsed\s+-i|\bperl\s+-[a-z]*i|\bpython3?\b(?!\s+-c\s+["'][^"']*json\.load)|\bnode\b(?!\s+(-e\s+["'][^"']*(?:console\.log|JSON\.parse|require\(['"]\.\/package)|--check))|\bperl\b|\bruby\b|\b(sh|bash|zsh)\s+-c|\beval\b|\bsource\b|\bxargs\b|\bgit\s+(add|commit|checkout|switch|restore|reset|clean|stash|apply|am|mv|rm|merge|rebase|cherry-pick|update-ref|symbolic-ref)(?![\w-])|\bopen\b|\bosascript\b)/;

/**
 * ; && || | でセグメントに分割する。p0.2.1②：引用符（' " `）の中では分割しない。
 * 引用符が閉じていないコマンドは、そのまま1セグメントとして扱う（安全側：先頭の語で読み取り専用かを判定する）。
 * 単独の & と >& 2>&1 は分割しない（バックグラウンド実行・fd の合流）。
 */
function splitSegments(cmd) {
  const segs = [];
  let cur = '';
  let quote = null;
  for (let i = 0; i < cmd.length; i++) {
    const ch = cmd[i];
    if (quote) {
      cur += ch;
      if (ch === '\\' && quote === '"' && i + 1 < cmd.length) { cur += cmd[++i]; continue; }
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === "'" || ch === '"' || ch === '`') { quote = ch; cur += ch; continue; }
    if (ch === '\\' && i + 1 < cmd.length) { cur += ch + cmd[++i]; continue; }
    const two = cmd.slice(i, i + 2);
    if (ch === ';' || two === '&&' || two === '||' || (ch === '|' && two !== '||')) {
      if (two === '&&' || two === '||') i++;
      if (cur.trim()) segs.push(cur.trim());
      cur = '';
      continue;
    }
    cur += ch;
  }
  if (cur.trim()) segs.push(cur.trim());
  return segs;
}

// p0.4.0：git の全体のオプション（-c 鍵=値、--no-pager など）を挟んだ commit も commit として見る。
//   以前は `git -c user.name=x commit` が main へのコミットの照合をすり抜けた（作者名を偽る経路でもある）
const GIT_COMMIT_RE = /\bgit\s+((-c|--config-env)\s+\S+\s+|--[\w-]+(=\S+)?\s+|-[pP]\s+)*commit\b/;
/** ホームの .git と main を守る：git の対象の向け直し、main への統合・参照の書き換えを拒否 */
function judgeGitScope(command, git, agentType) {
  if (/\bGIT_(DIR|WORK_TREE|COMMON_DIR|INDEX_FILE)=/.test(command)) {
    return 'git の環境変数（GIT_DIR / GIT_WORK_TREE 等）で対象リポジトリを切り替えている';
  }
  const segs = splitSegments(command);
  let leftProject = false;
  for (const seg of segs) {
    const cd = seg.match(/^\s*(cd|pushd)\s+(\S+)/);
    if (cd) {
      const dest = cd[2].replace(/^["']|["']$/g, '');
      if (/^(\.\.|\/|~|\$HOME|\$\{HOME\})/.test(dest) || dest === '-') leftProject = true;
    }
    if (!/(^|[\s;&|(])git(\s|$)/.test(seg)) continue;
    if (leftProject) return `作業フォルダの外に cd したあとで git を実行している：「${seg.trim().slice(0, 60)}」`;
    if (/\s--git-dir(=|\s)|\s--work-tree(=|\s)/.test(seg)) return '--git-dir / --work-tree で対象リポジトリを切り替えている';
    const c = seg.match(/\s-C\s+(\S+)/) || seg.match(/\s-C(\S+)/);
    if (c) {
      const dir = c[1].replace(/^["']|["']$/g, '');
      if (!(dir === '.' || dir === './' || dir === '$PWD' || dir === '"$PWD"')) {
        return `git -C ${dir} で作業フォルダ以外のリポジトリを対象にしている（ホームの .git と main を守るため）`;
      }
    }
    // p0.3.1：git の設定の書き換えを拒否（OBS-033）。共有の .git/config に core.hooksPath・core.fsmonitor 等を書かれると、
    //   sandbox の外で動く gate-runner・夜間ランナーの git の操作で、作業員の用意したスクリプトがオーナーの権限で実行されうる。
    //   読み取り（--get・--list・-l・--get-all・--get-regexp・--show-origin）だけ許す。-c による一時的な上書きも、危険な鍵は拒否
    if (/\bgit\s+config\b/.test(seg) && !/\bgit\s+config\s+(--get(-all|-regexp)?|--list|-l|--show-origin|--show-scope)\b/.test(seg)) {
      return 'git config の書き換えは禁止（共有の git の設定は裁判所の動作に影響するため。OBS-033）';
    }
    if (/\bgit\s+(-c\s+\S+\s+)*-c\s+(core\.(hooksPath|fsmonitor|sshCommand|pager|editor|askPass)|filter\.|diff\.\S+\.textconv|alias\.)/i.test(seg)) {
      return 'git -c による危険な設定（hooksPath・fsmonitor・filter など）は禁止（OBS-033）';
    }
    // main への統合・参照の書き換え（統合は gate-runner だけが行う。D-45③・D-47①）
    // p0.2.1④：merge の語の終わりまで見る（git merge-base は読み取り）
    if (/\bgit\s+merge(?![\w-])/.test(seg)) return 'git merge は禁止（統合は gate-runner だけが行う）';
    if (/\bgit\s+(branch\s+(-f|-D|-d|--force|--delete)\s+\S*\bmain\b|update-ref\s+\S*refs\/heads\/main\b|symbolic-ref\s+HEAD\s+\S*main\b)/.test(seg)) {
      return 'main の参照を書き換えている';
    }
    if (/\bgit\s+push\b[^;|&]*\bmain\b/.test(seg) && agentType) return `作業員（${agentType}）からの main への push は禁止`;
    if (git.branch === 'main' && /\bgit\s+(rebase|reset|cherry-pick|am|apply|revert)\b/.test(seg)) {
      return `main 上での git ${seg.match(/\bgit\s+(\w+)/)[1]} は禁止（main の履歴は gate-runner だけが進める）`;
    }
    if (git.branch === 'main' && agentType && GIT_COMMIT_RE.test(seg)) {
      return `作業員（${agentType}）が main に直接コミットしようとしている（票のブランチで作業する）`;
    }
    if (git.branch === 'main' && !agentType && GIT_COMMIT_RE.test(seg)) {
      const why = judgeHeadMainCommit(command, git);
      if (why) return why;
    }
  }
  return null;
}

/**
 * p0.4.0：行政の長が main に直接コミットしてよいのは docs/ の下（票・記録・文書）だけ（成立条件④。Codex の指摘 #16）。
 * ソースは作業員のブランチから裁判所を通って入る。判定：
 *   ・commit のセグメントは決まった形だけ（-q・-m・--message・-F・--file・-s・--signoff・-v）。-a・--all・パスの指定・--amend・-i・-o などは拒否
 *   ・同じコマンドの git add は、対象がすべて docs/ の下のパスのときだけ（-A・.・-u・グロブは拒否）。git rm・git mv・git apply などは拒否
 *   ・すでにステージされたファイル（git diff --cached）がすべて docs/ の下
 * git を読めなければ拒否（fail-closed）。コミットの本文は preprocessCommand で MSG に置き換わっている
 */
const HEAD_COMMIT_FORM = /^\s*git\s+commit(\s+(-q|--quiet|-s|--signoff|-v|--verbose|-m\s+MSG|--message(=|\s+)MSG|-F\s+\S+|--file(=|\s+)\S+|<<HEREDOC_BODY_REMOVED))*\s*$/;
function judgeHeadMainCommit(command, git) {
  const pre = preprocessCommand(command);
  const docsOnly = (p) => /^docs\/[^*?[\]{}]+$/.test(p.replace(/^\.\//, '')) && !p.includes('..');
  for (const seg of splitSegments(pre)) {
    if (!/(^|[\s(])git\s/.test(seg)) continue;
    if (GIT_COMMIT_RE.test(seg)) {
      if (!HEAD_COMMIT_FORM.test(seg)) return `行政の長の main へのコミットは「git commit -m …」の形だけ（-a・パスの指定・--amend などは不可）：「${seg.trim().slice(0, 60)}」`;
      continue;
    }
    const add = seg.match(/^\s*git\s+add\s+(.*)$/);
    if (add) {
      const paths = add[1].split(/\s+/).filter(Boolean).map((t) => t.replace(/^["']|["']$/g, ''));
      if (paths.length === 0 || paths.some((t) => t.startsWith('-') && t !== '--') || paths.filter((t) => t !== '--').some((t) => !docsOnly(t))) {
        return `行政の長が main にコミットしてよいのは docs/ の下だけ。git add の対象が docs/ の外（または -A・. など）：「${seg.trim().slice(0, 60)}」`;
      }
      continue;
    }
    if (/\bgit\s+(rm|mv|apply|am|checkout|restore|stash|reset|cherry-pick|revert|merge|rebase)\b/.test(seg)) {
      return `main へのコミットと同じコマンドで git の書き込み（${seg.trim().slice(0, 40)}）をしている`;
    }
  }
  let staged;
  try {
    staged = execFileSync('git', ['-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false', '-C', git.repo_root, 'diff', '--cached', '--name-only'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 4000 });
  } catch {
    return 'ステージされたファイルを確かめられないため、main へのコミットを拒否（fail-closed）';
  }
  const outside = staged.split('\n').filter(Boolean).filter((f) => !f.startsWith('docs/'));
  if (outside.length) return `行政の長が main にコミットしてよいのは docs/ の下だけ。ステージに docs/ の外がある：${outside.slice(0, 3).join(' ')}（ソースは作業員のブランチから裁判所を通す）`;
  return null;
}

/**
 * 作業員の閉じ込め（Bash）：cd の先と、書き込み系セグメントに現れるパスの実体が、自分の worktree の外なら拒否。
 * パスらしい語（/ を含む、~ や . で始まる）だけを見る。URL（://）とオプション（-）は除く。
 */
function judgeConfinedBash(pre, cwd, confine) {
  let cur = realish(cwd);
  const segs = splitSegments(pre);
  for (const seg of segs) {
    const cd = seg.match(/^\s*(cd|pushd)\s+(\S+)/);
    if (cd) {
      const dest = realish(path.resolve(cur, cd[2].replace(/^["']|["']$/g, '').replace(/^~/, HOME)));
      if (!isInside(dest, confine.root)) return `作業員（${confine.label}）は自分の worktree の外（${dest}）に cd できない`;
      cur = dest;
      continue;
    }
    if (!(WRITE_HINT.test(seg) || REDIRECT_WRITE.test(seg))) continue;
    // p0.2.1⑤：> < の直後の語も拾う（空白なしのリダイレクト）
    const tokens = seg.match(/(?:^|[\s=><])((?:~|\.{1,2})?\/[^\s'"`;|&<>]+|[^\s'"`;|&<>=-][^\s'"`;|&<>]*\/[^\s'"`;|&<>]*)/g) || [];
    for (let tok of tokens) {
      tok = tok.replace(/^[\s=><]+/, '');
      if (!tok || tok.includes('://') || tok.startsWith('-')) continue;
      if (/^\/dev\/(null|stdout|stderr|tty)$/.test(tok)) continue; // p0.2.1③：デバイスへの出力は外への書き込みではない
      const abs = realish(path.resolve(cur, tok.replace(/^~/, HOME)));
      if (!isInside(abs, confine.root)) {
        return `作業員（${confine.label}）は自分の worktree の外（${abs}）に書けない：「${seg.trim().slice(0, 60)}」`;
      }
    }
  }
  return null;
}

/** 保護語と同じ判定を、コマンド中のパスの実体（リンク先）に対しても行う（OBS-013①） */
function judgeBashSymlinks(pre, cwd, projectDir) {
  const tokens = pre.match(/(?:^|[\s=><])((?:~|\.{1,2})?\/[^\s'"`;|&<>]+|[^\s'"`;|&<>=-][^\s'"`;|&<>]*\/[^\s'"`;|&<>]*)/g) || [];
  const writeish = WRITE_HINT.test(pre) || REDIRECT_WRITE.test(pre);
  for (let tok of tokens) {
    tok = tok.replace(/^[\s=><]+/, '');
    if (!tok || tok.includes('://') || tok.startsWith('-')) continue;
    const abs = path.resolve(cwd, tok.replace(/^~/, HOME));
    let real;
    try {
      real = fs.realpathSync(abs);
    } catch {
      continue; // 存在しないものはリンクではない
    }
    if (real === abs) continue; // リンクではない
    if (isNoReadAbs(real)) return `リンク ${tok} の実体が Z3 保護領域を指している`;
    if (writeish) {
      const why = judgeWritePath(real, projectDir, null, null);
      if (why) return `リンク ${tok} の実体が保護パス（${why}）を指している`;
    }
  }
  return null;
}

/**
 * p0.2.1⑤（OBS-015①）：リダイレクトの先を取り出し、Edit/Write と同じ判定（保護パス・Z3・準備資料・作業員の閉じ込め）を直接かける。
 * 対象：`> f`・`>> f`・`N> f`・`&> f`・`>| f`（空白の有無を問わない。引用符つきも）。`2>&1`・`>&2` は先が & なので対象外。
 * /dev/null 等のデバイス、変数（$）やグロブ（* ? {）を含む先は解決できないので見ない（文字列照合と sandbox に任せる）。
 * cwd はコマンドの先頭の cwd で解決する（途中の cd は閉じ込めの判定が別に見る）。
 */
const REDIRECT_TARGET_RE = /(?:^|[^<>])(?:\d*>>?|&>>?|>\|)\s*("(?:[^"\\]|\\.)*"|'[^']*'|[^\s'"`;|&<>()]+)/g;
function judgeRedirectTargets(pre, cwd, projectDir, agentType, confine) {
  for (const m of pre.matchAll(REDIRECT_TARGET_RE)) {
    const t = m[1].replace(/^["']|["']$/g, '');
    if (!t || /^\/dev\/(null|stdout|stderr|tty)$/.test(t) || /[$*?{]/.test(t)) continue;
    const abs = path.resolve(cwd, t.replace(/^~(?=\/|$)/, HOME));
    const why = judgeWritePath(abs, projectDir, agentType, confine);
    if (why) return `リダイレクトの先「${t}」が保護パス（${why}）`;
  }
  return null;
}

function judgeBash(command, git, agentType, cwd, projectDir, confine) {
  const pre = preprocessCommand(command);
  // ln は保護語の有無にかかわらず拒否（シンボリックリンクで保護を迂回する経路を塞ぐ。OBS-013①）
  if (/(^|[\s;&|(])ln(\s|$)/.test(pre)) return { decision: 'deny', reason: 'Bash: ln（リンクの作成）は禁止' };
  // リダイレクトの先を直接判定（OBS-015①）
  const rd = judgeRedirectTargets(pre, cwd, projectDir, agentType, confine);
  if (rd) return { decision: 'deny', reason: `Bash: ${rd}` };
  const gitScope = judgeGitScope(pre, git, agentType);
  if (gitScope) return { decision: 'deny', reason: `Bash: ${gitScope}` };
  const link = judgeBashSymlinks(pre, cwd, projectDir);
  if (link) return { decision: 'deny', reason: `Bash: ${link}` };
  if (confine) {
    if (!confine.root) return { decision: 'deny', reason: 'Bash: 作業員の cwd がリポジトリ（worktree）の中ではない' };
    const c = judgeConfinedBash(pre, cwd, confine);
    if (c) return { decision: 'deny', reason: `Bash: ${c}` };
  }
  const hasCd = splitSegments(pre).some((sg) => /^\s*(cd|pushd|popd)\b/.test(sg)) || /(^|[\s;&|(])(cd|pushd|popd)\b/.test(pre);
  const hits = bashProtectedTokens(projectDir, cwd, hasCd).filter((t) => t.re.test(pre));
  if (hits.length === 0) return { decision: 'allow', reason: '保護パスへの言及なし' };
  const labels = hits.map((h) => h.label).join('・');
  if (hits.some((h) => h.noRead)) {
    return { decision: 'deny', reason: `Bash が ${labels} を参照している（読み取りも禁止）` };
  }
  const segs = splitSegments(pre);
  const bad = segs.find((s) => WRITE_HINT.test(s) || !READ_ONLY_HEAD.test(s));
  if (bad) {
    return {
      decision: 'deny',
      reason: `Bash が ${labels} に対して読み取り専用と判定できない操作を含む：「${bad.trim().slice(0, 80)}」。Edit/Write でも拒否される保護パスです`,
    };
  }
  return { decision: 'allow', reason: `保護パス（${labels}）への読み取り専用コマンド` };
}

// ---- p0.4.16：AI の役割による claude・codex の CLI の起動の拒否（入れ子の起動でフックの層を外させない） --------------------------
// 入れ子の claude（--bare・--settings '{"disableAllHooks":true}'・-p など）・codex は、外側の OS の sandbox の中では動くが、このフック（判定と
//   証拠の記録・役割の閉じ込め・main への統合の照合）と予算の台帳（metered.sh）を通らないエージェントになる。そのため、Bash のコマンドの中の
//   claude・codex の起動を、どの役割からも拒む（このフックを通るのは AI の役割だけ。裁判所・夜間の代行・朝刊などのオーナーのスクリプトはフックの外）。
//   起動しない扱い（読み取り専用の先頭のコマンドの引数として名前が現れるだけ：cat・grep・ls・echo・which・type・command -v・git log など）は通す。
//   --version・--help・doctor・update も起動として拒む（行政が版を知る必要はない。doctor・update は設定や本体を変えうる）。
//   見る形：先頭の語（パスつき・大文字・引用符やバックスラッシュで分けた名前・代入の値・3字以上の字が決まったグロブを含む）、npx・npm exec などの
//   パッケージの名前（@anthropic-ai/claude-code・@openai/codex）、env・command・exec・nohup・xargs などで包んだ形、$(…)・`…`・<(…) の中、
//   シェルとスクリプトの言語（sh -c・bash -c・eval・node -e・python3 -c など）に渡す文字列、それらへのパイプとヒアドキュメント。
//   文字列の照合なので、変数で組み立てた名前・別名・スクリプトのファイルを経た起動は見分けきれない（SPEC §12。最後に残るのは外側の sandbox）
const AGENT_CLI_BASENAMES = new Set(['claude', 'codex', 'claude-code']);
const AGENT_CLI_TEXT = /(?:^|[^\w.@-])(?:claude|codex)(?![\w.-])|@anthropic-ai\/claude-code|@openai\/codex|\/claude\/versions\//i;
// 名前を引数として扱うだけの、起動しない先頭のコマンド（awk・sed・sort・xargs などはコマンドを実行できるので入れない）
const CLI_SAFE_HEADS = new Set(['cat', 'ls', 'head', 'tail', 'wc', 'grep', 'egrep', 'fgrep', 'diff', 'stat', 'file', 'du', 'tree', 'jq', 'less', 'more', 'echo', 'printf',
  'pwd', 'cut', 'uniq', 'tr', 'nl', 'column', 'basename', 'dirname', 'realpath', 'readlink', 'which', 'whereis', 'type', 'true', 'false', 'test', '[']);
// 文字列やパイプの入力をコマンドとして実行しうるもの（シェル・スクリプトの言語・包むコマンド）
const CLI_INTERP = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'fish', 'csh', 'tcsh', 'eval', 'source', '.', 'xargs', 'su', 'script', 'parallel', 'watch', 'osascript',
  'node', 'nodejs', 'deno', 'bun', 'bunx', 'npx', 'npm', 'pnpm', 'yarn', 'python', 'python2', 'python3', 'perl', 'ruby', 'php', 'lua', 'tclsh', 'expect', 'ssh', 'tmux', 'screen',
  'at', 'batch', 'awk', 'gawk', 'nawk', 'make']);
// どの位置にあってもシェル・スクリプトの言語として扱う名前（引数として現れることが少ないもの）
const CLI_SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'fish', 'csh', 'tcsh', 'eval', 'osascript', 'node', 'nodejs', 'deno', 'python', 'python2', 'python3', 'perl', 'ruby', 'php', 'lua', 'tclsh', 'expect']);
// 包むコマンド（後ろの語が実際のコマンド）
const CLI_WRAPPERS = new Set(['env', 'sudo', 'doas', 'nohup', 'nice', 'timeout', 'gtimeout', 'time', 'exec', 'command', 'builtin', 'xargs', 'caffeinate', 'arch', 'stdbuf', 'setsid',
  'unbuffer', 'watch', 'parallel', 'script', 'chronic', 'taskpolicy', 'npx', 'bunx', 'then', 'do', 'else', 'elif', 'if', 'while', 'until']);

/** 対応する ) の位置（引用符の中は数えない）。なければ末尾 */
function closeParen(s, open) {
  let d = 0; let q = null;
  for (let i = open; i < s.length; i++) {
    const c = s[i];
    if (q) { if (c === '\\' && q === '"') { i++; continue; } if (c === q) q = null; continue; }
    if (c === "'" || c === '"' || c === '`') { q = c; continue; }
    if (c === '\\') { i++; continue; }
    if (c === '(') d++; else if (c === ')') { d--; if (d === 0) return i; }
  }
  return s.length - 1;
}
/** $(…)・`…`・<(…)・>(…) の中身（一重引用符の中は除く） */
function cliSubstitutions(s) {
  const out = []; let q = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q === "'") { if (c === "'") q = null; continue; }
    if (c === '\\') { i++; continue; }
    if (c === "'" && q !== '"') { q = "'"; continue; }
    if (c === '"') { q = q === '"' ? null : '"'; continue; }
    if ((c === '$' || c === '<' || c === '>') && s[i + 1] === '(') { const e = closeParen(s, i + 1); out.push(s.slice(i + 2, e)); i = e; continue; }
    if (c === '`') { const j = s.indexOf('`', i + 1); const e = j === -1 ? s.length : j; out.push(s.slice(i + 1, e)); i = e; continue; }
  }
  return out;
}
/** ヒアドキュメントの本文を取り出し、印（<<HD番号）に置き換える。<<< は対象外 */
function cliHeredocs(s) {
  const bodies = []; let out = ''; let i = 0;
  const re = /(?<!<)<<(?!<)(-?)\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\2/g;
  let m;
  while ((m = re.exec(s))) {
    const nl = s.indexOf('\n', m.index);
    if (nl === -1) break;
    const lines = s.slice(nl + 1).split('\n'); let n = 0; const body = [];
    for (; n < lines.length; n++) { if ((m[1] ? lines[n].replace(/^\t+/, '') : lines[n]) === m[3]) break; body.push(lines[n]); }
    const end = Math.min(s.length, nl + 1 + lines.slice(0, n + 1).join('\n').length);
    out += s.slice(i, m.index) + `<<HD${bodies.length}` + s.slice(m.index + m[0].length, nl);
    bodies.push(body.join('\n'));
    i = end; re.lastIndex = end;
  }
  return { text: out + s.slice(i), bodies };
}
/** ; && || | & 改行でセグメントに分ける（引用符と $(…) の中では分けない）。各セグメントの後ろの区切りも返す */
function cliSegments(s) {
  const segs = []; let cur = ''; let q = null; let depth = 0;
  const push = (sep) => { if (cur.trim()) segs.push({ raw: cur.trim(), sep }); cur = ''; };
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) { cur += c; if (c === '\\' && q === '"' && i + 1 < s.length) { cur += s[++i]; continue; } if (c === q) q = null; continue; }
    if (c === "'" || c === '"' || c === '`') { q = c; cur += c; continue; }
    if (c === '\\' && i + 1 < s.length) { cur += c + s[++i]; continue; }
    if ((c === '$' || c === '<' || c === '>') && s[i + 1] === '(') { depth++; cur += c + '('; i++; continue; }
    if (depth > 0) { if (c === '(') depth++; else if (c === ')') depth--; cur += c; continue; }
    const two = s.slice(i, i + 2);
    if (two === '&&' || two === '||') { push(two); i++; continue; }
    if (c === '|') { if (s[i + 1] === '&') i++; push('|'); continue; }
    if (c === ';' || c === '\n') { push(';'); continue; }
    if (c === '&' && s[i - 1] !== '>' && s[i - 1] !== '<' && s[i + 1] !== '>') { push('&'); continue; }
    cur += c;
  }
  push(null);
  return segs;
}
/** シェルの語（引用符とバックスラッシュを外す。$(…)・`…` は語の一部のまま）。spaced：引用の中に空白がある（文の引数） */
function cliWords(s) {
  const out = []; let w = ''; let on = false; let spaced = false;
  const end = () => { if (on) out.push({ w, spaced }); w = ''; on = false; spaced = false; };
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (/\s/.test(c)) { end(); continue; }
    on = true;
    if (c === "'") { const j = s.indexOf("'", i + 1); const e = j === -1 ? s.length : j; const part = s.slice(i + 1, e); if (/\s/.test(part)) spaced = true; w += part; i = e; continue; }
    if (c === '"') {
      let j = i + 1; let part = '';
      while (j < s.length && s[j] !== '"') {
        if (s[j] === '\\' && j + 1 < s.length) { part += s[j + 1]; j += 2; continue; }
        if (s[j] === '$' && s[j + 1] === '(') { const e = closeParen(s, j + 1); part += s.slice(j, e + 1); j = e + 1; continue; }   // 置き換えの中の空白は数えない
        if (/\s/.test(s[j])) spaced = true;
        part += s[j]; j++;
      }
      w += part; i = j; continue;
    }
    if (c === '\\' && i + 1 < s.length) { w += s[i + 1]; i++; continue; }
    if ((c === '$' || c === '<' || c === '>') && s[i + 1] === '(') { const e = closeParen(s, i + 1); w += s.slice(i, e + 1); i = e; continue; }
    if (c === '`') { const j = s.indexOf('`', i + 1); const e = j === -1 ? s.length : j; w += s.slice(i, e + 1); i = e; continue; }
    w += c;
  }
  end();
  return out;
}
/** グロブ（* ? [..]）の語が claude・codex に当たりうるか（決まった字が3字以上のときだけ） */
function cliGlobHits(base) {
  const lit = base.replace(/\[[^\]]*\]|[*?]/g, '');
  if (lit.length < 3) return false;
  let re = '';
  for (let i = 0; i < base.length; i++) {
    const c = base[i];
    if (c === '*') re += '.*'; else if (c === '?') re += '.';
    else if (c === '[') { const j = base.indexOf(']', i + 1); if (j === -1) { re += '\\['; continue; } re += '[' + base.slice(i + 1, j).replace(/^!/, '^').replace(/\\/g, '\\\\') + ']'; i = j; }
    else re += c.replace(/[.+^${}()|\\/]/g, '\\$&');
  }
  try { const r = new RegExp(`^${re}$`, 'i'); return [...AGENT_CLI_BASENAMES].some((n) => r.test(n)); } catch { return true; }
}
/** 語が claude・codex を指すか（パス・大文字・代入の値・選択肢の値・中括弧・グロブ） */
function isAgentCliWord(w0) {
  const w = w0.replace(/^[({!]+/, '').replace(/[)};]+$/, '');
  const cands = [w];
  const eq = w.indexOf('='); if (eq !== -1) cands.push(w.slice(eq + 1));   // 代入・選択肢・設定の値（C=claude・--pre=claude・core.pager=claude）
  return cands.some((x) => {
    const lw = x.toLowerCase();
    if (/@anthropic-ai\/claude-code|@openai\/codex|\/claude\/versions\//.test(lw)) return true;
    const base = lw.replace(/\/+$/, '').split('/').pop();
    if (AGENT_CLI_BASENAMES.has(base)) return true;
    if (/[{}]/.test(w0) && /claude|codex/i.test(x)) return true;
    if (/[*?[]/.test(base) && cliGlobHits(base)) return true;
    return false;
  });
}
/** 命令の位置の語（先頭と、包むコマンドの後の語。代入・( { ! と包むコマンドの選択肢を飛ばす）。語の名前（パスの最後の段・小文字）の配列 */
function cliCommandWords(ws) {
  const out = []; let k = 0;
  while (k < ws.length) {
    const w = ws[k].w.replace(/^[({!]+/, '');
    if (!w || /^[A-Za-z_][A-Za-z0-9_]*=/.test(w)) { k++; continue; }
    const b = w.split('/').pop().toLowerCase();
    out.push(b);
    if (!CLI_WRAPPERS.has(b)) break;
    k++;
    while (k < ws.length && (/^-/.test(ws[k].w) || /^[A-Za-z_][A-Za-z0-9_]*=/.test(ws[k].w) || /^\d+(\.\d+)?[smhd]?$/.test(ws[k].w))) k++;
  }
  return out;
}
/** 名前を扱うだけの、起動しない先頭か（先頭の前に代入があれば起動しうるとみなす） */
function cliSafeHead(ws) {
  let k = 0; while (k < ws.length && /^[({!]+$/.test(ws[k].w)) k++;
  const raw = (ws[k]?.w || '').replace(/^[({!]+/, '');
  if (!raw || /[=/$`]/.test(raw)) return false;
  const rest = ws.slice(k + 1).map((x) => x.w);
  if (CLI_SAFE_HEADS.has(raw)) return true;
  if (raw === 'rg') return !rest.some((x) => /^--pre(-glob)?(=|$)/.test(x));
  if (raw === 'find') return !rest.some((x) => /^-(exec|execdir|ok|okdir|delete|fprint|fprint0|fprintf|fls)$/.test(x));
  if (raw === 'git') return /^(log|diff|show|status|grep|ls-files|blame|branch|rev-parse|describe|shortlog)$/.test(rest[0] || '') && !rest.some((x) => /^(-O|--open-files-in-pager|--ext-diff$|--textconv$)/.test(x));
  if (raw === 'command') return /^-[vV]$/.test(rest[0] || '');
  return false;
}
/** コマンドの中の claude・codex の起動を探す。見つかれば理由を返す */
function judgeAgentCli(cmd, depth = 0) {
  if (depth > 6) return AGENT_CLI_TEXT.test(cmd) ? '入れ子が深すぎて決められない' : null;
  const { text, bodies } = cliHeredocs(cmd);
  const segs = cliSegments(text);
  const interpOf = (seg) => { const ws = cliWords(seg.raw); return cliCommandWords(ws).some((b) => CLI_INTERP.has(b)) || ws.some((x) => CLI_SHELLS.has(x.w.split('/').pop().toLowerCase())); };
  for (let i = 0; i < segs.length; i++) {
    const seg = segs[i];
    for (const sub of cliSubstitutions(seg.raw)) { const r = judgeAgentCli(sub, depth + 1); if (r) return r; }
    const ws = cliWords(seg.raw);
    const hit = ws.find((x) => !x.spaced && isAgentCliWord(x.w));
    const lead = []; for (const x of ws) { if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(x.w)) lead.push(x.w); else break; }
    const pipedToInterp = seg.sep === '|' && i + 1 < segs.length && interpOf(segs[i + 1]);
    const interp = interpOf(seg);
    const docs = [...seg.raw.matchAll(/<<HD(\d+)/g)].map((m) => bodies[Number(m[1])] || '');
    if (hit && !cliSafeHead(ws)) return `「${hit.w.slice(0, 60)}」の起動`;
    if (lead.some((x) => AGENT_CLI_TEXT.test(x.replace(/^[^=]*=/, '')))) return '環境変数の値の中の起動';
    if (hit && pipedToInterp) return 'シェルへのパイプで渡す起動';
    if ((interp || pipedToInterp) && AGENT_CLI_TEXT.test(seg.raw.replace(/<<HD\d+/g, ''))) return 'シェル・スクリプトの言語に渡す文字列の中の起動';
    if ((interp || pipedToInterp) && docs.some((d) => AGENT_CLI_TEXT.test(d))) return 'シェル・スクリプトの言語に渡すヒアドキュメントの中の起動';
    const first = (cliCommandWords(ws)[0] !== undefined) ? ws.find((x) => !/^[A-Za-z_][A-Za-z0-9_]*=/.test(x.w)) : null;
    if (first && /^[({!]*(\$\(|`)/.test(first.w) && AGENT_CLI_TEXT.test(seg.raw)) return '置き換えの結果をコマンドとして使う起動';
  }
  return null;
}

// ---- ツールごとの判定 -----------------------------------------------------

/** 作業員の閉じ込めの対象か（OBS-013②）。対象なら { root: 自分の worktree のルート, label } を返す */
function confinement(input, cwd) {
  const agentType = input.agent_type || null;
  const realCwd = realish(cwd);
  const inWorktreeDir = /\/\.claude\/worktrees\//.test(realCwd + '/');
  if (!(agentType === 'worker' || agentType === 'tester' || inWorktreeDir)) return null;
  const root = findRepoRoot(realCwd);
  const wtRoot = root && /\/\.claude\/worktrees\/[^/]+$/.test(root) ? root : inWorktreeDir ? realCwd.replace(/(\/\.claude\/worktrees\/[^/]+).*$/, '$1') : null;
  return { root: wtRoot ? realish(wtRoot) : null, label: agentType || 'worktree' };
}

/** p0.4.0：Kernel の停止（ADR-027）。Z3 の STOP の1行目（理由）を返す。STOP は Z3 にあり、エージェントは作れず消せない */
function kernelStop() {
  const f = path.join(Z3, 'STOP');
  if (!fs.existsSync(f)) return null;
  return (fs.readFileSync(f, 'utf8').split('\n')[0] || '理由なし').slice(0, 200);
}

function judge(input, projectDir, git) {
  const tool = input.tool_name || '';
  const ti = input.tool_input || {};
  const cwd = input.cwd || process.cwd();
  const agentType = input.agent_type || null;
  const confine = confinement(input, cwd);

  // p0.4.0：停止中は、読み取りのツール（Read・Glob・Grep）以外をすべて拒否する。読み取りも以下の通常の判定を通す。
  //   Bash は読み取り専用に見えても拒否する。文字列の照合では `sort -o`・`node -e` などの書き込みを見分けきれないため（Codex の指摘 #5）
  const stop = kernelStop();
  if (stop) {
    const readOnly = tool === 'Read' || tool === 'Glob' || tool === 'Grep';
    if (!readOnly) {
      return { target: tool === 'Bash' ? String(ti.command || '').slice(0, 200) : ti.file_path || null, decision: 'deny',
        reason: `Kernel の停止中（${stop}）。読み取り以外の操作はできない。再開はオーナーが kernel-resume.sh で行う` };
    }
  }

  const expandHome = (p) => (p && (p === '~' || p.startsWith('~/')) ? path.join(HOME, p.slice(1)) : p);
  const abs = (p) => (p ? path.resolve(cwd, expandHome(p)) : null);
  const absFromPattern = (p) => {
    if (!p) return null;
    const q = expandHome(String(p));
    if (!(q.startsWith('/') || q.startsWith('~'))) return null;
    const cut = q.search(/[*?[{]/);
    return path.resolve(cut === -1 ? q : q.slice(0, cut));
  };

  switch (tool) {
    case 'Agent':
    case 'Task': {
      // p0.4.10：作業員（worker）とテスト担当（tester）は、Kernel の起動の窓口（申請 merge-requests/launch/T-NNN.json）からだけ起動する。
      //   Agent ツールでの起動は、どの役割からも拒む（予算の台帳・承認・同時の数の照合を通らないため）。ほかのサブエージェントは今のまま許す
      const st = String(ti.subagent_type || '').trim().toLowerCase();
      if (st === 'worker' || st === 'tester') return { target: null, decision: 'deny', reason: `作業員（${st}）は Agent ツールでは起動できない。起動の窓口（merge-requests/launch/T-NNN.json に {"task":"T-NNN"} を置く）を使う` };
      return { target: null, decision: 'allow', reason: 'worker・tester 以外のサブエージェント' };
    }
    case 'Edit':
    case 'Write':
    case 'MultiEdit':
    case 'NotebookEdit': {
      const target = abs(ti.file_path || ti.notebook_path);
      if (!target) return { target, decision: 'allow', reason: '対象パスなし' };
      const why = judgeWritePath(target, projectDir, agentType, confine);
      if (why) return { target, decision: 'deny', reason: `${tool} の対象が保護パス（${why}）` };
      return { target, decision: 'allow', reason: '保護パス外への書き込み' };
    }
    case 'Read':
    case 'Glob':
    case 'Grep': {
      const candidates = [abs(ti.file_path || ti.path || cwd), absFromPattern(ti.pattern), absFromPattern(ti.glob)].filter(Boolean);
      for (const c of candidates) {
        if (isNoReadAbs(c)) return { target: c, decision: 'deny', reason: `${tool} の対象が読み取り禁止の保護パス（Z3 保護領域）` };
      }
      return { target: candidates[0] || null, decision: 'allow', reason: '読み取り' };
    }
    case 'Bash': {
      const cmd = String(ti.command || '');
      // p0.4.10：作業員・テスト担当を CLI で直接起動すること（claude … --agent worker|tester）も、起動の窓口を通らないので拒む（どの役割からも）
      if (/(^|[\s;&|(`$/'"])claude\b[^;&|\n]*\s--agent(\s+|=)\s*['"]?\s*(worker|tester)\b/i.test(cmd)) {
        return { target: cmd.slice(0, 200), decision: 'deny', reason: '作業員（worker・tester）を claude の CLI で直接起動できない。起動の窓口（merge-requests/launch/T-NNN.json）を使う' };
      }
      const r = judgeBash(cmd, git, agentType, cwd, projectDir, confine);
      // p0.4.16：ほかの規則が通したコマンドにだけ、claude・codex の CLI の起動の照合をかける（ほかの規則の拒否の理由は変えない）
      if (r.decision === 'allow') {
        const cli = judgeAgentCli(preprocessCommand(cmd));
        if (cli) return { target: cmd.slice(0, 200), decision: 'deny', reason: `Bash: AI の役割から claude・codex の CLI を起動できない（${cli}）。入れ子の起動はフック・証拠の記録・予算の台帳の外で動く。作業員は起動の窓口（merge-requests/launch/T-NNN.json）、司法は裁判所が起動する` };
      }
      return { target: cmd.slice(0, 200), ...r };
    }
    default:
      return { target: null, decision: 'allow', reason: '判定対象外のツール（記録のみ）' };
  }
}

// ---- 証拠ストア（追記専用・ハッシュチェーン・簡易ロック） --------------------

function sha256(s) {
  return 'sha256:' + crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

function lastLine(file) {
  if (!fs.existsSync(file)) return null;
  const size = fs.statSync(file).size;
  if (size === 0) return null;
  const fd = fs.openSync(file, 'r');
  try {
    const len = Math.min(size, 64 * 1024);
    const buf = Buffer.alloc(len);
    fs.readSync(fd, buf, 0, len, size - len);
    const text = buf.toString('utf8').replace(/\n+$/, '');
    const lines = text.split('\n');
    return lines[lines.length - 1];
  } finally {
    fs.closeSync(fd);
  }
}

function withLock(lockPath, fn) {
  const deadline = Date.now() + 3000;
  for (;;) {
    try {
      const fd = fs.openSync(lockPath, 'wx');
      try {
        return fn();
      } finally {
        fs.closeSync(fd);
        try { fs.unlinkSync(lockPath); } catch { /* ignore */ }
      }
    } catch (e) {
      if (e.code !== 'EEXIST' || Date.now() > deadline) throw e;
      try {
        const age = Date.now() - fs.statSync(lockPath).mtimeMs;
        if (age > 5000) { fs.unlinkSync(lockPath); continue; }
      } catch { /* 消えていれば次の試行で取れる */ }
      const until = Date.now() + 25;
      while (Date.now() < until) { /* spin */ }
    }
  }
}

function jstTimestamp(d = new Date()) {
  const t = new Date(d.getTime() + 9 * 60 * 60 * 1000);
  return t.toISOString().replace('Z', '+09:00');
}

function appendRecord(rec) {
  const dir = path.dirname(EVIDENCE);
  if (!fs.existsSync(dir)) {
    throw new Error(`証拠ストアのディレクトリがない: ${dir}（オーナーが作成する。作成されるまで fail-closed で全操作を拒否）`);
  }
  return withLock(EVIDENCE + '.lock', () => {
    const prev = lastLine(EVIDENCE);
    const prevHash = prev ? sha256(prev) : GENESIS;
    const n = prev ? (JSON.parse(prev).seq || 0) + 1 : 1;
    const full = { event_id: `evt-${String(n).padStart(6, '0')}`, seq: n, prev_hash: prevHash, ...rec };
    fs.appendFileSync(EVIDENCE, JSON.stringify(full) + '\n', { mode: 0o600 });
    return full;
  });
}

// ---- main -----------------------------------------------------------------

function baseRecord(input, git) {
  return {
    policy_version: POLICY_VERSION,
    hook_event: input.hook_event_name || 'PreToolUse',
    timestamp: jstTimestamp(),
    session_id: input.session_id || null,
    tool_use_id: input.tool_use_id || null,
    run_id: process.env.VGDD_RUN_ID || null,
    agent_id: input.agent_id || null,
    agent_type: input.agent_type || null,
    actor: { kind: 'agent', role: input.agent_type ? `executive:${input.agent_type}` : 'executive', model: process.env.VGDD_MODEL || 'unknown' },
    cwd: input.cwd || null,
    repo_root: git.repo_root,
    is_worktree: git.is_worktree,
    git_branch: git.branch,
    git_head: git.head,
    permission_mode: input.permission_mode || null,
  };
}

function main() {
  let input;
  try {
    input = JSON.parse(readStdin() || '{}');
  } catch (e) {
    process.stderr.write(`[VGDD] フック入力の JSON を解釈できない: ${e.message}\n`);
    process.exit(2);
  }
  const projectDir = process.env.CLAUDE_PROJECT_DIR || input.cwd || process.cwd();
  const cwd = input.cwd || process.cwd();
  const git = gitState(cwd);
  const event = input.hook_event_name || 'PreToolUse';

  // 実行後のイベント：結果を outcome として記録するだけ（判定はしない）
  if (event === 'PostToolUse' || event === 'PostToolUseFailure' || event === 'PermissionDenied') {
    const result = event === 'PostToolUse' ? 'success' : event === 'PostToolUseFailure' ? 'failure' : 'denied_by_classifier';
    const errText = input.error ? String(input.error).slice(0, 300) : input.reason ? String(input.reason).slice(0, 300) : null;
    const rec = {
      ...baseRecord(input, git),
      type: 'outcome',
      operation: input.tool_name || null,
      result,
      error: errText,
      duration_ms: typeof input.duration_ms === 'number' ? input.duration_ms : null,
    };
    try {
      appendRecord(rec);
    } catch (e) {
      process.stderr.write(`[VGDD] 結果を証拠ストアに記録できない: ${e.message}\n`);
      process.exit(2);
    }
    process.exit(0);
  }

  // PreToolUse：判定と記録
  // p0.4.15：Z3 の名前・配置と Kernel の設定を先に確かめる。決められなければ、すべての操作を拒否する（fail-closed。記録は残す）
  const conf = loadKernelConfig();
  const setupBad = conf.error || placementProblem(projectDir);
  if (!conf.error) KCONF = conf;
  const verdict = setupBad
    ? { target: null, decision: 'deny', reason: `Kernel の配置か設定を確かめられないため、すべての操作を拒否（fail-closed）：${setupBad}。オーナーが Z3 の名前・場所と kernel.config.json を直す` }
    : judge(input, projectDir, git);
  const rec = {
    ...baseRecord(input, git),
    type: 'tool_call',
    operation: input.tool_name || null,
    target: verdict.target,
    decision: verdict.decision,
    reason: verdict.reason,
  };
  try {
    appendRecord(rec);
  } catch (e) {
    process.stderr.write(`[VGDD] 証拠ストアに記録できないため操作を拒否（fail-closed）: ${e.message}\n`);
    process.exit(2);
  }
  if (verdict.decision === 'deny') {
    process.stderr.write(`[VGDD 拒否] ${verdict.reason}。この操作は Policy Engine（${POLICY_VERSION}）により止められ、証拠ストアに記録された。必要ならオーナーに依頼すること。\n`);
    process.exit(2);
  }
  process.exit(0);
}

try {
  main();
} catch (e) {
  process.stderr.write(`[VGDD] フック内部エラーのため操作を拒否（fail-closed）: ${e && e.stack ? e.stack : e}\n`);
  process.exit(2);
}
