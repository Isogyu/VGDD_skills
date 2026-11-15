#!/usr/bin/env node
// VGDD Governance Kernel — 導入の道具（法律 p0.4.16、SPEC §11-移植・設定の照合。オーナーが sandbox の外で実行する。依存なし、Node 22 以上）
//
// 元の案件（Z3 = ~/tsubuyaki-z3、リポジトリ = ~/tsubuyaki-worklog/app）と違う場所・違う名前に Kernel を置くための道具。
// この道具は Kernel の強制の経路に入らない（フック・裁判所・夜間の代行はこのファイルを読まない）。配置の結果は、適合性テストの ST16 と
// 群 P が、この道具とは別に実装した規則で確かめる（この道具の誤りが、そのまま合格にならないように）。
//
// 使い方:
//   node vgdd-setup.mjs render-settings --repo <repo> --z3 <z3> [--law <vgdd>]
//       原本 vgdd/settings.v2.json の元の案件のパスを、指定の場所に置き換えた設定を標準出力に出す。
//       文字列の一括置換ではなく、設定の構造を読んで、パスを持つ項目（権限の規則・additionalDirectories・sandbox の一覧・フックのコマンド）だけを書き換える。
//       置き換えられなかった元の案件の名前（tsubuyaki）が残れば失敗する（終了 65）
//   node vgdd-setup.mjs install --repo <repo> --z3 <z3> [--dry-run] [--law <vgdd>]
//       Z3 に hooks/・bin/・evidence/ を作って法律の写し（フック・スクリプト）を置き、Z3 の権限を 0700 にする。
//       リポジトリに .claude/settings.json（render-settings の出力）と .claude/agents/ を置く。
//       既にあるファイルは上書きしない：中身が違うファイルが1つでもあれば、一覧を出して何も書かずに止まる（終了 1。--force はない）。
//       git の設定の基準値（git-baseline.sh）・予算の上限・起動は、実行せずに次の手順として出す
//   node vgdd-setup.mjs doctor --repo <repo> --z3 <z3> [--law <vgdd>] [--json]
//       docs/adoption.md §4 の確認の表を機械で確かめる。**診断は表示用で、合格しても Kernel が正しく動く証明ではない**。
//       確かめられない項目は「確かめられない」、注意（既定の保護を外す設定・ありふれた名前の先頭）は「注意」と出し、どちらも合格に数えない。
//       終了コード 0＝全部合格、1＝不合格あり、2＝確かめられない・注意の項目あり。配置と Kernel の設定の検査は、配置したフックを実際に起動して確かめる
//       p0.4.16：配置済みの設定の厳しさ（sandbox の節は原本の項目だけ、フックを止める項目がない）と、上の層の設定（<repo>/.claude/settings.local.json、
//       ~/.claude/settings.json・settings.local.json）を、適合性テストの ST16〜ST16c と同じ部品 settings-check.mjs で確かめる（規則を2つに書かない）
//
// 規則（フック policy.mjs と同じものを写して持つ。変えるときは両方を変える）：
//   ・Z3 の名前は英数字と . _ - だけ（先頭は英数字）、4 文字以上、ありふれた名前でない
//   ・Z3 とリポジトリは入れ子にしない。設定のパスは ~/ の形で書くので、どちらもホームの下に置く（ホームの外の配置は扱わない）
//   ・--law の既定：この道具が原本（<vgdd>/scripts/）にあればその <vgdd>、そうでなければ <repo>/vgdd

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { projectProblems, checkUpperLayers } from './settings-check.mjs';   // p0.4.16：設定の層の検査（適合性テストと同じ部品）

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ORIG = { z3: '~/tsubuyaki-z3', repo: '~/tsubuyaki-worklog/app', repoParent: '~/tsubuyaki-worklog', hook: 'node ~/tsubuyaki-z3/hooks/policy.mjs' };
const RESIDUE = /tsubuyaki/;
const HOOK_EVENTS = ['PreToolUse', 'PostToolUse', 'PostToolUseFailure', 'PermissionDenied'];
const REQUIRED_CMDS = ['git', 'jq', 'node', 'npm', 'shasum', 'python3', 'sandbox-exec', 'perl', 'claude', 'codex'];
const NODE_MIN = 22;

// ---- 名前と配置の規則（policy.mjs の z3NameProblem・placementProblem と同じ） ------------------------------
const Z3_NAME_MIN = 4;
const Z3_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const Z3_COMMON_NAMES = new Set(['z3', 'tmp', 'temp', 'home', 'data', 'var', 'etc', 'opt', 'usr', 'bin', 'lib', 'src', 'app', 'apps', 'test', 'tests', 'doc', 'docs',
  'work', 'root', 'users', 'library', 'desktop', 'documents', 'downloads', 'applications', 'private', 'volumes', 'system', 'public', 'evidence', 'hooks', 'kernel',
  'vgdd', 'backup', 'config', 'node_modules']);
export function z3NameProblem(name) {
  if (typeof name !== 'string' || !Z3_NAME_RE.test(name)) return 'Z3 の名前に使えない文字がある（英数字と . _ - だけ。先頭は英数字）';
  if (name.length < Z3_NAME_MIN) return `Z3 の名前が短すぎる（${Z3_NAME_MIN} 文字以上）`;
  if (Z3_COMMON_NAMES.has(name.toLowerCase())) return 'Z3 の名前がありふれている（照合が広すぎるか狭すぎる）';
  return null;
}
function realish(p) {
  const abs = path.resolve(p);
  try { return fs.realpathSync(abs); } catch { /* まだない */ }
  const parts = []; let dir = abs;
  for (let i = 0; i < 64; i++) {
    parts.unshift(path.basename(dir)); const parent = path.dirname(dir); if (parent === dir) break; dir = parent;
    try { return path.join(fs.realpathSync(dir), ...parts); } catch { /* さらに上へ */ }
  }
  return abs;
}
const isInside = (t, d) => { const r = path.relative(d, t); return r === '' || (!r.startsWith('..') && !path.isAbsolute(r)); };
function homeDirs() { const h = os.homedir(); return [...new Set([path.resolve(h), realish(h)])]; }
/** ホームの下なら ~/… の形（ホームそのものは ~）。外なら null */
function tildeOf(abs) {
  for (const h of homeDirs()) for (const p of [path.resolve(abs), realish(abs)]) {
    if (isInside(p, h)) { const rel = path.relative(h, p).split(path.sep).join('/'); return rel ? `~/${rel}` : '~'; }
  }
  return null;
}
/** 配置の問題（名前・入れ子・ホームの外）。なければ null */
// p0.4.15 の審査（M2・m3・m4・m6）：ホームからの相対の全部の段を英数字と . _ - に限る（シェルの注入・権限の規則の形の崩れを塞ぐ）。
//   Z3 はホームから 2 段まで（フックと同じ）。実体（リンクの先）もホームの下。Z3 の名前とリポジトリの段の名前が互いに前置なら拒む（止めすぎるため）
const Z3_MAX_DEPTH = 2;
const PATH_SEG_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
/** ホームからの相対の段の配列（設定の場所と実体の両方がホームの下のときだけ）。外なら null */
function homeSegs(p) {
  const t = tildeOf(p);
  if (!t || t === '~') return null;
  const realOk = homeDirs().some((h) => isInside(realish(p), h));
  return realOk ? t.slice(2).split('/') : null;
}
export function placementProblem(repo, z3) {
  for (const n of new Set([path.basename(path.resolve(z3)), path.basename(realish(z3))])) { const p = z3NameProblem(n); if (p) return p; }
  const zs = homeSegs(z3); const rs = homeSegs(repo);
  if (!zs || !rs) return 'Z3 かリポジトリ（またはその実体）がホームの外にあるか、ホームそのもの（設定のパスは ~/ の形で書くので、ホームの外の配置は扱わない）';
  if (![...zs, ...rs].every((x) => PATH_SEG_RE.test(x))) return 'Z3 かリポジトリの場所の段に使えない文字がある（英数字と . _ - だけ。先頭は英数字。. と .. は不可）';
  if (zs.length > Z3_MAX_DEPTH) return `Z3 がホームから ${Z3_MAX_DEPTH} 段より深い`;
  const z = realish(z3); const r = realish(repo);
  if (isInside(z, r)) return 'Z3 がリポジトリの中にある';
  if (isInside(r, z)) return 'リポジトリが Z3 の中にある';
  const name = zs[zs.length - 1];
  const clash = rs.find((x) => x.startsWith(name) || name.startsWith(x));
  if (clash) return `Z3 の名前とリポジトリの場所の段の名前（${clash}）が互いに前置になっている（フックの照合が正当な操作を止めすぎる）`;
  return null;
}
// Z3 の名前の先頭4字がありふれた語と重なると、フックのグロブの疑いが正当な操作を止めやすい（拒まずに注意を出す。doctor は合格に数えない）
const COMMON_PREFIX4 = new Set(['node', 'test', 'docs', 'kern', 'conf', 'data', 'temp', 'work', 'home', 'user', 'util', 'pack', 'buil', 'dist', 'publ', 'scri', 'serv',
  'core', 'main', 'tool', 'vend', 'libr', 'priv', 'appl', 'desk', 'down', 'musi', 'pict', 'movi', 'tmp-', 'src-', 'lib-', 'app-', 'bin-', 'doc-', 'git-']);
export function namePrefixWarning(z3) {
  const p = path.basename(path.resolve(z3)).slice(0, 4).toLowerCase();
  return COMMON_PREFIX4.has(p) ? `Z3 の名前の先頭4字（${p}）がありふれた語と重なる。フックが ~/${p}… などの正当な操作を止めやすい` : null;
}

// ---- render-settings ---------------------------------------------------------------------------------
/** 原本の設定を、指定の場所に合わせて書き換える。返り値 { settings } か { error } */
export function renderSettings(orig, repo, z3) {
  const bad = placementProblem(repo, z3);
  if (bad) return { error: bad };
  const t = { z3: tildeOf(z3), repo: tildeOf(repo), repoParent: tildeOf(path.dirname(path.resolve(repo))) };
  const mapPath = (s) => {
    for (const [k, to] of [['z3', t.z3], ['repo', t.repo], ['repoParent', t.repoParent]]) {
      const from = ORIG[k];
      if (s === from || s.startsWith(from + '/')) return to + s.slice(from.length);
    }
    return s;
  };
  const mapRule = (s) => { const m = /^([A-Za-z]+)\((.*)\)$/s.exec(s); return m ? `${m[1]}(${mapPath(m[2])})` : s; };
  const out = JSON.parse(JSON.stringify(orig));
  const touched = new Set();   // 書き換えの対象として見た葉（置き換えの後の文字列）
  const mapArr = (arr, fn) => Array.isArray(arr) ? arr.map((x) => { if (typeof x !== 'string') return x; const y = fn(x); touched.add(y); return y; }) : arr;
  if (out.permissions) for (const k of ['additionalDirectories', 'deny', 'ask', 'allow']) {
    if (k in out.permissions) out.permissions[k] = mapArr(out.permissions[k], k === 'additionalDirectories' ? mapPath : mapRule);
  }
  const fsx = out.sandbox?.filesystem;
  if (fsx && typeof fsx === 'object') for (const k of Object.keys(fsx)) if (Array.isArray(fsx[k])) fsx[k] = mapArr(fsx[k], mapPath);
  const z3IsDefault = t.z3 === ORIG.z3;
  const rel = t.z3.slice(2);
  const hookCmd = z3IsDefault ? ORIG.hook : `VGDD_Z3_DIR="$HOME/${rel}" node "$HOME/${rel}/hooks/policy.mjs"`;
  for (const ev of Object.keys(out.hooks || {})) {
    for (const m of out.hooks[ev] || []) for (const h of m.hooks || []) {
      if (typeof h.command !== 'string') continue;
      if (h.command !== ORIG.hook) return { error: `フックのコマンドの形が原本の想定と違う（${ev}）` };
      h.command = hookCmd; touched.add(hookCmd);
    }
  }
  // 置き換えられなかった元の案件の名前が残れば失敗（書き換えの対象の葉は、指定の場所そのものが名前を含むときだけ許す）
  const leftovers = [];
  const walk = (x, at) => {
    if (typeof x === 'string') { if (RESIDUE.test(x) && !(touched.has(x) && !RESIDUE.test(x.replace(t.z3, '').replace(t.repo, '').replace(t.repoParent, '')))) leftovers.push(at); return; }
    if (Array.isArray(x)) x.forEach((y, i) => walk(y, `${at}[${i}]`));
    else if (x && typeof x === 'object') for (const [k, v] of Object.entries(x)) { if (RESIDUE.test(k)) leftovers.push(`${at}.${k}（キー）`); walk(v, `${at}.${k}`); }
  };
  walk(out, '$');
  if (leftovers.length) return { error: `元の案件の名前が残った：${leftovers.slice(0, 5).join(', ')}` };
  return { settings: out };
}

// ---- 共通 ---------------------------------------------------------------------------------------------
function parseArgs(argv) {
  const o = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--dry-run' || a === '--json') o[a.slice(2)] = true;
    else if (['--repo', '--z3', '--law'].includes(a)) { if (i + 1 >= argv.length) throw new Error(`${a} に値がない`); o[a.slice(2)] = argv[++i]; }
    else if (a.startsWith('--')) throw new Error(`不明な引数: ${a}`);
    else o._.push(a);
  }
  return o;
}
function lawDirOf(o) {
  if (o.law) return path.resolve(o.law);
  const own = path.resolve(HERE, '..');
  if (fs.existsSync(path.join(own, 'scripts', 'vgdd-setup.mjs')) && fs.existsSync(path.join(own, 'hooks', 'policy.mjs'))) return own;
  return path.join(path.resolve(o.repo), 'vgdd');
}
const readText = (f) => { try { return fs.readFileSync(f, 'utf8'); } catch { return null; } };
/** 法律の写しの一覧：[配置先, 原本, 実行の権限が要るか] */
function lawFiles(law, repo, z3) {
  const list = [];
  for (const f of ['policy.mjs', 'verify-chain.mjs']) list.push([path.join(z3, 'hooks', f), path.join(law, 'hooks', f), false]);
  for (const f of fs.readdirSync(path.join(law, 'scripts')).sort()) {
    const src = path.join(law, 'scripts', f);
    if (fs.lstatSync(src).isFile()) list.push([path.join(z3, 'bin', f), src, true]);
  }
  for (const f of fs.readdirSync(path.join(law, 'agents')).sort()) {
    const src = path.join(law, 'agents', f);
    if (f.endsWith('.md') && fs.lstatSync(src).isFile()) list.push([path.join(repo, '.claude', 'agents', f), src, false]);
  }
  return list;
}

// ---- install ------------------------------------------------------------------------------------------
function install(o) {
  const repo = path.resolve(o.repo); const z3 = path.resolve(o.z3); const law = lawDirOf(o);
  const bad = placementProblem(repo, z3);
  if (bad) { console.error(`✗ 配置を拒否：${bad}`); return 65; }
  if (!fs.existsSync(path.join(repo, '.git'))) { console.error('✗ --repo が git のリポジトリでない（.git がない）'); return 65; }
  const orig = JSON.parse(fs.readFileSync(path.join(law, 'settings.v2.json'), 'utf8'));
  const r = renderSettings(orig, repo, z3);
  if (r.error) { console.error(`✗ 設定を作れない：${r.error}`); return 65; }
  const plan = lawFiles(law, repo, z3).map(([to, from, exec]) => ({ to, text: fs.readFileSync(from, 'utf8'), mode: exec ? 0o755 : 0o644 }));
  plan.push({ to: path.join(repo, '.claude', 'settings.json'), text: JSON.stringify(r.settings, null, 2) + '\n', mode: 0o644 });
  const dirs = [z3, path.join(z3, 'hooks'), path.join(z3, 'bin'), path.join(z3, 'evidence'), path.join(z3, 'evidence', 'verdicts'), path.join(repo, '.claude'), path.join(repo, '.claude', 'agents')];
  // 既にあるファイルは上書きしない。違いがあれば一覧を出して止まる（何も書かない）
  const conflicts = []; const same = []; const create = [];
  for (const p of plan) {
    let st = null; try { st = fs.lstatSync(p.to); } catch { /* ない */ }
    if (!st) { create.push(p); continue; }
    if (!st.isFile()) { conflicts.push(`${p.to}（ファイルでない）`); continue; }
    (readText(p.to) === p.text ? same : conflicts).push(p.to === undefined ? p : p.to);
  }
  for (const d of dirs) { try { const st = fs.lstatSync(d); if (!st.isDirectory()) conflicts.push(`${d}（フォルダでない）`); } catch { /* 作る */ } }
  // 審査 m6：書く前に全部の書き先を確かめる。実体（記号リンクの先）がホームの下でなければ書かない
  const homes = homeDirs();
  for (const t of [...dirs, ...plan.map((p) => p.to)]) if (!homes.some((h) => isInside(realish(t), h))) conflicts.push(`${t}（実体がホームの外）`);
  if (conflicts.length) {
    console.error(`✗ 既にあるファイル ${conflicts.length} 件が、置くものと違う。上書きしないので、何も書かずに止める（オーナーが確かめて、直すか消してからやり直す）：`);
    for (const c of conflicts) console.error(`  - ${c}`);
    return 1;
  }
  const tag = o['dry-run'] ? '（dry-run。何も書かない）' : '';
  console.log(`VGDD の導入${tag}：Z3 = ${z3}、リポジトリ = ${repo}、法律の原本 = ${law}`);
  console.log(`  作る ${create.length} 件、同じなので触らない ${same.length} 件`);
  for (const p of create) console.log(`  + ${p.to}`);
  if (!o['dry-run']) {
    // 審査 m6：Z3 を作った直後に 0700 にする。途中で失敗したら、この実行が作ったものの一覧を出して止める（自動では消さない。オーナーが確かめて消す）
    const made = [];
    try {
      if (!fs.existsSync(z3)) { fs.mkdirSync(z3, { recursive: true, mode: 0o700 }); made.push(z3); }
      fs.chmodSync(z3, 0o700);
      for (const d of dirs.slice(1)) if (!fs.existsSync(d)) { fs.mkdirSync(d, { recursive: true }); made.push(d); }
      for (const p of create) { fs.writeFileSync(p.to, p.text, { flag: 'wx', mode: p.mode }); made.push(p.to); }   // wx：作る間に別の誰かが置いたものも上書きしない
    } catch (e) {
      console.error(`✗ 途中で失敗した（${e && e.code ? e.code : e}）。この実行が作った ${made.length} 件は消さずに残している。オーナーが確かめて消してから、やり直す：`);
      for (const m of made) console.error(`  - ${m}`);
      return 70;
    }
    console.log(`  Z3 の権限を 0700 にした`);
  } else console.log(`  Z3 の権限を 0700 にする`);
  const warn = namePrefixWarning(z3);
  if (warn) console.log(`  注意：${warn}`);
  const env = `VGDD_Z3_DIR=${z3}`;
  console.log(`\n次の手順（この道具は実行しない。オーナーが sandbox の外で確かめながら行う）：
  1. .git/config を確かめてから、git の設定の基準値を作る：${env} ${z3}/bin/git-baseline.sh --repo ${repo}
  2. 予算の上限を置く：${env} ${z3}/bin/budget-set.sh …（引数は budget-set.sh の頭書き）
  3. 診断を見る（表示用。合格は正しく動く証明ではない）：node ${path.join(law, 'scripts', 'vgdd-setup.mjs')} doctor --repo ${repo} --z3 ${z3}
  4. 適合性テストを、配置した写しで動かす：${env} node ${path.join(law, 'conformance', 'run.mjs')} --impl z3 --repo ${repo} --z3-name ${path.basename(z3)}
  5. 裁判所と起動の窓口を起こす：${env} ${z3}/bin/gate-runner.sh --repo ${repo}、${env} ${z3}/bin/launcher.sh --repo ${repo}
  6. Claude Code を ${repo} で起動し、フックが動くこと・停止と再開・迂回の検証（docs/vgdd-status.md の V6・V7）を実際のセッションで確かめる`);
  return 0;
}

// ---- doctor -------------------------------------------------------------------------------------------
function onPath(cmd) {
  for (const d of (process.env.PATH || '').split(':').filter(Boolean)) {
    try { const st = fs.statSync(path.join(d, cmd)); if (st.isFile() && (st.mode & 0o111)) return true; } catch { /* ない */ }
  }
  return false;
}
function doctor(o) {
  const repo = path.resolve(o.repo); const z3 = path.resolve(o.z3); const law = lawDirOf(o);
  const checks = [];
  const add = (id, title, status, detail = '') => checks.push({ id, title, status, detail });
  const pf = (b) => (b ? 'pass' : 'fail');
  add('os', 'OS が macOS（Darwin）', pf(process.platform === 'darwin'), process.platform);
  const missing = REQUIRED_CMDS.filter((c) => !onPath(c));
  add('commands', `必須のコマンドが PATH にある（${REQUIRED_CMDS.join('・')}。実行はしない）`, pf(missing.length === 0), missing.length ? `ない：${missing.join(',')}` : '');
  const major = Number(process.versions.node.split('.')[0]);
  add('node', `Node.js が ${NODE_MIN} 以上`, pf(major >= NODE_MIN), process.versions.node);
  const place = placementProblem(repo, z3);
  add('placement', 'Z3 の名前が使える形で、Z3 とリポジトリが入れ子でなく、どちらもホームの下', pf(!place), place || '');
  add('repo-git', 'リポジトリが git のリポジトリ', pf(fs.existsSync(path.join(repo, '.git'))));
  // Z3 の権限
  let zst = null; let zerr = null;
  try { zst = fs.lstatSync(z3); } catch (e) { zerr = e; }
  if (zst) add('z3-mode', 'Z3 がフォルダで、権限が 0700、持ち主が自分', pf(zst.isDirectory() && (zst.mode & 0o777) === 0o700 && (typeof process.getuid !== 'function' || zst.uid === process.getuid())), `mode=${(zst.mode & 0o777).toString(8)}`);
  else add('z3-mode', 'Z3 がフォルダで、権限が 0700、持ち主が自分', zerr && zerr.code === 'ENOENT' ? 'fail' : 'unverifiable', zerr ? zerr.code : '');
  add('z3-evidence', 'Z3 に証拠ストアの置き場所（evidence/）がある', pf(fs.existsSync(path.join(z3, 'evidence'))));
  // 審査 m5⑤：配置と Kernel の設定の検査は、配置したフックそのものに任せる（同じ検査を2つ書かない）。証拠の記録は一時ファイルに書く
  const hookFile = path.join(z3, 'hooks', 'policy.mjs');
  if (fs.existsSync(hookFile)) {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vgdd-doctor-'));
    const r = spawnSync(process.execPath, [hookFile], { input: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'doctor', tool_use_id: 'doctor', tool_name: 'Read', tool_input: { file_path: path.join(repo, '.git', 'HEAD') }, cwd: repo }),
      env: { ...process.env, VGDD_Z3_DIR: z3, CLAUDE_PROJECT_DIR: repo, VGDD_EVIDENCE_PATH: path.join(tmp, 'tool_calls.jsonl') }, encoding: 'utf8', timeout: 15000 });
    fs.rmSync(tmp, { recursive: true, force: true });
    const why = (/すべての操作を拒否（fail-closed）：([^。]*)/.exec(r.stderr || '') || [])[1];
    add('hook-selfcheck', '配置したフックが、この Z3 とリポジトリで起動の時点の検査（名前・場所・Kernel の設定）を通る（普通の Read が通る）', pf(r.status === 0), r.status === 0 ? '' : why || `終了 ${r.status}`);
  } else add('hook-selfcheck', '配置したフックが起動の時点の検査を通る', 'fail', 'フックがない');
  // Kernel の設定（中身は出さない）。形の検査はフック（上）が行う。ここでは読み取り専用の一覧と、既定の保護を外していないかだけを見る
  const kc = path.join(z3, 'kernel.config.json');
  let ro = ['../preparation', '../event_records'];
  let kj = null; try { kj = fs.lstatSync(kc).isFile() ? JSON.parse(fs.readFileSync(kc, 'utf8')) : null; } catch { kj = null; }
  if (kj && Array.isArray(kj.readonly_dirs)) { ro = kj.readonly_dirs; add('kernel-config-replace', 'Kernel の設定が readonly_dirs で既定の保護（準備資料・作業記録）を外している', 'warn', `読み取り専用 ${ro.length} 件（既定を置き換え）`); }
  else if (kj && Array.isArray(kj.extra_readonly_dirs)) ro = [...new Set([...ro, ...kj.extra_readonly_dirs])];
  const pw = namePrefixWarning(z3);
  if (pw) add('name-prefix', 'Z3 の名前の先頭4字がありふれた語と重ならない', 'warn', pw);
  // 設定
  const sp = path.join(repo, '.claude', 'settings.json');
  let dep = null; let depText = readText(sp);
  try { dep = depText === null ? null : JSON.parse(depText); } catch { dep = null; }
  add('settings', '配置済みの設定（.claude/settings.json）を JSON として読める', pf(!!dep), depText === null ? 'ない' : dep ? '' : 'JSON でない');
  let orig = null; try { orig = JSON.parse(fs.readFileSync(path.join(law, 'settings.v2.json'), 'utf8')); } catch { orig = null; }
  const rr = orig && !place ? renderSettings(orig, repo, z3) : { error: orig ? place : '原本を読めない' };
  if (dep) {
    const hooks = dep.hooks || {};
    const cmds = HOOK_EVENTS.flatMap((e) => (hooks[e] || []).flatMap((m) => (m.hooks || []).map((h) => h)));
    add('hooks', `フックが4つの出来事（${HOOK_EVENTS.join('・')}）に登録されている`, pf(HOOK_EVENTS.every((e) => (hooks[e] || []).some((m) => (m.hooks || []).length > 0))));
    add('hooks-block', 'フックがすべて onFailure: block', pf(cmds.length > 0 && Object.values(hooks).flat().flatMap((m) => m.hooks || []).every((h) => h.onFailure === 'block')));
    const want = rr.settings ? rr.settings.hooks?.PreToolUse?.[0]?.hooks?.[0]?.command : null;
    add('hooks-z3', '自分の Z3 のフック（<z3>/hooks/policy.mjs）を、その Z3 で起動する', want ? pf(cmds.length > 0 && cmds.every((h) => h.command === want)) : 'unverifiable', want ? '' : (rr.error || ''));
    const sb = dep.sandbox || {};
    add('sandbox', 'sandbox が [enabled, failIfUnavailable, allowUnsandboxedCommands] = [true, true, false]', pf(sb.enabled === true && sb.failIfUnavailable === true && sb.allowUnsandboxedCommands === false));
    const dw = sb.filesystem?.denyWrite || []; const dr = sb.filesystem?.denyRead || []; const deny = dep.permissions?.deny || [];
    const zt = tildeOf(z3);
    const core = ['vgdd', 'CLAUDE.md', '.claude/settings.json', 'docs/governance', 'docs/tasks/_board.json', 'merge-requests/launch'];
    const lackW = [zt, ...core, ...ro].filter((x) => !x || !dw.includes(x));
    add('deny-write', '書き込みの禁止（sandbox の denyWrite）に、自分の Z3・統治の核・Kernel の設定の読み取り専用の領域が入っている', pf(lackW.length === 0), lackW.length ? `欠け ${lackW.length} 件` : '');
    const lackR = [zt, '.env.local'].filter((x) => !x || !dr.includes(x));
    add('deny-read', '読み取りの禁止（sandbox の denyRead）に、自分の Z3 と .env.local が入っている', pf(lackR.length === 0), lackR.length ? `欠け ${lackR.length} 件` : '');
    const lackP = zt ? ['Read', 'Edit', 'Write'].map((k) => `${k}(${zt}/**)`).filter((x) => !deny.includes(x)) : ['Z3'];
    add('deny-rules', '権限の規則（permissions.deny）に、自分の Z3 の Read・Edit・Write の拒否が入っている', pf(lackP.length === 0), lackP.join(','));
    // 元の案件のパスの残り（指定の場所そのものの表記を除いて）
    let rest = depText;
    for (const x of [zt, tildeOf(repo), tildeOf(path.dirname(repo)), `$HOME/${(zt || '').slice(2)}`]) if (x) rest = rest.split(x).join('');
    add('residue', '元の案件のパス（tsubuyaki）が残っていない（指定の場所の表記を除く）', pf(!RESIDUE.test(rest)));
    // 原本との一致（ST16 と同じ項目と厳しさ）
    if (rr.settings) {
      const v2 = rr.settings;
      const lack = (sel) => (sel(v2) || []).filter((x) => !(sel(dep) || []).includes(x));
      const flags = ['enabled', 'failIfUnavailable', 'allowUnsandboxedCommands'].filter((k) => (v2.sandbox || {})[k] !== (dep.sandbox || {})[k]);
      const canon = (x) => Array.isArray(x) ? x.map(canon) : (x && typeof x === 'object') ? Object.fromEntries(Object.keys(x).sort().map((k) => [k, canon(x[k])])) : x;
      const lacks = [...lack((s) => s.permissions?.deny), ...lack((s) => s.sandbox?.filesystem?.denyWrite), ...lack((s) => s.sandbox?.filesystem?.denyRead), ...flags];
      const hs = JSON.stringify(canon(dep.hooks)) === JSON.stringify(canon(v2.hooks));
      add('settings-match', '配置済みの設定が、原本をこの場所に合わせて書き換えたもの（render-settings）の拒否の規則・禁止の一覧をすべて含み、sandbox の3つの値とフックの構造が同じ', pf(lacks.length === 0 && hs), `欠け ${lacks.length} 件 hooks=${hs ? '同じ' : '違う'}`);
    } else add('settings-match', '配置済みの設定と原本の一致', 'unverifiable', rr.error || '');
    // p0.4.16：配置済みの設定の厳しさ（ST16 と同じ部品）。注意（フックに効きうる env）は合格に数えない
    if (rr.settings) {
      const pp = projectProblems(rr.settings, dep);
      add('settings-strict', '配置済みの設定の sandbox の節が原本にある項目だけで（excludedCommands・allowRead・allowWrite・disabled・enableWeaker* などがない。宛先は原本の部分集合）、フックを止める項目（disableAllHooks など）がない',
        pp.fail.length ? 'fail' : pp.warn.length ? 'warn' : 'pass', [...pp.fail, ...pp.warn].slice(0, 4).join('・'));
    } else add('settings-strict', '配置済みの設定の厳しさ', 'unverifiable', rr.error || '');
  }
  // p0.4.16：上の層の設定（値の設定は上の層が勝つ）。ファイルがなければ合格、読めなければ不合格。弱めるかを決められない項目は注意（合格に数えない）
  if (rr.settings) {
    const layers = checkUpperLayers({ repo, home: os.homedir(), want: rr.settings });
    const LABEL = { 'project-local': '<repo>/.claude/settings.local.json', user: '~/.claude/settings.json', 'user-local': '~/.claude/settings.local.json' };
    const nf = layers.flatMap((l) => l.fail.map((x) => `${LABEL[l.kind]}：${x}`)); const nw = layers.flatMap((l) => l.warn.map((x) => `${LABEL[l.kind]}：${x}`));
    add('settings-layers', `上の層の設定（${Object.values(LABEL).join('・')}）に、Kernel の保護を弱める値がない（ファイルがなければ合格。管理者の設定・起動の引数・環境変数は見られない）`,
      nf.length ? 'fail' : nw.length ? 'warn' : 'pass', [...nf, ...nw].slice(0, 4).join(' / ') || `あるファイル ${layers.filter((l) => l.present).length} 件`);
  } else add('settings-layers', '上の層の設定に、Kernel の保護を弱める値がない', 'unverifiable', rr.error || '');
  // 原本と配置済みの写しの一致
  let files = null; try { files = lawFiles(law, repo, z3); } catch { files = null; }
  if (files) {
    const diff = files.filter(([to, from]) => readText(to) !== readText(from)).map(([to]) => path.relative(path.dirname(z3), to));
    const agentsDiff = diff.filter((d) => !d.startsWith(path.basename(z3) + path.sep));
    add('law-copy', 'フック・スクリプト（<z3>/hooks・<z3>/bin）が法律の原本と同じ', pf(diff.length === agentsDiff.length), `違う ${diff.length - agentsDiff.length} 件`);
    add('agents-copy', 'エージェントの定義（.claude/agents）が原本と同じ', pf(agentsDiff.length === 0), `違う ${agentsDiff.length} 件`);
  } else add('law-copy', 'フック・スクリプトが法律の原本と同じ', 'unverifiable', `法律の原本（${law}）を読めない`);
  const nFail = checks.filter((c) => c.status === 'fail').length; const nUnv = checks.filter((c) => c.status === 'unverifiable').length;
  const nWarn = checks.filter((c) => c.status === 'warn').length;
  const code = nFail ? 1 : nUnv || nWarn ? 2 : 0;   // 注意（warn）は合格に数えない（終了 2）
  const notice = 'この診断は表示用です。合格しても Kernel が正しく動く証明ではありません（実際のフックの起動・sandbox の阻止・裁判所と司法の動作は確かめていない。適合性テストと実際のセッションで確かめる）';
  if (o.json) process.stdout.write(JSON.stringify({ schema: 'vgdd.doctor.v1', checks, fail: nFail, unverifiable: nUnv, warn: nWarn, exit: code, notice }, null, 2) + '\n');
  else {
    console.log(`VGDD の導入の診断：Z3 = ${z3}、リポジトリ = ${repo}`);
    for (const c of checks) console.log(`${c.status === 'pass' ? '✓' : c.status === 'fail' ? '✗' : c.status === 'warn' ? '!' : '?'} ${c.title}${c.status === 'unverifiable' ? '（確かめられない。合格に数えない）' : c.status === 'warn' ? '（注意。合格に数えない）' : ''}${c.detail ? `  — ${c.detail}` : ''}`);
    console.log(`\n合格 ${checks.length - nFail - nUnv - nWarn}・不合格 ${nFail}・確かめられない ${nUnv}・注意 ${nWarn}（全 ${checks.length} 項目）`);
    console.log(notice);
  }
  return code;
}

// ---- 本体 ---------------------------------------------------------------------------------------------
const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  let o;
  try { o = parseArgs(process.argv.slice(2)); } catch (e) { console.error(e.message); process.exit(64); }
  const cmd = o._[0];
  if (!['render-settings', 'install', 'doctor'].includes(cmd) || !o.repo || !o.z3) {
    console.error('使い方: vgdd-setup.mjs render-settings|install|doctor --repo <repo> --z3 <z3> [--dry-run] [--json] [--law <vgdd>]');
    process.exit(64);
  }
  try {
    if (cmd === 'render-settings') {
      const law = lawDirOf(o);
      const r = renderSettings(JSON.parse(fs.readFileSync(path.join(law, 'settings.v2.json'), 'utf8')), o.repo, o.z3);
      if (r.error) { console.error(`✗ ${r.error}`); process.exit(65); }
      process.stdout.write(JSON.stringify(r.settings, null, 2) + '\n');
      process.exit(0);
    }
    process.exit(cmd === 'install' ? install(o) : doctor(o));
  } catch (e) {
    console.error(`✗ 道具の内部の失敗（何も確かめていない）：${e && e.message ? e.message : e}`);
    process.exit(cmd === 'doctor' ? 2 : 70);
  }
}
