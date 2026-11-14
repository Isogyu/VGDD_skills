// VGDD Governance Kernel — 設定の層の検査（法律 p0.4.16、SPEC §11 の設定の照合・§12。依存なし、Node 22 以上）
//
// Claude Code の設定には層がある（優先の高い順に：管理者の設定、起動の引数 --settings、<repo>/.claude/settings.local.json、
//   <repo>/.claude/settings.json、~/.claude/settings.json）。配列（permissions の deny など）は統合され、上の層の allow は下の層の deny を
//   取り消せないが、値の設定（sandbox.enabled など）は上の層が勝つ（2026-11-14 に公式の文書で確かめた。実機では確かめていない）。
//   p0.4.15 までの照合（適合性テストの ST16・導入の道具の doctor）は、プロジェクトの .claude/settings.json が原本の項目を「含むか」だけを見ていた。
//
// この部品は、検査の規則を1か所に書き、適合性テスト（run.mjs の ST16・ST16b〜ST16e）と導入の道具（vgdd-setup.mjs doctor）の両方が使う。
//   適合性テストは、この部品を、試す実装の場所（--impl z3 なら Z3 の bin、原本なら vgdd/scripts）から読み、判例 ST16d・ST16e で
//   手で書いた設定（緩める項目ごと・陽性の対照）にかけて、規則そのものを確かめる（規則の誤りが、そのまま合格にならないように）。
//   原本の書き換え（場所に合わせる）は、今までどおり適合性テストと導入の道具で別々に実装する（判例 PT7）。
//
// 規則：
//   (1) プロジェクトの配置済みの設定（projectProblems）：今までの包含の検査（拒否の規則・denyWrite・denyRead・sandbox の3つの値・フックの構造。
//       呼ぶ側が行う）に加えて、sandbox の節は原本にある項目の名前だけ（filesystem・network の中も同じ）。denyWrite・denyRead は原本を含む上位集合、
//       network.allowedDomains は原本の部分集合（宛先を足すのは原本を改める立法による）、ほかの原本の項目は原本と同じ値（autoAllowBashIfSandboxed は
//       真偽値なら値を問わない。false は確認が増えるだけ）。最上位に Kernel のフックを止める項目（disableAllHooks・allowManagedHooksOnly が false 以外）が
//       あれば不合格。
//   (2) 上の層の設定（upperLayerProblems。<repo>/.claude/settings.local.json、~/.claude/settings.json、~/.claude/settings.local.json）：
//       ファイルがなければ合格。読めない・JSON のオブジェクトでない・大きすぎる（1 MiB）・ファイルでないときは不合格（fail-closed）。
//       中に Kernel の保護を弱める値があれば不合格、弱めるかを決められない項目は「注意」（合格に数えない）。
//   どちらも結果は { fail: [...], warn: [...] }（文字列は項目の名前と短い理由だけ。パスの中身・値は出さない）
//
// 見られないもの（SPEC §12）：管理者の設定（managed settings）、起動の引数 --settings・--setting-sources・--bare、環境変数。
//   worktree の作業員のセッションが読む写し（git で追跡された .claude/settings.json）

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const SETTINGS_CHECK_VERSION = 'p0.4.16';
const MAX_BYTES = 1024 * 1024;
const isObj = (x) => !!x && typeof x === 'object' && !Array.isArray(x);
const strArr = (x) => Array.isArray(x) && x.every((y) => typeof y === 'string');
const canon = (x) => Array.isArray(x) ? x.map(canon) : isObj(x) ? Object.fromEntries(Object.keys(x).sort().map((k) => [k, canon(x[k])])) : x;
const same = (a, b) => JSON.stringify(canon(a)) === JSON.stringify(canon(b));

// フックを止める最上位の項目（false 以外なら不合格）。allowManagedHooksOnly は管理者の設定でだけ効くと思われるが、文書で確かめていないので止める側に数える
const HOOK_DISABLERS = ['disableAllHooks', 'allowManagedHooksOnly'];
// フックのプロセスの動作を変えうる環境の名前（設定の env がフックに渡るかは文書で確かめていない（R3）。決められないので「注意」）
const RISKY_ENV = /^(NODE_OPTIONS|NODE_PATH|PATH|HOME|CLAUDE_PROJECT_DIR|VGDD_.*|DYLD_.*|LD_.*|GIT_.*)$/;
// sandbox.network の中で、明らかに緩める項目（上の層で真・空でない値なら不合格）
const NET_LOOSEN = ['allowUnixSockets', 'allowAllUnixSockets', 'allowLocalBinding', 'httpProxyPort', 'socksProxyPort'];

function topLevelProblems(s, fail, warn, where) {
  for (const k of HOOK_DISABLERS) if (k in s && s[k] !== false) fail.push(`${where}${k}（Kernel のフックを止める）`);
  if ('env' in s) {
    if (!isObj(s.env)) fail.push(`${where}env（形が違う）`);
    else for (const k of Object.keys(s.env)) if (RISKY_ENV.test(k)) warn.push(`${where}env.${k}（フックのプロセスに渡るかを確かめていない。フックの動作を変えうる）`);
  }
}

/**
 * プロジェクトの配置済みの設定（.claude/settings.json）の厳しさの検査（包含の検査は呼ぶ側）。
 * want：原本（試す場所に合わせて書き換えたもの）、dep：配置済みの設定
 */
export function projectProblems(want, dep) {
  const fail = []; const warn = [];
  if (!isObj(dep)) return { fail: ['配置済みの設定がない（または JSON のオブジェクトでない）'], warn };
  topLevelProblems(dep, fail, warn, '');
  const ws = isObj(want.sandbox) ? want.sandbox : {};
  if (!('sandbox' in dep)) { fail.push('sandbox（節がない）'); return { fail, warn }; }
  if (!isObj(dep.sandbox)) { fail.push('sandbox（形が違う）'); return { fail, warn }; }
  const ds = dep.sandbox;
  for (const k of Object.keys(ds)) {
    if (!(k in ws)) { fail.push(`sandbox.${k}（原本にない項目）`); continue; }
    const a = ws[k]; const b = ds[k];
    if (k === 'filesystem' || k === 'network') {
      if (!isObj(b)) { fail.push(`sandbox.${k}（形が違う）`); continue; }
      const wa = isObj(a) ? a : {};
      for (const kk of Object.keys(b)) {
        if (!(kk in wa)) { fail.push(`sandbox.${k}.${kk}（原本にない項目）`); continue; }
        const x = wa[kk]; const y = b[kk];
        if (k === 'filesystem' && (kk === 'denyWrite' || kk === 'denyRead')) { if (!strArr(y)) fail.push(`sandbox.filesystem.${kk}（文字列の配列でない）`); continue; }   // 上位集合かは包含の検査
        if (k === 'network' && kk === 'allowedDomains') {
          if (!strArr(y)) { fail.push('sandbox.network.allowedDomains（文字列の配列でない）'); continue; }
          const extra = y.filter((d) => !(x || []).includes(d));
          if (extra.length) fail.push(`sandbox.network.allowedDomains（原本にない宛先 ${extra.length} 件。宛先を足すのは原本を改める立法による）`);
          continue;
        }
        if (!same(x, y)) fail.push(`sandbox.${k}.${kk}（原本と違う値）`);
      }
      continue;
    }
    if (k === 'enabled' || k === 'failIfUnavailable' || k === 'allowUnsandboxedCommands') { if (a !== b) fail.push(`sandbox.${k}（原本と違う値）`); continue; }
    if (k === 'autoAllowBashIfSandboxed') { if (typeof b !== 'boolean') fail.push('sandbox.autoAllowBashIfSandboxed（真偽値でない）'); continue; }
    if (!same(a, b)) fail.push(`sandbox.${k}（原本と違う値）`);
  }
  return { fail, warn };
}

/** パスの項目を絶対パスにする（決められなければ null）。base は相対の基準（プロジェクトの設定はリポジトリ、ユーザーの設定は ~/.claude） */
function resolveEntry(entry, base, home) {
  if (typeof entry !== 'string' || !entry || /[*?[\]{}$`]/.test(entry)) return null;   // グロブ・変数は決められない
  let p;
  if (entry === '~' || entry.startsWith('~/')) p = path.join(home, entry.slice(1));
  else if (entry.startsWith('//')) p = entry.slice(1);
  else if (entry.startsWith('/')) p = entry;
  else if (entry.startsWith('~')) return null;   // ~名前 は決められない
  else p = path.join(base, entry);
  return path.resolve(p);
}
const overlaps = (a, b) => { const r1 = path.relative(a, b); const r2 = path.relative(b, a); const inside = (r) => r === '' || (!r.startsWith('..') && !path.isAbsolute(r)); return inside(r1) || inside(r2); };

/**
 * 上の層の設定の中の、Kernel の保護を弱める値。
 * s：設定（JSON のオブジェクト）。ctx：{ base（相対の基準）, home, want（原本を場所に合わせたもの）, repo }
 */
export function upperLayerProblems(s, ctx) {
  const fail = []; const warn = [];
  if (!isObj(s)) return { fail: ['JSON のオブジェクトでない'], warn };
  topLevelProblems(s, fail, warn, '');
  if ('hooks' in s) {
    if (!isObj(s.hooks)) fail.push('hooks（形が違う）');
    else if (Object.keys(s.hooks).length) warn.push('hooks（Kernel のフックの登録と統合されるか・置き換えるか、ほかのフックの判定と出力が Kernel の判定にどう効くかを文書で確かめていない）');
  }
  if (!('sandbox' in s)) return { fail, warn };
  if (!isObj(s.sandbox)) { fail.push('sandbox（形が違う）'); return { fail, warn }; }
  const sb = s.sandbox; const want = ctx.want || {}; const wsb = isObj(want.sandbox) ? want.sandbox : {};
  const home = ctx.home; const repo = ctx.repo;
  // 保護する場所（原本の denyRead・denyWrite をリポジトリの基準で絶対パスにしたもの）。決められない項目は保護の一覧に入れない（下で、重なりを決められなければ不合格にする）
  const prot = (k) => ((wsb.filesystem || {})[k] || []).map((e) => resolveEntry(e, repo, home)).filter(Boolean);
  for (const k of Object.keys(sb)) {
    const v = sb[k];
    if (k === 'enabled') { if (v !== true) fail.push('sandbox.enabled（true 以外。sandbox が外れる）'); continue; }
    if (k === 'allowUnsandboxedCommands') { if (v !== false) fail.push('sandbox.allowUnsandboxedCommands（false 以外。sandbox の外での実行を許す）'); continue; }
    if (k === 'failIfUnavailable') { if (v !== true) fail.push('sandbox.failIfUnavailable（true 以外。sandbox が使えないときに止まらない）'); continue; }
    if (k === 'autoAllowBashIfSandboxed') { if (typeof v !== 'boolean') fail.push('sandbox.autoAllowBashIfSandboxed（真偽値でない）'); continue; }
    if (k === 'excludedCommands') { if (!Array.isArray(v) || v.length > 0) fail.push('sandbox.excludedCommands（書いたコマンドは sandbox の外で動く）'); continue; }
    if (/^enableWeaker/.test(k) || k === 'allowNestedUserNamespaces' || k === 'allowAppleEvents') { if (v !== false) fail.push(`sandbox.${k}（sandbox を弱める）`); continue; }
    if (k === 'filesystem') {
      if (!isObj(v)) { fail.push('sandbox.filesystem（形が違う）'); continue; }
      for (const kk of Object.keys(v)) {
        const x = v[kk];
        if (kk === 'disabled') { if (x !== false) fail.push('sandbox.filesystem.disabled（ファイルの隔離が外れる）'); continue; }
        if (kk === 'denyWrite' || kk === 'denyRead') { if (!strArr(x)) fail.push(`sandbox.filesystem.${kk}（文字列の配列でない）`); continue; }   // 足すのは締める側
        if (kk === 'allowRead' || kk === 'allowWrite') {
          if (!strArr(x)) { fail.push(`sandbox.filesystem.${kk}（文字列の配列でない）`); continue; }
          const areas = kk === 'allowRead' ? prot('denyRead') : [...prot('denyWrite'), ...prot('denyRead')];
          let bad = 0; let undecided = 0;
          for (const e of x) { const p = resolveEntry(e, ctx.base, home); if (!p) undecided++; else if (areas.some((a) => overlaps(a, p))) bad++; }
          if (bad || undecided) fail.push(`sandbox.filesystem.${kk}（保護する場所に重なる ${bad} 件・重なるかを決められない ${undecided} 件）`);
          else if (kk === 'allowWrite' && x.length) warn.push(`sandbox.filesystem.allowWrite（保護の一覧の外への書き込みを ${x.length} 件開く。害がないかを人が確かめる）`);
          continue;
        }
        warn.push(`sandbox.filesystem.${kk}（知らない項目）`);
      }
      continue;
    }
    if (k === 'network') {
      if (!isObj(v)) { fail.push('sandbox.network（形が違う）'); continue; }
      const wd = ((wsb.network || {}).allowedDomains) || [];
      for (const kk of Object.keys(v)) {
        const x = v[kk];
        if (kk === 'allowedDomains') { if (!strArr(x)) fail.push('sandbox.network.allowedDomains（文字列の配列でない）'); else { const extra = x.filter((d) => !wd.includes(d)); if (extra.length) fail.push(`sandbox.network.allowedDomains（原本にない宛先 ${extra.length} 件。上の層の一覧も統合される）`); } continue; }
        if (kk === 'deniedDomains') { if (!strArr(x)) fail.push('sandbox.network.deniedDomains（文字列の配列でない）'); continue; }
        if (NET_LOOSEN.includes(kk)) { const off = x === false || x === null || (Array.isArray(x) && x.length === 0); if (!off) fail.push(`sandbox.network.${kk}（ネットワークの隔離を弱める）`); continue; }
        warn.push(`sandbox.network.${kk}（知らない項目）`);
      }
      continue;
    }
    warn.push(`sandbox.${k}（知らない項目）`);
  }
  return { fail, warn };
}

/** 検査する上の層のファイル（試験ではホームを一時ディレクトリにする） */
export function upperLayerFiles(repo, home = os.homedir()) {
  return [
    { kind: 'project-local', file: path.join(repo, '.claude', 'settings.local.json'), base: repo },
    { kind: 'user', file: path.join(home, '.claude', 'settings.json'), base: path.join(home, '.claude') },
    { kind: 'user-local', file: path.join(home, '.claude', 'settings.local.json'), base: path.join(home, '.claude') },
  ];
}

/** 設定のファイルを読む。返り値 { absent } か { json } か { error } （fail-closed：読めない・形が違うものは error） */
export function readSettingsFile(file) {
  let st;
  try { st = fs.statSync(file); } catch (e) { if (e && e.code === 'ENOENT') { try { fs.lstatSync(file); return { error: '記号リンクの先がない' }; } catch { return { absent: true }; } } return { error: '状態を読めない' }; }
  if (!st.isFile()) return { error: 'ファイルでない' };
  if (st.size > MAX_BYTES) return { error: '大きすぎる' };
  let text; try { text = fs.readFileSync(file, 'utf8'); } catch { return { error: '読めない' }; }
  let j; try { j = JSON.parse(text); } catch { return { error: 'JSON でない' }; }
  if (!isObj(j)) return { error: 'JSON のオブジェクトでない' };
  return { json: j };
}

/** 上の層をまとめて検査する。返り値 [{ kind, present, fail: [...], warn: [...] }]（ファイルのパスは呼ぶ側が kind から出す） */
export function checkUpperLayers({ repo, home = os.homedir(), want }) {
  return upperLayerFiles(repo, home).map(({ kind, file, base }) => {
    const r = readSettingsFile(file);
    if (r.absent) return { kind, present: false, fail: [], warn: [] };
    if (r.error) return { kind, present: true, fail: [`ファイルを検査できない（${r.error}）`], warn: [] };
    const p = upperLayerProblems(r.json, { base, home, want, repo });
    return { kind, present: true, ...p };
  });
}
