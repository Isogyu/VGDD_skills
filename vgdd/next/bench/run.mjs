#!/usr/bin/env node
// vgdd/next の統治の検査（ガード）の評価：攻撃の阻止・良性の通過・アブレーション・性能（起草段階の試作）
//
//   node vgdd/next/bench/run.mjs                 … 表を標準出力に出す
//   node vgdd/next/bench/run.mjs --json out.json … 結果を JSON でも残す
//   node vgdd/next/bench/run.mjs --no-perf       … 性能の測定を省く
//
// 何を測るか：
//   1. 全ガードを有効にしたとき、攻撃のシナリオがすべて止まり、良性のシナリオがすべて通るか（陽性の対照）
//   2. アブレーション：ガードを1つだけ外したとき、どの攻撃が通るようになるか。
//      外しても何も通らないガードは「このシナリオの集まりでは必要性を示せていない」（冗長か、攻撃の例が足りない）
//   3. 性能：鎖つき記録の追記と検証、経験の取り出しの所要時間
//
// 何を測らないか：LLM を呼ばない。エージェントの仕事の成功率・品質・費用は測らない（それには実際の実行と予算の承認が要る）。
// ここで分かるのは「検査の論理が、用意した攻撃の例に対して働くか」まで。用意していない攻撃を止める保証ではない。
//
// 終了コード：0=全ガード有効で攻撃をすべて阻止し良性をすべて通した／1=そうでない／2=準備の失敗

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { performance } from 'node:perf_hooks';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const opt = (k) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : null; };

function runScenario(s, guardNames) {
  try {
    const r = s.run(guardNames);
    if (!r || typeof r.blocked !== 'boolean') return { blocked: null, by: [], error: 'run の戻り値の形が違う' };
    return { blocked: r.blocked, by: Array.isArray(r.by) ? r.by : [], error: null };
  } catch (e) {
    // シナリオが投げた例外は「止まった」とも「通った」とも数えない（試験の不具合として出す）
    return { blocked: null, by: [], error: String(e && e.message || e).slice(0, 200) };
  }
}

async function loadModules() {
  const files = fs.readdirSync(HERE).filter((f) => /^scenarios-.+\.mjs$/.test(f)).sort();
  const mods = [];
  for (const f of files) {
    const m = await import(pathToFileURL(path.join(HERE, f)).href);
    if (!m.MODULE || !m.GUARDS || !Array.isArray(m.SCENARIOS)) throw new Error(`${f}: MODULE・GUARDS・SCENARIOS が要る`);
    mods.push({ file: f, name: m.MODULE, guards: Object.keys(m.GUARDS), scenarios: m.SCENARIOS, extra: m });
  }
  return mods;
}

function evaluate(mod) {
  const all = mod.guards;
  const attacks = mod.scenarios.filter((s) => s.kind === 'attack');
  const benign = mod.scenarios.filter((s) => s.kind === 'benign');
  const base = mod.scenarios.map((s) => ({ id: s.id, kind: s.kind, title: s.title, expectGuards: s.expectGuards || [], ...runScenario(s, all) }));
  const errors = base.filter((r) => r.error);
  const attacksBlocked = base.filter((r) => r.kind === 'attack' && r.blocked === true).length;
  const benignPassed = base.filter((r) => r.kind === 'benign' && r.blocked === false).length;
  // 攻撃を止めたガードが、シナリオの宣言（expectGuards）を含むか（別の理由で偶然止まっていないか）
  const wrongReason = base.filter((r) => r.kind === 'attack' && r.blocked === true && r.expectGuards.length
    && !r.expectGuards.some((g) => r.by.includes(g))).map((r) => ({ id: r.id, expected: r.expectGuards, by: r.by }));

  // アブレーション：ガードを1つ外す
  const ablation = all.map((g) => {
    const rest = all.filter((x) => x !== g);
    const escaped = []; const benignBroken = [];
    for (const s of attacks) { const r = runScenario(s, rest); if (r.blocked === false) escaped.push(s.id); }
    for (const s of benign) { const r = runScenario(s, rest); if (r.blocked === true) benignBroken.push(s.id); }
    return { guard: g, escaped, benignBroken, necessary: escaped.length > 0 };
  });
  // 全ガードを外す（検査がなければ攻撃が通ることの確認。通らない攻撃は、ガード以外の何かが止めている）
  const noGuards = attacks.map((s) => ({ id: s.id, ...runScenario(s, []) }));
  const stillBlockedWithoutGuards = noGuards.filter((r) => r.blocked !== false).map((r) => r.id);

  return {
    module: mod.name, guards: all.length, attacks: attacks.length, benign: benign.length,
    attacksBlocked, benignPassed, errors: errors.map((e) => ({ id: e.id, error: e.error })), wrongReason,
    ablation, unprovenGuards: ablation.filter((a) => !a.necessary).map((a) => a.guard), stillBlockedWithoutGuards,
    ok: errors.length === 0 && attacksBlocked === attacks.length && benignPassed === benign.length,
    scenarios: base.map(({ id, kind, title, blocked, by }) => ({ id, kind, title, blocked, by })),
  };
}

function timeIt(fn, repeat = 5) {
  const xs = [];
  for (let i = 0; i < repeat; i += 1) { const t = performance.now(); fn(); xs.push(performance.now() - t); }
  xs.sort((a, b) => a - b);
  return { median_ms: +xs[Math.floor(xs.length / 2)].toFixed(3), min_ms: +xs[0].toFixed(3), max_ms: +xs[xs.length - 1].toFixed(3), repeat };
}

async function perf(mods) {
  const out = { node: process.version, platform: `${os.platform()} ${os.arch()}`, cpus: os.cpus().length, note: '1台の機械での測定。fsync を含む。値は目安' };
  const { openChain } = await import(pathToFileURL(path.join(HERE, '../lib/chain.mjs')).href);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vgdd-next-bench-'));
  // 鎖つき記録：追記は毎回、全行を読んで鎖を確かめる（fail-closed の代償）。件数に対する伸びを見る
  out.chain = [];
  for (const n of [100, 500, 2000]) {
    const c = openChain(path.join(dir, `chain-${n}.jsonl`));
    const t0 = performance.now();
    for (let i = 0; i < n; i += 1) c.append({ type: 'bench', i, payload: 'x'.repeat(120) });
    const total = performance.now() - t0;
    const last = timeIt(() => c.append({ type: 'bench', i: -1, payload: 'x'.repeat(120) }), 5);
    const verify = timeIt(() => c.read(), 5);
    out.chain.push({ records: n, append_total_ms: +total.toFixed(1), append_avg_ms: +(total / n).toFixed(3), append_at_n_median_ms: last.median_ms, verify_median_ms: verify.median_ms });
  }
  // 各モジュールの検査1回の所要時間（良性のシナリオを全ガードで）
  out.check = mods.map((m) => {
    const b = m.scenarios.filter((s) => s.kind === 'benign');
    if (!b.length) return { module: m.name, median_ms: null };
    const t = timeIt(() => { for (const s of b) runScenario(s, m.guards); }, 5);
    return { module: m.name, scenarios: b.length, median_ms_per_scenario: +(t.median_ms / b.length).toFixed(3) };
  });
  // 経験の取り出し（モジュールが測定用の関数を出していれば）
  const exp = mods.find((m) => typeof m.extra.benchRetrieve === 'function');
  if (exp) {
    out.retrieve = [];
    for (const n of [100, 1000, 5000]) {
      try { out.retrieve.push({ items: n, result: exp.extra.benchRetrieve(n) }); } catch (e) { out.retrieve.push({ items: n, error: String(e.message || e).slice(0, 200) }); }
    }
  }
  fs.rmSync(dir, { recursive: true, force: true });
  return out;
}

function print(results, perfOut) {
  const L = [];
  L.push('## 1. 攻撃の阻止と良性の通過（全ガード有効）', '');
  L.push('| モジュール | ガード | 攻撃（阻止／全体） | 良性（通過／全体） | 試験の不具合 | 判定 |', '|---|---:|---:|---:|---:|---|');
  for (const r of results) L.push(`| ${r.module} | ${r.guards} | ${r.attacksBlocked}/${r.attacks} | ${r.benignPassed}/${r.benign} | ${r.errors.length} | ${r.ok ? '合格' : '**不合格**'} |`);
  const T = (k) => results.reduce((a, r) => a + r[k], 0);
  L.push(`| **合計** | ${T('guards')} | ${T('attacksBlocked')}/${T('attacks')} | ${T('benignPassed')}/${T('benign')} | ${results.reduce((a, r) => a + r.errors.length, 0)} | |`, '');
  L.push('## 2. アブレーション（ガードを1つだけ外したとき、通るようになる攻撃）', '');
  L.push('| モジュール | 外したガード | 通るようになった攻撃 | 誤って止まった良性 |', '|---|---|---|---|');
  for (const r of results) for (const a of r.ablation) L.push(`| ${r.module} | ${a.guard} | ${a.escaped.length ? a.escaped.join(', ') : '（なし）'} | ${a.benignBroken.length ? a.benignBroken.join(', ') : '—'} |`);
  L.push('');
  const nec = results.reduce((a, r) => a + r.ablation.filter((x) => x.necessary).length, 0);
  L.push(`外すと攻撃が通るガード：${nec}/${T('guards')}。`);
  for (const r of results) {
    if (r.unprovenGuards.length) L.push(`- ${r.module}：外しても攻撃が通らなかったガード（このシナリオの集まりでは必要性を示せていない）：${r.unprovenGuards.join(', ')}`);
    if (r.stillBlockedWithoutGuards.length) L.push(`- ${r.module}：全ガードを外しても通らなかった攻撃（ガード以外が止めている）：${r.stillBlockedWithoutGuards.join(', ')}`);
    if (r.wrongReason.length) L.push(`- ${r.module}：宣言と違うガードで止まった攻撃：${r.wrongReason.map((w) => `${w.id}（宣言 ${w.expected.join('/')}、実際 ${w.by.join('/') || 'なし'}）`).join('、')}`);
    for (const e of r.errors) L.push(`- ${r.module}：試験の不具合 ${e.id}：${e.error}`);
  }
  if (perfOut) {
    L.push('', '## 3. 性能（目安）', '', `環境：Node ${perfOut.node}、${perfOut.platform}、CPU ${perfOut.cpus}。${perfOut.note}。`, '');
    L.push('| 鎖つき記録の件数 | 追記の平均 (ms) | その件数での追記1回 (ms) | 全行の検証 (ms) |', '|---:|---:|---:|---:|');
    for (const c of perfOut.chain) L.push(`| ${c.records} | ${c.append_avg_ms} | ${c.append_at_n_median_ms} | ${c.verify_median_ms} |`);
    L.push('', '| モジュール | 検査1回 (ms) |', '|---|---:|');
    for (const c of perfOut.check) L.push(`| ${c.module} | ${c.median_ms_per_scenario ?? '—'} |`);
    if (perfOut.retrieve) { L.push('', '経験の取り出し：'); for (const r of perfOut.retrieve) L.push(`- ${r.items} 件：${r.error ? `失敗（${r.error}）` : JSON.stringify(r.result)}`); }
  }
  console.log(L.join('\n'));
}

let mods;
try { mods = await loadModules(); } catch (e) { console.error(`準備に失敗：${e.message}`); process.exit(2); }
if (!mods.length) { console.error('シナリオのファイルがない'); process.exit(2); }
const results = mods.map(evaluate);
const perfOut = args.includes('--no-perf') ? null : await perf(mods);
print(results, perfOut);
const jsonOut = opt('--json');
if (jsonOut) fs.writeFileSync(jsonOut, JSON.stringify({ schema: 'vgdd.next-bench.v1', generated_at: new Date().toISOString(), results, perf: perfOut }, null, 2) + '\n');
process.exit(results.every((r) => r.ok) ? 0 : 1);
