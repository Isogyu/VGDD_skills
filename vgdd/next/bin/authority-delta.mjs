#!/usr/bin/env node
// 権限の表の旧版と新版の差分を分類する（起草段階の試作）
//
//   node vgdd/next/bin/authority-delta.mjs <old.json> <new.json> [--json]
//
// 終了コード：0=neutral・tightening／3=loosening／4=indeterminate／65=入力エラー（ファイルが読めない・JSON でない・引数が違う）
// どの終了コードでも、採用は人（オーナー）の承認による。この CLI は採用も承認もしない。

import fs from 'node:fs';
import { authorityDelta, routeFor, formatDelta, check } from '../authority-delta.mjs';

const args = process.argv.slice(2);
const json = args.includes('--json');
const files = args.filter((a) => a !== '--json');
if (files.length !== 2 || args.some((a) => a.startsWith('--') && a !== '--json')) {
  process.stderr.write('使い方：node vgdd/next/bin/authority-delta.mjs <old.json> <new.json> [--json]\n');
  process.exit(65);
}
const load = (f) => {
  try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch (e) {
    process.stderr.write(`入力エラー：${f} を JSON として読めない（${e.code || e.name}）\n`);
    process.exit(65);
  }
};
const oldCaps = load(files[0]);
const newCaps = load(files[1]);
const delta = authorityDelta(oldCaps, newCaps);
const route = routeFor(delta);
const guards = check({ oldCaps, newCaps });
if (json) process.stdout.write(JSON.stringify({ ...delta, route, standard_lane_check: guards }, null, 2) + '\n');
else {
  process.stdout.write(formatDelta(delta) + '\n');
  if (!guards.ok) process.stdout.write(`  通常の経路に乗せられない理由：\n${guards.violations.map((v) => `    ${v.guard}：${v.reason}`).join('\n')}\n`);
}
process.exit(delta.class === 'loosening' ? 3 : delta.class === 'indeterminate' ? 4 : 0);
