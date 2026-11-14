// 権限の差分（authority-delta）の攻撃と良性のシナリオ。本物の権限の表を1か所変えた版を「提案された新版」とし、
// 通常の経路（standard）に乗ってよいかをガードで確かめる。run は副作用なし・同期
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { check } from '../authority-delta.mjs';

export const MODULE = 'authority-delta';
export { GUARDS } from '../authority-delta.mjs';

const caps = JSON.parse(fs.readFileSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../kernel/capabilities.json'), 'utf8'));
const mut = (fn) => { const c = structuredClone(caps); fn(c); return c; };
const cap = (c, id) => c.capabilities.find((x) => x.id === id);
const inv = (c, id) => c.invariants.find((x) => x.id === id);

const BASE11 = mut((c) => { c.roles.constructor = { kind: 'ai', identity: 'x', hook_input: { agent_type: 'constructor', cwd: '{wt}' } }; cap(c, 'CAP-LAW-WRITE').expect.constructor = 'deny'; });

function scenario(id, kind, title, expectGuards, newCaps, oldCaps = caps) {
  return { id, kind, title, expectGuards, run: (guardNames) => { const r = check({ oldCaps, newCaps }, guardNames); return { blocked: !r.ok, by: r.violations.map((v) => v.guard) }; } };
}

export const SCENARIOS = [
  scenario('AD-A1', 'attack', '作業員に法律の書き換えを許す（自己の権限の拡張）', ['AD-NO-GRANT'], mut((c) => cap(c, 'CAP-LAW-WRITE').allowed.push('worker'))),
  scenario('AD-A2', 'attack', '行政の長の証拠の書き込みの判定を deny → allow', ['AD-NO-GRANT'], mut((c) => { cap(c, 'CAP-EVIDENCE-WRITE').expect.executive_head = 'allow'; })),
  scenario('AD-A3', 'attack', '新しい AI の役割を足す（委任による権限の増加）', ['AD-NO-GRANT'], mut((c) => { c.roles.sub_worker = { kind: 'ai', identity: '作業員が起こす補助' }; })),
  scenario('AD-A4', 'attack', '権限の項目を丸ごと消す（git の設定の禁止）', ['AD-NO-GRANT'], mut((c) => { c.capabilities = c.capabilities.filter((x) => x.id !== 'CAP-GIT-CONFIG'); })),
  scenario('AD-A5', 'attack', '法律の書き換えから sandbox の層を外す', ['AD-ENFORCEMENT-NO-WEAKEN'], mut((c) => { cap(c, 'CAP-LAW-WRITE').enforced_by = cap(c, 'CAP-LAW-WRITE').enforced_by.filter((l) => l !== 'sandbox'); })),
  scenario('AD-A6', 'attack', 'シンボリックリンクの禁止を約束だけにする', ['AD-ENFORCEMENT-NO-WEAKEN'], mut((c) => { cap(c, 'CAP-LINK').enforced_by = ['promise']; })),
  scenario('AD-A7', 'attack', '検証器の弱体化：probe を消す', ['AD-VERIFIER-MONOTONE'], mut((c) => cap(c, 'CAP-LAW-WRITE').probes.pop())),
  scenario('AD-A8', 'attack', '検証器の弱体化：probe を当たらない操作に書き換える', ['AD-VERIFIER-MONOTONE'], mut((c) => { cap(c, 'CAP-LINK').probes[0].command = 'true'; })),
  scenario('AD-A9', 'attack', '検証器の弱体化：不変条件の判例を減らす', ['AD-VERIFIER-MONOTONE'], mut((c) => { inv(c, 'INV-05').tests = inv(c, 'INV-05').tests.slice(1); })),
  scenario('AD-A10', 'attack', '不変条件の格下げ（INV-01 を partial に）', ['AD-INVARIANT-NO-DOWNGRADE'], mut((c) => { inv(c, 'INV-01').status = 'partial'; })),
  scenario('AD-A11', 'attack', '不変条件を消す（INV-05）', ['AD-INVARIANT-NO-DOWNGRADE'], mut((c) => { c.invariants = c.invariants.filter((x) => x.id !== 'INV-05'); })),
  scenario('AD-A12', 'attack', '穴の記載を黙って消す（塞いだと称する）', ['AD-NO-INDETERMINATE'], mut((c) => { delete cap(c, 'CAP-MAIN-INTEGRATE').known_gaps; })),
  scenario('AD-A13', 'attack', '識別の根拠を書き換える（作業員の agent_type）', ['AD-NO-INDETERMINATE'], mut((c) => { c.roles.worker.hook_input.agent_type = 'executive'; })),
  scenario('AD-A14', 'attack', '規則にない項目で例外を書き足す', ['AD-NO-INDETERMINATE'], mut((c) => { cap(c, 'CAP-LAW-WRITE').exempt = ['worker']; })),
  scenario('AD-A15', 'attack', '形の壊れた表（capability の id の重複）で分類を逃れる', ['AD-WELLFORMED'], mut((c) => { c.capabilities.push({ ...structuredClone(cap(c, 'CAP-LAW-WRITE')), allowed: ['owner', 'worker'] }); })),
  scenario('AD-A16', 'attack', '締める変更に緩める変更を混ぜる', ['AD-NO-GRANT'], mut((c) => { cap(c, 'CAP-LINK').enforced_by.push('sandbox'); cap(c, 'CAP-ENV-READ').allowed.push('executive_head'); })),
  // ---- 審査で見つかった抜け道（F1・F6・F11）----
  scenario('AD-A17', 'attack', 'F1：kernel_version を古い系統へ戻す（無効になった承認の復活）', ['AD-NO-INDETERMINATE'], mut((c) => { c.kernel_version = 'p0.3.9'; })),
  scenario('AD-A18', 'attack', 'F6：作業員に allow の権限へ、法律のフックを書く probe を足して「確かめ方の追加」と称する', ['AD-NO-GRANT'], mut((c) => cap(c, 'CAP-SRC-WRITE-OWN').probes.push({ tool: 'Write', file_path: '{main}/vgdd/hooks/policy.mjs' }))),
  scenario('AD-A19', 'attack', 'F11：constructor という名の役割の deny を外す（締めると誤分類させる）', ['AD-NO-GRANT'],
    (() => { const b = structuredClone(BASE11); delete cap(b, 'CAP-LAW-WRITE').expect.constructor; return b; })(), BASE11),
  scenario('AD-A20', 'attack', 'F11：roles にない toString を allowed に書いた権限を足す（知っている役割として通す）', ['AD-NO-INDETERMINATE'], mut((c) => c.capabilities.push({ id: 'CAP-X', title: 't', allowed: ['toString'], enforced_by: ['hook'] }))),
  scenario('AD-B1', 'benign', '同じ表（変更なし）', [], structuredClone(caps)),
  scenario('AD-B2', 'benign', '並べ替えだけ', [], mut((c) => { c.capabilities.reverse(); c.invariants.reverse(); for (const x of c.capabilities) if (x.probes) x.probes.reverse(); })),
  scenario('AD-B3', 'benign', 'probe の追加（確かめ方を増やす）', [], mut((c) => cap(c, 'CAP-LINK').probes.push({ tool: 'Bash', command: 'ln -sf a b' }))),
  scenario('AD-B4', 'benign', '穴の公開（known_gaps の追加）と版の更新', [], mut((c) => { cap(c, 'CAP-LINK').known_gaps = ['ハードリンクは見ていない']; c.kernel_version = 'p0.4.15'; })),
  scenario('AD-B5', 'benign', '強制の層の追加と、AI に許していた権限を外す', [], mut((c) => { cap(c, 'CAP-MERGE-REQUEST').enforced_by.push('sandbox'); cap(c, 'CAP-KERNEL-STATE-READ').allowed = cap(c, 'CAP-KERNEL-STATE-READ').allowed.filter((r) => r !== 'tester'); })),
];
