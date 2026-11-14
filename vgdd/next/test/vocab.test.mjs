// 共通の語彙（lib/vocab.mjs）の試験
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as V from '../lib/vocab.mjs';
import { Refused } from '../lib/chain.mjs';

const CAPS = JSON.parse(fs.readFileSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../kernel/capabilities.json'), 'utf8'));

test('役割の表：本物の capabilities.json の roles はすべて vocab にあり、食い違いがない', () => {
  assert.deepEqual(V.checkAgainstCapabilities(CAPS), []);
  for (const r of Object.keys(CAPS.roles)) assert.ok(V.ROLES.includes(r), r);
  assert.deepEqual([...V.ROLES_NOT_IN_CAPABILITIES].sort(), ['codex_security', 'reaper', 'trace_importer']);
});

test('役割の表：照合は食い違いを見つける（表にない役割・kind の違い・表から消えた役割）', () => {
  const c = structuredClone(CAPS);
  c.roles.planner = { kind: 'ai' };
  c.roles.judge.kind = 'script';
  delete c.roles.scribe;
  const got = V.checkAgainstCapabilities(c).map((x) => x.role).sort();
  assert.deepEqual(got, ['judge', 'planner', 'scribe']);
  assert.equal(V.checkAgainstCapabilities(null).length, 1);
  // 権限の表にまだない役割が表に足されると、in_capabilities: false との食い違いとして出る（足したら vocab を直す）
  const d = structuredClone(CAPS); d.roles.reaper = { kind: 'script' };
  assert.deepEqual(V.checkAgainstCapabilities(d).map((x) => x.role), ['reaper']);
});

test('normRole：表にある名前だけ。全角・前後の空白・大文字は正規化、別名・部分一致・ハイフンは null', () => {
  assert.equal(V.normRole(' Executive_Head '), 'executive_head');
  assert.equal(V.normRole('ｊｕｄｇｅ'), 'judge');
  for (const x of ['executive', 'court', 'night_agent', 'court_script', 'judiciary', 'codex-judge', 'judge​', 'courtesy_bot', '', null, 1, 'constructor', '__proto__', 'toString']) assert.equal(V.normRole(x), null, String(x));
});

test('isJudicialRole：判定する司法だけ（security の審査を含む）。裁判所の執行・行政・表にない名前は false', () => {
  for (const r of ['judge', 'codex_judge', 'constitutional_review', 'codex_security', ' JUDGE ']) assert.equal(V.isJudicialRole(r), true, r);
  for (const r of ['gate_runner', 'worker', 'executive_head', 'night_runner', 'owner', 'reaper', 'security', 'court', 'judge_x', 'prejudice_check']) assert.equal(V.isJudicialRole(r), false, r);
  assert.equal(V.isCourtSide('gate_runner'), true);
  assert.equal(V.isCourtSide('codex_security'), true);
  assert.equal(V.isCourtSide('trace_importer'), false);
  assert.equal(V.branchOf('night_runner'), 'executive');
  assert.equal(V.branchOf('nope'), null);
});

test('系統：知っている系統だけ。別名（anthropic・openai）・ハイフン・空白は null。differentLineage は両方読めて違うときだけ', () => {
  assert.equal(V.normLineage(' Claude '), 'claude');
  assert.equal(V.normLineage('ｃｏｄｅｘ'), 'codex');
  for (const x of ['anthropic', 'openai', 'open-ai', 'open_ai', 'gemini', 'claude ai', 'claude​', '', null]) assert.equal(V.normLineage(x), null, String(x));
  assert.equal(V.differentLineage('claude', 'codex'), true);
  assert.equal(V.differentLineage('claude', 'Claude'), false);
  assert.equal(V.differentLineage('claude', 'anthropic'), false, '知らない系統は違う系統とみなさない');
});

test('行為者：同じオブジェクトの形。lineage は人・スクリプトで補い、AI は必須。役割と種類が表と合う', () => {
  assert.deepEqual(V.normActor({ role: 'owner', kind: 'human', id: 'Azuki' }), { role: 'owner', kind: 'human', id: 'azuki', lineage: 'human' });
  assert.deepEqual(V.normActor({ role: 'gate_runner', kind: 'script', id: 'gate', lineage: 'script' }), { role: 'gate_runner', kind: 'script', id: 'gate', lineage: 'script' });
  assert.deepEqual(V.normActor({ role: 'executive_head', kind: 'ai', id: 'h', lineage: 'Claude' }), { role: 'executive_head', kind: 'ai', id: 'h', lineage: 'claude' });
  assert.ok(V.normActor({ role: 'scribe', kind: 'ai', id: 's', lineage: 'claude' }));
  assert.ok(V.normActor({ role: 'scribe', kind: 'script', id: 's' }));
  const bad = [
    { role: 'executive_head', kind: 'ai', id: 'h' }, // AI の lineage がない
    { role: 'executive_head', kind: 'ai', id: 'h', lineage: 'anthropic' },
    { role: 'executive_head', kind: 'ai', id: 'h', lineage: 'human' },
    { role: 'executive_head', kind: 'ai', id: 'h', lineage: 'script' },
    { role: 'owner', kind: 'ai', id: 'x', lineage: 'claude' }, // オーナーは人だけ
    { role: 'owner', kind: 'human', id: 'x', lineage: 'claude' },
    { role: 'gate_runner', kind: 'ai', id: 'g', lineage: 'codex' }, // 裁判所の執行はスクリプトだけ
    { role: 'executive_head', kind: 'script', id: 'h' },
    { role: 'executive_head', kind: 'ai', id: 'h', lineage: 'claude', extra: 1 },
    { role: 'executive', kind: 'ai', id: 'h', lineage: 'claude' },
    { role: 'owner', kind: 'human', id: 'a b' },
    { role: 'owner', kind: 'human', id: '' },
    { role: 'owner', kind: 'robot', id: 'a' },
    null, 'owner', [],
  ];
  for (const b of bad) assert.equal(V.normActor(b), null, JSON.stringify(b));
  assert.ok(V.parseActor({ role: 'owner', kind: 'ai', id: 'x', lineage: 'claude' }).errors.some((e) => e.includes('種類')));
});

test('sameActor・isOwner：正規化した形で比べる。owner を名乗る AI はオーナーでない', () => {
  assert.equal(V.sameActor({ role: 'owner', kind: 'human', id: 'A' }, { role: 'owner', kind: 'human', id: 'a', lineage: 'human' }), true);
  assert.equal(V.sameActor({ role: 'worker', kind: 'ai', id: 'w', lineage: 'claude' }, { role: 'worker', kind: 'ai', id: 'w', lineage: 'codex' }), false);
  assert.equal(V.isOwner({ role: 'owner', kind: 'human', id: 'a' }), true);
  assert.equal(V.isOwner({ role: 'owner', kind: 'ai', id: 'a', lineage: 'claude' }), false);
  assert.equal(V.isOwner(null), false);
});

test('票の ID：宣言の形で照合する。大文字小文字・全角を畳まない。宣言は prefix と digits（1〜12）だけ', () => {
  const t = V.makeWorkItemId();
  for (const ok of ['T-101', 'T-0001', 'T-9999']) assert.equal(t(ok), true, ok);
  for (const ng of ['t-101', 'T-12', 'T-12345', 'Ｔ-101', 'T-10a', 'T-101 ', 'X-101', '', null]) assert.equal(t(ng), false, String(ng));
  const r = V.makeWorkItemId({ prefix: 'R-', digits: [2, 2] });
  assert.equal(r('R-01'), true);
  assert.equal(r('R-001'), false);
  assert.deepEqual(r.spec, { prefix: 'R-', digits: [2, 2] });
  for (const bad of [null, {}, { prefix: 'T-' }, { prefix: '1-', digits: [1, 2] }, { prefix: 'T-', digits: [0, 2] }, { prefix: 'T-', digits: [3, 2] }, { prefix: 'T-', digits: [1, 13] }, { prefix: 'T-', digits: [1, 2], re: '.*' }, { prefix: '^T-[0-9]+$', digits: [1, 2] }]) assert.equal(V.makeWorkItemId(bad), null, JSON.stringify(bad));
});

test('指紋と参照：sha256: と 64 桁の小文字。申請・統合の参照は 40 桁の 16 進か sha256: 形の 2 形だけ', () => {
  const h = 'a'.repeat(64);
  assert.equal(V.asDigest(h), `sha256:${h}`);
  assert.equal(V.asDigest('A'.repeat(64)), null);
  assert.equal(V.isDigest(`sha256:${h}`), true);
  assert.equal(V.isDigest(h), false);
  assert.equal(V.isArtifactRef('b'.repeat(40)), true);
  assert.equal(V.isArtifactRef(`sha256:${h}`), true);
  for (const x of ['a'.repeat(12), 'a'.repeat(7), 'A'.repeat(40), `sha256:${'a'.repeat(63)}`]) assert.equal(V.isArtifactRef(x), false, x);
  assert.equal(V.refHead12('0123456789abcdef'.repeat(2) + '01234567'), '0123456789ab');
  assert.equal(V.refHead12(`sha256:${'c'.repeat(64)}`), 'c'.repeat(12));
});

test('判定・監査の id と審査の種類：mode と役割・（種類, 系統）の対応は 1 か所', () => {
  assert.equal(V.reviewModeOf('judge', 'claude'), 'judge');
  assert.equal(V.reviewModeOf('judge', 'codex'), 'codex-judge');
  assert.equal(V.reviewModeOf('security', 'codex'), 'codex-security');
  assert.equal(V.reviewModeOf('security', 'claude'), null);
  assert.equal(V.reviewModeOf('judge', 'anthropic'), null);
  assert.equal(V.roleOfMode('codex-security'), 'codex_security');
  const req = 'd'.repeat(40);
  const id = V.verdictId(req, 'codex-judge');
  assert.equal(id, 'VRD-dddddddddddd-codex-judge');
  assert.equal(V.verdictId(req, 'codex-judge', `sha256:${'1'.repeat(64)}`), 'VRD-dddddddddddd-codex-judge-11111111');
  assert.equal(V.verdictId(req, 'gemini-judge'), null);
  assert.deepEqual(V.parseVerdictId(id), { head: 'dddddddddddd', mode: 'codex-judge', short: null });
  assert.equal(V.auditId(req), 'AUD-dddddddddddd');
  assert.equal(V.isAuditId('AUD-dddddddddddd-12345678'), true);
  assert.equal(V.isFindingRef(`${id}#finding-1`), true);
  for (const bad of [`${id}#`, `${id}#Finding`, 'VRD-x-judge#1', `${id}`, `${id}#a b`]) assert.equal(V.isFindingRef(bad), false, bad);
});

test('時刻：秒まで必須・時差は Z か ±HH:MM。+0900・時差なし・秒なし・ありえない日付は null。Kernel の +0900 は写す関数だけが読む', () => {
  assert.equal(V.parseTs('2026-11-14T09:00:00+09:00'), Date.parse('2026-11-14T00:00:00Z'));
  assert.equal(V.parseTs('2026-11-14T00:00:00.123Z'), Date.parse('2026-11-14T00:00:00.123Z'));
  for (const bad of ['2026-11-14T09:00:00+0900', '2026-11-14T09:00:00', '2026-11-14T09:00+09:00', '2026-02-30T00:00:00Z', '2026-11-14T24:00:00Z', '2026-11-14 09:00:00Z', '2026-11-14T09:00:00+15:00', 1, null]) assert.equal(V.parseTs(bad), null, String(bad));
  assert.equal(V.kernelTsToIso('2026-11-14T09:00:00+0900'), '2026-11-14T09:00:00+09:00');
  assert.equal(V.kernelTsToIso('2026-11-14T09:00:00+09:00'), '2026-11-14T09:00:00+09:00');
  assert.equal(V.kernelTsToIso('2026-11-14T09:00:00'), null);
});

test('法律の系統：pN.N.N と権限の表から pN.N を取る。先頭の 0・形の崩れは null', () => {
  assert.equal(V.policyLineOf('p0.4.15'), 'p0.4');
  assert.equal(V.policyLineOf(CAPS), 'p0.4');
  assert.equal(V.policyLineOf('p0.4.15a'), 'p0.4');
  for (const bad of ['p0.4', 'p0.04.1', 'v0.4.1', '', null, {}]) assert.equal(V.policyLineOf(bad), null, String(bad));
  assert.equal(V.isPolicyLine('p0.4'), true);
  assert.equal(V.isPolicyLine('p0.4.14'), false);
});

test('拒否の形：Refused(guard_violation) と violations の配列', () => {
  const e = V.refusal([{ guard: 'XX-A', reason: 'だめ' }]);
  assert.ok(e instanceof Refused);
  assert.equal(e.code, 'guard_violation');
  assert.deepEqual(e.violations, [{ guard: 'XX-A', reason: 'だめ' }]);
  assert.deepEqual([...V.STATUSES], ['ready', 'in_progress', 'review', 'held', 'merged', 'blocked']);
  assert.deepEqual([...V.VERDICTS], ['APPROVED', 'CHANGES_REQUIRED', 'UNAVAILABLE']);
  assert.deepEqual([...V.AUDIT_RESULTS], ['passed', 'failed', 'not_run']);
});

test('E-2：系統が役割で決まる役割（司法・立法補佐）は、表の系統だけを名乗れる（省略は補う）。審査の種類・runstate の必須の審査・team の型の系統と一貫している', async () => {
  const fixed = V.ROLES.filter((r) => V.ROLE_TABLE[r].lineage_fixed);
  assert.deepEqual(fixed.sort(), ['codex_judge', 'codex_security', 'constitutional_review', 'judge', 'legislative_assistant']);
  assert.deepEqual(V.normActor({ role: 'judge', kind: 'ai', id: 'j' }), { role: 'judge', kind: 'ai', id: 'j', lineage: 'claude' });
  assert.equal(V.normActor({ role: 'judge', kind: 'ai', id: 'j', lineage: 'codex' }), null);
  assert.equal(V.normActor({ role: 'constitutional_review', kind: 'ai', id: 'c', lineage: 'codex' }), null);
  assert.equal(V.normActor({ role: 'codex_judge', kind: 'ai', id: 'c', lineage: 'claude' }), null);
  assert.ok(V.normActor({ role: 'worker', kind: 'ai', id: 'w', lineage: 'codex' }), '行政の役割の系統は縛らない');
  assert.equal(V.normActor({ role: 'worker', kind: 'ai', id: 'w' }), null, '縛らない役割の系統は必須');
  for (const m of V.REVIEW_MODES) if (m.role) assert.equal(V.ROLE_TABLE[m.role].lineage, m.lineage, m.mode);
  const { DEFAULT_CONFIG } = await import('../runstate.mjs');
  for (const j of DEFAULT_CONFIG.judiciary) assert.ok(V.ROLE_TABLE[V.roleOfMode(V.reviewModeOf('judge', j.lineage))].lineage === j.lineage);
  const { catalogFromCapabilities } = await import('../team.mjs');
  const cat = catalogFromCapabilities(CAPS);
  for (const r of fixed.filter((x) => Object.hasOwn(cat, x))) assert.equal(cat[r].lineage, V.ROLE_TABLE[r].lineage, r);
});
