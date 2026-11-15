// runstate の攻撃・良性のシナリオ（起草段階の試作）
//
// 攻撃は「他の条件は正しいが、1つだけ違反している」出来事を、本物の状態（memoryRun で全ガードを通して作る）に対して検査する。
// verdict の結果に関わる攻撃（合格にしてはならないものを合格にする）は、結果を決める decide が壊れた（または改ざんされた）場合の備えを
// 示すため、素朴な（誤った）決め方の結果を ctx.result に入れて、ガードが止めるかを見る。
// 本物の decide が同じ入力で正しく動くことは、試験（test/runstate.test.mjs）で別に確かめる。
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { sha256, canonical } from '../lib/chain.mjs';
import { GUARDS, check, makeCtx, memoryRun, unsafeOpenRunWithClock, MAX_EVENTS, HUMAN_RESERVE, MAX_AI_PLANS, MAX_DEPS_TOTAL, MAX_PLAN_NODES, HUMAN_NODE_RESERVE, MAX_NODES_TOTAL, TIME_FUTURE_MS, DEFAULT_CONFIG } from '../runstate.mjs';

export const MODULE = 'runstate';
export { GUARDS };

const EX = { role: 'executive_head', kind: 'ai', id: 'max', lineage: 'claude' };
const OW = { role: 'owner', kind: 'human', id: 'azuki' };
const CT = { role: 'gate_runner', kind: 'script', id: 'gate_runner' };
const NA = { role: 'night_runner', kind: 'script', id: 'night_runner' };
const RP = { role: 'reaper', kind: 'script', id: 'reaper' };
const S1 = `sha256:${'a'.repeat(64)}`;
const S2 = `sha256:${'b'.repeat(64)}`;
const R1 = 'a1b2c3d4e5f6'.padEnd(40, '0'); // 申請の指紋（Git の 40 桁）
const R2 = 'f6e5d4c3b2a1'.padEnd(40, '0');
const J = (lineage, verdict = 'APPROVED', major = false, kind = 'judge') => ({ kind, judge: `${kind}_${lineage}`, lineage, verdict, major });
const AP2 = [J('claude'), J('codex')];
const SPLIT_MAJOR = [J('claude'), J('codex', 'CHANGES_REQUIRED', true)];
const SPLIT_MINOR = [J('claude'), J('codex', 'CHANGES_REQUIRED')];
const CR2 = [J('claude', 'CHANGES_REQUIRED'), J('codex', 'CHANGES_REQUIRED')];
const ONE = [AP2[0]];
const UNAV1 = [AP2[0], J('codex', 'UNAVAILABLE')];
const SEC_OK = J('codex', 'APPROVED', false, 'security');
const SEC_NG = J('codex', 'CHANGES_REQUIRED', true, 'security');

// ---- 世界の作り方 ----
export function mk(opt = {}, steps = null) {
  const { config = {}, ...rest } = opt;
  const r = memoryRun({ ...rest, config: { concurrent_work: 2, ...config } });
  let n = 0;
  r.id = () => `e${++n}`;
  if (steps) steps(r);
  return r;
}
const go = (r, actor, ev) => r.apply(actor, { event_id: r.id(), ...ev });
const plan = (r, nodes, supersede) => go(r, EX, { op: 'plan', nodes, ...(supersede ? { supersede } : {}) });
const N = (id, depends_on = [], resources = [`src/${id}/**`]) => ({ id, depends_on, resources });
/** 生成する節の id（config の票の ID の宣言の既定：T- と 3〜4 桁） */
const T = (i) => `T-${String(i).padStart(4, '0')}`;
const approve = (r, id, o = {}) => go(r, OW, { op: 'approve', node: id, spec_digest: o.spec || S1, policy_line: o.line || 'p0.4', def_digest: r.state().nodes[id].def_digest });
const start = (r, id, o = {}) => go(r, o.actor || EX, { op: 'start', node: id, spec_digest: o.spec || S1, lease_sec: o.lease || 3600 });
const submit = (r, id, req = R1) => go(r, EX, { op: 'submit', node: id, request: req });
const verdict = (r, id, req, audits, verdicts) => go(r, CT, { op: 'verdict', node: id, request: req, audits, verdicts });
const base3 = (r) => { plan(r, [N('T-001'), N('T-002'), N('T-003', ['T-001', 'T-002'])]); for (const id of ['T-001', 'T-002', 'T-003']) approve(r, id); };
const inProgressA = (r) => { base3(r); start(r, 'T-001'); };
const reviewA = (r) => { inProgressA(r); submit(r, 'T-001'); };
const mergedA = (r) => { reviewA(r); verdict(r, 'T-001', R1, 'passed', AP2); };
const heldA = (r) => { reviewA(r); verdict(r, 'T-001', R1, 'passed', AP2); }; // hold の世界で使う
const blockedDisagree = (r) => { reviewA(r); verdict(r, 'T-001', R1, 'passed', SPLIT_MAJOR); };
const returned3 = (r) => { inProgressA(r); for (let i = 0; i < 3; i += 1) { submit(r, 'T-001'); verdict(r, 'T-001', R1, 'failed', AP2); } submit(r, 'T-001'); };

// ---- 攻撃の定義 ----
// build: (r) => 世界の変更。event: 出来事（関数なら世界を受ける）。res: 誤った結果の上書き（関数）。at・actor: ctx の上書き。設定は記録の config の出来事（world の config）で決める
function ctxFor(def) {
  const r = mk(def.world || {}, def.build);
  if (def.after) def.after(r);
  const ev = typeof def.event === 'function' ? def.event(r) : def.event;
  const actor = typeof def.actor === 'function' ? def.actor(r) : (def.actor || EX);
  const o = { at: def.at === undefined ? r.now() : (typeof def.at === 'function' ? def.at(r) : def.at), wall: typeof def.wall === 'function' ? def.wall(r) : def.wall };
  if (def.res) o.result = def.res(r, ev);
  const withId = ev && typeof ev === 'object' && !Array.isArray(ev) && !('event_id' in ev) && !def.noId ? { event_id: 'zz-attack', ...ev } : ev;
  return makeCtx(r.st, actor, withId, o);
}
const run = (def) => (guardNames) => { const c = check(ctxFor(def), guardNames); return { blocked: !c.ok, by: c.violations.map((v) => v.guard) }; };
export const SCENARIOS = [];
const A = (id, title, expectGuards, def) => SCENARIOS.push({ id, kind: 'attack', title, expectGuards, run: run(def) });

const naive = (to, kind = 'pass') => (r, ev) => ({ op: 'verdict', node: ev.node, kind, to, patch: kind === 'return' ? { attempts: r.state().nodes[ev.node].attempts + 1 } : {} });
const holdWorld = { config: { hold: true } };
const tick = (r) => r.tick(3601e3);
const verdictEv = (audits, verdicts, req = R1) => ({ op: 'verdict', node: 'T-001', request: req, audits, verdicts });
const approveEv = (id) => (r) => ({ op: 'approve', node: id, spec_digest: S1, policy_line: 'p0.4', def_digest: r.state().nodes[id].def_digest });
const startEv = (id, spec = S1) => ({ op: 'start', node: id, spec_digest: spec, lease_sec: 3600 });

// -- 行為者（INV-05）--
A('RS-A1', '行政（ai）が verdict を起こす（role を gate_runner と名乗る。kind と合わない）', ['RS-ACTOR-SHAPE'], { build: reviewA, actor: { role: 'gate_runner', kind: 'ai', id: 'max', lineage: 'claude' }, event: verdictEv('passed', AP2) });
A('RS-A2', '行政（ai）が release を起こす（role owner の名乗り）', ['RS-ACTOR-SHAPE'], { world: holdWorld, build: heldA, actor: { role: 'owner', kind: 'ai', id: 'max', lineage: 'claude' }, event: { op: 'release', node: 'T-001', request: R1 },
  });
A('RS-A3', '行政（ai）が approve を起こす（自己承認）', ['RS-ACTOR-SHAPE'], { build: base3Unapproved, actor: { role: 'owner', kind: 'ai', id: 'max', lineage: 'claude' }, event: approveEv('T-001') });
A('RS-A4', '行政（ai）が unblock を起こす', ['RS-ACTOR-SHAPE'], { build: blockedDisagree, actor: { role: 'owner', kind: 'ai', id: 'max', lineage: 'claude' }, event: { op: 'unblock', node: 'T-001', reason: '再開する' } });
A('RS-A5', '行政（ai）が stop を起こす', ['RS-ACTOR-SHAPE'], { build: base3, actor: { role: 'owner', kind: 'ai', id: 'max', lineage: 'claude' }, event: { op: 'stop', reason: '止める' } });
A('RS-A6', '行政（ai）が rule を起こす（merge の裁定）', ['RS-ACTOR-SHAPE'], { build: blockedDisagree, actor: { role: 'owner', kind: 'ai', id: 'max', lineage: 'claude' }, event: { op: 'rule', node: 'T-001', request: R1, decision: 'merge', reason: '通す' } });
A('RS-A7', '行政（ai）が annul・resume・epoch を起こす（annul）', ['RS-ACTOR-SHAPE'], { build: (r) => { returned3(r); }, actor: { role: 'owner', kind: 'ai', id: 'max', lineage: 'claude' }, event: { op: 'annul', node: 'T-001', reason: '取り消す' } });
// rs.v2：役割と種類の対応は vocab（RS-ACTOR-SHAPE）が見るので、役割違いは種類の正しい行為者（行政の長 ai）で示す
A('RS-A8', '役割違い：行政の長（種類は正しい ai）が verdict を起こす', ['RS-ROLE-OP'], { build: reviewA, actor: EX, event: verdictEv('passed', AP2) });
A('RS-A9', '役割違い：行政の長（種類は正しい ai）が approve を起こす', ['RS-ROLE-OP'], { build: base3Unapproved, actor: EX, event: approveEv('T-001') });
A('RS-A10', '役割違い：裁判所の役割が start を起こす', ['RS-ROLE-OP'], { build: base3, actor: CT, event: startEv('T-001') });
A('RS-A11', '表記ゆれ：役割の o がキリル文字（大文字の Owner は vocab が小文字にそろえて受けるので、NFKC で畳まれない似た文字で示す）', ['RS-ACTOR-SHAPE'], { build: base3Unapproved, actor: { role: 'оwner', kind: 'human', id: 'azuki' }, event: approveEv('T-001') });
A('RS-A12', '表記ゆれ：役割にゼロ幅文字', ['RS-ACTOR-SHAPE'], { build: base3Unapproved, actor: { role: 'own​er', kind: 'human', id: 'azuki' }, event: approveEv('T-001') });
A('RS-A13', '表記ゆれ：種類が大文字（Human）', ['RS-ACTOR-SHAPE'], { build: base3Unapproved, actor: { role: 'owner', kind: 'Human', id: 'azuki' }, event: approveEv('T-001') });
A('RS-A14', '表記ゆれ：知らない役割（admin）・余分な項目', ['RS-ACTOR-SHAPE'], { build: base3Unapproved, actor: { role: 'admin', kind: 'human', id: 'azuki', extra: 1 }, event: approveEv('T-001') });
A('RS-A15', '表記ゆれ：役割が配列（型のゆれ）', ['RS-ACTOR-SHAPE'], { build: base3Unapproved, actor: { role: ['owner'], kind: 'human', id: 'azuki' }, event: approveEv('T-001') });
function base3Unapproved(r) { plan(r, [N('T-001'), N('T-002'), N('T-003', ['T-001', 'T-002'])]); }

// -- 出来事の形・時刻の申告 --
A('RS-A16', '期限切れの偽装：呼び出し側の申告の時刻（now）で expire', ['RS-EVENT-SHAPE', 'RS-EXPIRE-DUE'], { build: inProgressA, event: { op: 'expire', node: 'T-001', now: '2999-01-01T00:00:00+09:00' }, actor: RP });
A('RS-A17', '節の追加に見せかけて承認済み・統合済みの状態を持ち込む（plan の節に approved・status）', ['RS-EVENT-SHAPE'], { build: base3Unapproved, event: { op: 'plan', nodes: [{ ...N('T-004'), approved: true, status: 'merged' }] } });
A('RS-A18', 'event_id が大文字・空白入りの別綴り', ['RS-EVENT-SHAPE'], { build: base3, event: { event_id: 'E-1', op: 'stop', reason: '止める' }, actor: OW, noId: true });
A('RS-A19', '知らない出来事の種類（force_merge）', ['RS-EVENT-SHAPE'], { build: base3, event: { op: 'force_merge', node: 'T-001' } });
A('RS-A20', '同じ審査者が2回出る（1人を2人に数える）', ['RS-EVENT-SHAPE'], { build: reviewA, event: verdictEv('passed', [AP2[0], { ...AP2[0], lineage: 'codex' }]) });
A('RS-A21', 'verdicts が文字列（型のゆれ。fail-open にしない）', ['RS-EVENT-SHAPE'], { build: reviewA, event: { op: 'verdict', node: 'T-001', request: R1, audits: 'passed', verdicts: 'APPROVED' } });
A('RS-A22', 'major が文字列 "false"（真偽値の型のゆれ）', ['RS-EVENT-SHAPE'], { build: reviewA, event: verdictEv('passed', [{ ...AP2[0], major: 'false' }, AP2[1]]) });
A('RS-A23', '節の id が小文字（t-004。宣言の T- と別物として通さない）', ['RS-WORK-ITEM-ID'], { build: base3Unapproved, event: { op: 'plan', nodes: [N('t-004')] } });

// -- 同じ event_id・停止 --
A('RS-A24', '同じ event_id の二度目（違う内容。冪等の鍵の使い回し）', ['RS-EVENT-ID-UNIQUE'], { build: (r) => { base3Unapproved(r); r.apply(OW, { event_id: 'dup-1', op: 'approve', node: 'T-001', spec_digest: S1, policy_line: 'p0.4', def_digest: r.state().nodes['T-001'].def_digest }); },
  event: (r) => ({ event_id: 'dup-1', op: 'approve', node: 'T-001', spec_digest: S2, policy_line: 'p0.4', def_digest: r.state().nodes['T-001'].def_digest }), actor: OW, noId: true });
A('RS-A25', '停止中の start', ['RS-STOPPED'], { build: (r) => { base3(r); go(r, OW, { op: 'stop', reason: '停止する' }); }, event: startEv('T-001') });
A('RS-A26', '停止中の verdict（court の周回が続く）', ['RS-STOPPED'], { build: (r) => { reviewA(r); go(r, OW, { op: 'stop', reason: '停止する' }); }, actor: CT, event: verdictEv('passed', AP2) });
A('RS-A27', '停止中の plan・approve（approve）', ['RS-STOPPED'], { build: (r) => { base3Unapproved(r); go(r, OW, { op: 'stop', reason: '停止する' }); }, actor: OW, event: approveEv('T-001') });
A('RS-A28', '停止中でないのに resume', ['RS-STOP-STATE'], { build: base3, actor: OW, event: { op: 'resume', reason: '再開する' } });
A('RS-A29', 'すでに停止中なのに stop（記録を増やす）', ['RS-STOP-STATE'], { build: (r) => { base3(r); go(r, OW, { op: 'stop', reason: '停止する' }); }, actor: OW, event: { op: 'stop', reason: '二度目' } });
A('RS-A30', '出来事の数が上限（20000）に達した後の出来事', ['RS-SIZE-LIMIT'], { build: base3Unapproved, after: (r) => { r.st.count = MAX_EVENTS; }, actor: OW, event: approveEv('T-001') });
const cfgEv = (o) => ({ op: 'config', ...DEFAULT_CONFIG, ...o });
const stuff = (r, n) => { const base = r.st.nodes.get('T-001') || { depends_on: [], resources: [] }; for (let i = 0; r.st.nodes.size < n; i += 1) r.st.nodes.set(`stuff${i}`, { ...base, id: `stuff${i}` }); }; // 節の数を水増しした状態（試験用。order には入れない）
A('RS-A31', '節の数が上限（2000）を超える、オーナーの plan', ['RS-SIZE-LIMIT'], { build: base3Unapproved, after: (r) => stuff(r, MAX_NODES_TOTAL - 1), actor: OW, event: { op: 'plan', nodes: [N('T-101', [], []), N('T-102', [], [])] } });
A('RS-A121', '1回の plan で足せる節の数（200）を超える', ['RS-EVENT-SHAPE'], { build: base3Unapproved, event: { op: 'plan', nodes: Array.from({ length: MAX_PLAN_NODES + 1 }, (_, i) => N(T(i), [], [])) } });
A('RS-A122', '行政が節を足し続けて、オーナーのために取ってある節の枠（200）に踏み込む', ['RS-EVENT-QUOTA'], { build: base3Unapproved, after: (r) => stuff(r, MAX_NODES_TOTAL - HUMAN_NODE_RESERVE - 1), event: { op: 'plan', nodes: [N('T-101', [], []), N('T-102', [], [])] } });
// rs.v2：kind: human を名乗る行政の長は、役割と種類の不一致として RS-ACTOR-SHAPE が止める（RS-EVENT-QUOTA まで届かない）
A('RS-A123', 'kind: human を名乗る行政（role: executive_head）が、plan の回数の上限を回避する', ['RS-ACTOR-SHAPE'], { build: base3Unapproved, after: (r) => { r.st.ai_plans = MAX_AI_PLANS; }, actor: { role: 'executive_head', kind: 'human', id: 'max' }, event: { op: 'plan', nodes: [N('T-017', [], [])] } });
A('RS-A124', 'kind: human を名乗る行政が、オーナーのために取ってある出来事の枠を使う', ['RS-ACTOR-SHAPE'], { build: base3Unapproved, after: (r) => { r.st.count = MAX_EVENTS - HUMAN_RESERVE; }, actor: { role: 'executive_head', kind: 'human', id: 'max' }, event: { op: 'plan', nodes: [N('T-017', [], [])] } });
A('RS-A32', '規則の数値が許す範囲の外の config（必須の審査を空にする・差し戻しの上限 99）', ['RS-EVENT-SHAPE'], { build: base3Unapproved, actor: OW, event: cfgEv({ judiciary: [], max_returns: 99, reason: '弱める' }) });
A('RS-A33', 'lineage のハイフン入りの表記ゆれ（open-ai）を一覧に入れる config', ['RS-EVENT-SHAPE'], { build: base3Unapproved, actor: OW, event: cfgEv({ judiciary: [{ kind: 'judge', lineage: 'open-ai' }], reason: '系統を替える' }) });
A('RS-A91', 'config のない記録への plan（開く側の申告に頼らない。config 以外すべて拒む）', ['RS-CONFIG-REQUIRED'], { world: { noConfig: true }, event: { op: 'plan', nodes: [N('T-001')] } });
A('RS-A92', 'config のない記録への stop（人の操作も config 以外は拒む）', ['RS-CONFIG-REQUIRED'], { world: { noConfig: true }, actor: OW, event: { op: 'stop', reason: '止める' } });
A('RS-A93', '行政（ai）が config を起こす（上限を上げる）', ['RS-ACTOR-SHAPE'], { build: base3Unapproved, actor: { role: 'owner', kind: 'ai', id: 'max', lineage: 'claude' }, event: cfgEv({ concurrent_work: 64, reason: '広げる' }) });
A('RS-A94', '作業中（in_progress）に、同時の数を上げる config（緩める変更）', ['RS-CONFIG-TIGHTEN'], { build: inProgressA, actor: OW, event: cfgEv({ concurrent_work: 8, reason: '広げる' }) });
A('RS-A95', '夜間の合格（held）がある間に、hold を外す config', ['RS-CONFIG-TIGHTEN'], { world: holdWorld, build: heldA, actor: OW, event: cfgEv({ hold: false, reason: '外す' }) });
A('RS-A96', '申請中（review）に、必須の審査を減らす config', ['RS-CONFIG-TIGHTEN'], { build: reviewA, actor: OW, event: cfgEv({ judiciary: [{ kind: 'judge', lineage: 'claude' }], reason: '減らす' }) });
A('RS-A97', '作業中に、法律の系統の縛りを外す config（policy_line を null に）', ['RS-CONFIG-TIGHTEN'], { world: { config: { policy_line: 'p0.4' } }, build: inProgressA, actor: OW, event: cfgEv({ policy_line: null, reason: '外す' }) });
A('RS-A98', '理由なしの config の変更', ['RS-REASON'], { build: base3Unapproved, actor: OW, event: cfgEv({ concurrent_work: 1 }) });
A('RS-A99', '追記する側の実時間より 5 分以上先の時刻の行（未来の時刻で他人の lease を即座に expire する）', ['RS-TIME-FUTURE'], { build: inProgressA, at: (r) => r.now() + TIME_FUTURE_MS + 1000, wall: (r) => r.now(), actor: RP, event: { op: 'expire', node: 'T-001' } });
A('RS-A34', '記録の時刻が読めない（NaN）', ['RS-TIME-FUTURE'], { build: base3Unapproved, at: Number.NaN, actor: OW, event: approveEv('T-001') });
A('RS-A35', '理由なしの unblock', ['RS-REASON'], { build: blockedDisagree, actor: OW, event: { op: 'unblock', node: 'T-001' } });
A('RS-A36', '理由なしの resume', ['RS-REASON'], { build: (r) => { base3(r); go(r, OW, { op: 'stop', reason: '停止する' }); }, actor: OW, event: { op: 'resume' } });
A('RS-A37', '理由が空白だけの rule', ['RS-REASON', 'RS-EVENT-SHAPE'], { build: blockedDisagree, actor: OW, event: { op: 'rule', node: 'T-001', request: R1, decision: 'merge', reason: '   ' } });

// -- 節・遷移・凍結 --
A('RS-A38', 'ない節への approve', ['RS-NODE-EXISTS'], { build: base3Unapproved, actor: OW, event: { op: 'approve', node: 'T-999', spec_digest: S1, policy_line: 'p0.4', def_digest: S1 } });
A('RS-A39', '統合済みの節への approve（動かさない）', ['RS-FROZEN'], { build: mergedA, actor: OW, event: approveEv('T-001') });
A('RS-A40', '置き換え済みの節の unblock（承認の引き継ぎ・復活）', ['RS-FROZEN'], { build: (r) => { base3(r); plan(r, [N('T-012')], [{ old: 'T-001', new: 'T-012' }]); }, actor: OW, event: { op: 'unblock', node: 'T-001', reason: '戻す' } });
A('RS-A41', '統合済みの節の再着手', ['RS-FROZEN', 'RS-TRANSITION'], { build: mergedA, event: startEv('T-001') });
A('RS-A42', '作業中の節をもう一度 start（二重の着手）', ['RS-TRANSITION'], { build: inProgressA, event: startEv('T-001') });
A('RS-A43', 'ready の節を直接 submit（着手の飛ばし）', ['RS-TRANSITION'], { build: base3, event: { op: 'submit', node: 'T-001', request: R1 } });
A('RS-A44', '夜間の held を見ずに、作業中の節へ release', ['RS-TRANSITION', 'RS-REQUEST-MATCH'], { build: inProgressA, actor: OW, event: { op: 'release', node: 'T-001', request: R1 } });
A('RS-A45', 'merged になる迂回：夜間（hold）の合格を merged にする（held を飛ばす）', ['RS-MERGE-PATH'], { world: holdWorld, build: reviewA, actor: CT, event: verdictEv('passed', AP2), res: naive('merged') });
A('RS-A46', 'merged になる迂回：start の結果を merged にする', ['RS-MERGE-PATH', 'RS-TRANSITION'], { build: base3, event: startEv('T-001'), res: (r, ev) => ({ op: 'start', node: ev.node, to: 'merged', patch: {} }) });

// -- plan --
A('RS-A47', '節の追加に見せかけた既存の節（a）の範囲の書き換え', ['RS-PLAN-APPEND-ONLY'], { build: base3Unapproved, event: { op: 'plan', nodes: [N('T-001', [], ['src/**'])] } });
A('RS-A48', '節の追加に見せかけた既存の節（c）の依存の書き換え', ['RS-PLAN-APPEND-ONLY'], { build: base3Unapproved, event: { op: 'plan', nodes: [N('T-003', [], ['src/c/**'])] } });
A('RS-A49', '循環する節を追加', ['RS-PLAN-GRAPH'], { build: base3Unapproved, event: { op: 'plan', nodes: [N('T-024', ['T-025']), N('T-025', ['T-024'])] } });
A('RS-A50', '存在しない依存を持つ節を追加', ['RS-PLAN-GRAPH'], { build: base3Unapproved, event: { op: 'plan', nodes: [N('T-024', ['T-999'])] } });
A('RS-A51', '同じ id を2つ含む plan', ['RS-PLAN-GRAPH'], { build: base3Unapproved, event: { op: 'plan', nodes: [N('T-024'), N('T-024', [], ['other/**'])] } });
A('RS-A52', '統合済みの節を置き換える（supersede）', ['RS-PLAN-SUPERSEDE'], { build: mergedA, event: { op: 'plan', nodes: [N('T-012')], supersede: [{ old: 'T-001', new: 'T-012' }] } });
A('RS-A53', '置き換え先が計画にない（既存の節を新しい節として指す）', ['RS-PLAN-SUPERSEDE'], { build: base3, event: { op: 'plan', nodes: [N('T-012')], supersede: [{ old: 'T-001', new: 'T-002' }] } });
A('RS-A54', 'ない節を置き換える', ['RS-PLAN-SUPERSEDE'], { build: base3, event: { op: 'plan', nodes: [N('T-012')], supersede: [{ old: 'T-999', new: 'T-012' }] } });

// -- 承認・着手 --
A('RS-A55', '承認の後に定義が変わった（古い定義の指紋での承認）', ['RS-APPROVAL-FRESH'], { build: base3Unapproved, actor: OW, event: { op: 'approve', node: 'T-001', spec_digest: S1, policy_line: 'p0.4', def_digest: S2 } });
A('RS-A56', '未承認の節の start', ['RS-APPROVED'], { build: (r) => { plan(r, [N('T-001'), N('T-002')]); approve(r, 'T-002'); }, event: startEv('T-001') });
A('RS-A57', '置き換えた新しい節は承認を引き継がない（start）', ['RS-APPROVED'], { build: (r) => { base3(r); plan(r, [N('T-012')], [{ old: 'T-001', new: 'T-012' }]); }, event: startEv('T-012') });
A('RS-A58', '承認の後に仕様が変わった（着手時の仕様の指紋が違う）', ['RS-SPEC-DIGEST'], { build: base3, event: startEv('T-001', S2) });
A('RS-A59', '法律の系統が違う承認（p0.4 の承認で p0.5 の系統の着手）', ['RS-POLICY-LINE'], { world: { config: { policy_line: 'p0.5' } }, build: base3, event: startEv('T-001') });
A('RS-A60', '依存が未統合（review）の節 c の start', ['RS-DEPS-MERGED'], { build: (r) => { reviewA(r); }, event: startEv('T-003') });
A('RS-A61', '依存の一方だけ統合（b が未統合）の節 c の start', ['RS-DEPS-MERGED'], { build: mergedA, event: startEv('T-003') });
A('RS-A62', '依存が blocked の節の start', ['RS-DEPS-MERGED'], { build: blockedDisagree, event: startEv('T-003') });
A('RS-A63', '範囲の重なる節の同時の start（dir/** と dir/file）', ['RS-RESOURCE-DISJOINT'], { build: (r) => { plan(r, [N('T-024', [], ['src/shared/**']), N('T-025', [], ['src/shared/util.js'])]); approve(r, 'T-024'); approve(r, 'T-025'); start(r, 'T-024'); }, event: startEv('T-025') });
A('RS-A64', '範囲の重なる節の同時の start（大文字小文字だけ違う）', ['RS-RESOURCE-DISJOINT'], { build: (r) => { plan(r, [N('T-024', [], ['src/x']), N('T-025', [], ['Src/x'])]); approve(r, 'T-024'); approve(r, 'T-025'); start(r, 'T-024'); }, event: startEv('T-025') });
A('RS-A65', '同時の数の超過（concurrent_work=1 で2つ目）', ['RS-WORKER-LIMIT'], { world: { config: { concurrent_work: 1 } }, build: inProgressA, event: startEv('T-002') });
A('RS-A66', '同時の数の超過（concurrent_work=0：予算なし）', ['RS-WORKER-LIMIT'], { world: { config: { concurrent_work: 0 } }, build: base3, event: startEv('T-001') });
A('RS-A67', '着手の回数の上限（attempts）を超えた start', ['RS-ATTEMPTS'], { build: (r) => { inProgressA(r); tick(r); go(r, RP, { op: 'expire', node: 'T-001' }); go(r, OW, cfgEv({ max_attempts: 1, reason: '試行を絞る（締める変更）' })); }, event: startEv('T-001') });
A('RS-A68', '期限前の expire（他人の作業を奪う）', ['RS-EXPIRE-DUE'], { build: inProgressA, actor: RP, event: { op: 'expire', node: 'T-001' } });
A('RS-A69', '期限の1ミリ秒前の expire', ['RS-EXPIRE-DUE'], { build: inProgressA, after: (r) => r.tick(3600e3 - 1), actor: RP, event: { op: 'expire', node: 'T-001' } });

// -- 申請・司法・統合 --
A('RS-A70', '前の申請の合格の使い回し（別の申請の指紋で verdict）', ['RS-REQUEST-MATCH'], { build: reviewA, actor: CT, event: verdictEv('passed', AP2, R2) });
A('RS-A71', '別の申請の指紋で release', ['RS-REQUEST-MATCH'], { world: holdWorld, build: (r) => { reviewA(r); verdict(r, 'T-001', R1, 'passed', AP2); }, actor: OW, event: { op: 'release', node: 'T-001', request: R2 } });
A('RS-A72', '別の申請の指紋で rule（裁定の使い回し）', ['RS-REQUEST-MATCH'], { build: blockedDisagree, actor: OW, event: { op: 'rule', node: 'T-001', request: R2, decision: 'merge', reason: '通す' } });
A('RS-A73', '判定が分かれた以外の blocked（差し戻しの上限）を rule で通す', ['RS-RULE-SCOPE'], { build: (r) => { returned3(r); verdict(r, 'T-001', R1, 'passed', AP2); }, actor: OW, event: { op: 'rule', node: 'T-001', request: R1, decision: 'merge', reason: '通す' } });
A('RS-A74', '監査が not_run なのに合格（司法は全員 APPROVED）', ['RS-PASS-AUDIT'], { build: reviewA, event: verdictEv('not_run', AP2), actor: CT, res: naive('merged') });
A('RS-A75', '監査が failed なのに合格', ['RS-PASS-AUDIT'], { build: reviewA, event: verdictEv('failed', AP2), actor: CT, res: naive('merged') });
A('RS-A76', '判定が1つだけで合格（司法の欠落を合格とみなす。G15・G19）', ['RS-PASS-QUORUM'], { build: reviewA, event: verdictEv('passed', ONE), actor: CT, res: naive('merged') });
// rs.v2：知らない系統（open_ai）は vocab の系統の一覧になく、形の検査（RS-EVENT-SHAPE）で止まる
A('RS-A77', '一覧にない系統（open_ai）の結果を足して、必須の codex の代わりにする', ['RS-EVENT-SHAPE', 'RS-VERDICT-SET', 'RS-PASS-QUORUM'], { build: reviewA, event: verdictEv('passed', [AP2[0], J('open_ai')]), actor: CT });
A('RS-A78', '1つが UNAVAILABLE で、残り1つの APPROVED だけで合格（G15 の形）', ['RS-PASS-QUORUM'], { build: reviewA, event: verdictEv('passed', UNAV1), actor: CT, res: naive('merged') });
A('RS-A79', '分かれた判定（重大でない差し戻しが1つ）での合格', ['RS-PASS-CONSENSUS'], { build: reviewA, event: verdictEv('passed', SPLIT_MINOR), actor: CT, res: naive('merged') });
A('RS-A80', '重大な指摘で分かれた判定での合格', ['RS-PASS-CONSENSUS', 'RS-DISAGREE-BLOCK'], { build: reviewA, event: verdictEv('passed', SPLIT_MAJOR), actor: CT, res: naive('merged') });
A('RS-A81', '重大な指摘で分かれたのに差し戻しとして処理（裁定待ちにしない）', ['RS-DISAGREE-BLOCK'], { build: reviewA, event: verdictEv('passed', SPLIT_MAJOR), actor: CT, res: naive('in_progress', 'return') });
A('RS-A82', '差し戻しの上限を超えた再申請を合格にする', ['RS-RETURN-CAP'], { build: returned3, event: verdictEv('passed', AP2), actor: CT, res: naive('merged') });
A('RS-A83', '差し戻しの上限を超えた再申請を、また差し戻しにする（無限の再試行）', ['RS-RETURN-CAP'], { build: returned3, event: verdictEv('failed', AP2), actor: CT, res: naive('in_progress', 'return') });
A('RS-A84', '司法が使えないことを差し戻しに数える', ['RS-UNAVAILABLE-CAP'], { build: reviewA, event: verdictEv('passed', ONE), actor: CT, res: naive('in_progress', 'return') });
A('RS-A85', '同じ申請で司法が使えない3回目を blocked にしない（無限の待ち）', ['RS-UNAVAILABLE-CAP'],
  { build: (r) => { reviewA(r); verdict(r, 'T-001', R1, 'passed', ONE); verdict(r, 'T-001', R1, 'passed', ONE); }, event: verdictEv('passed', ONE), actor: CT, res: naive('review', 'unavailable') });

// -- 人の操作の出口・移行 --
A('RS-A86', '差し戻しが0回の節の annul（回数の水増し）', ['RS-ANNUL-BOUND'], { build: inProgressA, actor: OW, event: { op: 'annul', node: 'T-001', reason: '取り消す' } });
A('RS-A87', '上限で止まる再開（行き止まりを作る unblock。extra なし）', ['RS-UNBLOCK-PROGRESS'], { build: (r) => { returned3(r); verdict(r, 'T-001', R1, 'passed', AP2); }, actor: OW, event: { op: 'unblock', node: 'T-001', reason: '再開する' } });
A('RS-A88', '着手の上限で止まる再開（extra_attempts なし）', ['RS-UNBLOCK-PROGRESS'], { build: (r) => { inProgressA(r); r.st.nodes.get('T-001').attempts = 4; r.st.nodes.get('T-001').status = 'blocked'; r.st.nodes.get('T-001').blocked_reason = 'attempts_exhausted'; }, actor: OW, event: { op: 'unblock', node: 'T-001', reason: '再開する' } });
A('RS-A89', '移行の記録が、実際の最後の行と違うハッシュを覆う', ['RS-EPOCH-COVERS'], { build: base3, actor: OW, event: { op: 'epoch', covers: { count: 1, last_hash: '0'.repeat(64) }, reason: '移行する' } });
A('RS-A90', '移行の記録が、まだない行を覆う', ['RS-EPOCH-COVERS'], { build: base3, actor: OW, event: { op: 'epoch', covers: { count: 999, last_hash: '0'.repeat(64) }, reason: '移行する' } });


A('RS-A125', '長い lease（config の上限を超える）で範囲と枠を占める start', ['RS-LEASE-LIMIT'], { build: base3, event: { op: 'start', node: 'T-001', spec_digest: S1, lease_sec: 604800 } });
A('RS-A126', '作業中に、法律の系統を p0.4 から p0.3 に付け替える config（承認が効き直る）', ['RS-CONFIG-TIGHTEN'], { world: { config: { policy_line: 'p0.4' } }, build: inProgressA, actor: OW, event: cfgEv({ policy_line: 'p0.3', reason: '付け替える' }) });
// N3：未統合の申請を持つ blocked の節も範囲を占める。rule の return・unblock も範囲と同時の数を通す
const blockedShared = (r) => { plan(r, [N('T-024', [], ['src/shared/**']), N('T-025', [], ['src/shared/x.ts']), N('T-026')]); for (const id of ['T-024', 'T-025', 'T-026']) approve(r, id); start(r, 'T-024'); submit(r, 'T-024'); verdict(r, 'T-024', R1, 'passed', SPLIT_MAJOR); };
A('RS-A127', 'x が判定の不一致で blocked（オーナーの裁定待ち）の間に、範囲の重なる y を start', ['RS-RESOURCE-DISJOINT'], { build: blockedShared, event: startEv('T-025') });
A('RS-A128', 'rule の return で、重なる節が作業中のまま x を in_progress に戻す（状態を作り込んだ場合）', ['RS-RESOURCE-DISJOINT'],
  { build: (r) => { blockedShared(r); r.st.nodes.get('T-025').status = 'in_progress'; }, actor: OW, event: { op: 'rule', node: 'T-024', request: R1, decision: 'return', reason: 'やり直す' } });
A('RS-A129', '同時の数を締めた後の rule の return（作業中の別の節と合わせて上限を超える）', ['RS-WORKER-LIMIT'],
  { build: (r) => { plan(r, [N('T-024'), N('T-025')]); approve(r, 'T-024'); approve(r, 'T-025'); start(r, 'T-024'); start(r, 'T-025'); submit(r, 'T-024'); verdict(r, 'T-024', R1, 'passed', SPLIT_MAJOR); go(r, OW, cfgEv({ concurrent_work: 1, reason: '枠を締める' })); },
    actor: OW, event: { op: 'rule', node: 'T-024', request: R1, decision: 'return', reason: 'やり直す' } });
A('RS-A130', 'unblock で、範囲の重なる節が作業中のまま再開する（状態を作り込んだ場合）', ['RS-RESOURCE-DISJOINT'],
  { build: (r) => { blockedShared(r); r.st.nodes.get('T-025').status = 'in_progress'; r.st.nodes.get('T-024').attempts = 1; }, actor: OW, event: { op: 'unblock', node: 'T-024', reason: '再開する' } });

// -- F2：申請中（review）・held も範囲と同時の数に入る --
const sharedXY = (r) => { plan(r, [N('T-024', [], ['src/shared/**']), N('T-025', [], ['src/shared/x.ts']), N('T-026')]); for (const id of ['T-024', 'T-025', 'T-026']) approve(r, id); };
A('RS-A100', 'x が申請中（review）の間に、範囲の重なる y を start（差し戻せば両方が作業中になる）', ['RS-RESOURCE-DISJOINT'], { build: (r) => { sharedXY(r); start(r, 'T-024'); submit(r, 'T-024'); }, event: startEv('T-025') });
A('RS-A101', 'x が夜間の合格（held。オーナーの承認待ち）の間に、範囲の重なる y を start（held も範囲を占める）', ['RS-RESOURCE-DISJOINT'], { world: { config: { hold: true } }, build: (r) => { sharedXY(r); start(r, 'T-024'); submit(r, 'T-024'); verdict(r, 'T-024', R1, 'passed', AP2); }, event: startEv('T-025') });
A('RS-A102', 'concurrent_work=1 で x が申請中（review）の間に、重ならない z を start（review は枠を使う）', ['RS-WORKER-LIMIT'], { world: { config: { concurrent_work: 1 } }, build: (r) => { sharedXY(r); start(r, 'T-024'); submit(r, 'T-024'); }, event: startEv('T-026') });

// -- F3：必須の審査の一覧（config に固定）--
const secNode = (r) => { plan(r, [{ ...N('T-001'), security_review: true }, N('T-002'), N('T-003', ['T-001', 'T-002'])]); for (const id of ['T-001', 'T-002', 'T-003']) approve(r, id); start(r, 'T-001'); submit(r, 'T-001'); };
A('RS-A103', 'セキュリティ審査の印のある節に、セキュリティ審査の結果がない（2人の APPROVED だけで合格にする）', ['RS-PASS-QUORUM'], { build: secNode, event: verdictEv('passed', AP2), actor: CT, res: naive('merged') });
A('RS-A104', 'セキュリティ審査が UNAVAILABLE のまま、残りの2人の APPROVED で合格', ['RS-PASS-QUORUM'], { build: secNode, event: verdictEv('passed', [...AP2, J('codex', 'UNAVAILABLE', false, 'security')]), actor: CT, res: naive('merged') });
A('RS-A105', 'セキュリティ審査の印のない節に、余分なセキュリティ審査の結果を足す', ['RS-VERDICT-SET'], { build: reviewA, event: verdictEv('passed', [...AP2, SEC_OK]), actor: CT });
A('RS-A106', 'セキュリティ審査が不合格（major）なのに、不一致として blocked にする（裁定で通せるようにする）', ['RS-SECURITY-FAIL'], { build: secNode, event: verdictEv('passed', [...AP2, SEC_NG]), actor: CT, res: naive('blocked', 'blocked_disagreement') });
A('RS-A107', 'セキュリティ審査が不合格なのに、司法2人が APPROVED だからと合格にする', ['RS-SECURITY-FAIL', 'RS-PASS-CONSENSUS'], { build: secNode, event: verdictEv('passed', [...AP2, SEC_NG]), actor: CT, res: naive('merged') });
A('RS-A108', '全員が差し戻し（CHANGES_REQUIRED）なのに合格にする', ['RS-PASS-CONSENSUS'], { build: reviewA, event: verdictEv('passed', CR2), actor: CT, res: naive('merged') });
A('RS-A109', '同じ申請の指紋で通算の回数（2回済み）を、別の申請を挟んだ後の3回目で blocked にしない', ['RS-UNAVAILABLE-CAP'],
  { build: (r) => { reviewA(r); verdict(r, 'T-001', R1, 'passed', ONE); verdict(r, 'T-001', R1, 'passed', ONE); verdict(r, 'T-001', R1, 'failed', AP2); submit(r, 'T-001', R2); verdict(r, 'T-001', R2, 'failed', AP2); submit(r, 'T-001', R1); },
    event: verdictEv('passed', ONE), actor: CT, res: naive('review', 'unavailable') });
A('RS-A110', '差し戻しで in_progress に戻るのに、試行（attempts）を数えない', ['RS-ATTEMPTS-ON-RETURN'], { build: reviewA, event: verdictEv('failed', AP2), actor: CT, res: (r, ev) => ({ op: 'verdict', node: ev.node, kind: 'return', to: 'in_progress', patch: {} }) });
A('RS-A111', '試行の上限に達した票を、差し戻しで作業員の起動し直し（in_progress）にする', ['RS-ATTEMPTS-ON-RETURN'],
  { world: { config: { max_attempts: 1 } }, build: reviewA, event: verdictEv('failed', AP2), actor: CT, res: (r, ev) => ({ op: 'verdict', node: ev.node, kind: 'return', to: 'in_progress', patch: { returns: 1, attempts: 2 } }) });

// -- F4：行政が記録を使い切れない --
A('RS-A112', '行政（ai）が空の plan を送る', ['RS-PLAN-NONEMPTY'], { build: base3Unapproved, event: { op: 'plan', nodes: [] } });
A('RS-A113', '人以外の出来事の枠（上限 - 人の予備）が尽きた後の行政の plan', ['RS-EVENT-QUOTA'], { build: base3Unapproved, after: (r) => { r.st.count = MAX_EVENTS - HUMAN_RESERVE; }, event: { op: 'plan', nodes: [N('T-017')] } });
A('RS-A114', '行政（ai）の plan の回数が上限に達した後の plan', ['RS-EVENT-QUOTA'], { build: base3Unapproved, after: (r) => { r.st.ai_plans = MAX_AI_PLANS; }, event: { op: 'plan', nodes: [N('T-017')] } });
A('RS-A115', '依存の総数が上限を超える plan', ['RS-SIZE-LIMIT'], { build: base3Unapproved, after: (r) => { r.st.dep_total = MAX_DEPS_TOTAL; }, event: { op: 'plan', nodes: [N('T-017', ['T-001'])] } });
A('RS-A116', '1つの節の依存が 65 個（上限 64）', ['RS-EVENT-SHAPE'], { build: base3Unapproved, event: { op: 'plan', nodes: [N('T-017', Array.from({ length: 65 }, (_, i) => T(5000 + i)))] } });

// -- F5：置き換えの鎖 --
A('RS-A117', '置き換えの鎖が上限（8）を超える', ['RS-PLAN-SUPERSEDE'], { build: (r) => { base3Unapproved(r); r.st.nodes.get('T-001').gen = 8; }, event: { op: 'plan', nodes: [N('T-012')], supersede: [{ old: 'T-001', new: 'T-012' }] } });

// -- F6 --
A('RS-A118', '夜間の代行（night_runner）が着手した節を、別の行為者（行政 max）が submit', ['RS-WORKER-BIND'], { build: (r) => { base3(r); start(r, 'T-001', { actor: NA }); }, event: { op: 'submit', node: 'T-001', request: R1 } });
A('RS-A119', '行政（ai）が、夜間に合格して held（オーナーの release 待ち）の節を置き換えで消す', ['RS-PLAN-SUPERSEDE'], { world: holdWorld, build: heldA, event: { op: 'plan', nodes: [N('T-012')], supersede: [{ old: 'T-001', new: 'T-012' }] } });
A('RS-A120', '行政（ai）が、判定が分かれて blocked（オーナーの裁定待ち）の節を置き換えで消す', ['RS-PLAN-SUPERSEDE'], { build: blockedDisagree, event: { op: 'plan', nodes: [N('T-012')], supersede: [{ old: 'T-001', new: 'T-012' }] } });

// -- rs.v2：節の id は config の票の ID の宣言（vocab の work_item。既定は T- と 3〜4 桁、書いたとおり）--
// 全角（Ｔ－１０１）は入口の NFKC で T-101 にそろうので、ここでは NFKC で畳まれない文字（アラビア・インドの数字、キリル文字）で示す
A('RS-A131', '節の id が小文字（t-101。T-101 と別の節として通す）', ['RS-WORK-ITEM-ID'], { build: base3Unapproved, event: { op: 'plan', nodes: [N('t-101')] } });
A('RS-A132', '節の id の数字が NFKC で畳まれない別の数字（T-١٠١）', ['RS-WORK-ITEM-ID'], { build: base3Unapproved, event: { op: 'plan', nodes: [N('T-١٠١')] } });
A('RS-A133', '節の id の桁が足りない（T-01）', ['RS-WORK-ITEM-ID'], { build: base3Unapproved, event: { op: 'plan', nodes: [N('T-01')] } });
A('RS-A134', '節の id の桁が多すぎる（T-10000）', ['RS-WORK-ITEM-ID'], { build: base3Unapproved, event: { op: 'plan', nodes: [N('T-10000')] } });
A('RS-A135', '節の id の接頭辞が違う（TASK-101）', ['RS-WORK-ITEM-ID'], { build: base3Unapproved, event: { op: 'plan', nodes: [N('TASK-101')] } });
A('RS-A136', '節の id の T がキリル文字（Т-101。見た目は同じ）', ['RS-WORK-ITEM-ID'], { build: base3Unapproved, event: { op: 'plan', nodes: [N('Т-101')] } });
A('RS-A137', '置き換え先の id だけが宣言に合わない（supersede の new が t-012）', ['RS-WORK-ITEM-ID'], { build: base3, event: { op: 'plan', nodes: [N('t-012')], supersede: [{ old: 'T-001', new: 't-012' }] } });
A('RS-A138', 'config の宣言（JOB- と 2 桁）に合わない、既定の形（T-101）の節を足す', ['RS-WORK-ITEM-ID'], { world: { config: { work_item: { prefix: 'JOB-', digits: [2, 2] } } }, event: { op: 'plan', nodes: [N('T-101')] } });

// -- rs.v2：範囲は taskgraph が扱える形（literal・dir/**・prefix*）だけ --
A('RS-A139', '範囲に角括弧（src/[a]*）', ['RS-PLAN-RESOURCES'], { build: base3Unapproved, event: { op: 'plan', nodes: [N('T-101', [], ['src/[a]*'])] } });
A('RS-A140', '範囲に ?（src/?）', ['RS-PLAN-RESOURCES'], { build: base3Unapproved, event: { op: 'plan', nodes: [N('T-101', [], ['src/?'])] } });
A('RS-A141', '範囲が上の階層を指す（../x）', ['RS-PLAN-RESOURCES'], { build: base3Unapproved, event: { op: 'plan', nodes: [N('T-101', [], ['../x'])] } });
A('RS-A142', '範囲の途中に ..（src/a/../b）と、途中の *（src/*.js）', ['RS-PLAN-RESOURCES'], { build: base3Unapproved, event: { op: 'plan', nodes: [N('T-101', [], ['src/a/../b', 'src/*.js'])] } });
A('RS-A143', '範囲が ** だけ（全体を占める。taskgraph は扱えない）', ['RS-PLAN-RESOURCES'], { build: base3Unapproved, event: { op: 'plan', nodes: [N('T-101', [], ['**'])] } });

// -- rs.v2：保護された範囲（config.protected）と重なる節は計画に入れない（オーナーも）--
const protWorld = { config: { protected: ['vgdd/**'] } };
A('RS-A144', '保護された範囲の下（vgdd/kernel/**）を触る節を行政が足す', ['RS-PROTECTED'], { world: protWorld, build: base3Unapproved, event: { op: 'plan', nodes: [N('T-101', [], ['vgdd/kernel/**'])] } });
A('RS-A145', '保護された範囲そのもの（vgdd/**）を触る節', ['RS-PROTECTED'], { world: protWorld, build: base3Unapproved, event: { op: 'plan', nodes: [N('T-101', [], ['src/ok/**', 'vgdd/**'])] } });
A('RS-A146', '保護された範囲の大文字の別綴り（VGDD/x）', ['RS-PROTECTED'], { world: protWorld, build: base3Unapproved, event: { op: 'plan', nodes: [N('T-101', [], ['VGDD/x'])] } });
A('RS-A147', 'オーナーの plan でも、保護された範囲（vgdd/kernel/hooks/guard.sh）を触る節は入れない', ['RS-PROTECTED'], { world: protWorld, build: base3Unapproved, actor: OW, event: { op: 'plan', nodes: [N('T-101', [], ['vgdd/kernel/hooks/guard.sh'])] } });
A('RS-A148', '前置きの * で保護された範囲にかかる（vgd*）', ['RS-PROTECTED'], { world: protWorld, build: base3Unapproved, event: { op: 'plan', nodes: [N('T-101', [], ['vgd*'])] } });

// -- rs.v2：統合の参照（merge）は merged になる出来事だけが持てる --
const M1 = '0123456789abcdef0123456789abcdef01234567';
A('RS-A149', '差し戻しになる verdict に統合の参照（merge）を付ける（追跡に偽の統合を残す）', ['RS-MERGE-REF'], { build: reviewA, actor: CT, event: { ...verdictEv('failed', AP2), merge: M1 } });
A('RS-A150', '司法が使えない（review のまま）の verdict に merge を付ける', ['RS-MERGE-REF'], { build: reviewA, actor: CT, event: { ...verdictEv('passed', ONE), merge: M1 } });
A('RS-A151', '夜間の合格（held。統合はまだ）の verdict に merge を付ける', ['RS-MERGE-REF'], { world: holdWorld, build: reviewA, actor: CT, event: { ...verdictEv('passed', AP2), merge: M1 } });
A('RS-A152', 'オーナーの rule の return（やり直し）に merge を付ける', ['RS-MERGE-REF'], { build: blockedDisagree, actor: OW, event: { op: 'rule', node: 'T-001', request: R1, decision: 'return', reason: 'やり直す', merge: M1 } });

// ---- 良性 ----
// ---- 独立した審査 E-7：計画の後に足した保護も、作業に入る出来事で見る ----
const protLater = (r) => { plan(r, [N('T-001', [], ['vgdd/kernel/x'])]); approve(r, 'T-001'); go(r, OW, cfgEv({ concurrent_work: 2, protected: ['vgdd/**'], reason: '統治の核を保護する（締める）' })); };
A('RS-A153', 'E-7：計画の後に保護を足しても、計画済みの節（vgdd/kernel/x）を start する', ['RS-PROTECTED'], { build: protLater, event: startEv('T-001') });
A('RS-A154', 'E-7：保護に重なる blocked の節を unblock で作業に戻す', ['RS-PROTECTED'], {
  build: (r) => { plan(r, [N('T-001', [], ['vgdd/x'])]); approve(r, 'T-001'); start(r, 'T-001'); submit(r, 'T-001'); verdict(r, 'T-001', R1, 'passed', SPLIT_MAJOR); go(r, OW, cfgEv({ concurrent_work: 2, protected: ['vgdd/**'], reason: '締める' })); },
  actor: OW, event: { op: 'unblock', node: 'T-001', reason: '再開' } });
A('RS-A155', 'E-7：保護に重なる blocked の節を rule の return で作業に戻す', ['RS-PROTECTED'], {
  build: (r) => { plan(r, [N('T-001', [], ['vgdd/x'])]); approve(r, 'T-001'); start(r, 'T-001'); submit(r, 'T-001'); verdict(r, 'T-001', R1, 'passed', SPLIT_MAJOR); go(r, OW, cfgEv({ concurrent_work: 2, protected: ['vgdd/**'], reason: '締める' })); },
  actor: OW, event: { op: 'rule', node: 'T-001', request: R1, decision: 'return', reason: 'やり直す' } });

// ---- 独立した審査（4 回目）R-1：作業中の節に重なる保護を後から足したとき、申請・判定・統合で止める ----
// 本物の結果（computeResult）は blocked（protected）を出す。攻撃は、結果を決める部分が壊れた・改ざんされた場合の備えとして、
// 素朴な（保護を見ない）結果を ctx.result に入れて、RS-PROTECTED が止めるかを見る。範囲の表記ゆれ（大文字・全角・前置きの *・下の **）の変種つき
const PROT_SPELL = [['', 'vgdd/kernel/x'], ['大文字', 'VGDD/x'], ['大文字小文字の混在', 'Vgdd/Kernel/x'], ['全角', 'ｖｇｄｄ/x'], ['前置きの *', 'vgd*'], ['下の **', 'vgdd/kernel/**']];
const protOn = (r) => go(r, OW, cfgEv({ ...r.state().config, protected: ['vgdd/**'], reason: '統治の核を保護する（締める）' }));
const protInProgress = (res, o = {}) => (r) => { plan(r, [{ ...N('T-001', [], [res]), ...(o.sec ? { security_review: true } : {}) }]); approve(r, 'T-001'); start(r, 'T-001'); if (o.review || o.held) submit(r, 'T-001'); if (o.held) verdict(r, 'T-001', R1, 'passed', AP2); protOn(r); };
PROT_SPELL.forEach(([label, res], i) => {
  const sfx = label ? `（範囲の綴り：${label} ${res}）` : '';
  A(`RS-A${156 + i * 4}`, `R-1：保護を足した後、作業中の節（${res}）の submit を review に進める${sfx}`, ['RS-PROTECTED'], {
    build: protInProgress(res), event: { op: 'submit', node: 'T-001', request: R1 }, res: (r, ev) => ({ op: 'submit', node: ev.node, to: 'review', patch: { request: R1 } }) });
  A(`RS-A${157 + i * 4}`, `R-1：保護を足した後、申請中の節の差し戻し（重大でない CHANGES_REQUIRED）で作業を続ける${sfx}`, ['RS-PROTECTED'], {
    build: protInProgress(res, { review: true }), actor: CT, event: verdictEv('passed', CR2), res: naive('in_progress', 'return') });
  A(`RS-A${158 + i * 4}`, `R-1：保護を足した後、申請中の節を verdict の合格で統合する${sfx}`, ['RS-PROTECTED'], {
    build: protInProgress(res, { review: true }), actor: CT, event: verdictEv('passed', AP2), res: naive('merged') });
  A(`RS-A${159 + i * 4}`, `R-1：保護を足した後、夜間に合格した節（held）を release で統合する${sfx}`, ['RS-PROTECTED'], {
    world: holdWorld, build: protInProgress(res, { held: true }), actor: OW, event: { op: 'release', node: 'T-001', request: R1 }, res: (r, ev) => ({ op: 'release', node: ev.node, to: 'merged', patch: {} }) });
});
A('RS-A180', 'R-1：保護と重なって止めた申請（審査に合格していない）を、オーナーの裁定で統合する', ['RS-PROTECTED'], {
  build: (r) => { protInProgress('vgdd/x')(r); submit(r, 'T-001'); }, actor: OW, event: { op: 'rule', node: 'T-001', request: R1, decision: 'merge', reason: '通す' } });
A('RS-A181', 'R-1：保護と重なって差し戻しで止めた申請を、オーナーの裁定で統合する', ['RS-PROTECTED'], {
  build: (r) => { protInProgress('VGDD/x', { review: true })(r); verdict(r, 'T-001', R1, 'passed', CR2); }, actor: OW, event: { op: 'rule', node: 'T-001', request: R1, decision: 'merge', reason: '通す' } });
A('RS-A182', 'R-1：保護の判断待ち（blocked: protected）の節を、行政が置き換えで消す', ['RS-PLAN-SUPERSEDE'], {
  build: (r) => { protInProgress('vgdd/x')(r); submit(r, 'T-001'); }, event: { op: 'plan', nodes: [N('T-012')], supersede: [{ old: 'T-001', new: 'T-012' }] } });
A('RS-A183', 'R-1：セキュリティ審査の不合格の申請を、保護で止めるときに裁定で統合できる形（rule_merge_ok）にする', ['RS-SECURITY-FAIL'], {
  build: protInProgress('vgdd/x', { review: true, sec: true }), actor: CT, event: verdictEv('passed', [...AP2, SEC_NG]),
  res: (r, ev) => ({ op: 'verdict', node: ev.node, kind: 'blocked_protected', to: 'blocked', patch: { blocked_reason: 'protected', rule_merge_ok: true } }) });

function benign(id, title, flow) {
  SCENARIOS.push({ id, kind: 'benign', title, run: (guardNames) => {
    try {
      const w = (opt = {}) => { const r = mk({ guardNames, ...opt }); return r; };
      flow(w);
      return { blocked: false, by: [] };
    } catch (e) {
      if (e && e.violations) return { blocked: true, by: e.violations.map((v) => v.guard) };
      throw e;
    }
  } });
}
const expect = (c, m) => { if (!c) throw new Error(`良性の流れの結果が違う: ${m}`); };
const st = (r, id) => r.state().nodes[id].status;

benign('RS-B1', '3つの節（a、b は独立、c は a と b に依存）を、承認→着手→申請→合格→統合まで通す', (w) => {
  const r = w();
  plan(r, [N('T-001'), N('T-002'), N('T-003', ['T-001', 'T-002'])]);
  for (const id of ['T-001', 'T-002', 'T-003']) approve(r, id);
  start(r, 'T-001'); start(r, 'T-002'); // 範囲が重ならず、同時の数の上限（2）に収まる
  for (const id of ['T-001', 'T-002']) { submit(r, id, R1); verdict(r, id, R1, 'passed', AP2); }
  start(r, 'T-003'); submit(r, 'T-003', R2); verdict(r, 'T-003', R2, 'passed', AP2);
  expect(['T-001', 'T-002', 'T-003'].every((id) => st(r, id) === 'merged'), 'すべて merged');
});
benign('RS-B2', '差し戻し→再申請→合格', (w) => {
  const r = w(); inProgressA(r);
  submit(r, 'T-001', R1); verdict(r, 'T-001', R1, 'failed', AP2);
  expect(st(r, 'T-001') === 'in_progress' && r.state().nodes['T-001'].returns === 1, '差し戻し');
  submit(r, 'T-001', R2); verdict(r, 'T-001', R2, 'passed', AP2);
  expect(st(r, 'T-001') === 'merged', '合格');
});
benign('RS-B3', '司法が使えない→戻った周回で合格（差し戻しに数えない）', (w) => {
  const r = w(); reviewA(r);
  verdict(r, 'T-001', R1, 'passed', ONE);
  expect(st(r, 'T-001') === 'review' && r.state().nodes['T-001'].returns === 0 && Object.values(r.state().nodes['T-001'].unavail)[0] === 1, '使えない');
  verdict(r, 'T-001', R1, 'passed', AP2);
  expect(st(r, 'T-001') === 'merged', '合格');
});
benign('RS-B4', '夜間の held → オーナーの release', (w) => {
  const r = w({ config: { hold: true } }); reviewA(r);
  verdict(r, 'T-001', R1, 'passed', AP2);
  expect(st(r, 'T-001') === 'held', 'held');
  go(r, OW, { op: 'release', node: 'T-001', request: R1 });
  expect(st(r, 'T-001') === 'merged', 'merged');
});
benign('RS-B5', '分かれた判定 → オーナーの裁定（merge）', (w) => {
  const r = w(); blockedDisagree(r);
  expect(st(r, 'T-001') === 'blocked', 'blocked');
  go(r, OW, { op: 'rule', node: 'T-001', request: R1, decision: 'merge', reason: '指摘は軽微と判断した' });
  expect(st(r, 'T-001') === 'merged', 'merged');
});
benign('RS-B6', '停止 → 再開 → 続行', (w) => {
  const r = w(); inProgressA(r);
  go(r, OW, { op: 'stop', reason: '点検する' });
  go(r, OW, { op: 'resume', reason: '点検した' });
  submit(r, 'T-001'); verdict(r, 'T-001', R1, 'passed', AP2);
  expect(st(r, 'T-001') === 'merged', '続行');
});
benign('RS-B7', 'b が未承認のままでも a は最後まで進む（INV-12）', (w) => {
  const r = w(); plan(r, [N('T-001'), N('T-002'), N('T-003', ['T-002'])]); approve(r, 'T-001');
  start(r, 'T-001'); submit(r, 'T-001'); verdict(r, 'T-001', R1, 'passed', AP2);
  expect(st(r, 'T-001') === 'merged' && st(r, 'T-002') === 'ready' && r.next().start.length === 0, 'a だけ進む');
});
benign('RS-B8', '前後の空白・全角の行為者の表記は正規化されて受け入れる', (w) => {
  const r = w(); plan(r, [N('T-001')]);
  r.apply({ role: ' ｏｗｎｅｒ ', kind: 'human', id: 'azuki' }, { event_id: 'e-x', op: 'approve', node: 'T-001', spec_digest: S1, policy_line: 'p0.4', def_digest: r.state().nodes['T-001'].def_digest });
  expect(r.state().nodes['T-001'].approved, '承認');
});
benign('RS-B9', '期限ちょうどの expire → ready に戻って再着手（attempts は戻らない）', (w) => {
  const r = w(); inProgressA(r); r.tick(3600e3);
  go(r, RP, { op: 'expire', node: 'T-001' });
  expect(st(r, 'T-001') === 'ready' && r.state().nodes['T-001'].attempts === 1, 'ready');
  start(r, 'T-001'); expect(r.state().nodes['T-001'].attempts === 2, '再着手');
});
benign('RS-B10', '置き換え（supersede）：新しい節を承認し直せば、依存していた節も進める', (w) => {
  const r = w(); base3(r);
  plan(r, [N('T-012')], [{ old: 'T-001', new: 'T-012' }]);
  approve(r, 'T-012'); start(r, 'T-012'); submit(r, 'T-012'); verdict(r, 'T-012', R1, 'passed', AP2);
  start(r, 'T-002'); submit(r, 'T-002', R2); verdict(r, 'T-002', R2, 'passed', AP2);
  start(r, 'T-003');
  expect(st(r, 'T-003') === 'in_progress' && st(r, 'T-001') === 'blocked', '置き換え先が統合されれば c が進む');
});
benign('RS-B11', '上限で止まった節を、オーナーが追加の回数つきで再開して合格', (w) => {
  const r = w(); returned3(r); verdict(r, 'T-001', R1, 'passed', AP2);
  expect(st(r, 'T-001') === 'blocked', '上限で blocked');
  go(r, OW, { op: 'unblock', node: 'T-001', reason: '司法の環境を直した', extra_returns: 1, extra_attempts: 1 });
  start(r, 'T-001'); submit(r, 'T-001', R2); verdict(r, 'T-001', R2, 'passed', AP2);
  expect(st(r, 'T-001') === 'merged' && r.state().nodes['T-001'].returns === 3, '合格（回数は戻していない）');
});
benign('RS-B12', '同じ event_id・同じ内容の二度目は何も起こさない（冪等）', (w) => {
  const r = w(); plan(r, [N('T-001')]);
  const ev = { event_id: 'same-1', op: 'approve', node: 'T-001', spec_digest: S1, policy_line: 'p0.4', def_digest: r.state().nodes['T-001'].def_digest };
  r.apply(OW, ev); const c = r.state().count;
  const second = r.apply(OW, ev);
  expect(second.duplicate === true && r.state().count === c, '二度目は効かない');
});
benign('RS-B13', 'オーナーによる annul で差し戻しの数を減らす', (w) => {
  const r = w(); inProgressA(r); submit(r, 'T-001'); verdict(r, 'T-001', R1, 'failed', AP2);
  go(r, OW, { op: 'annul', node: 'T-001', reason: '法律の不具合による差し戻し' });
  expect(r.state().nodes['T-001'].returns === 0, '数えない');
});
benign('RS-B14', 'night_runner（スクリプト）の start と reaper の expire', (w) => {
  const r = w(); base3(r); start(r, 'T-001', { actor: NA }); r.tick(3600e3); go(r, RP, { op: 'expire', node: 'T-001' });
  expect(st(r, 'T-001') === 'ready', 'ready');
});

benign('RS-B16', '重大でない指摘だけで分かれた判定は、指摘を記録に残して合格（法律 §3.1 の 8。kind: pass_minor_disagreement）', (w) => {
  const r = w(); reviewA(r);
  const res = verdict(r, 'T-001', R1, 'passed', SPLIT_MINOR);
  expect(res.kind === 'pass_minor_disagreement' && st(r, 'T-001') === 'merged', '合格');
});
benign('RS-B17', 'セキュリティ審査の印のある節：3つの結果がそろって APPROVED なら合格。不合格なら差し戻し（裁定で通せない）', (w) => {
  const r = w(); secNode(r);
  expect(verdict(r, 'T-001', R1, 'passed', [...AP2, SEC_NG]).kind === 'return', '差し戻し');
  submit(r, 'T-001', R2);
  expect(verdict(r, 'T-001', R2, 'passed', [...AP2, SEC_OK]).kind === 'pass' && st(r, 'T-001') === 'merged', '合格');
});
benign('RS-B18', 'held（人の承認待ち）の節は作業員の枠を使わない。範囲の重ならない節は concurrent_work=1 でも着手できる', (w) => {
  const r = w({ config: { hold: true, concurrent_work: 1 } }); sharedXY(r);
  start(r, 'T-024'); submit(r, 'T-024'); verdict(r, 'T-024', R1, 'passed', AP2);
  expect(st(r, 'T-024') === 'held', 'held');
  start(r, 'T-026'); expect(st(r, 'T-026') === 'in_progress', '着手');
});
benign('RS-B19', '行政が予測した event_id を先に使っても、オーナーの同じ id の stop は通る（役割と op の組ごとの一意性）', (w) => {
  const r = w(); plan(r, [N('T-001')]);
  r.apply(EX, { event_id: 'stop-20260101', op: 'plan', nodes: [N('T-002')] });
  r.apply(OW, { event_id: 'stop-20260101', op: 'stop', reason: '止める' });
  expect(r.state().stopped === true, '停止');
});
benign('RS-B20', 'config：締める変更はいつでも、緩める変更は作業中の節がないときだけ', (w) => {
  const r = w(); inProgressA(r);
  go(r, OW, cfgEv({ concurrent_work: 1, max_returns: 2, reason: '締める' }));
  expect(r.state().config.concurrent_work === 1, '締める変更は作業中でも通る');
  const r2 = w(); base3(r2);
  go(r2, OW, cfgEv({ concurrent_work: 8, reason: '作業中の節がないので緩められる' }));
  expect(r2.state().config.concurrent_work === 8, '緩める変更');
});
benign('RS-B21', '行政（ai）が、オーナーの判断待ちでない blocked の節（置き換えの対象）を置き換える', (w) => {
  const r = w(); base3(r); plan(r, [N('T-012')], [{ old: 'T-001', new: 'T-012' }]);
  expect(st(r, 'T-001') === 'blocked' && r.state().nodes['T-001'].superseded_by === 'T-012', '置き換え');
});
benign('RS-B22', '差し戻しで in_progress に戻るときも attempts を数える（着手1回＋差し戻し1回＝2）', (w) => {
  const r = w(); inProgressA(r); submit(r, 'T-001'); verdict(r, 'T-001', R1, 'failed', AP2);
  expect(r.state().nodes['T-001'].attempts === 2, 'attempts');
});
benign('RS-B23', '要件の ID（requirements）つきの節を計画して、承認→統合まで通す', (w) => {
  const r = w();
  plan(r, [{ ...N('T-001'), requirements: ['R-2', 'A1'] }]);
  expect(JSON.stringify(r.state().nodes['T-001'].requirements) === '["A1","R-2"]', '要件は並べ替えて残る');
  approve(r, 'T-001'); start(r, 'T-001'); submit(r, 'T-001'); verdict(r, 'T-001', R1, 'passed', AP2);
  expect(st(r, 'T-001') === 'merged', 'merged');
});
benign('RS-B24', '判定の参照（refs）と統合の参照（merge）つきの合格の verdict', (w) => {
  const r = w(); reviewA(r);
  const h = R1.slice(0, 12);
  const refs = { verdicts: [{ kind: 'judge', lineage: 'claude', id: `VRD-${h}-judge` }, { kind: 'judge', lineage: 'codex', id: `VRD-${h}-codex-judge` }], findings: [`VRD-${h}-codex-judge#f1`], audit: { id: `AUD-${h}` } };
  go(r, CT, { ...verdictEv('passed', AP2), refs, merge: M1 });
  expect(st(r, 'T-001') === 'merged' && r.state().nodes['T-001'].merge === M1, '統合の参照が残る');
});
benign('RS-B25', '着手に作業員（assignee：worker の行為者）を記録する', (w) => {
  const r = w(); base3(r);
  go(r, EX, { ...startEv('T-001'), assignee: { role: 'worker', kind: 'ai', id: 'w1', lineage: 'codex' } });
  const n = r.state().nodes['T-001'];
  expect(n.status === 'in_progress' && n.assignee.id === 'w1' && n.started_by === 'max', '着手した行為者と作業員');
});
benign('RS-B26', '保護された範囲（vgdd/**）の外の節は計画できる。夜間の release に統合の参照を付けられる', (w) => {
  const r = w({ config: { protected: ['vgdd/**'], hold: true } });
  plan(r, [N('T-001', [], ['src/app/**', 'docs/vgdd.md'])]);
  approve(r, 'T-001'); start(r, 'T-001'); submit(r, 'T-001'); verdict(r, 'T-001', R1, 'passed', AP2);
  go(r, OW, { op: 'release', node: 'T-001', request: R1, merge: M1 });
  expect(st(r, 'T-001') === 'merged' && r.state().nodes['T-001'].merge === M1, 'merged');
});

// 途中で落ちた想定：記録を開き直して同じ状態が作り直せ、続きができる（ファイルを使う）
SCENARIOS.push({ id: 'RS-B15', kind: 'benign', title: '落ちた想定：記録を開き直して同じ状態が作り直せ、続きができる', run: () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vgdd-next-rs-'));
  try {
    const file = path.join(dir, 'run.jsonl');
    let t = Date.parse('2026-01-01T00:00:00+09:00');
    const now = () => new Date((t += 1000)).toISOString().replace('Z', '+00:00');
    const run1 = unsafeOpenRunWithClock(file, { now });
    let n = 0; const ap = (rr, a, ev) => rr.apply(a, { event_id: `f${++n}`, ...ev });
    ap(run1, OW, cfgEv({ concurrent_work: 2 }));
    ap(run1, EX, { op: 'plan', nodes: [N('T-001'), N('T-002', ['T-001'])] });
    ap(run1, OW, { op: 'approve', node: 'T-001', spec_digest: S1, policy_line: 'p0.4', def_digest: run1.state().nodes['T-001'].def_digest });
    ap(run1, EX, { op: 'start', node: 'T-001', spec_digest: S1, lease_sec: 600 });
    const before = JSON.stringify(run1.state());
    const run2 = unsafeOpenRunWithClock(file, { now }); // 落ちて開き直した
    if (JSON.stringify(run2.state()) !== before || !run2.verify().ok) return { blocked: true, by: ['（再生が一致しない）'] };
    ap(run2, EX, { op: 'submit', node: 'T-001', request: R1 });
    ap(run2, CT, { op: 'verdict', node: 'T-001', request: R1, audits: 'passed', verdicts: AP2 });
    return { blocked: run2.state().nodes['T-001'].status !== 'merged', by: [] };
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
} });

// ---- 性能の測定 ----
/** 鎖つき記録のファイルを、chain.mjs と同じ形式で直接書く（追記のたびに全行を確かめる追記を数千回呼ぶと遅いので、準備だけ直接書く） */
function writeChain(file, rows) {
  let prev = 'genesis'; const lines = [];
  rows.forEach((r, i) => { const full = { ...r.body, seq: i + 1, at: r.at, prev }; const hash = sha256(canonical(full)); lines.push(JSON.stringify({ ...full, hash })); prev = hash; });
  fs.writeFileSync(file, `${lines.join('\n')}\n`);
  fs.writeFileSync(`${file}.head`, `${JSON.stringify({ seq: rows.length, hash: prev })}\n`);
}
/**
 * 節 n・出来事 約 events の記録を作り、state() と apply() 1回・next() の所要時間を測る（ms）。
 * 記録は memoryRun（全ガードを通す）で作って chain 形式で書く。apply は別のプロセス相当（開き直し直後）の最初の1回と、続けての1回を測る。
 */
export function benchRun(n = 500, events = 5000) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vgdd-next-rsb-'));
  try {
    const m = memoryRun({ config: { concurrent_work: 8 }, start: '2026-01-01T00:00:00+09:00' });
    let k = 0; const ap = (a, ev) => { m.tick(1000); return m.apply(a, { event_id: `b${++k}`, ...ev }); };
    const nodes = Array.from({ length: n }, (_, i) => N(T(i), i >= 8 ? [T(i - 8)] : [], [`src/n${i}/**`]));
    for (let i = 0; i < n; i += 100) ap(EX, { op: 'plan', nodes: nodes.slice(i, i + 100) });
    const defs = m.state().nodes;
    let i = 0;
    // 出来事の数が events に届くまで、節ごとに 承認・着手・（申請・不合格・差し戻しの取り消し）×2・申請・合格（10 出来事）を進める
    while (k < events - 60 && i < n) {
      const id = T(i);
      ap(OW, { op: 'approve', node: id, spec_digest: S1, policy_line: 'p0.4', def_digest: defs[id].def_digest });
      ap(EX, { op: 'start', node: id, spec_digest: S1, lease_sec: 600 });
      for (let c = 0; c < 2; c += 1) { ap(EX, { op: 'submit', node: id, request: R1 }); ap(CT, { op: 'verdict', node: id, request: R1, audits: 'failed', verdicts: AP2 }); ap(OW, { op: 'annul', node: id, reason: '試験' }); }
      ap(EX, { op: 'submit', node: id, request: R2 });
      ap(CT, { op: 'verdict', node: id, request: R2, audits: 'passed', verdicts: AP2 });
      i += 1;
    }
    const file = path.join(dir, 'run.jsonl');
    writeChain(file, m.rows);
    const base = m.now() + 1000;
    let j = 0; const now = () => new Date(base + (j += 1) * 1000).toISOString();
    const timeIt = (fn) => { const a = performance.now(); const r = fn(); return [performance.now() - a, r]; };
    const run = unsafeOpenRunWithClock(file, { now });
    const [stateFirst] = timeIt(() => run.state()); // 初回：全行を読んで再生する
    const verifyMs = timeIt(() => run.verify())[0];
    const cold = unsafeOpenRunWithClock(file, { now });
    const apply = (rr, node) => rr.apply(OW, { event_id: `bz${(k += 1)}`, op: 'approve', node, spec_digest: S1, policy_line: 'p0.4', def_digest: defs[node].def_digest });
    const [applyCold] = timeIt(() => apply(cold, T(n - 1))); // 開き直した直後の最初の apply（全行を再生する）
    const warm = []; for (let q = 2; q < 6; q += 1) warm.push(timeIt(() => apply(cold, T(n - q)))[0]);
    warm.sort((x, y) => x - y);
    const stateNow = []; for (let q = 0; q < 3; q += 1) stateNow.push(timeIt(() => run.state())[0]);
    stateNow.sort((x, y) => x - y);
    const [nextMs, nextR] = timeIt(() => run.next());
    return { nodes: n, events: run.state().count, state_first_ms: +stateFirst.toFixed(1), state_median_ms: +stateNow[1].toFixed(1), verify_ms: +verifyMs.toFixed(1),
      apply_cold_ms: +applyCold.toFixed(1), apply_warm_median_ms: +warm[1].toFixed(1), next_ms: +nextMs.toFixed(1), next_start: nextR.start.length };
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}
benign('RS-B27', 'E-8：票の ID の宣言を U- に変えた後、新しい節 U-101 が旧い宣言の節 T-001 に依存し、オーナーが T-002 を U-102 で置き換える', (w) => {
  const r = w(); plan(r, [N('T-001'), N('T-002')]);
  go(r, OW, cfgEv({ concurrent_work: 2, work_item: { prefix: 'U-', digits: [3, 4] }, reason: 'prefix を変える' }));
  plan(r, [N('U-101', ['T-001'])]);
  go(r, OW, { op: 'plan', nodes: [N('U-102')], supersede: [{ old: 'T-002', new: 'U-102' }] });
  expect(r.state().nodes['T-002'].superseded_by === 'U-102', '置き換え');
});

benign('RS-B28', 'R-1：保護を後から足しても、重ならない節は申請・合格・統合まで通る。重なる節は blocked になり、合格済みならオーナーの裁定で統合できる', (w) => {
  const r = w();
  plan(r, [N('T-001', [], ['vgdd/kernel/x']), N('T-002', [], ['src/a/**'])]); approve(r, 'T-001'); approve(r, 'T-002');
  start(r, 'T-001'); start(r, 'T-002'); submit(r, 'T-001');
  const c = protOn(r);
  expect(JSON.stringify(c.protected_busy) === '["T-001"]', 'config が重なる作業中の節を知らせる');
  submit(r, 'T-002', R2); verdict(r, 'T-002', R2, 'passed', AP2);
  expect(st(r, 'T-002') === 'merged', '重ならない節は merged');
  verdict(r, 'T-001', R1, 'passed', AP2);
  expect(st(r, 'T-001') === 'blocked' && r.state().nodes['T-001'].blocked_reason === 'protected', '重なる節は blocked');
  go(r, OW, { op: 'rule', node: 'T-001', request: R1, decision: 'merge', reason: '保護を承知で通す' });
  expect(st(r, 'T-001') === 'merged', 'オーナーの裁定で統合');
});
benign('RS-B29', 'R-1：保護と重なって止めた節は、オーナーが置き換えるか、保護を見直して unblock で作業に戻せる', (w) => {
  const r = w();
  plan(r, [N('T-001', [], ['vgdd/x']), N('T-002', [], ['Vgdd/y'])]); approve(r, 'T-001'); approve(r, 'T-002');
  start(r, 'T-001'); start(r, 'T-002'); protOn(r); submit(r, 'T-001'); submit(r, 'T-002', R2);
  go(r, OW, { op: 'plan', nodes: [N('T-011', [], ['src/k/**'])], supersede: [{ old: 'T-001', new: 'T-011' }] });
  go(r, OW, cfgEv({ ...r.state().config, protected: [], reason: '保護を見直した' }));
  go(r, OW, { op: 'unblock', node: 'T-002', reason: '再開' });
  start(r, 'T-002');
  expect(st(r, 'T-002') === 'in_progress', 'unblock の後に着手できる');
});
