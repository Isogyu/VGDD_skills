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

const EX = { role: 'executive', kind: 'ai', id: 'max' };
const OW = { role: 'owner', kind: 'human', id: 'azuki' };
const CT = { role: 'court', kind: 'script', id: 'gate_runner' };
const NA = { role: 'night_agent', kind: 'script', id: 'night_runner' };
const RP = { role: 'reaper', kind: 'script', id: 'reaper' };
const S1 = `sha256:${'a'.repeat(64)}`;
const S2 = `sha256:${'b'.repeat(64)}`;
const R1 = 'a1b2c3d4e5f6';
const R2 = 'f6e5d4c3b2a1';
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
  const r = memoryRun({ ...rest, config: { workers: 2, ...config } });
  let n = 0;
  r.id = () => `e${++n}`;
  if (steps) steps(r);
  return r;
}
const go = (r, actor, ev) => r.apply(actor, { event_id: r.id(), ...ev });
const plan = (r, nodes, supersede) => go(r, EX, { op: 'plan', nodes, ...(supersede ? { supersede } : {}) });
const N = (id, depends_on = [], resources = [`src/${id}/**`]) => ({ id, depends_on, resources });
const approve = (r, id, o = {}) => go(r, OW, { op: 'approve', node: id, spec_digest: o.spec || S1, policy_line: o.line || 'p0.4', def_digest: r.state().nodes[id].def_digest });
const start = (r, id, o = {}) => go(r, o.actor || EX, { op: 'start', node: id, spec_digest: o.spec || S1, lease_sec: o.lease || 3600 });
const submit = (r, id, req = R1) => go(r, EX, { op: 'submit', node: id, request: req });
const verdict = (r, id, req, audits, verdicts) => go(r, CT, { op: 'verdict', node: id, request: req, audits, verdicts });
const base3 = (r) => { plan(r, [N('a'), N('b'), N('c', ['a', 'b'])]); for (const id of ['a', 'b', 'c']) approve(r, id); };
const inProgressA = (r) => { base3(r); start(r, 'a'); };
const reviewA = (r) => { inProgressA(r); submit(r, 'a'); };
const mergedA = (r) => { reviewA(r); verdict(r, 'a', R1, 'passed', AP2); };
const heldA = (r) => { reviewA(r); verdict(r, 'a', R1, 'passed', AP2); }; // hold の世界で使う
const blockedDisagree = (r) => { reviewA(r); verdict(r, 'a', R1, 'passed', SPLIT_MAJOR); };
const returned3 = (r) => { inProgressA(r); for (let i = 0; i < 3; i += 1) { submit(r, 'a'); verdict(r, 'a', R1, 'failed', AP2); } submit(r, 'a'); };

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
const verdictEv = (audits, verdicts, req = R1) => ({ op: 'verdict', node: 'a', request: req, audits, verdicts });
const approveEv = (id) => (r) => ({ op: 'approve', node: id, spec_digest: S1, policy_line: 'p0.4', def_digest: r.state().nodes[id].def_digest });
const startEv = (id, spec = S1) => ({ op: 'start', node: id, spec_digest: spec, lease_sec: 3600 });

// -- 行為者（INV-05）--
A('RS-A1', '行政（ai）が verdict を起こす（role を court と名乗る）', ['RS-KIND-OP'], { build: reviewA, actor: { role: 'court', kind: 'ai', id: 'max' }, event: verdictEv('passed', AP2) });
A('RS-A2', '行政（ai）が release を起こす（role owner の名乗り）', ['RS-KIND-OP'], { world: holdWorld, build: heldA, actor: { role: 'owner', kind: 'ai', id: 'max' }, event: { op: 'release', node: 'a', request: R1 },
  });
A('RS-A3', '行政（ai）が approve を起こす（自己承認）', ['RS-KIND-OP'], { build: base3Unapproved, actor: { role: 'owner', kind: 'ai', id: 'max' }, event: approveEv('a') });
A('RS-A4', '行政（ai）が unblock を起こす', ['RS-KIND-OP'], { build: blockedDisagree, actor: { role: 'owner', kind: 'ai', id: 'max' }, event: { op: 'unblock', node: 'a', reason: '再開する' } });
A('RS-A5', '行政（ai）が stop を起こす', ['RS-KIND-OP'], { build: base3, actor: { role: 'owner', kind: 'ai', id: 'max' }, event: { op: 'stop', reason: '止める' } });
A('RS-A6', '行政（ai）が rule を起こす（merge の裁定）', ['RS-KIND-OP'], { build: blockedDisagree, actor: { role: 'owner', kind: 'ai', id: 'max' }, event: { op: 'rule', node: 'a', request: R1, decision: 'merge', reason: '通す' } });
A('RS-A7', '行政（ai）が annul・resume・epoch を起こす（annul）', ['RS-KIND-OP'], { build: (r) => { returned3(r); }, actor: { role: 'owner', kind: 'ai', id: 'max' }, event: { op: 'annul', node: 'a', reason: '取り消す' } });
A('RS-A8', '役割違い：行政の役割（人）が verdict・release を起こす（verdict）', ['RS-ROLE-OP'], { build: reviewA, actor: { role: 'executive', kind: 'script', id: 'x' }, event: verdictEv('passed', AP2) });
A('RS-A9', '役割違い：行政の役割の人が approve を起こす', ['RS-ROLE-OP'], { build: base3Unapproved, actor: { role: 'executive', kind: 'human', id: 'x' }, event: approveEv('a') });
A('RS-A10', '役割違い：裁判所の役割が start を起こす', ['RS-ROLE-OP'], { build: base3, actor: CT, event: startEv('a') });
A('RS-A11', '表記ゆれ：役割が大文字（Owner）', ['RS-ACTOR-SHAPE'], { build: base3Unapproved, actor: { role: 'Owner', kind: 'human', id: 'azuki' }, event: approveEv('a') });
A('RS-A12', '表記ゆれ：役割にゼロ幅文字', ['RS-ACTOR-SHAPE'], { build: base3Unapproved, actor: { role: 'own​er', kind: 'human', id: 'azuki' }, event: approveEv('a') });
A('RS-A13', '表記ゆれ：種類が大文字（Human）', ['RS-ACTOR-SHAPE'], { build: base3Unapproved, actor: { role: 'owner', kind: 'Human', id: 'azuki' }, event: approveEv('a') });
A('RS-A14', '表記ゆれ：知らない役割（admin）・余分な項目', ['RS-ACTOR-SHAPE'], { build: base3Unapproved, actor: { role: 'admin', kind: 'human', id: 'azuki', extra: 1 }, event: approveEv('a') });
A('RS-A15', '表記ゆれ：役割が配列（型のゆれ）', ['RS-ACTOR-SHAPE'], { build: base3Unapproved, actor: { role: ['owner'], kind: 'human', id: 'azuki' }, event: approveEv('a') });
function base3Unapproved(r) { plan(r, [N('a'), N('b'), N('c', ['a', 'b'])]); }

// -- 出来事の形・時刻の申告 --
A('RS-A16', '期限切れの偽装：呼び出し側の申告の時刻（now）で expire', ['RS-EVENT-SHAPE', 'RS-EXPIRE-DUE'], { build: inProgressA, event: { op: 'expire', node: 'a', now: '2999-01-01T00:00:00+09:00' }, actor: RP });
A('RS-A17', '節の追加に見せかけて承認済み・統合済みの状態を持ち込む（plan の節に approved・status）', ['RS-EVENT-SHAPE'], { build: base3Unapproved, event: { op: 'plan', nodes: [{ ...N('d'), approved: true, status: 'merged' }] } });
A('RS-A18', 'event_id が大文字・空白入りの別綴り', ['RS-EVENT-SHAPE'], { build: base3, event: { event_id: 'E-1', op: 'stop', reason: '止める' }, actor: OW, noId: true });
A('RS-A19', '知らない出来事の種類（force_merge）', ['RS-EVENT-SHAPE'], { build: base3, event: { op: 'force_merge', node: 'a' } });
A('RS-A20', '同じ審査者が2回出る（1人を2人に数える）', ['RS-EVENT-SHAPE'], { build: reviewA, event: verdictEv('passed', [AP2[0], { ...AP2[0], lineage: 'openai' }]) });
A('RS-A21', 'verdicts が文字列（型のゆれ。fail-open にしない）', ['RS-EVENT-SHAPE'], { build: reviewA, event: { op: 'verdict', node: 'a', request: R1, audits: 'passed', verdicts: 'APPROVED' } });
A('RS-A22', 'major が文字列 "false"（真偽値の型のゆれ）', ['RS-EVENT-SHAPE'], { build: reviewA, event: verdictEv('passed', [{ ...AP2[0], major: 'false' }, AP2[1]]) });
A('RS-A23', '節の id が大文字（別物として通さない）', ['RS-EVENT-SHAPE'], { build: base3Unapproved, event: { op: 'plan', nodes: [N('Dd')] } });

// -- 同じ event_id・停止 --
A('RS-A24', '同じ event_id の二度目（違う内容。冪等の鍵の使い回し）', ['RS-EVENT-ID-UNIQUE'], { build: (r) => { base3Unapproved(r); r.apply(OW, { event_id: 'dup-1', op: 'approve', node: 'a', spec_digest: S1, policy_line: 'p0.4', def_digest: r.state().nodes.a.def_digest }); },
  event: (r) => ({ event_id: 'dup-1', op: 'approve', node: 'a', spec_digest: S2, policy_line: 'p0.4', def_digest: r.state().nodes.a.def_digest }), actor: OW, noId: true });
A('RS-A25', '停止中の start', ['RS-STOPPED'], { build: (r) => { base3(r); go(r, OW, { op: 'stop', reason: '停止する' }); }, event: startEv('a') });
A('RS-A26', '停止中の verdict（court の周回が続く）', ['RS-STOPPED'], { build: (r) => { reviewA(r); go(r, OW, { op: 'stop', reason: '停止する' }); }, actor: CT, event: verdictEv('passed', AP2) });
A('RS-A27', '停止中の plan・approve（approve）', ['RS-STOPPED'], { build: (r) => { base3Unapproved(r); go(r, OW, { op: 'stop', reason: '停止する' }); }, actor: OW, event: approveEv('a') });
A('RS-A28', '停止中でないのに resume', ['RS-STOP-STATE'], { build: base3, actor: OW, event: { op: 'resume', reason: '再開する' } });
A('RS-A29', 'すでに停止中なのに stop（記録を増やす）', ['RS-STOP-STATE'], { build: (r) => { base3(r); go(r, OW, { op: 'stop', reason: '停止する' }); }, actor: OW, event: { op: 'stop', reason: '二度目' } });
A('RS-A30', '出来事の数が上限（20000）に達した後の出来事', ['RS-SIZE-LIMIT'], { build: base3Unapproved, after: (r) => { r.st.count = MAX_EVENTS; }, actor: OW, event: approveEv('a') });
const cfgEv = (o) => ({ op: 'config', ...DEFAULT_CONFIG, ...o });
const stuff = (r, n) => { const base = r.st.nodes.get('a') || { depends_on: [], resources: [] }; for (let i = 0; r.st.nodes.size < n; i += 1) r.st.nodes.set(`stuff${i}`, { ...base, id: `stuff${i}` }); }; // 節の数を水増しした状態（試験用。order には入れない）
A('RS-A31', '節の数が上限（2000）を超える、オーナーの plan', ['RS-SIZE-LIMIT'], { build: base3Unapproved, after: (r) => stuff(r, MAX_NODES_TOTAL - 1), actor: OW, event: { op: 'plan', nodes: [N('q1', [], []), N('q2', [], [])] } });
A('RS-A121', '1回の plan で足せる節の数（200）を超える', ['RS-EVENT-SHAPE'], { build: base3Unapproved, event: { op: 'plan', nodes: Array.from({ length: MAX_PLAN_NODES + 1 }, (_, i) => N(`n${i}`, [], [])) } });
A('RS-A122', '行政が節を足し続けて、オーナーのために取ってある節の枠（200）に踏み込む', ['RS-EVENT-QUOTA'], { build: base3Unapproved, after: (r) => stuff(r, MAX_NODES_TOTAL - HUMAN_NODE_RESERVE - 1), event: { op: 'plan', nodes: [N('q1', [], []), N('q2', [], [])] } });
A('RS-A123', 'kind: human を名乗る行政（role: executive）が、plan の回数の上限を回避する', ['RS-EVENT-QUOTA'], { build: base3Unapproved, after: (r) => { r.st.ai_plans = MAX_AI_PLANS; }, actor: { role: 'executive', kind: 'human', id: 'max' }, event: { op: 'plan', nodes: [N('q', [], [])] } });
A('RS-A124', 'kind: human を名乗る行政が、オーナーのために取ってある出来事の枠を使う', ['RS-EVENT-QUOTA'], { build: base3Unapproved, after: (r) => { r.st.count = MAX_EVENTS - HUMAN_RESERVE; }, actor: { role: 'executive', kind: 'human', id: 'max' }, event: { op: 'plan', nodes: [N('q', [], [])] } });
A('RS-A32', '規則の数値が許す範囲の外の config（必須の審査を空にする・差し戻しの上限 99）', ['RS-EVENT-SHAPE'], { build: base3Unapproved, actor: OW, event: cfgEv({ judiciary: [], max_returns: 99, reason: '弱める' }) });
A('RS-A33', 'lineage のハイフン入りの表記ゆれ（open-ai）を一覧に入れる config', ['RS-EVENT-SHAPE'], { build: base3Unapproved, actor: OW, event: cfgEv({ judiciary: [{ kind: 'judge', lineage: 'open-ai' }], reason: '系統を替える' }) });
A('RS-A91', 'config のない記録への plan（開く側の申告に頼らない。config 以外すべて拒む）', ['RS-CONFIG-REQUIRED'], { world: { noConfig: true }, event: { op: 'plan', nodes: [N('a')] } });
A('RS-A92', 'config のない記録への stop（人の操作も config 以外は拒む）', ['RS-CONFIG-REQUIRED'], { world: { noConfig: true }, actor: OW, event: { op: 'stop', reason: '止める' } });
A('RS-A93', '行政（ai）が config を起こす（上限を上げる）', ['RS-KIND-OP'], { build: base3Unapproved, actor: { role: 'owner', kind: 'ai', id: 'max' }, event: cfgEv({ workers: 64, reason: '広げる' }) });
A('RS-A94', '作業中（in_progress）に、同時の数を上げる config（緩める変更）', ['RS-CONFIG-TIGHTEN'], { build: inProgressA, actor: OW, event: cfgEv({ workers: 8, reason: '広げる' }) });
A('RS-A95', '夜間の合格（held）がある間に、hold を外す config', ['RS-CONFIG-TIGHTEN'], { world: holdWorld, build: heldA, actor: OW, event: cfgEv({ hold: false, reason: '外す' }) });
A('RS-A96', '申請中（review）に、必須の審査を減らす config', ['RS-CONFIG-TIGHTEN'], { build: reviewA, actor: OW, event: cfgEv({ judiciary: [{ kind: 'judge', lineage: 'claude' }], reason: '減らす' }) });
A('RS-A97', '作業中に、法律の系統の縛りを外す config（policy_line を null に）', ['RS-CONFIG-TIGHTEN'], { world: { config: { policy_line: 'p0.4' } }, build: inProgressA, actor: OW, event: cfgEv({ policy_line: null, reason: '外す' }) });
A('RS-A98', '理由なしの config の変更', ['RS-REASON'], { build: base3Unapproved, actor: OW, event: cfgEv({ workers: 1 }) });
A('RS-A99', '追記する側の実時間より 5 分以上先の時刻の行（未来の時刻で他人の lease を即座に expire する）', ['RS-TIME-FUTURE'], { build: inProgressA, at: (r) => r.now() + TIME_FUTURE_MS + 1000, wall: (r) => r.now(), actor: RP, event: { op: 'expire', node: 'a' } });
A('RS-A34', '記録の時刻が読めない（NaN）', ['RS-TIME-FUTURE'], { build: base3Unapproved, at: Number.NaN, actor: OW, event: approveEv('a') });
A('RS-A35', '理由なしの unblock', ['RS-REASON'], { build: blockedDisagree, actor: OW, event: { op: 'unblock', node: 'a' } });
A('RS-A36', '理由なしの resume', ['RS-REASON'], { build: (r) => { base3(r); go(r, OW, { op: 'stop', reason: '停止する' }); }, actor: OW, event: { op: 'resume' } });
A('RS-A37', '理由が空白だけの rule', ['RS-REASON', 'RS-EVENT-SHAPE'], { build: blockedDisagree, actor: OW, event: { op: 'rule', node: 'a', request: R1, decision: 'merge', reason: '   ' } });

// -- 節・遷移・凍結 --
A('RS-A38', 'ない節への approve', ['RS-NODE-EXISTS'], { build: base3Unapproved, actor: OW, event: { op: 'approve', node: 'ghost', spec_digest: S1, policy_line: 'p0.4', def_digest: S1 } });
A('RS-A39', '統合済みの節への approve（動かさない）', ['RS-FROZEN'], { build: mergedA, actor: OW, event: approveEv('a') });
A('RS-A40', '置き換え済みの節の unblock（承認の引き継ぎ・復活）', ['RS-FROZEN'], { build: (r) => { base3(r); plan(r, [N('a2')], [{ old: 'a', new: 'a2' }]); }, actor: OW, event: { op: 'unblock', node: 'a', reason: '戻す' } });
A('RS-A41', '統合済みの節の再着手', ['RS-FROZEN', 'RS-TRANSITION'], { build: mergedA, event: startEv('a') });
A('RS-A42', '作業中の節をもう一度 start（二重の着手）', ['RS-TRANSITION'], { build: inProgressA, event: startEv('a') });
A('RS-A43', 'ready の節を直接 submit（着手の飛ばし）', ['RS-TRANSITION'], { build: base3, event: { op: 'submit', node: 'a', request: R1 } });
A('RS-A44', '夜間の held を見ずに、作業中の節へ release', ['RS-TRANSITION', 'RS-REQUEST-MATCH'], { build: inProgressA, actor: OW, event: { op: 'release', node: 'a', request: R1 } });
A('RS-A45', 'merged になる迂回：夜間（hold）の合格を merged にする（held を飛ばす）', ['RS-MERGE-PATH'], { world: holdWorld, build: reviewA, actor: CT, event: verdictEv('passed', AP2), res: naive('merged') });
A('RS-A46', 'merged になる迂回：start の結果を merged にする', ['RS-MERGE-PATH', 'RS-TRANSITION'], { build: base3, event: startEv('a'), res: (r, ev) => ({ op: 'start', node: ev.node, to: 'merged', patch: {} }) });

// -- plan --
A('RS-A47', '節の追加に見せかけた既存の節（a）の範囲の書き換え', ['RS-PLAN-APPEND-ONLY'], { build: base3Unapproved, event: { op: 'plan', nodes: [N('a', [], ['**'])] } });
A('RS-A48', '節の追加に見せかけた既存の節（c）の依存の書き換え', ['RS-PLAN-APPEND-ONLY'], { build: base3Unapproved, event: { op: 'plan', nodes: [N('c', [], ['src/c/**'])] } });
A('RS-A49', '循環する節を追加', ['RS-PLAN-GRAPH'], { build: base3Unapproved, event: { op: 'plan', nodes: [N('x', ['y']), N('y', ['x'])] } });
A('RS-A50', '存在しない依存を持つ節を追加', ['RS-PLAN-GRAPH'], { build: base3Unapproved, event: { op: 'plan', nodes: [N('x', ['ghost'])] } });
A('RS-A51', '同じ id を2つ含む plan', ['RS-PLAN-GRAPH'], { build: base3Unapproved, event: { op: 'plan', nodes: [N('x'), N('x', [], ['other/**'])] } });
A('RS-A52', '統合済みの節を置き換える（supersede）', ['RS-PLAN-SUPERSEDE'], { build: mergedA, event: { op: 'plan', nodes: [N('a2')], supersede: [{ old: 'a', new: 'a2' }] } });
A('RS-A53', '置き換え先が計画にない（既存の節を新しい節として指す）', ['RS-PLAN-SUPERSEDE'], { build: base3, event: { op: 'plan', nodes: [N('a2')], supersede: [{ old: 'a', new: 'b' }] } });
A('RS-A54', 'ない節を置き換える', ['RS-PLAN-SUPERSEDE'], { build: base3, event: { op: 'plan', nodes: [N('a2')], supersede: [{ old: 'ghost', new: 'a2' }] } });

// -- 承認・着手 --
A('RS-A55', '承認の後に定義が変わった（古い定義の指紋での承認）', ['RS-APPROVAL-FRESH'], { build: base3Unapproved, actor: OW, event: { op: 'approve', node: 'a', spec_digest: S1, policy_line: 'p0.4', def_digest: S2 } });
A('RS-A56', '未承認の節の start', ['RS-APPROVED'], { build: (r) => { plan(r, [N('a'), N('b')]); approve(r, 'b'); }, event: startEv('a') });
A('RS-A57', '置き換えた新しい節は承認を引き継がない（start）', ['RS-APPROVED'], { build: (r) => { base3(r); plan(r, [N('a2')], [{ old: 'a', new: 'a2' }]); }, event: startEv('a2') });
A('RS-A58', '承認の後に仕様が変わった（着手時の仕様の指紋が違う）', ['RS-SPEC-DIGEST'], { build: base3, event: startEv('a', S2) });
A('RS-A59', '法律の系統が違う承認（p0.4 の承認で p0.5 の系統の着手）', ['RS-POLICY-LINE'], { world: { config: { policy_line: 'p0.5' } }, build: base3, event: startEv('a') });
A('RS-A60', '依存が未統合（review）の節 c の start', ['RS-DEPS-MERGED'], { build: (r) => { reviewA(r); }, event: startEv('c') });
A('RS-A61', '依存の一方だけ統合（b が未統合）の節 c の start', ['RS-DEPS-MERGED'], { build: mergedA, event: startEv('c') });
A('RS-A62', '依存が blocked の節の start', ['RS-DEPS-MERGED'], { build: blockedDisagree, event: startEv('c') });
A('RS-A63', '範囲の重なる節の同時の start（dir/** と dir/file）', ['RS-RESOURCE-DISJOINT'], { build: (r) => { plan(r, [N('x', [], ['src/shared/**']), N('y', [], ['src/shared/util.js'])]); approve(r, 'x'); approve(r, 'y'); start(r, 'x'); }, event: startEv('y') });
A('RS-A64', '範囲の重なる節の同時の start（大文字小文字だけ違う）', ['RS-RESOURCE-DISJOINT'], { build: (r) => { plan(r, [N('x', [], ['src/x']), N('y', [], ['Src/x'])]); approve(r, 'x'); approve(r, 'y'); start(r, 'x'); }, event: startEv('y') });
A('RS-A65', '同時の数の超過（workers=1 で2つ目）', ['RS-WORKER-LIMIT'], { world: { config: { workers: 1 } }, build: inProgressA, event: startEv('b') });
A('RS-A66', '同時の数の超過（workers=0：予算なし）', ['RS-WORKER-LIMIT'], { world: { config: { workers: 0 } }, build: base3, event: startEv('a') });
A('RS-A67', '着手の回数の上限（attempts）を超えた start', ['RS-ATTEMPTS'], { build: (r) => { inProgressA(r); tick(r); go(r, RP, { op: 'expire', node: 'a' }); go(r, OW, cfgEv({ max_attempts: 1, reason: '試行を絞る（締める変更）' })); }, event: startEv('a') });
A('RS-A68', '期限前の expire（他人の作業を奪う）', ['RS-EXPIRE-DUE'], { build: inProgressA, actor: RP, event: { op: 'expire', node: 'a' } });
A('RS-A69', '期限の1ミリ秒前の expire', ['RS-EXPIRE-DUE'], { build: inProgressA, after: (r) => r.tick(3600e3 - 1), actor: RP, event: { op: 'expire', node: 'a' } });

// -- 申請・司法・統合 --
A('RS-A70', '前の申請の合格の使い回し（別の申請の指紋で verdict）', ['RS-REQUEST-MATCH'], { build: reviewA, actor: CT, event: verdictEv('passed', AP2, R2) });
A('RS-A71', '別の申請の指紋で release', ['RS-REQUEST-MATCH'], { world: holdWorld, build: (r) => { reviewA(r); verdict(r, 'a', R1, 'passed', AP2); }, actor: OW, event: { op: 'release', node: 'a', request: R2 } });
A('RS-A72', '別の申請の指紋で rule（裁定の使い回し）', ['RS-REQUEST-MATCH'], { build: blockedDisagree, actor: OW, event: { op: 'rule', node: 'a', request: R2, decision: 'merge', reason: '通す' } });
A('RS-A73', '判定が分かれた以外の blocked（差し戻しの上限）を rule で通す', ['RS-RULE-SCOPE'], { build: (r) => { returned3(r); verdict(r, 'a', R1, 'passed', AP2); }, actor: OW, event: { op: 'rule', node: 'a', request: R1, decision: 'merge', reason: '通す' } });
A('RS-A74', '監査が not_run なのに合格（司法は全員 APPROVED）', ['RS-PASS-AUDIT'], { build: reviewA, event: verdictEv('not_run', AP2), actor: CT, res: naive('merged') });
A('RS-A75', '監査が failed なのに合格', ['RS-PASS-AUDIT'], { build: reviewA, event: verdictEv('failed', AP2), actor: CT, res: naive('merged') });
A('RS-A76', '判定が1つだけで合格（司法の欠落を合格とみなす。G15・G19）', ['RS-PASS-QUORUM'], { build: reviewA, event: verdictEv('passed', ONE), actor: CT, res: naive('merged') });
A('RS-A77', '一覧にない系統（open-ai）の結果を足して、必須の codex の代わりにする', ['RS-VERDICT-SET', 'RS-PASS-QUORUM'], { build: reviewA, event: verdictEv('passed', [AP2[0], J('open_ai')]), actor: CT });
A('RS-A78', '1つが UNAVAILABLE で、残り1つの APPROVED だけで合格（G15 の形）', ['RS-PASS-QUORUM'], { build: reviewA, event: verdictEv('passed', UNAV1), actor: CT, res: naive('merged') });
A('RS-A79', '分かれた判定（重大でない差し戻しが1つ）での合格', ['RS-PASS-CONSENSUS'], { build: reviewA, event: verdictEv('passed', SPLIT_MINOR), actor: CT, res: naive('merged') });
A('RS-A80', '重大な指摘で分かれた判定での合格', ['RS-PASS-CONSENSUS', 'RS-DISAGREE-BLOCK'], { build: reviewA, event: verdictEv('passed', SPLIT_MAJOR), actor: CT, res: naive('merged') });
A('RS-A81', '重大な指摘で分かれたのに差し戻しとして処理（裁定待ちにしない）', ['RS-DISAGREE-BLOCK'], { build: reviewA, event: verdictEv('passed', SPLIT_MAJOR), actor: CT, res: naive('in_progress', 'return') });
A('RS-A82', '差し戻しの上限を超えた再申請を合格にする', ['RS-RETURN-CAP'], { build: returned3, event: verdictEv('passed', AP2), actor: CT, res: naive('merged') });
A('RS-A83', '差し戻しの上限を超えた再申請を、また差し戻しにする（無限の再試行）', ['RS-RETURN-CAP'], { build: returned3, event: verdictEv('failed', AP2), actor: CT, res: naive('in_progress', 'return') });
A('RS-A84', '司法が使えないことを差し戻しに数える', ['RS-UNAVAILABLE-CAP'], { build: reviewA, event: verdictEv('passed', ONE), actor: CT, res: naive('in_progress', 'return') });
A('RS-A85', '同じ申請で司法が使えない3回目を blocked にしない（無限の待ち）', ['RS-UNAVAILABLE-CAP'],
  { build: (r) => { reviewA(r); verdict(r, 'a', R1, 'passed', ONE); verdict(r, 'a', R1, 'passed', ONE); }, event: verdictEv('passed', ONE), actor: CT, res: naive('review', 'unavailable') });

// -- 人の操作の出口・移行 --
A('RS-A86', '差し戻しが0回の節の annul（回数の水増し）', ['RS-ANNUL-BOUND'], { build: inProgressA, actor: OW, event: { op: 'annul', node: 'a', reason: '取り消す' } });
A('RS-A87', '上限で止まる再開（行き止まりを作る unblock。extra なし）', ['RS-UNBLOCK-PROGRESS'], { build: (r) => { returned3(r); verdict(r, 'a', R1, 'passed', AP2); }, actor: OW, event: { op: 'unblock', node: 'a', reason: '再開する' } });
A('RS-A88', '着手の上限で止まる再開（extra_attempts なし）', ['RS-UNBLOCK-PROGRESS'], { build: (r) => { inProgressA(r); r.st.nodes.get('a').attempts = 4; r.st.nodes.get('a').status = 'blocked'; r.st.nodes.get('a').blocked_reason = 'attempts_exhausted'; }, actor: OW, event: { op: 'unblock', node: 'a', reason: '再開する' } });
A('RS-A89', '移行の記録が、実際の最後の行と違うハッシュを覆う', ['RS-EPOCH-COVERS'], { build: base3, actor: OW, event: { op: 'epoch', covers: { count: 1, last_hash: '0'.repeat(64) }, reason: '移行する' } });
A('RS-A90', '移行の記録が、まだない行を覆う', ['RS-EPOCH-COVERS'], { build: base3, actor: OW, event: { op: 'epoch', covers: { count: 999, last_hash: '0'.repeat(64) }, reason: '移行する' } });


A('RS-A125', '長い lease（config の上限を超える）で範囲と枠を占める start', ['RS-LEASE-LIMIT'], { build: base3, event: { op: 'start', node: 'a', spec_digest: S1, lease_sec: 604800 } });
A('RS-A126', '作業中に、法律の系統を p0.4 から p0.3 に付け替える config（承認が効き直る）', ['RS-CONFIG-TIGHTEN'], { world: { config: { policy_line: 'p0.4' } }, build: inProgressA, actor: OW, event: cfgEv({ policy_line: 'p0.3', reason: '付け替える' }) });
// N3：未統合の申請を持つ blocked の節も範囲を占める。rule の return・unblock も範囲と同時の数を通す
const blockedShared = (r) => { plan(r, [N('x', [], ['src/shared/**']), N('y', [], ['src/shared/x.ts']), N('z')]); for (const id of ['x', 'y', 'z']) approve(r, id); start(r, 'x'); submit(r, 'x'); verdict(r, 'x', R1, 'passed', SPLIT_MAJOR); };
A('RS-A127', 'x が判定の不一致で blocked（オーナーの裁定待ち）の間に、範囲の重なる y を start', ['RS-RESOURCE-DISJOINT'], { build: blockedShared, event: startEv('y') });
A('RS-A128', 'rule の return で、重なる節が作業中のまま x を in_progress に戻す（状態を作り込んだ場合）', ['RS-RESOURCE-DISJOINT'],
  { build: (r) => { blockedShared(r); r.st.nodes.get('y').status = 'in_progress'; }, actor: OW, event: { op: 'rule', node: 'x', request: R1, decision: 'return', reason: 'やり直す' } });
A('RS-A129', '同時の数を締めた後の rule の return（作業中の別の節と合わせて上限を超える）', ['RS-WORKER-LIMIT'],
  { build: (r) => { plan(r, [N('x'), N('y')]); approve(r, 'x'); approve(r, 'y'); start(r, 'x'); start(r, 'y'); submit(r, 'x'); verdict(r, 'x', R1, 'passed', SPLIT_MAJOR); go(r, OW, cfgEv({ workers: 1, reason: '枠を締める' })); },
    actor: OW, event: { op: 'rule', node: 'x', request: R1, decision: 'return', reason: 'やり直す' } });
A('RS-A130', 'unblock で、範囲の重なる節が作業中のまま再開する（状態を作り込んだ場合）', ['RS-RESOURCE-DISJOINT'],
  { build: (r) => { blockedShared(r); r.st.nodes.get('y').status = 'in_progress'; r.st.nodes.get('x').attempts = 1; }, actor: OW, event: { op: 'unblock', node: 'x', reason: '再開する' } });

// -- F2：申請中（review）・held も範囲と同時の数に入る --
const sharedXY = (r) => { plan(r, [N('x', [], ['src/shared/**']), N('y', [], ['src/shared/x.ts']), N('z')]); for (const id of ['x', 'y', 'z']) approve(r, id); };
A('RS-A100', 'x が申請中（review）の間に、範囲の重なる y を start（差し戻せば両方が作業中になる）', ['RS-RESOURCE-DISJOINT'], { build: (r) => { sharedXY(r); start(r, 'x'); submit(r, 'x'); }, event: startEv('y') });
A('RS-A101', 'x が夜間の合格（held。オーナーの承認待ち）の間に、範囲の重なる y を start（held も範囲を占める）', ['RS-RESOURCE-DISJOINT'], { world: { config: { hold: true } }, build: (r) => { sharedXY(r); start(r, 'x'); submit(r, 'x'); verdict(r, 'x', R1, 'passed', AP2); }, event: startEv('y') });
A('RS-A102', 'workers=1 で x が申請中（review）の間に、重ならない z を start（review は枠を使う）', ['RS-WORKER-LIMIT'], { world: { config: { workers: 1 } }, build: (r) => { sharedXY(r); start(r, 'x'); submit(r, 'x'); }, event: startEv('z') });

// -- F3：必須の審査の一覧（config に固定）--
const secNode = (r) => { plan(r, [{ ...N('a'), security_review: true }, N('b'), N('c', ['a', 'b'])]); for (const id of ['a', 'b', 'c']) approve(r, id); start(r, 'a'); submit(r, 'a'); };
A('RS-A103', 'セキュリティ審査の印のある節に、セキュリティ審査の結果がない（2人の APPROVED だけで合格にする）', ['RS-PASS-QUORUM'], { build: secNode, event: verdictEv('passed', AP2), actor: CT, res: naive('merged') });
A('RS-A104', 'セキュリティ審査が UNAVAILABLE のまま、残りの2人の APPROVED で合格', ['RS-PASS-QUORUM'], { build: secNode, event: verdictEv('passed', [...AP2, J('codex', 'UNAVAILABLE', false, 'security')]), actor: CT, res: naive('merged') });
A('RS-A105', 'セキュリティ審査の印のない節に、余分なセキュリティ審査の結果を足す', ['RS-VERDICT-SET'], { build: reviewA, event: verdictEv('passed', [...AP2, SEC_OK]), actor: CT });
A('RS-A106', 'セキュリティ審査が不合格（major）なのに、不一致として blocked にする（裁定で通せるようにする）', ['RS-SECURITY-FAIL'], { build: secNode, event: verdictEv('passed', [...AP2, SEC_NG]), actor: CT, res: naive('blocked', 'blocked_disagreement') });
A('RS-A107', 'セキュリティ審査が不合格なのに、司法2人が APPROVED だからと合格にする', ['RS-SECURITY-FAIL', 'RS-PASS-CONSENSUS'], { build: secNode, event: verdictEv('passed', [...AP2, SEC_NG]), actor: CT, res: naive('merged') });
A('RS-A108', '全員が差し戻し（CHANGES_REQUIRED）なのに合格にする', ['RS-PASS-CONSENSUS'], { build: reviewA, event: verdictEv('passed', CR2), actor: CT, res: naive('merged') });
A('RS-A109', '同じ申請の指紋で通算の回数（2回済み）を、別の申請を挟んだ後の3回目で blocked にしない', ['RS-UNAVAILABLE-CAP'],
  { build: (r) => { reviewA(r); verdict(r, 'a', R1, 'passed', ONE); verdict(r, 'a', R1, 'passed', ONE); verdict(r, 'a', R1, 'failed', AP2); submit(r, 'a', R2); verdict(r, 'a', R2, 'failed', AP2); submit(r, 'a', R1); },
    event: verdictEv('passed', ONE), actor: CT, res: naive('review', 'unavailable') });
A('RS-A110', '差し戻しで in_progress に戻るのに、試行（attempts）を数えない', ['RS-ATTEMPTS-ON-RETURN'], { build: reviewA, event: verdictEv('failed', AP2), actor: CT, res: (r, ev) => ({ op: 'verdict', node: ev.node, kind: 'return', to: 'in_progress', patch: {} }) });
A('RS-A111', '試行の上限に達した票を、差し戻しで作業員の起動し直し（in_progress）にする', ['RS-ATTEMPTS-ON-RETURN'],
  { world: { config: { max_attempts: 1 } }, build: reviewA, event: verdictEv('failed', AP2), actor: CT, res: (r, ev) => ({ op: 'verdict', node: ev.node, kind: 'return', to: 'in_progress', patch: { returns: 1, attempts: 2 } }) });

// -- F4：行政が記録を使い切れない --
A('RS-A112', '行政（ai）が空の plan を送る', ['RS-PLAN-NONEMPTY'], { build: base3Unapproved, event: { op: 'plan', nodes: [] } });
A('RS-A113', '人以外の出来事の枠（上限 - 人の予備）が尽きた後の行政の plan', ['RS-EVENT-QUOTA'], { build: base3Unapproved, after: (r) => { r.st.count = MAX_EVENTS - HUMAN_RESERVE; }, event: { op: 'plan', nodes: [N('q')] } });
A('RS-A114', '行政（ai）の plan の回数が上限に達した後の plan', ['RS-EVENT-QUOTA'], { build: base3Unapproved, after: (r) => { r.st.ai_plans = MAX_AI_PLANS; }, event: { op: 'plan', nodes: [N('q')] } });
A('RS-A115', '依存の総数が上限を超える plan', ['RS-SIZE-LIMIT'], { build: base3Unapproved, after: (r) => { r.st.dep_total = MAX_DEPS_TOTAL; }, event: { op: 'plan', nodes: [N('q', ['a'])] } });
A('RS-A116', '1つの節の依存が 65 個（上限 64）', ['RS-EVENT-SHAPE'], { build: base3Unapproved, event: { op: 'plan', nodes: [N('q', Array.from({ length: 65 }, (_, i) => `d${i}`))] } });

// -- F5：置き換えの鎖 --
A('RS-A117', '置き換えの鎖が上限（8）を超える', ['RS-PLAN-SUPERSEDE'], { build: (r) => { base3Unapproved(r); r.st.nodes.get('a').gen = 8; }, event: { op: 'plan', nodes: [N('a2')], supersede: [{ old: 'a', new: 'a2' }] } });

// -- F6 --
A('RS-A118', '夜間の代行（night_runner）が着手した節を、別の行為者（行政 max）が submit', ['RS-WORKER-BIND'], { build: (r) => { base3(r); start(r, 'a', { actor: NA }); }, event: { op: 'submit', node: 'a', request: R1 } });
A('RS-A119', '行政（ai）が、夜間に合格して held（オーナーの release 待ち）の節を置き換えで消す', ['RS-PLAN-SUPERSEDE'], { world: holdWorld, build: heldA, event: { op: 'plan', nodes: [N('a2')], supersede: [{ old: 'a', new: 'a2' }] } });
A('RS-A120', '行政（ai）が、判定が分かれて blocked（オーナーの裁定待ち）の節を置き換えで消す', ['RS-PLAN-SUPERSEDE'], { build: blockedDisagree, event: { op: 'plan', nodes: [N('a2')], supersede: [{ old: 'a', new: 'a2' }] } });

// ---- 良性 ----
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
  plan(r, [N('a'), N('b'), N('c', ['a', 'b'])]);
  for (const id of ['a', 'b', 'c']) approve(r, id);
  start(r, 'a'); start(r, 'b'); // 範囲が重ならず、同時の数の上限（2）に収まる
  for (const id of ['a', 'b']) { submit(r, id, R1); verdict(r, id, R1, 'passed', AP2); }
  start(r, 'c'); submit(r, 'c', R2); verdict(r, 'c', R2, 'passed', AP2);
  expect(['a', 'b', 'c'].every((id) => st(r, id) === 'merged'), 'すべて merged');
});
benign('RS-B2', '差し戻し→再申請→合格', (w) => {
  const r = w(); inProgressA(r);
  submit(r, 'a', R1); verdict(r, 'a', R1, 'failed', AP2);
  expect(st(r, 'a') === 'in_progress' && r.state().nodes.a.returns === 1, '差し戻し');
  submit(r, 'a', R2); verdict(r, 'a', R2, 'passed', AP2);
  expect(st(r, 'a') === 'merged', '合格');
});
benign('RS-B3', '司法が使えない→戻った周回で合格（差し戻しに数えない）', (w) => {
  const r = w(); reviewA(r);
  verdict(r, 'a', R1, 'passed', ONE);
  expect(st(r, 'a') === 'review' && r.state().nodes.a.returns === 0 && Object.values(r.state().nodes.a.unavail)[0] === 1, '使えない');
  verdict(r, 'a', R1, 'passed', AP2);
  expect(st(r, 'a') === 'merged', '合格');
});
benign('RS-B4', '夜間の held → オーナーの release', (w) => {
  const r = w({ config: { hold: true } }); reviewA(r);
  verdict(r, 'a', R1, 'passed', AP2);
  expect(st(r, 'a') === 'held', 'held');
  go(r, OW, { op: 'release', node: 'a', request: R1 });
  expect(st(r, 'a') === 'merged', 'merged');
});
benign('RS-B5', '分かれた判定 → オーナーの裁定（merge）', (w) => {
  const r = w(); blockedDisagree(r);
  expect(st(r, 'a') === 'blocked', 'blocked');
  go(r, OW, { op: 'rule', node: 'a', request: R1, decision: 'merge', reason: '指摘は軽微と判断した' });
  expect(st(r, 'a') === 'merged', 'merged');
});
benign('RS-B6', '停止 → 再開 → 続行', (w) => {
  const r = w(); inProgressA(r);
  go(r, OW, { op: 'stop', reason: '点検する' });
  go(r, OW, { op: 'resume', reason: '点検した' });
  submit(r, 'a'); verdict(r, 'a', R1, 'passed', AP2);
  expect(st(r, 'a') === 'merged', '続行');
});
benign('RS-B7', 'b が未承認のままでも a は最後まで進む（INV-12）', (w) => {
  const r = w(); plan(r, [N('a'), N('b'), N('c', ['b'])]); approve(r, 'a');
  start(r, 'a'); submit(r, 'a'); verdict(r, 'a', R1, 'passed', AP2);
  expect(st(r, 'a') === 'merged' && st(r, 'b') === 'ready' && r.next().start.length === 0, 'a だけ進む');
});
benign('RS-B8', '前後の空白・全角の行為者の表記は正規化されて受け入れる', (w) => {
  const r = w(); plan(r, [N('a')]);
  r.apply({ role: ' ｏｗｎｅｒ ', kind: 'human', id: 'azuki' }, { event_id: 'e-x', op: 'approve', node: 'a', spec_digest: S1, policy_line: 'p0.4', def_digest: r.state().nodes.a.def_digest });
  expect(r.state().nodes.a.approved, '承認');
});
benign('RS-B9', '期限ちょうどの expire → ready に戻って再着手（attempts は戻らない）', (w) => {
  const r = w(); inProgressA(r); r.tick(3600e3);
  go(r, RP, { op: 'expire', node: 'a' });
  expect(st(r, 'a') === 'ready' && r.state().nodes.a.attempts === 1, 'ready');
  start(r, 'a'); expect(r.state().nodes.a.attempts === 2, '再着手');
});
benign('RS-B10', '置き換え（supersede）：新しい節を承認し直せば、依存していた節も進める', (w) => {
  const r = w(); base3(r);
  plan(r, [N('a2')], [{ old: 'a', new: 'a2' }]);
  approve(r, 'a2'); start(r, 'a2'); submit(r, 'a2'); verdict(r, 'a2', R1, 'passed', AP2);
  start(r, 'b'); submit(r, 'b', R2); verdict(r, 'b', R2, 'passed', AP2);
  start(r, 'c');
  expect(st(r, 'c') === 'in_progress' && st(r, 'a') === 'blocked', '置き換え先が統合されれば c が進む');
});
benign('RS-B11', '上限で止まった節を、オーナーが追加の回数つきで再開して合格', (w) => {
  const r = w(); returned3(r); verdict(r, 'a', R1, 'passed', AP2);
  expect(st(r, 'a') === 'blocked', '上限で blocked');
  go(r, OW, { op: 'unblock', node: 'a', reason: '司法の環境を直した', extra_returns: 1, extra_attempts: 1 });
  start(r, 'a'); submit(r, 'a', R2); verdict(r, 'a', R2, 'passed', AP2);
  expect(st(r, 'a') === 'merged' && r.state().nodes.a.returns === 3, '合格（回数は戻していない）');
});
benign('RS-B12', '同じ event_id・同じ内容の二度目は何も起こさない（冪等）', (w) => {
  const r = w(); plan(r, [N('a')]);
  const ev = { event_id: 'same-1', op: 'approve', node: 'a', spec_digest: S1, policy_line: 'p0.4', def_digest: r.state().nodes.a.def_digest };
  r.apply(OW, ev); const c = r.state().count;
  const second = r.apply(OW, ev);
  expect(second.duplicate === true && r.state().count === c, '二度目は効かない');
});
benign('RS-B13', 'オーナーによる annul で差し戻しの数を減らす', (w) => {
  const r = w(); inProgressA(r); submit(r, 'a'); verdict(r, 'a', R1, 'failed', AP2);
  go(r, OW, { op: 'annul', node: 'a', reason: '法律の不具合による差し戻し' });
  expect(r.state().nodes.a.returns === 0, '数えない');
});
benign('RS-B14', 'night_agent（スクリプト）の start と reaper の expire', (w) => {
  const r = w(); base3(r); start(r, 'a', { actor: NA }); r.tick(3600e3); go(r, RP, { op: 'expire', node: 'a' });
  expect(st(r, 'a') === 'ready', 'ready');
});

benign('RS-B16', '重大でない指摘だけで分かれた判定は、指摘を記録に残して合格（法律 §3.1 の 8。kind: pass_minor_disagreement）', (w) => {
  const r = w(); reviewA(r);
  const res = verdict(r, 'a', R1, 'passed', SPLIT_MINOR);
  expect(res.kind === 'pass_minor_disagreement' && st(r, 'a') === 'merged', '合格');
});
benign('RS-B17', 'セキュリティ審査の印のある節：3つの結果がそろって APPROVED なら合格。不合格なら差し戻し（裁定で通せない）', (w) => {
  const r = w(); secNode(r);
  expect(verdict(r, 'a', R1, 'passed', [...AP2, SEC_NG]).kind === 'return', '差し戻し');
  submit(r, 'a', R2);
  expect(verdict(r, 'a', R2, 'passed', [...AP2, SEC_OK]).kind === 'pass' && st(r, 'a') === 'merged', '合格');
});
benign('RS-B18', 'held（人の承認待ち）の節は作業員の枠を使わない。範囲の重ならない節は workers=1 でも着手できる', (w) => {
  const r = w({ config: { hold: true, workers: 1 } }); sharedXY(r);
  start(r, 'x'); submit(r, 'x'); verdict(r, 'x', R1, 'passed', AP2);
  expect(st(r, 'x') === 'held', 'held');
  start(r, 'z'); expect(st(r, 'z') === 'in_progress', '着手');
});
benign('RS-B19', '行政が予測した event_id を先に使っても、オーナーの同じ id の stop は通る（役割と op の組ごとの一意性）', (w) => {
  const r = w(); plan(r, [N('a')]);
  r.apply(EX, { event_id: 'stop-20260101', op: 'plan', nodes: [N('b')] });
  r.apply(OW, { event_id: 'stop-20260101', op: 'stop', reason: '止める' });
  expect(r.state().stopped === true, '停止');
});
benign('RS-B20', 'config：締める変更はいつでも、緩める変更は作業中の節がないときだけ', (w) => {
  const r = w(); inProgressA(r);
  go(r, OW, cfgEv({ workers: 1, max_returns: 2, reason: '締める' }));
  expect(r.state().config.workers === 1, '締める変更は作業中でも通る');
  const r2 = w(); base3(r2);
  go(r2, OW, cfgEv({ workers: 8, reason: '作業中の節がないので緩められる' }));
  expect(r2.state().config.workers === 8, '緩める変更');
});
benign('RS-B21', '行政（ai）が、オーナーの判断待ちでない blocked の節（置き換えの対象）を置き換える', (w) => {
  const r = w(); base3(r); plan(r, [N('a2')], [{ old: 'a', new: 'a2' }]);
  expect(st(r, 'a') === 'blocked' && r.state().nodes.a.superseded_by === 'a2', '置き換え');
});
benign('RS-B22', '差し戻しで in_progress に戻るときも attempts を数える（着手1回＋差し戻し1回＝2）', (w) => {
  const r = w(); inProgressA(r); submit(r, 'a'); verdict(r, 'a', R1, 'failed', AP2);
  expect(r.state().nodes.a.attempts === 2, 'attempts');
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
    ap(run1, OW, cfgEv({ workers: 2 }));
    ap(run1, EX, { op: 'plan', nodes: [N('a'), N('b', ['a'])] });
    ap(run1, OW, { op: 'approve', node: 'a', spec_digest: S1, policy_line: 'p0.4', def_digest: run1.state().nodes.a.def_digest });
    ap(run1, EX, { op: 'start', node: 'a', spec_digest: S1, lease_sec: 600 });
    const before = JSON.stringify(run1.state());
    const run2 = unsafeOpenRunWithClock(file, { now }); // 落ちて開き直した
    if (JSON.stringify(run2.state()) !== before || !run2.verify().ok) return { blocked: true, by: ['（再生が一致しない）'] };
    ap(run2, EX, { op: 'submit', node: 'a', request: R1 });
    ap(run2, CT, { op: 'verdict', node: 'a', request: R1, audits: 'passed', verdicts: AP2 });
    return { blocked: run2.state().nodes.a.status !== 'merged', by: [] };
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
    const m = memoryRun({ config: { workers: 8 }, start: '2026-01-01T00:00:00+09:00' });
    let k = 0; const ap = (a, ev) => { m.tick(1000); return m.apply(a, { event_id: `b${++k}`, ...ev }); };
    const nodes = Array.from({ length: n }, (_, i) => N(`n${i}`, i >= 8 ? [`n${i - 8}`] : [], [`src/n${i}/**`]));
    for (let i = 0; i < n; i += 100) ap(EX, { op: 'plan', nodes: nodes.slice(i, i + 100) });
    const defs = m.state().nodes;
    let i = 0;
    // 出来事の数が events に届くまで、節ごとに 承認・着手・（申請・不合格・差し戻しの取り消し）×2・申請・合格（10 出来事）を進める
    while (k < events - 60 && i < n) {
      const id = `n${i}`;
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
    const [applyCold] = timeIt(() => apply(cold, `n${n - 1}`)); // 開き直した直後の最初の apply（全行を再生する）
    const warm = []; for (let q = 2; q < 6; q += 1) warm.push(timeIt(() => apply(cold, `n${n - q}`))[0]);
    warm.sort((x, y) => x - y);
    const stateNow = []; for (let q = 0; q < 3; q += 1) stateNow.push(timeIt(() => run.state())[0]);
    stateNow.sort((x, y) => x - y);
    const [nextMs, nextR] = timeIt(() => run.next());
    return { nodes: n, events: run.state().count, state_first_ms: +stateFirst.toFixed(1), state_median_ms: +stateNow[1].toFixed(1), verify_ms: +verifyMs.toFixed(1),
      apply_cold_ms: +applyCold.toFixed(1), apply_warm_median_ms: +warm[1].toFixed(1), next_ms: +nextMs.toFixed(1), next_start: nextR.start.length };
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}
