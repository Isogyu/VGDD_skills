// 結合の試験：vgdd/next の 8 つの部品が 1 つの流れとしてつながるか、つながらない箇所はどこか（起草段階の試作）
//
// 前半：examples/walkthrough.mjs の流れ（領域パック → 編成 → 実行の記録 → 経験 → 申請と判定 → 経験の蓄積 → 追跡 → 改善提案 → 統治の確認）を
//       1 回動かし、各段の出力が次の段の入力に使われ、期待どおりの結果になることを確かめる。
// 後半：部品の間の食い違い（行為者・系統・ID と指紋・範囲・状態の名前・時刻・規則の版と設定・つながらない箇所・API）が
//       今の実装で実際にそうなっていることを、部品を呼んで確かめる。流れを通すために試験の側で値を変換した箇所は、
//       walkthrough の adaptations に 1 件ずつ記録されており、後半はその裏づけである。
//       後半の試験は「今こうなっている」ことの記録で、直すべきと決めたものではない。部品が直れば、この試験は意図して書き換える。
//
// 部品（vgdd/next/*.mjs・lib/）と既存の試験・bench は変更していない。

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import * as rsMod from '../runstate.mjs';
import { parseActor, parseEvent, ROLES as RS_ROLES, DEFAULT_CONFIG, openRun } from '../runstate.mjs';
import { openTrace, SCRIPT_ROLES, parseTs, check as trCheck, linksFromEvidence } from '../trace.mjs';
import { openExperience, isJudicialRole, JUDICIAL_ROLES as EX_JUDICIAL, check as exCheck, REF_RE } from '../experience.mjs';
import { openImprovements, JUDICIAL_ROLES as IM_JUDICIAL, check as imCheck, CAPS_PATH } from '../improvement.mjs';
import { validateTeam, catalogFromCapabilities, normLineage } from '../team.mjs';
import { STATUSES, parsePattern, covers } from '../taskgraph.mjs';
import { openChain, Refused } from '../lib/chain.mjs';
import { runWalkthrough, refusalOf, TICKETS, CAPS_FILE } from '../examples/walkthrough.mjs';

const dirs = [];
const scratch = () => { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'vgdd-next-int-')); dirs.push(d); return d; };
after(() => { for (const d of dirs) fs.rmSync(d, { recursive: true, force: true }); });

const caps = JSON.parse(fs.readFileSync(CAPS_FILE, 'utf8'));
const hex = (c, n) => c.repeat(n);
const SD = `sha256:${hex('a', 64)}`;
/** 例外（Refused）を { code, guards } にして返す。通ったら null */
const refused = (fn) => { try { fn(); return null; } catch (e) { if (!(e instanceof Refused)) throw e; return refusalOf(e); } };

// =====================================================================
// 前半：結合の流れ
// =====================================================================
describe('結合：3 つの票を開発の領域パックで進める（領域パック → 編成 → 実行 → 経験 → 追跡 → 改善 → 統治）', () => {
  let W;
  before(() => { W = runWalkthrough({ dir: scratch() }); });

  it('段 1：領域パック software-dev が検査を通り、票の ID の形が使える', () => {
    assert.equal(W.packResult.ok, true);
    assert.equal(W.pack.id, 'software-dev');
    const re = new RegExp(W.pack.work_item.id_pattern);
    for (const t of TICKETS) assert.ok(re.test(t.id));
    assert.equal(W.policyLine, 'p0.4');
  });

  it('段 2：行政の長の編成案（作業員 2 体＋司法 2 体）が通り、requires_approval は true、効力は none', () => {
    assert.equal(W.teamResult.ok, true);
    assert.equal(W.teamResult.requires_approval, true);
    assert.equal(W.teamResult.effect, 'none');
    assert.deepEqual(Object.keys(W.catalog).sort(), Object.keys(W.caps.roles).sort(), 'catalog は capabilities.json の roles から作る');
    assert.equal(W.teamRefusal.ok, false);
    assert.ok(W.teamRefusal.violations.some((v) => v.guard === 'TM-HUMAN-SEAT'), '裁判所は編成に入れられない');
  });

  it('段 3：config → plan → approve の後、next() が着手の組（独立の 2 節）と待ち（依存する 1 節）を返す', () => {
    assert.deepEqual([...W.next1.start].sort(), ['t-101', 't-102']);
    assert.ok(['single', 'parallel', 'staged'].includes(W.next1.recommend.topology));
    const w = W.next1.waiting.find((x) => x.id === 't-103');
    assert.ok(w && w.reasons.every((r) => r.startsWith('waiting_dependency')));
    const first = W.rows[0];
    assert.equal(first.op, 'config');
    assert.deepEqual(first.actor, { role: 'owner', kind: 'human', id: 'azuki' });
    assert.deepEqual(first.judiciary, [{ kind: 'judge', lineage: 'claude' }, { kind: 'judge', lineage: 'codex' }]);
    assert.equal(first.security_lineage, 'codex');
    const s = W.run.state();
    assert.equal(s.config.policy_line, 'p0.4');
    assert.equal(s.nodes['t-102'].security_review, true);
  });

  it('段 4：着手の前の retrieve は空で、作業員への指示に添える文字列も空', () => {
    for (const r of [W.r101, W.r102]) { assert.deepEqual(r.items, []); assert.equal(r.rendered, ''); assert.equal(r.searchKind, 'lexical'); }
  });

  it('段 5：T-101 は 1 回目に差し戻し（claude・codex とも CHANGES_REQUIRED）、再申請で合格。T-102 は security を含めて合格', () => {
    assert.equal(W.v1.kind, 'return');
    assert.equal(W.v1.to, 'in_progress');
    assert.equal(W.v1.node.returns, 1);
    assert.equal(W.v2.kind, 'pass');
    assert.equal(W.v3.kind, 'pass');
    const s = W.run.state();
    for (const id of ['t-101', 't-102', 't-103']) assert.equal(s.nodes[id].status, 'merged');
    assert.equal(s.nodes['t-101'].returns, 1);
    assert.equal(s.nodes['t-101'].attempts, 2, 'start の 1 回と、差し戻しでの作業員の起動し直し 1 回');
    const sec = W.rows.find((r) => r.op === 'verdict' && r.node === 't-102');
    assert.ok(sec.verdicts.some((v) => v.kind === 'security' && v.lineage === 'codex' && v.verdict === 'APPROVED'));
  });

  it('段 6：差し戻しの指摘から reflection → 3 つの票から induce → オーナーが昇格 → T-103 の着手の前に引用の形で出る', () => {
    assert.equal(W.refl.length, 3);
    for (const r of W.refl) { assert.equal(r.layer, 'reflection'); assert.equal(r.trust, 'grounded'); assert.equal(r.provenance[0].kind, 'verdict_finding'); }
    assert.deepEqual(W.refl.map((r) => r.provenance[0].task), ['T-101', 'T-102', 'T-090']);
    assert.equal(W.induced.layer, 'experience');
    assert.equal(W.promoted.status, 'adopted');
    const top = W.r103.items[0];
    assert.equal(top.id, W.induced.id);
    assert.equal(top.status, 'adopted');
    assert.match(W.r103.rendered, /囲みの中は\*\*引用\*\*/);
    assert.ok(W.r103.rendered.includes('```text'));
    assert.ok(W.r103.rendered.includes(W.induced.text.normalize('NFKC')), '本文は NFKC にそろえて（全角の括弧が半角に変わって）渡る');
    // 候補のままの reflection も出るが「未検証の仮説」と明記される
    assert.ok(W.r103.items.length >= 2);
    assert.ok(W.r103.rendered.includes('未検証の仮説'));
  });

  it('段 6：T-103 の合格の後に feedback（helpful）が入り、司法の役割への retrieve は拒まれる', () => {
    assert.equal(W.fb[0].helpful, 1);
    assert.equal(W.fb[0].harmful, 0);
    assert.ok(W.judgeAsk.refused && W.judgeAsk.items.length === 0 && W.judgeAsk.rendered === '');
    const ev = W.exp.state().items.get(W.induced.id);
    assert.equal(ev.helpful, 1);
  });

  it('段 7：要件→票→仕様の指紋→承認→申請→監査・判定→統合→受け入れの段が 3 要件ともそろい、差し戻された 1 回目の申請が見える', () => {
    for (const row of W.cov.rows) {
      for (const k of ['ticket', 'spec', 'approval', 'request', 'audit', 'verdict', 'merge', 'acceptance']) assert.equal(row.stages[k], true, `${row.requirement}.${k}`);
      assert.equal(row.stages.incident, false);
    }
    assert.deepEqual(W.cov.rows.map((r) => r.requirement), ['R-1', 'R-2', 'R-3']);
    const r1 = W.cov.rows[0];
    assert.equal(r1.requests, 2);
    assert.equal(r1.returned_requests, 1);
    assert.equal(r1.approved_requests, 1);
    assert.equal(r1.verdict_basis, 'required_kinds');
    // T-102 は security_review つきなので、必須の判定の種類に codex-security が入る
    assert.equal(W.cov.rows[1].verdict_basis, 'required_kinds');
    assert.equal(W.cov.integrity.ok, true);
  });

  it('段 7：gaps は「差し戻された 1 回目の申請」の 2 件だけ。障害を足すと「対応の票がない」が出る', () => {
    const first = W.req['T-101'][0];
    assert.deepEqual(W.gaps1.gaps.map((g) => [g.code, g.kind, g.id]), [['REQUEST_CHANGES_REQUIRED', 'request', first], ['REQUEST_NOT_MERGED', 'request', first]]);
    assert.equal(W.gaps1.undetermined_count, 0);
    assert.deepEqual(W.gaps2.gaps.map((g) => g.code).sort(), ['INCIDENT_NO_TICKET', 'REQUEST_CHANGES_REQUIRED', 'REQUEST_NOT_MERGED']);
    assert.equal(W.gaps2.gaps.find((g) => g.code === 'INCIDENT_NO_TICKET').id, 'INC-001');
    assert.deepEqual(W.cov2.rows.find((r) => r.requirement === 'R-3').incidents, ['INC-001']);
  });

  it('段 7：承認の指紋・申請・判定は runstate の記録の値で、trace をたどると同じ値に戻る', () => {
    const t = W.tr.trace({ kind: 'ticket', id: 'T-101' }, { direction: 'both' });
    assert.equal(t.found, true);
    const upKinds = new Set(t.up.nodes.map((n) => n.kind));
    assert.ok(upKinds.has('requirement') && upKinds.has('goal'));
    const downIds = t.down.nodes.map((n) => n.id);
    assert.ok(downIds.includes(W.specDigest['T-101']));
    assert.ok(downIds.includes(W.approveHash['T-101']));
    assert.ok(downIds.includes(W.req['T-101'][0]) && downIds.includes(W.req['T-101'][1]));
    assert.ok(downIds.includes(W.mergeSha['T-101']) && downIds.includes(W.accId['T-101']));
    const approveRow = W.rows.find((r) => r.op === 'approve' && r.node === 't-101');
    assert.equal(W.approveHash['T-101'], `sha256:${approveRow.hash}`);
  });

  it('段 8：差し戻しの経験から手順（playbook）の改善を提案 → 評価 → codex の judge の審査 → オーナーが採用', () => {
    const p = W.im.get(W.playbook.id);
    assert.equal(p.tier, 'playbook');
    assert.equal(p.status, 'adopted');
    assert.deepEqual(p.content.derived_from, [W.induced.id]);
    assert.equal(p.route.lane, 'standard');
    const ev = p.evaluations[0].evidence.conformance;
    assert.ok(ev.after.total > ev.before.total, '試験の数は増える');
    assert.ok(ev.new_cases_fail_on_before >= 1, '足した試験は前の版で落ちる');
    assert.deepEqual(p.reviews.map((r) => [r.actor.role, r.actor.lineage, r.verdict]), [['codex_judge', 'codex', 'APPROVED']]);
    assert.equal(W.im.adoptionValid(p.id), true);
  });

  it('段 8：「作業員に main への統合を許す」は緩めると分類され、通常の経路では採用できない。probe を足す変更は採用できる', () => {
    assert.equal(W.dLoose.class, 'loosening');
    assert.equal(W.lawLoose.route.lane, 'full_legislative');
    assert.equal(W.im.get(W.lawLoose.id).status, 'reviewed', '採用されずに残る');
    assert.ok(W.refusals.some((r) => r.stage === 8 && r.guards.includes('IM-FULL-LEGISLATIVE')));
    assert.ok(W.refusals.some((r) => r.stage === 8 && r.guards.includes('IM-CROSS-LINEAGE')), '実際の憲法審査は Claude 系統で、Claude の提案者と同じ系統');
    assert.equal(W.dTight.class, 'tightening');
    assert.equal(W.lawTight.route.lane, 'standard');
    assert.equal(W.im.get(W.lawTight.id).status, 'adopted');
  });

  it('段 9：行政の長は verdict・approve・release・採用・昇格・feedback・つながりの記録をどれも起こせない', () => {
    const labels = W.refusals.filter((r) => r.stage === 9).map((r) => r.label);
    for (const needle of ['verdict', 'approve', 'release', '採用', '昇格', 'feedback', 'つながり']) assert.ok(labels.some((l) => l.includes(needle)), needle);
    const g = (needle) => W.refusals.find((r) => r.stage === 9 && r.label.includes(needle)).guards;
    assert.ok(g('verdict').includes('RS-ROLE-OP') && g('verdict').includes('RS-KIND-OP'));
    assert.ok(g('approve').includes('RS-ROLE-OP'));
    assert.ok(g('release').includes('RS-ROLE-OP'));
    assert.ok(g('採用').includes('IM-ADOPT-HUMAN-OWNER'));
    assert.deepEqual(g('昇格'), ['EX-PROMOTE-OWNER']);
    assert.deepEqual(g('feedback'), ['EX-FEEDBACK-ACTOR']);
    assert.deepEqual(g('つながり'), ['TR-WRITER-ALLOWED']);
  });

  it('段 9：停止（stop）の後は start が拒まれ、再開（resume）の後に続けられる。全部の記録の verify が ok', () => {
    assert.ok(W.refusals.some((r) => r.stage === 9 && r.guards.includes('RS-STOPPED')));
    assert.equal(W.run.state().stopped, false);
    assert.equal(W.run.state().nodes['t-104'].status, 'in_progress');
    for (const k of ['run', 'experience', 'trace', 'improvement']) assert.equal(W.verify[k].ok, true, k);
    // 記録のファイルは別々に開き直しても同じ（再生で作り直せる）
    assert.equal(openRun(W.files.run).verify().ok, true);
    assert.equal(openTrace(W.files.trace).verify().ok, true);
  });

  it('流れを通すために試験の側で変換した値が、1 件ずつ記録されている', () => {
    const whats = W.adaptations.map((a) => a.what);
    for (const needle of ['行政の長の役割名', '夜間の代行の役割名', '裁判所のスクリプトの役割名（runstate 用）', '裁判所のスクリプトの役割名（trace 用）', '人の lineage', 'スクリプトの lineage',
      '票の ID（大文字 → 小文字）', '節の定義の指紋', '判定の種類', '承認の指紋', '統合のコミット', '追跡の判定・監査の id', '出どころの ref', 'codex の security 審査の役割']) {
      assert.ok(whats.some((w) => w.includes(needle)), `変換の記録がない: ${needle}`);
    }
    assert.ok(W.adaptations.length >= 14);
    // 変換が要らなかった例（trace が両者の書式を取り込んである）も記録している
    assert.ok(whats.includes('改善提案の id と経験の id'));
  });
});

// =====================================================================
// 後半：食い違い
// =====================================================================
describe('食い違い：行為者の表し方（role・kind・id・lineage）', () => {
  const ROLE_CANDIDATES = ['owner', 'executive', 'executive_head', 'worker', 'judge', 'codex_judge', 'court', 'gate_runner', 'court_script', 'night_agent', 'night_runner', 'reaper'];

  it('runstate は lineage を持つ行為者を拒み、improvement は lineage のない行為者を拒む（同じ行為者の値を共有できない）', () => {
    const shared = { role: 'executive', kind: 'ai', id: 'exec-head' };
    assert.equal(parseActor(shared).ok, true);
    const withLineage = parseActor({ ...shared, lineage: 'claude' });
    assert.equal(withLineage.ok, false);
    assert.match(withLineage.errors.join(), /知らない項目: lineage/);
    const d = scratch();
    const im = openImprovements(path.join(d, 'i.jsonl'), { currentCapabilities: caps });
    const e = refused(() => im.propose(shared, { title: 't', tier: 'playbook', target: { name: 'x' }, content: 'c' }));
    assert.deepEqual(e.guards, ['IM-ACTOR-SHAPE']);
    // trace は lineage を任意で受ける。experience は受けるが捨てる（記録に残らない）
    const t = openTrace(path.join(d, 't.jsonl'));
    assert.equal(trCheck(t.contextFor('link', { role: 'court_script', kind: 'script', id: 'cs', lineage: 'x' }, { rel: 'satisfies', from: { kind: 'ticket', id: 'T-101' }, to: { kind: 'requirement', id: 'R-1' } }), ['TR-ACTOR-SHAPE']).ok, true);
    const ex = openExperience(path.join(d, 'e.jsonl'));
    ex.add({ role: 'court', kind: 'script', id: 'c', lineage: 'script' }, { text: 'abc', scope: { domain: 'software-dev', roles: ['worker'], tags: [] }, provenance: [{ kind: 'obs', ref: 'x', task: 'T-1' }] });
    assert.equal(Object.hasOwn(ex.state().items.get('exp-000001').provenance[0], 'lineage'), false);
    assert.deepEqual(Object.keys(JSON.parse(fs.readFileSync(path.join(d, 'e.jsonl'), 'utf8').split('\n')[0]).actor).sort(), ['id', 'kind', 'role']);
  });

  it('役割の名前の一覧が部品ごとに違い、同じ主体を同じ名前で渡せるのは owner だけ', () => {
    const d = scratch();
    const t = openTrace(path.join(d, 't.jsonl'));
    const link = { rel: 'satisfies', from: { kind: 'ticket', id: 'T-101' }, to: { kind: 'requirement', id: 'R-1' } };
    const catalog = catalogFromCapabilities(caps);
    const acceptedBy = {
      runstate: ROLE_CANDIDATES.filter((r) => parseActor({ role: r, kind: r === 'owner' ? 'human' : 'script', id: 'x1' }).ok),
      trace: ROLE_CANDIDATES.filter((r) => trCheck(t.contextFor('link', { role: r, kind: r === 'owner' ? 'human' : 'script', id: 'x1' }, link), ['TR-ACTOR-SHAPE', 'TR-WRITER-ALLOWED', 'TR-SCRIPT-ROLE']).ok),
      team: ROLE_CANDIDATES.filter((r) => Object.hasOwn(catalog, r)),
      improvementScript: ROLE_CANDIDATES.filter((r) => imCheck({ actor: { role: r, kind: 'script', id: 'x1', lineage: 'script' } }, ['IM-ACTOR-SHAPE']).ok),
      experienceScript: ROLE_CANDIDATES.filter((r) => exCheck({ op: 'feedback', actor: { role: r, kind: 'script', id: 'x1' } }, ['EX-ACTOR', 'EX-FEEDBACK-ACTOR']).ok),
    };
    assert.deepEqual(acceptedBy.runstate, ['owner', 'executive', 'court', 'night_agent', 'reaper']);
    assert.deepEqual(acceptedBy.trace, ['owner', 'gate_runner', 'court_script']);
    assert.deepEqual(acceptedBy.team, ['owner', 'executive_head', 'worker', 'judge', 'codex_judge', 'gate_runner', 'night_runner']);
    assert.deepEqual(acceptedBy.improvementScript, ROLE_CANDIDATES, 'improvement は script の役割名を見ない（形だけ）');
    assert.deepEqual(acceptedBy.experienceScript, ROLE_CANDIDATES, 'experience は feedback の役割名を見ない（kind: script だけ）');
    // runstate と trace が script として受ける役割名は重ならない。3 部品（runstate・trace・team）で通る名前は owner だけ
    assert.deepEqual(RS_ROLES.filter((r) => SCRIPT_ROLES.includes(r)), []);
    assert.deepEqual(acceptedBy.runstate.filter((r) => acceptedBy.trace.includes(r) && acceptedBy.team.includes(r)), ['owner']);
    // 同じ「行政の長」も、runstate では executive、team・improvement・capabilities.json では executive_head
    assert.ok(RS_ROLES.includes('executive') && !Object.hasOwn(catalog, 'executive'));
  });

  it('作業員（worker）と司法（judge）は runstate の行為者になれない。着手・申請は行政の長か夜間の代行の名前で記録される', () => {
    for (const r of ['worker', 'judge', 'codex_judge', 'executive_head']) assert.equal(parseActor({ role: r, kind: 'ai', id: 'x1' }).ok, false, r);
    const d = scratch();
    const run = openRun(path.join(d, 'r.jsonl'));
    const owner = { role: 'owner', kind: 'human', id: 'azuki' };
    run.apply(owner, { op: 'config', event_id: 'c1', ...DEFAULT_CONFIG, workers: 2, policy_line: 'p0.4' });
    run.apply({ role: 'executive', kind: 'ai', id: 'exec-head' }, { op: 'plan', event_id: 'p1', nodes: [{ id: 't-1', depends_on: [], resources: ['a/**'] }] });
    run.apply(owner, { op: 'approve', event_id: 'a1', node: 't-1', spec_digest: SD, policy_line: 'p0.4', def_digest: run.state().nodes['t-1'].def_digest });
    run.apply({ role: 'executive', kind: 'ai', id: 'exec-head' }, { op: 'start', event_id: 's1', node: 't-1', spec_digest: SD, lease_sec: 60 });
    assert.equal(run.state().nodes['t-1'].worker, 'exec-head', '作業員の id でなく、起こした側の id が worker に入る');
  });

  it('行為者は申告で、行政の長が owner を名乗れば runstate は通す（README §5.1 の限界。部品の間の食い違いではなく共通の限界）', () => {
    const d = scratch();
    const run = openRun(path.join(d, 'r.jsonl'));
    const claimed = { role: 'owner', kind: 'human', id: 'exec-head' };
    run.apply(claimed, { op: 'config', event_id: 'c1', ...DEFAULT_CONFIG, policy_line: 'p0.4' });
    assert.equal(run.state().config.policy_line, 'p0.4');
  });

  it('司法の役割の判定が部品ごとに違う：experience は security を司法とみなさず、経験を渡してしまう', () => {
    // 司法とみなす名前：experience は 6 つ＋部分一致、improvement は審査者になれる 3 つだけ、runstate・trace・team は司法の判定の名前を持たない
    assert.deepEqual(EX_JUDICIAL, ['judge', 'codex_judge', 'constitutional_review', 'gate_runner', 'court', 'judiciary']);
    assert.deepEqual(IM_JUDICIAL, ['judge', 'codex_judge', 'constitutional_review']);
    for (const r of ['court', 'gate_runner', 'court_script', 'codex-judge']) assert.equal(isJudicialRole(r), true, r);
    for (const r of ['security', 'codex_security', 'security_reviewer', 'night_agent', 'reaper', 'executive']) assert.equal(isJudicialRole(r), false, r);
    // runstate・trace が司法の判定として扱う security 審査（codex-security）の役割名で retrieve すると、経験が渡る
    const d = scratch();
    const ex = openExperience(path.join(d, 'e.jsonl'));
    ex.add({ role: 'court', kind: 'script', id: 'c' }, { text: '入力検証の観点を確かめる', scope: { domain: 'software-dev', roles: ['codex_security'], tags: ['a'] }, provenance: [{ kind: 'verdict_finding', ref: 'VRD-aaaaaaaaaaaa-codex-security#1', task: 'T-1' }] });
    const got = ex.retrieve({ audience: { role: 'codex_security' }, query: { text: '入力検証', domain: 'software-dev' } });
    assert.equal(got.items.length, 1, 'security 審査の役割に経験が渡る（司法の独立に穴）');
    assert.equal(got.refused, undefined);
    assert.ok(ex.retrieve({ audience: { role: 'codex_judge' }, query: { text: '入力検証', domain: 'software-dev' } }).refused);
  });

  it('experience の feedback は役割名を見ず、kind: script なら worker という名前でも通る（裁判所の側であることを役割で確かめない）', () => {
    const d = scratch();
    const ex = openExperience(path.join(d, 'e.jsonl'));
    ex.add({ role: 'court', kind: 'script', id: 'c' }, { text: 'abc', scope: { domain: 'software-dev', roles: ['worker'], tags: [] }, provenance: [{ kind: 'obs', ref: 'x', task: 'T-1' }] });
    const out = ex.feedback({ role: 'worker', kind: 'script', id: 'w' }, { item_ids: ['exp-000001'], outcome: 'helpful', evidence: { kind: 'verdict', ref: 'x1', task: 'T-1' } });
    assert.equal(out[0].helpful, 1);
  });
});

describe('食い違い：系統（lineage）の書式・正規化・既定の名前', () => {
  const verdictEv = (lineage) => ({ op: 'verdict', event_id: 'v1', node: 't-1', request: hex('a', 40), audits: 'passed', verdicts: [{ kind: 'judge', judge: 'j', lineage, verdict: 'APPROVED', major: false }] });

  it('許す文字が違う：team はハイフンと大文字（小文字に直す）を受け、runstate は小文字・数字・_ だけ、trace は行為者の lineage に大文字を受けない', () => {
    assert.equal(normLineage(' Open-AI '), 'open-ai');
    assert.equal(normLineage('open ai'), null);
    assert.equal(parseEvent(verdictEv('open-ai')).ok, false, 'runstate はハイフンを許さない（LINEAGE_RE）');
    assert.equal(parseEvent(verdictEv('Claude')).ok, false, 'runstate は小文字に直さず拒む');
    assert.equal(parseEvent(verdictEv('open_ai')).ok, true);
    const d = scratch();
    const t = openTrace(path.join(d, 't.jsonl'));
    const link = { rel: 'satisfies', from: { kind: 'ticket', id: 'T-101' }, to: { kind: 'requirement', id: 'R-1' } };
    const shape = (lineage) => trCheck(t.contextFor('link', { role: 'court_script', kind: 'script', id: 'cs', lineage }, link), ['TR-ACTOR-SHAPE']).ok;
    assert.equal(shape('open-ai'), true);
    assert.equal(shape('Claude'), false);
  });

  it('improvement は lineage を NFKC・小文字にそろえて比べる（Claude と claude は同じ系統）が、runstate は別物として拒む', () => {
    const d = scratch();
    const im = openImprovements(path.join(d, 'i.jsonl'), { currentCapabilities: caps });
    const p = im.propose({ role: 'executive_head', kind: 'ai', id: 'h', lineage: 'Claude' }, { title: 't', tier: 'playbook', target: { name: 'x' }, content: 'c' });
    im.evaluate({ role: 'court', kind: 'script', id: 'ev', lineage: 'script' }, p.id, { digest: p.digest, evidence: { conformance: { before: { total: 1, passed: 1 }, after: { total: 1, passed: 1 } } } });
    const input = { digest: p.digest, verdict: 'APPROVED', findings: [], review_input_digest: im.reviewInputFor(p.id).digest };
    const e = refused(() => im.review({ role: 'judge', kind: 'ai', id: 'j', lineage: 'claude' }, p.id, input));
    assert.deepEqual(e.guards, ['IM-CROSS-LINEAGE']);
  });

  it('既定の名前は claude・codex だけで、anthropic・openai の別名の表はどこにもない。improvement は claude の提案を anthropic が審査できてしまう', () => {
    assert.deepEqual(DEFAULT_CONFIG.judiciary.map((j) => j.lineage), ['claude', 'codex']);
    assert.equal(DEFAULT_CONFIG.security_lineage, 'codex');
    const catalog = catalogFromCapabilities(caps);
    assert.equal(catalog.judge.lineage, 'claude');
    assert.equal(catalog.codex_judge.lineage, 'codex');
    // runstate：config の必須の審査にない系統の名前は拒む。team：catalog の系統と違う申告は拒む
    assert.equal(parseEvent(verdictEv('anthropic')).ok, true, '形は通る');
    const d = scratch();
    const run = openRun(path.join(d, 'r.jsonl'));
    const owner = { role: 'owner', kind: 'human', id: 'azuki' };
    run.apply(owner, { op: 'config', event_id: 'c1', ...DEFAULT_CONFIG, workers: 2, policy_line: 'p0.4' });
    run.apply({ role: 'executive', kind: 'ai', id: 'h' }, { op: 'plan', event_id: 'p1', nodes: [{ id: 't-1', depends_on: [], resources: ['a/**'] }] });
    run.apply(owner, { op: 'approve', event_id: 'a1', node: 't-1', spec_digest: SD, policy_line: 'p0.4', def_digest: run.state().nodes['t-1'].def_digest });
    run.apply({ role: 'executive', kind: 'ai', id: 'h' }, { op: 'start', event_id: 's1', node: 't-1', spec_digest: SD, lease_sec: 60 });
    run.apply({ role: 'executive', kind: 'ai', id: 'h' }, { op: 'submit', event_id: 'u1', node: 't-1', request: hex('a', 40) });
    const e1 = refused(() => run.apply({ role: 'court', kind: 'script', id: 'cs' }, { ...verdictEv('anthropic'), verdicts: [{ kind: 'judge', judge: 'j', lineage: 'anthropic', verdict: 'APPROVED', major: false }, { kind: 'judge', judge: 'k', lineage: 'codex', verdict: 'APPROVED', major: false }] }));
    assert.ok(e1.guards.includes('RS-VERDICT-SET'));
    const plan = { task: 'x', proposed_by: 'h', members: [{ id: 'h', template: 'executive_head', scope: { resources: [], tools: [] } }, { id: 'j', template: 'judge', lineage: 'anthropic', scope: { resources: [], tools: [] } }, { id: 'k', template: 'codex_judge', scope: { resources: [], tools: [] } }] };
    const tv = validateTeam(plan, { catalog, ticket: { resources: [] }, limits: { workers: 4 } });
    assert.ok(tv.violations.some((v) => v.guard === 'TM-LINEAGE-HONEST'));
    // improvement は申告をそのまま比べる：claude の提案を anthropic（同じ Anthropic のモデル）が審査して通る
    const im = openImprovements(path.join(d, 'i.jsonl'), { currentCapabilities: caps });
    const p = im.propose({ role: 'executive_head', kind: 'ai', id: 'h', lineage: 'claude' }, { title: 't', tier: 'playbook', target: { name: 'x' }, content: 'c' });
    im.evaluate({ role: 'court', kind: 'script', id: 'ev', lineage: 'script' }, p.id, { digest: p.digest, evidence: { conformance: { before: { total: 1, passed: 1 }, after: { total: 1, passed: 1 } } } });
    const r = im.review({ role: 'judge', kind: 'ai', id: 'j', lineage: 'anthropic' }, p.id, { digest: p.digest, verdict: 'APPROVED', findings: [], review_input_digest: im.reviewInputFor(p.id).digest });
    assert.equal(r.status, 'reviewed');
  });
});

describe('食い違い：ID と指紋の書式', () => {
  const link = (rel, from, to, evidence) => ({ rel, from, to, ...(evidence ? { evidence } : {}) });
  const CS = { role: 'court_script', kind: 'script', id: 'cs' };

  it('票の ID：領域パック・trace・experience は大文字の T-101、runstate の節は小文字だけで、変換なしには対応づけられない', () => {
    const pack = JSON.parse(fs.readFileSync(path.resolve(path.dirname(CAPS_FILE), '../next/domains/software-dev.json'), 'utf8'));
    const re = new RegExp(pack.work_item.id_pattern);
    assert.equal(re.test('T-101'), true);
    assert.equal(re.test('t-101'), false);
    const plan = (id) => parseEvent({ op: 'plan', event_id: 'e1', nodes: [{ id, depends_on: [], resources: ['a/**'] }] }).ok;
    assert.equal(plan('T-101'), false);
    assert.equal(plan('t-101'), true);
    const d = scratch();
    const t = openTrace(path.join(d, 't.jsonl'));
    assert.equal(t.link(CS, link('satisfies', { kind: 'ticket', id: 'T-101' }, { kind: 'requirement', id: 'R-1' })).seq, 1);
    assert.ok(refused(() => t.link(CS, link('satisfies', { kind: 'ticket', id: 't-101' }, { kind: 'requirement', id: 'R-2' }))).guards.includes('TR-ID-FORMAT'));
    // experience の task は大文字小文字とも通る（TASK_RE）。同じ票が別の綴りで別物として数えられる余地がある
    const ex = openExperience(path.join(d, 'e.jsonl'));
    for (const task of ['T-101', 't-101']) ex.add({ role: 'court', kind: 'script', id: 'c' }, { text: `abc ${task}`, scope: { domain: 'software-dev', roles: ['worker'], tags: [] }, provenance: [{ kind: 'obs', ref: `x-${task}`, task }] });
    assert.equal(ex.state().items.size, 2);
  });

  it('runstate が受ける節の id（fix-login・t-1.2 など）は、trace の票の ID の形（T-+3〜4 桁）に写せない', () => {
    for (const id of ['fix-login', 't-1.2', 'a_b', 't-12345']) assert.equal(parseEvent({ op: 'plan', event_id: 'e1', nodes: [{ id, depends_on: [], resources: ['a/**'] }] }).ok, true, id);
    const d = scratch();
    const t = openTrace(path.join(d, 't.jsonl'));
    for (const id of ['fix-login', 'T-1.2', 'T-12345', 'T-12']) assert.deepEqual(refused(() => t.link(CS, link('satisfies', { kind: 'ticket', id }, { kind: 'requirement', id: 'R-1' }))).guards, ['TR-ID-FORMAT'], id);
  });

  it('申請の指紋：runstate は 7〜64 桁の 16 進と sha256: 形式を受けるが、trace の申請は 40 桁の SHA だけ（40 桁なら両方が通る）', () => {
    for (const q of [hex('a', 12), hex('a', 7), SD, hex('a', 40)]) assert.equal(parseEvent({ op: 'submit', event_id: 'e1', node: 't-1', request: q }).ok, true, q);
    assert.equal(parseEvent({ op: 'submit', event_id: 'e1', node: 't-1', request: hex('A', 40) }).ok, false, '大文字は runstate が拒む');
    const d = scratch();
    const t = openTrace(path.join(d, 't.jsonl'));
    const tryReq = (id) => refused(() => t.link(CS, link('verifies', { kind: 'audit', id: 'AUD-aaaaaaaaaaaa' }, { kind: 'request', id })));
    assert.deepEqual(tryReq(hex('a', 12)).guards, ['TR-ID-FORMAT']);
    assert.deepEqual(tryReq(SD).guards, ['TR-ID-FORMAT']);
    assert.equal(tryReq(hex('a', 40)), null);
  });

  it('仕様の指紋は両方が sha256:<64 桁>。承認の指紋は trace が sha256: つき、runstate の行の hash は接頭辞なしで、写す必要がある', () => {
    const d = scratch();
    const W = runWalkthrough({ dir: d });
    const row = W.rows.find((r) => r.op === 'approve');
    assert.match(row.spec_digest, /^sha256:[0-9a-f]{64}$/);
    assert.match(row.hash, /^[0-9a-f]{64}$/);
    const t = openTrace(path.join(scratch(), 't.jsonl'));
    assert.deepEqual(refused(() => t.link(CS, link('approves', { kind: 'approval', id: row.hash }, { kind: 'spec', id: row.spec_digest }))).guards, ['TR-ID-FORMAT']);
    assert.equal(t.link(CS, link('approves', { kind: 'approval', id: `sha256:${row.hash}` }, { kind: 'spec', id: row.spec_digest })).seq, 1);
  });

  it('判定の種類：runstate の（kind, lineage）と trace の判定の種類（judge・codex-judge・codex-security・codex-ux）の対応は表にない。claude 系統の security は写せない', () => {
    const W = runWalkthrough({ dir: scratch() });
    assert.equal(W.modeOf('judge', 'claude'), 'judge');
    assert.equal(W.modeOf('judge', 'codex'), 'codex-judge');
    assert.equal(W.modeOf('security', 'codex'), 'codex-security');
    assert.throws(() => W.modeOf('security', 'claude'), /写せない/);
    assert.throws(() => W.modeOf('judge', 'gemini'), /写せない/);
    const t = openTrace(path.join(scratch(), 't.jsonl'));
    assert.deepEqual(refused(() => t.link(CS, link('verifies', { kind: 'verdict', id: 'VRD-aaaaaaaaaaaa-gemini-judge' }, { kind: 'request', id: hex('a', 40) }))).guards, ['TR-ID-FORMAT']);
  });

  it('improvement の IMP-0001 と experience の exp-000001 は trace の書式と一致する（変換なしで使える）', () => {
    const W = runWalkthrough({ dir: scratch() });
    assert.match(W.playbook.id, /^IMP-\d{4}$/);
    assert.match(W.induced.id, /^exp-\d{6}$/);
    const t = W.tr.trace({ kind: 'improvement', id: W.playbook.id }, { direction: 'up' });
    assert.ok(t.up.nodes.some((n) => n.kind === 'experience' && n.id === W.induced.id));
    assert.match('VRD-aaaaaaaaaaaa-codex-judge#finding-1', REF_RE, 'trace の判定の id に # をつけた形は experience の ref の書式に合う（規約はどこにもない）');
  });
});

describe('食い違い：範囲（resources）', () => {
  it('runstate は taskgraph が扱えない形の範囲（[a] を含む）を plan で受ける。扱えない形は重なりとみなされ、他の節の着手を止める', () => {
    assert.equal(parsePattern('src/[a]*'), null);
    assert.equal(covers('src/**', 'src/[a]*'), null);
    const d = scratch();
    const run = openRun(path.join(d, 'r.jsonl'));
    const owner = { role: 'owner', kind: 'human', id: 'azuki' };
    const head = { role: 'executive', kind: 'ai', id: 'h' };
    run.apply(owner, { op: 'config', event_id: 'c1', ...DEFAULT_CONFIG, workers: 2, policy_line: 'p0.4' });
    run.apply(head, { op: 'plan', event_id: 'p1', nodes: [{ id: 't-1', depends_on: [], resources: ['src/[a]*'] }, { id: 't-2', depends_on: [], resources: ['src/b/**'] }] });
    for (const id of ['t-1', 't-2']) run.apply(owner, { op: 'approve', event_id: `a-${id}`, node: id, spec_digest: SD, policy_line: 'p0.4', def_digest: run.state().nodes[id].def_digest });
    const n = run.next();
    assert.deepEqual(n.start, ['t-1']);
    assert.deepEqual(n.waiting, [{ id: 't-2', reasons: ['resource_conflict:t-1'] }]);
    // team は同じ形を「包含を判定できない」として拒む
    const catalog = catalogFromCapabilities(caps);
    const v = validateTeam({ task: 'x', proposed_by: 'h', members: [{ id: 'h', template: 'executive_head', scope: { resources: ['src/[a]*'], tools: [] } }, { id: 'j', template: 'codex_judge', scope: { resources: [], tools: [] } }] }, { catalog, ticket: { resources: ['src/**'] }, limits: { workers: 2 } });
    assert.ok(v.violations.some((x) => x.guard === 'TM-SCOPE-RESOURCES'));
  });

  it('領域パックの protected（vgdd/** など）を、runstate は見ない。保護されたパスの節も plan に入る', () => {
    const d = scratch();
    const run = openRun(path.join(d, 'r.jsonl'));
    run.apply({ role: 'owner', kind: 'human', id: 'azuki' }, { op: 'config', event_id: 'c1', ...DEFAULT_CONFIG, policy_line: 'p0.4' });
    const r = run.apply({ role: 'executive', kind: 'ai', id: 'h' }, { op: 'plan', event_id: 'p1', nodes: [{ id: 't-1', depends_on: [], resources: ['vgdd/kernel/**'] }] });
    assert.equal(r.ok, true);
  });

  it('team の limits.workers は「行政の member の総数（長を含む）」、runstate の config.workers は「同時に動かす作業の数」で、同じ名前で意味が違う', () => {
    const catalog = catalogFromCapabilities(caps);
    const m = (id, template, parent) => ({ id, template, ...(parent ? { parent } : {}), scope: { resources: [], tools: [] } });
    const plan = { task: 'x', proposed_by: 'h', members: [m('h', 'executive_head'), m('w1', 'worker', 'h'), m('w2', 'worker', 'h'), m('j', 'codex_judge')] };
    const ctx = (workers) => validateTeam(plan, { catalog, ticket: { resources: [] }, limits: { workers } });
    assert.ok(ctx(2).violations.some((v) => v.guard === 'TM-WORKER-LIMIT'), '同時 2 のつもりで 2 と書くと、長を含む 3 体が上限超過');
    assert.equal(ctx(3).ok, true);
  });
});

describe('食い違い：状態の名前・判定の結論の名前', () => {
  it('状態の名前は taskgraph と runstate で共通。判定（APPROVED・CHANGES_REQUIRED）と監査（passed・failed・not_run）の値も、runstate と trace で同じ綴り', () => {
    const W = runWalkthrough({ dir: scratch() });
    for (const n of Object.values(W.run.state().nodes)) assert.ok(STATUSES.includes(n.status));
    const t = W.tr.trace({ kind: 'request', id: W.req['T-101'][0] }, { direction: 'down' });
    const links = W.tr.state().links;
    const vlinks = links.filter((l) => l.rel === 'verifies' && l.to.id === W.req['T-101'][0]);
    assert.deepEqual(vlinks.map((l) => l.evidence.result).sort(), ['CHANGES_REQUIRED', 'CHANGES_REQUIRED', 'passed']);
    assert.ok(t.found);
  });

  it('UNAVAILABLE は runstate と trace では受けるが、improvement の審査は APPROVED・CHANGES_REQUIRED だけ。trace は結論の綴りの誤りを書く時に拒まず「不明」に倒す', () => {
    const d = scratch();
    const im = openImprovements(path.join(d, 'i.jsonl'), { currentCapabilities: caps });
    const p = im.propose({ role: 'executive_head', kind: 'ai', id: 'h', lineage: 'claude' }, { title: 't', tier: 'playbook', target: { name: 'x' }, content: 'c' });
    im.evaluate({ role: 'court', kind: 'script', id: 'ev', lineage: 'script' }, p.id, { digest: p.digest, evidence: { conformance: { before: { total: 1, passed: 1 }, after: { total: 1, passed: 1 } } } });
    const e = refused(() => im.review({ role: 'codex_judge', kind: 'ai', id: 'j', lineage: 'codex' }, p.id, { digest: p.digest, verdict: 'UNAVAILABLE', findings: [], review_input_digest: im.reviewInputFor(p.id).digest }));
    assert.deepEqual(e.guards, ['IM-INPUT-SHAPE']);

    const t = openTrace(path.join(d, 't.jsonl'));
    const CS = { role: 'court_script', kind: 'script', id: 'cs' };
    const req = hex('a', 40);
    const at = '2026-11-14T09:00:00+09:00';
    t.link(CS, { rel: 'implements', from: { kind: 'request', id: req }, to: { kind: 'spec', id: SD, digest: SD }, evidence: { no_codex: false, security_required: false } });
    t.link(CS, { rel: 'verifies', from: { kind: 'verdict', id: 'VRD-aaaaaaaaaaaa-judge' }, to: { kind: 'request', id: req }, evidence: { result: 'approved', at } }); // 小文字の綴りの誤り
    t.link(CS, { rel: 'verifies', from: { kind: 'verdict', id: 'VRD-aaaaaaaaaaaa-codex-judge' }, to: { kind: 'request', id: req }, evidence: { result: 'UNAVAILABLE', at } });
    t.link(CS, { rel: 'specifies', from: { kind: 'spec', id: SD, digest: SD }, to: { kind: 'ticket', id: 'T-101' } });
    t.link(CS, { rel: 'satisfies', from: { kind: 'ticket', id: 'T-101' }, to: { kind: 'requirement', id: 'R-1' } });
    const row = t.coverage().rows[0];
    assert.equal(row.unknown_verdict_requests, 1);
    assert.equal(row.approved_requests, 0);
    assert.ok(t.gaps().gaps.some((g) => g.code === 'REQUEST_VERDICT_UNKNOWN'));
  });
});

describe('食い違い：時刻の書式', () => {
  it('記録の時刻は chain の nowIso（+09:00・秒まで）で、runstate・improvement・trace の行は同じ形。experience は at を持つがイベントの型名が type', () => {
    const W = runWalkthrough({ dir: scratch() });
    for (const f of ['run', 'trace', 'improvement', 'experience']) {
      const rows = openChain(W.files[f]).read();
      assert.ok(rows.length > 0);
      for (const r of rows) assert.match(r.at, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\+09:00|\.\d+Z)$/, f);
    }
  });

  it('experience の expires_at は秒つき・時差つきだけ。+0900（時差のコロンなし）と時差なしは拒む。trace.parseTs は +0900 を受け、秒なしは拒む', () => {
    const d = scratch();
    const ex = openExperience(path.join(d, 'e.jsonl'));
    const add = (expires_at) => refused(() => ex.add({ role: 'court', kind: 'script', id: 'c' }, { text: 'abc', scope: { domain: 'software-dev', roles: ['worker'], tags: [] }, provenance: [{ kind: 'obs', ref: 'x', task: 'T-1' }], expires_at }));
    assert.deepEqual(add('2027-01-01T00:00:00').guards, ['EX-EXPIRY']);
    assert.deepEqual(add('2027-01-01T00:00:00+0900').guards, ['EX-EXPIRY']);
    assert.equal(add('2027-01-01T00:00:00+09:00'), null);
    assert.equal(typeof parseTs('2026-11-14T09:00:00+0900'), 'number');
    assert.equal(parseTs('2026-11-14T09:00+09:00'), null);
    assert.equal(parseTs('2026-11-14T09:00:00'), null);
  });

  it('trace の evidence.at は書く時に形を検査しない（読めない時刻でも書ける）。読む側が厳しい側に倒す', () => {
    const t = openTrace(path.join(scratch(), 't.jsonl'));
    const CS = { role: 'court_script', kind: 'script', id: 'cs' };
    const r = t.link(CS, { rel: 'verifies', from: { kind: 'verdict', id: 'VRD-aaaaaaaaaaaa-judge' }, to: { kind: 'request', id: hex('a', 40) }, evidence: { result: 'APPROVED', at: '2026-11-14 09:00' } });
    assert.equal(r.seq, 1);
    assert.equal(parseTs('2026-11-14 09:00'), null);
  });
});

describe('食い違い：規則の版・epoch・設定の持ち方', () => {
  it('記録の行の持ち方：runstate・improvement・trace は rules と op を持ち、experience は rules も epoch もなく type に操作名を入れる', () => {
    const W = runWalkthrough({ dir: scratch() });
    const first = (f) => openChain(W.files[f]).read()[0];
    assert.deepEqual([first('run').type, first('run').rules, first('run').op], ['vgdd.runstate.v1', 'rs.v1', 'config']);
    assert.equal(first('improvement').rules, 'im.v2');
    assert.equal(first('trace').rules, 'tr.v2');
    const e = first('experience');
    assert.equal(e.type, 'add');
    assert.equal(Object.hasOwn(e, 'rules'), false);
    assert.equal(Object.hasOwn(e, 'op'), false);
    assert.equal(typeof W.exp.state().rejected.length, 'number');
  });

  it('設定の持ち方：runstate は config を記録の中のオーナーの出来事に持つが、trace の ticketId・improvement の policyLine・experience の minSources は開く側の引数で、記録に残らない', () => {
    const W = runWalkthrough({ dir: scratch() });
    // trace：同じ記録を別の ticketId で開くと、過去の行が再生で外れる
    const other = openTrace(W.files.trace, { ticketId: { prefix: 'X-', digits: [3, 3] } });
    const v = other.verify();
    assert.equal(v.ok, false);
    assert.ok(v.rejected_count > 0);
    assert.equal(openTrace(W.files.trace).verify().ok, true);
    // improvement：法律の系統は開く側が決める。同じ記録でも、系統を変えれば採用の有効性が変わる
    assert.equal(openImprovements(W.files.improvement, { currentCapabilities: caps }).adoptionValid(W.playbook.id), true);
    assert.equal(openImprovements(W.files.improvement, { policyLine: 'p0.5' }).adoptionValid(W.playbook.id), false);
    // experience：帰納の元の下限を開く側が決める。上げると、同じ記録の induce が再生で却下に変わるが、verify は ok のまま（鎖しか確かめない）
    const strict = openExperience(W.files.experience, { minSources: 5 });
    assert.ok(strict.state().rejected.some((x) => x.violations.some((g) => g.guard === 'EX-INDUCE-SOURCES')));
    assert.equal(strict.verify().ok, true);
    assert.equal(W.exp.state().rejected.length, 0);
    // runstate：config は記録の中。開く側の引数では変えられない
    assert.throws(() => openRun(W.files.run, { workers: 64 }), (e) => e instanceof Refused && e.code === 'bad_option');
  });

  it('法律の系統（pN.N）の取り出しが 3 か所に別々にある（improvement.policyLineOf・authority-delta の VERSION_RE・runstate の POLICY_RE）が、書式は同じ', () => {
    assert.equal(openImprovements(path.join(scratch(), 'i.jsonl'), { currentCapabilities: caps }) !== null, true);
    assert.equal(caps.kernel_version, 'p0.4.14');
    assert.equal(parseEvent({ op: 'approve', event_id: 'e1', node: 't-1', spec_digest: SD, policy_line: 'p0.4', def_digest: SD }).ok, true);
    assert.equal(parseEvent({ op: 'approve', event_id: 'e1', node: 't-1', spec_digest: SD, policy_line: 'p0.4.14', def_digest: SD }).ok, false, 'runstate は pN.N だけ。kernel_version（pN.N.N）はそのまま渡せない');
  });
});

describe('食い違い：つながらない箇所（ある部品の出力を次の部品の入力にするために足りない情報）', () => {
  it('runstate の apply は seq と at しか返さない。承認の行の hash・差し戻された申請の指紋は、記録のファイルを直接読まないと得られない', () => {
    const W = runWalkthrough({ dir: scratch() });
    const ret = W.v1;
    assert.deepEqual(Object.keys(ret).sort(), ['at', 'duplicate', 'kind', 'node', 'ok', 'seq', 'to']);
    assert.equal(Object.hasOwn(ret, 'hash'), false);
    const s = W.run.state().nodes['t-101'];
    assert.equal(s.request, W.req['T-101'][1], 'state() に残るのは最後の申請だけ');
    assert.ok(![s.request].includes(W.req['T-101'][0]));
    assert.ok(W.rows.some((r) => r.op === 'submit' && r.request === W.req['T-101'][0]), '1 回目の申請は記録のファイルにだけある');
    assert.equal('defDigest' in rsMod, false, 'def_digest を計算する関数は export されていない');
  });

  it('runstate の判定の記録は、指摘の本文・番号・判定の id・統合の SHA を持たない。experience の出どころと trace の判定・統合の id は、外から与える', () => {
    const W = runWalkthrough({ dir: scratch() });
    const vd = W.rows.find((r) => r.op === 'verdict' && r.node === 't-101');
    assert.deepEqual(Object.keys(vd).sort(), ['actor', 'at', 'audits', 'event_id', 'hash', 'node', 'op', 'prev', 'request', 'rules', 'seq', 'type', 'verdicts']);
    for (const v of vd.verdicts) assert.deepEqual(Object.keys(v).sort(), ['judge', 'kind', 'lineage', 'major', 'verdict']);
    const merged = W.rows.filter((r) => r.node === 't-101').map((r) => r.op);
    assert.ok(!merged.includes('release'), 'hold でないので統合は verdict の合格で起き、統合の SHA を記録する出来事はない');
    // 通せない段：verdict の取り込みだけから experience の reflection（本文・指摘の番号）は作れない。作るには判定のファイル（記録の外）が要る
    assert.ok(Object.keys(vd).every((k) => !['text', 'findings', 'ref', 'finding', 'message'].includes(k)));
  });

  it('trace.linksFromEvidence は Kernel の記録（approvals・held など）を取り込む関数で、runstate の記録の行は取り込めない', () => {
    const W = runWalkthrough({ dir: scratch() });
    const out = linksFromEvidence({ approvals: W.rows.filter((r) => r.op === 'approve') });
    assert.deepEqual(out.links, []);
    assert.ok(out.skipped.length >= 3);
    assert.match(out.skipped[0].reason, /知らない schema/);
  });

  it('通せない：capabilities.json に security 専用の役割がないので、team の編成に codex の security 審査の役割（codex_security）を入れられない', () => {
    const catalog = catalogFromCapabilities(caps);
    assert.equal(Object.hasOwn(catalog, 'codex_security'), false);
    const v = validateTeam({ task: 'x', proposed_by: 'h', members: [{ id: 'h', template: 'executive_head', scope: { resources: [], tools: [] } }, { id: 'j', template: 'codex_judge', scope: { resources: [], tools: [] } }, { id: 's', template: 'codex_security', scope: { resources: [], tools: [] } }] }, { catalog, ticket: { resources: [] }, limits: { workers: 3 } });
    assert.ok(v.violations.some((x) => x.guard === 'TM-TEMPLATE-EXISTS'));
  });

  it('通せない：実際の憲法審査（Claude 系統）で、Claude の提案者の「法律を緩める」変更は採用できない。通るのは、憲法審査の lineage を codex と申告したときだけ', () => {
    const d = scratch();
    const loosen = structuredClone(caps);
    loosen.capabilities.find((c) => c.id === 'CAP-MAIN-INTEGRATE').allowed.push('worker');
    const owner = { role: 'owner', kind: 'human', id: 'azuki', lineage: 'human' };
    const ev = { role: 'court', kind: 'script', id: 'ev', lineage: 'script' };
    const head = { role: 'executive_head', kind: 'ai', id: 'h', lineage: 'claude' };
    const codex = { role: 'codex_judge', kind: 'ai', id: 'cj', lineage: 'codex' };
    const run = (constLineage) => {
      const im = openImprovements(path.join(d, `i-${constLineage}.jsonl`), { currentCapabilities: caps });
      const p = im.propose(head, { title: 'x', tier: 'law', target: { paths: [CAPS_PATH] }, content: { capabilities: loosen }, capabilities: { old: caps, new: loosen } });
      im.evaluate(ev, p.id, { digest: p.digest, evidence: { conformance: { before: { total: 10, passed: 10 }, after: { total: 11, passed: 11 }, new_cases_fail_on_before: 1 } } });
      const rv = (who) => im.review(who, p.id, { digest: p.digest, verdict: 'APPROVED', findings: [], review_input_digest: im.reviewInputFor(p.id).digest });
      rv(codex);
      const cr = refused(() => rv({ role: 'constitutional_review', kind: 'ai', id: 'cr', lineage: constLineage }));
      if (cr) return { cr, adopted: false };
      return { cr, adopted: im.adopt(owner, p.id, { digest: p.digest, policy_line: 'p0.4' }).status === 'adopted' };
    };
    assert.equal(caps.roles.constitutional_review.identity.includes('claude'), true);
    const honest = run('claude');
    assert.deepEqual(honest.cr.guards, ['IM-CROSS-LINEAGE']);
    assert.equal(honest.adopted, false);
    assert.equal(run('codex').adopted, true, '系統は申告の文字列なので、codex と書けば通る');
  });
});

describe('食い違い：API の使いにくさ・エラーの出方', () => {
  it('拒否の出方が 4 通り：例外（guard・guard_violation）、例外に violations がない、戻り値の { ok:false }、戻り値の { refused }', () => {
    const d = scratch();
    const run = openRun(path.join(d, 'r.jsonl'));
    const e1 = (() => { try { run.apply({ role: 'owner', kind: 'human', id: 'azuki' }, { op: 'stop', event_id: 's', reason: 'x' }); } catch (e) { return e; } return null; })();
    assert.equal(e1.code, 'guard', 'runstate は guard');
    assert.ok(Array.isArray(e1.violations));
    const im = openImprovements(path.join(d, 'i.jsonl'), { currentCapabilities: caps });
    const e2 = (() => { try { im.adopt({ role: 'executive_head', kind: 'ai', id: 'h', lineage: 'claude' }, 'IMP-0001', {}); } catch (e) { return e; } return null; })();
    assert.equal(e2.code, 'guard_violation', 'improvement・trace・experience は guard_violation');
    assert.ok(Array.isArray(e2.violations));
    const ex = openExperience(path.join(d, 'e.jsonl'));
    const e3 = (() => { try { ex.promote({ role: 'executive_head', kind: 'ai', id: 'h' }, 'exp-000001', {}); } catch (e) { return e; } return null; })();
    assert.equal(e3.code, 'guard_violation');
    assert.equal(Object.hasOwn(e3, 'violations'), false, 'experience の例外にはガード名の配列がない（message の文字列だけ）');
    assert.equal(refusalOf(e3).hasViolations, false);
    const t4 = validateTeam({ task: 'x', proposed_by: 'h', members: [] }, { catalog: {}, ticket: { resources: [] }, limits: { workers: 1 } });
    assert.equal(t4.ok, false, 'team・domain は例外でなく { ok:false, violations }');
    const t5 = ex.retrieve({ audience: { role: 'judge' } });
    assert.ok(t5.refused && Array.isArray(t5.items), 'retrieve は例外でなく { refused }');
  });

  it('retrieve の query.domain を省くと、エラーでなく 0 件になる（scope.domain との完全一致）', () => {
    const W = runWalkthrough({ dir: scratch() });
    const withDomain = W.exp.retrieve({ audience: { role: 'worker', task: 'T-103' }, query: { text: '境界値', domain: 'software-dev' } });
    const without = W.exp.retrieve({ audience: { role: 'worker', task: 'T-103' }, query: { text: '境界値' } });
    assert.ok(withDomain.items.length > 0);
    assert.deepEqual(without.items, []);
    assert.equal(without.refused, undefined);
  });

  it('戻り値の形が部品ごとに違う：runstate は { ok, seq, node, kind, to }、improvement は提案の状態、experience は項目（feedback は配列）、trace はつながり', () => {
    const W = runWalkthrough({ dir: scratch() });
    assert.equal(W.v1.ok, true);
    assert.equal(Array.isArray(W.fb), true);
    assert.equal(typeof W.induced.id, 'string');
    assert.equal(typeof W.playbook.status, 'string');
    assert.equal(W.im.get(W.playbook.id).route.lane, 'standard');
  });

  it('同じ内容の出来事の再送は、runstate では例外でなく { ok:true, duplicate:true }（冪等）。成功と区別して見る必要がある', () => {
    const d = scratch();
    const run = openRun(path.join(d, 'r.jsonl'));
    const ev = { op: 'config', event_id: 'c1', ...DEFAULT_CONFIG, policy_line: 'p0.4' };
    const owner = { role: 'owner', kind: 'human', id: 'azuki' };
    assert.equal(run.apply(owner, ev).duplicate, false);
    const again = run.apply(owner, ev);
    assert.deepEqual(again, { ok: true, duplicate: true });
    assert.equal(run.state().count, 1);
  });
});
