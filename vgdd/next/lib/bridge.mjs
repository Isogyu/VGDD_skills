// 部品の間をつなぐ純関数（起草段階の試作。法律ではない）
//
// 領域パック → 実行の記録（runstate）の設定、実行の記録 → 追跡のつながり（trace）、判定 → 経験の出どころと feedback（experience）。
// どれも純関数で、ファイルを開かない（呼び出し側が記録を読んで渡す）。語彙は lib/vocab.mjs。
// 決められないものは作らず、理由つきで返す（fail-closed。推し量って埋めない）。
//
// 保証できないこと：
//   - 入力の記録が本物であること（runstate の記録の行は replay で規則に合うことだけ確かめる。鎖の検証は呼び出し側が chain.read() で行う）
//   - 判定の id・指摘への参照・統合の参照が実在すること（runstate の verdict の refs・merge は外から来る値で、形と整合だけ確かめてある）
//   - feedbackFromRun の helpful・harmful が、経験が本当に役に立ったかを表すこと（下の規則は「最初の判定の結果」という代理の指標）
//   - feedbackFromRun に渡す取り出しの行が、本物の経験の記録の行であること。1 行ずつ、経験の部品の再生と同じ規則（行為者の正規形・
//     EX-RETRIEVE-ACTOR・EX-RETRIEVE-JUDGE）は確かめるが、記録全体の鎖・版・設定の写しは確かめない（呼び出し側が openChain(経験).read() で
//     鎖を確かめた行を渡す前提。runRecords と同じ。独立した審査 4 回目の疑い）

import { validateDomainPack } from '../domain.mjs';
import { replay as rsReplay, RECORD_TYPE as RS_TYPE } from '../runstate.mjs';
import { digest, canonical } from './chain.mjs';
import { check as exCheck, RECORD_TYPE as EX_TYPE } from '../experience.mjs';
import {
  REVIEW_MODES, AI_LINEAGES, reviewModeOf, verdictId, auditId, asDigest, parseWorkItemSpec, isFindingRef, parseFindingRef, parseTs, sameActor, normActor,
} from './vocab.mjs';

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

// ---------------------------------------------------------------------------
// 領域パック → runstate の設定
// ---------------------------------------------------------------------------

/** 領域パックを検査し、通らなければ理由 */
function packProblem(pack) {
  const r = validateDomainPack(pack);
  return r.ok ? null : `領域パックが検査を通らない（${r.violations.slice(0, 3).map((v) => v.guard).join('・')}）`;
}

/**
 * 領域パックの judiciary（min_judges・distinct_lineage）から、runstate の config.judiciary と security_lineage の案を作る。
 * 規則：審査の種類に写せる judge の系統（vocab の REVIEW_MODES で kind: judge のもの）を、vocab の AI_LINEAGES の順に min_judges 個使う。
 *   distinct_lineage は常に true（domain.mjs が強制）なので、系統は互いに違う。min_judges が 1 なら codex（既定の行政の系統 claude と違う側）。
 *   security_lineage は、審査の種類に写せる security の系統（今は codex だけ）。
 * 決められない（知っている系統が足りない・パックが通らない）ときは null と理由。
 * @returns {{ judiciary: {kind:'judge', lineage:string}[] | null, security_lineage: string | null, reason: string | null }}
 */
export function judiciaryFromDomainPack(pack) {
  const bad = packProblem(pack);
  if (bad) return { judiciary: null, security_lineage: null, reason: bad };
  const n = pack.judiciary.min_judges;
  const judgeLineages = AI_LINEAGES.filter((l) => reviewModeOf('judge', l));
  const sec = REVIEW_MODES.find((m) => m.kind === 'security');
  const security_lineage = sec ? sec.lineage : null;
  if (n > judgeLineages.length) return { judiciary: null, security_lineage, reason: `min_judges ${n} に対し、系統の違う judge を ${judgeLineages.length} つしか作れない（知っている系統 ${judgeLineages.join('・')}。系統を足すのは vocab の改正）` };
  const chosen = n === 1 ? [judgeLineages[judgeLineages.length - 1]] : judgeLineages.slice(0, n);
  return { judiciary: chosen.map((lineage) => ({ kind: 'judge', lineage })).sort((a, b) => cmp(a.lineage, b.lineage)), security_lineage, reason: null };
}

/** 領域パックの protected → runstate の config.protected（並べ替え・重複なし）。パックが通らなければ null と理由 */
export function protectedFromDomainPack(pack) {
  const bad = packProblem(pack);
  if (bad) return { protected: null, reason: bad };
  return { protected: [...new Set(pack.protected)].sort(), reason: null };
}

/** 領域パックの work_item.id → runstate の config.work_item・trace の ticketId・experience の workItem。通らなければ null と理由 */
export function workItemFromDomainPack(pack) {
  const bad = packProblem(pack);
  if (bad) return { work_item: null, reason: bad };
  return { work_item: parseWorkItemSpec(pack.work_item.id), reason: null };
}

// ---------------------------------------------------------------------------
// runstate の記録 → trace のつながり
// ---------------------------------------------------------------------------

/** runstate の記録の行を replay で確かめる。規則に合わなければ理由 */
function checkRun(records) {
  if (!Array.isArray(records)) return { st: null, reason: 'runstate の記録の行の配列でない' };
  try { return { st: rsReplay(records), reason: null }; } catch (e) { return { st: null, reason: `runstate の記録が規則に合わない（${String(e && e.message).slice(0, 160)}）` }; }
}
const fieldsOf = (r) => { const o = {}; for (const k of Object.keys(r)) if (!['type', 'rules', 'actor', 'seq', 'at', 'prev', 'hash', 'op', 'event_id'].includes(k)) o[k] = r[k]; return o; };

/**
 * runstate の記録の行から、trace のつながりの入力の配列を作る（trace.linksFromEvidence と同じ戻り値の形）。
 *   plan：票 -satisfies-> 要件（節の requirements）、票 -depends_on-> 票
 *   approve：仕様 -specifies-> 票、承認（sha256: ＋ 行の hash）-approves-> 仕様（evidence: at・policy_line）
 *   submit：申請 -implements-> 仕様（その時点の承認の仕様。evidence: no_codex・security_required は config と節の security_review から）
 *   verdict：判定 -verifies-> 申請（審査ごと。id は refs.verdicts、なければ vocab の verdictId で（種類, 系統）から作る）、
 *            監査 -verifies-> 申請（id は refs.audit、なければ auditId）、統合 -integrates-> 申請（merge があるときだけ）
 *   release・rule（merge）：統合 -integrates-> 申請（merge があるときだけ）。rule（merge）は 裁定 -approves-> 申請 も
 * 時刻は記録の行の at（書いた側の時刻）。記録は replay で確かめ、規則に合わなければ何も作らない。
 * @param {object[]} runRecords chain.read() の行
 * @returns {{ links: object[], skipped: {source:string, index:number, reason:string}[] }}
 */
export function linksFromRun(runRecords) {
  const links = []; const skipped = [];
  const { st, reason } = checkRun(runRecords); // 状態は使わず、規則に合う記録であることだけを確かめる
  if (!st) return { links, skipped: [{ source: 'runstate', index: -1, reason }] };
  const seen = new Set();
  const emit = (from, to, rel, evidence) => {
    const k = `${rel}|${from.kind}:${from.id}|${to.kind}:${to.id}`;
    if (seen.has(k)) return;
    seen.add(k); links.push({ from, to, rel, ...(evidence ? { evidence } : {}) });
  };
  let cfg = null;
  const spec = new Map(); // 節 → 今の承認の仕様の指紋
  const security = new Map(); // 節 → security_review
  const ticket = (id) => ({ kind: 'ticket', id });
  const mergeLink = (i, f, at) => {
    if (f.merge === undefined) { skipped.push({ source: 'runstate', index: i, reason: `${f.node} の統合の参照（merge）が記録にない。統合のつながりは作らない` }); return; }
    emit({ kind: 'merge', id: f.merge }, { kind: 'request', id: f.request }, 'integrates', { source: 'runstate', at });
  };
  runRecords.forEach((r, i) => {
    if (!isObj(r) || r.type !== RS_TYPE) return;
    const f = fieldsOf(r);
    switch (r.op) {
      case 'config': cfg = f; break;
      case 'plan':
        for (const d of f.nodes) {
          security.set(d.id, d.security_review === true);
          for (const q of d.requirements || []) emit(ticket(d.id), { kind: 'requirement', id: q }, 'satisfies', { source: 'runstate_plan' });
          for (const dep of d.depends_on) emit(ticket(d.id), ticket(dep), 'depends_on', { source: 'runstate_plan' });
        }
        break;
      case 'approve': {
        const s = { kind: 'spec', id: f.spec_digest, digest: f.spec_digest };
        const ap = asDigest(r.hash);
        spec.set(f.node, f.spec_digest);
        emit(s, ticket(f.node), 'specifies', { source: 'runstate', at: r.at });
        if (ap) emit({ kind: 'approval', id: ap, digest: ap }, s, 'approves', { source: 'runstate', at: r.at, policy_line: f.policy_line });
        break;
      }
      case 'submit': {
        const sd = spec.get(f.node);
        if (!sd) { skipped.push({ source: 'runstate', index: i, reason: `${f.node} の承認の仕様が決まらない` }); break; }
        const noCodex = !(cfg && cfg.judiciary.some((j) => j.lineage === 'codex'));
        emit({ kind: 'request', id: f.request }, { kind: 'spec', id: sd, digest: sd }, 'implements', { source: 'runstate', no_codex: noCodex, security_required: security.get(f.node) === true });
        break;
      }
      case 'verdict': {
        const refs = isObj(f.refs) ? f.refs : {};
        for (const v of f.verdicts) {
          const ref = (refs.verdicts || []).find((x) => x.kind === v.kind && x.lineage === v.lineage);
          const mode = reviewModeOf(v.kind, v.lineage);
          const id = ref ? ref.id : verdictId(f.request, mode);
          if (!id) { skipped.push({ source: 'runstate', index: i, reason: `判定（${v.kind}:${v.lineage}）を審査の種類に写せない` }); continue; }
          emit({ kind: 'verdict', id, ...(ref && ref.digest ? { digest: ref.digest } : {}) }, { kind: 'request', id: f.request }, 'verifies', { source: 'runstate', at: r.at, result: v.verdict, ...(ref ? {} : { basis: 'synthesized_id' }) });
        }
        const aid = refs.audit ? refs.audit.id : auditId(f.request);
        emit({ kind: 'audit', id: aid, ...(refs.audit && refs.audit.digest ? { digest: refs.audit.digest } : {}) }, { kind: 'request', id: f.request }, 'verifies', { source: 'runstate', at: r.at, result: f.audits, ...(refs.audit ? {} : { basis: 'synthesized_id' }) });
        if (f.merge !== undefined) mergeLink(i, f, r.at);
        break;
      }
      case 'release': mergeLink(i, f, r.at); break;
      case 'rule':
        if (f.decision === 'merge') {
          const d = digest({ hash: r.hash });
          emit({ kind: 'ruling', id: `RUL-${d.slice(7, 23)}`, digest: d }, { kind: 'request', id: f.request }, 'approves', { source: 'runstate', at: r.at, result: 'merge' });
          mergeLink(i, f, r.at);
        }
        break;
      default: break;
    }
  });
  return { links, skipped };
}

// ---------------------------------------------------------------------------
// 判定 → 経験の出どころ・feedback
// ---------------------------------------------------------------------------

/**
 * runstate の verdict の行から、experience の出どころ（provenance）の配列を作る（refs.findings の指摘への参照から。vocab の形に合うものだけ）。
 * opt.records（その行を含む記録の全体）を渡せば、記録を replay で確かめ、行がその記録の中にある（同じ hash）ときだけ作る。
 * 渡さないときは、呼び出し側が再生で確かめた記録の行を渡す前提（この関数は単独の行の真偽を確かめられない。独立した審査 E-10）。
 * refs がなければ空と理由（判定の本文・番号は runstate の記録にない。作らずに理由を返す）。
 * @returns {{ provenance: {kind:'verdict_finding', ref:string, task:string}[], reason: string|null }}
 */
export function provenanceFromVerdict(runRecord, opt = {}) {
  if (!isObj(runRecord) || runRecord.type !== RS_TYPE || runRecord.op !== 'verdict') return { provenance: [], reason: 'runstate の verdict の行でない' };
  if (isObj(opt) && opt.records !== undefined) {
    const { st, reason } = checkRun(opt.records);
    if (!st) return { provenance: [], reason };
    if (!opt.records.some((r) => isObj(r) && r.hash === runRecord.hash && r.seq === runRecord.seq)) return { provenance: [], reason: 'verdict の行が、渡した記録の中にない' };
  }
  const f = runRecord.refs && Array.isArray(runRecord.refs.findings) ? runRecord.refs.findings : [];
  if (!f.length) return { provenance: [], reason: 'verdict の refs に指摘への参照（findings）がない' };
  const out = f.filter(isFindingRef).map((ref) => ({ kind: 'verdict_finding', ref, task: runRecord.node }));
  return { provenance: out, reason: out.length ? null : '指摘への参照が vocab の形でない' };
}

/** 取り出しの行が、経験の部品の再生と同じ規則に合うか（合わなければ理由）。経験の記録の reduce の retrieved の扱いと同じ検査 */
function retrievedProblem(e) {
  if (e.type !== EX_TYPE) return `経験の記録の行でない（type ${String(e.type).slice(0, 40)}）`;
  if (typeof e.role !== 'string') return '渡す先の役割（role）がない';
  if (!e.item_ids.every((x) => typeof x === 'string')) return '項目の id が文字列でない';
  let canon = false; try { canon = isObj(e.actor) && canonical(e.actor) === canonical(normActor(e.actor)); } catch { canon = false; }
  if (!canon) return '行為者の綴りが vocab の正規形でない';
  const r = exCheck({ op: 'retrieve', actor: e.actor, audience: { role: e.role } }, ['EX-RETRIEVE-ACTOR', 'EX-RETRIEVE-JUDGE']);
  return r.ok ? null : r.violations.map((v) => v.guard).join('・');
}

/**
 * 経験の feedback の入力の案を作る（決定論的）。評価は代理の指標なので、数える取り出しを狭く決める（独立した審査 E-1・E-9）。
 * 規則：
 *   1. 票ごとに「評価の根拠にする申請」を決める：runstate の節の申請の履歴（requests。使えない審査 unavailable は入らない）の先頭。
 *      履歴が上限で落ちた節（requests_dropped > 0）は、先頭が最初の判定と言えないので出さない。
 *   2. 結果：その申請の結果が pass・pass_minor_disagreement → helpful、return（差し戻し）→ harmful。それ以外は決められないので出さない。
 *   3. 数える取り出し：experience の retrieved の行のうち、
 *      (a) task がその票で、(b) 時刻（行の at）が「その申請の submit の直前の start の時刻以降、その submit の時刻まで」にあり
 *      （submit と同じ時刻（記録の時刻はミリ秒まで）の取り出しは数える。それより後は数えない）、
 *      (c) 取り出した行為者（retrieved の actor）が、その start を起こした行為者か、その start の assignee と同じもの。
 *      (d) 行そのものが、経験の部品の再生と同じ規則に合う（経験の記録の行で、行為者が正規形、取り出せる役割、渡す先が司法でない）。
 *      時刻が読めない・範囲の外・行為者が違う取り出しは数えず、skipped に理由を返す（申告の task だけでは評価を付けない）。
 *   4. 証拠は、その申請の判定の id（verdict の refs.verdicts の最初、なければ vocab の verdictId で judge の種類から作る）。
 *   限界：取り出した経験を作業員が実際に読んだか・使ったかは分からない。時刻は二つの鎖の書いた側の時刻で、同じ時計とは限らない。
 *   前提：retrievedEvents は、鎖を確かめた経験の記録の行（openChain(経験の記録).read()）。この関数は行を 1 つずつ確かめるだけで、
 *     記録全体の鎖・規則の版・設定の写しは確かめない（行を作り直して渡せる呼び出し側は、評価を作れる。runRecords の鎖も同じ前提）。
 *     作業員は、合格しそうな申請の直前に、上げたい経験を取り出せば helpful を付けられる（代理の指標の限界）。この評価を経験の昇格
 *     （improvement の tier: 'experience'）の根拠にするときは、オーナーが見る前提。
 * @param {object[]} runRecords runstate の記録の行
 * @param {object[]} retrievedEvents experience の記録の行（op: 'retrieved' 以外は無視）
 * @returns {{ feedback: {item_ids:string[], outcome:'helpful'|'harmful', evidence:{kind:'verdict', ref:string, task:string}}[], skipped: {task:string|null, reason:string}[] }}
 */
export function feedbackFromRun(runRecords, retrievedEvents) {
  const { st, reason } = checkRun(runRecords);
  if (!st) return { feedback: [], skipped: [{ task: null, reason }] };
  return feedbackFromState(st, runRecords, retrievedEvents);
}

/**
 * feedbackFromRun の本体（試験用に公開）。st は runstate.replay(runRecords) の結果（呼び出し側が同じ記録から作ったもの）。
 * 規則は feedbackFromRun の説明のとおり
 */
export function feedbackFromState(st, runRecords, retrievedEvents) {
  const feedback = []; const skipped = [];
  if (!st || !(st.nodes instanceof Map) || !Array.isArray(runRecords)) return { feedback, skipped: [{ task: null, reason: '実行の状態・記録が読めない' }] };
  if (!Array.isArray(retrievedEvents)) return { feedback, skipped: [{ task: null, reason: 'retrievedEvents が配列でない' }] };
  const byTask = new Map();
  for (const e of retrievedEvents) {
    if (!isObj(e) || e.op !== 'retrieved' || typeof e.task !== 'string' || !Array.isArray(e.item_ids)) continue;
    const bad = retrievedProblem(e);
    if (bad) { skipped.push({ task: e.task, reason: `取り出しの行（seq ${e.seq}）が経験の記録の規則に合わない（${bad}）` }); continue; }
    (byTask.get(e.task) || byTask.set(e.task, []).get(e.task)).push(e);
  }
  const rows = runRecords.filter((r) => isObj(r) && r.type === RS_TYPE);
  for (const task of [...byTask.keys()].sort()) {
    const node = st.nodes.get(task);
    if (!node) { skipped.push({ task, reason: '実行の記録にこの票の節がない' }); continue; }
    if (node.requests_dropped > 0) { skipped.push({ task, reason: `申請の履歴が上限で ${node.requests_dropped} 件落ちていて、最初の判定が決まらない` }); continue; }
    const first = node.requests[0];
    const outcome = first && (first.kind === 'pass' || first.kind === 'pass_minor_disagreement') ? 'helpful' : first && first.kind === 'return' ? 'harmful' : null;
    if (!outcome) { skipped.push({ task, reason: first ? `最初の判定の結果（${first.kind}）からは決められない` : 'まだ判定がない' }); continue; }
    const si = rows.findIndex((r) => r.op === 'submit' && r.node === task && r.request === first.request);
    let startRow = null;
    for (let k = si - 1; k >= 0; k -= 1) if (rows[k].op === 'start' && rows[k].node === task) { startRow = rows[k]; break; }
    const submitAt = si >= 0 ? parseTs(rows[si].at) : null; const startAt = startRow ? parseTs(startRow.at) : null;
    if (submitAt === null || startAt === null) { skipped.push({ task, reason: '評価の根拠にする申請の start・submit の時刻が決まらない' }); continue; }
    const items = new Set();
    for (const e of byTask.get(task)) {
      const at = parseTs(e.at);
      if (at === null) { skipped.push({ task, reason: `取り出しの行（seq ${e.seq}）の時刻が読めない` }); continue; }
      if (at < startAt || at > submitAt) { skipped.push({ task, reason: `取り出しの行（seq ${e.seq}）が、評価の根拠にする申請の着手から申請までの間にない` }); continue; }
      if (!(sameActor(e.actor, startRow.actor) || (startRow.assignee && sameActor(e.actor, startRow.assignee)))) { skipped.push({ task, reason: `取り出しの行（seq ${e.seq}）の行為者が、その着手の行為者・assignee と違う` }); continue; }
      for (const id of e.item_ids) if (typeof id === 'string') items.add(id);
    }
    if (!items.size) { skipped.push({ task, reason: '数えられる取り出しがない' }); continue; }
    const row = rows.find((r) => r.op === 'verdict' && r.node === task && r.request === first.request);
    const refId = row && row.refs && Array.isArray(row.refs.verdicts) && row.refs.verdicts.length ? row.refs.verdicts[0].id : verdictId(first.request, 'judge');
    if (!refId) { skipped.push({ task, reason: '証拠の判定の id を作れない' }); continue; }
    feedback.push({ item_ids: [...items].sort(), outcome, evidence: { kind: 'verdict', ref: refId, task } });
  }
  return { feedback, skipped };
}

/** 指摘への参照から、その判定の id を取り出す（experience の出どころから trace の判定へつなぐとき） */
export const verdictOfFinding = (ref) => { const p = parseFindingRef(ref); return p ? p.verdict : null; };
