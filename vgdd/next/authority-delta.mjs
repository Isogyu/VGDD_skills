// 権限の差分（Authority Delta）：権限の表（vgdd.capabilities.v1）の旧版と新版を比べ、変更1つずつを分類する（起草段階の試作。法律ではない）
//
// 分類：'tightening'（締める）| 'neutral'（権限に影響しない）| 'loosening'（緩める）| 'indeterminate'（分類できない）
//   全体の分類は最も重いもの（indeterminate ≥ loosening > tightening > neutral）。indeterminate は fail-closed で
//   loosening と同じ経路（full_legislative）に回すが、区別して報告する。
//
// 原則：
//   - 純関数。LLM・ネットワーク・時刻を使わない。例外を投げず、読めない入力は class: 'indeterminate'（category 'malformed'）
//   - 配列は順序を無視して集合として比べる。capability と invariant は id で、probe は「expect を除いた中身」で対応づける
//   - 規則にないフィールドの変更は indeterminate（知らない項目を「影響なし」と見なさない）
//
// 限界（保証できないこと）：
//   - 見るのは「表に書かれた宣言」だけ。フック・スクリプトの実装の差分は分類しない（表を変えずに実装だけ緩めた変更は neutral に見える）。
//     そのため improvement.mjs は、表以外のファイルを含む法律の提案を常に full_legislative に回す
//   - 文字列（title・note・known_gaps の文）の意味は読まない。note の変更は neutral、title の変更は indeterminate とする
//   - 新しい probe が本当に意味のある操作か（空回りしないか）は、適合性テストを前の版に当てて確かめる仕事で、ここでは見ない

import { canonical } from './lib/chain.mjs';

export const CLASSES = ['neutral', 'tightening', 'loosening', 'indeterminate'];
// 対応表は null プロトタイプ（'constructor' などの名前を既知の値と取り違えない。F11）
const dict = (o) => Object.freeze(Object.assign(Object.create(null), o));
const RANK = dict({ neutral: 0, tightening: 1, loosening: 2, indeterminate: 3 });

const TOP_FIELDS = new Set(['schema', 'kernel_version', 'note', 'title', 'layers', 'roles', 'capabilities', 'invariants']);
const ROLE_FIELDS = new Set(['kind', 'identity', 'note', 'hook_input']);
const CAP_FIELDS = new Set(['id', 'title', 'allowed', 'drafting', 'enforced_by', 'probes', 'expect', 'known_gaps', 'scenario_tests', 'verified_by', 'note']);
const INV_FIELDS = new Set(['id', 'title', 'status', 'tests', 'gaps', 'reason']);
const KINDS = new Set(['human', 'ai', 'script', 'ai+script']);
const STATUS_RANK = dict({ not_applicable: 0, partial: 1, enforced: 2 });
const SCHEMA = 'vgdd.capabilities.v1';

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const isStrArr = (v) => Array.isArray(v) && v.every((x) => typeof x === 'string');
const isAiKind = (k) => typeof k === 'string' && k.split('+').includes('ai');
const same = (a, b) => { if (a === undefined || b === undefined) return a === b; try { return canonical(a) === canonical(b); } catch { return false; } };
const probeKey = (p) => { const op = Object.create(null); for (const k of Object.keys(p)) if (k !== 'expect') op[k] = p[k]; return canonical(op); };
const has = (o, k) => o != null && Object.hasOwn(o, k);
const own = (o, k) => (has(o, k) ? o[k] : undefined);

/** JSON の値を null プロトタイプのオブジェクトに写す（'__proto__'・'constructor' などのキーも普通のデータとして扱う。F11） */
function nullProto(v) {
  if (Array.isArray(v)) return v.map(nullProto);
  if (isObj(v)) { const o = Object.create(null); for (const k of Object.keys(v)) o[k] = nullProto(v[k]); return o; }
  return v;
}

// 法律の系統（SPEC §4-6・INV-06）：kernel_version は pN.N.N（末尾に英小文字1つを許す）。系統は先頭の pN.N
const VERSION_RE = /^p(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)([a-z]?)$/; // 先頭の 0（p0.4.015 など）は形の崩れ
/** kernel_version の変更の分類。同じ系統の中で末尾が増えるだけなら neutral、それ以外（系統の変更・下げ・形の崩れ・追加・削除）は indeterminate（F1） */
function classifyVersion(a, b) {
  const x = typeof a === 'string' ? VERSION_RE.exec(a) : null; const y = typeof b === 'string' ? VERSION_RE.exec(b) : null;
  if (!x || !y) return ['indeterminate', `kernel_version の形が pN.N.N でない・欠けている（${a} → ${b}）。系統が読めないと承認の有効性が決まらない`];
  if (x[1] !== y[1] || x[2] !== y[2]) return ['indeterminate', `法律の系統の変更（p${x[1]}.${x[2]} → p${y[1]}.${y[2]}）は承認の有効性を変える（戻せば無効になった承認が復活しうる）`];
  const up = Number(y[3]) > Number(x[3]) || (Number(y[3]) === Number(x[3]) && y[4] > x[4]);
  return up ? ['neutral', `同じ系統の中の版の上がり（${a} → ${b}）`] : ['indeterminate', `同じ系統の中の版の下げ（${a} → ${b}）`];
}

/** 形の検査。問題があれば理由（日本語）、なければ null */
function malformed(caps, label) {
  if (!isObj(caps)) return `${label}: オブジェクトでない`;
  if (typeof caps.schema !== 'string') return `${label}: schema がない`;
  if (!isObj(caps.roles)) return `${label}: roles がオブジェクトでない`;
  for (const [name, r] of Object.entries(caps.roles)) {
    if (!isObj(r)) return `${label}: roles.${name} がオブジェクトでない`;
    if (!KINDS.has(r.kind)) return `${label}: roles.${name}.kind が human・ai・script・ai+script のどれでもない`;
    if (r.hook_input !== undefined && !isObj(r.hook_input)) return `${label}: roles.${name}.hook_input がオブジェクトでない`;
  }
  if (caps.layers !== undefined && (!isObj(caps.layers) || !Object.values(caps.layers).every((v) => typeof v === 'string'))) return `${label}: layers の形が違う`;
  if (!Array.isArray(caps.capabilities)) return `${label}: capabilities が配列でない`;
  const ids = new Set();
  for (const [i, c] of caps.capabilities.entries()) {
    if (!isObj(c) || typeof c.id !== 'string' || !c.id) return `${label}: capabilities[${i}] に id がない`;
    if (ids.has(c.id)) return `${label}: capability の id が重複（${c.id}）`;
    ids.add(c.id);
    for (const k of ['allowed', 'drafting', 'enforced_by', 'known_gaps', 'scenario_tests']) {
      if (c[k] !== undefined && !isStrArr(c[k])) return `${label}: ${c.id}.${k} が文字列の配列でない`;
      if (['allowed', 'drafting', 'enforced_by'].includes(k) && c[k] && new Set(c[k]).size !== c[k].length) return `${label}: ${c.id}.${k} に重複`;
    }
    if (c.allowed === undefined) return `${label}: ${c.id}.allowed がない`;
    if (c.verified_by !== undefined && typeof c.verified_by !== 'string' && !isStrArr(c.verified_by)) return `${label}: ${c.id}.verified_by の形が違う`;
    if (c.expect !== undefined && !isExpect(c.expect)) return `${label}: ${c.id}.expect の値が allow・deny でない`;
    if (c.probes !== undefined) {
      if (!Array.isArray(c.probes) || !c.probes.every(isObj)) return `${label}: ${c.id}.probes がオブジェクトの配列でない`;
      const keys = new Set();
      for (const p of c.probes) {
        if (p.expect !== undefined && !isExpect(p.expect)) return `${label}: ${c.id} の probe の expect の値が allow・deny でない`;
        const k = probeKey(p); if (keys.has(k)) return `${label}: ${c.id} に同じ probe が重複`; keys.add(k);
      }
    }
  }
  if (caps.invariants !== undefined) {
    if (!Array.isArray(caps.invariants)) return `${label}: invariants が配列でない`;
    const iids = new Set();
    for (const [i, v] of caps.invariants.entries()) {
      if (!isObj(v) || typeof v.id !== 'string' || !v.id) return `${label}: invariants[${i}] に id がない`;
      if (iids.has(v.id)) return `${label}: invariant の id が重複（${v.id}）`;
      iids.add(v.id);
      if (!has(STATUS_RANK, v.status)) return `${label}: ${v.id}.status が enforced・partial・not_applicable のどれでもない`;
      for (const k of ['tests', 'gaps']) if (v[k] !== undefined && !isStrArr(v[k])) return `${label}: ${v.id}.${k} が文字列の配列でない`;
      if (v.reason !== undefined && typeof v.reason !== 'string') return `${label}: ${v.id}.reason が文字列でない`;
    }
  }
  return null;
}
function isExpect(e) { return isObj(e) && Object.values(e).every((x) => x === 'allow' || x === 'deny'); }

const setOf = (v) => (v === undefined ? [] : typeof v === 'string' ? [v] : [...new Set(v)]);
function setDiff(a, b) { const A = new Set(setOf(a)); const B = new Set(setOf(b)); return { added: [...B].filter((x) => !A.has(x)).sort(), removed: [...A].filter((x) => !B.has(x)).sort() }; }

function summarize(changes) {
  const summary = { tightening: 0, neutral: 0, loosening: 0, indeterminate: 0 };
  let cls = 'neutral';
  for (const c of changes) { summary[c.class] += 1; if (RANK[c.class] > RANK[cls]) cls = c.class; }
  return { class: cls, changes, summary };
}

/**
 * 旧版と新版の権限の表を比べる。
 * @returns {{ class: string, changes: { path: string, kind: string, class: string, category: string, reason: string }[], summary: object }}
 *   category：'grant'（権限の付与）| 'enforcement'（強制の層）| 'verification'（確かめ方）| 'invariant'（不変条件の状態）
 *            | 'disclosure'（穴の公開）| 'identity'（役割の識別）| 'structure'（構造・schema・layers・未知の項目）| 'doc'（説明だけ）| 'malformed'
 */
export function authorityDelta(oldCaps, newCaps) {
  // 深すぎる入力・正規形にできない値は、写す前に弾く（再帰の失敗も読めない入力として扱う）
  for (const [v, label] of [[oldCaps, '旧版'], [newCaps, '新版']]) {
    let ok = isObj(v); try { if (ok) canonical(v); } catch { ok = false; }
    if (!ok) return summarize([{ path: '', kind: 'malformed', class: 'indeterminate', category: 'malformed', reason: `形として読めない：${label}: オブジェクトでない・正規形にできない値を含む` }]);
  }
  oldCaps = nullProto(oldCaps); newCaps = nullProto(newCaps);
  const bad = malformed(oldCaps, '旧版') || malformed(newCaps, '新版');
  if (bad) return summarize([{ path: '', kind: 'malformed', class: 'indeterminate', category: 'malformed', reason: `形として読めない：${bad}` }]);
  if (oldCaps.schema !== SCHEMA) return summarize([{ path: 'schema', kind: 'malformed', class: 'indeterminate', category: 'malformed', reason: `旧版の schema が ${SCHEMA} でない（${oldCaps.schema}）` }]);

  const out = [];
  const add = (path, kind, cls, category, reason) => out.push({ path, kind, class: cls, category, reason });
  const roleKind = (name) => (own(newCaps.roles, name) || own(oldCaps.roles, name) || {}).kind;
  const known = (name) => has(newCaps.roles, name) || has(oldCaps.roles, name);
  // 適合性テスト C1 が probe を実際に回す役割：capability の expect にあり、新版の roles に hook_input を持つ役割（run.mjs groupC1 と同じ）
  const executed = (c) => Object.keys(c.expect || {}).filter((r) => isObj(own(own(newCaps.roles, r), 'hook_input')));

  // 最上位
  for (const k of new Set([...Object.keys(oldCaps), ...Object.keys(newCaps)])) {
    if (['roles', 'capabilities', 'invariants', 'layers'].includes(k)) continue;
    if (same(oldCaps[k], newCaps[k])) continue;
    if (k === 'schema') add('schema', 'changed', 'indeterminate', 'structure', `schema の変更（${oldCaps.schema} → ${newCaps.schema}）は表の読み方そのものを変える`);
    else if (k === 'kernel_version') { const [cls, why] = classifyVersion(oldCaps[k], newCaps[k]); add(k, kind3(oldCaps[k], newCaps[k]), cls, cls === 'neutral' ? 'doc' : 'structure', why); }
    else if (TOP_FIELDS.has(k)) add(k, kind3(oldCaps[k], newCaps[k]), 'neutral', 'doc', `${k} だけの変更（権限に影響しない）`);
    else add(k, kind3(oldCaps[k], newCaps[k]), 'indeterminate', 'structure', `規則にない最上位の項目 ${k} の変更`);
  }

  // layers（強制の層の定義。意味の変更は機械で分からない）
  const lo = oldCaps.layers || {}; const ln = newCaps.layers || {};
  for (const k of new Set([...Object.keys(lo), ...Object.keys(ln)])) {
    if (lo[k] !== ln[k]) add(`layers.${k}`, kind3(lo[k], ln[k]), 'indeterminate', 'structure', '強制の層の定義の変更（層の意味が変わる）');
  }

  // roles
  for (const name of new Set([...Object.keys(oldCaps.roles), ...Object.keys(newCaps.roles)])) {
    const o = own(oldCaps.roles, name); const n = own(newCaps.roles, name); const p = `roles.${name}`;
    if (!o) {
      if (isAiKind(n.kind)) add(p, 'added', 'loosening', 'grant', `AI の役割（kind ${n.kind}）の追加`);
      else add(p, 'added', 'indeterminate', 'identity', `人・スクリプトの役割（kind ${n.kind}）の追加（承認や執行の主体が増えうるので人が見る）`);
      continue;
    }
    if (!n) {
      const refs = referencesTo(newCaps, name);
      if (refs.length) add(p, 'removed', 'indeterminate', 'identity', `役割の削除だが、まだ参照がある（${refs.slice(0, 3).join('、')}）`);
      else add(p, 'removed', 'tightening', 'grant', '役割の削除（参照なし）');
      continue;
    }
    for (const f of new Set([...Object.keys(o), ...Object.keys(n)])) {
      if (same(o[f], n[f])) continue;
      if (f === 'note') add(`${p}.note`, kind3(o[f], n[f]), 'neutral', 'doc', '役割の説明だけの変更');
      else if (ROLE_FIELDS.has(f)) add(`${p}.${f}`, kind3(o[f], n[f]), 'indeterminate', 'identity', `識別の根拠（${f}）の変更は人が見る`);
      else add(`${p}.${f}`, kind3(o[f], n[f]), 'indeterminate', 'structure', `規則にない役割の項目 ${f} の変更`);
    }
  }

  // capabilities
  const co = new Map(oldCaps.capabilities.map((c) => [c.id, c]));
  const cn = new Map(newCaps.capabilities.map((c) => [c.id, c]));
  for (const id of new Set([...co.keys(), ...cn.keys()])) {
    const o = co.get(id); const n = cn.get(id); const p = `capabilities[${id}]`;
    if (!n) { add(p, 'removed', 'loosening', 'grant', '権限の項目の削除（禁止と確かめ方が消える）'); continue; }
    const unknownRoles = rolesIn(n).filter((r) => !known(r));
    if (unknownRoles.length) add(p, o ? 'changed' : 'added', 'indeterminate', 'identity', `新旧どちらの roles にもない役割名：${unknownRoles.join('、')}`);
    const unknownLayers = setOf(n.enforced_by).filter((l) => !has(newCaps.layers, l));
    if (unknownLayers.length) add(`${p}.enforced_by`, 'changed', 'indeterminate', 'structure', `layers にない層の名前：${unknownLayers.join('、')}`);
    if (!o) { classifyNewCap(n, p, add, roleKind); continue; }
    diffCap(o, n, p, add, { roleKind, executed: executed(n) });
  }

  // invariants
  const io = new Map((oldCaps.invariants || []).map((v) => [v.id, v]));
  const inn = new Map((newCaps.invariants || []).map((v) => [v.id, v]));
  for (const id of new Set([...io.keys(), ...inn.keys()])) {
    const o = io.get(id); const n = inn.get(id); const p = `invariants[${id}]`;
    if (!n) { add(p, 'removed', 'loosening', 'invariant', '不変条件の削除'); continue; }
    if (!o) {
      if (n.status !== 'not_applicable' && setOf(n.tests).length === 0) add(p, 'added', 'indeterminate', 'invariant', `判例のない ${n.status} の不変条件の追加（SPEC §11-0 に合わない）`);
      else add(p, 'added', 'tightening', 'invariant', '不変条件の追加');
      for (const f of Object.keys(n)) if (!INV_FIELDS.has(f)) add(`${p}.${f}`, 'added', 'indeterminate', 'structure', `規則にない不変条件の項目 ${f}`);
      continue;
    }
    diffInv(o, n, p, add);
  }
  return summarize(out);
}

function kind3(o, n) { return o === undefined ? 'added' : n === undefined ? 'removed' : 'changed'; }

/** capability の中に出てくる役割名（allowed・drafting・expect・probe の expect） */
function rolesIn(c) {
  const s = new Set([...setOf(c.allowed), ...setOf(c.drafting), ...Object.keys(c.expect || {})]);
  for (const p of c.probes || []) for (const r of Object.keys(p.expect || {})) s.add(r);
  return [...s];
}
function referencesTo(caps, name) { return caps.capabilities.filter((c) => rolesIn(c).includes(name)).map((c) => c.id); }

function classifyNewCap(n, p, add, roleKind) {
  const unknown = Object.keys(n).filter((f) => !CAP_FIELDS.has(f));
  if (unknown.length) add(p, 'added', 'indeterminate', 'structure', `規則にない項目を持つ権限の追加（${unknown.join('、')}）`);
  const aiHolders = [...setOf(n.allowed), ...setOf(n.drafting)].filter((r) => isAiKind(roleKind(r)));
  if (aiHolders.length) { add(p, 'added', 'loosening', 'grant', `AI の役割に許す権限の追加（${aiHolders.join('、')}）`); return; }
  const allows = [];
  for (const [r, v] of Object.entries(n.expect || {})) if (v === 'allow' && isAiKind(roleKind(r))) allows.push(r);
  for (const pr of n.probes || []) for (const [r, v] of Object.entries(pr.expect || {})) if (v === 'allow' && isAiKind(roleKind(r))) allows.push(r);
  if (allows.length) { add(p, 'added', 'loosening', 'grant', `AI の役割の判定が allow の権限の追加（${[...new Set(allows)].join('、')}）`); return; }
  add(p, 'added', 'tightening', 'grant', '人・スクリプトだけに許し、AI の判定がすべて deny の権限の追加');
}

function diffCap(o, n, p, add, { roleKind, executed }) {
  for (const f of new Set([...Object.keys(o), ...Object.keys(n)])) {
    if (CAP_FIELDS.has(f) || same(o[f], n[f])) continue;
    add(`${p}.${f}`, kind3(o[f], n[f]), 'indeterminate', 'structure', `規則にない権限の項目 ${f} の変更`);
  }
  if (!same(o.title, n.title)) add(`${p}.title`, kind3(o.title, n.title), 'indeterminate', 'structure', '権限の題（何を守るか）の書き換えは範囲の変更でありうる');
  if (!same(o.note, n.note)) add(`${p}.note`, kind3(o.note, n.note), 'neutral', 'doc', '権限の説明だけの変更');

  for (const f of ['allowed', 'drafting']) {
    const d = setDiff(o[f], n[f]);
    for (const r of d.added) add(`${p}.${f}[${r}]`, 'added', 'loosening', 'grant', `${f === 'allowed' ? '許す' : '起草を許す'}役割の追加`);
    for (const r of d.removed) add(`${p}.${f}[${r}]`, 'removed', 'tightening', 'grant', `${f === 'allowed' ? '許す' : '起草を許す'}役割の削除`);
  }

  // expect（役割ごとのフックの判定）
  const eo = o.expect || {}; const en = n.expect || {};
  for (const r of new Set([...Object.keys(eo), ...Object.keys(en)])) {
    const a = own(eo, r); const b = own(en, r); if (a === b) continue;
    const q = `${p}.expect.${r}`;
    if (b === undefined) add(q, 'removed', 'loosening', 'grant', '役割が検査の対象から外れる');
    else if (a === undefined) add(q, 'added', b === 'deny' ? 'tightening' : 'loosening', 'grant', b === 'deny' ? '検査の対象に役割を加える（deny）' : '役割の判定を allow として加える');
    else add(q, 'changed', b === 'allow' ? 'loosening' : 'tightening', 'grant', `${a} → ${b}`);
  }

  // enforced_by（promise は強制の層に数えない）
  const lo = new Set(setOf(o.enforced_by)); const ln = new Set(setOf(n.enforced_by));
  for (const l of lo) if (!ln.has(l)) {
    if (l === 'promise') {
      const strongAdded = [...ln].some((x) => x !== 'promise' && !lo.has(x));
      add(`${p}.enforced_by[promise]`, 'removed', strongAdded ? 'neutral' : 'indeterminate', 'enforcement', strongAdded ? '約束を強制の層に置き換え' : '強制の層を足さずに「約束だけ」の印を外す（弱点の非公開になりうる）');
    } else add(`${p}.enforced_by[${l}]`, 'removed', 'loosening', 'enforcement', `強制の層（${l}）を減らす`);
  }
  for (const l of ln) if (!lo.has(l)) {
    if (l === 'promise') add(`${p}.enforced_by[promise]`, 'added', 'neutral', 'enforcement', '約束だけの層の追加（強制には数えない）');
    else add(`${p}.enforced_by[${l}]`, 'added', 'tightening', 'enforcement', `強制の層（${l}）を増やす`);
  }

  // probes（expect を除いた中身で対応づける。中身の書き換えは削除＋追加）
  const po = new Map((o.probes || []).map((x) => [probeKey(x), x]));
  const pn = new Map((n.probes || []).map((x) => [probeKey(x), x]));
  for (const [k, x] of po) if (!pn.has(k)) add(`${p}.probes${short(x)}`, 'removed', 'loosening', 'verification', 'probe の削除（確かめ方が減る）');
  for (const [k, x] of pn) {
    const prev = po.get(k);
    if (!prev) {
      // 実効の判定（probe の上書き ?? capability の expect）が allow になる AI の役割があれば、表が「その操作を許せ」と要求する＝緩める（F6）
      const roles = new Set([...Object.keys(en), ...Object.keys(x.expect || {})]);
      const allows = [...roles].filter((r) => (own(x.expect, r) ?? own(en, r)) === 'allow' && isAiKind(roleKind(r)));
      if (allows.length) add(`${p}.probes${short(x)}`, 'added', 'loosening', 'grant', `実効の判定が allow になる AI の役割を持つ probe の追加（${allows.join('、')}）`);
      else if (!executed.length) add(`${p}.probes${short(x)}`, 'added', 'neutral', 'verification', 'probe の追加だが適合性テストで実行されない（expect に hook_input を持つ役割がない）ので確かめ方に数えない'); // F12
      else add(`${p}.probes${short(x)}`, 'added', 'tightening', 'verification', 'probe の追加（確かめ方が増える）');
      continue;
    }
    const xo = prev.expect || {}; const xn = x.expect || {};
    for (const r of new Set([...Object.keys(xo), ...Object.keys(xn)])) {
      const a = own(xo, r); const b = own(xn, r); if (a === b) continue;
      const q = `${p}.probes${short(x)}.expect.${r}`;
      // 適合性テストで回らない役割への上書きは、allow にする（後で回り始めたとき緩む）ものだけを緩める側に数え、ほかは neutral（F12）
      if (!executed.includes(r)) { if (b === 'allow') add(q, kind3(a, b), 'loosening', 'grant', '適合性テストで実行されない役割への allow の上書き（後で回り始めると緩む）'); else add(q, kind3(a, b), 'neutral', 'verification', '適合性テストで実行されない役割の上書きの変更（確かめ方に数えない）'); continue; }
      if (a !== undefined && b !== undefined) add(q, 'changed', b === 'allow' ? 'loosening' : 'tightening', 'grant', `${a} → ${b}`);
      else if (a === undefined) add(q, 'added', b === 'deny' ? 'tightening' : 'loosening', 'grant', `probe の判定を ${b} として上書き`);
      else {
        const fall = own(en, r);
        if (fall === a) add(q, 'removed', 'neutral', 'grant', '同じ値の上書きを外す（実効の判定は変わらない）');
        else if (fall === 'deny') add(q, 'removed', 'tightening', 'grant', '上書きを外し、権限の判定（deny）に戻す');
        else add(q, 'removed', 'loosening', 'grant', '上書きを外し、その役割の判定がなくなる・allow になる');
      }
    }
  }

  for (const f of ['scenario_tests', 'verified_by']) {
    const d = setDiff(o[f], n[f]);
    for (const t of d.removed) add(`${p}.${f}[${t}]`, 'removed', 'loosening', 'verification', `確かめ方（${f}）の削除`);
    for (const t of d.added) add(`${p}.${f}[${t}]`, 'added', 'tightening', 'verification', `確かめ方（${f}）の追加`);
  }
  const g = setDiff(o.known_gaps, n.known_gaps);
  for (const t of g.added) add(`${p}.known_gaps`, 'added', 'neutral', 'disclosure', `穴の公開：${t.slice(0, 40)}`);
  for (const t of g.removed) add(`${p}.known_gaps`, 'removed', 'indeterminate', 'disclosure', `穴の記載の削除（本当に塞がったかは機械で分からない）：${t.slice(0, 40)}`);
}

function short(probe) { const s = canonical(probe); return `{${s.length > 60 ? s.slice(0, 57) + '...' : s}}`; }

function diffInv(o, n, p, add) {
  for (const f of new Set([...Object.keys(o), ...Object.keys(n)])) {
    if (INV_FIELDS.has(f) || same(o[f], n[f])) continue;
    add(`${p}.${f}`, kind3(o[f], n[f]), 'indeterminate', 'structure', `規則にない不変条件の項目 ${f} の変更`);
  }
  if (o.status !== n.status) {
    const down = STATUS_RANK[n.status] < STATUS_RANK[o.status];
    if (down) add(`${p}.status`, 'changed', 'loosening', 'invariant', `状態の格下げ（${o.status} → ${n.status}）`);
    else if (setOf(n.tests).length === 0) add(`${p}.status`, 'changed', 'indeterminate', 'invariant', `判例がないまま格上げ（${o.status} → ${n.status}）`);
    else add(`${p}.status`, 'changed', 'tightening', 'invariant', `状態の格上げ（${o.status} → ${n.status}）`);
  }
  const t = setDiff(o.tests, n.tests);
  for (const x of t.removed) add(`${p}.tests[${x}]`, 'removed', 'loosening', 'verification', '判例の削除（確かめ方が減る）');
  for (const x of t.added) add(`${p}.tests[${x}]`, 'added', 'tightening', 'verification', '判例の追加');
  // gaps・reason・title は known_gaps と同じ考え方：足すのは公開（neutral）、消す・書き換えるのは indeterminate
  for (const f of ['gaps', 'reason', 'title']) {
    const d = setDiff(o[f], n[f]);
    for (const x of d.added) if (!d.removed.length) add(`${p}.${f}`, 'added', 'neutral', 'disclosure', `${f} の追加：${x.slice(0, 40)}`);
    for (const x of d.removed) add(`${p}.${f}`, d.added.length ? 'changed' : 'removed', 'indeterminate', 'disclosure', `${f} の削除・書き換え（機械で妥当性が分からない）：${x.slice(0, 40)}`);
  }
}

/** 経路。どちらの経路でも人（オーナー）の承認は必須で、自動採用の値は存在しない */
export function routeFor(delta) {
  const cls = delta && CLASSES.includes(delta.class) ? delta.class : 'indeterminate';
  if (cls === 'loosening' || cls === 'indeterminate') return { lane: 'full_legislative', requires: ['constitutional_review', 'owner_approval'] };
  return { lane: 'standard', requires: ['independent_review', 'owner_approval'] };
}

// ---- ガード：「この権限の表の変更が、改善提案の通常の経路に乗ってよいか」の検査。ctx = { oldCaps, newCaps } ----
const changesOf = (ctx) => authorityDelta(ctx && ctx.oldCaps, ctx && ctx.newCaps).changes;
const firstOf = (ctx, pred) => { const c = changesOf(ctx).find(pred); return c ? `${c.path || '(全体)'}：${c.reason}` : null; };

/** 名前 → (ctx) => null | string（違反の理由） */
export const GUARDS = {
  'AD-WELLFORMED': (ctx) => firstOf(ctx, (c) => c.category === 'malformed'),
  'AD-NO-GRANT': (ctx) => firstOf(ctx, (c) => c.class === 'loosening' && c.category === 'grant'),
  'AD-ENFORCEMENT-NO-WEAKEN': (ctx) => firstOf(ctx, (c) => c.class === 'loosening' && c.category === 'enforcement'),
  'AD-VERIFIER-MONOTONE': (ctx) => firstOf(ctx, (c) => c.class === 'loosening' && c.category === 'verification'),
  'AD-INVARIANT-NO-DOWNGRADE': (ctx) => firstOf(ctx, (c) => c.class === 'loosening' && c.category === 'invariant'),
  'AD-NO-INDETERMINATE': (ctx) => firstOf(ctx, (c) => c.class === 'indeterminate' && c.category !== 'malformed'),
};

/** 既定は全ガード。guardNames はアブレーション実験（bench）だけが絞る */
export function check(ctx, guardNames = Object.keys(GUARDS)) {
  const violations = [];
  for (const g of guardNames) {
    const fn = GUARDS[g];
    if (!fn) { violations.push({ guard: g, reason: '知らないガード名' }); continue; }
    let r; try { r = fn(ctx); } catch (e) { r = `検査の失敗：${e && e.message}`; }
    if (r) violations.push({ guard: g, reason: r });
  }
  return { ok: violations.length === 0, violations };
}

/** 人が読む日本語の要約 */
export function formatDelta(delta) {
  const r = routeFor(delta);
  const name = { neutral: '影響なし', tightening: '締める', loosening: '緩める', indeterminate: '分類できない' };
  const lines = [`権限の差分：${name[delta.class]}（${delta.class}）`,
    `  内訳：締める ${delta.summary.tightening}・影響なし ${delta.summary.neutral}・緩める ${delta.summary.loosening}・分類できない ${delta.summary.indeterminate}`,
    `  経路：${r.lane}（必要：${r.requires.join('・')}。どちらの経路でもオーナーの承認が要る）`];
  if (!delta.changes.length) lines.push('  変更なし');
  for (const c of delta.changes) lines.push(`  [${name[c.class]}] ${c.path || '(全体)'}（${c.kind}）… ${c.reason}`);
  return lines.join('\n');
}
