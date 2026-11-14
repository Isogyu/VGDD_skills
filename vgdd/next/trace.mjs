// 追跡の記録（起草段階の試作。法律ではない）
//
// 要求から運用上の問題まで、成果物（artifact）どうしのつながり（link）を、追記専用の鎖つき記録（lib/chain.mjs）に残し、
// そこから「たどる（trace）」「要件ごとの網羅（coverage）」「欠け（gaps）」を作り直す。LLM は使わない。決定論的。
//
// 今の Kernel の記録には「要件の ID ── 票 ── 仕様の指紋 ── 承認の記録 ── 申請の SHA ── 判定の記録 ── 統合のコミット ── 受け入れの記録」
// のつながりが別々のファイルの欄として散らばっている。この部品は、それを1つの形（from → to ＋ rel）で持ち、両端（企画・設計の成果物、
// 統合の後の障害や指摘から票へ戻るつながり）を足せるようにする。Kernel の記録から取り込む純関数が linksFromEvidence（Kernel は変えない）。
//
// つながりの向き（1か所で決める）：link は「下流の成果物 from」から「上流の成果物 to」へ向く（from は to から導かれた・to に依る）。
//   trace の 'up' は from → to の向きにたどる（要求の側）、'down' は to → from の向きにたどる（運用の側）。
//
// 語彙（役割・行為者・票の ID・指紋・判定と監査の id・審査の種類・時刻・結論の名前）は lib/vocab.mjs。行為者は { role, kind, id, lineage }。
// 書けるのは：kind: 'script'（裁判所の側のプロセス。役割は SCRIPT_ROLES の許可リスト）と、kind: 'human' かつ role: 'owner'。
//   AI の役割は書けない（行政が自分の成果物に都合のよいつながりを作れない）。取り消し（retract）・移行（epoch）はオーナーだけ。
//
// 部品が保証すること：記録された行為者と入力が規則（GUARDS）に合うときだけ追記する。入力と行為者は入口で一度だけ JSON として写して凍結し、
//   検査と記録の両方にその写しを使う。記録を読み直すとき（state・verify）は各行をその時点の状態で再びガードに通し、通らない行は状態に入れない
//   （記録に直接書かれた偽の行を採らない）。入れなかった行は verify() の rejected_rows に出す。
//
// 保証できないこと（限界）：
//   - 行為者が本物であること。actor は呼び出し側の申告で、この部品は確かめられない。「記録を行政が書けない保護領域（Z3 と同じ扱い）に置き、
//     裁判所・オーナー側のプロセスだけがこの関数を呼ぶ」配置で強制する前提（未配線）。行政の AI がこの関数を直接呼べる配置では、
//     kind: 'script' の許可の役割や kind: 'human', role: 'owner' を名乗るだけで書ける。
//   - つながりの内容が事実であること。from と to が実在することも確かめない（ref は名前と書式だけ。digest は食い違いを検出するだけ）。
//     「要件 R-1 を票 T-001 が満たす」という主張が正しいかは、人が見る。この部品が言えるのは「記録にこう残っている」まで。
//   - 欠け（gaps）は「記録にない」ことを言うだけで、「行われなかった」ことの証明ではない。記録されていない成果物（つながりに一度も出ない
//     要件・票）は、expected を渡さない限り欠けとして見えない。
//   - 申請が「どの仕様の指紋に対するものか」は Kernel の held に書かれていない。取り込みでは直前の承認からの推定で、evidence.basis に残す。
//   - 規則を変えたとき、記録の鎖を書き換えられる者（オーナーの権限）が古い版の印を付けた偽の行を移行の記録の前に作り直す余地は、鎖の限界と同じ根。
//   - 票の id の形の宣言（ticketId）は開く側の設定だが、書く行に設定の写し（cfg.ticket_id）を残す（tr.v3）。再生では、写しが開く側の設定と
//     違う行は状態に入れず（古い版の行と同じ扱い）、書き込みも止める。オーナーの epoch に覆われた行は、その行の写しの宣言で確かめる。
//     正規表現は受けない。
//   - coverage の段階（stages）は「少なくとも1本」の道の存在で、全部の票・申請が満たされたことではない（tickets_without_spec・unsettled を併せて見る）。
//     判定の最新は evidence.at（判定の記録の collected_at）で決め、時刻がなければ厳しい側に倒す。この時刻は記録を書く側（取り込み）の申告。
//   - Kernel の gate_events の merged は統合のコミットを12桁しか持たない（gate-runner.sh:404、release.sh:111）。受け入れの記録か shaIndex
//     （呼び出し側が git から作る。この部品は git を呼ばない）で完全な SHA に決まらない統合は取り込めず、unresolved_merges に別に返す。
//     根本の解決は、Kernel の側で統合のコミットの完全な SHA を残す改正（この部品は Kernel を変えない）。
//   - 申請が再び held になり、別の承認を挟むと、同じ申請が2つの仕様に結び付く（未確定として数える）。held に仕様の指紋がないため、推定の限界。
//   - 再生の循環の検査は、速い道（全辺のトポロジカルソートを1回。線形）と、循環が見つかったときだけの遅い道（追記の順に増分の順位で入れ直す）がある。
//     偽の循環の行を書ける者（記録を書けるオーナー権限）は、遅い道に落として再生を遅くできる（正しさは変わらない）。
//   - tr.v1 の行は、オーナーの epoch に覆われれば根幹の検査と v1 の書式で受ける。v1 の時刻は記録の at で代用するが、これは書いた側の時刻で、
//     v1 の鍵の大文字小文字の畳み込みが生んだ「同じ節」は、今の規則では決められないので衝突する綴りの行は外す（integrity に出る）。
//   - 裁定の効力は judge・codex-judge の不一致だけ。時刻（evidence.at）は書く側の申告で、裁定と差し戻しの前後はその申告に頼る。
//   - state の使い回し（キャッシュ）は内部の読み取りと検査だけ。鍵は検証済みの記録の行数と末尾のハッシュで、鎖の検証は毎回やる。
//   - 件数・深さ・訪れる数の上限は資源の保護で、正しさの保証ではない（上限に達した結果は truncated で示す）。

import { openChain, digest, canonical, Refused } from './lib/chain.mjs';
import {
  parseActor, normActor, isOwner as vocabIsOwner, makeWorkItemId, parseWorkItemSpec, sameWorkItemSpec, DEFAULT_WORK_ITEM, isDigest, isArtifactRef, isGitSha,
  parseVerdictId, isAuditId, isRequirementId, isPolicyLine, parseTs as vocabParseTs, kernelTsToIso, VERDICTS, AUDIT_RESULTS, MODE_NAMES, refusal,
} from './lib/vocab.mjs';

export const RECORD_TYPE = 'vgdd.trace.v1';
/** 規則の版。ガードの規則を変えるたびに上げ、各行に rules として記録する。古い版の行はオーナーの移行の記録（epoch）に覆われるまで状態に入れない */
export const RULES = 'tr.v3';
export const DEFAULT_MAX_LINKS = 20000;
export const MAX_DEPTH = 64;
export const DEFAULT_DEPTH = 16;
export const MAX_VISIT = 100000;
export const DEFAULT_VISIT = 5000;
const MAX_NOTE = 500;
const MAX_STR = 200;
const MAX_REASON = 1000;
const MAX_EXPECTED = 5000;
const MAX_GAPS = 10000;

/** 欠けの出力に必ず付ける注記 */
export const NOT_PROOF_NOTE = '欠けは「記録にない」ことを言うだけで、「行われなかった」ことの証明ではない。記録されていない成果物（つながりに一度も出ない要件・票）は、expected を渡さない限り見えない。';

/** 成果物の種類の許可リスト */
export const KINDS = Object.freeze([
  'goal', 'requirement', 'design', 'ticket', 'spec', 'approval', 'request', 'audit', 'verdict', 'ruling',
  'merge', 'acceptance', 'release', 'incident', 'improvement', 'experience',
]);
const KIND_SET = new Set(KINDS);

/** 述語を test の形にする（ID_RE の表で vocab の述語と正規表現を同じに扱う） */
const P = (fn) => ({ test: fn });
/**
 * id の書式（kind ごとの許可リスト）。null プロトタイプ。
 * 票・要件・仕様と承認の指紋・申請と統合の参照・判定と監査の id は lib/vocab.mjs の語彙。ほかの kind（目標・設計・裁定・受け入れ・リリース・障害・
 * 改善提案・経験）は、この部品だけが扱う成果物の名前で、ここに持つ（改善提案・経験の id は improvement.mjs・experience.mjs の採番と同じ形）
 */
const ID_RE = Object.assign(Object.create(null), {
  goal: /^G-[0-9]{1,4}$/,
  requirement: P(isRequirementId),                // A1、R-12、FR-1.2（vocab）
  design: /^(?:DES|ADR)-[0-9]{3,4}$/,
  spec: P(isDigest),                              // 仕様の指紋（spec-digest.mjs。SPEC §4）
  approval: P(isDigest),                          // 承認の記録の1行の指紋（sha256: ＋ 行の hash）
  request: P(isArtifactRef),                      // 申請の参照（40桁の Git の SHA か sha256: 形。vocab）
  // ticket の書式は vocab の票の ID の宣言（既定 T-+3〜4桁。opt.ticketId で差し替え）。正規表現は利用者から受けない
  audit: P(isAuditId),                            // 判定の記録の head（12桁）＋内容の指紋の先頭8桁（vocab）
  verdict: P((x) => parseVerdictId(x) !== null),  // VRD-<12桁>-<審査の種類>[-<8桁>]（vocab）
  ruling: /^RUL-[0-9a-f]{16}$/,                   // 裁定の記録の1行の指紋の先頭
  merge: P(isArtifactRef),                        // 統合のコミット（40桁）か、Git でない領域の統合の指紋（vocab）
  acceptance: /^ACC-[0-9a-f]{16}$/,
  release: /^REL-[A-Z0-9][A-Z0-9._-]{0,38}$/,        // 大文字だけ（F11）
  incident: /^INC-[0-9]{3,5}$/,
  improvement: /^IMP-[0-9]{4}$/,                  // improvement.mjs の提案 id
  experience: /^exp-[0-9]{6}$/,                   // experience.mjs の項目 id
});
/** id そのものが指紋である kind。digest を付けるなら id と同じでなければならない */
const ID_IS_DIGEST = new Set(['spec', 'approval']);

/**
 * つなぎ方の表（これ以外は拒む。この1か所だけに持つ）。[rel, from の kind, to の kind, 意味]。向きは「from（下流）→ to（上流）」。
 *
 * 工程との対応（docs/design/vgdd-next-architecture.md §6）：
 *   企画     goal ← requirement（satisfies）／approval（approves：目標・要件・設計のオーナーの承認）
 *   要件     requirement ← ticket・design（satisfies）
 *   設計     design ← design（derives：決定の導出）／verdict（verifies：設計の司法の審査）／approval（approves）
 *   実装     ticket ← spec（specifies）← approval（approves）、spec ← request（implements）
 *   試験     request ← audit（verifies：決定論的な監査。単体・結合の試験はここ）
 *   セキュリティ request ← verdict（verifies：別系統の司法。evidence.mode で judge・security を区別）
 *   リリース request ← merge（integrates）← release（deploys）、merge ← acceptance（approves：オーナーの受け入れ）、request ← ruling
 *   運用     incident → merge／release／ticket（caused_by：起因）
 *   保守     ticket → incident（addresses：障害を受けた票）、ticket ← ticket（derives・depends_on）
 *   改善     improvement → incident（addresses）、experience → verdict／incident（derives）、improvement → experience（derives）
 *   廃止     ticket → requirement／design／release（retires）、同じ kind の新旧（supersedes）
 *
 * 仕様の rel に足したもの（理由）：
 *   - approves に approval → goal・requirement・design：§6 の表の企画・要件・設計の関門は「オーナーの承認」で、承認の記録を結べないと関門が追えない
 *   - verifies に verdict → design：設計の関門は「司法の審査」
 *   - retires（ticket → requirement・design・release）：廃止・移行の工程を supersedes だけでは表せない（置き換えのない廃止がある）
 *   - depends_on（ticket → ticket。to は前提で上流）：票の front matter の depends_on を取り込むため。循環は拒む
 *   - derives に ticket → ticket：保守・改修の票が前の票から生まれたことを残すため
 */
export const REL_TABLE = Object.freeze([
  ['satisfies', 'ticket', 'requirement'], ['satisfies', 'design', 'requirement'], ['satisfies', 'requirement', 'goal'],
  ['specifies', 'spec', 'ticket'],
  ['approves', 'approval', 'spec'], ['approves', 'approval', 'goal'], ['approves', 'approval', 'requirement'], ['approves', 'approval', 'design'],
  ['approves', 'acceptance', 'merge'], ['approves', 'ruling', 'request'],
  ['implements', 'request', 'spec'],
  ['verifies', 'audit', 'request'], ['verifies', 'verdict', 'request'], ['verifies', 'verdict', 'design'],
  ['integrates', 'merge', 'request'],
  ['deploys', 'release', 'merge'],
  ['caused_by', 'incident', 'merge'], ['caused_by', 'incident', 'release'], ['caused_by', 'incident', 'ticket'],
  ['addresses', 'ticket', 'incident'], ['addresses', 'improvement', 'incident'],
  ['derives', 'design', 'design'], ['derives', 'ticket', 'ticket'], ['derives', 'experience', 'verdict'], ['derives', 'experience', 'incident'], ['derives', 'improvement', 'experience'],
  ...KINDS.map((k) => ['supersedes', k, k]),
  ['retires', 'ticket', 'requirement'], ['retires', 'ticket', 'design'], ['retires', 'ticket', 'release'],
  ['depends_on', 'ticket', 'ticket'],
].map((r) => Object.freeze(r)));
export const RELS = Object.freeze([...new Set(REL_TABLE.map((r) => r[0]))]);
const REL_SET = new Set(RELS);
const PAIR_SET = new Set(REL_TABLE.map((r) => `${r[0]}|${r[1]}|${r[2]}`));
/** 循環を拒む rel。supersedes は単独、derives と depends_on は1つの群として見る（互いに逆向きの組み合わせも循環） */
export const CYCLE_RELS = Object.freeze(['supersedes', 'derives', 'depends_on']);

/** script の役割の許可リスト（vocab の役割。裁判所の執行と取り込み。行政の代行 night_runner・回収 reaper は入れない） */
export const SCRIPT_ROLES = Object.freeze(['gate_runner', 'trace_importer']);
const WRITE_OPS = ['link', 'retract', 'epoch'];
const ALL_OPS = new Set([...WRITE_OPS, 'query']);
const DIRECTIONS = new Set(['up', 'down', 'both']);
const EVKEY_RE = /^[a-z][a-z_]{0,23}$/;
const CTRL = /[\p{Cc}\p{Cf}\u2028\u2029]/u;

// ---- 小さな道具 ----
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const isInt = (n, lo, hi) => Number.isSafeInteger(n) && n >= lo && n <= hi;
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const clone = (v) => (v === undefined ? undefined : JSON.parse(JSON.stringify(v)));
function deepFreeze(v) { if (v && typeof v === 'object' && !Object.isFrozen(v)) { Object.freeze(v); for (const k of Object.keys(v)) deepFreeze(v[k]); } return v; }
/** 入口の写し：JSON として一度だけ写して凍結する（toJSON・getter・Proxy で検査と記録を食い違わせない）。写せなければ null */
function snapshot(v) { if (v === undefined) return undefined; try { const s = JSON.stringify(v); return s === undefined ? null : deepFreeze(JSON.parse(s)); } catch { return null; } }
const cleanText = (s, max) => typeof s === 'string' && s.length > 0 && s.length <= max && !CTRL.test(s);
// 鍵用の正規化（NFKC・前後の空白を落とす）。大文字小文字は畳まない：id の大文字小文字は kind ごとの書式で固定してあり（ID_RE の表）、
// 畳むと REL-V1 と REL-v1 のような別の id が同じ節になるため。書式を通らない表記ゆれは TR-ID-FORMAT が拒む
const normKey = (s) => String(s).normalize('NFKC').trim();
export const nodeKey = (ref) => `${normKey(ref.kind)}:${normKey(ref.id)}`;
const linkKey = (rel, f, t) => `${normKey(rel)}|${nodeKey(f)}|${nodeKey(t)}`;
const refOk = (r) => isObj(r) && Object.keys(r).every((k) => k === 'kind' || k === 'id' || k === 'digest') && typeof r.kind === 'string' && typeof r.id === 'string' && (r.digest === undefined || typeof r.digest === 'string');
const isOwner = vocabIsOwner;
const actorOk = (a) => parseActor(a).ok;

/** どの kind の id にも共通の検査：1〜128 字、制御文字・書式文字（ゼロ幅）・空白・行区切りを含まず、NFKC で変わらない */
const SAFE_ID_BAD = /[\p{Cc}\p{Cf}\p{Z}\u2028\u2029]/u;
const safeId = (id) => typeof id === 'string' && id.length > 0 && id.length <= 128 && !SAFE_ID_BAD.test(id) && id.normalize('NFKC') === id;
/** 票の id の宣言 { prefix, digits: [最小, 最大] } を照合関数にする（vocab の makeWorkItemId。線形時間。正規表現は利用者から受けない） */
const ticketMatcher = (spec) => makeWorkItemId(spec);
const DEFAULT_TICKET = makeWorkItemId(DEFAULT_WORK_ITEM);
const RELEASE_V1 = /^REL-[A-Za-z0-9][A-Za-z0-9._-]{0,38}$/; // tr.v1 の release の id（大文字小文字を区別しない綴りを許していた）
/**
 * id の書式の検査（safeId ＋ kind ごとの固定の書式）。ticket は cfg.ticketMatch で差し替わる。
 * cfg.idFormat === 'v1'（移行の記録に覆われた tr.v1 の行）は v1 の書式：共通の safeId を課さず（長さだけ）、release は v1 の綴り
 */
function idOk(kind, id, cfg) {
  const v1 = !!cfg && cfg.idFormat === 'v1';
  if (v1 ? !(typeof id === 'string' && id.length > 0 && id.length <= 128) : !safeId(id)) return false;
  if (kind === 'ticket') return (cfg && cfg.ticketMatch ? cfg.ticketMatch : DEFAULT_TICKET)(id);
  const re = v1 && kind === 'release' ? RELEASE_V1 : ID_RE[kind];
  return !!re && re.test(id);
}

/** 時刻 → ミリ秒（lib/vocab.mjs の parseTs。秒まで必須・時差は Z か ±HH:MM。読めなければ null） */
export const parseTs = vocabParseTs;

// ---- 状態 ----

// 循環の検査は増分（Pearce–Kelly のトポロジカル順位）。辺 from → to が増えるとき、順位 ord が ord[from] < ord[to] を保つ。
// 逆順に積む鎖でも1辺あたり定数で済むよう、新しい from には最小より小さい順位、新しい to には最大より大きい順位を与える。
// 取り消しで辺が減っても順位は有効なまま。循環を見る辺の集まり（群）：supersedes は単独、derives と depends_on は1つの群（互いに逆向きの
// 組み合わせも循環とみなす。F12）
const cycGroup = (rel) => (rel === 'supersedes' ? 'supersedes' : (rel === 'derives' || rel === 'depends_on') ? 'order' : null);
const newCyc = () => ({ ord: new Map(), out: new Map(), inn: new Map(), lo: 0, hi: 0 });
const edgeSet = (m, a, b) => { let s = m.get(a); if (!s) m.set(a, s = new Map()); s.set(b, (s.get(b) || 0) + 1); };
const edgeDel = (m, a, b) => { const s = m.get(a); if (!s) return; const c = (s.get(b) || 0) - 1; if (c > 0) s.set(b, c); else { s.delete(b); if (!s.size) m.delete(a); } };
/** 【遅い道の再生だけ】辺 f → t を足すと循環になるか（t から f へ、順位が ord[f] 以下の範囲だけをたどる。読み取りだけ） */
function wouldCyclePK(st, group, f, t) {
  const c = st.cyc[group]; const of = c.ord.get(f); const ot = c.ord.get(t);
  if (of === undefined || ot === undefined || of < ot) return false;
  const stack = [t]; const seen = new Set([t]);
  while (stack.length) {
    const u = stack.pop();
    if (u === f) return true;
    for (const v of (c.out.get(u) || new Map()).keys()) if (!seen.has(v) && c.ord.get(v) <= of) { seen.add(v); stack.push(v); }
  }
  return false;
}
function cycAdd(st, group, f, t) {
  const c = st.cyc[group];
  if (!c.ord.has(f) && !c.ord.has(t)) { c.ord.set(f, c.hi); c.hi += 1; c.ord.set(t, c.hi); c.hi += 1; }
  else if (!c.ord.has(f)) { c.lo -= 1; c.ord.set(f, c.lo); }
  else if (!c.ord.has(t)) { c.ord.set(t, c.hi); c.hi += 1; }
  const of = c.ord.get(f); const ot = c.ord.get(t);
  if (of > ot) {
    const reach = (start, nextOf, ok) => { const seen = new Set([start]); const stack = [start]; while (stack.length) { const u = stack.pop(); for (const v of (nextOf.get(u) || new Map()).keys()) if (!seen.has(v) && ok(c.ord.get(v))) { seen.add(v); stack.push(v); } } return [...seen]; };
    const fwd = reach(t, c.out, (o) => o <= of).sort((a, b) => c.ord.get(a) - c.ord.get(b));
    const bwd = reach(f, c.inn, (o) => o >= ot).sort((a, b) => c.ord.get(a) - c.ord.get(b));
    const pool = [...bwd, ...fwd].map((k) => c.ord.get(k)).sort((a, b) => a - b);
    [...bwd, ...fwd].forEach((k, i) => c.ord.set(k, pool[i]));
  }
  edgeSet(c.out, f, t); edgeSet(c.inn, t, f);
}
function cycDel(st, group, f, t) { const c = st.cyc[group]; edgeDel(c.out, f, t); edgeDel(c.inn, t, f); }

/**
 * 辺 f → t を足すと循環になるか。今の状態から t を出発して同じ群の有効な辺をたどり、f に着くか1回の探索で見る（順位は要らない。反復）。
 * 追記の検査（TR-NO-CYCLE）が使う。探索は状態の大きさまで（上限の打ち切りはない）
 */
function wouldCycle(st, group, f, t) {
  const stack = [t]; const seen = new Set([t]);
  while (stack.length) {
    const u = stack.pop();
    if (u === f) return true;
    for (const idx of st.outAdj.get(u) || []) {
      const e = st.links[idx];
      if (e.retracted || cycGroup(e.rel) !== group || seen.has(e.tk)) continue;
      seen.add(e.tk); stack.push(e.tk);
    }
  }
  return false;
}
/** 辺の集まりに循環があるか（反復のトポロジカルソート＝Kahn 法。群ごとに1回。線形） */
function hasCycle(edges) {
  const idx = new Map(); const names = [];
  const id = (k) => { let i = idx.get(k); if (i === undefined) { i = names.length; idx.set(k, i); names.push(k); } return i; };
  const out = []; const indeg = [];
  for (const [a, b] of edges) { const x = id(a); const y = id(b); while (out.length < names.length) { out.push([]); indeg.push(0); } out[x].push(y); indeg[y] += 1; }
  const q = []; for (let i = 0; i < names.length; i += 1) if (indeg[i] === 0) q.push(i);
  let done = 0;
  for (let h = 0; h < q.length; h += 1) { done += 1; for (const y of out[q[h]]) { indeg[y] -= 1; if (indeg[y] === 0) q.push(y); } }
  return done < names.length;
}

function newState(pk = false) {
  return {
    links: [], bySeq: new Map(), nodes: new Map(), outAdj: new Map(), inAdj: new Map(),
    active: new Map(), retractedKeys: new Set(), epochs: [], cyc: pk ? { supersedes: newCyc(), order: newCyc() } : null, lc: new Map(),
    meta: { rows: 0, uncoveredLegacy: 0, rejected: [], rules: RULES },
  };
}
const push = (m, k, v) => { const a = m.get(k); if (a) a.push(v); else m.set(k, [v]); };
/** 節の digest は、有効なつながりが主張している値から決める。有効なつながりが1つもなくなった節は空に戻す（オーナーの取り消しが出口。F4） */
function nodeTouch(st, ref, k, d, delta) {
  let n = st.nodes.get(k);
  if (!n) { if (delta < 0) return; n = { kind: ref.kind, id: ref.id, digest: null, dc: new Map(), ac: 0 }; st.nodes.set(k, n); }
  n.ac += delta;
  if (d !== null) { const c = (n.dc.get(d) || 0) + delta; if (c > 0) n.dc.set(d, c); else n.dc.delete(d); }
  n.digest = n.dc.size ? n.dc.keys().next().value : null;
}

function applyLink(st, r, input) {
  const f = input.from; const t = input.to;
  const fk = nodeKey(f); const tk = nodeKey(t);
  const key = linkKey(input.rel, f, t);
  const idx = st.links.length;
  const entry = {
    seq: r.seq, rules: r.rules ?? null, rel: input.rel, from: { kind: f.kind, id: f.id, digest: f.digest ?? null }, to: { kind: t.kind, id: t.id, digest: t.digest ?? null },
    fk, tk, key, evidence: input.evidence === undefined ? null : clone(input.evidence), note: input.note === undefined ? null : input.note,
    actor: normActor(r.actor), at: typeof r.at === 'string' ? r.at : null, retracted: null,
  };
  st.links.push(entry); st.bySeq.set(r.seq, idx); st.active.set(key, idx);
  nodeTouch(st, f, fk, f.digest ?? null, 1); nodeTouch(st, t, tk, t.digest ?? null, 1);
  push(st.outAdj, fk, idx); push(st.inAdj, tk, idx);
  const g = cycGroup(input.rel); if (g && fk !== tk && st.cyc) cycAdd(st, g, fk, tk);
}
function applyRetract(st, r) {
  const idx = st.bySeq.get(r.target_seq); const l = st.links[idx];
  l.retracted = { seq: r.seq, actor: normActor(r.actor), reason: r.reason, at: typeof r.at === 'string' ? r.at : null };
  st.active.delete(l.key); st.retractedKeys.add(l.key);
  nodeTouch(st, l.from, l.fk, l.from.digest, -1); nodeTouch(st, l.to, l.tk, l.to.digest, -1);
  const g = cycGroup(l.rel); if (g && l.fk !== l.tk && st.cyc) cycDel(st, g, l.fk, l.tk);
}

/** 記録の1行を、検査に渡す入力の形に戻す（行の欄は許可リストで射影する） */
function inputOf(r) {
  if (r.op === 'link') return isObj(r.link) ? clone(r.link) : null;
  if (r.op === 'retract') return { link_seq: r.target_seq, reason: r.reason };
  if (r.op === 'epoch') return { reason: r.reason };
  return null;
}

// 再生で確かめ直さないガード：鎖の状態・件数の上限（書く時の設定）・規則の版（行ごとに別に扱う）・問い合わせの範囲
const REPLAY_SKIP = new Set(['TR-CHAIN-INTACT', 'TR-LINK-LIMIT', 'TR-RULES-VERSION', 'TR-QUERY-BOUNDS']);
/**
 * 統治の根幹の検査。規則の版が変わっても変わらない：誰が書けるか・書式・表・重複・自己・循環。
 * 古い版の行（移行の記録に覆われたもの）にも課す。通らない行は、覆われていても状態に入れない（F8）
 */
export const ROOT_GUARDS = Object.freeze({
  link: ['TR-ACTOR-SHAPE', 'TR-WRITER-ALLOWED', 'TR-SCRIPT-ROLE', 'TR-INPUT-SHAPE', 'TR-KIND-ALLOWLIST', 'TR-ID-FORMAT', 'TR-REL-ALLOWLIST', 'TR-REL-KIND-PAIR', 'TR-NO-SELF', 'TR-NO-DUPLICATE', 'TR-NODE-SPELLING', 'TR-NO-CYCLE'],
  retract: ['TR-ACTOR-SHAPE', 'TR-WRITER-ALLOWED', 'TR-SCRIPT-ROLE', 'TR-INPUT-SHAPE', 'TR-RETRACT-OWNER', 'TR-RETRACT-TARGET', 'TR-REASON-REQUIRED'],
});

/** 移行の記録が覆う行の数。再生と同じ判定：今の版・全ガードを通った・覆う範囲が直前の行までと一致するものだけ（F9） */
function coveredCount(records, cfg) {
  const guards = Object.keys(GUARDS).filter((g) => !REPLAY_SKIP.has(g) && g !== 'TR-RETRACT-TARGET');
  let n = 0;
  records.forEach((r, i) => {
    if (!isObj(r) || r.op !== 'epoch' || r.rules !== RULES || !isObj(r.covers)) return;
    const c = r.covers.count;
    if (!Number.isSafeInteger(c) || c !== i || r.covers.last_hash !== (c === 0 ? 'genesis' : (records[c - 1] || {}).hash)) return;
    const ctx = { op: 'epoch', actor: snapshot(r.actor), input: snapshot(inputOf(r)), state: newState(), chain: { ok: true }, config: cfg };
    if (check(ctx, guards).ok) n = Math.max(n, c);
  });
  return n;
}

/**
 * 記録の全行から状態を組み立てる。今の版（RULES）の行は、その時点の状態で全ガードに通し、通らない行は状態に入れず
 * meta.rejected に残す（投げない。偽の行で全体が止まる行き止まりを作らない）。古い版の行は、移行の記録に覆われていれば根幹の検査
 * （ROOT_GUARDS）だけ確かめて入れ、覆われていなければ入れずに meta.uncoveredLegacy を数える（書く側は TR-RULES-VERSION で止まる。
 * 解くのはオーナーの epoch だけ）。
 * @param {object[]} records chain.read() の行
 * @param {{ ticketMatch?: Function|null }} [config]
 * @param {{ pendingEpoch?: boolean }} [o] 移行の記録を書く直前だけ：今ある全行を覆うとみなす
 */
export function replay(records, config = {}, o = {}) {
  // 速い道：循環の検査を再生の途中でやらず、全行を入れた後に、群ごとに1回だけ反復のトポロジカルソートで確かめる（線形）。
  //   追記の時に循環を拒んでいるので、正しい記録なら循環はない。取り消された辺も含めた「これまでに入れた全辺」が非循環なら、どの時点でも循環はなかった
  //   ので、1行ずつ確かめた結果と同じになる。循環が見つかった（＝偽の行がある）ときだけ、遅い道（追記の順に増分の順位で入れ直し、循環を作った行を特定して外す）
  const fast = replayWith(records, config, o, false);
  return fast.suspect ? replayWith(records, config, o, true).st : fast.st;
}

function replayWith(records, config, o, pk) {
  const st = newState(pk);
  const cfg = { maxLinks: Infinity, ticketMatch: config.ticketMatch || null, rules: RULES };
  const v1cfg = { ...cfg, idFormat: 'v1' }; // tr.v1 の行の書式の細部は v1 の規則で見る（大文字小文字の固定・判定の id の形など。N5）
  const noCycle = (list) => list.filter((g) => g !== 'TR-NO-CYCLE'); // 循環は上の方法で別に見る（各行で到達可能性を探索すると行数の2乗になる）
  const guards = noCycle(Object.keys(GUARDS).filter((g) => !REPLAY_SKIP.has(g)));
  const covered = o.pendingEpoch ? records.length : coveredCount(records, cfg);
  const edges = { supersedes: [], order: [] };
  const reject = (r, why) => st.meta.rejected.push({ seq: isObj(r) && Number.isSafeInteger(r.seq) ? r.seq : null, reason: why });
  records.forEach((r, i) => {
    st.meta.rows += 1;
    if (!isObj(r) || r.type !== RECORD_TYPE || !WRITE_OPS.includes(r.op) || !Number.isSafeInteger(r.seq)) { reject(r, '知らない行'); return; }
    const current = r.rules === RULES;
    if (!current && i >= covered) { st.meta.uncoveredLegacy += 1; reject(r, `規則の版が今（${RULES}）と違う（${String(r.rules).slice(0, 20)}）。オーナーの移行の記録（epoch）が要る`); return; }
    // 設定の写し（tr.v3）：今の版の行は、書いた時の票の ID の宣言が開く側の宣言と同じでなければ状態に入れない（覆われていない古い版の行と同じ扱い）。
    // オーナーの epoch に覆われた行は、その行の写しの宣言で確かめる（開き方で過去の行の扱いを変えない）
    const rowSpec = isObj(r.cfg) && Object.keys(r.cfg).every((k) => k === 'ticket_id') ? parseWorkItemSpec(r.cfg.ticket_id) : null;
    if (current && r.op !== 'epoch' && i >= covered && !sameWorkItemSpec(rowSpec, ticketSpecOf(cfg))) { st.meta.uncoveredLegacy += 1; reject(r, '設定の写し（cfg.ticket_id）が開く側の票の ID の宣言と違う（書いた時と別の設定で開いている）。オーナーの移行の記録（epoch）が要る'); return; }
    const rowCfg = i < covered && rowSpec ? { ...(r.rules === 'tr.v1' ? v1cfg : cfg), ticketMatch: makeWorkItemId(rowSpec) } : (!current && r.rules === 'tr.v1' ? v1cfg : cfg);
    const actor = snapshot(r.actor); const input = inputOf(r);
    if (!actorOk(actor)) { reject(r, '行為者の形が合わない'); return; }
    const ctx = { op: r.op, actor, input: snapshot(input), state: st, chain: { ok: true }, config: rowCfg };
    if (r.op === 'epoch') {
      const res = check(ctx, guards.filter((g) => g !== 'TR-RETRACT-TARGET'));
      const c = isObj(r.covers) ? r.covers.count : null;
      const okCover = current && Number.isSafeInteger(c) && c === i && r.covers.last_hash === (c === 0 ? 'genesis' : (records[c - 1] || {}).hash);
      if (!res.ok) { reject(r, res.violations.map((v) => v.guard).join('・')); return; }
      if (current && !okCover) { reject(r, '移行の記録の覆う範囲が、その前の行と一致しない'); return; }
      st.epochs.push({ seq: r.seq, actor: normActor(actor), reason: r.reason, covers: clone(r.covers), at: r.at ?? null });
      return;
    }
    const res = check(ctx, current ? guards : noCycle(ROOT_GUARDS[r.op]));
    if (!res.ok) { reject(r, res.violations.map((v) => v.guard).join('・')); return; }
    if (st.bySeq.has(r.seq)) { reject(r, 'seq が重複'); return; }
    if (r.op === 'link') {
      const inp = ctx.input; const fk = nodeKey(inp.from); const tk = nodeKey(inp.to);
      const g = cycGroup(inp.rel);
      if (g && fk !== tk) {
        if (pk) { if (wouldCyclePK(st, g, fk, tk)) { reject(r, 'TR-NO-CYCLE'); return; } } else edges[g].push([fk, tk]);
      }
      st.lc.set(fk.toLowerCase(), fk); st.lc.set(tk.toLowerCase(), tk);
      applyLink(st, { ...r, actor }, inp);
    } else applyRetract(st, { ...r, actor });
  });
  const suspect = !pk && (hasCycle(edges.supersedes) || hasCycle(edges.order));
  return { st, suspect };
}

/**
 * 検査に渡す文脈。actor と input は入口の写し（JSON として写して凍結）にそろえる。
 * ctx = { op, actor, input, state, chain, config }。鎖が壊れているときは chain.ok=false で state は空
 * @param {{ state?: object }} a state を渡すと再生を省く（呼び出し側が、検証済みの同じ記録から作った状態だけを渡す）
 */
export function buildContext({ records, chain = { ok: true }, op, actor, input = {}, config, state }) {
  const st = !chain.ok ? newState() : (state && op !== 'epoch' ? state : replay(records, config, { pendingEpoch: op === 'epoch' }));
  return { op, actor: snapshot(actor), input: snapshot(input), state: st, chain, config: { maxLinks: DEFAULT_MAX_LINKS, ticketMatch: null, rules: RULES, ...config } };
}

// ---- ガード ----
// 各ガードは自分の関心だけを見る。前提が成り立たない入力（型が違うなど）は null を返し、前提を見るガードが止める（全ガードを通れば fail-closed）。

const refsOf = (ctx) => {
  if (!isObj(ctx.input)) return [];
  if (ctx.op === 'link') return [ctx.input.from, ctx.input.to].filter(refOk);
  if (ctx.op === 'query') return [ctx.input.ref].filter(refOk);
  return [];
};
const linkParts = (ctx) => (ctx.op === 'link' && isObj(ctx.input) && refOk(ctx.input.from) && refOk(ctx.input.to) && typeof ctx.input.rel === 'string' ? ctx.input : null);

function evidenceProblem(e) {
  if (!isObj(e)) return 'evidence がオブジェクトでない';
  const ks = Object.keys(e);
  if (ks.length > 8) return 'evidence の項目が多すぎる（8まで）';
  for (const k of ks) {
    if (!EVKEY_RE.test(k)) return `evidence の項目名が許可の形でない：${k.slice(0, 30)}`;
    const v = e[k];
    if (!(cleanText(v, MAX_STR) || (typeof v === 'number' && Number.isSafeInteger(v)) || typeof v === 'boolean')) return `evidence.${k} が 1〜${MAX_STR} 字の文字列・安全な整数・真偽値でない`;
  }
  return null;
}

/**
 * evidence の値の検査（tr.v3。書く時に拒む）：at は vocab の時刻の形、result はつながりの種類ごとの結論の名前（vocab）だけ。
 *   判定 → 申請（verifies）：APPROVED・CHANGES_REQUIRED・UNAVAILABLE。監査 → 申請：passed・failed・not_run。裁定 → 申請（approves）：merge。
 *   ほかのつながりは result を持てない（読む側が「不明」に倒すだけの綴りの誤りを、記録に入れさせない）
 */
function evidenceValueProblem(i) {
  const e = i.evidence;
  if (e.at !== undefined && vocabParseTs(e.at) === null) return 'evidence.at が時刻の形（秒まで・時差は Z か ±HH:MM）でない';
  if (e.result === undefined) return null;
  const fk = isObj(i.from) ? i.from.kind : null;
  const allowed = i.rel === 'verifies' && fk === 'verdict' ? VERDICTS : i.rel === 'verifies' && fk === 'audit' ? AUDIT_RESULTS : i.rel === 'approves' && fk === 'ruling' ? ['merge'] : null;
  if (!allowed) return `このつながり（${String(fk)} -${String(i.rel)}->）は evidence.result を持てない`;
  return allowed.includes(e.result) ? null : `evidence.result が ${allowed.join('・')} のどれでもない：${String(e.result).slice(0, 30)}`;
}

/** 名前 → (ctx) => null | string（違反の理由。日本語） */
export const GUARDS = {
  'TR-CHAIN-INTACT': (ctx) => (ctx.chain && ctx.chain.ok ? null : `記録の鎖が壊れている（${ctx.chain && ctx.chain.code}）`),

  'TR-OP-VALID': (ctx) => (typeof ctx.op === 'string' && ALL_OPS.has(ctx.op) ? null : `操作が許可リストにない：${String(ctx.op).slice(0, 30)}`),

  'TR-ACTOR-SHAPE': (ctx) => {
    if (ctx.op === 'query') return null;
    const a = parseActor(ctx.actor);
    return a.ok ? null : `行為者が vocab の形（{ role, kind, id, lineage }。役割は表の名前、種類は役割と合う）でない：${a.errors[0]}`;
  },

  'TR-WRITER-ALLOWED': (ctx) => {
    if (ctx.op === 'query' || !actorOk(ctx.actor)) return null;
    const a = normActor(ctx.actor);
    if (a.kind === 'script' || isOwner(a)) return null;
    return `書けるのは script とオーナー（human・owner）だけ。${a.kind}・${a.role} は書けない（成果物を作る側が自分のつながりを作れない）`;
  },

  'TR-SCRIPT-ROLE': (ctx) => {
    const a = ctx.op === 'query' ? null : normActor(ctx.actor);
    if (!a || a.kind !== 'script') return null;
    return SCRIPT_ROLES.includes(a.role) ? null : `script の役割が許可リスト（${SCRIPT_ROLES.join('・')}）にない：${a.role}`;
  },

  'TR-INPUT-SHAPE': (ctx) => {
    const i = ctx.input;
    if (ctx.op === 'link') {
      if (!isObj(i)) return '入力がオブジェクトでない（JSON として写せない値を含む）';
      const extra = Object.keys(i).filter((k) => !['from', 'to', 'rel', 'evidence', 'note'].includes(k));
      if (extra.length) return `知らない項目：${extra.map((k) => k.slice(0, 30)).join('、')}`;
      for (const k of ['from', 'to']) if (!refOk(i[k])) return `${k} が { kind, id, digest? } の形でない`;
      if (typeof i.rel !== 'string') return 'rel が文字列でない';
      if (i.note !== undefined && !cleanText(i.note, MAX_NOTE)) return `note が 1〜${MAX_NOTE} 字の文字列でない（制御文字・ゼロ幅文字を含む）`;
      if (i.evidence !== undefined) return evidenceProblem(i.evidence) || evidenceValueProblem(i);
      return null;
    }
    if (ctx.op === 'retract') {
      if (!isObj(i)) return '入力がオブジェクトでない';
      const extra = Object.keys(i).filter((k) => k !== 'link_seq' && k !== 'reason');
      if (extra.length) return `知らない項目：${extra.map((k) => k.slice(0, 30)).join('、')}`;
      if (!isInt(i.link_seq, 1, 1e9)) return 'link_seq が正の安全な整数でない';
      if (i.reason !== undefined && (typeof i.reason !== 'string' || i.reason.length > MAX_REASON || CTRL.test(i.reason))) return `reason が ${MAX_REASON} 字までの文字列でない`;
      return null;
    }
    if (ctx.op === 'epoch') {
      if (!isObj(i)) return '入力がオブジェクトでない';
      const extra = Object.keys(i).filter((k) => k !== 'reason');
      if (extra.length) return `知らない項目：${extra.map((k) => k.slice(0, 30)).join('、')}`;
      if (i.reason !== undefined && (typeof i.reason !== 'string' || i.reason.length > MAX_REASON || CTRL.test(i.reason))) return `reason が ${MAX_REASON} 字までの文字列でない`;
      return null;
    }
    if (ctx.op === 'query') {
      if (!isObj(i)) return '問い合わせがオブジェクトでない';
      const extra = Object.keys(i).filter((k) => !['ref', 'direction', 'maxDepth', 'maxVisit'].includes(k));
      if (extra.length) return `知らない項目：${extra.map((k) => k.slice(0, 30)).join('、')}`;
      return refOk(i.ref) ? null : 'ref が { kind, id, digest? } の形でない';
    }
    return null;
  },

  'TR-KIND-ALLOWLIST': (ctx) => {
    for (const r of refsOf(ctx)) if (!KIND_SET.has(r.kind)) return `kind が許可リストにない：${r.kind.slice(0, 30)}（大文字・全角・空白の違いも別物として拒む）`;
    return null;
  },

  'TR-ID-FORMAT': (ctx) => {
    for (const r of refsOf(ctx)) {
      if (!KIND_SET.has(r.kind)) continue;
      if (!idOk(r.kind, r.id, ctx.config)) return `${r.kind} の id が書式に合わない（制御文字・ゼロ幅文字・空白・128字超・kind ごとの形）：${r.id.slice(0, 40)}`;
      if (r.digest !== undefined && !isDigest(r.digest)) return `digest が sha256:<64桁の16進> でない：${r.digest.slice(0, 20)}`;
    }
    return null;
  },

  'TR-REL-ALLOWLIST': (ctx) => {
    if (ctx.op !== 'link' || !isObj(ctx.input) || typeof ctx.input.rel !== 'string') return null;
    return REL_SET.has(ctx.input.rel) ? null : `rel が許可リスト（${RELS.join('・')}）にない：${ctx.input.rel.slice(0, 30)}`;
  },

  'TR-REL-KIND-PAIR': (ctx) => {
    const l = linkParts(ctx); if (!l) return null;
    if (!REL_SET.has(l.rel) || !KIND_SET.has(l.from.kind) || !KIND_SET.has(l.to.kind)) return null;
    return PAIR_SET.has(`${l.rel}|${l.from.kind}|${l.to.kind}`) ? null : `表にない組：${l.from.kind} -${l.rel}-> ${l.to.kind}`;
  },

  'TR-DIGEST-CONSISTENT': (ctx) => {
    for (const r of refsOf(ctx)) {
      if ((r.kind === 'verdict' || r.kind === 'audit') && r.digest === undefined && /-[0-9a-f]{8}$/.test(r.id) && idOk(r.kind, r.id, ctx.config)) return `${r.kind} の id に指紋（8桁）があるのに digest がない`;
      if (!KIND_SET.has(r.kind) || r.digest === undefined || !isDigest(r.digest)) continue;
      if (!idOk(r.kind, r.id, ctx.config)) continue;
      if (ID_IS_DIGEST.has(r.kind) && r.digest !== r.id) return `${r.kind} は id が指紋なので、digest は id と同じでなければならない`;
      // 判定・監査の節の id の末尾8桁は、内容の指紋（digest）の先頭8桁（sha256: の後）と一致しなければならない（F4 の残り。8桁を付けるなら digest も要る）
      if (r.kind === 'verdict' || r.kind === 'audit') {
        const m = /-([0-9a-f]{8})$/.exec(r.id);
        if (m && m[1] !== r.digest.slice(7, 15)) return `${r.kind} の id の指紋（${m[1]}）が digest の先頭8桁と一致しない`;
      }
      const n = ctx.state.nodes.get(nodeKey(r));
      if (n && n.digest !== null && n.digest !== r.digest) return `${r.kind}:${r.id} の指紋が記録済みの値と食い違う（記録 ${n.digest.slice(0, 19)}…）`;
    }
    return null;
  },

  'TR-NO-SELF': (ctx) => {
    const l = linkParts(ctx); if (!l) return null;
    return nodeKey(l.from) === nodeKey(l.to) ? '自分自身へのつながり' : null;
  },

  // 大文字小文字だけが違う別の綴りの節が、すでに状態にある（tr.v1 は鍵を小文字にそろえて同じ節にしていた）：同じ節か別の節か決められないので、
  // 書き込みも、覆われた古い行の再生も、拒む。今の書式は大文字小文字を固定しているので、衝突は tr.v1 の行が入っているときだけ起きる
  'TR-NODE-SPELLING': (ctx) => {
    for (const r of refsOf(ctx)) {
      const k = nodeKey(r); const prev = ctx.state.lc.get(k.toLowerCase());
      if (prev !== undefined && prev !== k) return `節の綴り ${r.id.slice(0, 40)} が、大文字小文字だけ違う既存の節（${prev.slice(0, 40)}）と衝突する（同じ節か別の節か決められない）`;
    }
    return null;
  },

  'TR-NO-DUPLICATE': (ctx) => {
    const l = linkParts(ctx); if (!l) return null;
    const idx = ctx.state.active.get(linkKey(l.rel, l.from, l.to));
    return idx === undefined ? null : `同じ from・to・rel のつながりがすでにある（seq ${ctx.state.links[idx].seq}。正規化した鍵で照合。digest・evidence・note の違いでは別にならない）`;
  },

  'TR-NO-CYCLE': (ctx) => {
    const l = linkParts(ctx); if (!l) return null;
    const g = cycGroup(l.rel); if (!g) return null;
    const f = nodeKey(l.from); const t = nodeKey(l.to);
    if (f === t) return null; // 自己へのつながりは TR-NO-SELF
    // 増分の順位（cycAdd）で、新しい辺 from → to が循環になるかを、影響する範囲だけ見て決める（上限の打ち切りがなく、正当な行が永久に拒まれない）
    return wouldCycle(ctx.state, g, f, t) ? `${l.rel} が循環する（${l.to.id} から ${l.from.id} へすでにたどれる。derives と depends_on は同じ群）` : null;
  },

  'TR-RETRACT-OWNER': (ctx) => {
    if (ctx.op !== 'retract' && ctx.op !== 'epoch') return null;
    return isOwner(ctx.actor) ? null : `${ctx.op === 'retract' ? '取り消し' : '移行の記録'}はオーナー（human・owner）だけ。AI・script には解けない`;
  },

  'TR-RETRACT-TARGET': (ctx) => {
    if (ctx.op !== 'retract' || !isObj(ctx.input) || !isInt(ctx.input.link_seq, 1, 1e9)) return null;
    const idx = ctx.state.bySeq.get(ctx.input.link_seq);
    if (idx === undefined) return `seq ${ctx.input.link_seq} のつながりがない（つながり以外の行・状態に入っていない行は取り消せない）`;
    return ctx.state.links[idx].retracted ? `seq ${ctx.input.link_seq} はすでに取り消されている` : null;
  },

  'TR-REASON-REQUIRED': (ctx) => {
    if ((ctx.op !== 'retract' && ctx.op !== 'epoch') || !isObj(ctx.input)) return null;
    const r = ctx.input.reason;
    return typeof r === 'string' && r.trim().length > 0 ? null : '理由（reason）が要る（空・空白だけは不可）';
  },

  'TR-LINK-LIMIT': (ctx) => {
    if (ctx.op !== 'link') return null;
    const max = ctx.config && ctx.config.maxLinks;
    return Number.isSafeInteger(max) && ctx.state.links.length < max ? null : `つながりの件数が上限（${max}）に達した。追記を拒む（取り消しの行は消さないので件数は減らない。上限を上げるのは開く側の設定）`;
  },

  'TR-RULES-VERSION': (ctx) => {
    if (ctx.op !== 'link' && ctx.op !== 'retract') return null;
    if (!ctx.config || ctx.config.rules !== RULES) return `規則の版が今（${RULES}）と違う`;
    return ctx.state.meta.uncoveredLegacy === 0 ? null : `古い版の行が ${ctx.state.meta.uncoveredLegacy} 行あり、オーナーの移行の記録（epoch）に覆われていない。オーナーが確かめて epoch を書くまで追記しない`;
  },

  'TR-RELINK-RETRACTED': (ctx) => {
    const l = linkParts(ctx); if (!l) return null;
    const k = linkKey(l.rel, l.from, l.to);
    if (!ctx.state.retractedKeys.has(k) || ctx.state.active.has(k)) return null;
    return isOwner(ctx.actor) ? null : 'オーナーが取り消したつながりを、オーナー以外が書き戻すことはできない（取り込みの再実行で復活させない）';
  },

  'TR-QUERY-BOUNDS': (ctx) => {
    if (ctx.op !== 'query' || !isObj(ctx.input)) return null;
    const i = ctx.input;
    if (typeof i.direction !== 'string' || !DIRECTIONS.has(i.direction)) return `direction が up・down・both のどれでもない`;
    if (!isInt(i.maxDepth, 1, MAX_DEPTH)) return `maxDepth が 1〜${MAX_DEPTH} の安全な整数でない`;
    if (!isInt(i.maxVisit, 1, MAX_VISIT)) return `maxVisit が 1〜${MAX_VISIT} の安全な整数でない`;
    return null;
  },
};

/** 既定は全ガード。guardNames はアブレーション実験（bench）だけが絞る。例外は投げず、違反として返す */
export function check(ctx, guardNames = Object.keys(GUARDS)) {
  const violations = [];
  for (const g of guardNames) {
    if (!Object.hasOwn(GUARDS, g)) { violations.push({ guard: g, reason: '知らないガード名（fail-closed）' }); continue; }
    let r;
    try { r = GUARDS[g](ctx); } catch (e) { r = `検査中に例外（fail-closed）：${String((e && e.message) || e).slice(0, 80)}`; }
    if (r) violations.push({ guard: g, reason: r });
  }
  return { ok: violations.length === 0, violations };
}

// ---- 問い合わせ（状態に対する純関数。決定論的。並びは固定） ----

/** 問い合わせの結果に必ず付ける。偽の行・覆われていない古い版の行があれば ok: false（行は結果に入っていない） */
export function integrityOf(st) {
  const rejected = st.meta.rejected.length; const legacy = st.meta.uncoveredLegacy;
  const ok = rejected === 0 && legacy === 0;
  return { ok, rejected_count: rejected, legacy_uncovered: legacy, warning: ok ? null : `記録に、規則に合わず状態に入れなかった行が ${rejected} 行ある（うち古い版で覆われていない行 ${legacy}）。この結果にはそれらの行が入っていない。verify() の rejected_rows を確かめる` };
}

function queryOrThrow(st, input, config = {}) {
  // 状態にすでにある節は、tr.v1 の綴り（REL-v1 など）でも引ける（v1 の書式で見る）。状態にない節は今の書式だけ
  const known = isObj(input) && refOk(input.ref) && st.nodes.has(nodeKey(input.ref));
  const ctx = { op: 'query', actor: null, input: snapshot(input), state: st, chain: { ok: true }, config: { ticketMatch: null, ...config, ...(known ? { idFormat: 'v1' } : {}) } };
  const r = check(ctx, ['TR-OP-VALID', 'TR-INPUT-SHAPE', 'TR-KIND-ALLOWLIST', 'TR-ID-FORMAT', 'TR-QUERY-BOUNDS']);
  if (!r.ok) { const e = new Refused('bad_query', r.violations.map((v) => `${v.guard}: ${v.reason}`).join(' / ')); e.violations = r.violations; throw e; }
  return ctx.input;
}

const linkView = (l) => ({
  seq: l.seq, rel: l.rel, from: { ...l.from }, to: { ...l.to }, evidence: l.evidence === null ? null : { ...l.evidence }, note: l.note, at: l.at,
  actor_role: l.actor.role,
});
function neighbors(st, k, dir) {
  const arr = (dir === 'up' ? st.outAdj : st.inAdj).get(k) || [];
  const out = [];
  for (const idx of arr) { const l = st.links[idx]; if (!l.retracted) out.push({ l, other: dir === 'up' ? l.tk : l.fk }); }
  return out.sort((a, b) => cmp(a.l.rel, b.l.rel) || cmp(a.other, b.other) || a.l.seq - b.l.seq);
}
function walk(st, start, dir, maxDepth, maxVisit) {
  const seen = new Map([[start, 0]]); const used = new Set();
  let level = [start]; let depth = 0; let truncDepth = false; let truncVisit = false;
  while (level.length) {
    if (depth >= maxDepth) { for (const k of level) if (neighbors(st, k, dir).some((x) => !seen.has(x.other))) { truncDepth = true; break; } break; }
    const next = [];
    for (const k of level) for (const { l, other } of neighbors(st, k, dir)) {
      if (!seen.has(other)) {
        if (seen.size >= maxVisit) { truncVisit = true; continue; }
        seen.set(other, depth + 1); next.push(other);
      }
      used.add(l.seq);
    }
    level = next; depth += 1;
  }
  const nodes = [...seen].map(([k, d]) => ({ k, d })).sort((a, b) => a.d - b.d || cmp(a.k, b.k)).map(({ k, d }) => {
    const n = st.nodes.get(k); return { kind: n.kind, id: n.id, digest: n.digest, depth: d };
  });
  const links = [...used].sort((a, b) => a - b).map((s) => linkView(st.links[st.bySeq.get(s)]));
  return { nodes, links, truncated: { depth: truncDepth, visit: truncVisit } };
}

/**
 * ある成果物から上流（要求の側）・下流（運用の側）へたどった成果物とつながりの一覧。
 * 'both' は上流と下流を別々にたどる（行き来して別の枝へ広がらない）。取り消されたつながりは使わない。
 * note と evidence は外から来た文字列で、データとして扱う（untrusted_fields）。結果には integrity が付く。
 * @param {{ direction?: 'up'|'down'|'both', maxDepth?: number, maxVisit?: number }} [opt]
 */
export function traceOf(st, ref, opt = {}, config = {}) {
  const o = opt || {};
  const q = queryOrThrow(st, { ref, direction: o.direction === undefined ? 'both' : o.direction, maxDepth: o.maxDepth === undefined ? DEFAULT_DEPTH : o.maxDepth, maxVisit: o.maxVisit === undefined ? DEFAULT_VISIT : o.maxVisit }, config);
  const k = nodeKey(q.ref); const n = st.nodes.get(k);
  const res = { ref: { kind: q.ref.kind, id: q.ref.id }, found: !!n && n.ac > 0, direction: q.direction, limits: { maxDepth: q.maxDepth, maxVisit: q.maxVisit }, untrusted_fields: ['note', 'evidence'], digest_match: null, up: null, down: null, integrity: integrityOf(st) };
  if (!res.found) return res;
  if (q.ref.digest !== undefined) res.digest_match = n.digest === null ? null : n.digest === q.ref.digest;
  if (q.direction !== 'down') res.up = walk(st, k, 'up', q.maxDepth, q.maxVisit);
  if (q.direction !== 'up') res.down = walk(st, k, 'down', q.maxDepth, q.maxVisit);
  return res;
}

const activeIn = (st, k, rel, fromKind) => (st.inAdj.get(k) || []).map((i) => st.links[i]).filter((l) => !l.retracted && l.rel === rel && l.from.kind === fromKind);
const activeOut = (st, k, rel, toKind) => (st.outAdj.get(k) || []).map((i) => st.links[i]).filter((l) => !l.retracted && l.rel === rel && l.to.kind === toKind);
const idsOf = (ls, side) => [...new Set(ls.map((l) => l[side].id))].sort();

function expectedList(v, kind, config) {
  if (v === undefined) return [];
  if (!Array.isArray(v) || v.length > MAX_EXPECTED) throw new Refused('bad_query', `expected は ${MAX_EXPECTED} 件までの配列`);
  const out = new Set();
  for (const id of v) {
    if (!idOk(kind, id, config)) throw new Refused('bad_query', `${kind} の id が書式に合わない：${String(id).slice(0, 40)}`);
    out.add(id);
  }
  return [...out].sort();
}

// ---- 結論の集計（coverage と gaps で共有。同じ規則で数える） ----
//
// 申請ごとに：
//   - 判定は、種類（judge・codex-judge・codex-security・codex-ux。verdict の id から読む）ごとに「最新」の結論を取り、全部が APPROVED のときだけ approved。
//     CHANGES_REQUIRED が1つでもあれば returned（オーナーの裁定 ruling → request があれば ruled：判定が分かれた申請を裁定で統合する Kernel の経路）。
//     結論を読めない（evidence.result がない・知らない値）種類があれば unknown（承認に数えない）。判定がなければ none。
//   - 監査は最新の結論が passed のときだけ passed。failed・not_run・読めない値は別に数える。
//   - 「最新」は evidence.at（時刻）で決める。全部に時刻があり最大が1つなら、それ。時刻がない・同時刻で結論が割れるときは、厳しい側
//     （判定は CHANGES_REQUIRED > unknown > APPROVED、監査は failed > not_run > unknown > passed）。
// 票ごとに：置き換えられていない仕様（supersedes の to になっていない spec）だけを現行とする。現行が1つなら ok、複数なら ambiguous
//   （未確定。満たされているとは数えない）、現行がなければ none（仕様なし）か superseded_only。
// 申請が2つ以上の仕様に結び付くときは ambiguous（未確定）。
const VERDICT_RANK = { CHANGES_REQUIRED: 2, unknown: 1, APPROVED: 0 };
const AUDIT_RANK = { failed: 3, not_run: 2, unknown: 1, passed: 0 };
/** つながりの時刻：evidence.at。なければ、tr.v1 の行に限り記録の at（鎖の時刻）で代用する（v1 は at を必須にしていなかった。N6）。v2 の行は evidence.at が必須 */
const timeOf = (l) => { const t = l.evidence ? parseTs(l.evidence.at) : null; return t !== null ? t : (l.rules === 'tr.v1' ? parseTs(l.at) : null); };
function resultOf(l, rank) {
  const ev = l.evidence; const r = ev && typeof ev.result === 'string' && Object.hasOwn(rank, ev.result) ? ev.result : 'unknown';
  return { result: r, at: timeOf(l) };
}
/** 最新の結論と、その時刻（全部に時刻があるときだけ。なければ null）。list は resultOf の結果の配列 */
function latestOf(list, rank) {
  if (!list.length) return null;
  let pool = list; let at = null;
  if (list.every((x) => x.at !== null)) { at = Math.max(...list.map((x) => x.at)); pool = list.filter((x) => x.at === at); }
  return { result: pool.reduce((a, x) => (rank[x.result] > rank[a] ? x.result : a), pool[0].result), at };
}
/** 裁定で通せる判定の種類（Kernel：判定が分かれた judge と Codex の judge を、オーナーの裁定で統合する）。security などの不合格は裁定でも通せない（N2） */
const RULABLE = new Set(['judge', 'codex-judge']);
const ANA = new WeakMap();
function analyze(st) {
  let a = ANA.get(st); if (a) return a;
  const superseded = new Set();
  for (const l of st.links) if (!l.retracted && l.rel === 'supersedes' && l.from.kind === 'spec') superseded.add(l.tk);
  const reqs = new Map(); const tickets = new Map();
  a = {
    superseded,
    request(rk) {
      let r = reqs.get(rk); if (r) return r;
      const implLinks = activeOut(st, rk, 'implements', 'spec'); const specs = implLinks.map((l) => l.tk);
      // 必須の判定の種類（取り込みが held の no_codex・security_required から implements の evidence に残す）。分からなければ null（存在する種類だけで決める）
      let required = null;
      if (implLinks.length === 1 && implLinks[0].evidence && typeof implLinks[0].evidence.no_codex === 'boolean' && typeof implLinks[0].evidence.security_required === 'boolean') {
        const e = implLinks[0].evidence; required = ['judge'];
        if (!e.no_codex) { required.push('codex-judge'); if (e.security_required) required.push('codex-security'); }
      }
      const byMode = new Map();
      for (const l of activeIn(st, rk, 'verifies', 'verdict')) { const m = parseVerdictId(l.from.id); const k = m ? m.mode : 'unknown_mode'; (byMode.get(k) || byMode.set(k, []).get(k)).push(resultOf(l, VERDICT_RANK)); }
      const entries = [...byMode].map(([mode, list]) => ({ mode, ...latestOf(list, VERDICT_RANK) }));
      const missing = required ? required.filter((m) => !byMode.has(m)) : [];
      for (const m of missing) entries.push({ mode: m, result: 'unknown', at: null }); // 必須の種類がなければ、結論が不明（承認に数えない）
      const rulingLinks = activeIn(st, rk, 'approves', 'ruling');
      let judgment = 'none';
      if (entries.length) {
        const cr = entries.filter((e) => e.result === 'CHANGES_REQUIRED');
        if (cr.length) {
          // 裁定は、通せる種類（judge・codex-judge）の不一致だけに効き、差し戻しの時刻より前でない（同時刻は可）ものだけが有効。時刻が決まらなければ効かない
          const valid = cr.every((e) => RULABLE.has(e.mode) && e.at !== null) && rulingLinks.some((l) => { const t = timeOf(l); return t !== null && cr.every((e) => t >= e.at); });
          judgment = valid ? 'ruled' : 'returned';
        } else judgment = entries.some((e) => e.result === 'unknown') ? 'unknown' : 'approved';
      }
      const aud = latestOf(activeIn(st, rk, 'verifies', 'audit').map((l) => resultOf(l, AUDIT_RANK)), AUDIT_RANK);
      r = { key: rk, specs, ambiguous: specs.length > 1, judgment, rulings: rulingLinks.length, required, missing, audit: aud === null ? 'none' : aud.result, merges: activeIn(st, rk, 'integrates', 'merge') };
      reqs.set(rk, r); return r;
    },
    ticket(tk) {
      let t = tickets.get(tk); if (t) return t;
      const specs = [...new Set(activeIn(st, tk, 'specifies', 'spec').map((l) => l.fk))].sort();
      const current = specs.filter((s) => !superseded.has(s));
      t = { key: tk, specs, current, state: specs.length === 0 ? 'none' : current.length === 0 ? 'superseded_only' : current.length === 1 ? 'ok' : 'ambiguous' };
      tickets.set(tk, t); return t;
    },
  };
  ANA.set(st, a); return a;
}
const isActiveNode = (n) => n && n.ac > 0;

/**
 * 要件ごとの網羅の表。各欄は「記録にある」ことだけを言い、上の集計の規則で数える（現行の仕様・全部の判定が APPROVED・監査が passed）。
 * 段階（stages）は「少なくとも1本」の存在で、その要件を満たす票のうち、現行の仕様が1つに決まる票を通る道があること（仕様のない票が別にあっても true になりうるので、tickets_without_spec と unsettled を併せて見る）。未確定（ambiguous）は満たされているとは数えない。
 * 障害は、merge・ticket に直接つながるもの（incidents）と、release 経由のもの（incidents_possible。release が複数の merge を配置するので「可能性」）を分ける。
 * @param {{ expectedRequirements?: string[] }} [opt] 記録にまだ出ない要件も、全部 false の行として出したいとき（main の票・要件の表から渡す）
 */
export function coverageOf(st, opt = {}, config = {}) {
  const o = opt || {};
  const an = analyze(st);
  const reqs0 = new Map([...st.nodes].filter(([, n]) => n.kind === 'requirement' && isActiveNode(n)));
  for (const id of expectedList(o.expectedRequirements, 'requirement', config)) { const k = nodeKey({ kind: 'requirement', id }); if (!reqs0.has(k)) reqs0.set(k, { kind: 'requirement', id }); }
  const rows = [];
  for (const rk of [...reqs0.keys()].sort()) {
    const n = reqs0.get(rk);
    const goals = activeOut(st, rk, 'satisfies', 'goal'); const designs = activeIn(st, rk, 'satisfies', 'design'); const tickets = activeIn(st, rk, 'satisfies', 'ticket');
    const unsettled = []; const specsCurrent = new Set(); let superseded = 0; const noSpec = new Set();
    const requests = new Map(); let ambiguousReq = 0;
    const incidents = new Set(); const possible = new Set(); const allMerges = new Map(); const rel = new Set();
    for (const tl of tickets) {
      const ti = an.ticket(tl.fk);
      for (const il of activeIn(st, tl.fk, 'caused_by', 'incident')) incidents.add(il.from.id);
      superseded += ti.specs.length - ti.current.length;
      if (ti.state === 'none' || ti.state === 'superseded_only') noSpec.add(tl.from.id);
      if (ti.state === 'ambiguous' || ti.state === 'superseded_only') unsettled.push(`${tl.from.id}:spec_${ti.state}`);
      for (const sk of ti.specs) for (const ql of activeIn(st, sk, 'implements', 'request')) for (const ml of an.request(ql.fk).merges) allMerges.set(ml.fk, ml); // 障害の帰属は全版の申請から
      if (ti.state !== 'ok') continue;
      const sk = ti.current[0]; specsCurrent.add(sk);
      for (const ql of activeIn(st, sk, 'implements', 'request')) { const r = an.request(ql.fk); if (r.ambiguous) { ambiguousReq += 1; unsettled.push(`${ql.from.id.slice(0, 12)}:request_spec_ambiguous`); } else requests.set(ql.fk, r); }
    }
    for (const [mk] of allMerges) {
      for (const il of activeIn(st, mk, 'caused_by', 'incident')) incidents.add(il.from.id);
      for (const rl of activeIn(st, mk, 'deploys', 'release')) { rel.add(rl.from.id); for (const il of activeIn(st, rl.fk, 'caused_by', 'incident')) possible.add(il.from.id); }
    }
    for (const id of incidents) possible.delete(id);
    const rv = [...requests.values()];
    const merges = new Map(); for (const r of rv) for (const ml of r.merges) merges.set(ml.fk, ml);
    const approvedSpecs = [...specsCurrent].filter((sk) => activeIn(st, sk, 'approves', 'approval').length > 0).length;
    const c = (f) => rv.filter(f).length;
    const row = {
      requirement: n.id, goals: idsOf(goals, 'to'), designs: idsOf(designs, 'from'), tickets: idsOf(tickets, 'from'),
      tickets_without_spec: [...noSpec].sort(), specs_current: specsCurrent.size, specs_superseded: superseded, approved_specs: approvedSpecs,
      requests: rv.length, ambiguous_requests: ambiguousReq,
      audit_passed_requests: c((r) => r.audit === 'passed'), audit_failed_requests: c((r) => r.audit === 'failed'), audit_other_requests: c((r) => r.audit === 'not_run' || r.audit === 'unknown'),
      approved_requests: c((r) => r.judgment === 'approved'), ruled_requests: c((r) => r.judgment === 'ruled'), returned_requests: c((r) => r.judgment === 'returned'), unknown_verdict_requests: c((r) => r.judgment === 'unknown'),
      merges: merges.size, accepted_merges: [...merges.keys()].filter((mk) => activeIn(st, mk, 'approves', 'acceptance').length > 0).length,
      verdict_basis: rv.length === 0 ? null : rv.every((r) => r.required) ? 'required_kinds' : rv.some((r) => r.required) ? 'mixed' : 'present_kinds_only',
      releases: rel.size, incidents: [...incidents].sort(), incidents_possible: [...possible].sort(), unsettled: [...new Set(unsettled)].sort(),
    };
    row.stages = {
      ticket: tickets.length > 0, spec: specsCurrent.size > 0, approval: approvedSpecs > 0, request: rv.length > 0,
      audit: row.audit_passed_requests > 0, verdict: row.approved_requests + row.ruled_requests > 0, merge: merges.size > 0, acceptance: row.accepted_merges > 0,
      incident: incidents.size > 0,
    };
    rows.push(row);
  }
  const s = (f) => rows.filter(f).length;
  return {
    rows, untrusted_fields: [], integrity: integrityOf(st),
    summary: { requirements: rows.length, with_ticket: s((r) => r.stages.ticket), with_approved_spec: s((r) => r.stages.approval), with_request: s((r) => r.stages.request), with_audit_passed_and_verdict: s((r) => r.stages.audit && r.stages.verdict), with_merge: s((r) => r.stages.merge), with_acceptance: s((r) => r.stages.acceptance), with_incident: s((r) => r.stages.incident), unsettled: s((r) => r.unsettled.length > 0) },
    note: '各欄は記録にあることだけを言う。現行の仕様（置き換えられていない仕様）が1つに決まる票だけを数え、判定は種類ごとの最新が全部 APPROVED のときだけ approved、監査は passed のときだけ audit に数える。内容の正しさ（受け入れの中身など）は見ない。unsettled は未確定（満たされているとは数えない）。incidents_possible は release 経由で、どの要件の障害かは確定しない。各段は「少なくとも1本」の存在で、全部が満たされたことではない（tickets_without_spec と unsettled を併せて見る）。verdict_basis が present_kinds_only の行は、申請に必須の判定の種類が記録になく（取り込みの held の no_codex・security_required が付いていない）、存在する種類だけで決めた。裁定（ruled）は judge・codex-judge の不一致にだけ効き、security の不合格は通さない。',
  };
}

/** 票から要件に、satisfies・derives・depends_on だけをたどって着くか。'yes'・'no'・'undetermined'（訪れる数の上限で打ち切った） */
function ticketReachesRequirement(st, start, limit) {
  const seen = new Set([start]); const q = [start];
  for (let h = 0; h < q.length; h += 1) {
    for (const idx of st.outAdj.get(q[h]) || []) {
      const l = st.links[idx]; if (l.retracted) continue;
      if (l.rel === 'satisfies' && l.to.kind === 'requirement') return 'yes';
      if ((l.rel === 'derives' || l.rel === 'depends_on') && l.to.kind === 'ticket' && !seen.has(l.tk)) {
        if (seen.size >= limit) return 'undetermined';
        seen.add(l.tk); q.push(l.tk);
      }
    }
  }
  return 'no';
}

/**
 * 欠けの一覧（code, kind, id, detail）と、未確定の一覧（undetermined。欠けとは別に数える）。並びは code・kind・id。取り消されたつながりは数えない。
 * 欠けは「記録にない」ことを言うだけで、「行われなかった」ことの証明ではない（note に必ず入る）。
 * @param {{ expectedRequirements?: string[], expectedTickets?: string[], maxGaps?: number, maxVisit?: number, unresolvedMergeRequests?: string[] }} [opt]
 *   unresolvedMergeRequests：統合の記録はあるが完全な SHA に解決できなかった申請の SHA（linksFromEvidence の unresolved_merges から渡す）
 */
export function gapsOf(st, opt = {}, config = {}) {
  const o = opt || {};
  const maxGaps = o.maxGaps === undefined ? MAX_GAPS : o.maxGaps;
  if (!isInt(maxGaps, 1, MAX_GAPS)) throw new Refused('bad_query', `maxGaps は 1〜${MAX_GAPS}`);
  const maxVisit = o.maxVisit === undefined ? 2000 : o.maxVisit;
  if (!isInt(maxVisit, 1, MAX_VISIT)) throw new Refused('bad_query', `maxVisit は 1〜${MAX_VISIT}`);
  const unres = new Set();
  if (o.unresolvedMergeRequests !== undefined) {
    if (!Array.isArray(o.unresolvedMergeRequests) || o.unresolvedMergeRequests.length > MAX_EXPECTED) throw new Refused('bad_query', `unresolvedMergeRequests は ${MAX_EXPECTED} 件までの配列`);
    for (const x of o.unresolvedMergeRequests) { if (!idOk('request', x, config)) throw new Refused('bad_query', 'unresolvedMergeRequests に申請の SHA（40桁）でない値がある'); unres.add(x); }
  }
  const an = analyze(st);
  const nodes = new Map([...st.nodes].filter(([, n]) => isActiveNode(n)));
  for (const id of expectedList(o.expectedRequirements, 'requirement', config)) { const k = nodeKey({ kind: 'requirement', id }); if (!nodes.has(k)) nodes.set(k, { kind: 'requirement', id }); }
  for (const id of expectedList(o.expectedTickets, 'ticket', config)) { const k = nodeKey({ kind: 'ticket', id }); if (!nodes.has(k)) nodes.set(k, { kind: 'ticket', id }); }
  const gaps = []; const und = [];
  const add = (code, n, detail) => gaps.push({ code, kind: n.kind, id: n.id, detail });
  const unsure = (code, n, detail) => und.push({ code, kind: n.kind, id: n.id, detail });
  for (const [k, n] of nodes) {
    switch (n.kind) {
      case 'requirement':
        if (activeIn(st, k, 'satisfies', 'ticket').length === 0) add('REQ_NO_TICKET', n, '満たす票のつながりが記録にない');
        if (activeOut(st, k, 'satisfies', 'goal').length === 0) add('REQ_NO_GOAL', n, '目標へのつながりが記録にない');
        break;
      case 'ticket': {
        if (activeOut(st, k, 'satisfies', 'requirement').length === 0) {
          const r = ticketReachesRequirement(st, k, maxVisit);
          if (r === 'no') add('TICKET_NO_REQUIREMENT', n, '要件にたどれない（satisfies・derives・depends_on だけをたどる。retires・incident 経由は数えない）');
          else if (r === 'undetermined') unsure('TICKET_REQUIREMENT_UNDETERMINED', n, `訪れる数の上限（${maxVisit}）で打ち切った。欠けとは言えない`);
        }
        const t = an.ticket(k);
        if (t.state === 'none') add('TICKET_NO_SPEC', n, '仕様の指紋のつながりが記録にない');
        else if (t.state === 'superseded_only') add('TICKET_NO_CURRENT_SPEC', n, '仕様はすべて置き換えられており、現行の仕様の記録がない');
        else if (t.state === 'ambiguous') unsure('TICKET_SPEC_AMBIGUOUS', n, `置き換えの関係のない仕様が ${t.current.length} 個ある。現行の仕様が決まらない`);
        break;
      }
      case 'spec':
        if (an.superseded.has(k)) break; // 置き換えられた仕様は、承認がなくても欠けでない
        if (activeIn(st, k, 'approves', 'approval').length === 0) add('SPEC_NO_APPROVAL', n, '承認の記録のつながりがない（置き換えられていない仕様）');
        if (activeOut(st, k, 'specifies', 'ticket').length === 0) add('SPEC_NO_TICKET', n, 'どの票の仕様かの記録がない');
        break;
      case 'request': {
        const r = an.request(k);
        if (r.ambiguous) { unsure('REQUEST_SPEC_AMBIGUOUS', n, `${r.specs.length} 個の仕様に結び付く。どの仕様への申請か決まらない`); break; }
        if (r.specs.length === 0) add('REQUEST_NO_SPEC', n, 'どの仕様の指紋に対する申請かの記録がない');
        else if (an.superseded.has(r.specs[0])) break; // 置き換えられた仕様への申請は過去のもの
        if (r.audit === 'none') add('REQUEST_NO_AUDIT', n, '決定論的な監査のつながりがない');
        else if (r.audit === 'failed') add('REQUEST_AUDIT_FAILED', n, '最新の監査が failed');
        else if (r.audit === 'not_run') add('REQUEST_AUDIT_NOT_RUN', n, '最新の監査が not_run（未実行は合格ではない）');
        else if (r.audit === 'unknown') add('REQUEST_AUDIT_UNKNOWN', n, '最新の監査の結論を読めない');
        if (r.judgment === 'none') add('REQUEST_NO_VERDICT', n, '司法の判定のつながりがない');
        else if (r.judgment === 'returned') add('REQUEST_CHANGES_REQUIRED', n, '判定の種類のどれかが CHANGES_REQUIRED で、有効なオーナーの裁定がない（裁定で通せるのは judge・codex-judge の不一致だけ。security の不合格・差し戻しより前の裁定・時刻の決まらない裁定は通せない）');
        else if (r.judgment === 'unknown') add('REQUEST_VERDICT_UNKNOWN', n, `判定の結論を読めない種類がある、または必須の種類（${r.missing.join('・') || '—'}）がそろっていない（承認に数えない）`);
        if (r.merges.length === 0) {
          if (unres.has(n.id)) add('REQUEST_MERGE_UNRESOLVED', n, '統合の記録はあるが、統合のコミットの完全な SHA に解決できなかった（Kernel の merged の出来事が12桁しか持たない）');
          else add('REQUEST_NOT_MERGED', n, `統合のつながりがない（${r.judgment === 'returned' ? 'returned_by_verdict' : r.judgment === 'ruled' || r.rulings ? 'ruling_recorded' : 'pending_or_unknown'}。差し戻し・未決・記録漏れは機械では区別しきれない）`);
        } else if (r.judgment === 'returned' || r.judgment === 'unknown' || r.judgment === 'none') add('MERGE_NOT_APPROVED', n, `統合されているが、判定は ${r.judgment}（裁定もない）`);
        break;
      }
      case 'merge':
        if (activeIn(st, k, 'approves', 'acceptance').length === 0) add('MERGE_NO_ACCEPTANCE', n, '受け入れの記録のつながりがない');
        if (activeOut(st, k, 'integrates', 'request').length === 0) add('MERGE_NO_REQUEST', n, 'どの申請を統合したかの記録がない');
        break;
      case 'incident':
        if (activeIn(st, k, 'addresses', 'ticket').length === 0) add('INCIDENT_NO_TICKET', n, '対応する票のつながりがない');
        if ((st.outAdj.get(k) || []).every((i) => st.links[i].retracted || st.links[i].rel !== 'caused_by')) add('INCIDENT_NO_CAUSE', n, '起因する統合・リリース・票の記録がない');
        break;
      default: break;
    }
  }
  const sort = (arr) => arr.sort((a, b) => cmp(a.code, b.code) || cmp(a.kind, b.kind) || cmp(a.id, b.id));
  sort(gaps); sort(und);
  const byCode = {}; for (const g of gaps) byCode[g.code] = (byCode[g.code] || 0) + 1;
  return {
    gaps: gaps.slice(0, maxGaps), count: gaps.length, by_code: Object.fromEntries(Object.entries(byCode).sort(([a], [b]) => cmp(a, b))), truncated: gaps.length > maxGaps,
    undetermined: und.slice(0, maxGaps), undetermined_count: und.length, integrity: integrityOf(st), note: NOT_PROOF_NOTE,
  };
}

// ---- 記録を開く ----

/** 開く側の票の ID の宣言（設定がなければ既定） */
const ticketSpecOf = (cfg) => (cfg && cfg.ticketMatch && cfg.ticketMatch.spec) || DEFAULT_WORK_ITEM;
/** 行に残す設定の写し（tr.v3） */
const cfgCopy = (cfg) => { const t = ticketSpecOf(cfg); return { ticket_id: { prefix: t.prefix, digits: [t.digits[0], t.digits[1]] } }; };

function validConfig(opt) {
  const o = opt || {};
  let maxLinks = DEFAULT_MAX_LINKS;
  if (o.maxLinks !== undefined) { if (!isInt(o.maxLinks, 1, 1e6)) throw new Refused('bad_config', 'maxLinks は 1〜1000000 の安全な整数'); maxLinks = o.maxLinks; }
  // 票の id の形は、決まった形の宣言 { prefix, digits: [最小, 最大] } だけ受ける。正規表現は受けない（線形時間を保証できないため）
  if (o.ticketIdPattern !== undefined) throw new Refused('bad_config', 'ticketIdPattern（正規表現）は受けない。ticketId: { prefix, digits: [最小, 最大] } を使う');
  let ticketMatch = null;
  if (o.ticketId !== undefined) { ticketMatch = ticketMatcher(o.ticketId); if (!ticketMatch) throw new Refused('bad_config', 'ticketId は { prefix: ^[A-Za-z][A-Za-z0-9._-]{0,15}$, digits: [最小, 最大]（各 1〜12） }'); }
  return { maxLinks, ticketMatch, rules: RULES };
}

/**
 * 追跡の記録を開く。
 * @param {string} file 記録のファイル（JSONL）。行政が書けない保護領域に置く前提（未配線）
 * @param {{ now?: () => string, lockWaitMs?: number, maxLinks?: number, ticketId?: { prefix: string, digits: [number, number] } }} [opt]
 */
export function openTrace(file, opt = {}) {
  const config = validConfig(opt);
  const chain = openChain(file, { now: opt.now, lockWaitMs: opt.lockWaitMs });

  // 再生の結果の使い回し（内部の読み取りと書き込みの検査だけ）。鍵は、検証済みの記録の行数と末尾のハッシュ（ハッシュの鎖が全行の中身を結ぶ）。
  // 記録は毎回 chain.read()／追記の中の読み込みで鎖と head を確かめ直す（キャッシュがあっても検査は省かない）。設定は1つの openTrace で固定。
  // 公開の state() は使い回さず毎回作り直す（返した状態を呼び出し側が書き換えても、後の検査に影響しない）
  let cache = null;
  const stateOf = (records) => {
    const key = `${records.length}:${records.length ? records[records.length - 1].hash : 'genesis'}`;
    if (cache && cache.key === key) return cache.st;
    const st = replay(records, config); cache = { key, st }; return st;
  };
  const cachedState = () => stateOf(chain.read());

  // 状態を書く唯一の経路。追記の検査（ロックの中）で今の全行から文脈を作り、全ガードを通す。検査と記録は同じ写し（ctx）を使う
  function guarded(op, actor, input, makeBody) {
    const body = { type: RECORD_TYPE, op };
    const rec = chain.append(body, (records) => {
      const ctx = buildContext({ records, op, actor, input, config, state: op === 'epoch' ? undefined : stateOf(records) });
      const r = check(ctx); // 全ガード（絞らない）
      if (!r.ok) { const e = new Refused('guard_violation', r.violations.map((v) => `${v.guard}: ${v.reason}`).join(' / ')); e.violations = r.violations; throw e; }
      Object.assign(body, { rules: RULES, cfg: cfgCopy(config), actor: normActor(ctx.actor) }, makeBody(ctx, records));
    });
    return rec;
  }
  const state = () => replay(chain.read(), config);
  const addLink = (actor, input) => {
    const rec = guarded('link', actor, input, (ctx) => ({ link: clone(ctx.input) }));
    return deepFreeze({ seq: rec.seq, at: rec.at, ...clone(rec.link), actor: clone(rec.actor) });
  };

  return {
    file,
    /** つながりを1つ足す。入力 { from: {kind,id,digest?}, to, rel, evidence?, note? } */
    link: addLink,
    /** 取り消し（オーナーだけ。理由必須）。行は消さず、取り消しの行を足す */
    retract: (actor, linkSeq, input = {}) => {
      const rec = guarded('retract', actor, (isObj(input) ? { ...input, link_seq: linkSeq } : { link_seq: linkSeq, reason: input }), (ctx) => ({ target_seq: ctx.input.link_seq, reason: ctx.input.reason }));
      return deepFreeze({ seq: rec.seq, at: rec.at, target_seq: rec.target_seq, reason: rec.reason });
    },
    /** オーナーの移行の記録。今ある全行を覆い、古い版の規則で書かれた行を構造の検査だけで受け入れる。理由必須 */
    epoch: (actor, input = {}) => {
      const rec = guarded('epoch', actor, input, (ctx, records) => ({ reason: ctx.input.reason, covers: { count: records.length, last_hash: records.length ? records[records.length - 1].hash : 'genesis' } }));
      return deepFreeze({ seq: rec.seq, at: rec.at, reason: rec.reason, covers: clone(rec.covers) });
    },
    /**
     * 複数のつながりを順に足す（取り込みの結果用）。1件の拒否で止めず、足せたものと拒まれたものを返す。
     * すでにある同じつながり（TR-NO-DUPLICATE）の拒否は、再実行では普通に起きるので duplicates に分ける
     */
    linkMany: (actor, inputs) => {
      const added = []; const duplicates = []; const refused = [];
      if (!Array.isArray(inputs)) throw new Refused('bad_input', 'inputs が配列でない');
      inputs.forEach((inp, index) => {
        try { added.push(addLink(actor, inp).seq); } catch (e) {
          if (!(e instanceof Refused)) throw e;
          const gs = (e.violations || []).map((v) => v.guard);
          if (gs.length === 1 && gs[0] === 'TR-NO-DUPLICATE') duplicates.push(index); else refused.push({ index, code: e.code, reason: e.message.slice(0, 300) });
        }
      });
      return { added, duplicates, refused };
    },
    state,
    trace: (ref, o) => traceOf(cachedState(), ref, o, config),
    coverage: (o) => coverageOf(cachedState(), o, config),
    gaps: (o) => gapsOf(cachedState(), o, config),
    /** 鎖と、各行の再生の結果。rejected_rows があれば ok: false（行は状態に入っていない） */
    verify: () => {
      const v = chain.verify(); if (!v.ok) return v;
      const st = cachedState();
      return { ok: st.meta.rejected.length === 0, chain: v, count: v.count, links: st.links.length, active_links: st.active.size, epochs: st.epochs.length, rejected_rows: st.meta.rejected.slice(0, 100), rejected_count: st.meta.rejected.length, legacy_uncovered: st.meta.uncoveredLegacy };
    },
    /** 状態を書かずに文脈を作る（bench・事前確認用）。鎖が壊れていれば chain.ok=false の文脈を返す */
    contextFor: (op, actor, input) => {
      let records = []; let ch = { ok: true };
      try { records = chain.read(); } catch (e) { if (!(e instanceof Refused)) throw e; ch = { ok: false, code: e.code, detail: e.detail }; }
      return buildContext({ records, chain: ch, op, actor, input, config, state: ch.ok ? stateOf(records) : undefined });
    },
  };
}

// ---- Kernel の記録からの取り込み（純関数。ファイルを開かない。Kernel は変えない） ----
//
// 引数は、Z3 の各記録を1行ずつ JSON として読んだ配列（呼び出し側が読む）。各記録の欄は、次のスクリプトを読んで確かめた：
//   approvals（spec_approvals.jsonl）：vgdd/scripts/approve-spec.sh:37-38
//       { schema:"vgdd.spec-approval.v1", ts, task:"T-NNN", ticket, ref, digest:"sha256:…", policy_line, approved_by:"owner", note }
//   held（held.jsonl）：vgdd/scripts/gate-runner.sh:377-379
//       { ts, task, request:<40桁>, candidate:<40桁>, main_at_check, judge, codex, security, no_codex, route, majors, security_required, law:"p0.4.3" }
//       held に仕様の指紋はない（→ 申請→仕様は直前の承認からの推定。evidence.basis に残す）
//   gateEvents（gate_events.jsonl）：vgdd/scripts/gate-runner.sh:72-74（{ts,type,task,…}）、type:"merged" は gate-runner.sh:404
//       { main:<12桁>, judge, codex } と release.sh:111 { main:<12桁>, via:"release", candidate:<12桁> }。統合のコミットは12桁しかない
//       （→ 完全な SHA は、受け入れの記録の merge（40桁）と照合して前方一致で1つに決まるときだけ解決する。決まらなければ取り込めなかった）
//   verdicts（evidence/verdicts/ のファイル。{ name, content }）：名前は judge.sh:208 の ${TASK}-${HEAD_SHA}.json、judge-codex.sh:109 の
//       ${TASK}-${HEAD_SHA}-codex-${MODE}.json（HEAD_SHA は先頭12桁。judge.sh:66）。中身は judge.sh:248-262 { type:"verdict", task_id, head,
//       judge_parse_ok, deterministic_audits:"passed"|"failed"|"not_run", final_verdict }、judge-codex.sh:136-150 { type:"verdict", judge:"codex",
//       mode, task_id, head, parse_ok, final_verdict }。head は判定した候補（held.candidate）の先頭12桁で、held.candidate と照合して申請に結ぶ
//   rulings（rulings.jsonl）：vgdd/scripts/rule.sh:11 { ts, task, sha:<申請の40桁>, decision:"merge", reason, by:"owner" }
//   acceptance（acceptance.jsonl）：vgdd/scripts/owner-console.mjs:309 { ts, task, merge:<統合のコミットの40桁>, action_id }。
//       統合のコミットは owner-console.mjs:107-112（git log の %H）。受け入れは申告の記録で、確かめた中身は保証しない（architecture §6 の表）
//   tickets：main の票の front matter から取った { id, requirements:[..], depends_on:[..] }（spec-digest.mjs:63-77 の list の読み方）
// checkpoints.jsonl（gate-runner.sh:503）は鎖の切り詰めの検出用で、つながりを持たないので読まない。

const SHA40 = { test: isGitSha }; // Kernel の記録は Git の SHA（40桁）
const HEX12 = /^[0-9a-f]{12}$/;
const STATELESS = ['TR-INPUT-SHAPE', 'TR-KIND-ALLOWLIST', 'TR-ID-FORMAT', 'TR-REL-ALLOWLIST', 'TR-REL-KIND-PAIR', 'TR-NO-SELF'];
const VERDICT_NAME = /^(.{1,64})-([0-9a-f]{12})(?:-codex-(judge|security|ux))?\.json$/; // 票の部分は、あとで ticketId の宣言で確かめる
const IMPORT_MAX_ROWS = 200000;

/**
 * Kernel の記録の行から、つながりの入力の配列を作る。形の合わない行は捨てずに skipped として理由つきで返す。
 * 返すつながりは、状態に依らない検査（書式・表・自己）を通している。重複・循環・指紋の食い違いは追記の時に確かめる。
 * 判定・監査の節の id には内容の指紋の先頭8桁を含める（再判定でファイルが上書きされて指紋が変わっても、別の節になり取り込みが詰まらない）。
 * 統合の記録はあるが完全な SHA に解決できなかったものは、skipped でなく unresolved_merges に分けて返す（gaps の unresolvedMergeRequests に渡せる）。
 * @param {{ approvals?: object[], held?: object[], gateEvents?: object[], verdicts?: {name:string, content:object}[], rulings?: object[], acceptance?: object[], tickets?: {id:string, requirements?:string[], depends_on?:string[]}[] }} ev
 * @param {{ ticketId?: {prefix:string, digits:[number,number]}, shaIndex?: Map<string,string>|Object<string,string> }} [opt]
 *   shaIndex：短い SHA（12桁の接頭辞）→ 完全な SHA の対応表。呼び出し側が git から作って渡す（この部品は git を呼ばない）。
 *   受け入れの記録から決まる値と食い違えば、解決しない（厳しい側）。
 * @returns {{ links: object[], skipped: {source:string, index:number, reason:string, excerpt:string}[], unresolved_merges: object[], notes: string[], ignored: {gate_events: Object<string,number>} }}
 */
export function linksFromEvidence(ev, opt = {}) {
  const e = isObj(ev) ? ev : {};
  const o = isObj(opt) ? opt : {};
  const cfg = validConfig({ ticketId: o.ticketId });
  const links = []; const skipped = []; const unresolved = []; const notes = []; const seenKeys = new Set(); const ignoredEvents = Object.create(null);
  const excerpt = (v) => { try { return canonical(v).slice(0, 300); } catch { return String(typeof v).slice(0, 40); } };
  const skip = (source, index, reason, row) => skipped.push({ source, index, reason, excerpt: excerpt(row) });
  const arr = (name) => {
    const v = e[name];
    if (v === undefined) return [];
    if (!Array.isArray(v)) { skip(name, -1, '配列でない', v); return []; }
    if (v.length > IMPORT_MAX_ROWS) { skip(name, -1, `行が多すぎる（${IMPORT_MAX_ROWS} まで）`, null); return []; }
    return v;
  };
  const sane = (text) => { const t = String(text).replace(/[\p{Cc}\p{Cf}\u2028\u2029]+/gu, ' ').trim().slice(0, MAX_NOTE); return t.length ? t : undefined; };
  const stateless = { op: 'link', actor: null, state: newState(), chain: { ok: true }, config: cfg };
  /** つながりを足す。状態に依らない検査を通らなければ skipped。同じ鍵は1回だけ */
  const emit = (source, index, from, to, rel, evidence, row, note) => {
    const input = { from, to, rel, ...(evidence ? { evidence } : {}), ...(note ? { note } : {}) };
    const r = check({ ...stateless, input: snapshot(input) }, STATELESS);
    if (!r.ok) { skip(source, index, r.violations.map((v) => `${v.guard}: ${v.reason}`).join(' / '), row); return false; }
    const k = linkKey(rel, from, to);
    if (!seenKeys.has(k)) { seenKeys.add(k); links.push(input); }
    return true;
  };
  const dig = (row) => { try { return digest(row); } catch { return null; } };

  // Kernel の記録の時刻（date +%z の +0900）は、vocab の形（+09:00）に写してから読む・書く（kernelTsToIso）
  const kts = (x) => kernelTsToIso(x);
  const kms = (x) => { const t = kernelTsToIso(x); return t === null ? null : parseTs(t); };
  const approvals = arr('approvals'); const held = arr('held'); const events = arr('gateEvents'); const verdicts = arr('verdicts');
  const rulings = arr('rulings'); const acceptance = arr('acceptance'); const tickets = arr('tickets');

  // 短い SHA の解決用の表（12桁の接頭辞 → 完全な SHA の集合。1つに決まるときだけ使う）
  const addTo = (m, p, v) => (m.get(p) || m.set(p, new Set()).get(p)).add(v);
  const uniq = (m, p) => { const x = m.get(p); return x && x.size === 1 ? [...x][0] : null; };
  const mergeFull = new Map();
  for (const a of acceptance) if (isObj(a) && typeof a.merge === 'string' && SHA40.test(a.merge)) addTo(mergeFull, a.merge.slice(0, 12), a.merge);
  // 呼び出し側の対応表（git から作る）。形を確かめ、12桁の接頭辞で引く
  if (o.shaIndex !== undefined) {
    const entries = o.shaIndex instanceof Map ? [...o.shaIndex] : isObj(o.shaIndex) ? Object.entries(o.shaIndex) : null;
    if (!entries || entries.length > 100000) skip('shaIndex', -1, 'Map か { 接頭辞: 完全な SHA } のオブジェクトでない・大きすぎる', null);
    else entries.forEach(([k, v], i) => {
      if (typeof k !== 'string' || typeof v !== 'string' || !SHA40.test(v) || !/^[0-9a-f]{7,40}$/.test(k) || !v.startsWith(k)) { skip('shaIndex', i, '接頭辞と完全な SHA（40桁）の組として読めない', { k: String(k).slice(0, 20) }); return; }
      if (k.length >= 12) addTo(mergeFull, k.slice(0, 12), v);
    });
  }
  if (o.shaIndex !== undefined) notes.push('shaIndex は呼び出し側の申告で、この部品は確かめられない（git を呼ばない）。受け入れの記録と食い違う場合だけ解決しないが、受け入れの記録がなければ、偽の対応表で統合の SHA が決まりうる。');
  const reqByTask = new Map(); // 票 → (12桁の接頭辞 → 申請の SHA の集合)。別の票の判定が結び付かないよう、票ごとに持つ
  const noteReq = (task, sha) => { if (typeof task === 'string' && typeof sha === 'string' && SHA40.test(sha)) addTo(reqByTask.get(task) || reqByTask.set(task, new Map()).get(task), sha.slice(0, 12), sha); };

  // 1 承認：spec -specifies-> ticket、approval -approves-> spec
  const approvalsByTask = new Map();
  approvals.forEach((r, i) => {
    if (!isObj(r) || r.schema !== 'vgdd.spec-approval.v1') return skip('approvals', i, '知らない schema（vgdd.spec-approval.v1 でない）', r);
    if (r.approved_by !== 'owner') return skip('approvals', i, 'approved_by が owner でない', r);
    const ms = kms(r.ts);
    if (typeof r.task !== 'string' || typeof r.digest !== 'string' || ms === null) return skip('approvals', i, 'task・digest・ts のどれかが文字列・時刻として読めない', r);
    const ad = dig(r); if (!ad) return skip('approvals', i, '正規形にできない', r);
    const spec = { kind: 'spec', id: r.digest, digest: r.digest }; const ticket = { kind: 'ticket', id: r.task };
    const evd = { source: 'spec_approvals.jsonl', at: kts(r.ts), ...(isPolicyLine(r.policy_line) ? { policy_line: r.policy_line } : {}) };
    if (!emit('approvals', i, spec, ticket, 'specifies', { source: 'spec_approvals.jsonl', at: kts(r.ts) }, r)) return undefined;
    if (!emit('approvals', i, { kind: 'approval', id: ad, digest: ad }, spec, 'approves', evd, r, r.note === undefined || r.note === '' ? undefined : sane(r.note))) return undefined;
    (approvalsByTask.get(r.task) || approvalsByTask.set(r.task, []).get(r.task)).push({ ms, i, digest: r.digest, ts: kts(r.ts) });
    return undefined;
  });

  // 1b 仕様の変更と承認し直し：同じ票の承認を時刻の順に並べ、仕様の指紋が変わったら、新しい仕様が古い仕様を置き換える（spec -supersedes-> spec）。
  //    同じ指紋の承認し直しは出さない。時刻が決まらない（同時刻で指紋が違う）・以前の指紋に戻った承認は、出さずに skipped に理由を返す（未確定のまま）
  for (const [task, list] of approvalsByTask) {
    const ord = [...list].sort((a, b) => a.ms - b.ms || a.i - b.i);
    let cur = ord[0].digest; const seenD = new Set([cur]); let unknown = false;
    for (let k = 1; k < ord.length; k += 1) {
      const a = ord[k];
      const tie = ord.some((x, j) => j !== k && x.ms === a.ms && x.digest !== a.digest);
      if (tie) { skip('approvals', a.i, `同時刻の承認で指紋が違う（${task}）。新旧を決められないので置き換えは出さない`, { task, ts: a.ms }); unknown = true; continue; }
      if (unknown) { skip('approvals', a.i, `直前の仕様の指紋が決まっていない（${task}）。置き換えは出さない`, { task }); continue; }
      if (a.digest === cur) continue;
      if (seenD.has(a.digest)) { skip('approvals', a.i, `以前の仕様の指紋に戻った承認（${task}）。置き換えの向きを決められないので出さない`, { task }); unknown = true; continue; }
      emit('approvals', a.i, { kind: 'spec', id: a.digest, digest: a.digest }, { kind: 'spec', id: cur, digest: cur }, 'supersedes', { source: 'spec_approvals.jsonl', at: a.ts, basis: 'approval_order' }, { task, digest: a.digest });
      seenD.add(a.digest); cur = a.digest;
    }
  }

  // 2 held：申請 -implements-> 仕様（直前の承認からの推定）。候補（40桁）→ 申請の対応も持つ。
  //   同じ申請が再び held になると、別の承認を挟んで2つの仕様に結び付きうる（coverage・gaps は未確定として扱う）
  const heldByCand = new Map();
  held.forEach((r, i) => {
    if (!isObj(r) || typeof r.task !== 'string' || typeof r.request !== 'string' || !SHA40.test(r.request) || typeof r.candidate !== 'string' || !SHA40.test(r.candidate)) return skip('held', i, 'task・request・candidate（40桁）が読めない', r);
    const ms = kms(r.ts); if (ms === null) return skip('held', i, 'ts が読めない', r);
    noteReq(r.task, r.request);
    const key = r.candidate.slice(0, 12);
    (heldByCand.get(key) || heldByCand.set(key, []).get(key)).push({ task: r.task, request: r.request, i });
    const cands = (approvalsByTask.get(r.task) || []).filter((a) => a.ms <= ms).sort((a, b) => a.ms - b.ms || a.i - b.i);
    if (!cands.length) return skip('held', i, '申請の仕様の指紋を決められない（その票の、申請より前の承認の記録がない）。申請→仕様のつながりは作らない', r);
    const a = cands[cands.length - 1];
    // 必須の判定の種類の手がかり（held の no_codex・security_required。gate-runner.sh:377-379、release.sh:48-56 の条件）。boolean のときだけ残す
    const req = typeof r.no_codex === 'boolean' && typeof r.security_required === 'boolean' ? { no_codex: r.no_codex, security_required: r.security_required } : {};
    return emit('held', i, { kind: 'request', id: r.request }, { kind: 'spec', id: a.digest, digest: a.digest }, 'implements', { source: 'held.jsonl', basis: 'latest_approval_before_held', ...req }, r);
  });
  /** 票と12桁の接頭辞から申請の SHA を決める。同じ票の held の候補、なければ同じ票の申請・裁定の SHA（どちらも1つに決まるときだけ） */
  const resolveRequest = (task, p) => {
    const hs = (heldByCand.get(p) || []).filter((h) => h.task === task); const rs = new Set(hs.map((h) => h.request));
    if (rs.size === 1) return [...rs][0];
    if (rs.size > 1) return null;
    const m = reqByTask.get(task); return m ? uniq(m, p) : null;
  };

  // 3 裁定：ruling -approves-> request
  rulings.forEach((r, i) => {
    if (!isObj(r) || r.by !== 'owner' || r.decision !== 'merge' || typeof r.sha !== 'string' || !SHA40.test(r.sha) || typeof r.task !== 'string' || kms(r.ts) === null) return skip('rulings', i, 'by:owner・decision:merge・sha（40桁）・task・ts のどれかが合わない', r);
    const d = dig(r); if (!d) return skip('rulings', i, '正規形にできない', r);
    noteReq(r.task, r.sha);
    return emit('rulings', i, { kind: 'ruling', id: `RUL-${d.slice(7, 23)}`, digest: d }, { kind: 'request', id: r.sha }, 'approves', { source: 'rulings.jsonl', at: kts(r.ts), result: 'merge' }, r, typeof r.reason === 'string' ? sane(r.reason) : undefined);
  });

  // 4 判定の記録のファイル：verdict -verifies-> request、audit -verifies-> request
  verdicts.forEach((v, i) => {
    if (!isObj(v) || typeof v.name !== 'string' || !isObj(v.content)) return skip('verdicts', i, '{ name, content } の形でない', v);
    const m = v.name.length <= 128 ? VERDICT_NAME.exec(v.name) : null; if (!m || !idOk('ticket', m[1], cfg)) return skip('verdicts', i, 'ファイル名が <票>-<12桁>[-codex-<mode>].json でない（票は ticketId の宣言に合う id）', { name: String(v.name).slice(0, 80) });
    const [, task, head, cmode] = m; const c = v.content; const mode = cmode ? `codex-${cmode}` : 'judge';
    const parseOk = mode === 'judge' ? c.judge_parse_ok : c.parse_ok;
    if (c.type !== 'verdict' || c.task_id !== task || c.head !== head) return skip('verdicts', i, '中身の type・task_id・head がファイル名と合わない', { name: v.name });
    if (parseOk !== true) return skip('verdicts', i, '司法として成り立っていない（parse が true でない）。判定として取り込まない', { name: v.name });
    if (c.final_verdict !== 'APPROVED' && c.final_verdict !== 'CHANGES_REQUIRED') return skip('verdicts', i, 'final_verdict が APPROVED・CHANGES_REQUIRED でない', { name: v.name });
    const req = resolveRequest(task, head);
    if (!req) return skip('verdicts', i, '申請の完全な SHA を決められない（同じ票の held の candidate・申請と前方一致しない、または複数ある）', { name: v.name });
    const vd = dig(c); if (!vd) return skip('verdicts', i, '正規形にできない', { name: v.name });
    const base = { source: `verdicts/${v.name}`.slice(0, MAX_STR), mode, ...(kms(c.collected_at) !== null ? { at: kts(c.collected_at) } : {}) }; // 最新の結論を決める時刻（なければ厳しい側）
    if (!emit('verdicts', i, { kind: 'verdict', id: `VRD-${head}-${mode}-${vd.slice(7, 15)}`, digest: vd }, { kind: 'request', id: req }, 'verifies', { ...base, result: c.final_verdict }, { name: v.name })) return undefined;
    if (mode === 'judge' && ['passed', 'failed', 'not_run'].includes(c.deterministic_audits)) {
      const ad = dig({ audit: c.deterministic_audits, verdict_file: vd });
      return emit('verdicts', i, { kind: 'audit', id: `AUD-${head}-${ad.slice(7, 15)}`, digest: ad }, { kind: 'request', id: req }, 'verifies', { ...base, result: c.deterministic_audits }, { name: v.name });
    }
    return undefined;
  });

  // 5 統合（gate_events の type: merged）：merge -integrates-> request。他の type は数えるだけ（つながりを持たない）
  events.forEach((r, i) => {
    if (!isObj(r) || typeof r.type !== 'string') return skip('gateEvents', i, 'type が読めない', r);
    if (r.type !== 'merged') { ignoredEvents[r.type.slice(0, 40)] = (ignoredEvents[r.type.slice(0, 40)] || 0) + 1; return undefined; }
    if (typeof r.task !== 'string' || typeof r.main !== 'string' || kms(r.ts) === null) return skip('gateEvents', i, 'merged の task・main・ts が読めない', r);
    const key = typeof r.candidate === 'string' && HEX12.test(r.candidate) ? r.candidate : r.main.slice(0, 12); // release は candidate、gate-runner の直接の統合は main が候補と同じ
    const req = resolveRequest(r.task, key);
    const mainFull = SHA40.test(r.main) ? r.main : (HEX12.test(r.main) ? uniq(mergeFull, r.main) : null);
    if (!mainFull || !req) {
      // 統合の記録はある。完全な SHA に解決できないだけ（Kernel の merged の出来事が12桁しか持たない）。欠けや未統合とは区別して返す
      unresolved.push({ task: r.task.slice(0, 40), main: String(r.main).slice(0, 40), candidate: typeof r.candidate === 'string' ? r.candidate.slice(0, 40) : null, request: req, ts: r.ts, index: i,
        reason: !mainFull ? '統合のコミットの完全な SHA を決められない（12桁だけ。受け入れの記録・shaIndex から1つに決まらない）' : '申請の完全な SHA を決められない' });
      return undefined;
    }
    return emit('gateEvents', i, { kind: 'merge', id: mainFull }, { kind: 'request', id: req }, 'integrates', { source: 'gate_events.jsonl', at: kts(r.ts), via: r.via === 'release' ? 'release' : 'gate_runner' }, r);
  });

  // 6 受け入れ：acceptance -approves-> merge
  acceptance.forEach((r, i) => {
    if (!isObj(r) || typeof r.merge !== 'string' || !SHA40.test(r.merge) || typeof r.task !== 'string' || kms(r.ts) === null) return skip('acceptance', i, 'merge（40桁）・task・ts が読めない', r);
    const d = dig(r); if (!d) return skip('acceptance', i, '正規形にできない', r);
    return emit('acceptance', i, { kind: 'acceptance', id: `ACC-${d.slice(7, 23)}`, digest: d }, { kind: 'merge', id: r.merge }, 'approves', { source: 'acceptance.jsonl', at: kts(r.ts) }, r);
  });

  // 7 票：ticket -satisfies-> requirement、ticket -depends_on-> ticket
  tickets.forEach((t, i) => {
    if (!isObj(t) || typeof t.id !== 'string') return skip('tickets', i, '{ id, requirements, depends_on } の形でない', t);
    for (const [field, kind, rel] of [['requirements', 'requirement', 'satisfies'], ['depends_on', 'ticket', 'depends_on']]) {
      const list = t[field];
      if (list === undefined) continue;
      if (!Array.isArray(list)) { skip('tickets', i, `${field} が配列でない`, t); continue; }
      for (const id of list) {
        if (typeof id !== 'string') { skip('tickets', i, `${field} の要素が文字列でない`, { ticket: t.id, [field]: typeof id }); continue; } // String(id) は呼ばない（toString が投げうる）
        emit('tickets', i, { kind: 'ticket', id: t.id }, { kind, id }, rel, { source: 'ticket_front_matter' }, { ticket: t.id, [field]: id.slice(0, 40) });
      }
    }
  });

  return { links, skipped, unresolved_merges: unresolved, notes, ignored: { gate_events: Object.fromEntries(Object.entries(ignoredEvents).sort(([a], [b]) => cmp(a, b))) } };
}
