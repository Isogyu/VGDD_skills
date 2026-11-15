# VGDD の体制と統合の条件（governance）

- 位置づけ：役割ごとの体制、1 つの仕事（票）の流れ、main に統合する条件、worktree の扱いを説明する。最初は本稼働の前の設計案として書いたものを、今の仕組みを説明する文書に書き直した。
- 規範は [`vgdd/kernel/SPEC.md`](../vgdd/kernel/SPEC.md)。実装は `vgdd/scripts/` と `vgdd/hooks/`、実装の対応は [`kernel.md`](kernel.md)。この文書と SPEC が食い違えば、SPEC を正とする。SPEC と重なる部分は、SPEC の節への案内にとどめる。
- 夜間の運転は [`harness.md`](harness.md) にある。
- `D-47`、`OBS-013` のような番号は、最初の導入先の記録の番号である。元の記録はこのリポジトリにない（[`kernel.md`](kernel.md) の冒頭に断りがある）。
- 既定の名前（保護領域 `~/tsubuyaki-z3`）は、開発のときの配置の名前である。今の実装の既定の値なので、そのまま書いている。配布の前に変える予定である（[`adoption.md`](adoption.md) §2）。

## 1. 役割と実体

役割の識別と権限の全体は、SPEC §2 と [`vgdd/kernel/capabilities.json`](../vgdd/kernel/capabilities.json) にある。ここでは、実体と持てる権限を一覧にする。

| 役割 | 実体 | 持てる権限 | 出力 |
|---|---|---|---|
| オーナー（主権者） | 人 | すべて。法律（`.claude/`・`CLAUDE.md`・`vgdd/`）と Z3 を書ける唯一の主体。仕様の承認、裁定、停止と再開、朝の統合の承認 | 制定・改正、承認、裁定 |
| 立法補佐 | 別のアカウントの Claude | 法律と仕様の起草。効力は持たない。リポジトリのソースは読むだけ | 法案、改正案、点検の指摘 |
| 行政の長 | 開発エージェントの本体のセッション（フック入力の `agent_type` が空、cwd が main の checkout） | 票の起草、作業員の起動の申請、統合の申請。保護パスは書けない。`npm install`・push・`rm` は確認が要る。**merge と gate-runner は使えない**。main に直接コミットできるのは `docs/` の下だけ（SPEC §7-1） | 票、起動の申請（`merge-requests/launch/`）、統合の申請（`merge-requests/T-NNN.json`） |
| 作業員（worker） | [`vgdd/agents/worker.md`](../vgdd/agents/worker.md)。`isolation: worktree` | 自分の worktree の中だけを書く。Agent ツールは使えない。保護パスと `.env.local` は不可 | 票のブランチへのコミットと報告 |
| テスト担当（tester） | [`vgdd/agents/tester.md`](../vgdd/agents/tester.md)。`isolation: worktree` | 作業員と同じ。ただしテストのファイルだけを書く（票の `files_allowed`） | テストのコミットと報告 |
| 司法（judge） | [`vgdd/agents/judge.md`](../vgdd/agents/judge.md) と `vgdd/scripts/judge.sh` | **ツールなし**。差分、main の票の受け入れ条件、監査の結果だけを見る | `vgdd.verdict.v1` の JSON |
| 司法・別系統（Codex judge） | `vgdd/scripts/judge-codex.sh`。`codex exec`（読み取り専用の sandbox） | judge と同じ入力 | 同じスキーマの JSON |
| 司法・セキュリティ審査 | `judge-codex.sh --security` | 同上。観点を足す | 指摘（重さ、ファイル、行） |
| 司法・憲法審査 | [`vgdd/agents/constitutional-review.md`](../vgdd/agents/constitutional-review.md) と `vgdd/scripts/review-constitution.sh` | ツールなし。法律の改正の差分だけを見る | 「反しない」または「反する（どの約束に、どの行が）」 |
| 決定論的な監査 | gate-runner の中のスクリプト | テスト、型検査、lint、差分の検査、秘密情報の検査 | 合否と出力の末尾 |
| 裁判所の執行（gate-runner） | `vgdd/scripts/gate-runner.sh` | **オーナーの権限で、sandbox の外**。Z3 に書ける。main に統合できる主体の 1 つ（もう 1 つは朝の release） | 判定（Z3）、統合、票の更新 |
| 夜間の代行（night-runner） | `vgdd/scripts/night-runner.sh` | オーナーの権限で、sandbox の外。承認済みのキューを読み、作業員を無人で起動し、票の status と記録だけを main にコミットし、申請を置く。**実装しない、判定しない、merge しない** | worktree とブランチ、申請、一晩の要約 |
| 書記（朝刊） | `vgdd/scripts/morning-report.mjs` | ツールなし。**決めない**。入力は Z3 の集計だけ | 朝刊（`night/reports/<日付>.md`） |

AI のモデルは、各エージェントの定義（`vgdd/agents/`）と起動の引数で決める。worker と tester は `opus`、judge と constitutional-review は `sonnet` である。Codex の費用と利用枠は、オーナーの契約による。

実装の役割の識別に、git の作者名は使わない（SPEC §2）。

### 1.1 裁判所を別のプロセスにする理由

行政は sandbox の中で動き、Z3 に書けない。判定を行政が書ける場所に置くと、行政が判定と集計の数字を書き換えられる。そのため、gate-runner をオーナーの権限で sandbox の外に置く。判定は Z3 に残り、統合も行政の手を離れる。行政ができるのは、申請を置くことだけである。

## 2. 票の流れ

票は、仕事の単位である。形式は、導入先の `docs/tasks/README.md` にある（このリポジトリにはない）。front matter には、`id`・`status`・`requirements`・`files_allowed`・`files_forbidden`・`time_limit_min`・`branch`・`worker` などを置く。本文には目的、受け入れ条件、確かめ方、記録（§6）を置く。仕様と指紋の定義は SPEC §4、票の状態は SPEC §5 にある。

```
① 行政の長（または立法補佐）：票を起草する。files_allowed が重ならないように分ける
② オーナー：仕様の指紋を承認する（approve-spec.sh）。承認の記録は Z3 にあり、行政は書けない
③ 行政の長：起動の申請（merge-requests/launch/T-NNN.json）を置く。窓口（launcher.sh）が受け付けて、
   夜間の代行（night-runner.sh --launch）が作業員を 1 票ずつ起動する（SPEC §5）
④ 作業員：自分の worktree のブランチで実装し、テスト、型検査、lint を通してコミットし、報告する。
   files_allowed の外は触らない。time_limit_min を超えたら止めて報告する
⑤ 票を review にして、統合の申請（merge-requests/T-NNN.json）を置く
⑥ gate-runner：申請を拾い、§3 の条件で検査する。合格なら main に統合する。
   不合格なら票を in_progress に戻し、指摘を票の記録に残す。差し戻しは 3 回まで
⑦ オーナー：blocked の裁定、夜間の合格（held）の統合の承認、受け入れ
```

行政の長が作業員を起動する経路は、窓口だけである。Agent ツールでの起動は、どの役割からもフックが拒否する（SPEC §5）。

作業員の起動は、予算の台帳の窓口（`metered.sh`）を通る。上限はオーナーが `budget-set.sh` で置く（SPEC §9）。

## 3. 統合の条件

gate-runner は、次の順に検査する。1 つでも落ちれば統合しない。順序の正本は `vgdd/scripts/gate-runner.sh` の頭書きと SPEC §4・§6・§7 である。

1. **申請と票の整合**：票が `status: review` で、ブランチの HEAD が申請の SHA と一致する。main の票の仕様の指紋に、オーナーの承認の記録がある（なければ、司法を呼ぶ前に `blocked`）。Kernel の停止中は、申請を処理しない（SPEC §4・§8）。
2. **統合キュー**：ブランチが main を含まなければ、一時 worktree で「最新の main に申請の SHA を merge した候補」を作る。衝突すれば `needs_rebase` で差し戻す。以後の検査と判定は、候補に対して行う。票を鎖で積まなくてよく、前の票が止まっても後ろの票は止まらない。
3. **差分の範囲**：差分が票の `files_allowed` の中だけである。保護パス（`.claude/`・`CLAUDE.md`・`.github/`・`vgdd/`・`docs/governance/`・`docs/tasks/_board.json`・`merge-requests/` など）が含まれていれば拒否する。
4. **秘密情報**：差分に秘密情報らしい文字列や実名の形がない。
5. **決定論的な監査**：一時 worktree で `npm ci`、`npm test`、`npm run typecheck`、`npm run lint`（sandbox の中）。監査の不合格や未実行は、司法の合格で取り消せない（SPEC §6-3）。
6. **司法（judge）**、7. **別系統の司法（Codex judge）**。
8. **不一致の扱い**：重大な指摘（critical・major）で 2 つの判定が分かれたときだけ `blocked` にして、オーナーの裁定を待つ。裁定は票と申請の SHA に結び付く（`rule.sh`）。軽い指摘（minor）だけの違いなら、厳しい側の指摘を票の記録に残して進む。
9. **セキュリティ審査**：票が `security_review: true` なら、`judge-codex.sh --security` も APPROVED であること。
10. **統合**：検査した候補のコミットを、main で `git merge --ff-only` する。票の `status: merged` と記録をコミットし、申請を `merge-requests/done/` に移し、票の盤を更新する。1 件統合するたびに、残りの申請は次の周回で、最新の main と組み合わせて検査し直す。

司法が使えないこと（判定のファイルがない、壊れている、CLI の空の応答、認証切れなど）は、判定ではない。統合せず、差し戻しにも数えず、申請を残す。同じ申請の SHA で通算 3 回になれば `blocked` にする（SPEC §6-5）。裁判所は起動時に、監査と司法の道具がそろっているか確かめ、欠けていれば起動しない（SPEC §6-6）。

差し戻しの上限は 3 回である。上限に達した票の申請は、司法を呼ばずに `blocked` にする。回数は、票の記録の行と Z3 の裁判所の出来事の多い方で数える（SPEC §5）。

### 3.1 司法の入力

司法の入力は、gate-runner が機械的に集めた差分、main の票の受け入れ条件（または要件の行）、決定論的な監査の結果だけである。行政の説明（コミットの本文、報告、会話）は入れない（SPEC §6-1）。Codex judge は、同じ入力の組み立てを使う。judge と Codex judge は、Claude と Codex の別系統のモデルである。

Codex は次の形で呼ぶ（非対話、読み取り専用、記録を残さない）。

```bash
printf '%s' "$INPUT" | codex exec - \
  --output-schema vgdd/schemas/verdict.schema.json \
  -o "$OUT_FILE" --ephemeral --skip-git-repo-check
```

セキュリティ審査は、票の `security_review: true` で追加する。観点は、入力の検証、認可、秘密情報の扱い、依存の脆弱性である。憲法審査は、法律の改正のときだけ、オーナーが `review-constitution.sh` で実行する。承認の前段にあたる。

### 3.2 エージェントが main に統合できないことの強制

| 層 | 仕組み |
|---|---|
| 権限ルール | `Bash(git merge *)`・`Bash(gh pr merge *)`・`git push` の強制の形は deny。`git push` は確認が要る |
| フック | Bash の `git merge`・`git rebase` を main 上で実行する形、main への切り替えに続く書き込み、`git branch -f main`・`git update-ref refs/heads/main` を拒否する。行政の長の main へのコミットは `docs/` の下だけ |
| 隔離 | 作業員の worktree から main の checkout への Edit・Write や `git -C` は、Claude Code の isolation が拒否する |
| sandbox | main の `.git` は共有なので、git 自体は動く。参照の更新は、フックと権限で止める |
| 事後検知 | gate-runner は周回ごとに main の HEAD を前回と比べる。作者が `gate-runner` 以外のコミットで main が進んでいれば、`main_advanced_outside_gate` を Z3 に記録する（違反の検知であり、防ぐのは上の層である）。夜間の代行は、この記録のうち、自分の作者名（`night-runner`）のものだけを、止める理由にしない（[`harness.md`](harness.md) §5） |

限界：Bash の判定は文字列の照合なので、回避の余地が残る。main の保護は、フック、権限、事後検知を重ねたもので、OS が保証するものではない（SPEC §12）。

## 4. worktree の扱い

作業員は、Claude Code の worktree isolation（`isolation: worktree`）で、`.claude/worktrees/<name>/` に作業ツリーを持つ。公式の文書で確かめた挙動と、それに合わせた設定は次のとおりである。

- **フックはサブエージェントにも効く。** PreToolUse フックはサブエージェントの呼び出しごとに動き、フック入力の `agent_type` に名前が入る。
- **置き場所と保護の両立。** `.claude/worktrees/` は `.claude/` の下にあるため、`.claude/` 全体を保護すると、作業員が自分の worktree に書けない。そこで、フックは「`.claude/` はすべて保護、`.claude/worktrees/` だけ例外、例外の中の `.claude/` のコピーと `CLAUDE.md`・`.github/`・`vgdd/` などは保護」とする。権限ルールと sandbox の `denyWrite` は、`.claude/` の中の具体名（`settings.json`・`settings.local.json`・`agents`・`skills`・`hooks`・`commands`・`output-styles`・`rules`）に絞る。具体的な一覧は [`vgdd/settings.v2.json`](../vgdd/settings.v2.json) にある。この方式は、迂回の検証 V7 で、最初の方式（`.claude/` 全体の保護）では作業員が worktree に書けないことが分かって採った（[`vgdd-status.md`](vgdd-status.md) §2b）。
- **基点。** `worktree.baseRef` は `"head"` にする。既定の `"fresh"` は origin の既定のブランチから分岐するため、push していないコミットが worktree に入らない。
- **worktree の設定のコピー。** worktree の中の `.claude/settings.json` はリポジトリのコピーで、サブエージェントは設定を main の checkout から読むため効かない。ただし、統合すると main の設定が変わるので、gate-runner は差分に `.claude/**` が含まれる申請を拒否する。
- **`.env.local`。** `.worktreeinclude` を置かない。作業員は API キーを持たない。
- **同時に動く数。** 既定は 1 である（逐次）。並行は、夜間のキューで明示したときだけである（[`harness.md`](harness.md) §3）。
- **main への追従。** main が進んで作業ブランチが main を含まなくなったとき、作業員の worktree での `git rebase main` は、main の変更に `vgdd/**` や `.claude/agents/**` が含まれていると、sandbox の `denyWrite` に止められる（衝突ではない）。統合キュー（§3 の 2）で、gate-runner が候補を作るため、作業員が rebase する必要はない。衝突（`needs_rebase`）のときは、新しい worktree で作業員を起こして `git cherry-pick` させる。

## 5. 法律の改正

法律（`.claude/settings.json`・フック・gate-runner・`judge*.sh`・`CLAUDE.md`・`vgdd/`）の変更は、立法補佐の起草、憲法審査、別系統の監査、オーナーの承認を経る。行政は保護パスを書けない。変更のたびに、適合性テストの判例を足し、前の版にかけて新しい判例だけが落ちることを確かめる（SPEC §11）。経緯は [`vgdd/kernel/history.json`](../vgdd/kernel/history.json) にある。配置済みの設定は、原本から自動では変わらない。法律を改めたら、配置を更新する（[`adoption.md`](adoption.md)）。

設定の原本は [`vgdd/settings.v2.json`](../vgdd/settings.v2.json) である。

## 6. 危険と限界

| 項目 | 内容 | 対策、書き方 |
|---|---|---|
| 利用枠 | 作業員が同じ契約の利用枠を使う。枠の残りは読めない | 同時数は既定で 1。上限に達した文言で止める。予算の台帳が次の起動を拒む（SPEC §9） |
| 統合の衝突 | 同じファイルを触る票が並ぶと、統合できない | `files_allowed` を重ねない。衝突は `needs_rebase` で返す |
| 費用 | 司法は呼び出しごとに費用がかかる | 予算の台帳が起動の前に予約する。厳密な金額の上限は保証しない（SPEC §9） |
| フックの文字列照合 | パスの分割、広いグロブ、`main` への参照更新の別表現は通りうる | sandbox と隔離で補う。main は事後検知も行う |
| 裁判所の独立 | gate-runner はオーナーの権限で動く。judge は Claude 系統 | Codex（別系統）との一致を条件にする。両者が同じ見落としをする可能性は残る |
| 行政の長の自制 | 「自分では実装しない」は約束で、強制ではない（権限の表に `promise` と書く） | 証拠ストアの `agent_type` 別の件数で、本体の Edit・Write が増えていないかを見られる |
| worktree の設定のコピー | worktree の `.claude/settings.json` は効かないが、統合すれば main に入る | gate-runner が `.claude/**` の差分を拒否する |
| 夜間の運転 | フックの失敗で全操作が止まる。gate-runner が止まれば申請が溜まる | 朝に、Z3 の記録が途切れた時刻と、`merge-requests/` の残りを見る |
| 保証できないこと | Bash の文字列照合の回避、人が承認した操作、Z3 の存在の秘匿、`main` への直接更新の OS レベルの禁止、判定の正しさ（LLM） | SPEC §12 と [`vgdd-status.md`](vgdd-status.md) の限界の節 |

## 7. この文書で扱わないもの

最初の導入先のアプリに固有の仕組み（利用者の役を演じる画面操作の試験、統治の画面、最初の票の分け方）は、このリポジトリにないので扱わない。画面の評価に使うモード（`judge-codex.sh --ux`）は、`vgdd/scripts/` にある。
