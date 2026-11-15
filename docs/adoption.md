# 試す・構築する・ほかの案件に入れる

**この文書の範囲：macOS・Claude Code・Git・Node.js の案件・オーナー1人。** ほかの OS、ほかの開発エージェント、複数人の権限分離は扱いません。

## 3つの場面

| 場面 | 誰が | 何をするか | 確かめた範囲 |
|---|---|---|---|
| **A. clone で試す** | 誰でも | 適合性テストを動かし、画面と記録を読む。Kernel は実稼働しない | **確かめた**：最初の導入先のリポジトリを、作者の macOS の一時的な clone で（Node 25。[`validation.md` §4](validation.md)）。今の版の clone と、ほかの人の手元は未確認 |
| **B. 作者が別の場所に構築する** | 作者 | 別のフォルダと別の保護領域に、Kernel を実稼働させる | **適合性テストの水準でだけ確かめた**（法律 p0.4.15、判例 群 P）：一時ディレクトリの写しの上で、(1) 別の名前の Z3（`acme-kernel-z3`）でフックが C1 の全部の判定を同じにすること、(2) 裁判所・夜間の代行・起動の窓口が `--repo`・`VGDD_REPO` で指定のリポジトリを扱うこと（PT5）、(2b) 試験用の Z3 とリポジトリのフォルダの名前を変えて（`--z3-name acme-kernel-z3 --repo-name acme-worklog/app`）全部の群（G・N・L を含む。第2版の 583 件で依頼者も確かめた）が既定の名前と1件ずつ同じ結果になること（立法補佐と依頼者がそれぞれ確かめた）、(3) 導入の道具で一時のホームに置いた配置で、診断が合格し、C1 と ST16 が通ること（PT8）。**実際の Claude Code のセッション・実際の sandbox・実際の司法での運用は未確認**。実稼働させた記録はない |
| **C. ほかの人が既存の案件に入れる** | ほかの人 | 自分の案件に Kernel を入れ、参照実装を必要に応じて直す | **未確認**。試した人はいない（場所と名前の移植は B と同じ範囲で試験済み。案件ごとの前提（§3）は試していない） |

**実際に確かめたのは A だけです。** Kernel を実稼働させたのは、この案件の、この開発の配置（オーナー1人・macOS の機械1台）だけです。B は、上の (1)〜(3) を適合性テストの水準（一時ディレクトリの写し・偽の CLI）で確かめただけです。B と C の手順どおりに実際に動くことは、まだ確かめていません。

数字は法律 p0.4.16・適合性テスト 637 件の時点のものです（§1・§4 の一部の実例は p0.4.8 の時点のまま）。

## 1. A：clone で試す

手順は [README の「再現」](../README.md)にあります。

| できること | 確かめられる範囲 |
|---|---|
| 適合性テスト（`node vgdd/conformance/run.mjs`。`jq`・`shasum`・UTF-8 のロケールが要る） | 使い捨ての試験用リポジトリと偽の Z3 の上で、止めるべき操作が止まり、通すべき操作が通ること。LLM は呼ばないので、判定の中身ではなく判定の扱いを試す |
| 前の版との比較 | 法律の版の差は [`vgdd/kernel/history.json`](../vgdd/kernel/history.json) と Git の履歴で追える |
| 統治の画面（最初の導入先のアプリの `/governance`。このリポジトリにはない） | 統治の数字・票の盤・票1枚の運命・法律の歴史。全体図は一部の数が「—」で、Kernel と不変条件の区画は、状態の表示用ファイルがないので空（一時的な clone で確かめた。[`validation.md` §4](validation.md)） |
| 記録を読む | 票の §2 と §6（導入先の `docs/tasks/`。このリポジトリにはない）、主張と証拠（[`validation.md`](validation.md)） |

適合性テストは、実際の sandbox と起動設定を試しません（[`kernel.md` §6](kernel.md)）。A が通っても、B や C が動くことの証拠にはなりません。

## 2. B：作者が別の場所に構築する（未検証）

**既定の名前について。** このリポジトリの文書とコードに出てくる既定の名前（保護領域 `~/tsubuyaki-z3`、リポジトリ `~/tsubuyaki-worklog/app`）は、最初の導入先の開発のときの配置の名前です。今の実装の既定の値なので、設定の説明とコマンドの例では、そのまま書いています。配布の前に変える予定です。変えるまでは、環境変数 `VGDD_Z3_DIR`、`VGDD_REPO` と引数 `--repo` で指定してください。

### 要るもの

| 要るもの | 用途 | 正本 |
|---|---|---|
| Claude Code | 行政の実行、PreToolUse フック、権限ルール、sandbox、worktree | [`../vgdd/settings.v2.json`](../vgdd/settings.v2.json)（原本）を `.claude/settings.json` へ |
| 保護領域 Z3（作業フォルダの外） | フックと裁判所の実行用のファイル、承認・判定・証拠の記録 | [`SPEC.md` §4・§10](../vgdd/kernel/SPEC.md) |
| 裁判所の常駐（sandbox の外、オーナーの権限） | 統合キュー、監査、司法の呼び出し | [`../vgdd/scripts/gate-runner.sh`](../vgdd/scripts/gate-runner.sh) |
| 裁判所の道具 | `jq`・`node`・`git`・`npm`・`python3`・`sandbox-exec`。Git の設定の基準値（[`git-baseline.sh`](../vgdd/scripts/git-baseline.sh)）。裁判所は起動時に確かめ、欠ければ起動しない | `gate-runner.sh` の `preflight` |
| 司法の CLI | `claude` と `codex` | [`SPEC.md` §6](../vgdd/kernel/SPEC.md) |
| エージェントの定義 | 作業員・テスト担当・judge・憲法審査 | [`../vgdd/agents/`](../vgdd/agents/) を `.claude/agents/` へ |
| 票の運用 | 形式どおりの票、オーナーの `approve-spec.sh` | 導入先の `docs/tasks/README.md`（票の形式。このリポジトリにはない）。指紋の作り方は [`SPEC.md` §4](../vgdd/kernel/SPEC.md) |

`--no-codex` で起動すれば司法は judge だけになりますが、別系統の確認がなくなります。この開発の記録は、Claude の司法に Codex の第2の司法を加えた構成のものです。1つの Claude アカウントで役割を分けたセッションだけで運用する構成と、そのときの司法の独立性は確かめていません。

### 構築の順序（チェックリスト。実際の環境で通した記録はない）

`<repo>` は対象のリポジトリ、`<z3>` は作業フォルダの外の保護領域です。どちらもホームの下に置きます（設定のパスは `~/` の形で書くので、ホームの外の配置は扱いません）。Z3 の名前は英数字と `.`・`_`・`-` だけ・4 文字以上・ありふれた名前（`z3`・`tmp`・`data` など）でないもの。そうでなければ、フックはすべての操作を拒否し、導入の道具も拒みます（[`SPEC.md` §11 の移植](../vgdd/kernel/SPEC.md)）。

- [ ] **配置**（p0.4.15 から道具がある）：オーナーが sandbox の外で `node vgdd/scripts/vgdd-setup.mjs install --repo <repo> --z3 <z3> --dry-run` で置くものを確かめ、`--dry-run` を外して実行する。Z3 に `hooks/`・`bin/`・`evidence/` を作ってフックとスクリプトを置き、Z3 の権限を 0700 にし、`<repo>/.claude/settings.json`（原本のパスを指定の場所に置き換えたもの。`render-settings` と同じ）と `<repo>/.claude/agents/` を置く。既にあるファイルは上書きしない（違いがあれば一覧を出して何も書かずに止まる）。書き先の実体（記号リンクの先）がホームの外なら書かない。**途中で失敗したときは、その実行が作ったファイルとフォルダの一覧を出して終了 70 で止まり、自動では消さない**（オーナーが一覧を見て消してからやり直す）。Z3 は作った直後から 0700。Z3 はホームの下の 2 段まで、場所の各段は英数字と `.`・`_`・`-` だけ。一時ディレクトリの写しで確かめた（判例 PT8・PT9・PT10・PT16）
- [ ] **元の案件に固有の保護**：リポジトリの外の読み取り専用の領域を足すなら、`<z3>/kernel.config.json` に `{"schema":"vgdd.kernel-config.v1","extra_readonly_dirs":[…]}` を置く（既定の `../preparation`・`../event_records` に足す）。既定の2つを外すときだけ `readonly_dirs`（置き換え）を使う（doctor が注意を出す）。どちらか一方だけ。形が違えばフックはすべての操作を拒否する。足した領域は `.claude/settings.json` の `denyWrite` と権限の規則にも足す
- [ ] **基準値の作成**：`.git/config` を確かめてから `VGDD_Z3_DIR=<z3> <z3>/bin/git-baseline.sh --repo <repo>` を実行する（道具は実行しない）
- [ ] **確認**：`node vgdd/scripts/vgdd-setup.mjs doctor --repo <repo> --z3 <z3>`（§4。表示用）と、適合性テスト `VGDD_Z3_DIR=<z3> node vgdd/conformance/run.mjs --impl z3 --repo <repo> --z3-name <z3 の名前>`
- [ ] **起動**：sandbox の外で `VGDD_Z3_DIR=<z3> <z3>/bin/gate-runner.sh --repo <repo>` を動かす。道具が欠ければ起動しない（実際の環境では未確認）

### 変える設定の場所

| 変えるもの | 場所 |
|---|---|
| リポジトリ：すべてのスクリプト（`gate-runner.sh`・`night-runner.sh`・`launcher.sh`・`morning-report.mjs`・`approve-spec.sh`・`release.sh`・`kernel-stop.sh`・`kernel-resume.sh`・`git-baseline.sh`・`sandboxed-run.sh`） | 引数 `--repo <repo>` ＞ 環境変数 `VGDD_REPO` ＞ 既定（p0.4.15 でそろえた。判例 PT5・PT5b）。`release.sh` は `--repo` を最初に、`kernel-stop.sh`・`kernel-resume.sh` は理由の後に書く。`gate-runner.sh` は監査の sandbox に `--repo` の値を渡す（p0.4.6、判例 ST14） |
| Z3：スクリプトとフック（司法・憲法審査の判定の既定の出力先と verify-chain を含む） | 環境変数 `VGDD_Z3_DIR`（p0.4.15 で司法の出力先もそろえた。判例 PT4）。フックには `.claude/settings.json` のフックのコマンドで渡す（`render-settings` が書く） |
| 元の案件に固有の保護の対象（リポジトリの外の読み取り専用） | `<z3>/kernel.config.json`（なければ `../preparation`・`../event_records`。判例 PT6） |
| フックの起動のパス、保護パス、`additionalDirectories` | `<repo>/.claude/settings.json`。原本は開発時の配置で書いてあるので、`vgdd-setup.mjs render-settings --repo <repo> --z3 <z3>` で置き換える（判例 PT7） |

未指定のときの既定値は、この開発の配置です。

## 3. C：ほかの人が既存の案件に入れる（未検証）

B の準備に加えて、今の実装が次のことを前提にしています。外れるなら、参照実装を直す必要があります。

- **道具**：開発エージェントが Claude Code。フックの入力の形に依っている
- **OS**：sandbox は macOS の Seatbelt で確かめた
- **リポジトリ**：Git で、統合先が `main`。票は `docs/tasks/`
- **置き場所**：既定のパスは開発時の配置。スクリプトごとの指定のしかたは §2 の「変える設定の場所」
- **監査**：`npm ci`・`npm run test`・`npm run typecheck`・`npm run lint` が動く Node.js の案件（`gate-runner.sh` の決定論的な監査）
- **人**：仕様の承認・裁定・停止を担う人が1人いて、その人の権限で裁判所を動かす。複数人の権限分離、企業の認証基盤との接続、クラウドでの監査はない（[`kernel.md` §5](kernel.md)）
- **信頼**：同じ機械の管理者を信頼する。記録の外部への固定はしていない（[`SPEC.md` §10・§12](../vgdd/kernel/SPEC.md)）
- **費用**：司法を票ごとに呼ぶので、その費用を見込む。昼の司法の費用の上限は未実装（[`kernel.md` §2](kernel.md)）

入れるときは、まず適合性テストを動かし、次に迂回の検証（[`vgdd-status.md`](vgdd-status.md) の V6・V7。2026-11-03、フック p0.1.2〜p0.2.0 の記録）をその環境でやり直してください。合格の主張は、その構成と日時に限ります（[`SPEC.md` §11](../vgdd/kernel/SPEC.md)）。

## 4. 導入の確認の表

B・C で、上から順に人が確かめます。p0.4.15 から、この表の多く（OS、必須のコマンドが PATH にあること、Node の版、フックの登録と onFailure、sandbox の3つの値、書き込みと読み取りの保護に Z3 と統治の核が入っていること、元の案件のパスの残り、原本と配置済みの一致、Z3 がリポジトリの外にあること、Z3 の権限）を `node vgdd/scripts/vgdd-setup.mjs doctor --repo <repo> --z3 <z3>` が機械で確かめます。配置と Kernel の設定は、配置したフックを一時の証拠ストアで1回起動して確かめます（終了コード 0＝全部合格、1＝不合格あり、2＝確かめられない項目か注意（既定の保護を外す設定・ありふれた名前の先頭）あり）。**診断は表示用で、表も診断も、合格しても Kernel が正しく動く証明にはなりません**。司法の CLI の版・認証、裁判所の点検、対象のリポジトリの監査、追跡しないファイルは、診断では確かめません（下の表で人が確かめる）。

**実行する場所**：Z3 を読むコマンドは、開発エージェントからは読めないので、オーナーが sandbox の外で実行します。コマンドの `.claude/settings.json` などの相対パスは、`<repo>` で実行する前提です。

### 対応 OS と必須のコマンド

| 確かめること | 方法 | 合格の目安 |
|---|---|---|
| OS | `uname -s` | `Darwin` |
| sandbox の道具 | `command -v sandbox-exec python3` | 2つとも出る |
| 裁判所の道具 | `command -v jq git npm shasum` | すべて出る |
| Node.js | `node -v` | 24 以上（`package.json` の `engines`。適合性テストだけなら 22 以上） |
| 司法の CLI | 裁判所を動かす環境で `claude --version`、`codex --version`（開発エージェントの環境とは PATH が違うことがある） | どちらも版が出る。`codex` がなければ裁判所は起動しない。`--no-codex` で起動すると、別系統の確認がなくなる |
| 裁判所の点検（Z3 の配置の後） | `<z3>/bin/sandboxed-run.sh --preflight`、`<z3>/bin/judge.sh --preflight`、`<z3>/bin/judge-codex.sh --preflight` | どれも終了コード 0 |

### 対象のリポジトリ

| 確かめること | 方法 | 合格の目安 |
|---|---|---|
| 操作する先 | `git rev-parse --show-toplevel` | `<repo>` を指す。親のフォルダの別のリポジトリではない |
| 統合先 | `git rev-parse --verify main` | SHA が出る |
| 監査が動く | `npm ci`、`npm run test`、`npm run typecheck`、`npm run lint` | すべて通る |
| 票の置き場所 | `ls docs/tasks/README.md` | ある（票の形式の説明） |
| 追跡しないファイル | `git check-ignore .env.local docs/governance/kernel-state.json docs/governance/kernel-invariants.json` | 3つとも出る |

### フック・sandbox・保護の設定

| 確かめること | 方法 | 合格の目安 |
|---|---|---|
| フックの登録 | `jq -c '.hooks \| keys' .claude/settings.json` | `PermissionDenied`・`PostToolUse`・`PostToolUseFailure`・`PreToolUse` |
| フックが失敗したら止まる | `jq -c '[.hooks[][].hooks[].onFailure]' .claude/settings.json` | すべて `block` |
| フックの場所 | `jq -r '.hooks.PreToolUse[].hooks[].command' .claude/settings.json` | 自分の `<z3>/hooks/policy.mjs` を指す |
| sandbox | `jq -c '[.sandbox.enabled, .sandbox.failIfUnavailable, .sandbox.allowUnsandboxedCommands]' .claude/settings.json` | `[true,true,false]` |
| 書き込みの保護 | `jq '.sandbox.filesystem.denyWrite' .claude/settings.json` | 自分の Z3、`vgdd`、`CLAUDE.md`、`.claude/settings.json`、`docs/governance`、`docs/tasks/_board.json` が入っている |
| 読み取りの保護 | `jq '.sandbox.filesystem.denyRead' .claude/settings.json` | 自分の Z3 と `.env.local` が入っている |
| 開発時のパスの残り | `grep -n 'tsubuyaki' .claude/settings.json`（既定の名前は開発のときの配置の名前。配布の前に変える予定） | 自分の配置に直した後は何も出ない |

### 原本と配置済みの設定の一致

原本を直しても、配置済みの設定は自動では変わりません。法律を改めるたびに確かめます。

| 確かめること | 方法 | 合格の目安 |
|---|---|---|
| 設定 | `vgdd-setup.mjs render-settings --repo <repo> --z3 <z3>` の出力と `.claude/settings.json` の `diff`、適合性テストの ST16（`--impl z3 --repo <repo>`）、doctor の `settings-match`・`settings-strict` | 原本を指定の場所に合わせて書き換えたものの拒否の規則と禁止の一覧をすべて含み、sandbox の3つの値とフックの構造が同じ（p0.4.15 から ST16 は試す場所に合わせて書き換えた原本と比べる）。p0.4.16 から、sandbox の節は原本にある項目だけ（`excludedCommands`・`filesystem.allowRead`・`allowWrite`・`disabled`・`enableWeaker*`・`network` の緩める項目がない。`network.allowedDomains` は原本の部分集合で、宛先を足すのは原本を改める立法による）で、最上位に `disableAllHooks` などがない |
| 上の層の設定（p0.4.16） | doctor の `settings-layers`、適合性テストの ST16b・ST16c。人の目では `jq . <repo>/.claude/settings.local.json ~/.claude/settings.json ~/.claude/settings.local.json`（あるものだけ） | ファイルがないか、あっても `sandbox.enabled` が true 以外・`allowUnsandboxedCommands` が false 以外・`failIfUnavailable` が true 以外・`excludedCommands`・`filesystem.disabled`・保護の場所に重なる `allowRead`・`allowWrite`・`network` の緩める項目と原本にない宛先・`enableWeaker*`・`disableAllHooks` がない。`hooks` の節・保護の外への `allowWrite`・フックに効きうる `env` は「注意」（doctor は終了 2）。値の設定は上の層が勝つ（文書。実機では未確認）ので、プロジェクトの `.claude/settings.json` が正しくても、上の層で sandbox を外せる。`/sandbox` の画面は `enabled` を `settings.local.json` に書く。管理者の設定・起動の引数・環境変数はファイルの検査では見られない |
| エージェントの定義 | `diff -r vgdd/agents .claude/agents` | 違いがない |
| フック | `diff vgdd/hooks/policy.mjs <z3>/hooks/policy.mjs`（オーナー） | 違いがない |
| 裁判所のスクリプト | `vgdd/scripts/` の各ファイルと `<z3>/bin/` の同じ名前のファイルを `diff`（オーナー） | 違いがない |

**この開発の配置での実例**：11/7 12:3x の時点では、設定の `diff` に、原本にだけある4行が出ました（`Edit`・`Write` の `docs/governance` の deny。sandbox の `denyWrite` とフックでは守っていた）。法律 p0.4.8 で配置済みの設定に足し、判例 ST16 にしました。11/7 15:10 に原本と稼働中の写しの両方で 414/414 を確かめています。

フックの版（`policy_version`）と法律の版（`kernel_version`）は別の数字です。法律を改めてもフックを変えなければ、前の版のままです（11/7 15:10 の時点でフックは p0.4.5、法律は p0.4.8）。

### この改正（p0.4.16）を今の配置に入れるときにオーナーがすること

1. **設定を更新する**：原本に拒否の規則を足した（`git push * --force*`・`git push * -f*`・`git push * +*`、`claude`・`codex` の CLI の起動の形、`~/.claude` の指示・エージェント・スキル・コマンド・規則・出力の形の `Edit`）ので、今の配置済みの `.claude/settings.json` は、更新するまで ST16（と doctor の `settings-match`）に通らない。`vgdd-setup.mjs render-settings --repo <repo> --z3 <z3>` の出力と `diff` を取り、足りない拒否の規則を足す（install は既にあるファイルを上書きしない）
2. **配置済みの設定の緩める項目を外す**：`.claude/settings.json` の `sandbox` に原本にない項目（`excludedCommands`・`filesystem.allowRead` など）や原本にない宛先があれば、ST16 に通らない。宛先が要るなら、原本を改める（立法）
3. **上の層の設定を点検する**：`<repo>/.claude/settings.local.json`、`~/.claude/settings.json`、`~/.claude/settings.local.json` を開き、上の表の値がないことを確かめる（doctor の `settings-layers`）。`/sandbox` の画面で設定を変えたことがあれば、`settings.local.json` に `enabled` が書かれている。個人の `hooks` の節があれば注意になる（Kernel の判定にどう効くかは確かめていない。不要なら外す）
4. **フックとスクリプトの写しを更新する**：`vgdd/hooks/policy.mjs` を `<z3>/hooks/` に、`vgdd/scripts/` を `<z3>/bin/` に写す（`settings-check.mjs` が増えた）。フックの版は p0.4.16
5. 適合性テスト（`--impl z3 --repo <repo>`）を動かし、ST16・ST16b・ST16c・LN1・LN2 と C1 の CAP-LAUNCH-AGENT-CLI が通ることを見る
6. 行政の長のセッションで、`claude --version` などの起動が拒否されて記録に残ることを1回見る（行政が claude・codex の CLI を使う手順があれば、使わない形に直す）

### 実際の環境で確かめること（文書で確かめた・実機では確かめていない。p0.4.16）

2026-11-14 に、外部の調査の報告を、立法補佐が Claude Code の公式の文書と CHANGELOG で照合しました（取得した文書は随時更新の最新版で、手元の Claude Code の版は分かっていません）。**下の表は、文書では決まらないか、文書どおりに動くかを実機で確かめていないものです。** どれも本物の Z3 と作業記録には触れず、一時のリポジトリと一時のホーム（偽の Z3）で、オーナーが行います。先に `claude --version`、`/status`、`/permissions`、`/sandbox`、`claude doctor` で、版と実際に読み込まれた設定を記録してください。

| ID | 確かめること（文書で分かっていること） | 手順 | 結果が違ったときに見直すもの |
|---|---|---|---|
| R1 | `..` を含む相対の規則 `Edit(../preparation/**)`・`Edit(../event_records/**)` が一致するか（文書に例も保証もない） | 一時のリポジトリにその deny だけを置き、Edit ツールで `../preparation/a.md` を書かせる | 一致しないなら、絶対の形（`~/…`）の規則・sandbox・フックだけが止めている。`..` の規則は補助と書き直す |
| R2 | `.claude/settings.local.json` の `sandbox.enabled:false`・`allowUnsandboxedCommands:true`・`disableAllHooks:true` が `.claude/settings.json` の値を上書きするか（文書は「上の層が勝つ」）。worktree のセッションが main の checkout の `settings.local.json` を読むか（文書） | 一時のリポジトリで local に1つずつ書き、`/sandbox` の表示と、偽の Z3 への Bash の読み取りが止まるかを見る | 上書きしないなら、ST16b の不合格は止めすぎ（害はない）。上書きするなら、ST16b と doctor が実際の穴を見ていることになる |
| R3 | 設定の `env`（`NODE_OPTIONS`・`PATH`）がフックのプロセスに渡るか | 一時のリポジトリで `env` に印を付け、試験用のフックで `process.env` を出す | 渡るなら、ST16c の注意を不合格に上げる候補 |
| R4 | フックのコマンドの `~`・`$HOME`・行頭の `VAR=値 コマンド` が `sh -c` で期待どおり動くか。`node` が `sh -c` の PATH にあるか | 試験用のフックを動かし、`claude --debug-file` の記録を見る | 動かなければ、全操作が止まる（安全側だが止まる） |
| R5 | `--agent` で起動したメインのセッションで、定義の `disallowedTools`・`isolation: worktree`・`maxTurns` が効くか（文書に書いていない） | `claude -p --agent judge` で Read を求め、拒否されるか。`--agent worker` が worktree に入るか | 効かないなら、司法の「ツールなし」は `--max-turns 1` と入力の組み立てだけに依る。起動の引数で道具を外す改正の候補 |
| R6 | Linux：存在しない denyWrite のパスに作られるマウント点が git の状態を汚すか、`**/` で始まる Edit の規則が sandbox に反映されないこと | Linux の環境があるとき | 今は macOS だけを扱う |
| R7 | 同じパスを denyRead と allowRead の両方に書いたときの優先、`excludedCommands` に `node *` を足した状態で偽の Z3 が読めるか、`filesystem.disabled` をプロジェクトの設定に書いたとき無視されるか | 一時のホームに偽の Z3 を置いて試す | 結果を SPEC §12 の文書の限界に反映する |
| R8 | 入れ子の `claude --bare -p`・`claude --settings '{"disableAllHooks":true}' -p` が sandbox の中の Bash から起動できるか、そのときフックが走らないこと | 一時のリポジトリで、フックの LN の拒否を外した試験用の写しを使って試す（本物の配置の拒否は外さない） | 起動できないなら、LN の拒否は二重の守り。起動できれば、LN の拒否が唯一のフックの層 |
| R9 | 信頼を承認していない対話のセッションでフックが動かないこと。`~/.claude.json` の `projects[…].hasTrustDialogAccepted` の読み方 | 新しい clone で `claude` を起動し、承認の前後で最初の Read の記録を見る | 導入の手順に「信頼の承認の後にフックの記録を見る」を足す（今は §4 の「記録が残る」で見る） |
| R10 | `.claude/settings.json` が git で追跡されているか（追跡されていなければ、worktree の作業員のセッションに設定が入らない疑い） | sandbox の外で `git ls-files .claude/settings.json` | 追跡されていなければ、作業員のセッションの sandbox と権限の規則が外れている疑い。追跡するか、起動の引数で設定を渡す改正の候補 |
| R11 | Grep・Glob を Z3 の親（ホーム）から実行したとき、`Read(~/<z3>/**)` の拒否が Z3 の中に効くか（文書は "best-effort"） | 一時のホームで試す（フックの拒否を外した試験用の写しで） | 効かなければ、Read 系のツールで Z3 を止めるのはフックだけ |
| R12 | 親フォルダの信頼の扱い（文書のページの間で食い違う） | 版ごとの CHANGELOG と実機 | R9 の手順に反映する |
| R13 | `autoAllowBashIfSandboxed` の既定の変更が 2.1.324 か 2.1.325 か（文書と CHANGELOG で食い違う）。手元の版 | `claude --version` | 原本は true を明示しているので、既定の変更の影響は受けない |

**実機の確認の後の候補（今回はしない変更）**：文書が違っていた場合に、通す側に変わるか、起動の仕方を変えるものは、今回は入れていません。(1) 夜間の作業員・司法の起動に `--settings '<sandbox の3つの値と disableAllHooks:false>'` を渡して上の層を固定する（R2・R5 の後）、(2) 管理者の設定（managed settings）に sandbox の値を置く（オーナーの管理者権限が要る）、(3) 原本の `Write(...)` の規則と、死んでいる allow `Bash(npx --no-install *)` を外す（照合の期待が変わる。R13 と夜間の作業員の操作の確認の後）、(4) `..` を含む規則の書き直し（R1 の後）。

### 次に人が確かめること

表だけでは確かめられません。

| 確かめること | 方法 |
|---|---|
| 適合性テストが、配置した実装で通る | `VGDD_Z3_DIR=<z3> node vgdd/conformance/run.mjs --impl z3 --repo <repo> --z3-name <z3 の名前>`（指定した場所の写しと配置済みの設定を試す。p0.4.15 で、一時ディレクトリに導入した別の名前の Z3 で C1 と ST16 が通ることを確かめた（判例 PT8）。実際の環境での全体は未確認） |
| 票が最後まで通る | 小さな票を1枚、承認・申請・判定・統合まで通す |
| 未承認の票が止まる | 承認していない票を申請し、裁判所が blocked にすることを見る |
| 止められる | 停止と再開を1回試す（[`SPEC.md` §8](../vgdd/kernel/SPEC.md)）。停止中に開発エージェントの操作が拒否されることを見る |
| 迂回できない | 迂回の検証（[`vgdd-status.md`](vgdd-status.md) の V6・V7）を、その環境でやり直す |
| 記録が残る | 拒否された操作が証拠ストアに残り、ハッシュチェーンの検証が通ることを見る |
