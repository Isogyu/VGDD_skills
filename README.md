# VGDD_skills

VGDD（VGDD Governance Kernel）の改修用リポジトリ。

## 出どころ

[Isogyu/tsubuyaki-worklog](https://github.com/Isogyu/tsubuyaki-worklog) のコミット `10491be`（Built with Claude: Japan 2026 の提出版の後）から、VGDD に当たる部分だけを履歴なしでコピーした（2026-11-14）。

| パス | 中身 |
|---|---|
| `vgdd/` | 規範（`kernel/SPEC.md`・`capabilities.json`）、スキーマ、フック、エージェント定義、裁判所などのスクリプト、適合性テスト、settings の写し（`settings.v2.json` は元リポジトリの `.claude/settings.json` と同一） |
| `docs/` | VGDD の設計方針（kernel・governance・harness）、実装状況と検証（vgdd-status・validation）、導入の手引き（adoption）、Phase 1 技術仕様書、提出時の Kernel の状態の写し |
| `vgdd/next/` | **起草段階の試作（効力なし。稼働中の Kernel にはつないでいない）**：権限の差分、改善提案の記録、経験の記録、仕事のグラフ、編成案の検査、領域パック、評価の実行器。使い方と検証の結果は [`vgdd/next/README.md`](vgdd/next/README.md) |
| `docs/design/vgdd-next-architecture.md` | 次の段階の設計案：今の VGDD の分析、長期の全体アーキテクチャ、開発ライフサイクル全体と開発以外への広げ方、ロードマップ、リスクと研究課題 |
| `docs/research/prior-work.md` | 先行研究の調査（指定の8本と追加の調査）、既存技術との比較、新規性の分析 |

コピーしていないもの：題材アプリ「つぶやき業務ログ」のコード（`src/` など）、票（`docs/tasks/`）、要件定義などアプリ側の文書、有効な `.claude/settings.json`（`~/tsubuyaki-z3/` のフックを呼ぶため、この場所では動かない）。

## 試す

```sh
node vgdd/conformance/run.mjs              # 既存の Kernel の適合性テスト（jq・UTF-8 のロケールが要る。約2〜4分。同時に2つ動かさない）
node --test vgdd/next/test/*.test.mjs      # 試作の試験（依存なし。Node 22 以上）
node vgdd/next/bench/run.mjs               # 試作の検査の評価（攻撃の阻止・良性の通過・アブレーション・性能）
```

## 注意

ドキュメントとスクリプトには、元リポジトリの配置（`src/`・`docs/tasks/`・`merge-requests/`・`~/tsubuyaki-z3/` など）を前提にした記述が残っている。改修で汎用化する。
