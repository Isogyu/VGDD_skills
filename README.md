# VGDD_skills

VGDD（VGDD Governance Kernel）の改修用リポジトリ。

## 出どころ

[Isogyu/tsubuyaki-worklog](https://github.com/Isogyu/tsubuyaki-worklog) のコミット `10491be`（Built with Claude: Japan 2026 の提出版の後）から、VGDD に当たる部分だけを履歴なしでコピーした（2026-11-14）。

| パス | 中身 |
|---|---|
| `vgdd/` | 規範（`kernel/SPEC.md`・`capabilities.json`）、スキーマ、フック、エージェント定義、裁判所などのスクリプト、適合性テスト、settings の写し（`settings.v2.json` は元リポジトリの `.claude/settings.json` と同一） |
| `docs/` | VGDD の設計方針（kernel・governance・harness）、実装状況と検証（vgdd-status・validation）、導入の手引き（adoption）、Phase 1 技術仕様書、提出時の Kernel の状態の写し |

コピーしていないもの：題材アプリ「つぶやき業務ログ」のコード（`src/` など）、票（`docs/tasks/`）、要件定義などアプリ側の文書、有効な `.claude/settings.json`（`~/tsubuyaki-z3/` のフックを呼ぶため、この場所では動かない）。

## 注意

ドキュメントとスクリプトには、元リポジトリの配置（`src/`・`docs/tasks/`・`merge-requests/`・`~/tsubuyaki-z3/` など）を前提にした記述が残っている。改修で汎用化する。
