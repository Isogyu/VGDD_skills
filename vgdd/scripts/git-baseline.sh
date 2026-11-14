#!/usr/bin/env bash
# VGDD — 共有の .git/config の基準値を作る（オーナーが sandbox の外で実行。p0.3.1、OBS-033）。
# gate-runner と夜間ランナーは、周回のはじめに .git/config の要約をこの基準値と照合し、違えば止める。
# 使い方: vgdd/scripts/git-baseline.sh [--repo <repo>]  （.git/config をオーナーが確かめた後に実行する）
set -euo pipefail
REPO="${VGDD_REPO:-$HOME/tsubuyaki-worklog/app}"; Z3="${VGDD_Z3_DIR:-$HOME/tsubuyaki-z3}"   # p0.4.15：リポジトリは 引数 --repo ＞ 環境変数 VGDD_REPO ＞ 既定
if [ "${1:-}" = "--repo" ]; then [ -n "${2:-}" ] || { echo "--repo にリポジトリの場所を指定する" >&2; exit 64; }; REPO="$2"; fi
grep -nEi 'hookspath|fsmonitor|sshcommand|askpass|\[filter|textconv|\[alias|pager|editor' "$REPO/.git/config" && { echo "危険な設定が含まれている。確かめてから実行し直す" >&2; exit 1; }
shasum -a 256 "$REPO/.git/config" | cut -c1-64 > "$Z3/evidence/git-config.baseline"
echo "基準値を作った: $(cat "$Z3/evidence/git-config.baseline")"
