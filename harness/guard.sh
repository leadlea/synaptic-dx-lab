#!/bin/bash
# Kiro PreToolUse フックの実体。
# stdin で受けたツール実行内容を harness に渡し、
# 現在のロールで許されないレイヤーへの参照なら exit 2 で実行をブロックする。
#
# exit 0 : 許可（そのままツールが実行される）
# exit 2 : ブロック（stderr の内容が Kiro に返る）
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$HERE/harness.py" guard
exit $?
