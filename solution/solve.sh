#!/bin/bash
# Oracle solution.
#
# Document what was actually wrong and how the fix was derived — a reviewer reads this
# to judge whether the task is solvable by reasoning rather than by guessing:
#
#   src/summarize.py   Three defects. Entries came back in filesystem order instead of
#                      sorted by name; total_words counted files rather than words; and
#                      the report was written without its trailing newline.
#
# Harbor mounts solution/ at /solution/ and runs this script as the oracle agent.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cp "$HERE/src/summarize.py" /app/src/summarize.py

python3 /app/src/summarize.py --data /app/data --out /app/out/report.json

sha256sum /app/out/report.json
