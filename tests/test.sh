#!/bin/bash
# Verifier entrypoint. Runs in the separate verifier container.
#
# Deliberately NOT `set -e`: a failing pytest must still reach the reward write below.
set -uo pipefail

mkdir -p /logs/verifier
# If the verifier executes agent-produced code, keep the reward out of its reach so a
# planted binary cannot write its own verdict.
chmod 700 /logs/verifier

/venv/bin/python -m pytest --ctrf /logs/verifier/ctrf.json /tests/test_outputs.py -rA
rc=$?

if [ "$rc" -eq 0 ]; then
  echo 1 > /logs/verifier/reward.txt
else
  echo 0 > /logs/verifier/reward.txt
fi
