#!/bin/bash
# Builds the tool the way the grader does: main.zig as the root, ReleaseSafe, no other flag.
set -e
cd /app/flowkit
mkdir -p bin
/usr/local/lib/python3.13/site-packages/ziglang/zig build-exe /app/flowkit/src/main.zig -O ReleaseSafe -femit-bin=/app/flowkit/bin/flowkit
