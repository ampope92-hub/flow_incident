#!/bin/bash
# Builds and runs the tool against the archive in this environment.
set -e
/app/flowkit/build.sh
cd /app/flowkit
exec /app/flowkit/bin/flowkit
