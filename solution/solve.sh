#!/bin/bash
# Reference solution. Drops the finished tool into the project and builds it the same way the
# grader does, then reads the archive here once so the build is not the only thing proved.
# The read is time bounded so an archive that is not up yet cannot hang the run.
set -e

cp /solution/src/main.zig /app/flowkit/src/main.zig

/app/flowkit/build.sh

echo "built, reading the archive once"
cd /app/flowkit
timeout 300 /app/flowkit/bin/flowkit > /tmp/flowkit_out.json \
    && echo "report: $(head -c 200 /tmp/flowkit_out.json)..." \
    || echo "the archive did not answer from here, which is fine at build time"
