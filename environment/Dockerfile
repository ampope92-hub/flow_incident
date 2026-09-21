# Agent image. Nothing from tests/ or solution/ is ever copied in here, and the archive's
# datagrams are not here either: they live in the archive service's own image.
#
# Non-canonical toolchain, justification: the task is written in Zig, which bookworm has no
# apt package for; the ziglang wheel on PyPI is the Zig Software Foundation's own release
# repackaged, and pinning it by hash is what makes the compiler reproducible.
FROM public.ecr.aws/docker/library/python:3.13-slim-bookworm@sha256:01f42367a0a94ad4bc17111776fd66e3500c1d87c15bbd6055b7371d39c124fb

ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        asciinema \
        ca-certificates \
        curl \
        tmux \
    && rm -rf /var/lib/apt/lists/*

# Zig 0.14.1, the one compiler the task needs, from a hash-pinned wheel.
COPY zig-requirements.txt /tmp/zig-requirements.txt
RUN pip install --no-cache-dir --require-hashes --no-deps -r /tmp/zig-requirements.txt && rm -f /tmp/zig-requirements.txt
RUN /usr/local/lib/python3.13/site-packages/ziglang/zig version

# Where the archive is. The grader sets these to something else, so nothing may be built in.
ENV ARCHIVE_HOST=127.0.0.1 \
    ARCHIVE_PORT=9600

WORKDIR /app/flowkit

COPY app/flowkit/ /app/flowkit/
RUN chmod +x /app/flowkit/build.sh /app/flowkit/run.sh
