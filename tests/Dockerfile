# Verifier image. Runs in its own container, sees only the paths declared in `artifacts`, and
# holds everything the agent never gets to see: the three archives, the report each one must
# produce, and the archive service that serves them. It compiles the collected Zig itself and
# runs the tool against an archive it starts, so the report has to come out of the agent's
# own program talking the protocol.

# The tool is started through tests/launch.c, which lets it start no other program. It is built
# statically in a throwaway stage, so no C compiler reaches the final image.
FROM public.ecr.aws/docker/library/python:3.13-slim-bookworm@sha256:01f42367a0a94ad4bc17111776fd66e3500c1d87c15bbd6055b7371d39c124fb AS launcher
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
COPY launch.c /tmp/launch.c
RUN gcc -O2 -static -Wall -o /tool_launch /tmp/launch.c

FROM public.ecr.aws/docker/library/python:3.13-slim-bookworm@sha256:01f42367a0a94ad4bc17111776fd66e3500c1d87c15bbd6055b7371d39c124fb

ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# The same Zig 0.14.1 the agent's box carries, from the same hash-pinned wheel, and the
# verifier tooling from a hash-pinned lockfile. Nothing is installed at trial time.
COPY zig-requirements.txt requirements.txt /tmp/
RUN pip install --no-cache-dir --require-hashes --no-deps -r /tmp/zig-requirements.txt && rm -f /tmp/zig-requirements.txt
RUN pip install --no-cache-dir --require-hashes --no-deps -r /tmp/requirements.txt && rm -f /tmp/requirements.txt
RUN /usr/local/lib/python3.13/site-packages/ziglang/zig version

COPY --from=launcher /tool_launch /usr/local/bin/tool_launch
RUN useradd --create-home --uid 10001 --shell /bin/bash runner

# Landing directory for the declared artifact.
RUN mkdir -p /app/flowkit/src /app/flowkit/bin
RUN chown -R runner:runner /app && chmod 1755 /app

# The archives, the reports and the service. Root only, and never present in any container
# the agent reaches.
COPY data /opt/truth
COPY golden /opt/truth/golden
COPY archive /opt/archive
RUN chmod 700 /opt/truth /opt/archive

# Separate mode does not upload tests/ into the image, so the image owns /tests itself.
COPY . /tests/

WORKDIR /app/flowkit
