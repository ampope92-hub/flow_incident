# Verifier image. In separate mode harbor does NOT upload tests/ at verify time, so
# this image must own everything the verifier needs: the tests themselves, any held-out
# fixtures, and every tool test.sh invokes. Nothing may be installed at verify time.
FROM public.ecr.aws/docker/library/gcc:13-bookworm@sha256:930f2ebe239275fa67226654cb79273ea34eee672ae61c8a39f689c37fb7ac5c

# Debian marks the system interpreter externally managed, so pytest goes in a venv.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 \
        python3-venv \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /venv \
    && /venv/bin/pip install --no-cache-dir pytest==9.1.1 pytest-json-ctrf==0.5.2

# If the verifier executes anything the agent produced, it is running untrusted code.
# Drop it to an unprivileged user that owns nothing outside its own scratch space.
RUN useradd --system --uid 12000 --user-group --no-create-home --shell /usr/sbin/nologin sandbox \
    && mkdir -p /work/out \
    && chown sandbox:sandbox /work/out \
    && chmod 700 /work/out

COPY test.sh test_outputs.py /tests/
COPY holdout/ /tests/holdout/
RUN chmod -R a+rX /tests/holdout

# Landing directory for the declared artifact. Every artifact path in task.toml needs
# its parent to exist here, or the upload fails with "Could not find the file ...".
RUN mkdir -p /app
