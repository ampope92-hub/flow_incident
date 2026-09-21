# Agent image. Nothing from tests/ or solution/ may ever be copied in here.
#
# Pin the base by digest so the image can never drift. To re-pin after changing the
# tag:  docker buildx imagetools inspect <image>:<tag>
# REPLACE this base with whatever your task actually needs.
FROM public.ecr.aws/docker/library/gcc:13-bookworm@sha256:930f2ebe239275fa67226654cb79273ea34eee672ae61c8a39f689c37fb7ac5c

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        asciinema \
        ca-certificates \
        python3 \
        tmux \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY app/src/ /app/src/
COPY app/data/ /app/data/
