# syntax=docker/dockerfile:1.7
#
# Monorepo developer/CI image.
#
# This image is intentionally a workspace runner, not the production console
# image. The privileged console deploy continues to use
# acgi-ai/infra/Dockerfile.console so Cloud Run stays aligned with acgi-ai/DEPLOY.md.

FROM ghcr.io/astral-sh/uv:0.5.31 AS uv

FROM node:24-bookworm-slim AS workspace

ARG DEBIAN_FRONTEND=noninteractive

ENV PNPM_HOME=/pnpm
ENV PATH=/pnpm:/root/.local/bin:$PATH
ENV UV_LINK_MODE=copy

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    bash \
    build-essential \
    ca-certificates \
    curl \
    git \
    make \
    openssh-client \
    pkg-config \
    python3 \
    python3-venv \
  && rm -rf /var/lib/apt/lists/*

RUN corepack enable \
  && corepack prepare pnpm@9.15.4 --activate

COPY --from=uv /uv /uvx /usr/local/bin/

WORKDIR /workspace

# Source is mounted by Compose for normal development. Dependency installation
# is kept as an explicit `make install` / package-specific command so this
# image can build even when optional nested repos are not checked out.

CMD ["bash"]
