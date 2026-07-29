# syntax=docker/dockerfile:1

# ---- Builder -------------------------------------------------------------
# Resolve dependencies into a self-contained virtualenv so the runtime image
# carries no build tooling or package cache.
FROM python:3.12-slim AS builder

# Pinned so a new uv release can't silently invalidate this layer.
COPY --from=ghcr.io/astral-sh/uv:0.5.11 /uv /usr/local/bin/uv

# `lose-it` is a git dependency, so the resolver needs a git client. This stays
# in the builder stage only — the runtime image ships no build tooling. The
# cache mounts keep package lists out of the layer and make rebuilds cheap.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update \
    && apt-get install -y --no-install-recommends git

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# Dependency layer first, and *only* the files that affect resolution. Editing
# source or docs leaves this layer cached, so the expensive step — cloning the
# git-sourced SDK and building wheels — is skipped on almost every rebuild.
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-dev

# Source last: this is what actually changes between builds.
COPY README.md ./
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev

# ---- Runtime -------------------------------------------------------------
FROM python:3.12-slim AS runtime

# Run unprivileged. Azure App Service does not require root, and the app never
# writes outside its own data directory.
RUN groupadd --system --gid 1001 app \
    && useradd --system --uid 1001 --gid app --create-home app \
    && mkdir -p /data \
    && chown app:app /data

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LOSEIT_MULTI_TENANT=1 \
    LOSEIT_ENROLLMENT_PATH=/data/enrollments.json \
    PORT=8000

WORKDIR /app

COPY --from=builder --chown=app:app /app/.venv /app/.venv
COPY --from=builder --chown=app:app /app/src /app/src

USER app

# Enrollments must outlive the container. Mount a volume here, or point
# LOSEIT_ENROLLMENT_PATH at App Service's persistent /home share.
VOLUME ["/data"]

EXPOSE 8000

# Azure App Service pings the root path; the server answers /healthz.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os,urllib.request,sys; \
url=f\"http://127.0.0.1:{os.environ.get('PORT','8000')}/healthz\"; \
sys.exit(0 if urllib.request.urlopen(url, timeout=4).status == 200 else 1)"

# Exec form so the process is PID 1 and receives SIGTERM directly, letting
# Azure drain connections on restart instead of waiting for a kill.
CMD ["sh", "-c", "loseit-mcp serve --transport streamable-http --host 0.0.0.0 --port ${PORT}"]
