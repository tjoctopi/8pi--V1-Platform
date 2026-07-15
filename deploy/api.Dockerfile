# 8π Engine API — FastAPI over the REAL attack_engine, served by uvicorn.
#
# This replaces the legacy prototype backend/ as the deployed backend. It spawns
# sandboxed security-tool containers on the HOST Docker via the mounted socket
# (docker-out-of-docker), so the image ships the docker CLI (not a daemon).
# The docker CLI is copied from the official image (reliable + small — we only
# need the client to talk to the mounted host socket, not a daemon).
FROM docker:27-cli AS dockercli

FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker

WORKDIR /app

# Install the engine + api extra (fastapi, uvicorn, pyjwt). Deps first for layer caching.
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir ".[api,postgres,redis,neo4j]" boto3

# Persistent dir for the SQLite audit chain + shell (users/engagement metadata).
RUN mkdir -p /app/data
ENV AE_API_PORT=8000 \
    AE_API_DB=/app/data/api_shell.db \
    AE_AUDIT_SQLITE_PATH=/app/data/audit.db

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS http://localhost:8000/api/health || exit 1

# app.py's __main__ runs uvicorn on 0.0.0.0:$AE_API_PORT
CMD ["python", "-m", "attack_engine.api.app"]
