#!/usr/bin/env bash
# Stop containers but KEEP the named volumes (database, repos, reports, settings).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
docker compose down
echo "[stop] stopped. Data volumes are preserved (docker volume ls | grep ai-deep-audit)."
