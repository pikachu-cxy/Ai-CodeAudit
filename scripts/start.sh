#!/usr/bin/env bash
# One-command start: bootstrap credentials, build images, start the stack.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
bash scripts/bootstrap.sh
docker compose up -d --build
echo ""
echo "[start] waiting for health endpoint..."
PORT="$(grep -E '^HTTP_PORT=' .env | cut -d= -f2 | tr -d '\r' || true)"
PORT="${PORT:-8080}"
for i in $(seq 1 40); do
  code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT}/api/health" || true)"
  if [ "$code" = "200" ]; then
    echo "[start] healthy: http://127.0.0.1:${PORT}  (/api/health = 200)"
    docker compose ps
    exit 0
  fi
  sleep 3
done
echo "[start] ERROR: health check did not become 200" >&2
docker compose ps
docker compose logs --tail=60 backend
exit 1
