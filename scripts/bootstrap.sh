#!/usr/bin/env bash
# Create .env from the public example and generate strong local credentials.
# Linux / macOS / Git Bash. Never prints the generated values.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ ! -f .env ]; then
  cp .env.example .env
  echo "[bootstrap] .env created from .env.example"
fi

rand_hex() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex "$1"
  else
    od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'
  fi
}

secret="$(rand_hex 32)"
password="$(rand_hex 16)"

# awk (not sed -i) for macOS/BSD portability. Redirect back into .env so the
# inode is preserved even when a container already bind-mounts this single file.
awk -v secret="$secret" -v password="$password" '
  /^AUTH_SECRET_KEY=[[:space:]]*$/ { print "AUTH_SECRET_KEY=" secret; next }
  /^AUTH_PASSWORD=[[:space:]]*$/   { print "AUTH_PASSWORD=" password; next }
  { print }
' .env > .env.tmp
cat .env.tmp > .env
rm -f .env.tmp

if grep -qE '^AUTH_SECRET_KEY=[[:space:]]*$|^AUTH_PASSWORD=[[:space:]]*$' .env; then
  echo "[bootstrap] ERROR: credentials still empty; edit .env manually" >&2
  exit 1
fi
echo "[bootstrap] ready. Credentials are stored in .env (gitignored)."
