#!/bin/sh
# Install the scanner CLIs used by app/services/scanners/* into the image.
# All downloads come from public upstreams; no private registry or host tools.
set -eu

TOOLS=/opt/scanner-tools
BIN="$TOOLS/bin"
SEMGREP_LIBS=/opt/semgrep-libs
GITLEAKS_VERSION=8.24.3
OSV_SCANNER_VERSION=2.0.2

# CodeQL is OPT-IN (default 0): its CLI is ~400 MB and it is only used for Java
# deep analysis. Enable with the compose build arg INSTALL_CODEQL=1.
INSTALL_CODEQL="${INSTALL_CODEQL:-0}"

mkdir -p "$BIN" "$TOOLS"

echo "[scanners] gitleaks v${GITLEAKS_VERSION}"
curl -fsSL --retry 3 \
  "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
  | tar -xz -C "$BIN" gitleaks
chmod +x "$BIN/gitleaks"

echo "[scanners] osv-scanner v${OSV_SCANNER_VERSION}"
curl -fsSL --retry 3 -o "$BIN/osv-scanner" \
  "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64"
chmod +x "$BIN/osv-scanner"

if [ "$INSTALL_CODEQL" = "1" ]; then
  echo "[scanners] CodeQL CLI (INSTALL_CODEQL=1, ~400 MB)"
  CODEQL_ZIP="$(mktemp)"
  curl -fsSL --retry 3 -o "$CODEQL_ZIP" \
    "https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip"
  unzip -q -o "$CODEQL_ZIP" -d "$TOOLS"
  rm -f "$CODEQL_ZIP"
  chmod +x "$TOOLS/codeql/codeql"
else
  echo "[scanners] CodeQL CLI skipped (INSTALL_CODEQL=0) - Java deep analysis unavailable"
fi

echo "[scanners] semgrep (isolated --target install, avoids polluting app deps)"
python -m pip install --no-cache-dir --quiet --target "$SEMGREP_LIBS" semgrep
# Newer semgrep ships an OCaml launcher that re-execs the "pysemgrep" console
# script through execvp(), so $SEMGREP_LIBS/bin MUST be on PATH. PYTHONPATH alone
# is not enough (fails with: execvp pysemgrep: No such file or directory).
cat > "$BIN/semgrep" <<EOF
#!/bin/sh
export PYTHONPATH="$SEMGREP_LIBS\${PYTHONPATH:+:\$PYTHONPATH}"
export PATH="$SEMGREP_LIBS/bin:\$PATH"
# Keep the container offline-friendly and quiet: no metrics, no version check.
export SEMGREP_SEND_METRICS=off
export SEMGREP_ENABLE_VERSION_CHECK=0
exec "$SEMGREP_LIBS/bin/semgrep" "\$@"
EOF
chmod +x "$BIN/semgrep"

echo "[scanners] verifying"
for tool in gitleaks osv-scanner semgrep; do
  test -x "$BIN/$tool" || { echo "ERROR: missing $BIN/$tool" >&2; exit 1; }
done
if [ "$INSTALL_CODEQL" = "1" ]; then
  test -x "$TOOLS/codeql/codeql" || { echo "ERROR: missing CodeQL CLI" >&2; exit 1; }
fi
"$BIN/gitleaks" version
"$BIN/osv-scanner" --version
if [ "$INSTALL_CODEQL" = "1" ]; then
  "$TOOLS/codeql/codeql" version --format=terse
fi
"$BIN/semgrep" --version
echo "[scanners] all CLIs installed"
