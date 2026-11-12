# Official public base image. No private registry, no host-mounted tool directories.
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DATA_DIR=/data \
    APP_HOST=0.0.0.0 \
    APP_PORT=8787 \
    AI_AUDIT_ENV_FILE=/app/.env \
    OSV_SCANNER_PATH=/opt/scanner-tools/bin/osv-scanner \
    PATH="/opt/scanner-tools/bin:/opt/scanner-tools/codeql:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin"

# System dependencies:
#  - curl/git         : healthcheck + repository cloning
#  - unzip/ca-certs   : scanner CLI installation
#  - pango/cairo/ffi  : WeasyPrint PDF report engine
#  - fonts-noto-cjk   : Chinese text in exported PDF reports
#  - nodejs/npm       : npm_audit scanner

# CodeQL (Java deep analysis) is OPT-IN. Its CLI is ~400 MB and it is the only
# consumer of the JDK/Maven toolchain, so both are gated behind one build arg.
# Enable: docker compose build --build-arg INSTALL_CODEQL=1  (or INSTALL_CODEQL=1 in .env)
ARG INSTALL_CODEQL=0

RUN apt-get update && apt-get install -y --no-install-recommends \
      curl ca-certificates git unzip \
      libpango-1.0-0 libpangocairo-1.0-0 libcairo2 libgdk-pixbuf-2.0-0 \
      libffi8 shared-mime-info fonts-noto-cjk \
      nodejs npm procps \
    && if [ "$INSTALL_CODEQL" = "1" ]; then \
         apt-get install -y --no-install-recommends default-jdk-headless maven; \
       fi \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Scanner CLIs installed from public upstreams, inside the image (no host tools needed).
# Kept BEFORE the Python dependency layer on purpose: this layer downloads ~400 MB
# (CodeQL CLI) and changes far less often than requirements.txt. Putting it first means
# a dependency bump no longer forces a full re-download.
COPY backend/scripts/install-scanner-tools.sh /opt/install-scanner-tools.sh
RUN INSTALL_CODEQL="$INSTALL_CODEQL" sh /opt/install-scanner-tools.sh \
    && rm -f /opt/install-scanner-tools.sh

# Python dependencies (includes bandit + pip-audit scanners, FastAPI, WeasyPrint).
COPY backend/requirements.txt /app/requirements.txt
RUN python -m pip install --no-cache-dir -r /app/requirements.txt

COPY backend/app/ /app/app/
COPY backend/migrations/ /app/migrations/
COPY backend/samples/ /app/samples/

RUN mkdir -p /data && chmod 700 /data

EXPOSE 8787

HEALTHCHECK --interval=15s --timeout=5s --start-period=40s --retries=5 \
  CMD curl -fsS http://127.0.0.1:8787/api/health || exit 1

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8787"]
