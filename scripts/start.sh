#!/usr/bin/env bash
# Start Lono.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
if [ ! -f .env ]; then
  echo "No .env found. Run ./scripts/install.sh first." >&2
  exit 1
fi
docker compose up -d "$@"
echo "Lono requested. Health: http://127.0.0.1:4000/healthz"