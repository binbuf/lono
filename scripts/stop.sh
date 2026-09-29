#!/usr/bin/env bash
# Stop Lono. Containers and named volumes are preserved.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
if [ "${1:-}" = "--remove-volumes" ]; then
  docker compose down -v
else
  docker compose down
fi
echo "Lono stopped."