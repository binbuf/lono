#!/usr/bin/env bash
# Lono installer for macOS / Linux (Docker or Podman with compose).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SKIP_PULL=0
NO_START=0
for arg in "$@"; do
  case "$arg" in
    --skip-pull) SKIP_PULL=1 ;;
    --no-start) NO_START=1 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

random_hex() {
  local bytes="${1:-32}"
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex "$bytes"
  else
    od -An -N "$bytes" -tx1 /dev/urandom | tr -d ' \n'
  fi
}

if ! docker compose version >/dev/null 2>&1; then
  echo "Docker with Compose v2 is required (or Podman with docker-compose)." >&2
  exit 1
fi

if [ ! -f .env ]; then
  echo "Generating .env with fresh secrets..."
  cp .env.example .env
  repl() { sed "s|$1|$2|g" .env > .env.tmp && mv .env.tmp .env; }
  repl "__LONO_ADMIN_KEY__" "sk-lono-admin-$(random_hex 24)"
  repl "__PSEUDONYM_SECRET__" "$(random_hex 32)"
  repl "__LITELLM_MASTER_KEY__" "sk-lono-$(random_hex 24)"
  repl "__NEXTAUTH_SECRET__" "$(random_hex 32)"
  repl "__SALT__" "$(random_hex 16)"
  repl "__ENCRYPTION_KEY__" "$(random_hex 32)"
  repl "__LANGFUSE_PUBLIC_KEY__" "pk-lf-$(random_hex 16)"
  repl "__LANGFUSE_SECRET_KEY__" "sk-lf-$(random_hex 24)"
  repl "__LANGFUSE_PASSWORD__" "$(random_hex 12)"
  repl "__POSTGRES_PASSWORD__" "$(random_hex 16)"
  repl "__CLICKHOUSE_PASSWORD__" "$(random_hex 16)"
  repl "__REDIS_AUTH__" "$(random_hex 16)"
  repl "__MINIO_ROOT_PASSWORD__" "$(random_hex 16)"
  repl "^LONO_UID=.*" "LONO_UID=$(id -u)"
  repl "^LONO_GID=.*" "LONO_GID=$(id -g)"
else
  echo ".env already exists; keeping existing secrets."
fi

env_value() {
  local name="$1" default="${2:-}"
  local line
  line="$(grep -E "^${name}=" .env | tail -n 1 || true)"
  if [ -z "$line" ]; then echo "$default"; else echo "${line#*=}"; fi
}

mkdir -p data/gateway

if [ "$SKIP_PULL" -eq 0 ]; then
  echo "Pulling container images..."
  docker compose pull
fi

if [ "$NO_START" -eq 1 ]; then
  echo "Install complete. Start later with: ./scripts/start.sh"
  exit 0
fi

echo "Starting Lono..."
docker compose up -d

GATEWAY_PORT="$(env_value GATEWAY_PORT 4000)"
health_url="http://127.0.0.1:${GATEWAY_PORT}/healthz"
healthy=0
for _ in $(seq 1 60); do
  if curl -fsS --max-time 3 "$health_url" >/dev/null 2>&1; then
    healthy=1
    break
  fi
  sleep 5
done

if [ "$healthy" -eq 1 ]; then
  echo "Lono is up."
else
  echo "Warning: gateway did not become healthy yet. Check: docker compose logs -f gateway" >&2
fi

MASTER_KEY="$(env_value LITELLM_MASTER_KEY)"
ADMIN_KEY="$(env_value LONO_ADMIN_KEY)"
LANGFUSE_PASSWORD="$(env_value LANGFUSE_INIT_USER_PASSWORD)"
cat <<EOF

Gateway:        http://127.0.0.1:${GATEWAY_PORT}/v1  (OpenAI-compatible)
Anthropic API:  http://127.0.0.1:${GATEWAY_PORT}/v1/messages
Console (UI):   http://127.0.0.1:${GATEWAY_PORT}/ui  (enter the admin key)
Langfuse UI:    http://127.0.0.1:3000  (login: admin@lono.local / ${LANGFUSE_PASSWORD})
MinIO console:  http://127.0.0.1:9091
Audit API key:  ${ADMIN_KEY}

Add to OpenCode (~/.config/opencode/opencode.json or project opencode.json):
{
  "provider": {
    "lono": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "Lono Gateway",
      "options": {
        "baseURL": "http://127.0.0.1:${GATEWAY_PORT}/v1",
        "apiKey": "${MASTER_KEY}"
      },
      "models": {
        "deepseek-v4.1-flash": { "name": "DeepSeek V4.1 Flash" },
        "gpt-4o-mini": { "name": "GPT-4o mini" },
        "claude-sonnet-4": { "name": "Claude Sonnet 4" }
      }
    }
  }
}
EOF