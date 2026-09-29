#!/usr/bin/env pwsh
# Lono installer for Windows (Docker Desktop + PowerShell 7+).
[CmdletBinding()]
param(
    [switch]$SkipPull,
    [switch]$NoStart
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $root

function New-HexSecret {
    param([int]$Bytes = 32)
    $buffer = New-Object byte[] $Bytes
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($buffer)
    return [Convert]::ToHexString($buffer).ToLowerInvariant()
}

function Read-EnvValue {
    param([string]$Name, [string]$Default = "")
    $line = Get-Content (Join-Path $root ".env") | Where-Object { $_ -match "^$([regex]::Escape($Name))=" } | Select-Object -First 1
    if (-not $line) { return $Default }
    return $line.Substring($Name.Length + 1)
}

try {
    docker compose version | Out-Null
} catch {
    throw "Docker with Compose v2 is required. Install Docker Desktop and make sure 'docker' is on PATH."
}

$envPath = Join-Path $root ".env"
if (-not (Test-Path $envPath)) {
    Write-Host "Generating .env with fresh secrets..." -ForegroundColor Cyan
    $template = Get-Content (Join-Path $root ".env.example") -Raw
    $replacements = [ordered]@{
        "__LONO_ADMIN_KEY__"      = "sk-lono-admin-" + (New-HexSecret 24)
        "__PSEUDONYM_SECRET__"    = New-HexSecret 32
        "__LITELLM_MASTER_KEY__"  = "sk-lono-" + (New-HexSecret 24)
        "__NEXTAUTH_SECRET__"     = New-HexSecret 32
        "__SALT__"                = New-HexSecret 16
        "__ENCRYPTION_KEY__"      = New-HexSecret 32
        "__LANGFUSE_PUBLIC_KEY__" = "pk-lf-" + (New-HexSecret 16)
        "__LANGFUSE_SECRET_KEY__" = "sk-lf-" + (New-HexSecret 24)
        "__LANGFUSE_PASSWORD__"   = New-HexSecret 12
        "__POSTGRES_PASSWORD__"   = New-HexSecret 16
        "__CLICKHOUSE_PASSWORD__" = New-HexSecret 16
        "__REDIS_AUTH__"          = New-HexSecret 16
        "__MINIO_ROOT_PASSWORD__" = New-HexSecret 16
    }
    foreach ($entry in $replacements.GetEnumerator()) {
        $template = $template.Replace($entry.Key, $entry.Value)
    }
    Set-Content -Path $envPath -Value $template -NoNewline
} else {
    Write-Host ".env already exists; keeping existing secrets." -ForegroundColor Yellow
}

New-Item -ItemType Directory -Force -Path (Join-Path $root "data/gateway") | Out-Null

if (-not $SkipPull) {
    Write-Host "Pulling container images..." -ForegroundColor Cyan
    docker compose pull
}

if ($NoStart) {
    Write-Host "Install complete. Start later with: .\scripts\start.ps1"
    exit 0
}

Write-Host "Starting Lono..." -ForegroundColor Cyan
docker compose up -d

$gatewayPort = Read-EnvValue "GATEWAY_PORT" "4000"
$healthUrl = "http://127.0.0.1:$gatewayPort/healthz"
$deadline = (Get-Date).AddMinutes(5)
$healthy = $false
while ((Get-Date) -lt $deadline) {
    try {
        Invoke-WebRequest -Uri $healthUrl -UseBasicParsing -TimeoutSec 3 | Out-Null
        $healthy = $true
        break
    } catch {
        Start-Sleep -Seconds 5
    }
}

if (-not $healthy) {
    Write-Warning "Gateway did not become healthy yet. Check logs: docker compose logs -f gateway"
} else {
    Write-Host "Lono is up." -ForegroundColor Green
}

$masterKey = Read-EnvValue "LITELLM_MASTER_KEY"
$adminKey = Read-EnvValue "LONO_ADMIN_KEY"
Write-Host ""
Write-Host "Gateway:        http://127.0.0.1:$gatewayPort/v1  (OpenAI-compatible)"
Write-Host "Anthropic API:  http://127.0.0.1:$gatewayPort/v1/messages"
Write-Host "Console (UI):   http://127.0.0.1:$gatewayPort/ui  (enter the admin key)"
Write-Host "Langfuse UI:    http://127.0.0.1:3000  (login: admin@lono.local / $((Read-EnvValue 'LANGFUSE_INIT_USER_PASSWORD')))"
Write-Host "MinIO console:  http://127.0.0.1:9091"
Write-Host "Audit API key:  $adminKey"
Write-Host ""
Write-Host "Add to OpenCode (~/.config/opencode/opencode.json or project opencode.json):"
Write-Host @"
{
  "provider": {
    "lono": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "Lono Gateway",
      "options": {
        "baseURL": "http://127.0.0.1:$gatewayPort/v1",
        "apiKey": "$masterKey"
      },
      "models": {
        "deepseek-v4.1-flash": { "name": "DeepSeek V4.1 Flash" },
        "gpt-4o-mini": { "name": "GPT-4o mini" },
        "claude-sonnet-4": { "name": "Claude Sonnet 4" },
        "deepinfra-deepseek-v4-flash": { "name": "DeepInfra DeepSeek V4 Flash" },
        "lithos-kimi-k3": { "name": "Lithos Kimi K3" },
        "morph-kimi-k3": { "name": "Morph Kimi K3" },
        "openrouter-claude-sonnet-4": { "name": "OpenRouter Claude Sonnet 4" }
      }
    }
  }
}
"@ -ForegroundColor Gray