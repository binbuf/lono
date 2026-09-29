#!/usr/bin/env pwsh
# Start Lono.
[CmdletBinding()]
param([switch]$Build)
$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $root
if (-not (Test-Path (Join-Path $root ".env"))) {
    throw "No .env found. Run .\scripts\install.ps1 first."
}
$composeArgs = @("compose", "up", "-d")
if ($Build) { $composeArgs += "--build" }
docker @composeArgs
Write-Host "Lono requested. Health: http://127.0.0.1:4000/healthz" -ForegroundColor Green