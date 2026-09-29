#!/usr/bin/env pwsh
# Stop Lono. Containers and named volumes are preserved.
[CmdletBinding()]
param([switch]$RemoveVolumes)
$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $root
$composeArgs = @("compose", "down")
if ($RemoveVolumes) { $composeArgs += "-v" }
docker @composeArgs
Write-Host "Lono stopped." -ForegroundColor Green