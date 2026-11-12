# Stop containers but KEEP named volumes (database, repos, reports, settings).
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
docker compose down
if ($LASTEXITCODE -ne 0) { throw "docker compose down failed" }
Write-Host "[stop] stopped. Data volumes are preserved."
