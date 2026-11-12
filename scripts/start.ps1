# One-command start on Windows Docker Desktop.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
& powershell -NoProfile -ExecutionPolicy Bypass -File "scripts\bootstrap.ps1"
if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "bootstrap failed" }
docker compose up -d --build
if ($LASTEXITCODE -ne 0) { throw "docker compose up failed" }

$port = "8080"
Get-Content ".env" | ForEach-Object {
    if ($_ -match '^HTTP_PORT=(\d+)') { $port = $Matches[1] }
}
Write-Host "[start] waiting for health endpoint..."
for ($i = 0; $i -lt 40; $i++) {
    try {
        $r = Invoke-WebRequest -Uri "http://127.0.0.1:$port/api/health" -UseBasicParsing -TimeoutSec 5
        if ($r.StatusCode -eq 200) {
            Write-Host "[start] healthy: http://127.0.0.1:$port  (/api/health = 200)"
            docker compose ps
            exit 0
        }
    } catch { }
    Start-Sleep -Seconds 3
}
Write-Error "[start] health check did not become 200"
docker compose logs --tail=60 backend
exit 1
