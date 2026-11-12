# Create .env from the public example and generate strong local credentials.
# Windows PowerShell 5.1+ / PowerShell 7. Never prints the generated values.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "[bootstrap] .env created from .env.example"
}

function New-RandomHex([int]$byteCount) {
    $bytes = New-Object byte[] $byteCount
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return (-join ($bytes | ForEach-Object { $_.ToString("x2") }))
}

$lines = Get-Content ".env"
$changed = $false
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match '^AUTH_SECRET_KEY=\s*$') {
        $lines[$i] = "AUTH_SECRET_KEY=" + (New-RandomHex 32)
        $changed = $true
        Write-Host "[bootstrap] generated AUTH_SECRET_KEY"
    }
    if ($lines[$i] -match '^AUTH_PASSWORD=\s*$') {
        $lines[$i] = "AUTH_PASSWORD=" + (New-RandomHex 16)
        $changed = $true
        Write-Host "[bootstrap] generated AUTH_PASSWORD"
    }
}
if ($changed) {
    # UTF-8 without BOM + LF. Truncate-in-place preserves the bind-mounted inode.
    $text = ($lines -join "`n") + "`n"
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText((Join-Path (Get-Location) ".env"), $text, $utf8NoBom)
}

$content = [System.IO.File]::ReadAllText((Join-Path (Get-Location) ".env"))
if ($content -match '(?m)^AUTH_SECRET_KEY=\s*$' -or $content -match '(?m)^AUTH_PASSWORD=\s*$') {
    throw "[bootstrap] credentials still empty; edit .env manually"
}
Write-Host "[bootstrap] ready. Credentials are stored in .env (gitignored)."
