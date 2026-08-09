[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Downloads\Amnezia-RU-Direct.json"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0

$repoRoot = Split-Path -Parent $PSScriptRoot
$configPath = Join-Path $repoRoot "config\custom-host-policy.json"
$generatorPath = Join-Path $repoRoot "tools\generate_amnezia_full_import.py"

if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
    throw "Create config\custom-host-policy.json first. See README: Required configuration."
}

$python = Get-Command "py.exe" -ErrorAction SilentlyContinue
$prefix = @("-3")
if ($null -eq $python) {
    $python = Get-Command "python.exe" -ErrorAction SilentlyContinue
    $prefix = @()
}
if ($null -eq $python) {
    throw "Python 3.10+ not found. Install it from https://www.python.org/downloads/windows/."
}

$outputDirectory = Split-Path -Parent $OutputPath
if ([string]::IsNullOrWhiteSpace($outputDirectory)) {
    throw "OutputPath must include a directory."
}
[IO.Directory]::CreateDirectory($outputDirectory) | Out-Null

$pythonPath = [string]$python.Path
$versionText = (& $pythonPath @prefix --version 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $versionText -notmatch "Python\s+(\d+)\.(\d+)") {
    throw "Unable to verify Python version."
}
if ([int]$Matches[1] -lt 3 -or ([int]$Matches[1] -eq 3 -and [int]$Matches[2] -lt 10)) {
    throw "Python 3.10+ is required; found $versionText."
}
& $pythonPath @prefix $generatorPath --config $configPath --output $OutputPath
if ($LASTEXITCODE -ne 0) {
    throw "JSON generator failed with exit code $LASTEXITCODE."
}

$manifestPath = [IO.Path]::ChangeExtension($OutputPath, ".manifest.json")
$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
$outputHash = (Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($outputHash -ne [string]$manifest.sha256) {
    throw "Generated JSON SHA-256 does not match its manifest."
}

Write-Host ""
Write-Host "READY: $OutputPath" -ForegroundColor Green
Write-Host "Entries: $($manifest.entry_count) CIDR from $($manifest.community_resolved_hostname_count)/$($manifest.community_source_hostname_count) community domains"
Write-Host "Amnezia: Split tunneling -> sites/IP -> addresses from the list must NOT use VPN -> menu -> replace/import list."
Write-Host "No AmneziaVPN settings, Registry values, profiles, or Scheduled Tasks were changed."
