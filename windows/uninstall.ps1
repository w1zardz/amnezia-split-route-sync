<#
.SYNOPSIS
Снимает автообновление списка RU Direct для AmneziaVPN на Windows.

.DESCRIPTION
Убирает Scheduled Task и приватные файлы из %LOCALAPPDATA%\AmneziaRouteSync.
Незавершённая routing-транзакция сначала докатывается, чтобы не оставить
Preferences AmneziaVPN в промежуточном состоянии.

Сам список в AmneziaVPN не трогается: его чистят в интерфейсе приложения.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if ($env:OS -ne 'Windows_NT') { throw 'Этот uninstaller предназначен только для Windows.' }
if (-not $env:LOCALAPPDATA) { throw 'Не определён LOCALAPPDATA текущего пользователя.' }

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$CurrentSid = $identity.User.Value
if ($CurrentSid -eq 'S-1-5-18') { throw 'Uninstaller нельзя запускать от SYSTEM.' }

$InstallDir = Join-Path $env:LOCALAPPDATA 'AmneziaRouteSync'
$InstalledScript = Join-Path $InstallDir 'update-amnezia-routes.ps1'
$JournalPath = Join-Path $InstallDir '.registry-transaction.json'
$TaskName = "Amnezia-Split-Route-Sync-$CurrentSid"
$PowerShellExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

$tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -ceq $TaskName })
foreach ($task in $tasks) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
}
$remaining = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -ceq $TaskName })
if ($remaining.Count -ne 0) { throw 'Не удалось снять Scheduled Task; удаление остановлено.' }

if (Test-Path -LiteralPath $JournalPath -PathType Leaf) {
    if (-not (Test-Path -LiteralPath $InstalledScript -PathType Leaf)) {
        throw 'Найдена незавершённая транзакция, но updater отсутствует; удаление остановлено.'
    }
    & $PowerShellExe -NoProfile -ExecutionPolicy Bypass -File $InstalledScript -RecoverOnly
    if ($LASTEXITCODE -ne 0) { throw 'Routing recovery не завершён; файлы сохранены.' }
}
if (Test-Path -LiteralPath $JournalPath -PathType Leaf) {
    throw 'Routing recovery не завершён; файлы сохранены.'
}

if (Test-Path -LiteralPath $InstallDir) {
    Remove-Item -LiteralPath $InstallDir -Recurse -Force -ErrorAction Stop
}
if (Test-Path -LiteralPath $InstallDir) { throw 'Не удалось полностью удалить приватные файлы automation.' }

Write-Host 'Автоматизация удалена. Список RU Direct остался в AmneziaVPN — очистите его в интерфейсе приложения при необходимости.'
