<#
.SYNOPSIS
Ставит автообновление списка RU Direct для AmneziaVPN на Windows.

.DESCRIPTION
Копирует updater в %LOCALAPPDATA%\AmneziaRouteSync, прогоняет self-test и dry-run
и только после успешной проверки регистрирует Scheduled Task: обновление при входе
в систему и каждые 6 часов.

Задача регистрируется с наивысшими правами: чтобы применить новый список без
перезагрузки Windows, updater перезапускает службу AmneziaVPN-service. Поэтому и
установщик нужно запускать от имени администратора.
#>

[CmdletBinding()]
param(
    [switch]$Lite,
    [switch]$ReplaceAll,
    [ValidateRange(-1, 10000)]
    [int]$ServerIndex = -1,
    [string]$Source
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if ($env:OS -ne 'Windows_NT') { throw 'Этот installer предназначен только для Windows.' }
if (-not $env:LOCALAPPDATA) { throw 'Не определён LOCALAPPDATA текущего пользователя.' }

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$CurrentSid = $identity.User.Value
if ($CurrentSid -eq 'S-1-5-18') { throw 'Installer нельзя запускать от SYSTEM: настройки лежат в HKCU пользователя.' }
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Запустите PowerShell от имени администратора: без этого задача не сможет перезапускать службу AmneziaVPN-service.'
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SourceScript = Join-Path $ScriptDir 'update-amnezia-routes.ps1'
if (-not (Test-Path -LiteralPath $SourceScript -PathType Leaf)) { throw "Не найден $SourceScript" }

$InstallDir = Join-Path $env:LOCALAPPDATA 'AmneziaRouteSync'
$InstalledScript = Join-Path $InstallDir 'update-amnezia-routes.ps1'
$TaskName = "Amnezia-Split-Route-Sync-$CurrentSid"
$PowerShellExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
if (-not (Test-Path -LiteralPath $PowerShellExe -PathType Leaf)) { throw "Не найден $PowerShellExe" }

if ($Source) {
    if ($Source -match '["\r\n]') { throw 'Источник не должен содержать кавычки или переносы строк.' }
    if (-not $Source.StartsWith('https://', [StringComparison]::OrdinalIgnoreCase)) {
        $Source = (Resolve-Path -LiteralPath $Source -ErrorAction Stop).ProviderPath
    }
}
$updaterArguments = New-Object 'System.Collections.Generic.List[string]'
if ($Lite) { [void]$updaterArguments.Add('-Lite') }
if ($ReplaceAll) { [void]$updaterArguments.Add('-ReplaceAll') }
if ($Source) { [void]$updaterArguments.Add("-Source `"$Source`"") }
if ($ServerIndex -ge 0) { [void]$updaterArguments.Add("-ServerIndex $ServerIndex") }
$updaterArgumentText = ($updaterArguments -join ' ')

$stagingDir = Join-Path $env:TEMP ("amnezia-route-stage-{0}" -f [Guid]::NewGuid().ToString('N'))
$backupDir = Join-Path $env:TEMP ("amnezia-route-backup-{0}" -f [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($stagingDir) | Out-Null
[IO.Directory]::CreateDirectory($backupDir) | Out-Null

$stagedScript = Join-Path $stagingDir 'update-amnezia-routes.ps1'
$scriptExisted = $false
$taskWasPresent = $false
$oldTaskXml = $null
$mutationStarted = $false
$installComplete = $false
$keepBackup = $false

try {
    Copy-Item -LiteralPath $SourceScript -Destination $stagedScript -Force

    & $PowerShellExe -NoProfile -ExecutionPolicy Bypass -File $stagedScript -SelfTest
    if ($LASTEXITCODE -ne 0) { throw 'Self-test updater завершился ошибкой; ничего не установлено.' }

    $dryRunArguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $stagedScript, '-DryRun')
    if ($Lite) { $dryRunArguments += '-Lite' }
    if ($Source) { $dryRunArguments += @('-Source', $Source) }
    & $PowerShellExe @dryRunArguments
    if ($LASTEXITCODE -ne 0) { throw 'Dry-run updater завершился ошибкой; ничего не установлено.' }

    [IO.Directory]::CreateDirectory($InstallDir) | Out-Null
    $scriptExisted = Test-Path -LiteralPath $InstalledScript -PathType Leaf
    if ($scriptExisted) { Copy-Item -LiteralPath $InstalledScript -Destination (Join-Path $backupDir 'update-amnezia-routes.ps1') -Force }

    $oldTasks = @(Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
    if ($oldTasks.Count -gt 1) { throw 'Task Scheduler вернул несколько задач с одним именем.' }
    if ($oldTasks.Count -eq 1) {
        $taskWasPresent = $true
        $oldTaskXml = Export-ScheduledTask -TaskName $TaskName
    }

    $mutationStarted = $true
    $temporaryTarget = Join-Path $InstallDir ".update-amnezia-routes.ps1.new.$PID"
    Copy-Item -LiteralPath $stagedScript -Destination $temporaryTarget -Force
    if ([IO.File]::Exists($InstalledScript)) { [IO.File]::Replace($temporaryTarget, $InstalledScript, [NullString]::Value) }
    else { [IO.File]::Move($temporaryTarget, $InstalledScript) }

    $taskArgumentText = "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstalledScript`""
    if ($updaterArgumentText) { $taskArgumentText = "$taskArgumentText $updaterArgumentText" }
    $action = New-ScheduledTaskAction -Execute $PowerShellExe -Argument $taskArgumentText -WorkingDirectory $InstallDir
    $user = $identity.Name
    # Без задержки задача стартует одновременно с автозапуском самой AmneziaVPN и
    # перезапускает AmneziaVPN-service прямо посреди её подключения: приложение
    # остаётся в трее с бесконечным «подключением». Три минуты дают Amnezia
    # подняться и подключиться до того, как updater тронет службу.
    $logonTrigger = New-ScheduledTaskTrigger -AtLogOn -User $user
    $logonTrigger.Delay = 'PT3M'
    $triggers = @(
        $logonTrigger,
        (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) `
            -RepetitionInterval (New-TimeSpan -Hours 6) -RepetitionDuration (New-TimeSpan -Days 3650))
    )
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -MultipleInstances IgnoreNew `
        -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5) `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
    $task = New-ScheduledTask -Action $action -Trigger $triggers -Principal $taskPrincipal -Settings $settings `
        -Description 'Amnezia Route Sync: обновление списка RU Direct в split tunneling AmneziaVPN'
    Register-ScheduledTask -TaskName $TaskName -InputObject $task -Force | Out-Null

    $registeredTasks = @(Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop)
    if ($registeredTasks.Count -ne 1) { throw 'Task Scheduler не сохранил задачу.' }

    $installComplete = $true
    Start-ScheduledTask -TaskName $TaskName

    Write-Host "Установлено: $InstalledScript"
    Write-Host 'Обновление: при входе в Windows и каждые 6 часов.'
    Write-Host 'При смене списка updater сам закрывает AmneziaVPN, перезапускает службу и поднимает соединение — перезагрузка Windows не нужна.'
    Write-Host "Статус: Get-ScheduledTask -TaskName '$TaskName'"
    Write-Host "Результат последнего запуска: Get-Content `"$InstallDir\status.json`""
} catch {
    if ($mutationStarted -and -not $installComplete) {
        try {
            $rollbackTasks = @(Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
            if ($rollbackTasks.Count -ge 1) { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop }
            if ($taskWasPresent -and $oldTaskXml) {
                Register-ScheduledTask -TaskName $TaskName -Xml $oldTaskXml -Force | Out-Null
            }
            if ($scriptExisted) {
                Copy-Item -LiteralPath (Join-Path $backupDir 'update-amnezia-routes.ps1') -Destination $InstalledScript -Force
            } elseif (Test-Path -LiteralPath $InstalledScript) {
                Remove-Item -LiteralPath $InstalledScript -Force
            }
            Write-Warning 'Установка не завершена; предыдущее состояние восстановлено.'
        } catch {
            $keepBackup = $true
            Write-Error "АВАРИЯ: rollback installer неполный; backup сохранён: $backupDir"
        }
    }
    throw
} finally {
    Remove-Item -LiteralPath $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
    if (-not $keepBackup) { Remove-Item -LiteralPath $backupDir -Recurse -Force -ErrorAction SilentlyContinue }
}
