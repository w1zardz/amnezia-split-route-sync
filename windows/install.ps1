[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if ($env:OS -ne 'Windows_NT') { throw 'Этот installer предназначен только для Windows.' }
if (-not $env:LOCALAPPDATA) { throw 'Не определён LOCALAPPDATA текущего пользователя.' }
$CurrentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($CurrentSid -eq 'S-1-5-18') { throw 'Installer нельзя запускать от SYSTEM.' }

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ConfigDir = Join-Path (Split-Path -Parent $ScriptDir) 'config'
$InstallDir = Join-Path $env:LOCALAPPDATA 'AmneziaRouteSync'
$TaskName = "Amnezia-Split-Route-Sync-$CurrentSid"
$RunSubKey = 'Software\Microsoft\Windows\CurrentVersion\Run'
$RunValueName = 'AmneziaVPN'
$InstallStatePath = Join-Path $InstallDir 'install-state.json'
$PowerShellExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$updatePath = Join-Path $InstallDir 'update-amnezia-routes.ps1'
$startupCommand = "`"$PowerShellExe`" -NoProfile -ExecutionPolicy Bypass -File `"$updatePath`" -ApplyPending -StartAmnezia"
$OwnedFiles = @(
    'update-amnezia-routes.ps1',
    'route-policy.json',
    'custom-host-policy.json'
)

function Get-SourcePath([string]$Name) {
    if ($Name -eq 'update-amnezia-routes.ps1') { return (Join-Path $ScriptDir $Name) }
    return (Join-Path $ConfigDir $Name)
}

function Write-JsonAtomic([string]$Path, $Value) {
    $directory = Split-Path -Parent $Path
    [IO.Directory]::CreateDirectory($directory) | Out-Null
    $temporary = "$Path.tmp.$PID"
    try {
        $json = $Value | ConvertTo-Json -Depth 10
        [IO.File]::WriteAllText($temporary, $json + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false)))
        Move-Item -LiteralPath $temporary -Destination $Path -Force
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

function Find-AmneziaPath([string]$RunCommand) {
    $candidates = New-Object 'System.Collections.Generic.List[string]'
    if ($RunCommand) {
        if ($RunCommand -match '^\s*"([^"]+\.exe)"') { $candidates.Add($Matches[1]) }
        elseif ($RunCommand -match '^\s*(.+?\.exe)(?:\s|$)') { $candidates.Add($Matches[1]) }
    }
    $candidates.Add((Join-Path $env:ProgramFiles 'AmneziaVPN\AmneziaVPN.exe'))
    if (${env:ProgramFiles(x86)}) { $candidates.Add((Join-Path ${env:ProgramFiles(x86)} 'AmneziaVPN\AmneziaVPN.exe')) }
    $candidates.Add((Join-Path $env:LOCALAPPDATA 'Programs\AmneziaVPN\AmneziaVPN.exe'))
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    throw 'Не найден AmneziaVPN.exe. Установите AmneziaVPN 5.x и повторите.'
}

function Restore-File([string]$Name, [string]$BackupDir, [bool]$Existed) {
    $target = Join-Path $InstallDir $Name
    $backup = Join-Path $BackupDir $Name
    if ($Existed -and (Test-Path -LiteralPath $backup)) {
        Copy-Item -LiteralPath $backup -Destination $target -Force
    } else {
        if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Force -ErrorAction Stop }
    }
    if ($Existed -and -not (Test-Path -LiteralPath $target -PathType Leaf)) { throw "Не восстановлен $Name" }
    if (-not $Existed -and (Test-Path -LiteralPath $target)) { throw "Не удалён $Name" }
}

foreach ($name in $OwnedFiles) {
    $source = Get-SourcePath $name
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Не найден source-файл $source" }
}
$null = Get-Content -LiteralPath (Join-Path $ConfigDir 'route-policy.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$null = Get-Content -LiteralPath (Join-Path $ConfigDir 'custom-host-policy.json') -Raw -Encoding UTF8 | ConvertFrom-Json

$runKey = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($RunSubKey, $true)
try {
    $runWasPresentNow = $RunValueName -in @($runKey.GetValueNames())
    $currentRun = $runKey.GetValue($RunValueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    $currentRunKind = if ($runWasPresentNow) { $runKey.GetValueKind($RunValueName) } else { $null }
} finally { $runKey.Dispose() }
$existingInstallState = if (Test-Path -LiteralPath $InstallStatePath -PathType Leaf) {
    Get-Content -LiteralPath $InstallStatePath -Raw -Encoding UTF8 | ConvertFrom-Json
} else { $null }
$hadOriginalRun = $runWasPresentNow
$originalRun = $currentRun
$originalRunKind = if ($runWasPresentNow) { $currentRunKind.ToString() } else { $null }
if ($null -ne $existingInstallState -and
    $existingInstallState.PSObject.Properties.Name -contains 'installed_wrapper_value' -and
    $runWasPresentNow -and
    [string]$currentRun -ceq [string]$existingInstallState.installed_wrapper_value) {
    $hadOriginalRun = [bool]$existingInstallState.original_autostart_present
    $originalRun = [string]$existingInstallState.original_autostart_value
    $originalRunKind = if ($hadOriginalRun) { [string]$existingInstallState.original_autostart_kind } else { $null }
}
$amneziaPath = Find-AmneziaPath ([string]$originalRun)
$productVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($amneziaPath).ProductVersion
$major = 0
if (-not $productVersion -or -not [int]::TryParse(($productVersion -split '\.')[0], [ref]$major) -or $major -ne 5) {
    throw "Поддерживается AmneziaVPN major 5, найдена версия $productVersion"
}

$stagingDir = Join-Path $env:TEMP ("amnezia-route-stage-{0}" -f [Guid]::NewGuid().ToString('N'))
$backupDir = Join-Path $env:TEMP ("amnezia-route-backup-{0}" -f [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($stagingDir) | Out-Null
[IO.Directory]::CreateDirectory($backupDir) | Out-Null
$fileExisted = @{}
$oldTaskXml = $null
$taskWasPresent = $false
$mutationStarted = $false
$installComplete = $false
$rollbackComplete = $false
$installMutex = New-Object Threading.Mutex($false, "Global\Amnezia-Split-Route-Sync-$CurrentSid")
$mutexHeld = $false
$mutexDisposed = $false

try {
    foreach ($name in $OwnedFiles) {
        Copy-Item -LiteralPath (Get-SourcePath $name) -Destination (Join-Path $stagingDir $name) -Force
    }

    & $PowerShellExe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $stagingDir 'update-amnezia-routes.ps1') -DryRun
    if ($LASTEXITCODE -ne 0) { throw 'Windows updater dry-run завершился ошибкой.' }
    try {
        $mutexHeld = $installMutex.WaitOne(660000)
    } catch [Threading.AbandonedMutexException] {
        $mutexHeld = $true
    }
    if (-not $mutexHeld) { throw 'Не удалось дождаться завершения старого updater.' }

    [IO.Directory]::CreateDirectory($InstallDir) | Out-Null
    foreach ($name in $OwnedFiles) {
        $target = Join-Path $InstallDir $name
        $exists = Test-Path -LiteralPath $target -PathType Leaf
        $fileExisted[$name] = $exists
        if ($exists) { Copy-Item -LiteralPath $target -Destination (Join-Path $backupDir $name) -Force }
    }
    if (Test-Path -LiteralPath $InstallStatePath -PathType Leaf) {
        Copy-Item -LiteralPath $InstallStatePath -Destination (Join-Path $backupDir 'install-state.json') -Force
        $fileExisted['install-state.json'] = $true
    } else { $fileExisted['install-state.json'] = $false }

    $oldTasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskName -ceq $TaskName })
    if ($oldTasks.Count -gt 1) { throw 'Task Scheduler вернул несколько задач с одним именем.' }
    $oldTask = if ($oldTasks.Count -eq 1) { $oldTasks[0] } else { $null }
    if ($null -ne $oldTask) {
        $taskWasPresent = $true
        $oldTaskXml = Export-ScheduledTask -TaskName $TaskName
    }
    $mutationStarted = $true

    foreach ($name in $OwnedFiles) {
        $temporaryTarget = Join-Path $InstallDir (".$name.new.$PID")
        Copy-Item -LiteralPath (Join-Path $stagingDir $name) -Destination $temporaryTarget -Force
        Move-Item -LiteralPath $temporaryTarget -Destination (Join-Path $InstallDir $name) -Force
    }

    Write-JsonAtomic $InstallStatePath ([ordered]@{
        version = 1
        amnezia_path = $amneziaPath
        original_autostart_present = [bool]$hadOriginalRun
        original_autostart_value = if ($hadOriginalRun) { [string]$originalRun } else { $null }
        original_autostart_kind = if ($hadOriginalRun) { [string]$originalRunKind } else { $null }
        installed_wrapper_value = if ($hadOriginalRun) { $startupCommand } else { $null }
        installed_at = [DateTime]::UtcNow.ToString('o')
    })

    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$updatePath`""
    $action = New-ScheduledTaskAction -Execute $PowerShellExe -Argument $arguments
    $user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $triggers = @(
        (New-ScheduledTaskTrigger -AtLogOn -User $user),
        (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Hours 6) -RepetitionDuration (New-TimeSpan -Days 3650))
    )
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -RunOnlyIfNetworkAvailable -MultipleInstances IgnoreNew `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
    $task = New-ScheduledTask -Action $action -Trigger $triggers -Principal $principal -Settings $settings `
        -Description 'Amnezia Route Sync: безопасное обновление RU Direct маршрутов AmneziaVPN текущего пользователя'
    Register-ScheduledTask -TaskName $TaskName -InputObject $task -Force | Out-Null
    $registeredTasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskName -ceq $TaskName })
    if ($registeredTasks.Count -ne 1) { throw 'Task Scheduler не сохранил задачу.' }

    if ($hadOriginalRun) {
        $runKey = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($RunSubKey, $true)
        try { $runKey.SetValue($RunValueName, $startupCommand, [Microsoft.Win32.RegistryValueKind]::String) } finally { $runKey.Dispose() }
    }

    $installComplete = $true
    [void]$installMutex.ReleaseMutex()
    $mutexHeld = $false
    $installMutex.Dispose()
    $mutexDisposed = $true
    Start-ScheduledTask -TaskName $TaskName
    Write-Host "Установлено для пользователя ${user}: $InstallDir"
    Write-Host 'Обновление: проверка каждые 6 часов; pending применяется при безопасном старте Amnezia.'
    if ($hadOriginalRun) {
        Write-Host 'Автозапуск Amnezia сохранён: сначала pending-маршруты, затем AmneziaVPN.'
    } else {
        Write-Host 'Автозапуск Amnezia был выключен и остался выключен.'
    }
    Write-Host "Проверка: Get-ScheduledTask -TaskName '$TaskName'"
} catch {
    if ($mutationStarted -and -not $installComplete) {
        try {
            $rollbackTasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskName -ceq $TaskName })
            if ($rollbackTasks.Count -gt 1) { throw 'Task Scheduler вернул несколько задач при rollback.' }
            if ($rollbackTasks.Count -eq 1) {
                Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
            }
            $remainingRollbackTasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskName -ceq $TaskName })
            if ($remainingRollbackTasks.Count -ne 0) { throw 'Не удалось снять новую Scheduled Task при rollback.' }
            if ($taskWasPresent -and $oldTaskXml) {
                Register-ScheduledTask -TaskName $TaskName -Xml $oldTaskXml -Force | Out-Null
                $restoredTasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskName -ceq $TaskName })
                if ($restoredTasks.Count -ne 1) { throw 'Не восстановлена старая Scheduled Task.' }
            }
            foreach ($name in $OwnedFiles) { Restore-File $name $backupDir ([bool]$fileExisted[$name]) }
            Restore-File 'install-state.json' $backupDir ([bool]$fileExisted['install-state.json'])
            $runKey = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($RunSubKey, $true)
            try {
                if ($runWasPresentNow) { $runKey.SetValue($RunValueName, [string]$currentRun, $currentRunKind) }
                else { $runKey.DeleteValue($RunValueName, $false) }
            } finally { $runKey.Dispose() }
            $rollbackComplete = $true
        } catch {
            Write-Error "АВАРИЯ: installer rollback неполный; backup сохранён: $backupDir"
            throw
        }
    }
    throw
} finally {
    if ($mutexHeld) { [void]$installMutex.ReleaseMutex() }
    if (-not $mutexDisposed) { $installMutex.Dispose() }
    try {
        if (Test-Path -LiteralPath $stagingDir) { Remove-Item -LiteralPath $stagingDir -Recurse -Force -ErrorAction Stop }
    } finally {
        if (($installComplete -or $rollbackComplete) -and (Test-Path -LiteralPath $backupDir)) {
            Remove-Item -LiteralPath $backupDir -Recurse -Force -ErrorAction Stop
        }
    }
}
