[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') { throw 'Этот uninstaller предназначен только для Windows.' }
if (-not $env:LOCALAPPDATA) { throw 'Не определён LOCALAPPDATA текущего пользователя.' }
$CurrentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($CurrentSid -eq 'S-1-5-18') { throw 'Uninstaller нельзя запускать от SYSTEM.' }

$InstallDir = Join-Path $env:LOCALAPPDATA 'AmneziaRouteSync'
$InstallStatePath = Join-Path $InstallDir 'install-state.json'
$JournalPath = Join-Path $InstallDir '.registry-transaction.json'
$TaskName = "Amnezia-Split-Route-Sync-$CurrentSid"
$RunSubKey = 'Software\Microsoft\Windows\CurrentVersion\Run'
$RunValueName = 'AmneziaVPN'
$UpdatePath = Join-Path $InstallDir 'update-amnezia-routes.ps1'
$Mutex = New-Object Threading.Mutex($false, "Global\Amnezia-Split-Route-Sync-$CurrentSid")
$MutexHeld = $false

try {
    try {
        $MutexHeld = $Mutex.WaitOne(660000)
    } catch [Threading.AbandonedMutexException] {
        $MutexHeld = $true
    }
    if (-not $MutexHeld) { throw 'Не удалось дождаться завершения updater.' }
    if (Test-Path -LiteralPath $JournalPath -PathType Leaf) {
        throw 'Есть незавершённая Registry-транзакция. Закройте AmneziaVPN, запустите updater для recovery и повторите удаление.'
    }

    $state = if (Test-Path -LiteralPath $InstallStatePath -PathType Leaf) {
        Get-Content -LiteralPath $InstallStatePath -Raw -Encoding UTF8 | ConvertFrom-Json
    } else { $null }
    $runValueWasPresent = $false
    $runValueBefore = $null
    $runValueKindBefore = $null
    $runChanged = $false
    $runKey = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($RunSubKey, $true)
    try {
        $runValueWasPresent = @($runKey.GetValueNames()) -contains $RunValueName
        $current = $runKey.GetValue($RunValueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $runValueBefore = $current
        if ($runValueWasPresent) { $runValueKindBefore = $runKey.GetValueKind($RunValueName) }
        $stateComplete = $null -ne $state -and
            $state.PSObject.Properties.Name -contains 'installed_wrapper_value' -and
            $state.PSObject.Properties.Name -contains 'original_autostart_present' -and
            $state.PSObject.Properties.Name -contains 'original_autostart_value' -and
            $state.PSObject.Properties.Name -contains 'original_autostart_kind'
        if ($null -ne $current -and
            ([string]$current).IndexOf($UpdatePath, [StringComparison]::OrdinalIgnoreCase) -ge 0 -and
            -not $stateComplete) {
            throw 'Run wrapper найден, но install-state неполон; удаление остановлено, чтобы не сломать автозапуск.'
        }
        if ($null -ne $current -and
            ([string]$current).IndexOf($UpdatePath, [StringComparison]::OrdinalIgnoreCase) -ge 0 -and
            $stateComplete -and
            [string]$current -cne [string]$state.installed_wrapper_value) {
            throw 'Run wrapper был изменён пользователем; удаление остановлено, чтобы не оставить сломанный автозапуск.'
        }
        if ($null -ne $state -and
            $state.PSObject.Properties.Name -contains 'installed_wrapper_value' -and
            $null -ne $current -and
            [string]$current -ceq [string]$state.installed_wrapper_value) {
            $runChanged = $true
            if ($null -ne $state -and [bool]$state.original_autostart_present) {
                $kind = [Microsoft.Win32.RegistryValueKind][Enum]::Parse(
                    [Microsoft.Win32.RegistryValueKind], [string]$state.original_autostart_kind, $false
                )
                $runKey.SetValue($RunValueName, [string]$state.original_autostart_value, $kind)
            } else {
                $runKey.DeleteValue($RunValueName, $false)
            }
        }
    } finally { $runKey.Dispose() }

    try {
        $tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskName -ceq $TaskName })
        if ($tasks.Count -gt 1) { throw 'Task Scheduler вернул несколько задач с одинаковым именем.' }
        if ($tasks.Count -eq 1) {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
        }
        $remainingTasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskName -ceq $TaskName })
        if ($remainingTasks.Count -ne 0) {
            throw 'Scheduled Task осталась зарегистрирована; приватные файлы сохранены.'
        }
    } catch {
        $taskFailure = $_
        if ($runChanged) {
            try {
                $rollbackRunKey = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($RunSubKey, $true)
                try {
                    if ($runValueWasPresent) {
                        $rollbackRunKey.SetValue($RunValueName, $runValueBefore, $runValueKindBefore)
                    } else {
                        $rollbackRunKey.DeleteValue($RunValueName, $false)
                    }
                } finally { $rollbackRunKey.Dispose() }
            } catch {
                throw "Task Scheduler завершился ошибкой, и не удалось восстановить Run: $($_.Exception.Message)"
            }
        }
        throw $taskFailure
    }
    if (Test-Path -LiteralPath $InstallDir) {
        Remove-Item -LiteralPath $InstallDir -Recurse -Force -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $InstallDir) { throw 'Не удалось удалить приватный install directory.' }
    Write-Host 'Автоматизация удалена. Очистите managed-маршруты в интерфейсе AmneziaVPN.'
} finally {
    if ($MutexHeld) { [void]$Mutex.ReleaseMutex() }
    $Mutex.Dispose()
}
