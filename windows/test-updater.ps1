# Regression tests: isolated HKCU key and temporary files; no real VPN changes.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('amnezia-sync-test-' + [Guid]::NewGuid().ToString('N'))
$testRegistry = 'Software\AmneziaRouteSync-Tests\' + [Guid]::NewGuid().ToString('N')
$updater = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'update-amnezia-routes.ps1') -Raw -Encoding UTF8
# Load declarations only, never the entry point that uses the user's settings.
$declarations = $updater.Substring(0, $updater.IndexOf('# --- self-test'))
. ([scriptblock]::Create($declarations)) -StateDir $testRoot
$RegistryConfSubKey = $testRegistry + '\Conf'
$RegistryServersSubKey = $testRegistry + '\Servers'
[IO.Directory]::CreateDirectory($testRoot) | Out-Null

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
function Assert-Throws([scriptblock]$Action, [string]$Message) {
    $thrown = $false
    try { & $Action } catch { $thrown = $true }
    Assert-True $thrown $Message
}

try {
    Assert-QtCodec
    # This failed with Object[] instead of Byte[] in Windows PowerShell 5.1.
    $original = @{'example.com' = @('93.184.216.34'); '5.255.0.0/16' = @()}
    Write-RoutingRegistry $original
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($RegistryConfSubKey, $true)
    try { $key.SetValue('untouched', 'sentinel') } finally { $key.Dispose() }
    $snapshot = Read-RoutingRegistrySnapshot | ConvertTo-Json -Depth 12 | ConvertFrom-Json
    Write-RoutingRegistry @{'other.example' = @('8.8.8.8')}
    Restore-RoutingRegistrySnapshot $snapshot
    Assert-RoutingRegistry $original
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($RegistryConfSubKey)
    try { Assert-True ($key.GetValue('untouched') -ceq 'sentinel') 'Rollback changed an unrelated value' } finally { $key.Dispose() }
    Write-Host 'PASS: real registry binary backup/restore'

    foreach ($bad in @('bad-.example.com', 'ok.-bad.com', 'a..example.com')) {
        Assert-True (-not (Test-Hostname $bad)) "Invalid hostname accepted: $bad"
    }
    $current = @{'manual.example'=@('8.8.8.8'); 'old.example'=@('9.9.9.9'); 'example.com'=@('93.184.216.34')}
    $desired = Get-DesiredSites $current @('old.example','example.com') @('example.com','5.255.0.0/16') @{'example.com'=@('1.1.1.1')}
    Assert-True ($desired.ContainsKey('manual.example') -and -not $desired.ContainsKey('old.example')) 'Manual/managed merge failed'
    Assert-True ($desired['example.com'][0] -ceq '1.1.1.1') 'DNS rotation kept stale addresses'
    $fallback = Get-DesiredSites $current @('example.com') @('example.com') @{}
    Assert-True ($fallback['example.com'][0] -ceq '93.184.216.34') 'DNS failure discarded existing addresses'
    Assert-True ((@(Get-PublicIPv4Values @('10.0.0.1','127.0.0.1','::1','1.1.1.1')) -join ',') -ceq '1.1.1.1') 'DNS accepted non-public addresses'
    Write-Host 'PASS: DNS rotation, fallback, manual entries, reserved addresses'

    $originalLookup = ${function:Start-DomainLookup}
    $script:lookupCount = 0
    function Start-DomainLookup([string]$Hostname) {
        $script:lookupCount++
        $completion = New-Object 'System.Threading.Tasks.TaskCompletionSource[System.Net.IPAddress[]]'
        if ($Hostname -eq 'fail.example') {
            $completion.SetException([Exception]::new('DNS failure'))
        } else {
            $completion.SetResult([Net.IPAddress[]]@([Net.IPAddress]::Parse('1.1.1.1'),[Net.IPAddress]::Parse('::1')))
        }
        return ,$completion.Task
    }
    $dns = Resolve-ManagedDomains @('ok.example','fail.example')
    Assert-True ($dns.Addresses.Count -eq 1 -and $dns.Addresses['ok.example'][0] -eq '1.1.1.1') 'DNS resolver result failed'
    Write-JsonAtomic $DnsCachePath $dns.Cache
    $cached = Resolve-ManagedDomains @('fail.example','ok.example')
    Assert-True ($cached.Cached -and $script:lookupCount -eq 2) 'Fresh cache triggered DNS requests'
    $empty = Resolve-ManagedDomains @()
    Assert-True ($empty.Addresses.Count -eq 0) 'IP-only list needs no DNS'
    Remove-Item -LiteralPath $DnsCachePath -Force
    $script:lookupCount = 0
    function Start-DomainLookup([string]$Hostname) {
        $script:lookupCount++
        $completion = New-Object 'System.Threading.Tasks.TaskCompletionSource[System.Net.IPAddress[]]'
        return ,$completion.Task
    }
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $timedOut = Resolve-ManagedDomains @('a.example','b.example','c.example','d.example') -TimeoutSeconds 1 -Concurrency 2
    Assert-True ($timer.Elapsed.TotalSeconds -lt 3 -and $script:lookupCount -eq 2 -and $timedOut.Addresses.Count -eq 0) 'DNS timeout/concurrency not bounded'
    ${function:Start-DomainLookup} = $originalLookup
    Write-Host 'PASS: DNS cache, timeout and concurrency'

    $up = [Net.NetworkInformation.OperationalStatus]::Up
    Assert-True (Test-AmneziaAdapter ([pscustomobject]@{Name='AmneziaVPN';Description='WireGuard Tunnel';OperationalStatus=$up})) 'Amnezia adapter missed'
    foreach ($name in @('Corporate WireGuard','Wintun Userspace Tunnel','TAP-Windows Adapter V9')) {
        Assert-True (-not (Test-AmneziaAdapter ([pscustomobject]@{Name=$name;Description=$name;OperationalStatus=$up}))) 'Other VPN mistaken for Amnezia'
    }
    $getTunnel = ${function:Get-TunnelService}
    $adapterUp = ${function:Test-VpnAdapterUp}
    function Get-TunnelService {
        $mockService = [pscustomobject]@{Status=[ServiceProcess.ServiceControllerStatus]::Running}
        $mockService | Add-Member -MemberType ScriptMethod -Name Refresh -Value { }
        return $mockService
    }
    function Test-VpnAdapterUp { return $false }
    Assert-True (-not (Test-TunnelReady)) 'Running service with no adapter reported a restored VPN'
    function Test-VpnAdapterUp { return $true }
    Assert-True (Test-TunnelReady) 'Running tunnel and adapter not ready'
    ${function:Get-TunnelService} = $getTunnel
    ${function:Test-VpnAdapterUp} = $adapterUp
    Write-Host 'PASS: adapter ownership'

    # All process/service functions below are mocks. Transactions still exercise
    # the real codec, temporary HKCU data, journal, and managed-entry files.
    $restoreSession = ${function:Restore-AmneziaSession}
    $getSession = ${function:Get-AmneziaSession}
    function Test-GuiRunning { return $false }
    function Test-TunnelRunning { return $false }
    function Test-Elevated { return $true }
    function Stop-AmneziaGui { $script:stops++ }
    function Stop-AmneziaTunnel { }
    function Start-AmneziaDaemon { }
    $script:stops = 0
    $serverKey = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($RegistryServersSubKey)
    try { $serverKey.SetValue('defaultServerIndex', 3); $serverKey.SetValue('defaultServerId', 'new-id') } finally { $serverKey.Dispose() }
    $session = Get-AmneziaSession
    Assert-True ($session.ServerIndex -eq -1) 'Stale legacy server index trusted'
    $ServerIndex = 2
    Assert-True ((Get-AmneziaSession).ServerIndex -eq 2) 'Explicit server index ignored'
    $ServerIndex = -1

    function Get-AmneziaSession { return [pscustomobject]@{GuiRunning=$true;Connected=$true;AutoConnect=$true;ServerIndex=-1} }
    $script:restoreFails = $true
    function Restore-AmneziaSession($Session, [string]$ExePath) {
        if ($script:restoreFails) { throw 'Simulated reconnect failure' }
    }
    Write-JsonAtomic $ManagedPath @('example.com','5.255.0.0/16')
    Assert-Throws { Invoke-RoutingTransaction @('example.com','5.255.0.0/16') 'mock.exe' @{'example.com'=@('1.1.1.1')} } 'Reconnect failure reported success'
    Assert-True ((Read-JsonFile $JournalPath).phase -ceq 'restoring') 'Reconnect failure lost committed journal'
    $script:restoreFails = $false
    Restore-PendingTransaction 'mock.exe'
    Assert-True (-not (Test-Path -LiteralPath $JournalPath)) 'Recovery left a completed journal'
    Assert-True ((Read-ExceptSites)['example.com'][0] -ceq '1.1.1.1') 'Recovery rolled back a committed update'
    $stopsBefore = $script:stops
    $unchanged = Invoke-RoutingTransaction @('example.com','5.255.0.0/16') 'mock.exe' @{'example.com'=@('1.1.1.1')}
    Assert-True (-not $unchanged.Changed -and $script:stops -eq $stopsBefore) 'Unchanged list restarted VPN'
    Write-Host 'PASS: reconnect failure, crash recovery, no-op update'

    # Simulate a failed write, including a failed reconnect after rollback.
    $writeRegistry = ${function:Write-RoutingRegistry}
    function Write-RoutingRegistry($Sites) { throw 'Simulated write failure' }
    $script:restoreFails = $true
    Assert-Throws { Invoke-RoutingTransaction @('new.example') 'mock.exe' @{'new.example'=@('9.9.9.9')} } 'Write failure reported success'
    Assert-True ((Read-ExceptSites)['example.com'][0] -ceq '1.1.1.1') 'Failed write did not restore the previous list'
    Assert-True ((Read-JsonFile $JournalPath).phase -ceq 'restoring') 'Rollback lost reconnect journal'
    $script:restoreFails = $false
    Restore-PendingTransaction 'mock.exe'
    ${function:Write-RoutingRegistry} = $writeRegistry
    Write-Host 'PASS: write failure rolls back without losing recovery'

    function Get-AmneziaSession { return [pscustomobject]@{GuiRunning=$true;Connected=$true;AutoConnect=$false;ServerIndex=-1} }
    Assert-Throws { Invoke-RoutingTransaction @('new.example') 'mock.exe' } 'Unknown server index did not block restart'
    function Get-AmneziaSession { return [pscustomobject]@{GuiRunning=$true;Connected=$false;AutoConnect=$true;ServerIndex=-1} }
    Assert-Throws { Invoke-RoutingTransaction @('new.example') 'mock.exe' } 'Disconnected autoconnect session was restarted'
    Assert-True (-not (Test-Path -LiteralPath $JournalPath)) 'Preflight guard created a journal'

    ${function:Restore-AmneziaSession} = $restoreSession
    $script:started = $false
    $script:startArguments = @()
    function Test-GuiRunning { return $script:started }
    function Test-TunnelRunning { return $script:started }
    function Test-TunnelReady { return $script:started }
    function Start-Process($FilePath, $ArgumentList, $WindowStyle) {
        Assert-True ($WindowStyle -ceq 'Hidden') 'Background restore is not hidden'
        $script:started = $true
        $script:startArguments = @($ArgumentList)
    }
    Restore-AmneziaSession ([pscustomobject]@{GuiRunning=$false;Connected=$true;AutoConnect=$false;ServerIndex=2}) 'mock.exe'
    Assert-True ($script:started -and ($script:startArguments -join ' ') -ceq '--connect 2') 'Connected session with no GUI was not restored'
    Write-Host 'PASS: session preservation and server selection guards'
    Write-Host 'Windows regression tests: OK'
} finally {
    if (-not $testRegistry.StartsWith('Software\AmneziaRouteSync-Tests\')) { throw 'Unsafe registry cleanup target' }
    [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($testRegistry, $false)
    $resolvedRoot = [IO.Path]::GetFullPath($testRoot)
    $tempParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if (-not $resolvedRoot.StartsWith($tempParent, [StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path -Leaf $resolvedRoot) -notlike 'amnezia-sync-test-*') { throw 'Unsafe temporary cleanup target' }
    Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
}
