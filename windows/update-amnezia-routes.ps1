[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$ApplyPending,
    [switch]$StartAmnezia,
    [switch]$CodecSelfTest,
    [switch]$ValidationSelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if ($env:OS -ne 'Windows_NT' -and -not $CodecSelfTest -and -not $ValidationSelfTest) {
    throw 'Этот updater предназначен только для Windows.'
}
if (-not $env:LOCALAPPDATA -and -not $CodecSelfTest -and -not $ValidationSelfTest) {
    throw 'Не определён LOCALAPPDATA текущего пользователя.'
}
if (-not $env:LOCALAPPDATA) { $env:LOCALAPPDATA = [IO.Path]::GetTempPath() }

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$StateDir = Join-Path $env:LOCALAPPDATA 'AmneziaRouteSync'
$PolicyPath = Join-Path $ScriptDir 'route-policy.json'
$CustomPolicyPath = Join-Path $ScriptDir 'custom-host-policy.json'
$PendingPath = Join-Path $StateDir 'pending-routes.json'
$ManagedPath = Join-Path $StateDir 'managed-cidrs.json'
$StatusPath = Join-Path $StateDir 'status.json'
$ImportPath = Join-Path $StateDir 'amnezia-split-routes.json'
$JournalPath = Join-Path $StateDir '.registry-transaction.json'
$InstallStatePath = Join-Path $StateDir 'install-state.json'
$RegistryRoot = 'HKCU\Software\AmneziaVPN.ORG\AmneziaVPN'
$RegistrySubKey = 'Software\AmneziaVPN.ORG\AmneziaVPN'
$ConfSubKey = "$RegistrySubKey\Conf"
$ProtectedIps = @()
$RawBase = 'https://raw.githubusercontent.com/GrimbirdUsers/ru-routing-dat/main/data-geoip'
$MinimumPrefix = 16
$MinimumRoutes = 40
$MaximumRoutes = 256
$MaximumAddresses = 1000000L

Add-Type -AssemblyName System.Net.Http

$Sources = [ordered]@{
    'ru-yandex' = 10
    'ru-ozon' = 8
    'ru-vk' = 3
    'ru-wildberries' = 5
    'ru-banks' = 5
    'ru-payments' = 3
    'ru-cdn' = 1
}

$QtCodecSource = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace AmneziaRouteSync {
    public static class QtVariantMapCodec {
        private const UInt32 QVariantMap = 8;
        private const UInt32 QString = 10;
        private const UInt32 QStringList = 11;

        private static void WriteUInt32(Stream stream, UInt32 value) {
            stream.WriteByte((byte)(value >> 24));
            stream.WriteByte((byte)(value >> 16));
            stream.WriteByte((byte)(value >> 8));
            stream.WriteByte((byte)value);
        }

        private static UInt32 ReadUInt32(byte[] data, ref int offset) {
            if (offset + 4 > data.Length) throw new InvalidDataException("Unexpected end of QDataStream");
            UInt32 value = ((UInt32)data[offset] << 24) | ((UInt32)data[offset + 1] << 16)
                         | ((UInt32)data[offset + 2] << 8) | data[offset + 3];
            offset += 4;
            return value;
        }

        private static void WriteQString(Stream stream, string value) {
            byte[] bytes = Encoding.BigEndianUnicode.GetBytes(value ?? String.Empty);
            WriteUInt32(stream, checked((UInt32)bytes.Length));
            stream.Write(bytes, 0, bytes.Length);
        }

        private static string ReadQString(byte[] data, ref int offset) {
            UInt32 rawLength = ReadUInt32(data, ref offset);
            if (rawLength == UInt32.MaxValue) return null;
            if ((rawLength & 1) != 0 || rawLength > 131072 || offset + rawLength > data.Length)
                throw new InvalidDataException("Invalid QString length");
            string value = Encoding.BigEndianUnicode.GetString(data, offset, (int)rawLength);
            offset += (int)rawLength;
            return value;
        }

        public static byte[] Encode(IDictionary<string, List<string>> map) {
            using (MemoryStream stream = new MemoryStream()) {
                WriteUInt32(stream, QVariantMap);
                WriteUInt32(stream, checked((UInt32)map.Count));
                foreach (string key in map.Keys.OrderBy(k => k, StringComparer.Ordinal)) {
                    WriteQString(stream, key);
                    WriteUInt32(stream, QStringList);
                    List<string> values = map[key] ?? new List<string>();
                    WriteUInt32(stream, checked((UInt32)values.Count));
                    foreach (string value in values) WriteQString(stream, value);
                }
                byte[] payload = stream.ToArray();
                StringBuilder wrapper = new StringBuilder("@Variant(", payload.Length + 10);
                foreach (byte value in payload) wrapper.Append((char)value);
                wrapper.Append(')');
                return Encoding.Unicode.GetBytes(wrapper.ToString());
            }
        }

        public static Dictionary<string, List<string>> Decode(byte[] registryData) {
            Dictionary<string, List<string>> result = new Dictionary<string, List<string>>(StringComparer.Ordinal);
            if (registryData == null || registryData.Length == 0) return result;
            if ((registryData.Length & 1) != 0) throw new InvalidDataException("Invalid UTF-16 registry value");
            string wrapper = Encoding.Unicode.GetString(registryData);
            const string prefix = "@Variant(";
            if (!wrapper.StartsWith(prefix, StringComparison.Ordinal) || !wrapper.EndsWith(")", StringComparison.Ordinal))
                throw new InvalidDataException("ExceptSites is not a Qt @Variant value");
            string inner = wrapper.Substring(prefix.Length, wrapper.Length - prefix.Length - 1);
            byte[] payload = new byte[inner.Length];
            for (int i = 0; i < inner.Length; ++i) {
                if (inner[i] > 255) throw new InvalidDataException("Invalid byte in Qt wrapper");
                payload[i] = (byte)inner[i];
            }
            int offset = 0;
            if (ReadUInt32(payload, ref offset) != QVariantMap) throw new InvalidDataException("Root QVariant is not a map");
            UInt32 count = ReadUInt32(payload, ref offset);
            if (count > 4096) throw new InvalidDataException("Too many ExceptSites entries");
            for (UInt32 i = 0; i < count; ++i) {
                string key = ReadQString(payload, ref offset);
                UInt32 type = ReadUInt32(payload, ref offset);
                List<string> values = new List<string>();
                if (type == QString) {
                    values.Add(ReadQString(payload, ref offset) ?? String.Empty);
                } else if (type == QStringList) {
                    UInt32 valueCount = ReadUInt32(payload, ref offset);
                    if (valueCount > 4096) throw new InvalidDataException("Too many values for ExceptSites entry");
                    for (UInt32 j = 0; j < valueCount; ++j) values.Add(ReadQString(payload, ref offset) ?? String.Empty);
                } else {
                    throw new InvalidDataException("Unsupported QVariant type in ExceptSites: " + type);
                }
                if (result.ContainsKey(key)) throw new InvalidDataException("Duplicate ExceptSites key");
                result.Add(key, values);
            }
            if (offset != payload.Length) throw new InvalidDataException("Trailing data in ExceptSites QVariantMap");
            return result;
        }
    }
}
'@

Add-Type -TypeDefinition $QtCodecSource -Language CSharp

function Assert-QtCodec {
    $fixture = New-Object 'System.Collections.Generic.Dictionary[string,System.Collections.Generic.List[string]]'
    $fixture.Add('198.51.100.20/32', (New-Object 'System.Collections.Generic.List[string]'))
    $fixture.Add('203.0.113.100/32', (New-Object 'System.Collections.Generic.List[string]'))
    $expected = 'QABWAGEAcgBpAGEAbgB0ACgAAAAAAAAACAAAAAAAAAACAAAAAAAAACAAAAAxAAAAOQAAADgAAAAuAAAANQAAADEAAAAuAAAAMQAAADAAAAAwAAAALgAAADIAAAAwAAAALwAAADMAAAAyAAAAAAAAAAsAAAAAAAAAAAAAAAAAAAAgAAAAMgAAADAAAAAzAAAALgAAADAAAAAuAAAAMQAAADEAAAAzAAAALgAAADEAAAAwAAAAMAAAAC8AAAAzAAAAMgAAAAAAAAALAAAAAAAAAAAAKQA='
    $encoded = [AmneziaRouteSync.QtVariantMapCodec]::Encode($fixture)
    if ([Convert]::ToBase64String($encoded) -cne $expected) {
        throw 'Qt QVariantMap codec self-test failed; Registry не изменён.'
    }
    $decoded = [AmneziaRouteSync.QtVariantMapCodec]::Decode($encoded)
    if ($decoded.Count -ne 2 -or -not $decoded.ContainsKey('203.0.113.100/32')) {
        throw 'Qt QVariantMap codec round-trip failed; Registry не изменён.'
    }
    $manualFixture = New-Object 'System.Collections.Generic.Dictionary[string,System.Collections.Generic.List[string]]'
    $manualFixture.Add('203.0.113.100/32', (New-Object 'System.Collections.Generic.List[string]'))
    $manualValues = New-Object 'System.Collections.Generic.List[string]'
    $manualValues.Add('198.51.100.7')
    $manualFixture.Add('example.com', $manualValues)
    $manualExpected = 'QABWAGEAcgBpAGEAbgB0ACgAAAAAAAAACAAAAAAAAAACAAAAAAAAACAAAAAyAAAAMAAAADMAAAAuAAAAMAAAAC4AAAAxAAAAMQAAADMAAAAuAAAAMQAAADAAAAAwAAAALwAAADMAAAAyAAAAAAAAAAsAAAAAAAAAAAAAAAAAAAAWAAAAZQAAAHgAAABhAAAAbQAAAHAAAABsAAAAZQAAAC4AAABjAAAAbwAAAG0AAAAAAAAACwAAAAAAAAABAAAAAAAAABgAAAAxAAAAOQAAADgAAAAuAAAANQAAADEAAAAuAAAAMQAAADAAAAAwAAAALgAAADcAKQA='
    $manualEncoded = [AmneziaRouteSync.QtVariantMapCodec]::Encode($manualFixture)
    if ([Convert]::ToBase64String($manualEncoded) -cne $manualExpected) {
        throw 'Qt QVariantMap manual-entry fixture failed; Registry не изменён.'
    }
    $manualDecoded = [AmneziaRouteSync.QtVariantMapCodec]::Decode($manualEncoded)
    if ($manualDecoded['example.com'].Count -ne 1 -or $manualDecoded['example.com'][0] -cne '198.51.100.7') {
        throw 'Qt QVariantMap manual-entry round-trip failed; Registry не изменён.'
    }
}

if ($CodecSelfTest) {
    Assert-QtCodec
    Write-Host 'Qt QVariantMap codec: OK'
    exit 0
}

function Write-JsonAtomic([string]$Path, $Value) {
    $directory = Split-Path -Parent $Path
    [IO.Directory]::CreateDirectory($directory) | Out-Null
    $temporary = "$Path.tmp.$PID"
    try {
        $json = $Value | ConvertTo-Json -Depth 12
        [IO.File]::WriteAllText($temporary, $json + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false)))
        Move-Item -LiteralPath $temporary -Destination $Path -Force
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

function Read-JsonFile([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    return Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
}

function ConvertTo-IPv4Number([string]$Address) {
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($Address, [ref]$parsed) -or $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        throw 'Некорректный IPv4 в конфигурации или источнике'
    }
    $bytes = $parsed.GetAddressBytes()
    return ([uint64]$bytes[0] -shl 24) -bor ([uint64]$bytes[1] -shl 16) -bor ([uint64]$bytes[2] -shl 8) -bor [uint64]$bytes[3]
}

function ConvertFrom-IPv4Number([uint64]$Address) {
    return '{0}.{1}.{2}.{3}' -f (($Address -shr 24) -band 255), (($Address -shr 16) -band 255), (($Address -shr 8) -band 255), ($Address -band 255)
}

function ConvertTo-Cidr([string]$Value) {
    $parts = $Value.Split('/')
    if ($parts.Count -ne 2) { throw 'Некорректный CIDR в конфигурации или источнике' }
    $prefix = 0
    if (-not [int]::TryParse($parts[1], [ref]$prefix) -or $prefix -lt 0 -or $prefix -gt 32) {
        throw 'Некорректный CIDR в конфигурации или источнике'
    }
    $address = ConvertTo-IPv4Number $parts[0]
    $mask = if ($prefix -eq 0) { [uint64]0 } else { (([uint64]4294967295 -shl (32 - $prefix)) -band [uint64]4294967295) }
    $network = $address -band $mask
    if ($network -ne $address) { throw 'CIDR не является network address' }
    [pscustomobject]@{
        Text = "$($parts[0])/$prefix"
        Prefix = $prefix
        Address = $address
        Network = $network
        Mask = $mask
        Count = [uint64]1 -shl (32 - $prefix)
    }
}

function Test-CidrInside($Child, $Envelope) {
    return $Child.Prefix -ge $Envelope.Prefix -and (($Child.Network -band $Envelope.Mask) -eq $Envelope.Network)
}

function Test-CidrCoveredByEnvelopes($Cidr, $Envelopes) {
    $cursor = [uint64]$Cidr.Network
    $last = [uint64]($Cidr.Network + $Cidr.Count - 1)
    foreach ($envelope in @($Envelopes | Sort-Object Network, Prefix)) {
        $envelopeStart = [uint64]$envelope.Network
        $envelopeLast = [uint64]($envelope.Network + $envelope.Count - 1)
        if ($envelopeLast -lt $cursor) { continue }
        if ($envelopeStart -gt $cursor) { return $false }
        if ($envelopeLast -ge $last) { return $true }
        $cursor = $envelopeLast + 1
    }
    return $false
}

function Compress-Cidrs($Cidrs) {
    $current = @{}
    foreach ($cidr in @($Cidrs)) { $current[$cidr.Text] = $cidr }
    $changed = $true
    while ($changed) {
        $changed = $false
        $kept = New-Object 'System.Collections.Generic.List[object]'
        foreach ($cidr in @($current.Values | Sort-Object Prefix, Network)) {
            if ($kept | Where-Object { Test-CidrInside $cidr $_ } | Select-Object -First 1) {
                $changed = $true
            } else {
                $kept.Add($cidr)
            }
        }
        $current = @{}
        foreach ($cidr in $kept) { $current[$cidr.Text] = $cidr }

        $merged = $false
        for ($prefix = 32; $prefix -ge 1 -and -not $merged; $prefix--) {
            $groups = @{}
            foreach ($cidr in @($current.Values | Where-Object { $_.Prefix -eq $prefix })) {
                $parentPrefix = $prefix - 1
                $parentMask = if ($parentPrefix -eq 0) { [uint64]0 } else { (([uint64]4294967295 -shl (32 - $parentPrefix)) -band [uint64]4294967295) }
                $parentNetwork = $cidr.Network -band $parentMask
                $groupKey = "$parentPrefix/$parentNetwork"
                if (-not $groups.ContainsKey($groupKey)) { $groups[$groupKey] = New-Object 'System.Collections.Generic.List[object]' }
                $groups[$groupKey].Add($cidr)
            }
            foreach ($group in $groups.Values) {
                if ($group.Count -ne 2) { continue }
                $ordered = @($group | Sort-Object Network)
                $childSize = [uint64]1 -shl (32 - $prefix)
                if ($ordered[1].Network -ne ($ordered[0].Network + $childSize)) { continue }
                [void]$current.Remove($ordered[0].Text)
                [void]$current.Remove($ordered[1].Text)
                $parentPrefix = $prefix - 1
                $parent = ConvertTo-Cidr "$(ConvertFrom-IPv4Number $ordered[0].Network)/$parentPrefix"
                $current[$parent.Text] = $parent
                $changed = $true
                $merged = $true
                break
            }
        }
    }
    return @($current.Values | Sort-Object Address, Prefix)
}

function Get-HttpsText([string]$Url) {
    if (-not $Url.StartsWith('https://', [StringComparison]::OrdinalIgnoreCase)) { throw "Разрешён только HTTPS: $Url" }
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.AllowAutoRedirect = $false
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(30)
    $client.DefaultRequestHeaders.UserAgent.ParseAdd('Amnezia-Split-Route-Sync-Windows/1.0')
    $response = $null
    $stream = $null
    $memory = $null
    $cancellation = New-Object Threading.CancellationTokenSource
    $cancellation.CancelAfter(30000)
    try {
        $response = $client.GetAsync(
            $Url,
            [Net.Http.HttpCompletionOption]::ResponseHeadersRead,
            $cancellation.Token
        ).GetAwaiter().GetResult()
        if (-not $response.IsSuccessStatusCode) { throw "HTTP source вернул status $([int]$response.StatusCode)" }
        if ($null -ne $response.Content.Headers.ContentLength -and [long]$response.Content.Headers.ContentLength -gt 1048576) {
            throw 'HTTP source больше 1 MiB'
        }
        $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $memory = New-Object IO.MemoryStream
        $buffer = New-Object byte[] 8192
        $total = 0
        while (($read = $stream.ReadAsync($buffer, 0, $buffer.Length, $cancellation.Token).GetAwaiter().GetResult()) -gt 0) {
            $total += $read
            if ($total -gt 1048576) { throw 'HTTP source больше 1 MiB' }
            $memory.Write($buffer, 0, $read)
        }
        if ($total -eq 0) { throw 'HTTP source пуст' }
        $utf8 = [Text.UTF8Encoding]::new($false, $true)
        return $utf8.GetString($memory.ToArray())
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if ($null -ne $memory) { $memory.Dispose() }
        if ($null -ne $response) { $response.Dispose() }
        $cancellation.Dispose()
        $client.Dispose()
        $handler.Dispose()
    }
}

function Get-Policy {
    $policy = Read-JsonFile $PolicyPath
    if ($null -eq $policy -or $policy.version -ne 1) { throw 'Неизвестная версия route-policy.json' }
    $actualNames = @($policy.sources.PSObject.Properties.Name | Sort-Object)
    $expectedNames = @($Sources.Keys | Sort-Object)
    if (($actualNames -join ',') -cne ($expectedNames -join ',')) { throw 'Policy содержит неожиданный набор RU-источников' }
    foreach ($name in $actualNames) {
        $values = @($policy.sources.PSObject.Properties[$name].Value)
        if ($values.Count -eq 0) { throw "Policy $name не содержит reviewed CIDR" }
        foreach ($value in $values) {
            $cidr = ConvertTo-Cidr ([string]$value)
            if ($cidr.Prefix -lt $MinimumPrefix) { throw "Policy $name содержит широкую сеть $value" }
            foreach ($protected in $ProtectedIps) {
                if (($protected -band $cidr.Mask) -eq $cidr.Network) { throw "Policy $name содержит protected IP" }
            }
        }
    }
    return $policy
}

function Get-CustomPolicy {
    $script:ProtectedIps = @()
    $policy = Read-JsonFile $CustomPolicyPath
    if ($null -eq $policy -or $policy.version -ne 1 -or
        $policy.PSObject.Properties.Name -notcontains 'groups' -or
        $policy.PSObject.Properties.Name -notcontains 'protected_ips' -or
        @($policy.protected_ips).Count -eq 0) {
        throw 'custom-host-policy.json должен содержать version=1, groups и protected_ips'
    }
    foreach ($value in @($policy.protected_ips)) { $script:ProtectedIps += ConvertTo-IPv4Number ([string]$value) }
    $seenNames = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $seenHosts = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($group in @($policy.groups)) {
        $name = [string]$group.name
        $minimum = 0
        if (-not $name -or -not $seenNames.Add($name) -or
            @($group.hosts).Count -eq 0 -or @($group.allowed_networks).Count -eq 0 -or
            -not [int]::TryParse([string]$group.minimum_unique_ipv4, [ref]$minimum) -or $minimum -lt 1) {
            throw "Custom policy содержит неверную группу $name"
        }
        $groupHosts = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
        foreach ($hostNameValue in @($group.hosts)) {
            $hostName = [string]$hostNameValue
            if (-not $hostName -or $hostName -cne $hostName.ToLowerInvariant() -or
                $hostName.Contains('..') -or $hostName -notmatch '^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$' -or
                -not $seenHosts.Add($hostName) -or -not $groupHosts.Add($hostName)) {
                throw "Custom policy содержит неверный/повторный hostname $hostName"
            }
        }
        $optionalHosts = if ($group.PSObject.Properties.Name -contains 'optional_hosts') { @($group.optional_hosts) } else { @() }
        $seenOptional = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
        foreach ($optionalValue in $optionalHosts) {
            $optionalHost = [string]$optionalValue
            if (-not $groupHosts.Contains($optionalHost) -or -not $seenOptional.Add($optionalHost)) {
                throw "Custom policy $name содержит неверный optional hostname $optionalHost"
            }
        }
        foreach ($value in @($group.allowed_networks)) {
            $cidr = ConvertTo-Cidr ([string]$value)
            if ($cidr.Prefix -lt $MinimumPrefix) { throw "Custom policy $name содержит широкую сеть $value" }
            foreach ($protected in $ProtectedIps) {
                if (($protected -band $cidr.Mask) -eq $cidr.Network) { throw "Custom policy $name содержит protected IP" }
            }
        }
    }
    return $policy
}

function Resolve-IPv4Host([string]$HostName) {
    $async = [Net.Dns]::BeginGetHostAddresses($HostName, $null, $null)
    try {
        if (-not $async.AsyncWaitHandle.WaitOne(5000)) {
            throw "DNS lookup $HostName не завершился за 5 секунд"
        }
        try { return @([Net.Dns]::EndGetHostAddresses($async)) }
        catch [Net.Sockets.SocketException] { return @() }
    } finally {
        $async.AsyncWaitHandle.Close()
    }
}

function Get-SourceCidrs([string]$Name, [int]$Minimum, $AllowedValues) {
    $content = Get-HttpsText "$RawBase/$Name.txt"
    $allowed = @($AllowedValues | ForEach-Object { ConvertTo-Cidr ([string]$_) })
    $result = New-Object 'System.Collections.Generic.List[object]'
    $lineNumber = 0
    foreach ($rawLine in ($content -split "`r?`n")) {
        $lineNumber++
        $value = ($rawLine -split '#', 2)[0].Trim()
        if (-not $value) { continue }
        if ($value.Contains(':')) { continue }
        $cidr = ConvertTo-Cidr $value
        if ($cidr.Prefix -lt $MinimumPrefix) { throw "$Name`: слишком широкая сеть $value" }
        if (-not ($allowed | Where-Object { Test-CidrInside $cidr $_ } | Select-Object -First 1)) {
            throw "$Name`: новая сеть вне проверенного allowlist"
        }
        $result.Add($cidr)
    }
    if ($result.Count -lt $Minimum) { throw "$Name`: получено $($result.Count), ожидалось >= $Minimum" }
    return $result.ToArray()
}

function Get-CustomCidrs($Policy) {
    $result = New-Object 'System.Collections.Generic.List[object]'
    $counts = [ordered]@{}
    foreach ($group in @($Policy.groups)) {
        $allowed = @($group.allowed_networks | ForEach-Object { ConvertTo-Cidr ([string]$_) })
        $optional = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
        if ($group.PSObject.Properties.Name -contains 'optional_hosts') {
            foreach ($hostName in @($group.optional_hosts)) { [void]$optional.Add([string]$hostName) }
        }
        $addresses = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
        foreach ($hostName in @($group.hosts)) {
            $hostAddresses = @(Resolve-IPv4Host ([string]$hostName))
            $hostIpv4Count = 0
            foreach ($answer in $hostAddresses) {
                if ($answer.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
                    $cidr = ConvertTo-Cidr "$($answer.ToString())/32"
                    if (-not ($allowed | Where-Object { Test-CidrInside $cidr $_ } | Select-Object -First 1)) {
                        throw "$($group.name): DNS $hostName вернул адрес вне проверенного allowlist"
                    }
                    [void]$addresses.Add($answer.ToString())
                    $hostIpv4Count++
                }
            }
            if ($hostIpv4Count -eq 0 -and -not $optional.Contains([string]$hostName)) {
                throw "$($group.name): обязательный hostname $hostName не дал IPv4"
            }
        }
        if ($addresses.Count -lt [int]$group.minimum_unique_ipv4) {
            throw "$($group.name): DNS вернул только $($addresses.Count) уникальных IPv4"
        }
        foreach ($address in $addresses) {
            $cidr = ConvertTo-Cidr "$address/32"
            $result.Add($cidr)
        }
        $counts[[string]$group.name] = $addresses.Count
    }
    return [pscustomobject]@{ Cidrs = $result.ToArray(); Counts = $counts }
}

function Get-DesiredRoutes {
    $customPolicy = Get-CustomPolicy
    $policy = Get-Policy
    $all = New-Object 'System.Collections.Generic.List[object]'
    $counts = [ordered]@{}
    foreach ($source in $Sources.GetEnumerator()) {
        $allowedValues = $policy.sources.PSObject.Properties[$source.Key].Value
        $cidrs = @(Get-SourceCidrs $source.Key ([int]$source.Value) $allowedValues)
        foreach ($cidr in $cidrs) { $all.Add($cidr) }
        $counts[$source.Key] = $cidrs.Count
    }
    $custom = Get-CustomCidrs $customPolicy
    foreach ($cidr in $custom.Cidrs) { $all.Add($cidr) }
    foreach ($entry in $custom.Counts.GetEnumerator()) { $counts[$entry.Key] = $entry.Value }

    $unique = @(Compress-Cidrs $all.ToArray())
    if ($unique.Count -lt $MinimumRoutes -or $unique.Count -gt $MaximumRoutes) {
        throw "Подозрительное число маршрутов: $($unique.Count)"
    }
    $covered = [uint64]0
    foreach ($cidr in $unique) {
        $covered += $cidr.Count
        foreach ($protected in $ProtectedIps) {
            if (($protected -band $cidr.Mask) -eq $cidr.Network) { throw 'Итоговый маршрут покрывает protected IP' }
        }
    }
    if ($covered -gt $MaximumAddresses) { throw "Маршруты покрывают слишком много IPv4: $covered" }
    return [pscustomobject]@{ Cidrs = @($unique.Text); Counts = $counts }
}

function Assert-PendingRoutes([string[]]$Cidrs) {
    $customPolicy = Get-CustomPolicy
    $policy = Get-Policy
    $allowed = New-Object 'System.Collections.Generic.List[object]'
    foreach ($name in $Sources.Keys) {
        foreach ($value in @($policy.sources.PSObject.Properties[$name].Value)) {
            $allowed.Add((ConvertTo-Cidr ([string]$value)))
        }
    }
    foreach ($group in @($customPolicy.groups)) {
        foreach ($value in @($group.allowed_networks)) {
            $allowed.Add((ConvertTo-Cidr ([string]$value)))
        }
    }
    $parsed = New-Object 'System.Collections.Generic.List[object]'
    foreach ($value in @($Cidrs)) {
        $cidr = ConvertTo-Cidr ([string]$value)
        if ($cidr.Prefix -lt $MinimumPrefix) { throw 'Pending содержит слишком широкую сеть' }
        if (-not (Test-CidrCoveredByEnvelopes $cidr $allowed)) {
            throw 'Pending содержит сеть вне текущей reviewed-policy'
        }
        $parsed.Add($cidr)
    }
    $unique = @(Compress-Cidrs $parsed.ToArray())
    if ($unique.Count -lt $MinimumRoutes -or $unique.Count -gt $MaximumRoutes) {
        throw 'Pending содержит подозрительное число маршрутов'
    }
    $covered = [uint64]0
    foreach ($cidr in $unique) {
        $covered += $cidr.Count
        foreach ($protected in $ProtectedIps) {
            if (($protected -band $cidr.Mask) -eq $cidr.Network) {
                throw 'Pending покрывает protected IP'
            }
        }
    }
    if ($covered -gt $MaximumAddresses) { throw 'Pending покрывает слишком много IPv4' }
    return @($unique.Text)
}

function Test-AmneziaRunning { return $null -ne (Get-Process -Name 'AmneziaVPN' -ErrorAction SilentlyContinue) }

function Assert-AmneziaVersion {
    $state = Read-JsonFile $InstallStatePath
    if ($null -eq $state -or -not $state.amnezia_path) {
        throw 'Не найден install-state с путём AmneziaVPN.exe.'
    }
    $path = [string]$state.amnezia_path
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'Не найден сохранённый AmneziaVPN.exe.' }
    $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($path).ProductVersion
    $major = 0
    if (-not $version -or -not [int]::TryParse(($version -split '\.')[0], [ref]$major) -or $major -ne 5) {
        throw "Поддерживается AmneziaVPN major 5, найдена версия $version"
    }
}

function Read-ManagedCidrs {
    $value = Read-JsonFile $ManagedPath
    if ($null -eq $value) { return @() }
    return @($value | ForEach-Object { [string]$_ })
}

function Read-ExceptSites {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($ConfSubKey, $false)
    if ($null -eq $key) { return @{} }
    try {
        $value = $key.GetValue('ExceptSites', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if ($null -eq $value) { return @{} }
        if (-not ($value -is [byte[]])) { throw 'Conf\ExceptSites имеет неожиданный тип Registry' }
        $decoded = [AmneziaRouteSync.QtVariantMapCodec]::Decode([byte[]]$value)
        $result = @{}
        foreach ($entry in $decoded.GetEnumerator()) { $result[$entry.Key] = @($entry.Value) }
        return $result
    } finally { $key.Dispose() }
}

function Test-InstalledRoutingMatches([string[]]$Cidrs) {
    try {
        $sites = Read-ExceptSites
        foreach ($cidr in @($Cidrs)) {
            if (-not $sites.ContainsKey($cidr)) { return $false }
        }
        $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($ConfSubKey, $false)
        if ($null -eq $key) { return $false }
        try {
            if ($key.GetValueKind('routeMode') -ne [Microsoft.Win32.RegistryValueKind]::DWord -or
                [int]$key.GetValue('routeMode') -ne 2) { return $false }
            if ($key.GetValueKind('sitesSplitTunnelingEnabled') -ne [Microsoft.Win32.RegistryValueKind]::String -or
                [string]$key.GetValue('sitesSplitTunnelingEnabled') -cne 'true') { return $false }
        } finally { $key.Dispose() }
        return $true
    } catch {
        return $false
    }
}

function ConvertTo-QtMap($Sites) {
    $map = New-Object 'System.Collections.Generic.Dictionary[string,System.Collections.Generic.List[string]]' ([StringComparer]::Ordinal)
    foreach ($key in @($Sites.Keys | Sort-Object)) {
        $values = New-Object 'System.Collections.Generic.List[string]'
        foreach ($value in @($Sites[$key])) { if ($null -ne $value) { $values.Add([string]$value) } }
        $map.Add([string]$key, $values)
    }
    return $map
}

function Read-RoutingRegistrySnapshot {
    $items = [ordered]@{}
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($ConfSubKey, $false)
    try {
        $valueNames = if ($null -ne $key) { @($key.GetValueNames()) } else { @() }
        foreach ($name in @('ExceptSites', 'routeMode', 'sitesSplitTunnelingEnabled')) {
            if ($name -notin $valueNames) {
                $items[$name] = [ordered]@{ present = $false }
                continue
            }
            $kind = $key.GetValueKind($name)
            $value = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $encoded = switch ($kind) {
                ([Microsoft.Win32.RegistryValueKind]::Binary) { [Convert]::ToBase64String([byte[]]$value); break }
                ([Microsoft.Win32.RegistryValueKind]::DWord) { [string][uint32]$value; break }
                ([Microsoft.Win32.RegistryValueKind]::QWord) { [string][uint64]$value; break }
                ([Microsoft.Win32.RegistryValueKind]::MultiString) { @([string[]]$value); break }
                ([Microsoft.Win32.RegistryValueKind]::String) { [string]$value; break }
                ([Microsoft.Win32.RegistryValueKind]::ExpandString) { [string]$value; break }
                default { throw "Неподдерживаемый Registry type $kind для $name" }
            }
            $items[$name] = [ordered]@{ present = $true; kind = $kind.ToString(); value = $encoded }
        }
    } finally {
        if ($null -ne $key) { $key.Dispose() }
    }
    return [ordered]@{ version = 1; values = $items }
}

function Restore-RoutingRegistrySnapshot($Snapshot) {
    if ($null -eq $Snapshot -or $Snapshot.version -ne 1) { throw 'Неизвестная версия routing Registry backup' }
    $expected = @('ExceptSites', 'routeMode', 'sitesSplitTunnelingEnabled')
    $actual = @($Snapshot.values.PSObject.Properties.Name | Sort-Object)
    if (($actual -join ',') -cne (@($expected | Sort-Object) -join ',')) { throw 'Routing Registry backup имеет неожиданные поля' }
    $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($ConfSubKey, $true)
    try {
        foreach ($name in $expected) {
            $key.DeleteValue($name, $false)
            $item = $Snapshot.values.PSObject.Properties[$name].Value
            if (-not [bool]$item.present) { continue }
            $kind = [Microsoft.Win32.RegistryValueKind][Enum]::Parse([Microsoft.Win32.RegistryValueKind], [string]$item.kind, $false)
            $value = switch ($kind) {
                ([Microsoft.Win32.RegistryValueKind]::Binary) { [Convert]::FromBase64String([string]$item.value); break }
                ([Microsoft.Win32.RegistryValueKind]::DWord) { [uint32]::Parse([string]$item.value); break }
                ([Microsoft.Win32.RegistryValueKind]::QWord) { [uint64]::Parse([string]$item.value); break }
                ([Microsoft.Win32.RegistryValueKind]::MultiString) { [string[]]@($item.value); break }
                ([Microsoft.Win32.RegistryValueKind]::String) { [string]$item.value; break }
                ([Microsoft.Win32.RegistryValueKind]::ExpandString) { [string]$item.value; break }
                default { throw "Неподдерживаемый Registry type $kind для $name" }
            }
            $key.SetValue($name, $value, $kind)
        }
        $key.Flush()
    } finally { $key.Dispose() }
}

function Recover-RegistryTransaction {
    $journal = Read-JsonFile $JournalPath
    if ($null -eq $journal) { return }
    if (Test-AmneziaRunning) { throw 'Есть незавершённый Registry rollback, но AmneziaVPN запущена; восстановление отложено.' }
    if (-not (Test-Path -LiteralPath ([string]$journal.backup))) { throw 'Registry journal указывает на отсутствующий backup.' }
    Restore-RoutingRegistrySnapshot (Read-JsonFile ([string]$journal.backup))
    Write-JsonAtomic $ManagedPath @($journal.previous_managed)
    Remove-Item -LiteralPath $JournalPath -Force
    Write-Host 'Восстановлен Registry после прерванного обновления.'
}

function Remove-OldRoutingBackups([string]$BackupDir, [int]$Keep = 10) {
    if (-not (Test-Path -LiteralPath $BackupDir -PathType Container)) { return }
    @(Get-ChildItem -LiteralPath $BackupDir -Filter 'routing-*.json' -File |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -Skip $Keep) |
        Remove-Item -Force -ErrorAction Stop
}

function Apply-Routes([string[]]$Cidrs) {
    if (Test-AmneziaRunning) { return $false }
    Recover-RegistryTransaction
    Assert-AmneziaVersion
    $current = Read-ExceptSites
    $previousManaged = @(Read-ManagedCidrs)
    foreach ($old in $previousManaged) { [void]$current.Remove($old) }
    foreach ($cidr in $Cidrs) { $current[$cidr] = @() }

    $backupDir = Join-Path $StateDir 'backups'
    [IO.Directory]::CreateDirectory($backupDir) | Out-Null
    $backupPath = Join-Path $backupDir ("routing-{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
    Write-JsonAtomic $backupPath (Read-RoutingRegistrySnapshot)
    if (Test-AmneziaRunning) { throw 'AmneziaVPN запустилась во время подготовки; Registry не изменён.' }
    Write-JsonAtomic $JournalPath ([ordered]@{
        version = 1
        backup = $backupPath
        previous_managed = $previousManaged
        desired_managed = $Cidrs
    })

    try {
        $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($ConfSubKey, $true)
        try {
            $key.SetValue('ExceptSites', [AmneziaRouteSync.QtVariantMapCodec]::Encode((ConvertTo-QtMap $current)), [Microsoft.Win32.RegistryValueKind]::Binary)
            $key.SetValue('routeMode', 2, [Microsoft.Win32.RegistryValueKind]::DWord)
            $key.SetValue('sitesSplitTunnelingEnabled', 'true', [Microsoft.Win32.RegistryValueKind]::String)
            $key.Flush()
        } finally { $key.Dispose() }
        $verified = Read-ExceptSites
        foreach ($cidr in $Cidrs) { if (-not $verified.ContainsKey($cidr)) { throw "Read-back не содержит $cidr" } }
        foreach ($entry in $current.GetEnumerator()) {
            if (-not $verified.ContainsKey($entry.Key)) { throw "Read-back потерял ручную запись $($entry.Key)" }
            if ((@($verified[$entry.Key]) -join "`n") -cne (@($entry.Value) -join "`n")) {
                throw "Read-back изменил значение $($entry.Key)"
            }
        }
        $verifyKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($ConfSubKey, $false)
        try {
            if ($verifyKey.GetValueKind('routeMode') -ne [Microsoft.Win32.RegistryValueKind]::DWord -or [int]$verifyKey.GetValue('routeMode') -ne 2) {
                throw 'Read-back routeMode не равен DWORD 2'
            }
            if ($verifyKey.GetValueKind('sitesSplitTunnelingEnabled') -ne [Microsoft.Win32.RegistryValueKind]::String -or [string]$verifyKey.GetValue('sitesSplitTunnelingEnabled') -cne 'true') {
                throw 'Read-back sitesSplitTunnelingEnabled не равен true'
            }
        } finally { $verifyKey.Dispose() }
        Write-JsonAtomic $ManagedPath $Cidrs
        Remove-Item -LiteralPath $JournalPath -Force
        Remove-Item -LiteralPath $PendingPath -Force -ErrorAction SilentlyContinue
        try { Remove-OldRoutingBackups $backupDir }
        catch { Write-Warning 'Не удалось ограничить retention routing-backups.' }
        return $true
    } catch {
        try {
            Restore-RoutingRegistrySnapshot (Read-JsonFile $backupPath)
            Write-JsonAtomic $ManagedPath $previousManaged
            Remove-Item -LiteralPath $JournalPath -Force
        } catch {
            throw "АВАРИЯ: Registry rollback не удался; journal сохранён: $($_.Exception.Message)"
        }
        throw
    }
}

function Save-RouteArtifacts($Routes) {
    $desired = @($Routes.Cidrs | Sort-Object)
    $installed = @((Read-ManagedCidrs) | Sort-Object)
    $needsApply = ($desired -join "`n") -cne ($installed -join "`n")
    if (-not $needsApply) {
        $needsApply = -not (Test-InstalledRoutingMatches $desired)
    }
    if ($needsApply) {
        Write-JsonAtomic $PendingPath ([ordered]@{
            version = 1
            generated_at = [DateTime]::UtcNow.ToString('o')
            cidrs = @($Routes.Cidrs)
            source_counts = $Routes.Counts
        })
    } else {
        Remove-Item -LiteralPath $PendingPath -Force -ErrorAction SilentlyContinue
    }
    $import = @($Routes.Cidrs | ForEach-Object { [ordered]@{ hostname = $_; ip = '' } })
    Write-JsonAtomic $ImportPath $import
    return $needsApply
}

function Start-AmneziaIfRequested {
    if (-not $StartAmnezia -or (Test-AmneziaRunning)) { return }
    $state = Read-JsonFile $InstallStatePath
    if ($null -eq $state -or -not (Test-Path -LiteralPath ([string]$state.amnezia_path))) {
        throw 'Не найден сохранённый путь AmneziaVPN.exe.'
    }
    Start-Process -FilePath ([string]$state.amnezia_path) -ArgumentList '--autostart'
}

if ($ValidationSelfTest) {
    Assert-QtCodec
    $network = ConvertTo-Cidr '203.0.113.0/24'
    $hostRoute = ConvertTo-Cidr '203.0.113.100/32'
    if (-not (Test-CidrInside $hostRoute $network)) { throw 'CIDR containment self-test failed.' }
    $strictRejected = $false
    try { $null = ConvertTo-Cidr '203.0.113.100/24' } catch { $strictRejected = $true }
    if (-not $strictRejected) { throw 'Non-network CIDR self-test failed.' }
    $compressed = @(Compress-Cidrs @((ConvertTo-Cidr '10.0.0.0/25'), (ConvertTo-Cidr '10.0.0.128/25'), (ConvertTo-Cidr '10.0.0.1/32')))
    if ($compressed.Count -ne 1 -or $compressed[0].Text -cne '10.0.0.0/24') { throw 'CIDR collapse self-test failed.' }
    $custom = Get-CustomPolicy
    if ($ProtectedIps.Count -eq 0) { throw 'Custom policy self-test: protected_ips пуст' }
    $null = Get-Policy
    $pendingFixture = @(0..38 | ForEach-Object { "84.201.128.$(($_ * 2) + 1)/32" })
    $pendingFixture += '213.184.154.0/23'
    if (@(Assert-PendingRoutes $pendingFixture).Count -ne 40) { throw 'Pending validation self-test failed.' }
    $pendingRejected = $false
    try { $null = Assert-PendingRoutes @('192.0.2.10/32') } catch { $pendingRejected = $true }
    if (-not $pendingRejected) { throw 'Protected pending self-test failed.' }
    Write-Host 'Windows route validation: OK'
    exit 0
}

if (-not $DryRun) { [IO.Directory]::CreateDirectory($StateDir) | Out-Null }
$currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($currentSid -eq 'S-1-5-18') { throw 'Updater нельзя запускать от SYSTEM.' }
$mutex = New-Object Threading.Mutex($false, "Global\Amnezia-Split-Route-Sync-$currentSid")
$hasLock = $false
$mainSucceeded = $false
try {
    # Login-wrapper must not start Amnezia while the periodic updater can still
    # mutate QSettings. Its Scheduled Task has a hard 10-minute execution limit.
    $lockWaitMilliseconds = if ($StartAmnezia) { 660000 } else { 0 }
    try {
        $hasLock = $mutex.WaitOne($lockWaitMilliseconds)
    } catch [Threading.AbandonedMutexException] {
        $hasLock = $true
    }
    if (-not $hasLock) {
        if ($StartAmnezia) {
            $StartAmnezia = $false
            throw 'Не удалось безопасно дождаться updater; Amnezia не запущена.'
        }
        if ($DryRun) { throw 'Другой updater уже работает; dry-run не выполнен.' }
        Write-Host 'Другой updater уже работает.'
        exit 0
    }
    Assert-QtCodec
    if (-not $DryRun) {
        if ((Test-Path -LiteralPath $JournalPath) -and (Test-AmneziaRunning)) {
            Write-Host 'Registry recovery отложен до закрытия AmneziaVPN; свежий pending всё равно будет проверен.'
        } else {
            Recover-RegistryTransaction
        }
        Assert-AmneziaVersion
    }

    # На входе в Windows сначала применяем уже проверенный pending и сразу запускаем VPN.
    # Свежая сеть скачивается после запуска и станет следующим pending, если что-то изменилось.
    if ($StartAmnezia -and -not $DryRun -and -not (Test-AmneziaRunning)) {
        $startupPending = Read-JsonFile $PendingPath
        if ($null -ne $startupPending) {
            $safePending = @(Assert-PendingRoutes @($startupPending.cidrs | ForEach-Object { [string]$_ }))
            [void](Apply-Routes $safePending)
            Start-AmneziaIfRequested
            $StartAmnezia = $false
        }
    }

    if ($ApplyPending) {
        $pending = Read-JsonFile $PendingPath
        if ($null -ne $pending) {
            if (Test-AmneziaRunning) { Write-Host 'AmneziaVPN запущена; pending будет применён при следующем входе.' }
            else {
                $safePending = @(Assert-PendingRoutes @($pending.cidrs | ForEach-Object { [string]$_ }))
                [void](Apply-Routes $safePending)
            }
        }
    } else {
        $routes = Get-DesiredRoutes
        Write-Host "Проверено $(@($routes.Cidrs).Count) IPv4 CIDR, включая пользовательские DNS-маршруты."
        if (-not $DryRun) {
            $needsApply = [bool](Save-RouteArtifacts $routes)
            $changed = $false
            if ($needsApply -and (Test-AmneziaRunning)) {
                Write-Host 'AmneziaVPN запущена: безопасное применение отложено до следующего входа.'
            } elseif ($needsApply) {
                $changed = Apply-Routes @($routes.Cidrs)
            } else {
                Write-Host 'AmneziaVPN уже содержит актуальный managed-набор маршрутов.'
            }
            Write-JsonAtomic $StatusPath ([ordered]@{
                changed = [bool]$changed
                deferred = [bool](Test-Path -LiteralPath $PendingPath)
                cidr_count = @($routes.Cidrs).Count
                source_counts = $routes.Counts
                updated_at = [DateTime]::UtcNow.ToString('o')
            })
        }
    }
    $mainSucceeded = $true
} finally {
    try {
        if ($mainSucceeded) { Start-AmneziaIfRequested }
    } finally {
        if ($hasLock) { [void]$mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
}
