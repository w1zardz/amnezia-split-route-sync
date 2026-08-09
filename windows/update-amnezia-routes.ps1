<#
.SYNOPSIS
Обновляет список RU Direct в split tunneling AmneziaVPN на Windows.

.DESCRIPTION
Источник — список, который собирает этот же репозиторий (tools/build_ru_direct.py)
и публикует в dist/ и в GitHub Releases. Скрипт скачивает его, проверяет и
записывает в QSettings AmneziaVPN (HKCU\Software\AmneziaVPN.ORG\AmneziaVPN\Conf),
аккуратно останавливая и возвращая GUI вместе с туннелем.

Перезагрузка Windows не нужна. Демон AmneziaVPN-service не разбирает туннель,
когда GUI просто закрывают, поэтому старые маршруты живут до перезапуска службы —
скрипт перезапускает её сам и поднимает соединение через AmneziaVPN.exe --connect.
Именно этот шаг раньше заменяли ребутом.

Незавершённая запись журналируется и откатывается при следующем запуске.
#>

[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$Lite,
    [string]$Source,
    [switch]$ReplaceAll,
    [switch]$NoRestart,
    [switch]$SelfTest,
    [switch]$Status,
    [switch]$RecoverOnly,
    [string]$StateDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$IsWindowsHost = ($env:OS -eq 'Windows_NT')
if (-not $IsWindowsHost -and -not $SelfTest) {
    throw 'Этот updater предназначен только для Windows.'
}

if (-not $StateDir) {
    $base = $env:LOCALAPPDATA
    if (-not $base) { $base = [IO.Path]::GetTempPath() }
    $StateDir = Join-Path $base 'AmneziaRouteSync'
}

$ListBase = 'https://raw.githubusercontent.com/w1zardz/amnezia-split-route-sync/master/dist'
$ListFull = "$ListBase/amnezia-ru-direct.json"
$ListLite = "$ListBase/amnezia-ru-direct-lite.json"

$RegistryConfSubKey = 'Software\AmneziaVPN.ORG\AmneziaVPN\Conf'
$GuiProcessName = 'AmneziaVPN'
$DaemonServiceName = 'AmneziaVPN-service'
$TunnelServiceName = 'AmneziaWGTunnel$AmneziaVPN'
$SupportedAppMajor = 5

$RouteModeVpnAllExceptSites = 2
$MaxListBytes = 4194304
# Шире /12 не пускаем: такая сеть означала бы «пол-интернета мимо VPN».
$MinimumPrefix = 12
$MinimumRoutes = 40
$MaximumRoutes = 1500
$MaximumAddresses = [uint64]40000000
$MinimumEntries = 300
$MaximumEntries = 4000
$MaxRegistryEntries = 4096

$ManagedPath = Join-Path $StateDir 'managed-entries.json'
$StatusPath = Join-Path $StateDir 'status.json'
$ImportPath = Join-Path $StateDir 'amnezia-split-routes.json'
$JournalPath = Join-Path $StateDir '.registry-transaction.json'
$BackupDir = Join-Path $StateDir 'backups'

$RoutingValueNames = @('ExceptSites', 'routeMode', 'sitesSplitTunnelingEnabled')
$DaemonStopped = $false

Add-Type -AssemblyName System.Net.Http
Add-Type -AssemblyName System.ServiceProcess

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
            if (count > 8192) throw new InvalidDataException("Too many ExceptSites entries");
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

# --- файлы состояния ----------------------------------------------------------

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

function Write-TextAtomic([string]$Path, [string]$Text) {
    $directory = Split-Path -Parent $Path
    [IO.Directory]::CreateDirectory($directory) | Out-Null
    $temporary = "$Path.tmp.$PID"
    try {
        [IO.File]::WriteAllText($temporary, $Text, (New-Object Text.UTF8Encoding($false)))
        Move-Item -LiteralPath $temporary -Destination $Path -Force
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

function Read-JsonFile([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    return Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Read-ManagedEntries {
    $value = Read-JsonFile $ManagedPath
    if ($null -eq $value) { return @() }
    return @($value | ForEach-Object { [string]$_ })
}

# --- IPv4 ---------------------------------------------------------------------

function ConvertTo-IPv4Number([string]$Address) {
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($Address, [ref]$parsed) -or
        $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
        $parsed.ToString() -cne $Address) {
        throw "Некорректный IPv4: $Address"
    }
    $bytes = $parsed.GetAddressBytes()
    return ([uint64]$bytes[0] -shl 24) -bor ([uint64]$bytes[1] -shl 16) -bor ([uint64]$bytes[2] -shl 8) -bor [uint64]$bytes[3]
}

function ConvertFrom-IPv4Number([uint64]$Address) {
    return '{0}.{1}.{2}.{3}' -f (($Address -shr 24) -band 255), (($Address -shr 16) -band 255), (($Address -shr 8) -band 255), ($Address -band 255)
}

function Get-PrefixMask([int]$Prefix) {
    if ($Prefix -eq 0) { return [uint64]0 }
    return (([uint64]4294967295 -shl (32 - $Prefix)) -band [uint64]4294967295)
}

function New-Cidr([uint64]$Network, [int]$Prefix) {
    $mask = Get-PrefixMask $Prefix
    if (($Network -band $mask) -ne $Network) { throw 'CIDR не является network address' }
    return [pscustomobject]@{
        Text    = "$(ConvertFrom-IPv4Number $Network)/$Prefix"
        Prefix  = $Prefix
        Network = $Network
        Mask    = $mask
        Count   = [uint64]1 -shl (32 - $Prefix)
    }
}

function ConvertTo-Cidr([string]$Value) {
    if ($Value.Contains('/')) {
        $parts = $Value.Split('/')
        if ($parts.Count -ne 2) { throw "Некорректный CIDR: $Value" }
        $prefix = 0
        if (-not [int]::TryParse($parts[1], [ref]$prefix) -or $prefix -lt 0 -or $prefix -gt 32) {
            throw "Некорректный CIDR: $Value"
        }
        return (New-Cidr (ConvertTo-IPv4Number $parts[0]) $prefix)
    }
    return (New-Cidr (ConvertTo-IPv4Number $Value) 32)
}

$ReservedRanges = @(
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
    '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16',
    '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4'
)

function Test-CidrGlobal($Cidr) {
    $start = [uint64]$Cidr.Network
    $end = [uint64]($Cidr.Network + $Cidr.Count - 1)
    foreach ($value in $ReservedRanges) {
        $parts = $value.Split('/')
        $reservedNetwork = ConvertTo-IPv4Number $parts[0]
        $reservedCount = [uint64]1 -shl (32 - [int]$parts[1])
        $reservedEnd = $reservedNetwork + $reservedCount - 1
        if ($start -le $reservedEnd -and $reservedNetwork -le $end) { return $false }
    }
    return $true
}

function Compress-Cidrs($Cidrs) {
    $sorted = @($Cidrs | Sort-Object -Property @{ Expression = { $_.Network } }, @{ Expression = { $_.Prefix } })
    $stack = New-Object 'System.Collections.Generic.List[object]'
    foreach ($item in $sorted) {
        $current = $item
        while ($null -ne $current -and $stack.Count -gt 0) {
            $top = $stack[$stack.Count - 1]
            $topEnd = [uint64]($top.Network + $top.Count - 1)
            $currentEnd = [uint64]($current.Network + $current.Count - 1)
            if ($current.Network -ge $top.Network -and $currentEnd -le $topEnd) {
                $current = $null
                break
            }
            if ($top.Prefix -eq $current.Prefix -and $top.Prefix -gt 0 -and
                $current.Network -eq ($top.Network + $top.Count)) {
                $parentMask = Get-PrefixMask ($top.Prefix - 1)
                if (($top.Network -band $parentMask) -eq $top.Network) {
                    $stack.RemoveAt($stack.Count - 1)
                    $current = New-Cidr $top.Network ($top.Prefix - 1)
                    continue
                }
            }
            break
        }
        if ($null -ne $current) { $stack.Add($current) }
    }
    return @($stack.ToArray())
}

function Test-Hostname([string]$Value) {
    if (-not $Value -or $Value.Length -gt 253 -or -not $Value.Contains('.')) { return $false }
    if ($Value -cne $Value.ToLowerInvariant()) { return $false }
    if ($Value.StartsWith('.') -or $Value.StartsWith('-') -or $Value.EndsWith('.') -or $Value.EndsWith('-')) { return $false }
    if ($Value -notmatch '^[a-z0-9.-]+$') { return $false }
    foreach ($label in $Value.Split('.')) {
        if ($label.Length -lt 1 -or $label.Length -gt 63) { return $false }
    }
    return $true
}

# --- загрузка и проверка списка ------------------------------------------------

function Get-HttpsText([string]$Url) {
    if (-not $Url.StartsWith('https://', [StringComparison]::OrdinalIgnoreCase)) { throw "Разрешён только HTTPS: $Url" }
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.AllowAutoRedirect = $false
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(60)
    $client.DefaultRequestHeaders.UserAgent.ParseAdd('Amnezia-Split-Route-Sync-Windows/2.0')
    $response = $null
    $stream = $null
    $memory = $null
    $cancellation = New-Object Threading.CancellationTokenSource
    $cancellation.CancelAfter(60000)
    try {
        $response = $client.GetAsync($Url, [Net.Http.HttpCompletionOption]::ResponseHeadersRead, $cancellation.Token).GetAwaiter().GetResult()
        if (-not $response.IsSuccessStatusCode) { throw "Источник вернул HTTP $([int]$response.StatusCode): $Url" }
        if ($null -ne $response.Content.Headers.ContentLength -and [long]$response.Content.Headers.ContentLength -gt $MaxListBytes) {
            throw "Источник больше $MaxListBytes байт: $Url"
        }
        $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $memory = New-Object IO.MemoryStream
        $buffer = New-Object byte[] 65536
        $total = 0
        while (($read = $stream.ReadAsync($buffer, 0, $buffer.Length, $cancellation.Token).GetAwaiter().GetResult()) -gt 0) {
            $total += $read
            if ($total -gt $MaxListBytes) { throw "Источник больше $MaxListBytes байт: $Url" }
            $memory.Write($buffer, 0, $read)
        }
        if ($total -eq 0) { throw "Источник пуст: $Url" }
        $utf8 = [Text.UTF8Encoding]::new($false, $true)
        return $utf8.GetString($memory.ToArray())
    } catch [Threading.Tasks.TaskCanceledException] {
        # HttpClient переводит собственный таймаут именно в это исключение, а
        # необработанным оно вылезает в консоль как «Отменена задача» без единого
        # намёка на причину.
        throw "Источник не ответил за 60 секунд: $Url"
    } catch [OperationCanceledException] {
        throw "Источник не ответил за 60 секунд: $Url"
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if ($null -ne $memory) { $memory.Dispose() }
        if ($null -ne $response) { $response.Dispose() }
        $cancellation.Dispose()
        $client.Dispose()
        $handler.Dispose()
    }
}

function Get-SourceText([string]$SourceValue) {
    if ($SourceValue.StartsWith('https://', [StringComparison]::OrdinalIgnoreCase)) {
        # Задача по расписанию просыпается вместе с сетью, а список тянется из-за
        # рубежа: одна заминка не должна отменять весь запуск на шесть часов.
        $attempt = 0
        while ($true) {
            $attempt++
            try { return (Get-HttpsText $SourceValue) } catch {
                if ($attempt -ge 3) { throw }
                Write-Host "Загрузка не удалась ($($_.Exception.Message)), попытка $attempt из 3"
                Start-Sleep -Seconds (5 * $attempt)
            }
        }
    }
    if (-not (Test-Path -LiteralPath $SourceValue -PathType Leaf)) { throw "Не найден файл списка: $SourceValue" }
    $info = Get-Item -LiteralPath $SourceValue
    if ($info.Length -gt $MaxListBytes) { throw "Файл списка больше $MaxListBytes байт: $SourceValue" }
    return [IO.File]::ReadAllText($SourceValue, (New-Object Text.UTF8Encoding($false, $true)))
}

function ConvertFrom-ImportList([string]$Text, [string]$SourceName) {
    # Формат импорта Amnezia: [{"hostname": "<домен или CIDR>", "ip": ""}]
    $document = $null
    try { $document = $Text | ConvertFrom-Json } catch { throw "${SourceName}: список не является валидным JSON" }
    $entries = @($document)
    if ($entries.Count -eq 0) { throw "${SourceName}: ожидается непустой массив записей" }

    $domains = New-Object 'System.Collections.Generic.List[string]'
    $networks = New-Object 'System.Collections.Generic.List[object]'
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $index = -1
    foreach ($entry in $entries) {
        $index++
        if ($null -eq $entry -or $entry -isnot [psobject] -or
            ($entry.PSObject.Properties.Name -notcontains 'hostname')) {
            throw "${SourceName}: запись $index без hostname"
        }
        $value = [string]$entry.hostname
        if (-not $value -or -not $value.Trim()) { throw "${SourceName}: запись $index без hostname" }
        $value = $value.Trim().ToLowerInvariant().TrimEnd('.')
        if (-not $seen.Add($value)) { continue }

        if ($value.Contains('/') -or $value -match '^[0-9.]+$') {
            $cidr = ConvertTo-Cidr $value
            if ($cidr.Prefix -lt $MinimumPrefix) { throw "${SourceName}: слишком широкая сеть $value" }
            if (-not (Test-CidrGlobal $cidr)) { throw "${SourceName}: сеть $value не является публичной" }
            $networks.Add($cidr)
            continue
        }
        if (-not (Test-Hostname $value)) { throw "${SourceName}: некорректный домен $value" }
        $domains.Add($value)
    }

    $total = $domains.Count + $networks.Count
    if ($total -lt $MinimumEntries -or $total -gt $MaximumEntries) {
        throw "${SourceName}: $total записей вне допустимого диапазона $MinimumEntries..$MaximumEntries"
    }

    $collapsed = @(Compress-Cidrs $networks.ToArray())
    if ($collapsed.Count -lt $MinimumRoutes -or $collapsed.Count -gt $MaximumRoutes) {
        throw "подозрительное число маршрутов: $($collapsed.Count) (допустимо $MinimumRoutes..$MaximumRoutes)"
    }
    $covered = [uint64]0
    foreach ($cidr in $collapsed) { $covered += $cidr.Count }
    if ($covered -gt $MaximumAddresses) { throw "список покрывает слишком много IPv4-адресов: $covered" }

    $sortedDomains = @($domains.ToArray() | Sort-Object -CaseSensitive)
    return [pscustomobject]@{
        Domains = $sortedDomains
        Cidrs   = @($collapsed | ForEach-Object { $_.Text })
    }
}

# --- реестр -------------------------------------------------------------------

function Read-ExceptSites {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($RegistryConfSubKey, $false)
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

function Read-RoutingScalars {
    $result = [ordered]@{ mode = $null; enabled = $null }
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($RegistryConfSubKey, $false)
    if ($null -eq $key) { return $result }
    try {
        $names = @($key.GetValueNames())
        if ($names -contains 'routeMode') { $result.mode = [string]$key.GetValue('routeMode') }
        if ($names -contains 'sitesSplitTunnelingEnabled') { $result.enabled = [string]$key.GetValue('sitesSplitTunnelingEnabled') }
    } finally { $key.Dispose() }
    return $result
}

function ConvertTo-QtMap($Sites) {
    $map = New-Object 'System.Collections.Generic.Dictionary[string,System.Collections.Generic.List[string]]' ([StringComparer]::Ordinal)
    foreach ($key in @($Sites.Keys)) {
        $values = New-Object 'System.Collections.Generic.List[string]'
        foreach ($value in @($Sites[$key])) { if ($null -ne $value) { $values.Add([string]$value) } }
        $map.Add([string]$key, $values)
    }
    return $map
}

function Read-RoutingRegistrySnapshot {
    $items = [ordered]@{}
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($RegistryConfSubKey, $false)
    try {
        $valueNames = if ($null -ne $key) { @($key.GetValueNames()) } else { @() }
        foreach ($name in $RoutingValueNames) {
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
    $actual = @($Snapshot.values.PSObject.Properties.Name | Sort-Object)
    if (($actual -join ',') -cne (@($RoutingValueNames | Sort-Object) -join ',')) {
        throw 'Routing Registry backup имеет неожиданные поля'
    }
    $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($RegistryConfSubKey, $true)
    try {
        foreach ($name in $RoutingValueNames) {
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

function Write-RoutingRegistry($Sites) {
    $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($RegistryConfSubKey, $true)
    try {
        $key.SetValue('ExceptSites', [AmneziaRouteSync.QtVariantMapCodec]::Encode((ConvertTo-QtMap $Sites)), [Microsoft.Win32.RegistryValueKind]::Binary)
        $key.SetValue('routeMode', $RouteModeVpnAllExceptSites, [Microsoft.Win32.RegistryValueKind]::DWord)
        $key.SetValue('sitesSplitTunnelingEnabled', 'true', [Microsoft.Win32.RegistryValueKind]::String)
        $key.Flush()
    } finally { $key.Dispose() }
}

function Assert-RoutingRegistry($Sites) {
    $verified = Read-ExceptSites
    foreach ($entry in $Sites.GetEnumerator()) {
        if (-not $verified.ContainsKey($entry.Key)) { throw "Read-back не содержит запись $($entry.Key)" }
        if ((@($verified[$entry.Key]) -join "`n") -cne (@($entry.Value) -join "`n")) {
            throw "Read-back изменил значение $($entry.Key)"
        }
    }
    if ($verified.Count -ne $Sites.Count) { throw 'Read-back содержит лишние записи' }
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($RegistryConfSubKey, $false)
    if ($null -eq $key) { throw 'Read-back не нашёл ключ Conf' }
    try {
        if ($key.GetValueKind('routeMode') -ne [Microsoft.Win32.RegistryValueKind]::DWord -or
            [int]$key.GetValue('routeMode') -ne $RouteModeVpnAllExceptSites) {
            throw "Read-back routeMode не равен DWORD $RouteModeVpnAllExceptSites"
        }
        if ($key.GetValueKind('sitesSplitTunnelingEnabled') -ne [Microsoft.Win32.RegistryValueKind]::String -or
            [string]$key.GetValue('sitesSplitTunnelingEnabled') -cne 'true') {
            throw 'Read-back sitesSplitTunnelingEnabled не равен true'
        }
    } finally { $key.Dispose() }
}

function Get-DesiredSites($Current, [string[]]$PreviousManaged, [string[]]$Entries) {
    $desired = @{}
    if (-not $ReplaceAll) {
        $previous = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
        foreach ($value in @($PreviousManaged)) { [void]$previous.Add($value) }
        foreach ($entry in $Current.GetEnumerator()) {
            if (-not $previous.Contains($entry.Key)) { $desired[$entry.Key] = @($entry.Value) }
        }
    }
    # Amnezia дописывает в значение записи резолвнутые IP домена. Затирать их
    # пустым списком нельзя: иначе каждый запуск видел бы «список изменился»
    # и дёргал GUI с туннелем на ровном месте.
    foreach ($entry in @($Entries)) {
        if ($Current.ContainsKey($entry)) { $desired[$entry] = @($Current[$entry]) }
        else { $desired[$entry] = @() }
    }
    if ($desired.Count -gt $MaxRegistryEntries) {
        throw "итоговый список из $($desired.Count) записей превышает лимит $MaxRegistryEntries"
    }
    return $desired
}

function Test-SitesEqual($Left, $Right) {
    if ($Left.Count -ne $Right.Count) { return $false }
    foreach ($entry in $Left.GetEnumerator()) {
        if (-not $Right.ContainsKey($entry.Key)) { return $false }
        if ((@($entry.Value) -join "`n") -cne (@($Right[$entry.Key]) -join "`n")) { return $false }
    }
    return $true
}

# --- процессы, службы, сессия --------------------------------------------------

function Test-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-GuiProcesses {
    return @(Get-Process -Name $GuiProcessName -ErrorAction SilentlyContinue)
}

# return @(...) разворачивает массив обратно в один объект, поэтому оборачиваем
# результат на каждой стороне вызова: под Set-StrictMode .Count на Process падает.
function Test-GuiRunning { return @(Get-GuiProcesses).Count -gt 0 }

function Get-AmneziaService {
    $service = Get-Service -Name $DaemonServiceName -ErrorAction SilentlyContinue
    if ($null -ne $service) { return $service }
    $candidates = @(Get-Service -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'Amnezia*' -and $_.Name -notlike '*Tunnel*' })
    if ($candidates.Count -eq 1) { return $candidates[0] }
    return $null
}

function Get-TunnelService {
    $service = Get-Service -Name $TunnelServiceName -ErrorAction SilentlyContinue
    if ($null -ne $service) { return $service }
    $candidates = @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*Tunnel$AmneziaVPN' })
    if ($candidates.Count -eq 1) { return $candidates[0] }
    return $null
}

function Test-TunnelServiceRunning {
    $tunnel = Get-TunnelService
    if ($null -eq $tunnel) { return $false }
    $tunnel.Refresh()
    return ($tunnel.Status -eq [ServiceProcess.ServiceControllerStatus]::Running -or
            $tunnel.Status -eq [ServiceProcess.ServiceControllerStatus]::StartPending)
}

function Test-VpnAdapterUp {
    # AmneziaWG поднимает Wintun-адаптер, OpenVPN — TAP-Windows. Лишний
    # false positive безвреден (перезапустим службу зря), false negative —
    # это ровно тот баг, из-за которого раньше требовалась перезагрузка.
    foreach ($adapter in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        if ($adapter.OperationalStatus -ne [Net.NetworkInformation.OperationalStatus]::Up) { continue }
        $text = "$($adapter.Name) $($adapter.Description)"
        if ($text -match '(?i)amnezia|wintun|wireguard|tap-windows') { return $true }
    }
    return $false
}

function Test-TunnelRunning {
    if (Test-TunnelServiceRunning) { return $true }
    return (Test-VpnAdapterUp)
}

function Get-AmneziaExePath {
    foreach ($process in (Get-GuiProcesses)) {
        try {
            if ($process.Path -and (Test-Path -LiteralPath $process.Path -PathType Leaf)) { return $process.Path }
        } catch { }
    }
    $candidates = New-Object 'System.Collections.Generic.List[string]'
    if ($env:ProgramFiles) { $candidates.Add((Join-Path $env:ProgramFiles 'AmneziaVPN\AmneziaVPN.exe')) }
    if (${env:ProgramFiles(x86)}) { $candidates.Add((Join-Path ${env:ProgramFiles(x86)} 'AmneziaVPN\AmneziaVPN.exe')) }
    if ($env:LOCALAPPDATA) { $candidates.Add((Join-Path $env:LOCALAPPDATA 'Programs\AmneziaVPN\AmneziaVPN.exe')) }
    $service = Get-AmneziaService
    if ($null -ne $service) {
        $imagePath = (Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)" -ErrorAction SilentlyContinue).ImagePath
        if ($imagePath) {
            $exe = $imagePath.Trim('"')
            if ($exe -match '^(?<path>.+?\.exe)') { $exe = $Matches['path'] }
            $directory = Split-Path -Parent $exe
            if ($directory) { $candidates.Add((Join-Path $directory 'AmneziaVPN.exe')) }
        }
    }
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    throw 'Не найден AmneziaVPN.exe. Установите AmneziaVPN 5.x и повторите.'
}

function Assert-AmneziaVersion([string]$ExePath) {
    $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($ExePath).ProductVersion
    $major = 0
    if (-not $version -or -not [int]::TryParse(($version -split '\.')[0], [ref]$major) -or $major -ne $SupportedAppMajor) {
        throw "Поддерживается AmneziaVPN major $SupportedAppMajor, найдена версия $version"
    }
    return $version
}

function Get-AmneziaSession {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($RegistryConfSubKey, $false)
    $autoConnect = $false
    $serverIndex = 0
    try {
        if ($null -ne $key) {
            $names = @($key.GetValueNames())
            if ($names -contains 'autoConnect') { $autoConnect = ([string]$key.GetValue('autoConnect') -ceq 'true') }
        }
    } finally { if ($null -ne $key) { $key.Dispose() } }
    $serversKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\AmneziaVPN.ORG\AmneziaVPN\Servers', $false)
    try {
        if ($null -ne $serversKey -and (@($serversKey.GetValueNames()) -contains 'defaultServerIndex')) {
            $raw = $serversKey.GetValue('defaultServerIndex')
            $parsed = 0
            if ([int]::TryParse([string]$raw, [ref]$parsed)) { $serverIndex = $parsed }
        }
    } finally { if ($null -ne $serversKey) { $serversKey.Dispose() } }

    return [pscustomobject]@{
        GuiRunning  = (Test-GuiRunning)
        Connected   = (Test-TunnelRunning)
        AutoConnect = $autoConnect
        ServerIndex = $serverIndex
    }
}

function ConvertTo-SessionDocument($Session) {
    return [ordered]@{
        gui_running  = [bool]$Session.GuiRunning
        connected    = [bool]$Session.Connected
        auto_connect = [bool]$Session.AutoConnect
        server_index = [int]$Session.ServerIndex
    }
}

function ConvertFrom-SessionDocument($Value) {
    if ($null -eq $Value) { throw 'transaction journal не содержит Amnezia session' }
    foreach ($name in @('gui_running', 'connected', 'auto_connect', 'server_index')) {
        if ($Value.PSObject.Properties.Name -notcontains $name) { throw 'transaction journal содержит неполную Amnezia session' }
    }
    return [pscustomobject]@{
        GuiRunning  = [bool]$Value.gui_running
        Connected   = [bool]$Value.connected
        AutoConnect = [bool]$Value.auto_connect
        ServerIndex = [int]$Value.server_index
    }
}

function Stop-AmneziaGui {
    $processes = @(Get-GuiProcesses)
    if ($processes.Count -eq 0) { return }
    foreach ($process in $processes) {
        try { [void]$process.CloseMainWindow() } catch { }
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    while ([DateTime]::UtcNow -lt $deadline -and (Test-GuiRunning)) { Start-Sleep -Milliseconds 250 }
    foreach ($process in (Get-GuiProcesses)) {
        try { $process.Kill() } catch { }
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    while ([DateTime]::UtcNow -lt $deadline -and (Test-GuiRunning)) { Start-Sleep -Milliseconds 250 }
    if (Test-GuiRunning) { throw 'AmneziaVPN не завершилась за 25 секунд; Registry не изменён.' }
    # Qt дописывает кэш QSettings в реестр при выходе приложения.
    Start-Sleep -Milliseconds 750
}

function Wait-ServiceStatus($Service, [ServiceProcess.ServiceControllerStatus]$Status, [int]$Seconds) {
    try {
        $Service.WaitForStatus($Status, [TimeSpan]::FromSeconds($Seconds))
        return $true
    } catch [ServiceProcess.TimeoutException] {
        return $false
    }
}

function Stop-ServiceHard($Service) {
    $Service.Refresh()
    if ($Service.Status -eq [ServiceProcess.ServiceControllerStatus]::Stopped) { return $true }
    try {
        Stop-Service -InputObject $Service -Force -ErrorAction Stop
    } catch {
        Write-Warning "SCM не остановил $($Service.Name): $($_.Exception.Message)"
    }
    if (Wait-ServiceStatus $Service ([ServiceProcess.ServiceControllerStatus]::Stopped) 20) { return $true }
    # Служба может не объявлять SERVICE_ACCEPT_STOP — тогда гасим её процесс.
    $servicePid = 0
    try {
        $instance = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($Service.Name)'" -ErrorAction Stop
        if ($null -ne $instance) { $servicePid = [int]$instance.ProcessId }
    } catch {
        Write-Warning "не удалось узнать PID службы $($Service.Name): $($_.Exception.Message)"
    }
    if ($servicePid -gt 0) {
        Write-Host "Служба $($Service.Name) не приняла stop, снимаю процесс $servicePid"
        Stop-Process -Id $servicePid -Force -ErrorAction SilentlyContinue
    }
    return (Wait-ServiceStatus $Service ([ServiceProcess.ServiceControllerStatus]::Stopped) 20)
}

function Stop-AmneziaTunnel {
    # Демон не разбирает туннель, когда GUI просто закрывают: маршруты прошлого
    # списка остаются в таблице. Достаточно снять туннельную службу — вместе с
    # адаптером уходят и её маршруты. Демон трогаем только если это не помогло.
    $tunnel = Get-TunnelService
    if ($null -ne $tunnel) {
        if (-not (Stop-ServiceHard $tunnel)) {
            throw "Служба $($tunnel.Name) не остановилась"
        }
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    while ([DateTime]::UtcNow -lt $deadline -and (Test-VpnAdapterUp)) { Start-Sleep -Milliseconds 500 }
    if (-not (Test-VpnAdapterUp)) { return }

    $daemon = Get-AmneziaService
    if ($null -eq $daemon) { throw 'VPN-адаптер остался поднят, а служба демона не найдена' }
    if (-not (Stop-ServiceHard $daemon)) {
        throw "Служба $($daemon.Name) не остановилась"
    }
    $script:DaemonStopped = $true
}

function Start-AmneziaDaemon {
    $daemon = Get-AmneziaService
    if ($null -eq $daemon) { return }
    $daemon.Refresh()
    if ($daemon.Status -eq [ServiceProcess.ServiceControllerStatus]::Running) { return }
    Start-Service -InputObject $daemon -ErrorAction Stop
    if (-not (Wait-ServiceStatus $daemon ([ServiceProcess.ServiceControllerStatus]::Running) 30)) {
        throw "Служба $($daemon.Name) не запустилась за 30 секунд"
    }
}

function Restore-AmneziaSession($Session, [string]$ExePath) {
    if ($Session.Connected) { Start-AmneziaDaemon }
    if (-not $Session.GuiRunning) { return }
    if (Test-GuiRunning) { return }
    if (-not $ExePath) {
        Write-Warning 'Не найден AmneziaVPN.exe: приложение придётся запустить вручную.'
        return
    }
    $arguments = @()
    if ($Session.Connected -and -not $Session.AutoConnect) {
        $arguments = @('--connect', [string]$Session.ServerIndex)
    } elseif ($Session.Connected) {
        $arguments = @('--autostart')
    }
    if ($arguments.Count -gt 0) {
        Start-Process -FilePath $ExePath -ArgumentList $arguments | Out-Null
    } else {
        Start-Process -FilePath $ExePath | Out-Null
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    while ([DateTime]::UtcNow -lt $deadline -and -not (Test-GuiRunning)) { Start-Sleep -Milliseconds 250 }
    if (-not (Test-GuiRunning)) { throw 'настройки записаны, но процесс AmneziaVPN не появился' }
    if (-not $Session.Connected) { return }
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    while ([DateTime]::UtcNow -lt $deadline -and -not (Test-TunnelRunning)) { Start-Sleep -Milliseconds 500 }
    if (-not (Test-TunnelRunning)) {
        Write-Warning 'Настройки записаны, но туннель не поднялся за 60 секунд — нажмите «Подключиться» в AmneziaVPN.'
    }
}

# --- транзакция ----------------------------------------------------------------

function Remove-OldRoutingBackups([int]$Keep = 10) {
    if (-not (Test-Path -LiteralPath $BackupDir -PathType Container)) { return }
    @(Get-ChildItem -LiteralPath $BackupDir -Filter 'routing-*.json' -File |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -Skip $Keep) | Remove-Item -Force -ErrorAction SilentlyContinue
}

function Restore-PendingTransaction([string]$ExePath) {
    $journal = Read-JsonFile $JournalPath
    if ($null -eq $journal) { return }
    if ($journal.version -ne 1) { throw "повреждён transaction journal $JournalPath" }
    $session = ConvertFrom-SessionDocument $journal.session
    $phase = [string]$journal.phase

    if ($phase -eq 'stopping') {
        Restore-AmneziaSession $session $ExePath
        Remove-Item -LiteralPath $JournalPath -Force
        Write-Host 'Восстановлена AmneziaVPN после прерванной подготовки.'
        return
    }
    if ($phase -ne 'writing') { throw "transaction journal содержит неизвестную фазу '$phase'" }
    $backupPath = [string]$journal.backup
    if (-not (Test-Path -LiteralPath $backupPath -PathType Leaf)) {
        throw "Registry journal указывает на отсутствующий backup: $backupPath"
    }
    Stop-AmneziaGui
    if ($session.Connected) {
        if (Test-Elevated) {
            Stop-AmneziaTunnel
        } else {
            Write-Warning 'Нет прав администратора: туннель не перезапущен, старые маршруты доживут до переподключения VPN.'
        }
    }
    Restore-RoutingRegistrySnapshot (Read-JsonFile $backupPath)
    Write-JsonAtomic $ManagedPath @($journal.previous_managed | ForEach-Object { [string]$_ })
    Remove-Item -LiteralPath $JournalPath -Force
    Restore-AmneziaSession $session $ExePath
    Write-Host 'Откачена незавершённая routing-транзакция.'
}

function Invoke-RoutingTransaction([string[]]$Entries, [string]$ExePath) {
    $current = Read-ExceptSites
    $previousManaged = @(Read-ManagedEntries)
    $desired = Get-DesiredSites $current $previousManaged $Entries
    $scalars = Read-RoutingScalars
    $manualCount = $desired.Count - @($Entries).Count

    $needsChange = -not (Test-SitesEqual $current $desired) -or
                   ([string]$scalars.mode -cne [string]$RouteModeVpnAllExceptSites) -or
                   ([string]$scalars.enabled -cne 'true')
    if (-not $needsChange) {
        Write-JsonAtomic $ManagedPath @($Entries)
        return [pscustomobject]@{ Changed = $false; ManualCount = $manualCount }
    }

    $session = Get-AmneziaSession
    if ($NoRestart) {
        if ($session.GuiRunning -or $session.Connected) {
            throw 'Указан -NoRestart, но AmneziaVPN запущена: закройте её и отключите VPN, иначе запись затрётся.'
        }
    } elseif ($session.Connected -and -not (Test-Elevated)) {
        throw ('AmneziaVPN подключена: чтобы применить новый список без перезагрузки Windows, ' +
               'нужно перезапустить службу AmneziaVPN-service. Запустите PowerShell от имени администратора.')
    }

    [IO.Directory]::CreateDirectory($BackupDir) | Out-Null
    Write-JsonAtomic $JournalPath ([ordered]@{
        version = 1
        phase   = 'stopping'
        session = (ConvertTo-SessionDocument $session)
    })

    $stopAttempted = $false
    $resolved = $false
    try {
        if (-not $NoRestart) {
            $stopAttempted = $true
            Stop-AmneziaGui
            if ($session.Connected) { Stop-AmneziaTunnel }
        }

        # После выхода GUI кэш QSettings уже на диске — перечитываем факт.
        $current = Read-ExceptSites
        $desired = Get-DesiredSites $current $previousManaged $Entries
        $manualCount = $desired.Count - @($Entries).Count

        $backupPath = Join-Path $BackupDir ("routing-{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
        Write-JsonAtomic $backupPath (Read-RoutingRegistrySnapshot)
        Write-JsonAtomic $JournalPath ([ordered]@{
            version          = 1
            phase            = 'writing'
            session          = (ConvertTo-SessionDocument $session)
            backup           = $backupPath
            previous_managed = @($previousManaged)
            desired_managed  = @($Entries)
        })

        try {
            Write-RoutingRegistry $desired
            Assert-RoutingRegistry $desired
            Write-JsonAtomic $ManagedPath @($Entries)
            $resolved = $true
        } catch {
            try {
                Restore-RoutingRegistrySnapshot (Read-JsonFile $backupPath)
                Write-JsonAtomic $ManagedPath @($previousManaged)
                $resolved = $true
            } catch {
                throw "АВАРИЯ: routing rollback не удался; journal сохранён: $($_.Exception.Message)"
            }
            throw
        }
    } finally {
        if ($stopAttempted) {
            Restore-AmneziaSession $session $ExePath
        }
        if ($resolved) {
            Remove-Item -LiteralPath $JournalPath -Force -ErrorAction SilentlyContinue
            Remove-OldRoutingBackups
        }
    }

    return [pscustomobject]@{ Changed = $true; ManualCount = $manualCount }
}

# --- self-test -----------------------------------------------------------------

if ($SelfTest) {
    Assert-QtCodec
    $network = ConvertTo-Cidr '203.0.113.0/24'
    $hostRoute = ConvertTo-Cidr '203.0.113.100/32'
    if ($hostRoute.Prefix -ne 32 -or $network.Count -ne 256) { throw 'CIDR self-test failed.' }
    $strictRejected = $false
    try { $null = ConvertTo-Cidr '203.0.113.100/24' } catch { $strictRejected = $true }
    if (-not $strictRejected) { throw 'Non-network CIDR self-test failed.' }
    $collapsed = @(Compress-Cidrs @((ConvertTo-Cidr '10.0.0.0/25'), (ConvertTo-Cidr '10.0.0.128/25'), (ConvertTo-Cidr '10.0.0.1/32')))
    if ($collapsed.Count -ne 1 -or $collapsed[0].Text -cne '10.0.0.0/24') { throw 'CIDR collapse self-test failed.' }
    $chain = @(Compress-Cidrs @((ConvertTo-Cidr '5.255.192.0/18'), (ConvertTo-Cidr '5.255.128.0/18'), (ConvertTo-Cidr '5.255.0.0/17')))
    if ($chain.Count -ne 1 -or $chain[0].Text -cne '5.255.0.0/16') { throw 'CIDR merge-chain self-test failed.' }
    $unaligned = @(Compress-Cidrs @((ConvertTo-Cidr '10.0.1.0/24'), (ConvertTo-Cidr '10.0.2.0/24')))
    if ($unaligned.Count -ne 2) { throw 'CIDR unaligned-merge self-test failed.' }
    if (Test-CidrGlobal (ConvertTo-Cidr '10.0.0.0/12')) { throw 'Reserved-range self-test failed.' }
    if (-not (Test-CidrGlobal (ConvertTo-Cidr '5.255.0.0/16'))) { throw 'Global-range self-test failed.' }
    if (-not (Test-Hostname 'gosuslugi.ru') -or (Test-Hostname 'GosUslugi.ru') -or (Test-Hostname 'no-dot')) {
        throw 'Hostname self-test failed.'
    }
    $fixture = @(
        @(1..300 | ForEach-Object { [pscustomobject]@{ hostname = "host$_.example.ru"; ip = '' } }),
        @(0..39 | ForEach-Object { [pscustomobject]@{ hostname = "5.255.$($_ * 2).0/24"; ip = '' } })
    ) | ForEach-Object { $_ }
    $parsed = ConvertFrom-ImportList (($fixture | ConvertTo-Json -Depth 5)) 'self-test'
    if ($parsed.Domains.Count -ne 300 -or $parsed.Cidrs.Count -ne 40) { throw 'Import-list self-test failed.' }
    $rejected = $false
    try { $null = ConvertFrom-ImportList '[{"hostname":"10.0.0.0/8","ip":""}]' 'self-test' } catch { $rejected = $true }
    if (-not $rejected) { throw 'Private-network rejection self-test failed.' }
    $bulk = @{}
    foreach ($entry in (@($parsed.Domains) + @($parsed.Cidrs))) { $bulk[$entry] = @() }
    $bulkEncoded = [AmneziaRouteSync.QtVariantMapCodec]::Encode((ConvertTo-QtMap $bulk))
    $bulkDecoded = [AmneziaRouteSync.QtVariantMapCodec]::Decode($bulkEncoded)
    if ($bulkDecoded.Count -ne $bulk.Count) { throw 'Bulk QVariantMap round-trip self-test failed.' }
    Write-Host 'Windows updater self-test: OK'
    if ($Source) {
        $list = ConvertFrom-ImportList (Get-SourceText $Source) $Source
        Write-Host "Список $Source принят: $($list.Domains.Count) доменов и $($list.Cidrs.Count) сетей IPv4"
    }
    exit 0
}

# --- диагностика ----------------------------------------------------------------

if ($Status) {
    $sites = Read-ExceptSites
    $scalars = Read-RoutingScalars
    $managed = @(Read-ManagedEntries)
    Write-Host "Записей в Conf\ExceptSites: $($sites.Count)"
    Write-Host "routeMode: $($scalars.mode) (нужно 2)"
    Write-Host "sitesSplitTunnelingEnabled: $($scalars.enabled) (нужно true)"
    Write-Host "Записей под управлением скрипта: $($managed.Count)"

    try {
        foreach ($probe in @('gosuslugi.ru', 'esia.gosuslugi.ru', 'sberbank.ru', '213.59.252.0/22')) {
            # Присваивание из if разворачивает пустой массив в $null, поэтому @() отдельно.
            $values = @()
            if ($sites.ContainsKey($probe)) { $values = @($sites[$probe]) }
            $present = if ($sites.ContainsKey($probe)) { 'есть' } else { 'НЕТ' }
            $resolved = if ($values.Count -gt 0) { " (значения: $($values -join ', '))" } else { ' (значения пусты)' }
            Write-Host "  $probe в списке: $present$resolved"
        }
        $networkKeys = @($sites.Keys | Where-Object { $_ -like '*/*' })
        $domainKeys = @($sites.Keys | Where-Object { $_ -notlike '*/*' })
        Write-Host "Ключей-сетей: $($networkKeys.Count), ключей-доменов: $($domainKeys.Count)"
        Write-Host "Примеры сетей: $((@($networkKeys | Sort-Object | Select-Object -First 5)) -join ', ')"
        Write-Host "Примеры доменов: $((@($domainKeys | Sort-Object | Select-Object -First 5)) -join ', ')"
    } catch {
        Write-Warning "не удалось проверить записи: $($_.Exception.Message)"
    }

    try {
        $daemon = Get-AmneziaService
        $tunnel = Get-TunnelService
        $daemonStatus = if ($null -eq $daemon) { 'не найдена' } else { "$($daemon.Name) = $($daemon.Status)" }
        $tunnelStatus = if ($null -eq $tunnel) { 'не найдена' } else { "$($tunnel.Name) = $($tunnel.Status)" }
        Write-Host "Служба демона: $daemonStatus"
        Write-Host "Служба туннеля: $tunnelStatus"
        Write-Host "GUI запущена: $(Test-GuiRunning); VPN-адаптер поднят: $(Test-VpnAdapterUp)"
        foreach ($adapter in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            if ($adapter.OperationalStatus -eq [Net.NetworkInformation.OperationalStatus]::Up) {
                Write-Host "  адаптер up: $($adapter.Name) / $($adapter.Description)"
            }
        }
    } catch {
        Write-Warning "не удалось опросить службы и адаптеры: $($_.Exception.Message)"
    }

    try {
        $address = ([Net.Dns]::GetHostAddresses('gosuslugi.ru') |
            Where-Object { $_.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork } |
            Select-Object -First 1).IPAddressToString
        Write-Host "gosuslugi.ru резолвится в $address"
        if (Get-Command Find-NetRoute -ErrorAction SilentlyContinue) {
            # Find-NetRoute отдаёт пару объектов: NetIPAddress и NetRoute. NextHop
            # есть только у второго, поэтому фильтруем по свойству, а не по позиции.
            $route = @(Find-NetRoute -RemoteIPAddress $address -ErrorAction Stop |
                Where-Object { $_.PSObject.Properties.Name -contains 'NextHop' }) |
                Select-Object -First 1
            if ($null -ne $route) {
                $alias = (Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue).Name
                Write-Host "маршрут до gosuslugi.ru: префикс $($route.DestinationPrefix), шлюз $($route.NextHop), интерфейс $alias (index $($route.InterfaceIndex))"
            }
        }
    } catch {
        Write-Warning "не удалось проверить маршрут: $($_.Exception.Message)"
    }

    try {
        if (Test-Path -LiteralPath $JournalPath -PathType Leaf) {
            Write-Warning "Есть незавершённая транзакция: $JournalPath"
            Get-Content -LiteralPath $JournalPath -Raw -Encoding UTF8 | Write-Host
        }
        $taskName = "Amnezia-Split-Route-Sync-$([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"
        $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
        if ($null -ne $taskInfo) {
            Write-Host "Задача: последний запуск $($taskInfo.LastRunTime), код $($taskInfo.LastTaskResult)"
        } else {
            Write-Host "Задача $taskName не зарегистрирована"
        }
    } catch {
        Write-Warning "не удалось прочитать журнал и задачу: $($_.Exception.Message)"
    }

    if (Test-Path -LiteralPath $StatusPath -PathType Leaf) {
        Write-Host '--- status.json ---'
        Get-Content -LiteralPath $StatusPath -Raw -Encoding UTF8 | Write-Host
    } else {
        Write-Host "status.json отсутствует: $StatusPath"
    }
    exit 0
}

# --- основной сценарий ---------------------------------------------------------

$currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($currentSid -eq 'S-1-5-18') { throw 'Updater нельзя запускать от SYSTEM: настройки лежат в HKCU пользователя.' }

if (-not $Source) {
    $Source = if ($Lite) { $ListLite } else { $ListFull }
}

$mutex = New-Object Threading.Mutex($false, "Global\Amnezia-Split-Route-Sync-$currentSid")
$hasLock = $false
try {
    try { $hasLock = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $hasLock = $true }
    if (-not $hasLock) {
        Write-Host 'Другой updater уже работает, пропускаю запуск.'
        exit 0
    }

    Assert-QtCodec
    if (-not $DryRun) { [IO.Directory]::CreateDirectory($StateDir) | Out-Null }

    $exePath = $null
    $appVersion = 'не установлена'
    if ($DryRun -or $RecoverOnly) {
        try {
            $exePath = Get-AmneziaExePath
            $appVersion = Assert-AmneziaVersion $exePath
        } catch {
            Write-Warning $_.Exception.Message
        }
    } else {
        $exePath = Get-AmneziaExePath
        $appVersion = Assert-AmneziaVersion $exePath
    }

    if (-not $DryRun) {
        # Recovery не зависит от сети: сначала обязательно вернуть VPN и настройки.
        Restore-PendingTransaction $exePath
    }
    if ($RecoverOnly) {
        Write-Host 'Recovery завершён; незавершённых routing-транзакций нет.'
        exit 0
    }

    $text = Get-SourceText $Source
    $list = ConvertFrom-ImportList $text $Source
    $entries = @($list.Domains) + @($list.Cidrs)
    Write-Host "Проверено $($list.Domains.Count) доменов и $($list.Cidrs.Count) сетей IPv4 для AmneziaVPN $appVersion"

    if ($DryRun) { exit 0 }

    $result = Invoke-RoutingTransaction $entries $exePath

    Write-TextAtomic $ImportPath $text
    Write-JsonAtomic $StatusPath ([ordered]@{
        changed                  = [bool]$result.Changed
        source                   = $Source
        domain_count             = $list.Domains.Count
        cidr_count               = $list.Cidrs.Count
        entry_count              = $entries.Count
        manual_entries_preserved = [int]$result.ManualCount
        app_version              = $appVersion
        updated_at               = [DateTime]::UtcNow.ToString('o')
    })

    if ($result.Changed) {
        Write-Host ("AmneziaVPN обновлена: $($entries.Count) записей, сохранено ручных записей: $($result.ManualCount). " +
                    'GUI и туннель перезапущены — перезагрузка Windows не нужна.')
    } else {
        Write-Host "AmneziaVPN уже содержит актуальные $($entries.Count) записей."
    }
} finally {
    if ($hasLock) { [void]$mutex.ReleaseMutex() }
    $mutex.Dispose()
}
