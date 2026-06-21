[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$TargetIp = "127.0.0.1",
    [int]$StartPort = 20000,
    [int]$PortCount = 250,
    [int]$PacketsPerPort = 10,
    [int]$PayloadBytes = 32,
    [int]$KeepAliveSeconds = 2,
    [switch]$Worker,
    [switch]$NoTempCopy
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-IsPrivateOrLoopbackAddress {
    param([System.Net.IPAddress]$Address)

    if ($Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
        return $Address.IsIPv6LinkLocal `
            -or $Address.Equals([System.Net.IPAddress]::IPv6Loopback) `
            -or $Address.IsIPv6SiteLocal
    }

    $bytes = $Address.GetAddressBytes()
    if ($bytes.Length -ne 4) {
        return $false
    }

    if ($bytes[0] -eq 10) { return $true }
    if ($bytes[0] -eq 127) { return $true }
    if ($bytes[0] -eq 192 -and $bytes[1] -eq 168) { return $true }
    if ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) { return $true }

    return $false
}

function Resolve-TargetAddress {
    param([string]$IpText)

    try {
        return [System.Net.IPAddress]::Parse($IpText)
    }
    catch {
        throw "TargetIp must be a literal IP address. Received: $IpText"
    }
}

function Invoke-LocalBurstWorker {
    param(
        [System.Net.IPAddress]$Address,
        [int]$PortBase,
        [int]$RemotePortCount,
        [int]$BurstPacketsPerPort,
        [int]$DatagramBytes,
        [int]$StayAliveSeconds
    )

    if ($RemotePortCount -lt 160) {
        throw "PortCount should be at least 160 to reliably trigger the fan-out heuristic."
    }

    if ($BurstPacketsPerPort -gt 10) {
        throw "PacketsPerPort should stay at 10 or below, otherwise the scan-like fan-out heuristic may not trigger."
    }

    $totalPackets = $RemotePortCount * $BurstPacketsPerPort
    $endPort = $PortBase + $RemotePortCount - 1
    $targetLabel = "$Address`:$PortBase-$endPort"

    if (-not $PSCmdlet.ShouldProcess($targetLabel, "Send $totalPackets UDP packets over loopback/private space")) {
        return
    }

    $payload = [byte[]]::new($DatagramBytes)
    for ($i = 0; $i -lt $payload.Length; $i++) {
        $payload[$i] = [byte](65 + ($i % 26))
    }

    $socket = [System.Net.Sockets.Socket]::new(
        $Address.AddressFamily,
        [System.Net.Sockets.SocketType]::Dgram,
        [System.Net.Sockets.ProtocolType]::Udp)

    try {
        if ($Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
            $socket.Bind([System.Net.IPEndPoint]::new([System.Net.IPAddress]::IPv6Any, 0))
        }
        else {
            $socket.Bind([System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0))
        }

        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        for ($port = $PortBase; $port -le $endPort; $port++) {
            $remote = [System.Net.IPEndPoint]::new($Address, $port)

            for ($packet = 0; $packet -lt $BurstPacketsPerPort; $packet++) {
                [void]$socket.SendTo($payload, $remote)
            }
        }

        $stopwatch.Stop()
        $pps = if ($stopwatch.Elapsed.TotalSeconds -gt 0) {
            [math]::Round($totalPackets / $stopwatch.Elapsed.TotalSeconds, 0)
        }
        else {
            $totalPackets
        }

        Write-Host "Sent $totalPackets UDP packets to $targetLabel in $($stopwatch.Elapsed.TotalMilliseconds.ToString('0.0')) ms (~$pps pkt/s)."
        Write-Host "Keeping the worker alive for $StayAliveSeconds second(s) so TrafficMonitor can observe it as a live process before exit."

        if ($StayAliveSeconds -gt 0) {
            Start-Sleep -Seconds $StayAliveSeconds
        }
    }
    finally {
        $socket.Dispose()
    }
}

if ($StartPort -lt 1 -or $StartPort -gt 65535) {
    throw "StartPort must be between 1 and 65535."
}

if ($PortCount -lt 1 -or ($StartPort + $PortCount - 1) -gt 65535) {
    throw "The port range must stay within 1..65535."
}

if ($PacketsPerPort -lt 1) {
    throw "PacketsPerPort must be at least 1."
}

if ($PayloadBytes -lt 1 -or $PayloadBytes -gt 1400) {
    throw "PayloadBytes must be between 1 and 1400."
}

if ($KeepAliveSeconds -lt 0 -or $KeepAliveSeconds -gt 30) {
    throw "KeepAliveSeconds must be between 0 and 30."
}

$address = Resolve-TargetAddress -IpText $TargetIp
if (-not (Test-IsPrivateOrLoopbackAddress -Address $address)) {
    throw "For safety this script only targets loopback or private IP space. Use 127.0.0.1 with the Npcap Loopback Adapter for the cleanest local test."
}

if (-not $Worker -and -not $NoTempCopy) {
    $sourcePowerShell = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
    if (-not (Test-Path -LiteralPath $sourcePowerShell)) {
        throw "Windows PowerShell was not found at $sourcePowerShell"
    }

    $tempExe = Join-Path $env:TEMP ("tm-risk-runner-{0}.exe" -f ([guid]::NewGuid().ToString("N")))
    Copy-Item -LiteralPath $sourcePowerShell -Destination $tempExe

    try {
        $args = @(
            "-NoProfile"
            "-ExecutionPolicy", "Bypass"
            "-File", $PSCommandPath
            "-Worker"
            "-TargetIp", $TargetIp
            "-StartPort", $StartPort
            "-PortCount", $PortCount
            "-PacketsPerPort", $PacketsPerPort
            "-PayloadBytes", $PayloadBytes
            "-KeepAliveSeconds", $KeepAliveSeconds
        )

        if ($WhatIfPreference) {
            $args += "-WhatIf"
        }

        if (-not $PSCmdlet.ShouldProcess($tempExe, "Launch temp-copy worker to trigger the Temp-path heuristic")) {
            return
        }

        Write-Host "Launching temp-copy worker: $tempExe"
        Write-Host "Expected signals: Temp path (+15), packet burst (+25), scan-like fan-out (+22), burst-and-exit (+18)."
        & $tempExe @args
        exit $LASTEXITCODE
    }
    finally {
        Write-Host "Temp worker executable kept at: $tempExe"
        Write-Host "You can remove it after TrafficMonitor records the event."
    }
}

Write-Host "Target IP: $TargetIp"
Write-Host "Remote ports: $StartPort..$($StartPort + $PortCount - 1)"
Write-Host "Packets per port: $PacketsPerPort"
Write-Host "Payload bytes: $PayloadBytes"
Write-Host "Capture hint: select the Npcap Loopback Adapter in TrafficMonitor when using 127.0.0.1."

Invoke-LocalBurstWorker `
    -Address $address `
    -PortBase $StartPort `
    -RemotePortCount $PortCount `
    -BurstPacketsPerPort $PacketsPerPort `
    -DatagramBytes $PayloadBytes `
    -StayAliveSeconds $KeepAliveSeconds
