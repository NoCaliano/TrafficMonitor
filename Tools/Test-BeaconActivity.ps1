<#
.SYNOPSIS
Generates benign periodic outbound flow starts for TrafficMonitor beacon detection tests.

.DESCRIPTION
The script sends short UDP probes or opens TCP connections to one resolved remote endpoint
at a fixed cadence. UDP mode is the default because TrafficMonitor can attribute the sending
socket while it remains open, and each new UDP socket appears as a new outbound flow start.

.EXAMPLE
.\Tools\Test-BeaconActivity.ps1

.EXAMPLE
.\Tools\Test-BeaconActivity.ps1 -HostName example.com -Port 80 -IntervalSeconds 5 -Count 16

.EXAMPLE
.\Tools\Test-BeaconActivity.ps1 -Protocol Tcp -HostName example.com -Port 80 -IntervalSeconds 6 -Count 16 -HoldSeconds 4
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$HostName = "1.1.1.1",

    [Parameter()]
    [ValidateRange(1, 65535)]
    [int]$Port = 53,

    [Parameter()]
    [ValidateSet("Udp", "Tcp")]
    [string]$Protocol = "Udp",

    [Parameter()]
    [ValidateRange(2, 120)]
    [double]$IntervalSeconds = 5,

    [Parameter()]
    [ValidateRange(7, 10000)]
    [int]$Count = 16,

    [Parameter()]
    [ValidateRange(0, 0.20)]
    [double]$JitterRatio = 0.02,

    [Parameter()]
    [ValidateRange(500, 30000)]
    [int]$TimeoutMilliseconds = 5000,

    [Parameter()]
    [ValidateRange(0, 30)]
    [double]$HoldSeconds = 4,

    [Parameter()]
    [ValidateRange(0, 30)]
    [double]$PreSendHoldSeconds = 4,

    [Parameter()]
    [switch]$NoHttpProbe
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-TestEndpoint {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    $address = $null
    if ([System.Net.IPAddress]::TryParse($Name, [ref]$address)) {
        return $address
    }

    $addresses = [System.Net.Dns]::GetHostAddresses($Name) |
        Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork }

    if (-not $addresses -or $addresses.Count -eq 0) {
        throw "Could not resolve an IPv4 address for '$Name'."
    }

    return $addresses[0]
}

function Get-RouteLocalAddress {
    param(
        [Parameter(Mandatory)]
        [System.Net.IPAddress]$RemoteAddress,

        [Parameter(Mandatory)]
        [int]$RemotePort
    )

    $probe = [System.Net.Sockets.UdpClient]::new()
    try {
        $probe.Connect($RemoteAddress, $RemotePort)
        $localEndpoint = [System.Net.IPEndPoint]$probe.Client.LocalEndPoint
        return $localEndpoint.Address
    }
    finally {
        $probe.Dispose()
    }
}

function Invoke-TestConnection {
    param(
        [Parameter(Mandatory)]
        [System.Net.IPAddress]$Address,

        [Parameter(Mandatory)]
        [int]$RemotePort,

        [Parameter(Mandatory)]
        [string]$HostHeader,

        [Parameter(Mandatory)]
        [int]$TimeoutMs,

        [Parameter(Mandatory)]
        [double]$HoldOpenSeconds,

        [Parameter(Mandatory)]
        [bool]$SendHttpProbe
    )

    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $connectTask = $client.ConnectAsync($Address, $RemotePort)
        if (-not $connectTask.Wait($TimeoutMs)) {
            throw "Connection timed out after $TimeoutMs ms."
        }

        if ($connectTask.IsFaulted) {
            throw $connectTask.Exception.GetBaseException()
        }

        if ($SendHttpProbe) {
            $stream = $client.GetStream()
            $request = "HEAD / HTTP/1.1`r`nHost: $HostHeader`r`nUser-Agent: TrafficMonitor-Beacon-Test/1.0`r`nConnection: close`r`n`r`n"
            $bytes = [System.Text.Encoding]::ASCII.GetBytes($request)
            $stream.WriteTimeout = $TimeoutMs
            $stream.Write($bytes, 0, $bytes.Length)
        }

        if ($HoldOpenSeconds -gt 0) {
            Start-Sleep -Milliseconds ([int][Math]::Round($HoldOpenSeconds * 1000))
        }
    }
    finally {
        $client.Dispose()
    }
}

function Invoke-TestUdpProbe {
    param(
        [Parameter(Mandatory)]
        [System.Net.IPAddress]$Address,

        [Parameter(Mandatory)]
        [System.Net.IPAddress]$LocalAddress,

        [Parameter(Mandatory)]
        [int]$RemotePort,

        [Parameter(Mandatory)]
        [double]$PreSendHoldOpenSeconds,

        [Parameter(Mandatory)]
        [double]$HoldOpenSeconds
    )

    $localEndpoint = [System.Net.IPEndPoint]::new($LocalAddress, 0)
    $remoteEndpoint = [System.Net.IPEndPoint]::new($Address, $RemotePort)
    $client = [System.Net.Sockets.UdpClient]::new($localEndpoint)
    try {
        $client.Connect($remoteEndpoint)

        if ($PreSendHoldOpenSeconds -gt 0) {
            Start-Sleep -Milliseconds ([int][Math]::Round($PreSendHoldOpenSeconds * 1000))
        }

        $payloadText = "TrafficMonitor-Beacon-Test " + [Guid]::NewGuid().ToString("N")
        $payload = [System.Text.Encoding]::ASCII.GetBytes($payloadText)
        [void]$client.Send($payload, $payload.Length)

        if ($HoldOpenSeconds -gt 0) {
            Start-Sleep -Milliseconds ([int][Math]::Round($HoldOpenSeconds * 1000))
        }
    }
    finally {
        $client.Dispose()
    }
}

$remoteAddress = Resolve-TestEndpoint -Name $HostName
$localAddress = Get-RouteLocalAddress -RemoteAddress $remoteAddress -RemotePort $Port
$random = [System.Random]::new()
$sendHttpProbe = -not $NoHttpProbe

Write-Host "TrafficMonitor beacon activity test"
Write-Host "Target: $Protocol $HostName -> $remoteAddress`:$Port"
Write-Host "Local bind: $localAddress`:ephemeral"
Write-Host "Cadence: $Count connections, every ~$IntervalSeconds s, jitter ratio <= $JitterRatio"
if ($Protocol -eq "Udp") {
    Write-Host "Socket hold: each UDP socket opens ~$PreSendHoldSeconds s before send, then stays open ~$HoldSeconds s after send"
}
else {
    Write-Host "Socket hold: each TCP connection remains open for ~$HoldSeconds s to help PID attribution"
}
Write-Host "Expected detector samples: $($Count - 1). Keep TrafficMonitor capture running while this executes."
Write-Host ""

for ($i = 1; $i -le $Count; $i++) {
    $started = Get-Date

    try {
        if ($Protocol -eq "Udp") {
            Invoke-TestUdpProbe `
                -Address $remoteAddress `
                -LocalAddress $localAddress `
                -RemotePort $Port `
                -PreSendHoldOpenSeconds $PreSendHoldSeconds `
                -HoldOpenSeconds $HoldSeconds
        }
        else {
            Invoke-TestConnection `
                -Address $remoteAddress `
                -RemotePort $Port `
                -HostHeader $HostName `
                -TimeoutMs $TimeoutMilliseconds `
                -HoldOpenSeconds $HoldSeconds `
                -SendHttpProbe $sendHttpProbe
        }

        Write-Host ("[{0:HH:mm:ss}] flow {1}/{2} ok" -f $started, $i, $Count)
    }
    catch {
        Write-Warning ("[{0:HH:mm:ss}] flow {1}/{2} failed: {3}" -f $started, $i, $Count, $_.Exception.Message)
    }

    if ($i -lt $Count) {
        $jitterWindow = $IntervalSeconds * $JitterRatio
        $jitter = ($random.NextDouble() * 2 - 1) * $jitterWindow
        $elapsedSeconds = ((Get-Date) - $started).TotalSeconds
        $sleepSeconds = [Math]::Max(0, $IntervalSeconds + $jitter - $elapsedSeconds)
        Start-Sleep -Milliseconds ([int][Math]::Round($sleepSeconds * 1000))
    }
}

Write-Host ""
Write-Host "Done. In TrafficMonitor, check the PowerShell process row for a Beacon label and periodic-beacon scenario."
