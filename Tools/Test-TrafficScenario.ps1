<#
.SYNOPSIS
Runs a benign multi-phase traffic scenario for TrafficMonitor UI and detection testing.

.DESCRIPTION
This script creates a repeatable "suspicious-looking but harmless" process story:
normal warmup requests, periodic HTTP callbacks with low jitter, a short burst, and
optional fan-out to several safe HTTP endpoints. It is intended for local validation of
TrafficMonitor process rows, conversations, risk signals, timeline events, and reports.

.EXAMPLE
.\Tools\Test-TrafficScenario.ps1

.EXAMPLE
.\Tools\Test-TrafficScenario.ps1 -CallbackHost example.com -IntervalSeconds 8 -CallbackCount 18 -FanOut
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$CallbackHost = "example.com",

    [Parameter()]
    [ValidateRange(1, 65535)]
    [int]$CallbackPort = 80,

    [Parameter()]
    [ValidateRange(2, 120)]
    [double]$IntervalSeconds = 8,

    [Parameter()]
    [ValidateRange(7, 1000)]
    [int]$CallbackCount = 18,

    [Parameter()]
    [ValidateRange(0, 0.20)]
    [double]$JitterRatio = 0.03,

    [Parameter()]
    [ValidateRange(0, 120)]
    [int]$WarmupSeconds = 8,

    [Parameter()]
    [ValidateRange(0, 200)]
    [int]$BurstRequests = 30,

    [Parameter()]
    [switch]$FanOut,

    [Parameter()]
    [string[]]$FanOutHosts = @(
        "example.com",
        "neverssl.com",
        "iana.org",
        "www.ietf.org",
        "www.w3.org",
        "www.cloudflare.com",
        "www.microsoft.com",
        "www.github.com"
    ),

    [Parameter()]
    [ValidateRange(500, 30000)]
    [int]$TimeoutMilliseconds = 6000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-IPv4Address {
    param(
        [Parameter(Mandatory)]
        [string]$HostName
    )

    $address = $null
    if ([System.Net.IPAddress]::TryParse($HostName, [ref]$address)) {
        return $address
    }

    $addresses = [System.Net.Dns]::GetHostAddresses($HostName) |
        Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork }

    if (-not $addresses -or $addresses.Count -eq 0) {
        throw "Could not resolve an IPv4 address for '$HostName'."
    }

    return $addresses[0]
}

function Invoke-HttpProbe {
    param(
        [Parameter(Mandatory)]
        [string]$HostName,

        [Parameter(Mandatory)]
        [int]$Port,

        [Parameter(Mandatory)]
        [ValidateSet("HEAD", "GET")]
        [string]$Method,

        [Parameter(Mandatory)]
        [int]$TimeoutMs,

        [Parameter()]
        [int]$ReadBytes = 0,

        [Parameter()]
        [int]$HoldMilliseconds = 300
    )

    $remoteAddress = Resolve-IPv4Address -HostName $HostName
    $client = [System.Net.Sockets.TcpClient]::new()

    try {
        $connectTask = $client.ConnectAsync($remoteAddress, $Port)
        if (-not $connectTask.Wait($TimeoutMs)) {
            throw "Connection to $HostName ($remoteAddress`:$Port) timed out after $TimeoutMs ms."
        }

        if ($connectTask.IsFaulted) {
            throw $connectTask.Exception.GetBaseException()
        }

        $stream = $client.GetStream()
        $path = "/?tm_scenario=" + [Guid]::NewGuid().ToString("N")
        $request = "$Method $path HTTP/1.1`r`nHost: $HostName`r`nUser-Agent: TrafficMonitor-Scenario-Test/1.0`r`nConnection: close`r`n`r`n"
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($request)
        $stream.WriteTimeout = $TimeoutMs
        $stream.ReadTimeout = $TimeoutMs
        $stream.Write($bytes, 0, $bytes.Length)

        if ($ReadBytes -gt 0) {
            $buffer = [byte[]]::new([Math]::Min($ReadBytes, 8192))
            $remaining = $ReadBytes
            while ($remaining -gt 0) {
                $read = $stream.Read($buffer, 0, [Math]::Min($buffer.Length, $remaining))
                if ($read -le 0) {
                    break
                }

                $remaining -= $read
            }
        }

        if ($HoldMilliseconds -gt 0) {
            Start-Sleep -Milliseconds $HoldMilliseconds
        }

        return $remoteAddress
    }
    finally {
        $client.Dispose()
    }
}

function Write-Phase {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    Write-Host ""
    Write-Host "== $Name =="
}

$random = [System.Random]::new()
$callbackAddress = Resolve-IPv4Address -HostName $CallbackHost

Write-Host "TrafficMonitor scenario test"
Write-Host "Process: $PID ($((Get-Process -Id $PID).ProcessName))"
Write-Host "Callback target: HTTP $CallbackHost -> $callbackAddress`:$CallbackPort"
Write-Host "Callback cadence: $CallbackCount callbacks, every ~$IntervalSeconds s, jitter ratio <= $JitterRatio"
Write-Host "Warmup: $WarmupSeconds s | Burst: $BurstRequests request(s) | Fan-out: $($FanOut.IsPresent)"
Write-Host "Start TrafficMonitor capture before continuing."
Write-Host ""
Read-Host "Press Enter to start the scenario"

Write-Phase "Warmup"
$warmupEnd = (Get-Date).AddSeconds($WarmupSeconds)
$warmupIndex = 0
while ((Get-Date) -lt $warmupEnd) {
    $warmupIndex++
    try {
        [void](Invoke-HttpProbe -HostName $CallbackHost -Port $CallbackPort -Method "HEAD" -TimeoutMs $TimeoutMilliseconds -HoldMilliseconds 500)
        Write-Host ("[{0:HH:mm:ss}] warmup probe {1} ok" -f (Get-Date), $warmupIndex)
    }
    catch {
        Write-Warning ("Warmup probe failed: {0}" -f $_.Exception.Message)
    }

    Start-Sleep -Seconds 2
}

Write-Phase "Periodic callback"
for ($i = 1; $i -le $CallbackCount; $i++) {
    $started = Get-Date

    try {
        [void](Invoke-HttpProbe -HostName $CallbackHost -Port $CallbackPort -Method "HEAD" -TimeoutMs $TimeoutMilliseconds -HoldMilliseconds 1200)
        Write-Host ("[{0:HH:mm:ss}] callback {1}/{2} ok" -f $started, $i, $CallbackCount)
    }
    catch {
        Write-Warning ("[{0:HH:mm:ss}] callback {1}/{2} failed: {3}" -f $started, $i, $CallbackCount, $_.Exception.Message)
    }

    if ($i -lt $CallbackCount) {
        $jitterWindow = $IntervalSeconds * $JitterRatio
        $jitter = ($random.NextDouble() * 2 - 1) * $jitterWindow
        $elapsedSeconds = ((Get-Date) - $started).TotalSeconds
        $sleepSeconds = [Math]::Max(0, $IntervalSeconds + $jitter - $elapsedSeconds)
        Start-Sleep -Milliseconds ([int][Math]::Round($sleepSeconds * 1000))
    }
}

if ($BurstRequests -gt 0) {
    Write-Phase "Short burst"
    for ($i = 1; $i -le $BurstRequests; $i++) {
        try {
            [void](Invoke-HttpProbe -HostName $CallbackHost -Port $CallbackPort -Method "GET" -TimeoutMs $TimeoutMilliseconds -ReadBytes 4096 -HoldMilliseconds 50)
            Write-Host ("[{0:HH:mm:ss}] burst request {1}/{2} ok" -f (Get-Date), $i, $BurstRequests)
        }
        catch {
            Write-Warning ("Burst request {0}/{1} failed: {2}" -f $i, $BurstRequests, $_.Exception.Message)
        }

        Start-Sleep -Milliseconds 150
    }
}

if ($FanOut) {
    Write-Phase "Fan-out"
    $index = 0
    foreach ($hostName in $FanOutHosts) {
        $index++
        try {
            $ip = Invoke-HttpProbe -HostName $hostName -Port 80 -Method "HEAD" -TimeoutMs $TimeoutMilliseconds -HoldMilliseconds 500
            Write-Host ("[{0:HH:mm:ss}] fan-out {1}/{2}: {3} -> {4}:80 ok" -f (Get-Date), $index, $FanOutHosts.Count, $hostName, $ip)
        }
        catch {
            Write-Warning ("Fan-out {0}/{1} to {2} failed: {3}" -f $index, $FanOutHosts.Count, $hostName, $_.Exception.Message)
        }

        Start-Sleep -Milliseconds 700
    }
}

Write-Phase "Cooldown"
Write-Host "Keeping the process alive for 15 seconds so TrafficMonitor can refresh process details."
Start-Sleep -Seconds 15

Write-Host ""
Write-Host "Done. Check the PowerShell process row, conversations, timeline, risk signals, and incident report export."
