using Application.Abstractions;
using Domain.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace Application.Capture;

public sealed class CaptureController : ICaptureController
{
    private readonly IPacketCaptureService _captureService;
    private readonly IPacketParser _parser;
    private readonly IFlowAggregator _flowAggregator;

    private Channel<RawPacketCapturedEventArgs> _channel;

    private CancellationTokenSource? _cts;
    private Task? _readerTask;
    private long _packetNo = 0;

    public bool IsRunning => _captureService.IsRunning;

    public event Action<IReadOnlyList<PacketInfo>>? PacketsParsed;
    public event Action<IReadOnlyList<FlowInfo>, CaptureStats>? FlowsAndStatsAvailable;

    public CaptureController(IPacketCaptureService captureService, IPacketParser parser, IFlowAggregator flowAggregator)
    {
        _captureService = captureService;
        _parser = parser;
        _flowAggregator = flowAggregator;
        _channel = CreateChannel();

        _captureService.PacketCaptured += (_, args) =>
        {
            _channel.Writer.TryWrite(args);
        };
    }

    public void ResetSessionState()
    {
        if (_captureService.IsRunning)
            return;

        Interlocked.Exchange(ref _packetNo, 0);
        _channel = CreateChannel();
    }

    public async Task StartAsync(string deviceId, string? bpfFilter, CancellationToken ct)
    {
        if (_captureService.IsRunning) return;

        _cts = new CancellationTokenSource();
        _readerTask = RunReaderAsync(_cts.Token);

        await _captureService.StartAsync(deviceId, bpfFilter, ct);
    }

    public async Task StopAsync(CancellationToken ct)
    {
        if (!_captureService.IsRunning) return;

        await _captureService.StopAsync(ct);

        if (_cts is not null)
        {
            _cts.Cancel();
            try { if (_readerTask is not null) await _readerTask; } catch { }
            _cts.Dispose();
            _cts = null;
        }
    }

    private static Channel<RawPacketCapturedEventArgs> CreateChannel()
    {
        return Channel.CreateBounded<RawPacketCapturedEventArgs>(new BoundedChannelOptions(20_000)
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.DropOldest
        });
    }

    private async Task RunReaderAsync(CancellationToken ct)
    {
        var batch = new List<RawPacketCapturedEventArgs>(512);
        var lastFlowsUiUpdateUtc = DateTime.UtcNow;
        var capTotalPackets = 0L;
        var capTotalBytes = 0L;
        DateTime? capFirstSeen = null;
        DateTime? capLastSeen = null;
        var sw = Stopwatch.StartNew();

        try
        {
            while (await _channel.Reader.WaitToReadAsync(ct))
            {
                batch.Clear();

                while (batch.Count < 512 && _channel.Reader.TryRead(out var item))
                    batch.Add(item);

                var parsed = new List<PacketInfo>(batch.Count);
                foreach (var e in batch)
                {
                    var p = _parser.Parse(e.Timestamp, e.Length, e.RawCapture, PacketParseProfile.Live);
                    p.No = Interlocked.Increment(ref _packetNo);
                    parsed.Add(p);
                }

                if (parsed.Count > 0)
                {
                    capTotalPackets += parsed.Count;

                    long add = 0;
                    for (int i = 0; i < parsed.Count; i++)
                        add += parsed[i].Length;

                    capTotalBytes += add;

                    var min = parsed[0].Timestamp;
                    var max = parsed[0].Timestamp;

                    for (int i = 1; i < parsed.Count; i++)
                    {
                        var t = parsed[i].Timestamp;
                        if (t < min) min = t;
                        if (t > max) max = t;
                    }

                    if (!capFirstSeen.HasValue || min < capFirstSeen.Value) capFirstSeen = min;
                    if (!capLastSeen.HasValue || max > capLastSeen.Value) capLastSeen = max;
                }

                foreach (var p in parsed)
                    _flowAggregator.Add(p);

                // fire parsed batch to UI
                PacketsParsed?.Invoke(parsed);

                var nowUtc = DateTime.UtcNow;
                if ((nowUtc - lastFlowsUiUpdateUtc).TotalMilliseconds >= 1000)
                {
                    var stats = new CaptureStats
                    {
                        TotalPackets = capTotalPackets,
                        TotalBytes = capTotalBytes,
                        FirstSeen = capFirstSeen,
                        LastSeen = capLastSeen,
                        Elapsed = sw.Elapsed
                    };

                    lastFlowsUiUpdateUtc = nowUtc;

                    var top = _flowAggregator.SnapshotTop(take: 500);

                    FlowsAndStatsAvailable?.Invoke(top, stats);
                }

                await Task.Yield();
            }
        }
        catch (OperationCanceledException)
        {
            // ok
        }
        finally
        {
            sw.Stop();
        }
    }
}
