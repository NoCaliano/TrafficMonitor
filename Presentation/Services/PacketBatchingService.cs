using Domain.Models;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Windows.Threading;

namespace Presentation.Services;

public sealed class PacketBatchingService : IDisposable
{
    private readonly object _lock = new();
    private readonly List<PacketInfo> _pending = new();
    private readonly Dispatcher _dispatcher;

    private readonly int _flushIntervalMs;
    private readonly int _maxPendingPackets;
    private readonly int _maxUiAppendPerFlush;

    private Timer? _timer;
    private long _skipped;

    public event Action<IReadOnlyList<PacketInfo>, long>? BatchReady;

    public bool IsRunning => _timer is not null;

    public PacketBatchingService(
        Dispatcher dispatcher,
        int flushIntervalMs = 200,
        int maxPendingPackets = 50_000,
        int maxUiAppendPerFlush = 2_000)
    {
        _dispatcher = dispatcher;
        _flushIntervalMs = flushIntervalMs;
        _maxPendingPackets = maxPendingPackets;
        _maxUiAppendPerFlush = maxUiAppendPerFlush;
    }

    public void Reset()
    {
        lock (_lock)
        {
            _pending.Clear();
            _skipped = 0;
        }
    }

    public void Enqueue(IReadOnlyList<PacketInfo> parsed)
    {
        if (parsed.Count == 0)
            return;

        lock (_lock)
        {
            int canAdd = Math.Max(0, _maxPendingPackets - _pending.Count);
            if (canAdd <= 0)
                return;

            for (int i = 0; i < parsed.Count && canAdd > 0; i++)
            {
                _pending.Add(parsed[i]);
                canAdd--;
            }
        }
    }

    public void Start()
    {
        if (_timer is not null)
            return;

        _timer = new Timer(_ => Flush(), null, _flushIntervalMs, _flushIntervalMs);
    }

    public void StopAndFlush()
    {
        var t = Interlocked.Exchange(ref _timer, null);
        t?.Change(Timeout.Infinite, Timeout.Infinite);
        t?.Dispose();

        Flush();
    }

    public void Stop()
    {
        var t = Interlocked.Exchange(ref _timer, null);
        t?.Change(Timeout.Infinite, Timeout.Infinite);
        t?.Dispose();
    }

    private void Flush()
    {
        List<PacketInfo> snapshot;

        lock (_lock)
        {
            if (_pending.Count == 0)
                return;

            snapshot = new List<PacketInfo>(_pending);
            _pending.Clear();
        }

        int startIndex = 0;
        if (snapshot.Count > _maxUiAppendPerFlush)
        {
            startIndex = snapshot.Count - _maxUiAppendPerFlush;
            Interlocked.Add(ref _skipped, startIndex);
        }

        var toAdd = startIndex == 0
            ? snapshot
            : snapshot.GetRange(startIndex, snapshot.Count - startIndex);

        long skipped = Interlocked.Read(ref _skipped);

        if (_dispatcher.CheckAccess())
        {
            BatchReady?.Invoke(toAdd, skipped);
        }
        else
        {
            _dispatcher.BeginInvoke(new Action(() => BatchReady?.Invoke(toAdd, skipped)));
        }
    }

    public void Dispose()
    {
        Stop();
        Reset();
    }
}
