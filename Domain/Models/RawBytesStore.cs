using System.Collections.Concurrent;
using System.Threading;

namespace Domain.Models;

public static class RawBytesStore
{
    private static readonly ConcurrentDictionary<int, byte[]> _dict = new();
    private static readonly ConcurrentQueue<int> _order = new();
    private static int _nextId;
    private const int Capacity = 5000; // keep last N raw payloads

    public static int? Add(byte[] data)
    {
        if (data == null || data.Length == 0) return null;

        var id = Interlocked.Increment(ref _nextId);
        _dict[id] = data;
        _order.Enqueue(id);
        TrimIfNeeded();
        return id;
    }

    private static void TrimIfNeeded()
    {
        while (_order.Count > Capacity && _order.TryDequeue(out var old))
        {
            _dict.TryRemove(old, out _);
        }
    }

    public static byte[]? Get(int? id)
    {
        if (id is null) return null;
        return _dict.TryGetValue(id.Value, out var data) ? data : null;
    }

    public static void Remove(int? id)
    {
        if (id is null) return;
        _dict.TryRemove(id.Value, out _);
        // Note: we do not remove from _order queue; Trim will handle eventual dequeue.
    }

    public static void Clear()
    {
        // Clear dictionaries and reset id counter
        while (_order.TryDequeue(out _)) { }
        _dict.Clear();
        Interlocked.Exchange(ref _nextId, 0);
    }
}
