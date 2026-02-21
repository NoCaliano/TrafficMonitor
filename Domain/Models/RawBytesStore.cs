using System.Collections.Concurrent;
using System.Threading;

namespace Domain.Models;

public static class RawBytesStore
{
    private static readonly ConcurrentDictionary<int, byte[]> _dict = new();
    private static readonly ConcurrentQueue<int> _order = new();
    private static int _nextId;
    // keep a separate atomic count to avoid expensive ConcurrentQueue.Count calls
    private static int _orderCount;
    private const int Capacity = 5000; // keep last N raw payloads

    public static int? Add(byte[] data)
    {
        if (data == null || data.Length == 0) return null;

        // Make an internal copy to avoid keeping a reference to caller's buffer
        var copy = new byte[data.Length];
        Buffer.BlockCopy(data, 0, copy, 0, data.Length);

        var id = Interlocked.Increment(ref _nextId);
        _dict[id] = copy;
        _order.Enqueue(id);
        Interlocked.Increment(ref _orderCount);
        TrimIfNeeded();
        return id;
    }

    private static void TrimIfNeeded()
    {
        // Avoid calling _order.Count (O(n)). Use atomic _orderCount instead.
        while (System.Threading.Volatile.Read(ref _orderCount) > Capacity && _order.TryDequeue(out var old))
        {
            _dict.TryRemove(old, out _);
            Interlocked.Decrement(ref _orderCount);
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
        Interlocked.Exchange(ref _orderCount, 0);
        _dict.Clear();
        Interlocked.Exchange(ref _nextId, 0);
    }
}
