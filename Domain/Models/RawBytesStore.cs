using System.Collections.Concurrent;
using System.IO;
using System.Threading;

namespace Domain.Models;

public static class RawBytesStore
{
    private static readonly ConcurrentDictionary<int, (long Offset, int Length)> _index = new();

    private static readonly object _fileLock = new();
    private static readonly object _writeLock = new();
    private static readonly object _readLock = new();

    private static FileStream? _writeStream;
    private static FileStream? _readStream;
    private static string? _filePath;
    private static long _writePosition;

    // Flush periodically to make freshly captured bytes visible to the read stream
    // without paying Flush() cost on every packet.
    private const int FlushThresholdBytes = 1 * 1024 * 1024;
    private static int _bytesSinceFlush;

    private static int _nextId;

    private static void EnsureStreamCreated()
    {
        if (_writeStream is not null)
            return;

        lock (_fileLock)
        {
            if (_writeStream is not null)
                return;

            var dir = Path.Combine(Path.GetTempPath(), "TrafficMonitor");
            Directory.CreateDirectory(dir);

            _filePath = Path.Combine(dir, $"rawpackets_{Environment.ProcessId}_{DateTime.UtcNow:yyyyMMdd_HHmmss_fff}.bin");
            // Use separate read/write streams so reads don't disturb the write position.
            _writeStream = new FileStream(
                _filePath,
                FileMode.Create,
                FileAccess.Write,
                FileShare.ReadWrite,
                bufferSize: 1024 * 1024,
                options: FileOptions.SequentialScan);

            _readStream = new FileStream(
                _filePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite,
                bufferSize: 1024 * 1024,
                options: FileOptions.SequentialScan);

            _writePosition = 0;
        }
    }

    public static int? Add(byte[] data)
    {
        if (data == null || data.Length == 0) return null;

        EnsureStreamCreated();

        var id = Interlocked.Increment(ref _nextId);

        lock (_writeLock)
        {
            // Append raw bytes to a temp file so we don't allocate/copy for every packet.
            // This allows keeping details available even for very large packet counts.
            var offset = _writePosition;
            _writeStream!.Write(data, 0, data.Length);
            _writePosition += data.Length;
            _index[id] = (offset, data.Length);

            // Make recent bytes visible for reads (packet details) with amortized flush cost.
            _bytesSinceFlush += data.Length;
            if (_bytesSinceFlush >= FlushThresholdBytes)
            {
                _writeStream.Flush(flushToDisk: false);
                _bytesSinceFlush = 0;
            }
        }

        return id;
    }

    public static byte[]? Get(int? id)
    {
        if (id is null) return null;

        if (!_index.TryGetValue(id.Value, out var entry))
            return null;

        EnsureStreamCreated();

        // If a packet was captured very recently, it may still be sitting in the write stream buffer.
        // Ensure the write stream is flushed so the read stream can see the bytes.
        long requiredEnd = entry.Offset + entry.Length;
        lock (_writeLock)
        {
            if (_writeStream is not null && _writePosition < requiredEnd)
            {
                // Inconsistent index/writePosition shouldn't happen, but avoid throwing.
                return null;
            }

            // If we have unflushed buffered data, flush before reading.
            if (_bytesSinceFlush != 0)
            {
                _writeStream!.Flush(flushToDisk: false);
                _bytesSinceFlush = 0;
            }
        }

        var buffer = new byte[entry.Length];
        try
        {
            lock (_readLock)
            {
                _readStream!.Position = entry.Offset;
                _readStream.ReadExactly(buffer);
            }
        }
        catch (EndOfStreamException)
        {
            // If user clicked a packet while the capture is writing, we may race with buffering.
            // Returning null lets UI show "no data" instead of crashing.
            return null;
        }
        return buffer;
    }

    public static void Remove(int? id)
    {
        if (id is null) return;
        _index.TryRemove(id.Value, out _);
        // Note: we do not compact the file; it's append-only.
    }

    public static void Clear()
    {
        _index.Clear();
        Interlocked.Exchange(ref _nextId, 0);

        lock (_fileLock)
        {
            try
            {
                _writeStream?.Dispose();
                _readStream?.Dispose();
            }
            catch { }
            finally
            {
                _writeStream = null;
                _readStream = null;
                _writePosition = 0;
                _bytesSinceFlush = 0;
            }

            if (!string.IsNullOrWhiteSpace(_filePath))
            {
                try { File.Delete(_filePath); } catch { }
                _filePath = null;
            }
        }
    }
}
