using Domain.Models;
using System.IO;
using System.Text;

namespace Presentation.Services;

public static class PcapFileWriter
{
    // Writes classic libpcap ("*.pcap") file.
    public static void Write(string filePath, IReadOnlyList<PacketInfo> packets)
    {
        if (packets is null) throw new ArgumentNullException(nameof(packets));

        // Determine a single link-layer type for the capture (pcap global header supports only one).
        int? linkLayerType = null;
        foreach (var p in packets)
        {
            // pick first packet that actually has bytes
            var bytes = p.RawBytes ?? (p.RawBytesId is null ? null : RawBytesStore.Get(p.RawBytesId));
            if (bytes is null || bytes.Length == 0)
                continue;

            linkLayerType = p.LinkLayerType;
            break;
        }

        if (linkLayerType is null)
            throw new InvalidOperationException("No packet bytes available to export.");

        for (int i = 0; i < packets.Count; i++)
        {
            if (packets[i].LinkLayerType != linkLayerType.Value)
                throw new InvalidOperationException("Multiple link-layer types detected. Classic pcap supports only one link-layer per file.");
        }

        using var fs = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.Read, bufferSize: 1024 * 1024, options: FileOptions.SequentialScan);
        using var bw = new BinaryWriter(fs, Encoding.UTF8, leaveOpen: false);

        // pcap global header (little-endian)
        bw.Write(0xa1b2c3d4u);          // magic
        bw.Write((ushort)2);           // version major
        bw.Write((ushort)4);           // version minor
        bw.Write(0);                   // thiszone
        bw.Write(0u);                  // sigfigs
        bw.Write(65535u);              // snaplen
        bw.Write((uint)linkLayerType.Value); // network (DLT_*)

        foreach (var p in packets)
        {
            var bytes = p.RawBytes ?? (p.RawBytesId is null ? null : RawBytesStore.Get(p.RawBytesId));
            if (bytes is null || bytes.Length == 0)
                continue;

            var utc = p.Timestamp.Kind switch
            {
                DateTimeKind.Utc => p.Timestamp,
                DateTimeKind.Local => p.Timestamp.ToUniversalTime(),
                _ => DateTime.SpecifyKind(p.Timestamp, DateTimeKind.Local).ToUniversalTime()
            };

            var sec = (uint)new DateTimeOffset(utc).ToUnixTimeSeconds();
            var baseUtc = DateTimeOffset.FromUnixTimeSeconds(sec).UtcDateTime;
            var usec = (uint)((utc - baseUtc).Ticks / 10); // ticks -> microseconds

            uint inclLen = (uint)bytes.Length;
            uint origLen = (uint)bytes.Length;

            // record header
            bw.Write(sec);
            bw.Write(usec);
            bw.Write(inclLen);
            bw.Write(origLen);

            // record payload
            bw.Write(bytes);
        }

        bw.Flush();
        fs.Flush(flushToDisk: true);
    }
}
