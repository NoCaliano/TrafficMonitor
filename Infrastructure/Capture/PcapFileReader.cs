using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System.IO;

namespace Infrastructure.Capture;

public static class PcapFileReader
{
    public readonly record struct PcapPacket(DateTime TimestampUtc, int LinkLayerType, byte[] Data);

    public static List<PcapPacket> Read(string filePath, int? maxPackets = null)
    {
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);

        Span<byte> gh = stackalloc byte[24];
        int read = fs.Read(gh);
        if (read != gh.Length)
            throw new InvalidOperationException("Invalid pcap: file too small.");

        uint magic = ReadU32Little(gh.Slice(0, 4));

        bool swap;
        bool nano;

        // magic values:
        // 0xa1b2c3d4 - microsecond, little-endian
        // 0xd4c3b2a1 - microsecond, big-endian
        // 0xa1b23c4d - nanosecond, little-endian
        // 0x4d3cb2a1 - nanosecond, big-endian
        if (magic == 0xa1b2c3d4u) { swap = false; nano = false; }
        else if (magic == 0xd4c3b2a1u) { swap = true; nano = false; }
        else if (magic == 0xa1b23c4du) { swap = false; nano = true; }
        else if (magic == 0x4d3cb2a1u) { swap = true; nano = true; }
        else if (magic == 0x0A0D0D0Au) { return ReadPcapNg(filePath, maxPackets); }
        else { throw new InvalidOperationException($"Unsupported capture format (magic=0x{magic:X8})."); }

        // version major/minor (unused)
        ushort vmaj = ReadU16(gh.Slice(4, 2), swap);
        ushort vmin = ReadU16(gh.Slice(6, 2), swap);
        _ = vmaj;
        _ = vmin;

        // thiszone, sigfigs, snaplen (unused)
        _ = ReadI32(gh.Slice(8, 4), swap);
        _ = ReadU32(gh.Slice(12, 4), swap);
        _ = ReadU32(gh.Slice(16, 4), swap);

        int linkLayerType = (int)ReadU32(gh.Slice(20, 4), swap);

        // Basic sanity: accept known PacketDotNet link layers but don't hard-fail.
        _ = (LinkLayers)linkLayerType;

        var result = new List<PcapPacket>(capacity: 4096);

        Span<byte> rh = stackalloc byte[16];

        while (true)
        {
            if (maxPackets.HasValue && result.Count >= maxPackets.Value)
                break;

            int got = ReadExactlyOrZero(fs, rh);
            if (got == 0)
                break;
            if (got != rh.Length)
                throw new InvalidOperationException("Invalid pcap: truncated packet header.");

            uint tsSec = ReadU32(rh.Slice(0, 4), swap);
            uint tsFrac = ReadU32(rh.Slice(4, 4), swap);
            uint inclLen = ReadU32(rh.Slice(8, 4), swap);
            _ = ReadU32(rh.Slice(12, 4), swap); // origLen

            if (inclLen > int.MaxValue)
                throw new InvalidOperationException("Invalid pcap: packet too large.");

            var data = new byte[inclLen];
            fs.ReadExactly(data);

            // Timestamp stored as sec + usec/nsec since UNIX epoch
            var dto = DateTimeOffset.FromUnixTimeSeconds(tsSec);
            long ticks;
            if (nano)
            {
                // 1 tick = 100ns
                ticks = (long)tsFrac / 100;
            }
            else
            {
                // microseconds -> ticks
                ticks = (long)tsFrac * 10;
            }

            var utc = dto.UtcDateTime.AddTicks(ticks);

            result.Add(new PcapPacket(utc, linkLayerType, data));
        }

        return result;
    }

    private static List<PcapPacket> ReadPcapNg(string filePath, int? maxPackets)
    {
        try
        {
            using var device = new CaptureFileReaderDevice(filePath);
            var result = new List<PcapPacket>(capacity: 4096);

            device.OnPacketArrival += (_, e) =>
            {
                var raw = e.GetPacket();
                result.Add(new PcapPacket(raw.Timeval.Date, (int)raw.LinkLayerType, raw.Data));
            };

            device.Open();

            if (maxPackets is int packetLimit)
            {
                device.Capture(packetLimit);
            }
            else
            {
                device.Capture();
            }

            return result;
        }
        catch (DllNotFoundException ex)
        {
            throw new InvalidOperationException(
                "pcapng import requires Npcap/libpcap support. Please install or repair Npcap and try again.",
                ex);
        }
        catch (TypeInitializationException ex) when (ex.InnerException is DllNotFoundException or FileNotFoundException)
        {
            throw new InvalidOperationException(
                "pcapng import requires Npcap/libpcap support. Please install or repair Npcap and try again.",
                ex);
        }
        catch (PcapException ex)
        {
            throw new InvalidOperationException(
                $"Failed to read pcapng file '{Path.GetFileName(filePath)}'. {ex.Message}",
                ex);
        }
    }

    private static uint ReadU32Little(ReadOnlySpan<byte> b)
        => (uint)(b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24));

    private static uint ReadU32(ReadOnlySpan<byte> b, bool swap)
        => swap
            ? (uint)(b[3] | (b[2] << 8) | (b[1] << 16) | (b[0] << 24))
            : ReadU32Little(b);

    private static int ReadI32(ReadOnlySpan<byte> b, bool swap)
        => unchecked((int)ReadU32(b, swap));

    private static ushort ReadU16(ReadOnlySpan<byte> b, bool swap)
        => swap
            ? (ushort)(b[1] | (b[0] << 8))
            : (ushort)(b[0] | (b[1] << 8));

    private static int ReadExactlyOrZero(Stream s, Span<byte> buffer)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int n = s.Read(buffer.Slice(total));
            if (n == 0)
                return total;
            total += n;
        }
        return total;
    }
}
