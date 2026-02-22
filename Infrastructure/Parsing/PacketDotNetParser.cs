// Відповідає за швидкий (allocation-light) парсинг пакетів для таблиці.
// Для деталей (Protocol tree / HEX) повний парсинг робиться в UI при виборі пакета.
using Application.Abstractions;
using Domain.Models;
using Infrastructure.Networking;
using PacketDotNet;
using SharpPcap;
using System.Net;

namespace Infrastructure.Parsing;

public sealed class PacketDotNetParser : IPacketParser
{
    private readonly ProcessMapperService _processMapperService;

    public PacketDotNetParser(ProcessMapperService processMapperService)
    {
        _processMapperService = processMapperService;
    }

    public PacketInfo Parse(DateTime timestamp, int length, object rawCapture)
    {
        // локальний час
        var tsLocal = timestamp.Kind switch
        {
            DateTimeKind.Local => timestamp,
            DateTimeKind.Utc => timestamp.ToLocalTime(),
            _ => DateTime.SpecifyKind(timestamp, DateTimeKind.Utc).ToLocalTime() // Unspecified трактуємо як UTC
        };

        if (rawCapture is not RawCapture raw)
        {
            return new PacketInfo
            {
                Timestamp = tsLocal,
                Length = length,
                Protocol = "UNKNOWN",
                Info = "RawCapture type mismatch"
            };
        }

        // Відповідає за збереження типу LinkLayer для коректного повторного парсингу в UI.
        int linkLayerType = (int)raw.LinkLayerType;

        // Save raw bytes into central store. RawBytesStore.Add will make an internal copy
        // so we can safely pass raw.Data without calling ToArray() here.
        int? rawId = RawBytesStore.Add(raw.Data);

        // Локальна фабрика: щоб не дублювати RawBytes/LinkLayer у кожному return
        PacketInfo Make(
            string protocol,
            string srcMac = "",
            string dstMac = "",
            string srcIp = "",
            string dstIp = "",
            IPAddress? srcIpAddress = null,
            IPAddress? dstIpAddress = null,
            int? srcPort = null,
            int? dstPort = null,
            string tcpFlags = "",
            int? pid = null,
            string processName = "",
            string info = "")
        {
            return new PacketInfo
            {
                Timestamp = tsLocal,
                Length = length,

                SrcMac = srcMac,
                DstMac = dstMac,
                SrcIp = srcIp,
                DstIp = dstIp,
                SrcIpAddress = srcIpAddress,
                DstIpAddress = dstIpAddress,

                Protocol = protocol,
                SrcPort = srcPort,
                DstPort = dstPort,

                TcpFlags = tcpFlags,
                Info = info,

                Pid = pid,
                ProcessName = processName,

                RawBytesId = rawId,
                LinkLayer = raw.LinkLayerType.ToString(),
                LinkLayerType = linkLayerType
            };
        }

        try
        {
            var data = raw.Data;
            if (data is null || data.Length == 0)
                return Make(protocol: "UNKNOWN", info: "Empty packet");

            var span = data.AsSpan();

            // Fast path currently supports Ethernet (with optional VLAN). Other link layers fall back.
            if (raw.LinkLayerType != LinkLayers.Ethernet)
            {
                return Make(protocol: raw.LinkLayerType.ToString(), info: "Unsupported link-layer (fast path)");
            }

            if (span.Length < 14)
                return Make(protocol: "ETH", info: "Truncated Ethernet");

            string dstMacStr = FormatMac(span.Slice(0, 6));
            string srcMacStr = FormatMac(span.Slice(6, 6));

            int l2Len = 14;
            ushort etherType = ReadU16BE(span, 12);
            if (etherType == 0x8100 && span.Length >= 18)
            {
                // VLAN tag present; actual EtherType is after TCI.
                etherType = ReadU16BE(span, 16);
                l2Len = 18;
            }

            // -------- ARP --------
            if (etherType == 0x0806)
            {
                // Basic ARP header is 28 bytes.
                if (span.Length < l2Len + 28)
                    return Make(protocol: "ARP", srcMac: srcMacStr, dstMac: dstMacStr, info: "Truncated ARP");

                var arpSpan = span.Slice(l2Len);
                ushort op = ReadU16BE(arpSpan, 6);

                // Only handle IPv4 ARP (hlen=6, plen=4)
                byte hlen = arpSpan[4];
                byte plen = arpSpan[5];
                if (hlen == 6 && plen == 4 && arpSpan.Length >= 28)
                {
                    var senderIpBytes = arpSpan.Slice(14, 4);
                    var targetIpBytes = arpSpan.Slice(24, 4);
                    var senderIp = new IPAddress(senderIpBytes);
                    var targetIp = new IPAddress(targetIpBytes);
                    string senderIpStr = FormatIPv4(senderIpBytes);
                    string targetIpStr = FormatIPv4(targetIpBytes);

                    string opText = op switch
                    {
                        1 => "Request",
                        2 => "Reply",
                        _ => $"Op={op}"
                    };

                    return Make(
                        protocol: "ARP",
                        srcMac: srcMacStr,
                        dstMac: dstMacStr,
                        srcIp: senderIpStr,
                        dstIp: targetIpStr,
                        srcIpAddress: senderIp,
                        dstIpAddress: targetIp,
                        info: $"{opText} {senderIpStr} → {targetIpStr}"
                    );
                }

                return Make(protocol: "ARP", srcMac: srcMacStr, dstMac: dstMacStr, info: "Unsupported ARP");
            }

            // -------- IPv4 --------
            if (etherType == 0x0800)
            {
                if (span.Length < l2Len + 20)
                    return Make(protocol: "IPv4", srcMac: srcMacStr, dstMac: dstMacStr, info: "Truncated IPv4");

                int ipStart = l2Len;
                byte vihl = span[ipStart];
                int version = (vihl >> 4) & 0xF;
                if (version != 4)
                    return Make(protocol: "IP", srcMac: srcMacStr, dstMac: dstMacStr, info: "Invalid IPv4");

                int ihl = (vihl & 0x0F) * 4;
                if (ihl < 20) ihl = 20;
                if (span.Length < ipStart + ihl)
                    return Make(protocol: "IPv4", srcMac: srcMacStr, dstMac: dstMacStr, info: "Truncated IPv4 header");

                byte proto = span[ipStart + 9];

                var srcIpBytes = span.Slice(ipStart + 12, 4);
                var dstIpBytes = span.Slice(ipStart + 16, 4);
                var srcIpAddr = new IPAddress(srcIpBytes);
                var dstIpAddr = new IPAddress(dstIpBytes);
                string srcIpStr = FormatIPv4(srcIpBytes);
                string dstIpStr = FormatIPv4(dstIpBytes);

                int l4Start = ipStart + ihl;
                if (span.Length < l4Start)
                    return Make(protocol: "IPv4", srcMac: srcMacStr, dstMac: dstMacStr, srcIp: srcIpStr, dstIp: dstIpStr, srcIpAddress: srcIpAddr, dstIpAddress: dstIpAddr, info: "Truncated L4");

                // TCP
                if (proto == 6 && span.Length >= l4Start + 20)
                {
                    int srcPort = ReadU16BE(span, l4Start);
                    int dstPort = ReadU16BE(span, l4Start + 2);
                    string flagsStr = TcpFlagsToString(span[l4Start + 13]);

                    ResolveTcpProcess(srcIpAddr, srcPort, dstIpAddr, dstPort, out var pid, out var processName);
                    string info = BuildTcpInfo(srcIpStr, srcPort, dstIpStr, dstPort, flagsStr, payloadLen: Math.Max(0, span.Length - l4Start));

                    return Make(
                        protocol: "TCP",
                        srcMac: srcMacStr,
                        dstMac: dstMacStr,
                        srcIp: srcIpStr,
                        dstIp: dstIpStr,
                        srcIpAddress: srcIpAddr,
                        dstIpAddress: dstIpAddr,
                        srcPort: srcPort,
                        dstPort: dstPort,
                        tcpFlags: flagsStr,
                        pid: pid,
                        processName: processName,
                        info: info
                    );
                }

                // UDP
                if (proto == 17 && span.Length >= l4Start + 8)
                {
                    int srcPort = ReadU16BE(span, l4Start);
                    int dstPort = ReadU16BE(span, l4Start + 2);
                    int udpLen = ReadU16BE(span, l4Start + 4);
                    int payloadLen = Math.Max(0, udpLen - 8);

                    ResolveUdpProcess(srcIpAddr, srcPort, dstIpAddr, dstPort, out var pid, out var processName);

                    var protoHint = GuessUdpAppProtocol(srcPort, dstPort);
                    string info = protoHint is null
                        ? $"UDP {srcPort} → {dstPort} Len={payloadLen}"
                        : $"{protoHint} UDP {srcPort} → {dstPort} Len={payloadLen}";

                    return Make(
                        protocol: "UDP",
                        srcMac: srcMacStr,
                        dstMac: dstMacStr,
                        srcIp: srcIpStr,
                        dstIp: dstIpStr,
                        srcIpAddress: srcIpAddr,
                        dstIpAddress: dstIpAddr,
                        srcPort: srcPort,
                        dstPort: dstPort,
                        pid: pid,
                        processName: processName,
                        info: info
                    );
                }

                // ICMPv4
                if (proto == 1 && span.Length >= l4Start + 2)
                {
                    byte type = span[l4Start];
                    byte code = span[l4Start + 1];
                    return Make(
                        protocol: "ICMPv4",
                        srcMac: srcMacStr,
                        dstMac: dstMacStr,
                        srcIp: srcIpStr,
                        dstIp: dstIpStr,
                        srcIpAddress: srcIpAddr,
                        dstIpAddress: dstIpAddr,
                        info: $"ICMPv4 Type={type} Code={code}"
                    );
                }

                return Make(
                    protocol: "IPv4",
                    srcMac: srcMacStr,
                    dstMac: dstMacStr,
                    srcIp: srcIpStr,
                    dstIp: dstIpStr,
                    srcIpAddress: srcIpAddr,
                    dstIpAddress: dstIpAddr,
                    info: $"Proto={proto}"
                );
            }

            // -------- IPv6 --------
            if (etherType == 0x86DD)
            {
                if (span.Length < l2Len + 40)
                    return Make(protocol: "IPv6", srcMac: srcMacStr, dstMac: dstMacStr, info: "Truncated IPv6");

                int ipStart = l2Len;
                int version = (span[ipStart] >> 4) & 0xF;
                if (version != 6)
                    return Make(protocol: "IP", srcMac: srcMacStr, dstMac: dstMacStr, info: "Invalid IPv6");

                byte nextHeader = span[ipStart + 6];

                var srcIpBytes = span.Slice(ipStart + 8, 16);
                var dstIpBytes = span.Slice(ipStart + 24, 16);
                var srcIpAddr = new IPAddress(srcIpBytes);
                var dstIpAddr = new IPAddress(dstIpBytes);
                string srcIpStr = srcIpAddr.ToString();
                string dstIpStr = dstIpAddr.ToString();

                int l4Start = ipStart + 40;

                // TCP
                if (nextHeader == 6 && span.Length >= l4Start + 20)
                {
                    int srcPort = ReadU16BE(span, l4Start);
                    int dstPort = ReadU16BE(span, l4Start + 2);
                    string flagsStr = TcpFlagsToString(span[l4Start + 13]);

                    ResolveTcpProcess(srcIpAddr, srcPort, dstIpAddr, dstPort, out var pid, out var processName);
                    string info = BuildTcpInfo(srcIpStr, srcPort, dstIpStr, dstPort, flagsStr, payloadLen: Math.Max(0, span.Length - l4Start));

                    return Make(
                        protocol: "TCP",
                        srcMac: srcMacStr,
                        dstMac: dstMacStr,
                        srcIp: srcIpStr,
                        dstIp: dstIpStr,
                        srcIpAddress: srcIpAddr,
                        dstIpAddress: dstIpAddr,
                        srcPort: srcPort,
                        dstPort: dstPort,
                        tcpFlags: flagsStr,
                        pid: pid,
                        processName: processName,
                        info: info
                    );
                }

                // UDP
                if (nextHeader == 17 && span.Length >= l4Start + 8)
                {
                    int srcPort = ReadU16BE(span, l4Start);
                    int dstPort = ReadU16BE(span, l4Start + 2);
                    int udpLen = ReadU16BE(span, l4Start + 4);
                    int payloadLen = Math.Max(0, udpLen - 8);

                    ResolveUdpProcess(srcIpAddr, srcPort, dstIpAddr, dstPort, out var pid, out var processName);

                    var protoHint = GuessUdpAppProtocol(srcPort, dstPort);
                    string info = protoHint is null
                        ? $"UDP {srcPort} → {dstPort} Len={payloadLen}"
                        : $"{protoHint} UDP {srcPort} → {dstPort} Len={payloadLen}";

                    return Make(
                        protocol: "UDP",
                        srcMac: srcMacStr,
                        dstMac: dstMacStr,
                        srcIp: srcIpStr,
                        dstIp: dstIpStr,
                        srcIpAddress: srcIpAddr,
                        dstIpAddress: dstIpAddr,
                        srcPort: srcPort,
                        dstPort: dstPort,
                        pid: pid,
                        processName: processName,
                        info: info
                    );
                }

                // ICMPv6
                if (nextHeader == 58 && span.Length >= l4Start + 2)
                {
                    byte type = span[l4Start];
                    byte code = span[l4Start + 1];
                    return Make(
                        protocol: "ICMPv6",
                        srcMac: srcMacStr,
                        dstMac: dstMacStr,
                        srcIp: srcIpStr,
                        dstIp: dstIpStr,
                        srcIpAddress: srcIpAddr,
                        dstIpAddress: dstIpAddr,
                        info: $"ICMPv6 Type={type} Code={code}"
                    );
                }

                return Make(
                    protocol: "IPv6",
                    srcMac: srcMacStr,
                    dstMac: dstMacStr,
                    srcIp: srcIpStr,
                    dstIp: dstIpStr,
                    srcIpAddress: srcIpAddr,
                    dstIpAddress: dstIpAddr,
                    info: $"NextHeader={nextHeader}"
                );
            }

            return Make(protocol: "ETH", srcMac: srcMacStr, dstMac: dstMacStr, info: $"EtherType=0x{etherType:X4}");
        }
        catch (Exception ex)
        {
            return Make(protocol: "ERROR", info: ex.Message);
        }
    }

    private static ushort ReadU16BE(ReadOnlySpan<byte> span, int offset)
        => (ushort)((span[offset] << 8) | span[offset + 1]);

    private static string FormatMac(ReadOnlySpan<byte> mac)
    {
        if (mac.Length < 6) return "";
        return Convert.ToHexString(mac.Slice(0, 6));
    }

    private static string FormatIPv4(ReadOnlySpan<byte> ip)
    {
        if (ip.Length < 4) return "";

        Span<char> tmp = stackalloc char[15];
        int pos = 0;
        ip[0].TryFormat(tmp.Slice(pos), out int written);
        pos += written;
        tmp[pos++] = '.';
        ip[1].TryFormat(tmp.Slice(pos), out written);
        pos += written;
        tmp[pos++] = '.';
        ip[2].TryFormat(tmp.Slice(pos), out written);
        pos += written;
        tmp[pos++] = '.';
        ip[3].TryFormat(tmp.Slice(pos), out written);
        pos += written;
        return new string(tmp.Slice(0, pos));
    }

    private static string TcpFlagsToString(byte flags)
    {
        // TCP flags: CWR|ECE|URG|ACK|PSH|RST|SYN|FIN
        var list = new List<string>(6);
        if ((flags & 0x02) != 0) list.Add("SYN");
        if ((flags & 0x10) != 0) list.Add("ACK");
        if ((flags & 0x01) != 0) list.Add("FIN");
        if ((flags & 0x04) != 0) list.Add("RST");
        if ((flags & 0x08) != 0) list.Add("PSH");
        if ((flags & 0x20) != 0) list.Add("URG");
        return list.Count == 0 ? "" : string.Join(", ", list);
    }

    private static string BuildTcpInfo(string srcIp, int srcPort, string dstIp, int dstPort, string flags, int payloadLen)
    {
        var appHint = GuessTcpAppProtocol(srcPort, dstPort);
        if (appHint is null)
            return $"{srcIp}:{srcPort} → {dstIp}:{dstPort} [{flags}] Len={payloadLen}";

        return $"{appHint} {srcIp}:{srcPort} → {dstIp}:{dstPort} [{flags}] Len={payloadLen}";
    }

    private static string? GuessTcpAppProtocol(int srcPort, int dstPort)
    {
        if (srcPort == 80 || dstPort == 80) return "HTTP";
        if (srcPort == 443 || dstPort == 443) return "TLS";
        if (srcPort == 22 || dstPort == 22) return "SSH";
        if (srcPort == 3389 || dstPort == 3389) return "RDP";
        return null;
    }

    private static string? GuessUdpAppProtocol(int srcPort, int dstPort)
    {
        if (srcPort == 53 || dstPort == 53) return "DNS";
        if (srcPort == 67 || dstPort == 67 || srcPort == 68 || dstPort == 68) return "DHCP";
        if (srcPort == 123 || dstPort == 123) return "NTP";
        return null;
    }

    private void ResolveTcpProcess(IPAddress? srcIp, int srcPort, IPAddress? dstIp, int dstPort, out int? pid, out string processName)
    {
        pid = null;
        processName = "";

        if (srcIp is null || dstIp is null)
            return;

        if (!_processMapperService.TryResolveTcp(srcIp, srcPort, dstIp, dstPort, out var resolvedPid))
            return;

        pid = resolvedPid;
        processName = _processMapperService.GetProcessNameCached(resolvedPid);
    }

    private void ResolveUdpProcess(IPAddress? srcIp, int srcPort, IPAddress? dstIp, int dstPort, out int? pid, out string processName)
    {
        pid = null;
        processName = "";

        if (srcIp is not null && _processMapperService.TryResolveUdp(srcIp, srcPort, out var srcPid))
        {
            pid = srcPid;
            processName = _processMapperService.GetProcessNameCached(srcPid);
            return;
        }

        if (dstIp is not null && _processMapperService.TryResolveUdp(dstIp, dstPort, out var dstPid))
        {
            pid = dstPid;
            processName = _processMapperService.GetProcessNameCached(dstPid);
        }
    }
}
