// Відповідає за швидкий (allocation-light) парсинг пакетів для таблиці.
// Для деталей (Protocol tree / HEX) повний парсинг робиться в UI при виборі пакета.
using Application.Abstractions;
using Domain.Models;
using Infrastructure.Networking;
using PacketDotNet;
using SharpPcap;
using System.Net;
using System.Text;

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

        LinkLayers linkLayer;
        byte[]? data;

        if (rawCapture is RawCapture raw)
        {
            linkLayer = raw.LinkLayerType;
            data = raw.Data;
        }
        else if (rawCapture is RawPacketData offline)
        {
            linkLayer = (LinkLayers)offline.LinkLayerType;
            data = offline.Data;
        }
        else
        {
            return new PacketInfo
            {
                Timestamp = tsLocal,
                Length = length,
                Protocol = "UNKNOWN",
                TransportProtocol = "UNKNOWN",
                Info = "RawCapture type mismatch"
            };
        }

        // Відповідає за збереження типу LinkLayer для коректного повторного парсингу в UI.
        int linkLayerType = (int)linkLayer;

        // Save raw bytes into central store. RawBytesStore.Add will make an internal copy.
        int? rawId = RawBytesStore.Add(data);

        // Локальна фабрика: щоб не дублювати RawBytes/LinkLayer у кожному return
        PacketInfo Make(
            string protocol,
            string? transportProtocol = null,
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
                TransportProtocol = string.IsNullOrWhiteSpace(transportProtocol) ? protocol : transportProtocol,
                SrcPort = srcPort,
                DstPort = dstPort,

                TcpFlags = tcpFlags,
                Info = info,

                Pid = pid,
                ProcessName = processName,

                RawBytesId = rawId,
                LinkLayer = linkLayer.ToString(),
                LinkLayerType = linkLayerType
            };
        }

        PacketInfo ParseIpv4At(ReadOnlySpan<byte> span, int ipStart, string srcMacStr, string dstMacStr)
        {
            if (span.Length < ipStart + 20)
                return Make(protocol: "IPv4", srcMac: srcMacStr, dstMac: dstMacStr, info: "Truncated IPv4");

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
                int tcpHeaderLen = Math.Max(20, ((span[l4Start + 12] >> 4) & 0x0F) * 4);
                if (span.Length < l4Start + tcpHeaderLen)
                {
                    return Make(
                        protocol: "TCP",
                        transportProtocol: "TCP",
                        srcMac: srcMacStr,
                        dstMac: dstMacStr,
                        srcIp: srcIpStr,
                        dstIp: dstIpStr,
                        srcIpAddress: srcIpAddr,
                        dstIpAddress: dstIpAddr,
                        srcPort: srcPort,
                        dstPort: dstPort,
                        tcpFlags: flagsStr,
                        info: "Truncated TCP header"
                    );
                }

                int payloadStart = l4Start + tcpHeaderLen;
                var tcpPayload = payloadStart <= span.Length ? span.Slice(payloadStart) : ReadOnlySpan<byte>.Empty;
                string detectedProtocol = DetectTcpProtocol(tcpPayload, srcPort, dstPort, out var tcpDetail) ?? "TCP";

                ResolveTcpProcess(srcIpAddr, srcPort, dstIpAddr, dstPort, out var pid, out var processName);
                string info = BuildTcpInfo(detectedProtocol, srcIpStr, srcPort, dstIpStr, dstPort, flagsStr, payloadLen: tcpPayload.Length, detail: tcpDetail);

                return Make(
                    protocol: detectedProtocol,
                    transportProtocol: "TCP",
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
                int availablePayloadLen = Math.Max(0, span.Length - (l4Start + 8));
                int payloadLen = udpLen >= 8
                    ? Math.Min(udpLen - 8, availablePayloadLen)
                    : availablePayloadLen;
                var udpPayload = payloadLen > 0 ? span.Slice(l4Start + 8, payloadLen) : ReadOnlySpan<byte>.Empty;

                ResolveUdpProcess(srcIpAddr, srcPort, dstIpAddr, dstPort, out var pid, out var processName);
                string detectedProtocol = DetectUdpProtocol(udpPayload, srcPort, dstPort, out var udpDetail) ?? "UDP";
                string info = BuildUdpInfo(detectedProtocol, srcPort, dstPort, payloadLen, udpDetail);

                return Make(
                    protocol: detectedProtocol,
                    transportProtocol: "UDP",
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

            // IGMP
            if (proto == 2)
            {
                var igmpPayload = l4Start <= span.Length ? span.Slice(l4Start) : ReadOnlySpan<byte>.Empty;
                string igmpProtocol = DetectIgmpProtocol(igmpPayload, out var igmpInfo);

                return Make(
                    protocol: igmpProtocol,
                    transportProtocol: "IGMP",
                    srcMac: srcMacStr,
                    dstMac: dstMacStr,
                    srcIp: srcIpStr,
                    dstIp: dstIpStr,
                    srcIpAddress: srcIpAddr,
                    dstIpAddress: dstIpAddr,
                    info: igmpInfo
                );
            }

            // ICMPv4
            if (proto == 1 && span.Length >= l4Start + 2)
            {
                byte type = span[l4Start];
                byte code = span[l4Start + 1];
                return Make(
                    protocol: "ICMPv4",
                    transportProtocol: "ICMPv4",
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
                info: $"Proto={proto} ({GetIpProtocolName(proto)})"
            );
        }

        PacketInfo ParseIpv6At(ReadOnlySpan<byte> span, int ipStart, string srcMacStr, string dstMacStr)
        {
            if (span.Length < ipStart + 40)
                return Make(protocol: "IPv6", srcMac: srcMacStr, dstMac: dstMacStr, info: "Truncated IPv6");

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
                int tcpHeaderLen = Math.Max(20, ((span[l4Start + 12] >> 4) & 0x0F) * 4);
                if (span.Length < l4Start + tcpHeaderLen)
                {
                    return Make(
                        protocol: "TCP",
                        transportProtocol: "TCP",
                        srcMac: srcMacStr,
                        dstMac: dstMacStr,
                        srcIp: srcIpStr,
                        dstIp: dstIpStr,
                        srcIpAddress: srcIpAddr,
                        dstIpAddress: dstIpAddr,
                        srcPort: srcPort,
                        dstPort: dstPort,
                        tcpFlags: flagsStr,
                        info: "Truncated TCP header"
                    );
                }

                int payloadStart = l4Start + tcpHeaderLen;
                var tcpPayload = payloadStart <= span.Length ? span.Slice(payloadStart) : ReadOnlySpan<byte>.Empty;
                string detectedProtocol = DetectTcpProtocol(tcpPayload, srcPort, dstPort, out var tcpDetail) ?? "TCP";

                ResolveTcpProcess(srcIpAddr, srcPort, dstIpAddr, dstPort, out var pid, out var processName);
                string info = BuildTcpInfo(detectedProtocol, srcIpStr, srcPort, dstIpStr, dstPort, flagsStr, payloadLen: tcpPayload.Length, detail: tcpDetail);

                return Make(
                    protocol: detectedProtocol,
                    transportProtocol: "TCP",
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
                int availablePayloadLen = Math.Max(0, span.Length - (l4Start + 8));
                int payloadLen = udpLen >= 8
                    ? Math.Min(udpLen - 8, availablePayloadLen)
                    : availablePayloadLen;
                var udpPayload = payloadLen > 0 ? span.Slice(l4Start + 8, payloadLen) : ReadOnlySpan<byte>.Empty;

                ResolveUdpProcess(srcIpAddr, srcPort, dstIpAddr, dstPort, out var pid, out var processName);
                string detectedProtocol = DetectUdpProtocol(udpPayload, srcPort, dstPort, out var udpDetail) ?? "UDP";
                string info = BuildUdpInfo(detectedProtocol, srcPort, dstPort, payloadLen, udpDetail);

                return Make(
                    protocol: detectedProtocol,
                    transportProtocol: "UDP",
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
                    transportProtocol: "ICMPv6",
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
                info: $"NextHeader={nextHeader} ({GetIpProtocolName(nextHeader)})"
            );
        }

        static uint ReadU32LE(ReadOnlySpan<byte> s)
            => (uint)(s[0] | (s[1] << 8) | (s[2] << 16) | (s[3] << 24));

        static uint ReadU32BE(ReadOnlySpan<byte> s)
            => (uint)(s[3] | (s[2] << 8) | (s[1] << 16) | (s[0] << 24));

        try
        {
            if (data is null || data.Length == 0)
                return Make(protocol: "UNKNOWN", info: "Empty packet");

            var span = data.AsSpan();

            // Fast path currently supports Ethernet and common loopback link-layers (DLT_NULL / DLT_LOOP / DLT_RAW).
            // Other link layers fall back.
            if (linkLayer != LinkLayers.Ethernet)
            {
                const int DltNull = 0;
                const int DltRaw = 101;
                const int DltLoop = 108;

                // DLT_NULL / DLT_LOOP: 4-byte address family, then IP payload.
                if (linkLayerType == DltNull || linkLayerType == DltLoop)
                {
                    if (span.Length < 4)
                        return Make(protocol: "LOOP", info: "Truncated loopback header");

                    uint fam = ReadU32LE(span.Slice(0, 4));
                    if (fam != 2 && fam != 23 && fam != 24 && fam != 10)
                        fam = ReadU32BE(span.Slice(0, 4));

                    int ipStart = 4;
                    if (span.Length <= ipStart)
                        return Make(protocol: "LOOP", info: "Empty loopback payload");

                    if (fam == 2)
                        return ParseIpv4At(span, ipStart, srcMacStr: "", dstMacStr: "");
                    if (fam == 23 || fam == 24 || fam == 10)
                        return ParseIpv6At(span, ipStart, srcMacStr: "", dstMacStr: "");

                    // Unknown family -> fall back to IP version nibble
                    int v = (span[ipStart] >> 4) & 0xF;
                    if (v == 4) return ParseIpv4At(span, ipStart, srcMacStr: "", dstMacStr: "");
                    if (v == 6) return ParseIpv6At(span, ipStart, srcMacStr: "", dstMacStr: "");
                    return Make(protocol: "LOOP", info: $"Unknown address family={fam}");
                }

                // DLT_RAW: IP payload without link-layer header.
                if (linkLayerType == DltRaw)
                {
                    int v = (span[0] >> 4) & 0xF;
                    if (v == 4) return ParseIpv4At(span, 0, srcMacStr: "", dstMacStr: "");
                    if (v == 6) return ParseIpv6At(span, 0, srcMacStr: "", dstMacStr: "");
                    return Make(protocol: "RAW", info: "Unknown IP version");
                }

                return Make(protocol: linkLayer.ToString(), info: "Unsupported link-layer (fast path)");
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
                return ParseIpv4At(span, l2Len, srcMacStr, dstMacStr);

            // -------- IPv6 --------
            if (etherType == 0x86DD)
                return ParseIpv6At(span, l2Len, srcMacStr, dstMacStr);

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

    private static string BuildTcpInfo(string protocol, string srcIp, int srcPort, string dstIp, int dstPort, string flags, int payloadLen, string? detail = null)
    {
        var flagsPart = string.IsNullOrWhiteSpace(flags) ? string.Empty : $" [{flags}]";
        var detailPart = string.IsNullOrWhiteSpace(detail) ? string.Empty : $" {detail}";
        return $"{protocol}{detailPart} {srcIp}:{srcPort} → {dstIp}:{dstPort}{flagsPart} Len={payloadLen}";
    }

    private static string? GuessTcpAppProtocol(int srcPort, int dstPort)
    {
        if (srcPort == 80 || dstPort == 80) return "HTTP";
        if (srcPort == 53 || dstPort == 53) return "DNS";
        if (srcPort == 443 || dstPort == 443) return "TLS";
        if (srcPort == 465 || dstPort == 465 || srcPort == 563 || dstPort == 563 || srcPort == 636 || dstPort == 636 || srcPort == 853 || dstPort == 853 || srcPort == 8443 || dstPort == 8443) return "TLS";
        if (srcPort == 22 || dstPort == 22) return "SSH";
        if (srcPort == 3389 || dstPort == 3389) return "RDP";
        return null;
    }

    private static string? GuessUdpAppProtocol(int srcPort, int dstPort)
    {
        if (srcPort == 53 || dstPort == 53) return "DNS";
        if (srcPort == 5353 || dstPort == 5353) return "DNS";
        if (srcPort == 67 || dstPort == 67 || srcPort == 68 || dstPort == 68) return "DHCP";
        if (srcPort == 123 || dstPort == 123) return "NTP";
        return null;
    }

    private static string BuildUdpInfo(string protocol, int srcPort, int dstPort, int payloadLen, string? detail = null)
    {
        var detailPart = string.IsNullOrWhiteSpace(detail) ? string.Empty : $" {detail}";
        return $"{protocol}{detailPart} {srcPort} → {dstPort} Len={payloadLen}";
    }

    private static string? DetectTcpProtocol(ReadOnlySpan<byte> payload, int srcPort, int dstPort, out string? detail)
    {
        if (payload.Length > 0)
        {
            if (TryDetectTlsOrSsl(payload, out var tlsProtocol, out detail))
                return tlsProtocol;

            if (IsDnsPort(srcPort, dstPort) && TryParseDnsMessage(payload, tcpLengthPrefixed: true, out detail))
                return "DNS";
        }

        detail = null;
        return GuessTcpAppProtocol(srcPort, dstPort);
    }

    private static string? DetectUdpProtocol(ReadOnlySpan<byte> payload, int srcPort, int dstPort, out string? detail)
    {
        if (payload.Length > 0)
        {
            if ((IsDnsPort(srcPort, dstPort) || LooksLikeDnsMessage(payload)) &&
                TryParseDnsMessage(payload, tcpLengthPrefixed: false, out detail))
            {
                return "DNS";
            }

            if (TryDetectQuic(payload, srcPort, dstPort, out detail))
                return "QUIC";
        }

        detail = null;
        return GuessUdpAppProtocol(srcPort, dstPort);
    }

    private static bool TryDetectTlsOrSsl(ReadOnlySpan<byte> payload, out string protocol, out string? detail)
    {
        protocol = string.Empty;
        detail = null;

        if (payload.Length >= 3 && (payload[0] & 0x80) != 0)
        {
            protocol = "SSL";
            detail = payload[2] switch
            {
                1 => "ClientHello",
                4 => "ServerHello",
                _ => "SSLv2 Record"
            };
            return true;
        }

        if (payload.Length < 5)
            return false;

        byte contentType = payload[0];
        if (contentType is < 20 or > 24)
            return false;

        ushort recordVersion = ReadU16BE(payload, 1);
        if ((recordVersion >> 8) != 3)
            return false;

        ushort recordLength = ReadU16BE(payload, 3);
        if (recordLength == 0 || recordLength > 18_432)
            return false;

        protocol = MapTlsVersion(recordVersion);
        detail = GetTlsContentTypeName(contentType);

        if (contentType == 22 && payload.Length >= 9)
        {
            var recordBody = payload.Slice(5, Math.Min(recordLength, payload.Length - 5));
            if (recordBody.Length >= 4)
            {
                byte handshakeType = recordBody[0];
                int handshakeLength = (recordBody[1] << 16) | (recordBody[2] << 8) | recordBody[3];
                var handshakeBody = recordBody.Length > 4
                    ? recordBody.Slice(4, Math.Min(handshakeLength, recordBody.Length - 4))
                    : ReadOnlySpan<byte>.Empty;

                if (TryGetTlsHandshakeVersion(handshakeType, handshakeBody, recordVersion, out var handshakeVersion))
                    protocol = handshakeVersion;

                detail = GetTlsHandshakeName(handshakeType);
            }
        }

        return true;
    }

    private static bool TryDetectQuic(ReadOnlySpan<byte> payload, int srcPort, int dstPort, out string? detail)
    {
        detail = null;
        if (payload.Length < 1)
            return false;

        byte first = payload[0];
        if ((first & 0x40) == 0)
            return false;

        bool isLongHeader = (first & 0x80) != 0;
        if (isLongHeader)
        {
            if (payload.Length < 6)
                return false;

            uint version = ReadU32BE(payload.Slice(1, 4));
            string packetType = ((first >> 4) & 0x03) switch
            {
                0 => "Initial",
                1 => "0-RTT",
                2 => "Handshake",
                3 => "Retry",
                _ => "Long Header"
            };

            detail = version == 0
                ? $"{packetType} Version Negotiation"
                : $"{packetType} {FormatQuicVersion(version)}";

            return true;
        }

        if (!IsCommonQuicPort(srcPort, dstPort))
            return false;

        detail = "Short Header";
        return true;
    }

    private static string DetectIgmpProtocol(ReadOnlySpan<byte> payload, out string info)
    {
        if (payload.Length < 8)
        {
            info = "Truncated IGMP";
            return "IGMP";
        }

        byte type = payload[0];
        byte maxRespTime = payload[1];
        string version = type switch
        {
            0x12 => "IGMPv1",
            0x16 or 0x17 => "IGMPv2",
            0x22 => "IGMPv3",
            0x11 when payload.Length >= 12 => "IGMPv3",
            0x11 when maxRespTime == 0 => "IGMPv1",
            0x11 => "IGMPv2",
            _ => "IGMP"
        };

        string typeName = type switch
        {
            0x11 => "Membership Query",
            0x12 => "Membership Report",
            0x16 => "Membership Report",
            0x17 => "Leave Group",
            0x22 => "Membership Report",
            _ => $"Type=0x{type:X2}"
        };

        string group = payload.Length >= 8 ? FormatIPv4(payload.Slice(4, 4)) : string.Empty;
        info = string.IsNullOrWhiteSpace(group) || group == "0.0.0.0"
            ? $"{version} {typeName}"
            : $"{version} {typeName} {group}";

        return version;
    }

    private static bool IsDnsPort(int srcPort, int dstPort)
        => srcPort == 53 || dstPort == 53 || srcPort == 5353 || dstPort == 5353;

    private static bool LooksLikeDnsMessage(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 12)
            return false;

        ushort flags = ReadU16BE(payload, 2);
        int opcode = (flags >> 11) & 0xF;
        if (opcode > 6)
            return false;

        int questions = ReadU16BE(payload, 4);
        int answers = ReadU16BE(payload, 6);
        int authorities = ReadU16BE(payload, 8);
        int additionals = ReadU16BE(payload, 10);
        return questions + answers + authorities + additionals > 0;
    }

    private static bool TryParseDnsMessage(ReadOnlySpan<byte> payload, bool tcpLengthPrefixed, out string? detail)
    {
        detail = null;

        ReadOnlySpan<byte> message = payload;
        if (tcpLengthPrefixed)
        {
            if (payload.Length < 14)
                return false;

            int declaredLength = ReadU16BE(payload, 0);
            if (declaredLength <= 0)
                return false;

            int dnsLength = Math.Min(declaredLength, payload.Length - 2);
            if (dnsLength < 12)
                return false;

            message = payload.Slice(2, dnsLength);
        }
        else if (payload.Length < 12)
        {
            return false;
        }

        if (message.Length < 12)
            return false;

        ushort flags = ReadU16BE(message, 2);
        int opcode = (flags >> 11) & 0xF;
        if (opcode > 6)
            return false;

        int questions = ReadU16BE(message, 4);
        int answers = ReadU16BE(message, 6);
        int authorities = ReadU16BE(message, 8);
        int additionals = ReadU16BE(message, 10);
        if (questions + answers + authorities + additionals == 0)
            return false;

        bool isResponse = (flags & 0x8000) != 0;
        string direction = isResponse ? "Response" : "Query";

        if (questions > 0 && TryReadDnsName(message, 12, out var qname, out var nextOffset))
        {
            string typeSuffix = string.Empty;
            if (nextOffset + 2 <= message.Length)
            {
                ushort qtype = ReadU16BE(message, nextOffset);
                string qtypeName = GetDnsTypeName(qtype);
                if (!string.IsNullOrWhiteSpace(qtypeName))
                    typeSuffix = $" {qtypeName}";
            }

            detail = $"{direction} {qname}{typeSuffix}";
            return true;
        }

        detail = $"{direction} QD={questions} AN={answers}";
        return true;
    }

    private static bool TryReadDnsName(ReadOnlySpan<byte> message, int startOffset, out string name, out int nextOffset)
    {
        name = string.Empty;
        nextOffset = startOffset;

        if ((uint)startOffset >= (uint)message.Length)
            return false;

        var sb = new StringBuilder();
        int offset = startOffset;
        int jumps = 0;
        bool jumped = false;

        while ((uint)offset < (uint)message.Length && jumps < 16)
        {
            byte len = message[offset];
            if (len == 0)
            {
                if (!jumped)
                    nextOffset = offset + 1;

                name = sb.Length == 0 ? "<root>" : sb.ToString();
                return true;
            }

            if ((len & 0xC0) == 0xC0)
            {
                if (offset + 1 >= message.Length)
                    return false;

                int pointer = ((len & 0x3F) << 8) | message[offset + 1];
                if ((uint)pointer >= (uint)message.Length)
                    return false;

                if (!jumped)
                    nextOffset = offset + 2;

                offset = pointer;
                jumped = true;
                jumps++;
                continue;
            }

            offset++;
            if (offset + len > message.Length)
                return false;

            if (sb.Length > 0)
                sb.Append('.');

            for (int i = 0; i < len; i++)
            {
                byte ch = message[offset + i];
                sb.Append(IsDnsLabelChar(ch) ? (char)ch : '?');
            }

            offset += len;
            if (!jumped)
                nextOffset = offset;
        }

        return false;
    }

    private static bool IsDnsLabelChar(byte value)
        => (value >= (byte)'a' && value <= (byte)'z')
        || (value >= (byte)'A' && value <= (byte)'Z')
        || (value >= (byte)'0' && value <= (byte)'9')
        || value is (byte)'-' or (byte)'_';

    private static uint ReadU32BE(ReadOnlySpan<byte> span)
        => (uint)(span[3] | (span[2] << 8) | (span[1] << 16) | (span[0] << 24));

    private static string GetDnsTypeName(ushort type)
        => type switch
        {
            1 => "A",
            2 => "NS",
            5 => "CNAME",
            6 => "SOA",
            12 => "PTR",
            15 => "MX",
            16 => "TXT",
            28 => "AAAA",
            33 => "SRV",
            41 => "OPT",
            47 => "NSEC",
            255 => "ANY",
            _ => string.Empty
        };

    private static bool TryGetTlsHandshakeVersion(byte handshakeType, ReadOnlySpan<byte> handshakeBody, ushort recordVersion, out string protocol)
    {
        protocol = MapTlsVersion(recordVersion);

        if (handshakeBody.Length < 2)
            return true;

        ushort legacyVersion = ReadU16BE(handshakeBody, 0);

        if (handshakeType == 1 && TryGetTlsClientHelloVersion(handshakeBody, out var clientVersion))
        {
            protocol = MapTlsVersion(clientVersion);
            return true;
        }

        if (handshakeType == 2 && TryGetTlsServerHelloVersion(handshakeBody, out var serverVersion))
        {
            protocol = MapTlsVersion(serverVersion);
            return true;
        }

        if (legacyVersion != 0)
            protocol = MapTlsVersion(legacyVersion);

        return true;
    }

    private static bool TryGetTlsClientHelloVersion(ReadOnlySpan<byte> body, out ushort version)
    {
        version = 0;
        if (body.Length < 34)
            return false;

        int offset = 34;
        if (offset >= body.Length)
            return false;

        int sessionIdLength = body[offset];
        offset += 1 + sessionIdLength;
        if (offset + 2 > body.Length)
            return false;

        int cipherSuitesLength = ReadU16BE(body, offset);
        offset += 2 + cipherSuitesLength;
        if (offset >= body.Length)
            return false;

        int compressionMethodsLength = body[offset];
        offset += 1 + compressionMethodsLength;
        if (offset + 2 > body.Length)
            return false;

        int extensionsLength = ReadU16BE(body, offset);
        offset += 2;
        int extensionsEnd = Math.Min(body.Length, offset + extensionsLength);

        while (offset + 4 <= extensionsEnd)
        {
            ushort extensionType = ReadU16BE(body, offset);
            int extensionLength = ReadU16BE(body, offset + 2);
            offset += 4;
            if (offset + extensionLength > extensionsEnd)
                return false;

            if (extensionType == 0x002B && extensionLength >= 3)
            {
                int listLength = body[offset];
                if (listLength + 1 <= extensionLength)
                {
                    ushort bestVersion = 0;
                    for (int i = offset + 1; i + 1 < offset + 1 + listLength; i += 2)
                    {
                        ushort candidate = ReadU16BE(body, i);
                        if (candidate > bestVersion)
                            bestVersion = candidate;
                    }

                    if (bestVersion != 0)
                    {
                        version = bestVersion;
                        return true;
                    }
                }
            }

            offset += extensionLength;
        }

        return false;
    }

    private static bool TryGetTlsServerHelloVersion(ReadOnlySpan<byte> body, out ushort version)
    {
        version = 0;
        if (body.Length < 38)
            return false;

        int offset = 34;
        int sessionIdLength = body[offset];
        offset += 1 + sessionIdLength;
        if (offset + 3 > body.Length)
            return false;

        offset += 2; // cipher suite
        offset += 1; // compression method

        if (offset + 2 > body.Length)
            return false;

        int extensionsLength = ReadU16BE(body, offset);
        offset += 2;
        int extensionsEnd = Math.Min(body.Length, offset + extensionsLength);

        while (offset + 4 <= extensionsEnd)
        {
            ushort extensionType = ReadU16BE(body, offset);
            int extensionLength = ReadU16BE(body, offset + 2);
            offset += 4;
            if (offset + extensionLength > extensionsEnd)
                return false;

            if (extensionType == 0x002B && extensionLength == 2)
            {
                version = ReadU16BE(body, offset);
                return true;
            }

            offset += extensionLength;
        }

        return false;
    }

    private static string MapTlsVersion(ushort version)
        => version switch
        {
            0x0002 => "SSL",
            0x0300 => "SSL",
            0x0301 => "TLSv1.0",
            0x0302 => "TLSv1.1",
            0x0303 => "TLSv1.2",
            0x0304 => "TLSv1.3",
            _ => "TLS"
        };

    private static string GetTlsContentTypeName(byte contentType)
        => contentType switch
        {
            20 => "ChangeCipherSpec",
            21 => "Alert",
            22 => "Handshake",
            23 => "ApplicationData",
            24 => "Heartbeat",
            _ => "Record"
        };

    private static string GetTlsHandshakeName(byte handshakeType)
        => handshakeType switch
        {
            1 => "ClientHello",
            2 => "ServerHello",
            4 => "NewSessionTicket",
            8 => "EncryptedExtensions",
            11 => "Certificate",
            12 => "ServerKeyExchange",
            13 => "CertificateRequest",
            14 => "ServerHelloDone",
            15 => "CertificateVerify",
            16 => "ClientKeyExchange",
            20 => "Finished",
            _ => $"Handshake({handshakeType})"
        };

    private static bool IsCommonQuicPort(int srcPort, int dstPort)
        => srcPort == 443 || dstPort == 443 || srcPort == 784 || dstPort == 784 || srcPort == 8443 || dstPort == 8443;

    private static string FormatQuicVersion(uint version)
        => version switch
        {
            0x00000001 => "v1",
            0x6B3343CF => "v2",
            0xFF00001D => "draft-29",
            _ => $"0x{version:X8}"
        };

    private static string GetIpProtocolName(byte protocolNumber)
        => protocolNumber switch
        {
            1 => "ICMPv4",
            2 => "IGMP",
            6 => "TCP",
            17 => "UDP",
            41 => "IPv6",
            47 => "GRE",
            50 => "ESP",
            51 => "AH",
            58 => "ICMPv6",
            89 => "OSPF",
            _ => "Unknown"
        };

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
