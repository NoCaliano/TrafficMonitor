// Відповідає за реальний парсинг пакетів через PacketDotNet (Ethernet/IP/TCP/UDP/ICMP/ARP)
// та формування PacketInfo для UI.
using Application.Abstractions;
using Domain.Models;
using PacketDotNet;
using SharpPcap;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;

namespace Infrastructure.Parsing;

public sealed class PacketDotNetParser : IPacketParser
{
    public PacketInfo Parse(DateTime timestamp, int length, object rawCapture)
    {
        // rawCapture очікуємо як SharpPcap.RawCapture
        if (rawCapture is not RawCapture raw)
        {
            return new PacketInfo
            {
                Timestamp = timestamp,
                Length = length,
                Protocol = "UNKNOWN",
                Info = "RawCapture type mismatch"
            };
        }

        try
        {
            // Парсимо базовий пакет
            var packet = Packet.ParsePacket(raw.LinkLayerType, raw.Data);

            // Ethernet (якщо є)
            var eth = packet.Extract<EthernetPacket>();
            var srcMac = eth?.SourceHardwareAddress?.ToString() ?? "";
            var dstMac = eth?.DestinationHardwareAddress?.ToString() ?? "";

            // ARP
            var arp = packet.Extract<ArpPacket>();
            if (arp is not null)
            {
                return new PacketInfo
                {
                    Timestamp = timestamp,
                    Length = length,
                    SrcMac = srcMac,
                    DstMac = dstMac,
                    Protocol = "ARP",
                    SrcIp = SafeIpToString(arp.SenderProtocolAddress),
                    DstIp = SafeIpToString(arp.TargetProtocolAddress),
                    Info = $"{arp.Operation} {SafeIpToString(arp.SenderProtocolAddress)} → {SafeIpToString(arp.TargetProtocolAddress)}"
                };
            }

            // IPv4/IPv6
            var ip = packet.Extract<IPPacket>();
            var srcIpStr = ip is null ? "" : SafeIpToString(ip.SourceAddress);
            var dstIpStr = ip is null ? "" : SafeIpToString(ip.DestinationAddress);

            // TCP
            var tcp = packet.Extract<TcpPacket>();
            if (tcp is not null)
            {
                var flags = TcpFlagsToString(tcp);
                var info = BuildTcpInfo(tcp, srcIpStr, dstIpStr);

                return new PacketInfo
                {
                    Timestamp = timestamp,
                    Length = length,
                    SrcMac = srcMac,
                    DstMac = dstMac,
                    SrcIp = srcIpStr,
                    DstIp = dstIpStr,
                    Protocol = "TCP",
                    SrcPort = tcp.SourcePort,
                    DstPort = tcp.DestinationPort,
                    TcpFlags = flags,
                    Info = info
                };
            }

            // UDP
            var udp = packet.Extract<UdpPacket>();
            if (udp is not null)
            {
                var protoHint = GuessUdpAppProtocol(udp.SourcePort, udp.DestinationPort);
                var info = protoHint is null
                    ? $"UDP {udp.SourcePort} → {udp.DestinationPort} Len={udp.PayloadData?.Length ?? 0}"
                    : $"{protoHint} UDP {udp.SourcePort} → {udp.DestinationPort} Len={udp.PayloadData?.Length ?? 0}";

                return new PacketInfo
                {
                    Timestamp = timestamp,
                    Length = length,
                    SrcMac = srcMac,
                    DstMac = dstMac,
                    SrcIp = srcIpStr,
                    DstIp = dstIpStr,
                    Protocol = "UDP",
                    SrcPort = udp.SourcePort,
                    DstPort = udp.DestinationPort,
                    Info = info
                };
            }

            // ICMPv4 / ICMPv6 (в PacketDotNet це різні типи)
            var icmp4 = packet.Extract<IcmpV4Packet>();
            if (icmp4 is not null)
            {
                return new PacketInfo
                {
                    Timestamp = timestamp,
                    Length = length,
                    SrcMac = srcMac,
                    DstMac = dstMac,
                    SrcIp = srcIpStr,
                    DstIp = dstIpStr,
                    Protocol = "ICMPv4",
                    Info = $"ICMPv4 Type={icmp4.TypeCode} Len={icmp4.PayloadData?.Length ?? 0}"
                };
            }

            var icmp6 = packet.Extract<IcmpV6Packet>();
            if (icmp6 is not null)
            {
                return new PacketInfo
                {
                    Timestamp = timestamp,
                    Length = length,
                    SrcMac = srcMac,
                    DstMac = dstMac,
                    SrcIp = srcIpStr,
                    DstIp = dstIpStr,
                    Protocol = "ICMPv6",
                    Info = $"ICMPv6 Type={icmp6.Type} Code={icmp6.Code} Len={icmp6.PayloadData?.Length ?? 0}"
                };
            }

            // Якщо це не IP/ARP/ICMP/TCP/UDP — повертаємо те, що є
            var proto = ip is null ? (eth is null ? "UNKNOWN" : "ETH") : ip.Protocol.ToString();

            return new PacketInfo
            {
                Timestamp = timestamp,
                Length = length,
                SrcMac = srcMac,
                DstMac = dstMac,
                SrcIp = srcIpStr,
                DstIp = dstIpStr,
                Protocol = proto,
                Info = "Unclassified packet"
            };
        }
        catch (Exception ex)
        {
            return new PacketInfo
            {
                Timestamp = timestamp,
                Length = length,
                Protocol = "ERROR",
                Info = ex.Message
            };
        }
    }

    private static string SafeIpToString(IPAddress? ip) => ip?.ToString() ?? "";

    private static string TcpFlagsToString(TcpPacket tcp)
    {
        var sb = new StringBuilder(32);

        void Add(string s)
        {
            if (sb.Length > 0)
                sb.Append(", ");
            sb.Append(s);
        }

        if (tcp.Synchronize) Add("SYN");
        if (tcp.Acknowledgment) Add("ACK");
        if (tcp.Finished) Add("FIN");
        if (tcp.Reset) Add("RST");
        if (tcp.Push) Add("PSH");
        if (tcp.Urgent) Add("URG");

        return sb.ToString();
    }


    private static string BuildTcpInfo(TcpPacket tcp, string srcIp, string dstIp)
    {
        // Мінімальний “Info”, схожий на Wireshark: напрямок + прапори + seq/ack
        var flags = TcpFlagsToString(tcp);
        var seq = tcp.SequenceNumber;
        var ack = tcp.AcknowledgmentNumber;
        var payloadLen = tcp.PayloadData?.Length ?? 0;

        // Підказка для HTTP (дуже базово)
        var appHint = GuessTcpAppProtocol(tcp.SourcePort, tcp.DestinationPort);

        if (appHint is null)
            return $"{srcIp}:{tcp.SourcePort} → {dstIp}:{tcp.DestinationPort} [{flags}] Seq={seq} Ack={ack} Len={payloadLen}";

        return $"{appHint} {srcIp}:{tcp.SourcePort} → {dstIp}:{tcp.DestinationPort} [{flags}] Len={payloadLen}";
    }

    private static string? GuessTcpAppProtocol(int srcPort, int dstPort)
    {
        // Дуже прості евристики (потім можна зробити краще)
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
}
