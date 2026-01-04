// Відповідає за реальний парсинг пакетів через PacketDotNet (Ethernet/IP/TCP/UDP/ICMP/ARP)
// та формування PacketInfo для UI (включаючи RawBytes і LinkLayerType для деталей).
using Application.Abstractions;
using Domain.Models;
using PacketDotNet;
using SharpPcap;
using System.Net;

namespace Infrastructure.Parsing;

public sealed class PacketDotNetParser : IPacketParser
{
    public PacketInfo Parse(DateTime timestamp, int length, object rawCapture)
    {
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

        // Відповідає за збереження типу LinkLayer для коректного повторного парсингу в UI.
        int linkLayerType = (int)raw.LinkLayerType;

        // Відповідає за безпечне копіювання байтів пакета для деталей/hex/дерева.
        // (Не використовуємо raw.Data напряму, щоб уникнути проблем з життєвим циклом буфера)
        byte[] bytesCopy = raw.Data.ToArray();

        // Локальна фабрика: щоб не дублювати RawBytes/LinkLayer у кожному return
        PacketInfo Make(
            string protocol,
            string srcMac = "",
            string dstMac = "",
            string srcIp = "",
            string dstIp = "",
            int? srcPort = null,
            int? dstPort = null,
            string tcpFlags = "",
            string info = "")
        {
            return new PacketInfo
            {
                Timestamp = timestamp,
                Length = length,

                SrcMac = srcMac,
                DstMac = dstMac,
                SrcIp = srcIp,
                DstIp = dstIp,

                Protocol = protocol,
                SrcPort = srcPort,
                DstPort = dstPort,

                TcpFlags = tcpFlags,
                Info = info,

                RawBytes = bytesCopy,
                LinkLayer = raw.LinkLayerType.ToString(),
                LinkLayerType = linkLayerType
            };
        }

        try
        {
            var packet = Packet.ParsePacket(raw.LinkLayerType, bytesCopy);

            var eth = packet.Extract<EthernetPacket>();
            var srcMacStr = eth?.SourceHardwareAddress?.ToString() ?? "";
            var dstMacStr = eth?.DestinationHardwareAddress?.ToString() ?? "";

            // ARP
            var arp = packet.Extract<ArpPacket>();
            if (arp is not null)
            {
                return Make(
                    protocol: "ARP",
                    srcMac: srcMacStr,
                    dstMac: dstMacStr,
                    srcIp: SafeIpToString(arp.SenderProtocolAddress),
                    dstIp: SafeIpToString(arp.TargetProtocolAddress),
                    info: $"{arp.Operation} {SafeIpToString(arp.SenderProtocolAddress)} → {SafeIpToString(arp.TargetProtocolAddress)}"
                );
            }

            // IP (v4/v6)
            var ip = packet.Extract<IPPacket>();
            var srcIpStr = ip is null ? "" : SafeIpToString(ip.SourceAddress);
            var dstIpStr = ip is null ? "" : SafeIpToString(ip.DestinationAddress);

            // TCP
            var tcp = packet.Extract<TcpPacket>();
            if (tcp is not null)
            {
                var flags = TcpFlagsToString(tcp);
                var info = BuildTcpInfo(tcp, srcIpStr, dstIpStr);

                return Make(
                    protocol: "TCP",
                    srcMac: srcMacStr,
                    dstMac: dstMacStr,
                    srcIp: srcIpStr,
                    dstIp: dstIpStr,
                    srcPort: tcp.SourcePort,
                    dstPort: tcp.DestinationPort,
                    tcpFlags: flags,
                    info: info
                );
            }

            // UDP
            var udp = packet.Extract<UdpPacket>();
            if (udp is not null)
            {
                var protoHint = GuessUdpAppProtocol(udp.SourcePort, udp.DestinationPort);
                var info = protoHint is null
                    ? $"UDP {udp.SourcePort} → {udp.DestinationPort} Len={udp.PayloadData?.Length ?? 0}"
                    : $"{protoHint} UDP {udp.SourcePort} → {udp.DestinationPort} Len={udp.PayloadData?.Length ?? 0}";

                return Make(
                    protocol: "UDP",
                    srcMac: srcMacStr,
                    dstMac: dstMacStr,
                    srcIp: srcIpStr,
                    dstIp: dstIpStr,
                    srcPort: udp.SourcePort,
                    dstPort: udp.DestinationPort,
                    info: info
                );
            }

            // ICMPv4
            var icmp4 = packet.Extract<IcmpV4Packet>();
            if (icmp4 is not null)
            {
                return Make(
                    protocol: "ICMPv4",
                    srcMac: srcMacStr,
                    dstMac: dstMacStr,
                    srcIp: srcIpStr,
                    dstIp: dstIpStr,
                    info: $"ICMPv4 Type={icmp4.TypeCode} Len={icmp4.PayloadData?.Length ?? 0}"
                );
            }

            // ICMPv6
            var icmp6 = packet.Extract<IcmpV6Packet>();
            if (icmp6 is not null)
            {
                return Make(
                    protocol: "ICMPv6",
                    srcMac: srcMacStr,
                    dstMac: dstMacStr,
                    srcIp: srcIpStr,
                    dstIp: dstIpStr,
                    info: $"ICMPv6 Type={icmp6.Type} Code={icmp6.Code} Len={icmp6.PayloadData?.Length ?? 0}"
                );
            }

            // Інше/невідоме
            var proto = ip is null ? (eth is null ? "UNKNOWN" : "ETH") : ip.Protocol.ToString();
            return Make(
                protocol: proto,
                srcMac: srcMacStr,
                dstMac: dstMacStr,
                srcIp: srcIpStr,
                dstIp: dstIpStr,
                info: "Unclassified packet"
            );
        }
        catch (Exception ex)
        {
            return Make(protocol: "ERROR", info: ex.Message);
        }
    }

    private static string SafeIpToString(IPAddress? ip) => ip?.ToString() ?? "";

    // Відповідає за перетворення TCP flags у компактний рядок ("SYN, ACK, FIN")
    private static string TcpFlagsToString(TcpPacket tcp)
    {
        var flags = new List<string>(6);

        if (tcp.Synchronize) flags.Add("SYN");
        if (tcp.Acknowledgment) flags.Add("ACK");
        if (tcp.Finished) flags.Add("FIN");
        if (tcp.Reset) flags.Add("RST");
        if (tcp.Push) flags.Add("PSH");
        if (tcp.Urgent) flags.Add("URG");

        return flags.Count == 0 ? "" : string.Join(", ", flags);
    }

    private static string BuildTcpInfo(TcpPacket tcp, string srcIp, string dstIp)
    {
        var flags = TcpFlagsToString(tcp);
        var payloadLen = tcp.PayloadData?.Length ?? 0;

        var appHint = GuessTcpAppProtocol(tcp.SourcePort, tcp.DestinationPort);

        if (appHint is null)
            return $"{srcIp}:{tcp.SourcePort} → {dstIp}:{tcp.DestinationPort} [{flags}] Len={payloadLen}";

        return $"{appHint} {srcIp}:{tcp.SourcePort} → {dstIp}:{tcp.DestinationPort} [{flags}] Len={payloadLen}";
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
}
