using PacketDotNet;
using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Windows.Controls;
using System.Collections.ObjectModel;
using Domain.Models;

namespace Presentation.Helpers
{
    public static class PacketTreeBuilder
    {
        /// <summary>
        /// Будує кореневий TreeViewItem з вкладеними вузлами Ethernet/IP/TCP/UDP…
        /// У Tag кожного вузла кладеться (start,length) для підсвітки в Hex.
        /// </summary>
        public static ProtocolNode Build(Packet packet, PacketInfo row)
        {
            var bytes = row.RawBytes;
            if (bytes == null || bytes.Length == 0)
                return T("No data");

            int frameLen = bytes.Length;

            // Root: whole frame
            var root = T($"Frame: {frameLen} bytes, Time: {row.Timestamp}", (0, frameLen));

            // --- Ethernet (handle optional VLAN) ---
            int ethStart = 0;
            int ethLen = 14;

            if (frameLen >= 14)
            {
                ushort etherType = (ushort)((bytes[12] << 8) | bytes[13]);
                if (etherType == 0x8100 && frameLen >= 18)
                    ethLen = 18;
            }

        

            var eth = packet.Extract<EthernetPacket>();
            if (eth != null && frameLen >= ethLen)
            {
                // Type field position depends on VLAN or not
                ushort type = (ushort)((bytes[ethStart + ethLen - 2] << 8) | bytes[ethStart + ethLen - 1]);

                var ethNode = T(
                    $"Ethernet II, Src: {eth.SourceHardwareAddress}, Dst: {eth.DestinationHardwareAddress}",
                    (ethStart, ethLen));

                // ✅ FIX: children ranges must be ABSOLUTE offsets (ethStart + ...)
                ethNode.Items.Add(T($"Destination MAC: {eth.DestinationHardwareAddress}", (ethStart + 0, 6)));
                ethNode.Items.Add(T($"Source MAC: {eth.SourceHardwareAddress}", (ethStart + 6, 6)));

                if (ethLen == 14)
                {
                    ethNode.Items.Add(T($"Type: 0x{type:X4}", (ethStart + 12, 2)));
                }
                else
                {
                    ethNode.Items.Add(T($"Type: 0x8100 (802.1Q VLAN)", (ethStart + 12, 2)));
                    ethNode.Items.Add(T($"VLAN TCI: 0x{((bytes[ethStart + 14] << 8) | bytes[ethStart + 15]):X4}", (ethStart + 14, 2)));
                    ethNode.Items.Add(T($"Encapsulated Type: 0x{type:X4}", (ethStart + 16, 2)));
                }

                root.Items.Add(ethNode);
            }

            // --- IP start (after Ethernet) ---
            int ipStart = ethLen;
            if (frameLen < ipStart + 1)
            {
                ExpandAll(root);
                return root;
            }

            int ipVersion = (bytes[ipStart] >> 4) & 0xF;

            // ---------------- IPv4 ----------------
            if (ipVersion == 4 && frameLen >= ipStart + 20)
            {
                int ihl = (bytes[ipStart] & 0x0F) * 4;
                if (ihl < 20) ihl = 20;
                if (ipStart + ihl > frameLen) ihl = Math.Max(0, frameLen - ipStart);

                int vihlOff = ipStart + 0;
                int tosOff = ipStart + 1;
                int totLenOff = ipStart + 2;
                int idOff = ipStart + 4;
                int flagsFragOff = ipStart + 6;
                int ttlOff = ipStart + 8;
                int protoOff = ipStart + 9;
                int hdrCsumOff = ipStart + 10;
                int srcOff = ipStart + 12;
                int dstOff = ipStart + 16;

                var ip = packet.Extract<IPPacket>();
                var ipNode = T($"IPv4, Src: {ip?.SourceAddress}, Dst: {ip?.DestinationAddress}", (ipStart, ihl));

                ipNode.Items.Add(T($"Version/IHL: 0x{bytes[vihlOff]:X2}", (vihlOff, 1)));
                ipNode.Items.Add(T($"TOS: 0x{bytes[tosOff]:X2}", (tosOff, 1)));
                ipNode.Items.Add(T($"Total Length: {((bytes[totLenOff] << 8) | bytes[totLenOff + 1])}", (totLenOff, 2)));
                ipNode.Items.Add(T($"Identification: 0x{((bytes[idOff] << 8) | bytes[idOff + 1]):X4}", (idOff, 2)));
                ipNode.Items.Add(T($"Flags/Fragment: 0x{((bytes[flagsFragOff] << 8) | bytes[flagsFragOff + 1]):X4}", (flagsFragOff, 2)));
                ipNode.Items.Add(T($"TTL: {bytes[ttlOff]}", (ttlOff, 1)));
                ipNode.Items.Add(T($"Protocol: {bytes[protoOff]}", (protoOff, 1)));
                ipNode.Items.Add(T($"Header Checksum: 0x{((bytes[hdrCsumOff] << 8) | bytes[hdrCsumOff + 1]):X4}", (hdrCsumOff, 2)));
                ipNode.Items.Add(T($"Source IP: {new IPAddress(bytes.AsSpan(srcOff, 4))}", (srcOff, 4)));
                ipNode.Items.Add(T($"Destination IP: {new IPAddress(bytes.AsSpan(dstOff, 4))}", (dstOff, 4)));

                root.Items.Add(ipNode);

                int l4Start = ipStart + ihl;
                if (frameLen < l4Start) { ExpandAll(root); return root; }

                // ---- TCP ----
                var tcp = packet.Extract<TcpPacket>();
                if (tcp != null && frameLen >= l4Start + 20)
                {
                    int tcpHdrLen = ((bytes[l4Start + 12] >> 4) & 0xF) * 4;
                    if (tcpHdrLen < 20) tcpHdrLen = 20;
                    if (l4Start + tcpHdrLen > frameLen) tcpHdrLen = Math.Max(0, frameLen - l4Start);

                    int srcPortOff = l4Start + 0;
                    int dstPortOff = l4Start + 2;
                    int seqOff = l4Start + 4;
                    int ackOff = l4Start + 8;
                    int dataOffFlagsOff = l4Start + 12;
                    int winOff = l4Start + 14;
                    int csumOff = l4Start + 16;
                    int urgOff = l4Start + 18;

                    int payloadStart = l4Start + tcpHdrLen;
                    int payloadLen = Math.Max(0, frameLen - payloadStart);

                    var tcpNode = T($"TCP, Src Port: {tcp.SourcePort}, Dst Port: {tcp.DestinationPort}, Flags: {tcp.Flags}",
                        (l4Start, tcpHdrLen));

                    tcpNode.Items.Add(T($"Source Port: {tcp.SourcePort}", (srcPortOff, 2)));
                    tcpNode.Items.Add(T($"Destination Port: {tcp.DestinationPort}", (dstPortOff, 2)));
                    tcpNode.Items.Add(T($"Sequence Number: {tcp.SequenceNumber}", (seqOff, 4)));
                    tcpNode.Items.Add(T($"Acknowledgment Number: {tcp.AcknowledgmentNumber}", (ackOff, 4)));
                    tcpNode.Items.Add(T($"DataOffset/Flags: 0x{((bytes[dataOffFlagsOff] << 8) | bytes[dataOffFlagsOff + 1]):X4}", (dataOffFlagsOff, 2)));
                    tcpNode.Items.Add(T($"Window Size: {tcp.WindowSize}", (winOff, 2)));
                    tcpNode.Items.Add(T($"Checksum: 0x{tcp.Checksum:X4}", (csumOff, 2)));
                    tcpNode.Items.Add(T($"Urgent Pointer: {tcp.UrgentPointer}", (urgOff, 2)));

                    tcpNode.Items.Add(T($"Payload: {tcp.PayloadData?.Length ?? 0} bytes",
                        (payloadStart, Math.Min(payloadLen, tcp.PayloadData?.Length ?? 0))));

                    ipNode.Items.Add(tcpNode);
                    ExpandAll(root);
                    return root;
                }

                // ---- UDP ----
                var udp = packet.Extract<UdpPacket>();
                if (udp != null && frameLen >= l4Start + 8)
                {
                    int srcPortOff = l4Start + 0;
                    int dstPortOff = l4Start + 2;
                    int lenOff = l4Start + 4;
                    int csumOff = l4Start + 6;

                    int payloadStart = l4Start + 8;
                    int payloadLen = Math.Max(0, frameLen - payloadStart);

                    var udpNode = T($"UDP, Src Port: {udp.SourcePort}, Dst Port: {udp.DestinationPort}", (l4Start, 8));
                    udpNode.Items.Add(T($"Source Port: {udp.SourcePort}", (srcPortOff, 2)));
                    udpNode.Items.Add(T($"Destination Port: {udp.DestinationPort}", (dstPortOff, 2)));
                    udpNode.Items.Add(T($"Length: {((bytes[lenOff] << 8) | bytes[lenOff + 1])}", (lenOff, 2)));
                    udpNode.Items.Add(T($"Checksum: 0x{udp.Checksum:X4}", (csumOff, 2)));
                    udpNode.Items.Add(T($"Payload: {udp.PayloadData?.Length ?? 0} bytes",
                        (payloadStart, Math.Min(payloadLen, udp.PayloadData?.Length ?? 0))));

                    ipNode.Items.Add(udpNode);
                    ExpandAll(root);
                    return root;
                }

                ExpandAll(root);
                return root;
            }

            // ---------------- IPv6 ----------------
            if (ipVersion == 6 && frameLen >= ipStart + 40)
            {
                int ipv6Len = 40;

                int verTcFlOff = ipStart + 0;
                int payloadLenOff = ipStart + 4;
                int nextHdrOff = ipStart + 6;
                int hopLimitOff = ipStart + 7;
                int srcOff = ipStart + 8;
                int dstOff = ipStart + 24;

                var ip = packet.Extract<IPPacket>();
                var ipNode = T($"IPv6, Src: {ip?.SourceAddress}, Dst: {ip?.DestinationAddress}", (ipStart, ipv6Len));

                ipNode.Items.Add(T($"Version/TC/Flow: 0x{bytes[verTcFlOff]:X2}{bytes[verTcFlOff + 1]:X2}{bytes[verTcFlOff + 2]:X2}{bytes[verTcFlOff + 3]:X2}", (verTcFlOff, 4)));
                ipNode.Items.Add(T($"Payload Length: {((bytes[payloadLenOff] << 8) | bytes[payloadLenOff + 1])}", (payloadLenOff, 2)));
                ipNode.Items.Add(T($"Next Header: {bytes[nextHdrOff]}", (nextHdrOff, 1)));
                ipNode.Items.Add(T($"Hop Limit: {bytes[hopLimitOff]}", (hopLimitOff, 1)));
                ipNode.Items.Add(T($"Source IP: {new IPAddress(bytes.AsSpan(srcOff, 16))}", (srcOff, 16)));
                ipNode.Items.Add(T($"Destination IP: {new IPAddress(bytes.AsSpan(dstOff, 16))}", (dstOff, 16)));

                root.Items.Add(ipNode);

                int l4Start = ipStart + ipv6Len;

                var tcp = packet.Extract<TcpPacket>();
                if (tcp != null && frameLen >= l4Start + 20)
                {
                    int tcpHdrLen = ((bytes[l4Start + 12] >> 4) & 0xF) * 4;
                    if (tcpHdrLen < 20) tcpHdrLen = 20;
                    if (l4Start + tcpHdrLen > frameLen) tcpHdrLen = Math.Max(0, frameLen - l4Start);

                    int srcPortOff = l4Start + 0;
                    int dstPortOff = l4Start + 2;
                    int seqOff = l4Start + 4;
                    int ackOff = l4Start + 8;
                    int dataOffFlagsOff = l4Start + 12;
                    int winOff = l4Start + 14;
                    int csumOff = l4Start + 16;
                    int urgOff = l4Start + 18;

                    int payloadStart = l4Start + tcpHdrLen;
                    int payloadLen = Math.Max(0, frameLen - payloadStart);

                    var tcpNode = T($"TCP, Src Port: {tcp.SourcePort}, Dst Port: {tcp.DestinationPort}, Flags: {tcp.Flags}",
                        (l4Start, tcpHdrLen));

                    tcpNode.Items.Add(T($"Source Port: {tcp.SourcePort}", (srcPortOff, 2)));
                    tcpNode.Items.Add(T($"Destination Port: {tcp.DestinationPort}", (dstPortOff, 2)));
                    tcpNode.Items.Add(T($"Sequence Number: {tcp.SequenceNumber}", (seqOff, 4)));
                    tcpNode.Items.Add(T($"Acknowledgment Number: {tcp.AcknowledgmentNumber}", (ackOff, 4)));
                    tcpNode.Items.Add(T($"DataOffset/Flags: 0x{((bytes[dataOffFlagsOff] << 8) | bytes[dataOffFlagsOff + 1]):X4}", (dataOffFlagsOff, 2)));
                    tcpNode.Items.Add(T($"Window Size: {tcp.WindowSize}", (winOff, 2)));
                    tcpNode.Items.Add(T($"Checksum: 0x{tcp.Checksum:X4}", (csumOff, 2)));
                    tcpNode.Items.Add(T($"Urgent Pointer: {tcp.UrgentPointer}", (urgOff, 2)));

                    tcpNode.Items.Add(T($"Payload: {tcp.PayloadData?.Length ?? 0} bytes",
                        (payloadStart, Math.Min(payloadLen, tcp.PayloadData?.Length ?? 0))));

                    ipNode.Items.Add(tcpNode);
                    ExpandAll(root);
                    return root;
                }

                var udp = packet.Extract<UdpPacket>();
                if (udp != null && frameLen >= l4Start + 8)
                {
                    int srcPortOff = l4Start + 0;
                    int dstPortOff = l4Start + 2;
                    int lenOff = l4Start + 4;
                    int csumOff = l4Start + 6;

                    int payloadStart = l4Start + 8;
                    int payloadLen = Math.Max(0, frameLen - payloadStart);

                    var udpNode = T($"UDP, Src Port: {udp.SourcePort}, Dst Port: {udp.DestinationPort}", (l4Start, 8));
                    udpNode.Items.Add(T($"Source Port: {udp.SourcePort}", (srcPortOff, 2)));
                    udpNode.Items.Add(T($"Destination Port: {udp.DestinationPort}", (dstPortOff, 2)));
                    udpNode.Items.Add(T($"Length: {((bytes[lenOff] << 8) | bytes[lenOff + 1])}", (lenOff, 2)));
                    udpNode.Items.Add(T($"Checksum: 0x{udp.Checksum:X4}", (csumOff, 2)));
                    udpNode.Items.Add(T($"Payload: {udp.PayloadData?.Length ?? 0} bytes",
                        (payloadStart, Math.Min(payloadLen, udp.PayloadData?.Length ?? 0))));

                    ipNode.Items.Add(udpNode);
                    ExpandAll(root);
                    return root;
                }

                ExpandAll(root);
                return root;
            }

            root.Items.Add(T("Unknown / unsupported packet (no IPv4/IPv6 parsed)"));
            ExpandAll(root);
            return root;
        }

        private static ProtocolNode T(string header, (int start, int length)? range = null)
        {
            var item = new ProtocolNode { Header = header };
            if (range.HasValue)
                item.Range = (range.Value.start, range.Value.length);
            return item;
        }

        private static void ExpandAll(ProtocolNode node)
        {
            if (node == null) return;
            node.IsExpanded = true;
            foreach (var child in node.Items)
                ExpandAll(child);
        }

    }

    // Simple POCO used as data model for the TreeView in XAML.
    public class ProtocolNode
    {
        public string Header { get; set; } = string.Empty;
        public (int start, int length)? Range { get; set; }
        public ObservableCollection<ProtocolNode> Items { get; } = new();
        public bool IsExpanded { get; set; }
        public object Tag => Range.HasValue ? (Range.Value.start, Range.Value.length) : null;
    }
}
