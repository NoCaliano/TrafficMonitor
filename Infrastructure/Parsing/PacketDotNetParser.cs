// Відповідає за швидкий (allocation-light) парсинг пакетів для таблиці.
// Live path уникає дорогого DNS/TLS/QUIC enrichment; повний inspection лишається для offline parse.
using Application.Abstractions;
using Domain.Models;
using Infrastructure.Networking;
using PacketDotNet;
using SharpPcap;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Infrastructure.Parsing;

public sealed class PacketDotNetParser : IPacketParser
{
    private readonly ProcessMapperService _processMapperService;

    public PacketDotNetParser(ProcessMapperService processMapperService)
    {
        _processMapperService = processMapperService;
    }

    public PacketInfo Parse(DateTime timestamp, int length, object rawCapture, PacketParseProfile profile = PacketParseProfile.Live)
    {
        bool enableDeepInspection = profile == PacketParseProfile.Full;

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
            string info = "",
            string dnsQueryName = "",
            IReadOnlyList<string>? dnsAnswerIps = null,
            string serverNameHint = "",
            string tlsClientFingerprintKind = "",
            string tlsClientFingerprint = "",
            string tlsHandshakeType = "",
            string tlsCertificateFingerprint = "",
            IReadOnlyList<string>? tlsCertificateNames = null,
            string tlsCertificateSubject = "")
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
                DnsQueryName = dnsQueryName,
                DnsAnswerIps = dnsAnswerIps ?? Array.Empty<string>(),
                ServerNameHint = serverNameHint,
                TlsClientFingerprintKind = tlsClientFingerprintKind,
                TlsClientFingerprint = tlsClientFingerprint,
                TlsHandshakeType = tlsHandshakeType,
                TlsCertificateFingerprint = tlsCertificateFingerprint,
                TlsCertificateNames = tlsCertificateNames ?? Array.Empty<string>(),
                TlsCertificateSubject = tlsCertificateSubject,

                Pid = pid,
                ProcessName = processName,

                RawBytesId = rawId,
                LinkLayer = linkLayer.ToString(),
                LinkLayerType = linkLayerType
            };
        }

        void PopulateTcpDeepInspection(
            string detectedProtocol,
            ReadOnlySpan<byte> payload,
            out string dnsQueryName,
            out IReadOnlyList<string> dnsAnswerIps,
            out string serverNameHint,
            out string tlsClientFingerprintKind,
            out string tlsClientFingerprint,
            out string tlsHandshakeType,
            out string tlsCertificateFingerprint,
            out IReadOnlyList<string> tlsCertificateNames,
            out string tlsCertificateSubject)
        {
            dnsQueryName = string.Empty;
            dnsAnswerIps = Array.Empty<string>();
            serverNameHint = string.Empty;
            tlsClientFingerprintKind = string.Empty;
            tlsClientFingerprint = string.Empty;
            tlsHandshakeType = string.Empty;
            tlsCertificateFingerprint = string.Empty;
            tlsCertificateNames = Array.Empty<string>();
            tlsCertificateSubject = string.Empty;

            if (string.Equals(detectedProtocol, "DNS", StringComparison.OrdinalIgnoreCase))
            {
                if (enableDeepInspection)
                    TryExtractDnsResolution(payload, tcpLengthPrefixed: true, out dnsQueryName, out dnsAnswerIps);

                return;
            }

            if (!LooksLikeTlsProtocol(detectedProtocol))
                return;

            if (TryExtractTlsClientHelloIntelligence(payload, out var tlsServerName, out var ja3Lite))
            {
                serverNameHint = tlsServerName;
                tlsClientFingerprintKind = "JA3-lite";
                tlsClientFingerprint = ja3Lite;
                tlsHandshakeType = "ClientHello";
            }
            else
            {
                TryGetTlsHandshakeTypeFromRecord(payload, out tlsHandshakeType);
            }

            if (TryExtractTlsServerCertificateIntelligence(payload, out var certificateFingerprint, out var certificateNames, out var certificateSubject))
            {
                tlsCertificateFingerprint = certificateFingerprint;
                tlsCertificateNames = certificateNames;
                tlsCertificateSubject = certificateSubject;

                if (string.IsNullOrWhiteSpace(tlsHandshakeType))
                    tlsHandshakeType = "Certificate";
            }
        }

        void PopulateUdpDeepInspection(
            string detectedProtocol,
            ReadOnlySpan<byte> payload,
            out string dnsQueryName,
            out IReadOnlyList<string> dnsAnswerIps,
            out string serverNameHint,
            out string tlsClientFingerprintKind,
            out string tlsClientFingerprint,
            out string tlsHandshakeType,
            out string tlsCertificateFingerprint,
            out IReadOnlyList<string> tlsCertificateNames,
            out string tlsCertificateSubject)
        {
            dnsQueryName = string.Empty;
            dnsAnswerIps = Array.Empty<string>();
            serverNameHint = string.Empty;
            tlsClientFingerprintKind = string.Empty;
            tlsClientFingerprint = string.Empty;
            tlsHandshakeType = string.Empty;
            tlsCertificateFingerprint = string.Empty;
            tlsCertificateNames = Array.Empty<string>();
            tlsCertificateSubject = string.Empty;

            if (string.Equals(detectedProtocol, "DNS", StringComparison.OrdinalIgnoreCase))
            {
                if (enableDeepInspection)
                    TryExtractDnsResolution(payload, tcpLengthPrefixed: false, out dnsQueryName, out dnsAnswerIps);

                return;
            }

            if (!string.Equals(detectedProtocol, "QUIC", StringComparison.OrdinalIgnoreCase))
                return;

            if (TryExtractQuicClientHelloIntelligence(payload, out var quicServerName, out var ja4Lite))
            {
                serverNameHint = quicServerName;
                tlsClientFingerprintKind = "JA4-lite";
                tlsClientFingerprint = ja4Lite;
                tlsHandshakeType = "ClientHello";
            }
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
                PopulateTcpDeepInspection(
                    detectedProtocol,
                    tcpPayload,
                    out var dnsQueryName,
                    out var dnsAnswerIps,
                    out var serverNameHint,
                    out var tlsClientFingerprintKind,
                    out var tlsClientFingerprint,
                    out var tlsHandshakeType,
                    out var tlsCertificateFingerprint,
                    out var tlsCertificateNames,
                    out var tlsCertificateSubject);

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
                    info: info,
                    dnsQueryName: dnsQueryName,
                    dnsAnswerIps: dnsAnswerIps,
                    serverNameHint: serverNameHint,
                    tlsClientFingerprintKind: tlsClientFingerprintKind,
                    tlsClientFingerprint: tlsClientFingerprint,
                    tlsHandshakeType: tlsHandshakeType,
                    tlsCertificateFingerprint: tlsCertificateFingerprint,
                    tlsCertificateNames: tlsCertificateNames,
                    tlsCertificateSubject: tlsCertificateSubject
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
                PopulateUdpDeepInspection(
                    detectedProtocol,
                    udpPayload,
                    out var dnsQueryName,
                    out var dnsAnswerIps,
                    out var serverNameHint,
                    out var tlsClientFingerprintKind,
                    out var tlsClientFingerprint,
                    out var tlsHandshakeType,
                    out var tlsCertificateFingerprint,
                    out var tlsCertificateNames,
                    out var tlsCertificateSubject);
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
                    info: info,
                    dnsQueryName: dnsQueryName,
                    dnsAnswerIps: dnsAnswerIps,
                    serverNameHint: serverNameHint,
                    tlsClientFingerprintKind: tlsClientFingerprintKind,
                    tlsClientFingerprint: tlsClientFingerprint,
                    tlsHandshakeType: tlsHandshakeType,
                    tlsCertificateFingerprint: tlsCertificateFingerprint,
                    tlsCertificateNames: tlsCertificateNames,
                    tlsCertificateSubject: tlsCertificateSubject
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
                PopulateTcpDeepInspection(
                    detectedProtocol,
                    tcpPayload,
                    out var dnsQueryName,
                    out var dnsAnswerIps,
                    out var serverNameHint,
                    out var tlsClientFingerprintKind,
                    out var tlsClientFingerprint,
                    out var tlsHandshakeType,
                    out var tlsCertificateFingerprint,
                    out var tlsCertificateNames,
                    out var tlsCertificateSubject);

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
                    info: info,
                    dnsQueryName: dnsQueryName,
                    dnsAnswerIps: dnsAnswerIps,
                    serverNameHint: serverNameHint,
                    tlsClientFingerprintKind: tlsClientFingerprintKind,
                    tlsClientFingerprint: tlsClientFingerprint,
                    tlsHandshakeType: tlsHandshakeType,
                    tlsCertificateFingerprint: tlsCertificateFingerprint,
                    tlsCertificateNames: tlsCertificateNames,
                    tlsCertificateSubject: tlsCertificateSubject
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
                PopulateUdpDeepInspection(
                    detectedProtocol,
                    udpPayload,
                    out var dnsQueryName,
                    out var dnsAnswerIps,
                    out var serverNameHint,
                    out var tlsClientFingerprintKind,
                    out var tlsClientFingerprint,
                    out var tlsHandshakeType,
                    out var tlsCertificateFingerprint,
                    out var tlsCertificateNames,
                    out var tlsCertificateSubject);
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
                    info: info,
                    dnsQueryName: dnsQueryName,
                    dnsAnswerIps: dnsAnswerIps,
                    serverNameHint: serverNameHint,
                    tlsClientFingerprintKind: tlsClientFingerprintKind,
                    tlsClientFingerprint: tlsClientFingerprint,
                    tlsHandshakeType: tlsHandshakeType,
                    tlsCertificateFingerprint: tlsCertificateFingerprint,
                    tlsCertificateNames: tlsCertificateNames,
                    tlsCertificateSubject: tlsCertificateSubject
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

    private static readonly byte[] QuicV1InitialSalt = Convert.FromHexString("38762CF7F55934B34D179AE6A4C80CADCCBB7F0A");
    private static readonly byte[] QuicV2InitialSalt = Convert.FromHexString("0DEDE3DEF700A6DB819381BE6E269DCBF9BD2ED9");

    private static bool LooksLikeTlsProtocol(string protocol)
        => !string.IsNullOrWhiteSpace(protocol)
            && (protocol.StartsWith("TLS", StringComparison.OrdinalIgnoreCase)
                || protocol.Equals("SSL", StringComparison.OrdinalIgnoreCase));

    private static bool TryExtractTlsClientHelloIntelligence(ReadOnlySpan<byte> payload, out string serverName, out string fingerprint)
    {
        serverName = string.Empty;
        fingerprint = string.Empty;

        if (!TryGetTlsClientHelloBodyFromRecord(payload, out var handshakeBody))
            return false;

        TryGetTlsClientHelloServerName(handshakeBody, out serverName);
        TryBuildTlsJa3LiteFingerprint(handshakeBody, out fingerprint);
        return !string.IsNullOrWhiteSpace(serverName) || !string.IsNullOrWhiteSpace(fingerprint);
    }

    private static bool TryExtractQuicClientHelloIntelligence(ReadOnlySpan<byte> payload, out string serverName, out string fingerprint)
    {
        serverName = string.Empty;
        fingerprint = string.Empty;

        if (!TryDecryptQuicInitialCryptoStream(payload, out var cryptoStream))
            return false;

        if (!TryGetTlsClientHelloBodyFromCryptoStream(cryptoStream, out var handshakeBody))
            return false;

        TryGetTlsClientHelloServerName(handshakeBody, out serverName);
        TryBuildQuicJa4LiteFingerprint(handshakeBody, out fingerprint);
        return !string.IsNullOrWhiteSpace(serverName) || !string.IsNullOrWhiteSpace(fingerprint);
    }

    private static bool TryGetTlsHandshakeTypeFromRecord(ReadOnlySpan<byte> payload, out string handshakeType)
    {
        handshakeType = string.Empty;

        if (!TryGetTlsHandshakeBodyFromRecord(payload, out var type, out _))
            return false;

        handshakeType = GetTlsHandshakeName(type);
        return !string.IsNullOrWhiteSpace(handshakeType);
    }

    private static bool TryExtractTlsServerName(ReadOnlySpan<byte> payload, out string serverName)
    {
        serverName = string.Empty;

        if (!TryGetTlsClientHelloBodyFromRecord(payload, out var handshakeBody))
            return false;

        return TryGetTlsClientHelloServerName(handshakeBody, out serverName);
    }

    private static bool TryGetTlsClientHelloBodyFromRecord(ReadOnlySpan<byte> payload, out ReadOnlySpan<byte> handshakeBody)
    {
        return TryGetTlsHandshakeBodyFromRecord(payload, desiredHandshakeType: 1, out handshakeBody);
    }

    private static bool TryGetTlsHandshakeBodyFromRecord(ReadOnlySpan<byte> payload, byte desiredHandshakeType, out ReadOnlySpan<byte> handshakeBody)
    {
        handshakeBody = ReadOnlySpan<byte>.Empty;
        if (payload.Length < 9)
            return false;

        byte contentType = payload[0];
        if (contentType != 22)
            return false;

        ushort recordVersion = ReadU16BE(payload, 1);
        if ((recordVersion >> 8) != 3)
            return false;

        ushort recordLength = ReadU16BE(payload, 3);
        if (recordLength == 0)
            return false;

        var recordBody = payload.Slice(5, Math.Min(recordLength, payload.Length - 5));
        int offset = 0;
        while (offset + 4 <= recordBody.Length)
        {
            byte handshakeType = recordBody[offset];
            int handshakeLength = (recordBody[offset + 1] << 16) | (recordBody[offset + 2] << 8) | recordBody[offset + 3];
            offset += 4;
            if (handshakeLength <= 0 || offset + handshakeLength > recordBody.Length)
                return false;

            if (handshakeType == desiredHandshakeType)
            {
                handshakeBody = recordBody.Slice(offset, handshakeLength);
                return true;
            }

            offset += handshakeLength;
        }

        return false;
    }

    private static bool TryGetTlsHandshakeBodyFromRecord(ReadOnlySpan<byte> payload, out byte handshakeType, out ReadOnlySpan<byte> handshakeBody)
    {
        handshakeType = 0;
        handshakeBody = ReadOnlySpan<byte>.Empty;

        if (payload.Length < 9)
            return false;

        byte contentType = payload[0];
        if (contentType != 22)
            return false;

        ushort recordVersion = ReadU16BE(payload, 1);
        if ((recordVersion >> 8) != 3)
            return false;

        ushort recordLength = ReadU16BE(payload, 3);
        if (recordLength == 0)
            return false;

        var recordBody = payload.Slice(5, Math.Min(recordLength, payload.Length - 5));
        if (recordBody.Length < 4)
            return false;

        handshakeType = recordBody[0];
        int handshakeLength = (recordBody[1] << 16) | (recordBody[2] << 8) | recordBody[3];
        if (handshakeLength <= 0 || 4 + handshakeLength > recordBody.Length)
            return false;

        handshakeBody = recordBody.Slice(4, handshakeLength);
        return true;
    }

    private static bool TryExtractTlsServerCertificateIntelligence(
        ReadOnlySpan<byte> payload,
        out string fingerprint,
        out IReadOnlyList<string> certificateNames,
        out string certificateSubject)
    {
        fingerprint = string.Empty;
        certificateNames = Array.Empty<string>();
        certificateSubject = string.Empty;

        if (!TryGetTlsHandshakeBodyFromRecord(payload, desiredHandshakeType: 11, out var handshakeBody))
            return false;

        if (!TryReadTlsLeafCertificate(handshakeBody, out var certificateBytes))
            return false;

        try
        {
            using var certificate = X509CertificateLoader.LoadCertificate(certificateBytes.ToArray());
            fingerprint = Convert.ToHexString(SHA256.HashData(certificate.RawData)).ToLowerInvariant();
            certificateSubject = certificate.SubjectName.Name
                ?? certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false)
                ?? string.Empty;
            certificateNames = ExtractCertificateNames(certificate);
            return !string.IsNullOrWhiteSpace(fingerprint);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static bool TryReadTlsLeafCertificate(ReadOnlySpan<byte> handshakeBody, out ReadOnlySpan<byte> certificateBytes)
    {
        certificateBytes = ReadOnlySpan<byte>.Empty;
        if (handshakeBody.Length < 6)
            return false;

        int tls13Offset = 1 + handshakeBody[0];
        if (tls13Offset >= 4 && TryReadTlsCertificateEntry(handshakeBody, offset: tls13Offset, tls13: true, out certificateBytes))
            return true;

        return TryReadTlsCertificateEntry(handshakeBody, offset: 0, tls13: false, out certificateBytes);
    }

    private static bool TryReadTlsCertificateEntry(ReadOnlySpan<byte> handshakeBody, int offset, bool tls13, out ReadOnlySpan<byte> certificateBytes)
    {
        certificateBytes = ReadOnlySpan<byte>.Empty;
        if (offset < 0 || offset + 3 > handshakeBody.Length)
            return false;

        int certificateListLength = (handshakeBody[offset] << 16) | (handshakeBody[offset + 1] << 8) | handshakeBody[offset + 2];
        offset += 3;
        if (certificateListLength <= 0 || offset + certificateListLength > handshakeBody.Length || offset + 3 > handshakeBody.Length)
            return false;

        int certificateLength = (handshakeBody[offset] << 16) | (handshakeBody[offset + 1] << 8) | handshakeBody[offset + 2];
        offset += 3;
        if (certificateLength <= 0 || offset + certificateLength > handshakeBody.Length)
            return false;

        certificateBytes = handshakeBody.Slice(offset, certificateLength);
        if (!tls13)
            return true;

        int afterCertificate = offset + certificateLength;
        if (afterCertificate + 2 > handshakeBody.Length)
            return false;

        int extensionsLength = ReadU16BE(handshakeBody, afterCertificate);
        return afterCertificate + 2 + extensionsLength <= handshakeBody.Length;
    }

    private static IReadOnlyList<string> ExtractCertificateNames(X509Certificate2 certificate)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var extension in certificate.Extensions)
        {
            if (!string.Equals(extension.Oid?.Value, "2.5.29.17", StringComparison.Ordinal))
                continue;

            TryExtractDnsNamesFromSubjectAlternativeName(extension.RawData, names);
        }

        string preferredDnsName = certificate.GetNameInfo(X509NameType.DnsName, forIssuer: false) ?? string.Empty;
        string alternativeDnsName = certificate.GetNameInfo(X509NameType.DnsFromAlternativeName, forIssuer: false) ?? string.Empty;
        string simpleName = certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false) ?? string.Empty;

        TryAddCertificateName(names, preferredDnsName);
        TryAddCertificateName(names, alternativeDnsName);
        TryAddCertificateName(names, simpleName);

        return names
            .OrderBy(static value => value, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static void TryExtractDnsNamesFromSubjectAlternativeName(ReadOnlySpan<byte> rawData, HashSet<string> names)
    {
        if (rawData.Length < 2 || rawData[0] != 0x30)
            return;

        int offset = 1;
        if (!TryReadAsnLength(rawData, ref offset, out var sequenceLength))
            return;

        int end = Math.Min(rawData.Length, offset + sequenceLength);
        while (offset < end)
        {
            byte tag = rawData[offset++];
            if (!TryReadAsnLength(rawData, ref offset, out var valueLength))
                return;

            if (offset + valueLength > end)
                return;

            if (tag == 0x82)
            {
                string candidate = Encoding.ASCII.GetString(rawData.Slice(offset, valueLength));
                TryAddCertificateName(names, candidate);
            }

            offset += valueLength;
        }
    }

    private static void TryAddCertificateName(HashSet<string> names, string? candidate)
    {
        string normalized = NormalizeCertificateName(candidate);
        if (!string.IsNullOrWhiteSpace(normalized))
            names.Add(normalized);
    }

    private static bool TryReadAsnLength(ReadOnlySpan<byte> data, ref int offset, out int length)
    {
        length = 0;
        if (offset >= data.Length)
            return false;

        byte first = data[offset++];
        if ((first & 0x80) == 0)
        {
            length = first;
            return true;
        }

        int byteCount = first & 0x7F;
        if (byteCount <= 0 || byteCount > 4 || offset + byteCount > data.Length)
            return false;

        for (int i = 0; i < byteCount; i++)
            length = (length << 8) | data[offset++];

        return true;
    }

    private static bool TryBuildTlsJa3LiteFingerprint(ReadOnlySpan<byte> body, out string fingerprint)
    {
        fingerprint = string.Empty;
        if (!TryReadTlsClientHelloShape(body, out var version, out var cipherSuites, out var extensionTypes, out var supportedGroups, out var pointFormats, out _, out _))
            return false;

        string raw = BuildJa3LiteRaw(version, cipherSuites, extensionTypes, supportedGroups, pointFormats);
        if (string.IsNullOrWhiteSpace(raw))
            return false;

        fingerprint = Convert.ToHexString(MD5.HashData(Encoding.ASCII.GetBytes(raw))).ToLowerInvariant();
        return true;
    }

    private static bool TryBuildQuicJa4LiteFingerprint(ReadOnlySpan<byte> body, out string fingerprint)
    {
        fingerprint = string.Empty;
        if (!TryReadTlsClientHelloShape(body, out var version, out var cipherSuites, out var extensionTypes, out var supportedGroups, out _, out var hasServerName, out var alpn))
            return false;

        string versionToken = MapTlsVersionShort(version);
        string alpnToken = NormalizeAlpnToken(alpn);
        string digestSeed = BuildJa3LiteRaw(version, cipherSuites, extensionTypes, supportedGroups, Array.Empty<byte>());
        string digest = Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(digestSeed))).ToLowerInvariant();
        string digestShort = digest.Length > 10 ? digest[..10] : digest;
        fingerprint = $"q{versionToken}{(hasServerName ? 'd' : 'i')}{cipherSuites.Length:x2}{extensionTypes.Length:x2}{supportedGroups.Length:x2}{alpnToken}-{digestShort}";
        return true;
    }

    private static bool TryReadTlsClientHelloShape(
        ReadOnlySpan<byte> body,
        out ushort version,
        out ushort[] cipherSuites,
        out ushort[] extensionTypes,
        out ushort[] supportedGroups,
        out byte[] pointFormats,
        out bool hasServerName,
        out string alpn)
    {
        version = 0;
        cipherSuites = Array.Empty<ushort>();
        extensionTypes = Array.Empty<ushort>();
        supportedGroups = Array.Empty<ushort>();
        pointFormats = Array.Empty<byte>();
        hasServerName = false;
        alpn = string.Empty;

        if (body.Length < 34)
            return false;

        version = ReadU16BE(body, 0);
        if (TryGetTlsClientHelloVersion(body, out var negotiatedVersion) && negotiatedVersion != 0)
            version = negotiatedVersion;

        int offset = 34;
        if (offset >= body.Length)
            return false;

        int sessionIdLength = body[offset];
        offset += 1 + sessionIdLength;
        if (offset + 2 > body.Length)
            return false;

        int cipherSuitesLength = ReadU16BE(body, offset);
        offset += 2;
        if (cipherSuitesLength <= 0 || offset + cipherSuitesLength > body.Length || (cipherSuitesLength & 1) != 0)
            return false;

        var cipherSuitesList = new List<ushort>(cipherSuitesLength / 2);
        for (int i = 0; i < cipherSuitesLength; i += 2)
        {
            ushort candidate = ReadU16BE(body, offset + i);
            if (!IsGreaseValue(candidate))
                cipherSuitesList.Add(candidate);
        }

        offset += cipherSuitesLength;
        if (offset >= body.Length)
            return false;

        int compressionMethodsLength = body[offset];
        offset += 1 + compressionMethodsLength;
        if (offset + 2 > body.Length)
            return false;

        int extensionsLength = ReadU16BE(body, offset);
        offset += 2;
        if (extensionsLength < 0 || offset + extensionsLength > body.Length)
            return false;

        var extensions = body.Slice(offset, extensionsLength);
        var extensionTypeList = new List<ushort>();
        var supportedGroupList = new List<ushort>();
        var pointFormatList = new List<byte>();

        int extensionsOffset = 0;
        while (extensionsOffset + 4 <= extensions.Length)
        {
            ushort extensionType = ReadU16BE(extensions, extensionsOffset);
            int extensionLength = ReadU16BE(extensions, extensionsOffset + 2);
            extensionsOffset += 4;
            if (extensionsOffset + extensionLength > extensions.Length)
                return false;

            if (!IsGreaseValue(extensionType))
                extensionTypeList.Add(extensionType);

            var extensionBody = extensions.Slice(extensionsOffset, extensionLength);
            if (extensionType == 0x0000)
            {
                hasServerName = TryReadTlsServerNameExtension(extensionBody, out _);
            }
            else if (extensionType == 0x000A && extensionLength >= 2)
            {
                int groupsLength = ReadU16BE(extensionBody, 0);
                int groupsOffset = 2;
                int groupsEnd = Math.Min(extensionBody.Length, 2 + groupsLength);
                while (groupsOffset + 2 <= groupsEnd)
                {
                    ushort group = ReadU16BE(extensionBody, groupsOffset);
                    if (!IsGreaseValue(group))
                        supportedGroupList.Add(group);

                    groupsOffset += 2;
                }
            }
            else if (extensionType == 0x000B && extensionLength >= 1)
            {
                int formatsLength = extensionBody[0];
                int formatsEnd = Math.Min(extensionBody.Length, 1 + formatsLength);
                for (int i = 1; i < formatsEnd; i++)
                    pointFormatList.Add(extensionBody[i]);
            }
            else if (extensionType == 0x0010 && extensionLength >= 3)
            {
                int alpnListLength = ReadU16BE(extensionBody, 0);
                int alpnOffset = 2;
                int alpnEnd = Math.Min(extensionBody.Length, 2 + alpnListLength);
                if (alpnOffset < alpnEnd)
                {
                    int protocolLength = extensionBody[alpnOffset];
                    alpnOffset++;
                    if (protocolLength > 0 && alpnOffset + protocolLength <= alpnEnd)
                        alpn = Encoding.ASCII.GetString(extensionBody.Slice(alpnOffset, protocolLength));
                }
            }

            extensionsOffset += extensionLength;
        }

        cipherSuites = cipherSuitesList.ToArray();
        extensionTypes = extensionTypeList.ToArray();
        supportedGroups = supportedGroupList.ToArray();
        pointFormats = pointFormatList.ToArray();
        return cipherSuites.Length > 0 || extensionTypes.Length > 0 || supportedGroups.Length > 0;
    }

    private static string BuildJa3LiteRaw(ushort version, ushort[] cipherSuites, ushort[] extensionTypes, ushort[] supportedGroups, byte[] pointFormats)
        => $"{version},{string.Join('-', cipherSuites)},{string.Join('-', extensionTypes)},{string.Join('-', supportedGroups)},{string.Join('-', pointFormats)}";

    private static bool IsGreaseValue(ushort value)
    {
        byte hi = (byte)(value >> 8);
        byte lo = (byte)value;
        return hi == lo && (lo & 0x0F) == 0x0A;
    }

    private static string NormalizeAlpnToken(string? alpn)
    {
        if (string.IsNullOrWhiteSpace(alpn))
            return "na";

        string normalized = alpn.Trim().ToLowerInvariant();
        return normalized switch
        {
            "h2" => "h2",
            "http/1.1" => "h1",
            "h3" or "h3-29" or "h3-32" => "h3",
            _ => normalized.Length <= 3 ? normalized : normalized[..3]
        };
    }

    private static string MapTlsVersionShort(ushort version)
        => version switch
        {
            0x0304 => "13",
            0x0303 => "12",
            0x0302 => "11",
            0x0301 => "10",
            _ => $"{version:X4}"
        };

    private static string NormalizeCertificateName(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return string.Empty;

        string normalized = value.Trim().TrimEnd('.').ToLowerInvariant();
        return normalized.StartsWith("dns name=", StringComparison.OrdinalIgnoreCase)
            ? normalized["dns name=".Length..].Trim()
            : normalized;
    }

    private static bool TryGetTlsClientHelloServerName(ReadOnlySpan<byte> body, out string serverName)
    {
        serverName = string.Empty;

        if (!TryGetTlsClientHelloExtensions(body, out var extensions))
            return false;

        int offset = 0;
        while (offset + 4 <= extensions.Length)
        {
            ushort extensionType = ReadU16BE(extensions, offset);
            int extensionLength = ReadU16BE(extensions, offset + 2);
            offset += 4;
            if (offset + extensionLength > extensions.Length)
                return false;

            var extensionBody = extensions.Slice(offset, extensionLength);
            if (extensionType == 0x0000 && TryReadTlsServerNameExtension(extensionBody, out serverName))
                return true;

            offset += extensionLength;
        }

        return false;
    }

    private static bool TryGetTlsClientHelloExtensions(ReadOnlySpan<byte> body, out ReadOnlySpan<byte> extensions)
    {
        extensions = ReadOnlySpan<byte>.Empty;
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
        if (offset + extensionsLength > body.Length)
            return false;

        extensions = body.Slice(offset, extensionsLength);
        return true;
    }

    private static bool TryReadTlsServerNameExtension(ReadOnlySpan<byte> extensionBody, out string serverName)
    {
        serverName = string.Empty;
        if (extensionBody.Length < 5)
            return false;

        int listLength = ReadU16BE(extensionBody, 0);
        if (listLength <= 0 || listLength + 2 > extensionBody.Length)
            return false;

        int offset = 2;
        int end = Math.Min(extensionBody.Length, 2 + listLength);
        while (offset + 3 <= end)
        {
            byte nameType = extensionBody[offset];
            int nameLength = ReadU16BE(extensionBody, offset + 1);
            offset += 3;
            if (offset + nameLength > end)
                return false;

            if (nameType == 0)
            {
                string candidate = Encoding.ASCII.GetString(extensionBody.Slice(offset, nameLength));
                if (LooksLikeHostName(candidate))
                {
                    serverName = candidate.Trim().TrimEnd('.').ToLowerInvariant();
                    return true;
                }
            }

            offset += nameLength;
        }

        return false;
    }

    private static bool LooksLikeHostName(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return false;

        string normalized = value.Trim().TrimEnd('.');
        if (normalized.Length < 3 || normalized.Length > 255 || !normalized.Contains('.'))
            return false;

        foreach (char ch in normalized)
        {
            if (char.IsLetterOrDigit(ch) || ch is '-' or '.')
                continue;

            return false;
        }

        return true;
    }

    private static bool TryExtractQuicServerName(ReadOnlySpan<byte> payload, out string serverName)
    {
        serverName = string.Empty;

        if (!TryDecryptQuicInitialCryptoStream(payload, out var cryptoStream))
            return false;

        if (!TryGetTlsClientHelloBodyFromCryptoStream(cryptoStream, out var handshakeBody))
            return false;

        return TryGetTlsClientHelloServerName(handshakeBody, out serverName);
    }

    private static bool TryGetTlsClientHelloBodyFromCryptoStream(ReadOnlySpan<byte> cryptoStream, out ReadOnlySpan<byte> handshakeBody)
    {
        handshakeBody = ReadOnlySpan<byte>.Empty;
        if (cryptoStream.Length < 4 || cryptoStream[0] != 1)
            return false;

        int handshakeLength = (cryptoStream[1] << 16) | (cryptoStream[2] << 8) | cryptoStream[3];
        if (handshakeLength <= 0 || cryptoStream.Length < 4 + handshakeLength)
            return false;

        handshakeBody = cryptoStream.Slice(4, handshakeLength);
        return true;
    }

    private static bool TryDecryptQuicInitialCryptoStream(ReadOnlySpan<byte> packet, out byte[] cryptoStream)
    {
        cryptoStream = Array.Empty<byte>();

        if (packet.Length < 32)
            return false;

        byte first = packet[0];
        if ((first & 0x80) == 0 || ((first >> 4) & 0x03) != 0)
            return false;

        uint version = ReadU32BE(packet.Slice(1, 4));
        byte[] salt = GetQuicInitialSalt(version);
        if (salt.Length == 0)
            return false;

        int offset = 5;
        if (offset >= packet.Length)
            return false;

        int dcidLength = packet[offset++];
        if (offset + dcidLength > packet.Length || dcidLength == 0)
            return false;

        byte[] dcid = packet.Slice(offset, dcidLength).ToArray();
        offset += dcidLength;

        if (offset >= packet.Length)
            return false;

        int scidLength = packet[offset++];
        if (offset + scidLength > packet.Length)
            return false;

        offset += scidLength;

        if (!TryReadQuicVarInt(packet, ref offset, out var tokenLength))
            return false;

        if (tokenLength > (ulong)(packet.Length - offset))
            return false;

        offset += (int)tokenLength;

        if (!TryReadQuicVarInt(packet, ref offset, out var payloadLengthValue))
            return false;

        if (payloadLengthValue > int.MaxValue)
            return false;

        int payloadLength = (int)payloadLengthValue;
        int packetNumberOffset = offset;
        int sampleOffset = packetNumberOffset + 4;
        if (sampleOffset + 16 > packet.Length)
            return false;

        DeriveQuicInitialKeys(dcid, salt, out var key, out var iv, out var hp);

        byte[] mask = ComputeQuicHeaderProtectionMask(hp, packet.Slice(sampleOffset, 16));
        byte firstUnmasked = (byte)(packet[0] ^ (mask[0] & 0x0F));
        int packetNumberLength = (firstUnmasked & 0x03) + 1;
        if (packetNumberOffset + packetNumberLength > packet.Length)
            return false;

        byte[] aad = packet.Slice(0, packetNumberOffset + packetNumberLength).ToArray();
        aad[0] = firstUnmasked;

        ulong packetNumber = 0;
        for (int i = 0; i < packetNumberLength; i++)
        {
            byte pnByte = (byte)(packet[packetNumberOffset + i] ^ mask[i + 1]);
            aad[packetNumberOffset + i] = pnByte;
            packetNumber = (packetNumber << 8) | pnByte;
        }

        if (payloadLength < packetNumberLength + 16)
            return false;

        int encryptedPayloadOffset = packetNumberOffset + packetNumberLength;
        int encryptedPayloadLength = payloadLength - packetNumberLength;
        if (encryptedPayloadOffset + encryptedPayloadLength > packet.Length)
            return false;

        var encryptedPayload = packet.Slice(encryptedPayloadOffset, encryptedPayloadLength);
        int ciphertextLength = encryptedPayloadLength - 16;
        if (ciphertextLength <= 0)
            return false;

        byte[] plaintext = new byte[ciphertextLength];
        byte[] nonce = BuildQuicNonce(iv, packetNumber);

        try
        {
            using var aesGcm = new AesGcm(key);
            aesGcm.Decrypt(
                nonce,
                encryptedPayload.Slice(0, ciphertextLength),
                encryptedPayload.Slice(ciphertextLength, 16),
                plaintext,
                aad);
        }
        catch (CryptographicException)
        {
            return false;
        }

        return TryAssembleQuicCryptoStream(plaintext, out cryptoStream);
    }

    private static bool TryAssembleQuicCryptoStream(ReadOnlySpan<byte> plaintext, out byte[] cryptoStream)
    {
        cryptoStream = Array.Empty<byte>();
        int offset = 0;
        List<(int Offset, byte[] Data)> segments = new();
        int maxEnd = 0;

        while (offset < plaintext.Length)
        {
            if (!TryReadQuicVarInt(plaintext, ref offset, out var frameType))
                return false;

            switch (frameType)
            {
                case 0x00: // PADDING
                case 0x01: // PING
                    continue;

                case 0x06: // CRYPTO
                    if (!TryReadQuicVarInt(plaintext, ref offset, out var cryptoOffsetValue)
                        || !TryReadQuicVarInt(plaintext, ref offset, out var cryptoLengthValue))
                    {
                        return false;
                    }

                    if (cryptoOffsetValue > int.MaxValue || cryptoLengthValue > int.MaxValue)
                        return false;

                    int cryptoOffset = (int)cryptoOffsetValue;
                    int cryptoLength = (int)cryptoLengthValue;
                    if (offset + cryptoLength > plaintext.Length)
                        return false;

                    if (cryptoLength > 0)
                    {
                        byte[] data = plaintext.Slice(offset, cryptoLength).ToArray();
                        segments.Add((cryptoOffset, data));
                        maxEnd = Math.Max(maxEnd, cryptoOffset + cryptoLength);
                    }

                    offset += cryptoLength;
                    continue;

                default:
                    return false;
            }
        }

        if (maxEnd == 0 || segments.Count == 0)
            return false;

        cryptoStream = new byte[maxEnd];
        foreach (var segment in segments)
            segment.Data.CopyTo(cryptoStream, segment.Offset);

        return true;
    }

    private static bool TryReadQuicVarInt(ReadOnlySpan<byte> buffer, ref int offset, out ulong value)
    {
        value = 0;
        if (offset >= buffer.Length)
            return false;

        byte first = buffer[offset];
        int length = 1 << (first >> 6);
        if (offset + length > buffer.Length)
            return false;

        value = (ulong)(first & 0x3F);
        for (int i = 1; i < length; i++)
            value = (value << 8) | buffer[offset + i];

        offset += length;
        return true;
    }

    private static byte[] GetQuicInitialSalt(uint version)
        => version switch
        {
            0x00000001 => QuicV1InitialSalt,
            0x6B3343CF => QuicV2InitialSalt,
            _ => Array.Empty<byte>()
        };

    private static void DeriveQuicInitialKeys(byte[] dcid, byte[] salt, out byte[] key, out byte[] iv, out byte[] hp)
    {
        byte[] initialSecret = HkdfExtractSha256(salt, dcid);
        byte[] clientInitialSecret = TlsHkdfExpandLabel(initialSecret, "client in", Array.Empty<byte>(), 32);
        key = TlsHkdfExpandLabel(clientInitialSecret, "quic key", Array.Empty<byte>(), 16);
        iv = TlsHkdfExpandLabel(clientInitialSecret, "quic iv", Array.Empty<byte>(), 12);
        hp = TlsHkdfExpandLabel(clientInitialSecret, "quic hp", Array.Empty<byte>(), 16);
    }

    private static byte[] ComputeQuicHeaderProtectionMask(byte[] hpKey, ReadOnlySpan<byte> sample)
    {
        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        aes.Key = hpKey;
        using var encryptor = aes.CreateEncryptor();
        return encryptor.TransformFinalBlock(sample.ToArray(), 0, 16);
    }

    private static byte[] BuildQuicNonce(byte[] iv, ulong packetNumber)
    {
        byte[] nonce = (byte[])iv.Clone();
        Span<byte> pnBuffer = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(pnBuffer, packetNumber);
        for (int i = 0; i < pnBuffer.Length; i++)
            nonce[nonce.Length - pnBuffer.Length + i] ^= pnBuffer[i];

        return nonce;
    }

    private static byte[] HkdfExtractSha256(byte[] salt, byte[] ikm)
    {
        using var hmac = new HMACSHA256(salt);
        return hmac.ComputeHash(ikm);
    }

    private static byte[] HkdfExpandSha256(byte[] prk, byte[] info, int length)
    {
        if (length <= 0)
            return Array.Empty<byte>();

        byte[] output = new byte[length];
        byte[] previous = Array.Empty<byte>();
        int written = 0;
        byte counter = 1;

        using var hmac = new HMACSHA256(prk);
        while (written < length)
        {
            byte[] input = new byte[previous.Length + info.Length + 1];
            Buffer.BlockCopy(previous, 0, input, 0, previous.Length);
            Buffer.BlockCopy(info, 0, input, previous.Length, info.Length);
            input[^1] = counter;

            previous = hmac.ComputeHash(input);
            int toCopy = Math.Min(previous.Length, length - written);
            Buffer.BlockCopy(previous, 0, output, written, toCopy);
            written += toCopy;
            counter++;
        }

        return output;
    }

    private static byte[] TlsHkdfExpandLabel(byte[] secret, string label, byte[] context, int length)
    {
        byte[] labelBytes = Encoding.ASCII.GetBytes("tls13 " + label);
        byte[] info = new byte[2 + 1 + labelBytes.Length + 1 + context.Length];
        info[0] = (byte)(length >> 8);
        info[1] = (byte)length;
        info[2] = (byte)labelBytes.Length;
        Buffer.BlockCopy(labelBytes, 0, info, 3, labelBytes.Length);
        int offset = 3 + labelBytes.Length;
        info[offset] = (byte)context.Length;
        if (context.Length > 0)
            Buffer.BlockCopy(context, 0, info, offset + 1, context.Length);

        return HkdfExpandSha256(secret, info, length);
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
        if (!TryReadDnsSummary(payload, tcpLengthPrefixed, out var summary))
            return false;

        string direction = summary.IsResponse ? "Response" : "Query";
        if (!string.IsNullOrWhiteSpace(summary.QuestionName))
        {
            string typeSuffix = string.IsNullOrWhiteSpace(summary.QuestionType) ? string.Empty : $" {summary.QuestionType}";
            string answerSuffix = BuildDnsAnswerSuffix(summary.AnswerIps);
            detail = $"{direction} {summary.QuestionName}{typeSuffix}{answerSuffix}";
            return true;
        }

        detail = $"{direction} QD={summary.QuestionCount} AN={summary.AnswerCount}";
        return true;
    }

    private static bool TryExtractDnsResolution(ReadOnlySpan<byte> payload, bool tcpLengthPrefixed, out string dnsQueryName, out IReadOnlyList<string> dnsAnswerIps)
    {
        dnsQueryName = string.Empty;
        dnsAnswerIps = Array.Empty<string>();

        if (!TryReadDnsSummary(payload, tcpLengthPrefixed, out var summary))
            return false;

        if (!summary.IsResponse || string.IsNullOrWhiteSpace(summary.QuestionName) || summary.AnswerIps.Count == 0)
            return false;

        dnsQueryName = summary.QuestionName;
        dnsAnswerIps = summary.AnswerIps;
        return true;
    }

    private static bool TryReadDnsSummary(ReadOnlySpan<byte> payload, bool tcpLengthPrefixed, out DnsMessageSummary summary)
    {
        summary = default;

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
        int offset = 12;
        string questionName = string.Empty;
        string questionType = string.Empty;

        for (int i = 0; i < questions; i++)
        {
            if (!TryReadDnsQuestion(message, ref offset, out var currentName, out var currentType))
                return false;

            if (i == 0)
            {
                questionName = currentName;
                questionType = currentType;
            }
        }

        List<string>? answerIps = null;
        for (int i = 0; i < answers; i++)
        {
            if (!TryReadDnsAnswerRecord(message, ref offset, out var answerIp))
                return false;

            if (!string.IsNullOrWhiteSpace(answerIp))
            {
                answerIps ??= new List<string>();
                answerIps.Add(answerIp);
            }
        }

        summary = new DnsMessageSummary(
            IsResponse: isResponse,
            QuestionName: questionName,
            QuestionType: questionType,
            AnswerIps: answerIps is null ? Array.Empty<string>() : answerIps,
            QuestionCount: questions,
            AnswerCount: answers);
        return true;
    }

    private static bool TryReadDnsQuestion(ReadOnlySpan<byte> message, ref int offset, out string questionName, out string questionType)
    {
        questionName = string.Empty;
        questionType = string.Empty;

        if (!TryReadDnsName(message, offset, out questionName, out var nextOffset))
            return false;

        if (nextOffset + 4 > message.Length)
            return false;

        ushort qtype = ReadU16BE(message, nextOffset);
        questionType = GetDnsTypeName(qtype);
        offset = nextOffset + 4;
        return true;
    }

    private static bool TryReadDnsAnswerRecord(ReadOnlySpan<byte> message, ref int offset, out string answerIp)
    {
        answerIp = string.Empty;

        if (!TryReadDnsName(message, offset, out _, out var nextOffset))
            return false;

        if (nextOffset + 10 > message.Length)
            return false;

        ushort type = ReadU16BE(message, nextOffset);
        ushort dnsClass = ReadU16BE(message, nextOffset + 2);
        int rdLength = ReadU16BE(message, nextOffset + 8);
        int rdataOffset = nextOffset + 10;
        if (rdataOffset + rdLength > message.Length)
            return false;

        if (dnsClass == 1)
        {
            if (type == 1 && rdLength == 4)
                answerIp = FormatIPv4(message.Slice(rdataOffset, 4));
            else if (type == 28 && rdLength == 16)
                answerIp = new IPAddress(message.Slice(rdataOffset, 16)).ToString();
        }

        offset = rdataOffset + rdLength;
        return true;
    }

    private static string BuildDnsAnswerSuffix(IReadOnlyList<string> answerIps)
    {
        if (answerIps.Count == 0)
            return string.Empty;

        if (answerIps.Count == 1)
            return $" -> {answerIps[0]}";

        if (answerIps.Count == 2)
            return $" -> {answerIps[0]}, {answerIps[1]}";

        return $" -> {answerIps[0]}, {answerIps[1]}, +{answerIps.Count - 2} more";
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

    private readonly record struct DnsMessageSummary(
        bool IsResponse,
        string QuestionName,
        string QuestionType,
        IReadOnlyList<string> AnswerIps,
        int QuestionCount,
        int AnswerCount);

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
