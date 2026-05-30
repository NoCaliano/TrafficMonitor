using System;
using System.Collections.Generic;
using System.Net;

// Відповідає за модель відображення пакета в системі (дані для UI/агрегації/експорту).
namespace Domain.Models;

public sealed class PacketInfo
{
    public long No { get; set; }
    public DateTime Timestamp { get; init; }
    public int Length { get; init; }

    public string SrcMac { get; init; } = "";
    public string DstMac { get; init; } = "";

    public string SrcIp { get; init; } = "";
    public string DstIp { get; init; } = "";

    // Parsed IPs for fast lookups (e.g., PID resolution) without string -> IPAddress conversions.
    public IPAddress? SrcIpAddress { get; init; }
    public IPAddress? DstIpAddress { get; init; }

    public string Protocol { get; init; } = "";   // "TCP", "DNS", "TLSv1.2", "QUIC", ...
    public string TransportProtocol { get; init; } = "";   // "TCP", "UDP", "IGMP", ...
    public int? SrcPort { get; init; }
    public int? DstPort { get; init; }
    public int? Pid { get; init; }

    // Відповідає за ім'я процесу, який володіє сокетом (якщо вдалося визначити).
    public string ProcessName { get; init; } = "";

    public string TcpFlags { get; init; } = "";   // "SYN, ACK" ...
    public string Info { get; init; } = "";       // короткий опис (DNS query / TCP handshake / etc.)
    public string DnsQueryName { get; init; } = "";
    public IReadOnlyList<string> DnsAnswerIps { get; init; } = Array.Empty<string>();
    public string ServerNameHint { get; init; } = "";
    public string TlsClientFingerprintKind { get; init; } = "";
    public string TlsClientFingerprint { get; init; } = "";
    public string TlsHandshakeType { get; init; } = "";
    public string TlsCertificateFingerprint { get; init; } = "";
    public IReadOnlyList<string> TlsCertificateNames { get; init; } = Array.Empty<string>();
    public string TlsCertificateSubject { get; init; } = "";
    // Відповідає за збереження сирих даних пакета: зберігаємо лише id у RawBytesStore
    public int? RawBytesId { get; init; }

    // Optional pinned raw bytes for packets kept in UI lists.
    // If set, UI can show details even after RawBytesStore evicts the payload.
    public byte[]? RawBytes { get; set; }
    public string LinkLayer { get; init; } = "";

    // Відповідає за тип канального рівня (як int), щоб UI міг повторно парсити пакет через PacketDotNet.
    public int LinkLayerType { get; init; }


}
