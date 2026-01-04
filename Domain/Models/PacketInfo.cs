using System;
using System.Collections.Generic;
using System.Text;

// Відповідає за модель відображення пакета в системі (дані для UI/агрегації/експорту).
namespace Domain.Models;

public sealed class PacketInfo
{
    public DateTime Timestamp { get; init; }
    public int Length { get; init; }

    public string SrcMac { get; init; } = "";
    public string DstMac { get; init; } = "";

    public string SrcIp { get; init; } = "";
    public string DstIp { get; init; } = "";

    public string Protocol { get; init; } = "";   // "TCP", "UDP", "ICMP", "ARP", ...
    public int? SrcPort { get; init; }
    public int? DstPort { get; init; }

    public string TcpFlags { get; init; } = "";   // "SYN, ACK" ...
    public string Info { get; init; } = "";       // короткий опис (DNS query / TCP handshake / etc.)
}
