using System;
using System.Collections.Generic;
using System.Text;

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

    public string Protocol { get; init; } = "";   // "TCP", "UDP", "ICMP", "ARP", ...
    public int? SrcPort { get; init; }
    public int? DstPort { get; init; }
    public int? Pid { get; init; }

    // Відповідає за ім'я процесу, який володіє сокетом (якщо вдалося визначити).
    public string ProcessName { get; init; } = "";

    public string TcpFlags { get; init; } = "";   // "SYN, ACK" ...
    public string Info { get; init; } = "";       // короткий опис (DNS query / TCP handshake / etc.)

    // Відповідає за збереження сирих даних пакета для детального перегляду (hex + дерево протоколів).
    public byte[] RawBytes { get; init; } = Array.Empty<byte>();
    public string LinkLayer { get; init; } = "";

    // Відповідає за тип канального рівня (як int), щоб UI міг повторно парсити пакет через PacketDotNet.
    public int LinkLayerType { get; init; }


}
