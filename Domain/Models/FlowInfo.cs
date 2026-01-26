// Відповідає за агреговану інформацію про потік (bi-directional: A<->B).
namespace Domain.Models;

public sealed class FlowInfo
{
    public FlowKey Key { get; init; }

    public int Packets { get; set; }
    public long Bytes { get; set; }

    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }

    // Відповідає за визначення напрямку потоку відносно локального ПК (Inbound/Outbound/Local/Unknown).
    public FlowDirection Direction { get; set; } = FlowDirection.Unknown;

    public TimeSpan Duration => LastSeen - FirstSeen;

    // -------------------- Bi-directional counters (A<->B) --------------------
    // Відповідає за лічильники напрямків усередині нормалізованого ключа.
    public int PacketsAToB { get; set; }
    public long BytesAToB { get; set; }

    public int PacketsBToA { get; set; }
    public long BytesBToA { get; set; }

    // -------------------- Local-relative counters --------------------
    // Відповідає за лічильники "від мене" / "до мене" (якщо локальна сторона визначена).
    public int SentPackets { get; set; }
    public long SentBytes { get; set; }

    public int RecvPackets { get; set; }
    public long RecvBytes { get; set; }

    // -------------------- Local/Remote endpoints for UI --------------------
    // Відповідає за локальну/віддалену сторону (для Flow Details та таблиці).
    public string LocalIp { get; set; } = "";
    public int? LocalPort { get; set; }

    public string RemoteIp { get; set; } = "";
    public int? RemotePort { get; set; }

    // -------------------- UI helpers --------------------
    // Відповідає за зручний текст для UI (колонка Dir).
    public string Dir => Direction switch
    {
        FlowDirection.Outbound => "Out",
        FlowDirection.Inbound => "In",
        FlowDirection.Local => "Local",
        _ => "Unknown"
    };

    // Відповідає за рядки Local/Remote (для деталей).
    public string LocalEndpoint =>
        !string.IsNullOrWhiteSpace(LocalIp) ? $"{LocalIp}:{LocalPort}" : "";

    public string RemoteEndpoint =>
        !string.IsNullOrWhiteSpace(RemoteIp) ? $"{RemoteIp}:{RemotePort}" : "";

    // Відповідає за поля для таблиці Flows: якщо Local визначений — показуємо Local -> Remote.
    // Якщо ні — показуємо нормалізовані A -> B з Key.
    public string SrcIp => !string.IsNullOrWhiteSpace(LocalIp) ? LocalIp : Key.SrcIp;
    public int? SrcPort => !string.IsNullOrWhiteSpace(LocalIp) ? LocalPort : Key.SrcPort;

    public string DstIp => !string.IsNullOrWhiteSpace(RemoteIp) ? RemoteIp : Key.DstIp;
    public int? DstPort => !string.IsNullOrWhiteSpace(RemoteIp) ? RemotePort : Key.DstPort;

    public string Protocol => Key.Protocol;
}
