// Відповідає за агреговану інформацію про потік.
namespace Domain.Models;

public sealed class FlowInfo
{
    public FlowKey Key { get; init; }

    public int Packets { get; set; }
    public long Bytes { get; set; }

    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }

    // Відповідає за визначення напрямку потоку (Inbound/Outbound/Local/Unknown).
    public FlowDirection Direction { get; set; } = FlowDirection.Unknown;

    public TimeSpan Duration => LastSeen - FirstSeen;

    // Відповідає за зручний текст для UI (колонка Dir).
    public string Dir => Direction switch
    {
        FlowDirection.Outbound => "Out",
        FlowDirection.Inbound => "In",
        FlowDirection.Local => "Local",
        _ => "Unknown"
    };

    // Відповідає за локальну/віддалену сторону (для Flow Details).
    public string LocalEndpoint => Direction switch
    {
        FlowDirection.Outbound => $"{Key.SrcIp}:{Key.SrcPort}",
        FlowDirection.Inbound => $"{Key.DstIp}:{Key.DstPort}",
        FlowDirection.Local => $"{Key.SrcIp}:{Key.SrcPort}",
        _ => ""
    };

    public string RemoteEndpoint => Direction switch
    {
        FlowDirection.Outbound => $"{Key.DstIp}:{Key.DstPort}",
        FlowDirection.Inbound => $"{Key.SrcIp}:{Key.SrcPort}",
        FlowDirection.Local => $"{Key.DstIp}:{Key.DstPort}",
        _ => ""
    };
}
