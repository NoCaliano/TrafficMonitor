// Відповідає за агреговану інформацію про потік.
namespace Domain.Models;

public sealed class FlowInfo
{
    public FlowKey Key { get; init; }

    public int Packets { get; set; }
    public long Bytes { get; set; }

    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }

    public TimeSpan Duration => LastSeen - FirstSeen;

    public string Info => $"{Key.Protocol} {Key.SrcIp}:{Key.SrcPort} → {Key.DstIp}:{Key.DstPort}";
}
