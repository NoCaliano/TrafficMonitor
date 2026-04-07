namespace Presentation.Models;

public abstract class TrafficListRow
{
    public string Title { get; init; } = "";
    public string Subtitle { get; init; } = "";
    public long Bytes { get; init; }
    public string BytesLabel { get; init; } = "0 B";
    public double RelativePercent { get; init; }
}

public sealed class ProcessTrafficRow : TrafficListRow
{
    public int Pid { get; init; }
}

public sealed class ConversationTrafficRow : TrafficListRow
{
    public int Pid { get; init; }
    public string ProcessName { get; init; } = "";
    public string EndpointLabel { get; init; } = "";
    public string PacketCountLabel { get; init; } = "";
    public string DirectionLabel { get; init; } = "";
}

public sealed class HostStatRow : TrafficListRow
{
    public string Type { get; init; } = "";
    public string BadgeText { get; init; } = "";
}

public sealed class TrafficTypeStatRow : TrafficListRow
{
    public string Key { get; init; } = "";
    public string BadgeText { get; init; } = "";
}
