namespace Presentation.Models;

public sealed class ProcessConversationRow
{
    public required string Protocol { get; init; }
    public required string RemoteIp { get; init; }
    public required int RemotePort { get; init; }
    public required long PacketCount { get; init; }
    public required long TotalBytes { get; init; }
    public required DateTime FirstSeen { get; init; }
    public required DateTime LastSeen { get; init; }
    public required int OutboundPackets { get; init; }
    public required int InboundPackets { get; init; }

    public string EndpointLabel => RemotePort > 0 ? $"{RemoteIp}:{RemotePort}" : RemoteIp;
    public string ConversationLabel => string.IsNullOrWhiteSpace(Protocol) ? EndpointLabel : $"{Protocol} {EndpointLabel}";
    public string PacketCountLabel => $"{PacketCount:N0} pkt";
    public string BytesLabel => FormatBytes(TotalBytes);
    public string DirectionLabel
    {
        get
        {
            if (OutboundPackets > 0 || InboundPackets > 0)
                return $"{OutboundPackets:N0} out / {InboundPackets:N0} in";

            return $"{PacketCount:N0} observed";
        }
    }

    public string FirstSeenLabel => FirstSeen == default ? "" : $"First {FirstSeen:HH:mm:ss}";
    public string LastSeenLabel => LastSeen == default ? "" : $"Last {LastSeen:HH:mm:ss}";

    private static string FormatBytes(long bytes)
    {
        const double KB = 1024;
        const double MB = KB * 1024;
        const double GB = MB * 1024;

        if (bytes >= GB) return $"{bytes / GB:0.##} GB";
        if (bytes >= MB) return $"{bytes / MB:0.##} MB";
        if (bytes >= KB) return $"{bytes / KB:0.##} KB";
        return $"{bytes:N0} B";
    }
}
