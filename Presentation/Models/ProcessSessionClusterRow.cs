namespace Presentation.Models;

public sealed class ProcessSessionClusterRow
{
    public required int Index { get; init; }
    public required DateTime FirstSeen { get; init; }
    public required DateTime LastSeen { get; init; }
    public required long PacketCount { get; init; }
    public required long TotalBytes { get; init; }
    public required int DistinctRemoteEndpoints { get; init; }
    public required string TopRemoteEndpoint { get; init; }
    public required int OutboundPackets { get; init; }
    public required int InboundPackets { get; init; }
    public required bool IsActive { get; init; }

    public string Title => IsActive ? $"Session {Index} - ongoing" : $"Session {Index}";
    public string WindowLabel
        => FirstSeen == default || LastSeen == default
            ? ""
            : $"{FirstSeen:HH:mm:ss} - {LastSeen:HH:mm:ss}";
    public string DurationLabel => FormatDuration(LastSeen - FirstSeen);
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

    public string RemoteSummaryLabel
    {
        get
        {
            if (DistinctRemoteEndpoints <= 0)
                return "No remote endpoints";

            if (string.IsNullOrWhiteSpace(TopRemoteEndpoint))
                return $"{DistinctRemoteEndpoints:N0} remotes";

            return DistinctRemoteEndpoints == 1
                ? $"Top remote: {TopRemoteEndpoint}"
                : $"{DistinctRemoteEndpoints:N0} remotes - top {TopRemoteEndpoint}";
        }
    }

    private static string FormatDuration(TimeSpan value)
    {
        if (value <= TimeSpan.Zero)
            return "<1s";

        if (value.TotalHours >= 1)
            return $"{(int)value.TotalHours}h {value.Minutes}m";

        if (value.TotalMinutes >= 1)
            return $"{(int)value.TotalMinutes}m {value.Seconds}s";

        return $"{Math.Max(1, value.Seconds)}s";
    }

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
