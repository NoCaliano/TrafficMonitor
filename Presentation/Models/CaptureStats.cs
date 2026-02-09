namespace Presentation.Models;

public sealed class CaptureStats
{
    public long TotalPackets { get; set; }
    public long TotalBytes { get; set; }
    public DateTime? FirstSeen { get; set; }
    public DateTime? LastSeen { get; set; }

    // elapsed від старту capture
    public TimeSpan Elapsed { get; set; }
}