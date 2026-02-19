using Domain.Models;

namespace Presentation.Services;

public interface ICaptureController
{
    bool IsRunning { get; }
    event Action<IReadOnlyList<PacketInfo>>? PacketsParsed;
    event Action<IReadOnlyList<FlowInfo>, Presentation.Models.CaptureStats>? FlowsAndStatsAvailable;
    Task StartAsync(string deviceId, string? bpfFilter, CancellationToken ct);
    Task StopAsync(CancellationToken ct);
}
