using Application.Capture;
using Domain.Models;

namespace Application.Abstractions;

public interface ICaptureController
{
    bool IsRunning { get; }
    event Action<IReadOnlyList<PacketInfo>>? PacketsParsed;
    event Action<IReadOnlyList<FlowInfo>, CaptureStats>? FlowsAndStatsAvailable;
    void ResetSessionState();
    Task StartAsync(string deviceId, string? bpfFilter, CancellationToken ct);
    Task StopAsync(CancellationToken ct);
}
