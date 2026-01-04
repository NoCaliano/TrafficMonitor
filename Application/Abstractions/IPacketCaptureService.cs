// Відповідає за запуск/зупинку захоплення пакетів та передачу "сирих" пакетів у верхні рівні (без привʼязки до SharpPcap типів).
namespace Application.Abstractions;

public interface IPacketCaptureService : IAsyncDisposable
{
    bool IsRunning { get; }

    Task StartAsync(string deviceId, string? bpfFilter, CancellationToken ct);
    Task StopAsync(CancellationToken ct);

    event EventHandler<RawPacketCapturedEventArgs>? PacketCaptured;
}

public sealed class RawPacketCapturedEventArgs : EventArgs
{
    public RawPacketCapturedEventArgs(DateTime timestamp, int length, object rawCapture)
    {
        Timestamp = timestamp;
        Length = length;
        RawCapture = rawCapture;
    }

    public DateTime Timestamp { get; }
    public int Length { get; }

    // rawCapture – обʼєкт нижнього рівня (SharpPcap RawCapture). Тримаємо як object, щоб Application не залежав від Infrastructure.
    public object RawCapture { get; }
}
