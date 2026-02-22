// Відповідає за живе захоплення пакетів через SharpPcap та генерацію події PacketCaptured.
// У хендлері пакета не робимо важких операцій, щоб не гальмувати захоплення.
using Application.Abstractions;
using Infrastructure.Networking;
using SharpPcap;

namespace Infrastructure.Capture;

public sealed class SharpPcapCaptureService : IPacketCaptureService
{
    private readonly ProcessMapperService _processMapperService;
    private ILiveDevice? _device;

    public bool IsRunning { get; private set; }

    public event EventHandler<RawPacketCapturedEventArgs>? PacketCaptured;

    public SharpPcapCaptureService(ProcessMapperService processMapperService)
    {
        _processMapperService = processMapperService;
    }

    public Task StartAsync(string deviceId, string? bpfFilter, CancellationToken ct)
    {
        if (IsRunning) return Task.CompletedTask;

        // Enable endpoint->PID polling only while capture is running.
        _processMapperService.Start();

        var dev = CaptureDeviceList.Instance.FirstOrDefault(d => d.Name == deviceId);
        if (dev is null)
            throw new InvalidOperationException($"Capture device not found: {deviceId}");

        _device = dev;

        // Підписуємось на прихід пакетів
        _device.OnPacketArrival += Device_OnPacketArrival;

        // Відкриваємо адаптер (Promiscuous — щоб бачити більше трафіку; timeout — щоб цикл не "висів" вічно)
        _device.Open(DeviceModes.Promiscuous, read_timeout: 1000);

        // BPF-фільтр застосовується на рівні драйвера — це найшвидше
        if (!string.IsNullOrWhiteSpace(bpfFilter))
            _device.Filter = bpfFilter;

        IsRunning = true;

        // Запуск захоплення
        _device.StartCapture();

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken ct)
    {
        if (!IsRunning) return Task.CompletedTask;

        if (_device is not null)
        {
            _device.OnPacketArrival -= Device_OnPacketArrival;

            try { _device.StopCapture(); } catch { }
            try { _device.Close(); } catch { }
        }

        _device = null;
        IsRunning = false;

        _processMapperService.Stop();

        return Task.CompletedTask;
    }

    private void Device_OnPacketArrival(object sender, PacketCapture e)
    {
        var raw = e.GetPacket(); // RawCapture

        // Мінімальна робота: timestamp + length + сирий пакет як object
        PacketCaptured?.Invoke(this, new RawPacketCapturedEventArgs(
            timestamp: raw.Timeval.Date,
            length: raw.Data.Length,
            rawCapture: raw
        ));
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync(CancellationToken.None);
    }
}
