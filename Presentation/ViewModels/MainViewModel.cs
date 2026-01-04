// Відповідає за: прийом raw пакетів, парсинг через IPacketParser, батчинг і показ у DataGrid.
using System.Collections.ObjectModel;
using System.Threading.Channels;
using System.Windows;
using System.Windows.Input;
using Application.Abstractions;
using Domain.Models;

namespace Presentation.ViewModels;

public sealed class MainViewModel : ViewModelBase
{
    private readonly ICaptureDeviceService _deviceService;
    private readonly IPacketCaptureService _captureService;
    private readonly IPacketParser _parser;

    private readonly Channel<RawPacketCapturedEventArgs> _channel =
        Channel.CreateBounded<RawPacketCapturedEventArgs>(new BoundedChannelOptions(20_000)
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.DropOldest
        });

    private CancellationTokenSource? _captureCts;
    private Task? _uiReaderTask;

    public ObservableCollection<CaptureDeviceInfo> Devices { get; } = new();

    // Тепер тут PacketInfo
    public ObservableCollection<PacketInfo> Packets { get; } = new();

    private CaptureDeviceInfo? _selectedDevice;
    public CaptureDeviceInfo? SelectedDevice
    {
        get => _selectedDevice;
        set => Set(ref _selectedDevice, value);
    }

    private string? _bpfFilter;
    public string? BpfFilter
    {
        get => _bpfFilter;
        set => Set(ref _bpfFilter, value);
    }

    private string _statusText = "Idle";
    public string StatusText
    {
        get => _statusText;
        set => Set(ref _statusText, value);
    }

    public ICommand StartCommand { get; }
    public ICommand StopCommand { get; }

    public MainViewModel(
        ICaptureDeviceService deviceService,
        IPacketCaptureService captureService,
        IPacketParser parser)
    {
        _deviceService = deviceService;
        _captureService = captureService;
        _parser = parser;

        StartCommand = new AsyncRelayCommand(StartAsync);
        StopCommand = new AsyncRelayCommand(StopAsync);

        LoadDevices();

        _captureService.PacketCaptured += (_, args) =>
        {
            _channel.Writer.TryWrite(args);
        };
    }

    private void LoadDevices()
    {
        Devices.Clear();
        foreach (var d in _deviceService.GetAllDevices())
            Devices.Add(d);

        SelectedDevice = Devices.FirstOrDefault();
    }

    private async Task StartAsync(CancellationToken ct)
    {
        if (SelectedDevice is null) return;
        if (_captureService.IsRunning) return;

        StatusText = "Starting...";

        _captureCts = new CancellationTokenSource();
        _uiReaderTask = RunUiBatchReaderAsync(_captureCts.Token);

        await _captureService.StartAsync(SelectedDevice.Id, BpfFilter, ct);

        StatusText = "Capturing";
    }

    private async Task StopAsync(CancellationToken ct)
    {
        if (!_captureService.IsRunning) return;

        StatusText = "Stopping...";
        await _captureService.StopAsync(ct);

        if (_captureCts is not null)
        {
            _captureCts.Cancel();
            try { if (_uiReaderTask is not null) await _uiReaderTask; } catch { }
            _captureCts.Dispose();
            _captureCts = null;
        }

        StatusText = "Idle";
    }

    private async Task RunUiBatchReaderAsync(CancellationToken ct)
    {
        var batch = new List<RawPacketCapturedEventArgs>(512);

        try
        {
            while (await _channel.Reader.WaitToReadAsync(ct))
            {
                batch.Clear();
                while (batch.Count < 512 && _channel.Reader.TryRead(out var item))
                    batch.Add(item);

                // Парсимо в фоні (ми вже в фоні), в UI лише додаємо результати
                var parsed = new List<PacketInfo>(batch.Count);
                foreach (var e in batch)
                    parsed.Add(_parser.Parse(e.Timestamp, e.Length, e.RawCapture));

                await System.Windows.Application.Current.Dispatcher.InvokeAsync(() =>
                {
                    foreach (var p in parsed)
                        Packets.Add(p);

                    const int maxRows = 50_000;
                    while (Packets.Count > maxRows)
                        Packets.RemoveAt(0);
                });

                await Task.Delay(200, ct);
            }
        }
        catch (OperationCanceledException) { }
    }
}
