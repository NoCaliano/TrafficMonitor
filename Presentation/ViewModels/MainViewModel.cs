// Відповідає за: прийом raw пакетів, парсинг через IPacketParser, батчинг і показ у DataGrid.
using Application.Abstractions;
using Domain.Models;
using PacketDotNet;
using Presentation.Helpers;
using System.Collections.ObjectModel;
using System.Threading.Channels;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace Presentation.ViewModels;

public sealed class MainViewModel : ViewModelBase
{
    private readonly ICaptureDeviceService _deviceService;
    private readonly IPacketCaptureService _captureService;
    private readonly IPacketParser _parser;
    // Відповідає за вибраний пакет у таблиці (тригерить оновлення дерева протоколів і hex-дампу).
    private PacketInfo? _selectedPacket;
    public PacketInfo? SelectedPacket
    {
        get => _selectedPacket;
        set
        {
            if (!Set(ref _selectedPacket, value))
                return;

            UpdateDetails(value);
        }
    }

    // Відповідає за текстовий hex-дамп пакета для відображення у UI.
    private string _hexDump = "";
    public string HexDump
    {
        get => _hexDump;
        set => Set(ref _hexDump, value);
    }

    // Відповідає за кореневий вузол дерева протоколів для вибраного пакета (відображається в TreeView).
    private TreeViewItem? _protocolRoot;
    public TreeViewItem? ProtocolRoot
    {
        get => _protocolRoot;
        private set => Set(ref _protocolRoot, value);
    }
    // Відповідає за обраний діапазон байтів (start,length) у дереві деталей (Tag вузла).
    private (int start, int length)? _selectedRange;
    public (int start, int length)? SelectedRange
    {
        get => _selectedRange;
        set => Set(ref _selectedRange, value);
    }

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
    // Відповідає за оновлення панелі деталей при виборі пакета.
    // Відповідає за оновлення панелі деталей при виборі пакета: дерево протоколів + hex дамп.
    // Відповідає за оновлення панелі деталей при виборі пакета: дерево протоколів + hex дамп.
    private void UpdateDetails(PacketInfo? p)
    {
        // Очищення деталей
        ProtocolRoot = null;
        HexDump = "";

        if (p is null || p.RawBytes is null || p.RawBytes.Length == 0)
            return;

        // Hex dump
        HexDump = BuildHexDump(p.RawBytes, bytesPerLine: 16);

        try
        {
            // Відповідає за коректний повторний парсинг пакета для побудови дерева.
            // LinkLayerType зберігаємо як int у Domain, а тут приводимо до SharpPcap.LinkLayers.
            var link = (LinkLayers)p.LinkLayerType;

            // Парсимо пакет через PacketDotNet, використовуючи правильний LinkLayer.
            var parsedPacket = Packet.ParsePacket(link, p.RawBytes);

            // Будуємо дерево протоколів (PacketTreeBuilder.Build має приймати PacketInfo як row).
            ProtocolRoot = PacketTreeBuilder.Build(parsedPacket, p);
        }
        catch (Exception ex)
        {
            // Якщо парсинг зламався — показуємо причину як дерево з одним вузлом
            ProtocolRoot = new TreeViewItem { Header = $"Parse error: {ex.Message}" };
        }
    }


    // Відповідає за генерацію hex-дампу (без кольорів, простий, але читабельний).
    private static string BuildHexDump(byte[] data, int bytesPerLine)
    {
        if (data.Length == 0) return "";

        var sb = new System.Text.StringBuilder(data.Length * 4);

        for (int i = 0; i < data.Length; i += bytesPerLine)
        {
            sb.Append(i.ToString("X4"));
            sb.Append(": ");

            // hex
            int lineEnd = Math.Min(i + bytesPerLine, data.Length);
            for (int j = i; j < lineEnd; j++)
            {
                sb.Append(data[j].ToString("X2"));
                sb.Append(' ');
            }

            // padding
            for (int j = lineEnd; j < i + bytesPerLine; j++)
                sb.Append("   ");

            sb.Append(" |");

            // ascii
            for (int j = i; j < lineEnd; j++)
            {
                byte b = data[j];
                sb.Append(b >= 32 && b <= 126 ? (char)b : '.');
            }

            sb.AppendLine("|");
        }

        return sb.ToString();
    }
}
