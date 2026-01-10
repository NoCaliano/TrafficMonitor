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

            // Якщо вибрали пакет — прибираємо flow, щоб права панель перемкнулась
            if (value is not null && SelectedFlow is not null)
            {
                _selectedFlow = null;
                OnPropertyChanged(nameof(SelectedFlow));
            }

            UpdateDetails(value);

            OnPropertyChanged(nameof(DetailsContext));
            OnPropertyChanged(nameof(DetailsTitle));
        }
    }

    // Відповідає за вибраний flow у вкладці Flows.
    private FlowInfo? _selectedFlow;
    public FlowInfo? SelectedFlow
    {
        get => _selectedFlow;
        set => Set(ref _selectedFlow, value);
    }


    // Відповідає за контекст правої панелі (або PacketInfo, або FlowInfo, або null).
    public object? DetailsContext => (object?)SelectedPacket ?? SelectedFlow;

    // Відповідає за заголовок правої панелі.
    public string DetailsTitle => SelectedPacket is not null ? "Packet Details"
                                 : SelectedFlow is not null ? "Flow Details"
                                 : "Details";

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

    // Відповідає за агрегатор потоків.
    private readonly IFlowAggregator _flowAggregator;

    // Відповідає за список потоків для UI.
    public ObservableCollection<FlowInfo> Flows { get; } = new();


    public MainViewModel(
        ICaptureDeviceService deviceService,
        IPacketCaptureService captureService,
        IPacketParser parser,
        IFlowAggregator flowAggregator)

    {
        _deviceService = deviceService;
        _captureService = captureService;
        _flowAggregator = flowAggregator;
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

    // Відповідає за запуск захоплення: скидання UI, reset агрегатора flows, запуск reader task і старт capture.
    private async Task StartAsync(CancellationToken ct)
    {
        if (SelectedDevice is null) return;
        if (_captureService.IsRunning) return;

        StatusText = "Starting...";

        // Відповідає за повний reset перед новим захопленням
        Packets.Clear();
        Flows.Clear();
        _flowAggregator.Reset();

        // (не обов’язково, але логічно) скидаємо деталі вибраного пакета
        SelectedPacket = null;
        ProtocolRoot = null;
        HexDump = "";

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

    // Відповідає за батчинг: читаємо raw-пакети, парсимо, додаємо в Packets,
    // агрегіруємо в flows, і раз на ~1с оновлюємо Flows у UI.
    private async Task RunUiBatchReaderAsync(CancellationToken ct)
    {
        var batch = new List<RawPacketCapturedEventArgs>(512);
        var lastFlowsUiUpdate = DateTime.UtcNow;

        try
        {
            while (await _channel.Reader.WaitToReadAsync(ct))
            {
                batch.Clear();

                while (batch.Count < 512 && _channel.Reader.TryRead(out var item))
                    batch.Add(item);

                // Парсимо в фоні
                var parsed = new List<PacketInfo>(batch.Count);
                foreach (var e in batch)
                    parsed.Add(_parser.Parse(e.Timestamp, e.Length, e.RawCapture));

                // Оновлюємо UI (Packets) пачкою
                await System.Windows.Application.Current.Dispatcher.InvokeAsync(() =>
                {
                    foreach (var p in parsed)
                        Packets.Add(p);

                    const int maxRows = 50_000;
                    while (Packets.Count > maxRows)
                        Packets.RemoveAt(0);
                });

                // Аггрегуємо flows (це НЕ UI, можна робити поза Dispatcher)
                foreach (var p in parsed)
                    _flowAggregator.Add(p);

                // Раз на ~1 секунду оновлюємо Flows у UI
                if ((DateTime.UtcNow - lastFlowsUiUpdate).TotalMilliseconds >= 1000)
                {
                    lastFlowsUiUpdate = DateTime.UtcNow;
                    var top = _flowAggregator.SnapshotTop(take: 500);

                    await System.Windows.Application.Current.Dispatcher.InvokeAsync(() =>
                    {
                        UpdateFlows(top);
                    });
                }

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

    // Відповідає за оновлення Flows без втрати SelectedFlow.
    private void UpdateFlows(IReadOnlyList<FlowInfo> snapshot)
    {
        // Швидкий lookup по ключу
        var byKey = snapshot.ToDictionary(f => f.Key);

        // 1. Оновляємо існуючі
        foreach (var existing in Flows.ToList())
        {
            if (byKey.TryGetValue(existing.Key, out var fresh))
            {
                existing.Packets = fresh.Packets;
                existing.Bytes = fresh.Bytes;
                existing.FirstSeen = fresh.FirstSeen;
                existing.LastSeen = fresh.LastSeen;

                byKey.Remove(existing.Key);
            }
            else
            {
                // Flow зник — видаляємо
                Flows.Remove(existing);
            }
        }

        // 2. Додаємо нові flows
        foreach (var f in byKey.Values)
            Flows.Add(f);
    }

}
