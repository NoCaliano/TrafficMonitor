// Відповідає за: прийом raw пакетів, парсинг через IPacketParser, батчинг і показ у DataGrid.
using Application.Abstractions;
using Domain.Models;
using PacketDotNet;
using Presentation.Helpers;
using Presentation.Models;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;

namespace Presentation.ViewModels;

public sealed class MainViewModel : ViewModelBase
{
    private readonly ICaptureDeviceService _deviceService;
    private readonly IPacketCaptureService _captureService;
    private readonly IPacketParser _parser;

    // Відповідає за агрегатор потоків.
    private readonly IFlowAggregator _flowAggregator;

    // ===================== PACKETS (UI) =====================

    public ObservableCollection<PacketInfo> Packets { get; } = new();

    private long _packetNo = 0;
    // Відповідає за відображення пакетів у DataGrid з можливістю фільтрації.
    public ICollectionView PacketsView { get; }

    // Відповідає за вибраний пакет у таблиці (тригерить оновлення дерева протоколів і hex-дампу).
    private PacketInfo? _selectedPacket;
    public PacketInfo? SelectedPacket
    {
        get => _selectedPacket;
        set
        {
            if (!Set(ref _selectedPacket, value))
                return;

            // Якщо вибрали пакет — прибираємо flow, щоб не було конфліктів у деталях
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

    // ===================== FLOWS (UI) =====================

    // Відповідає за список потоків для UI.
    public ObservableCollection<FlowInfo> Flows { get; } = new();

    // Відповідає за вибраний flow у вкладці Flows.
    private FlowInfo? _selectedFlow;
    public FlowInfo? SelectedFlow
    {
        get => _selectedFlow;
        set
        {
            if (!Set(ref _selectedFlow, value))
                return;

            // Відповідає за оновлення доступності Follow-команд при зміні вибору
            RaiseCanExecuteChangedForFlowCommands();
        }
    }

    // ===================== DETAILS =====================

    // Відповідає за контекст (для сумісності зі старими шаблонами, якщо десь використовується).
    public object? DetailsContext => (object?)SelectedPacket ?? SelectedFlow;

    // Відповідає за заголовок деталей (для сумісності).
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

    private FlowDocument _hexDocument = new();
    public FlowDocument HexDocument
    {
        get => _hexDocument;
        private set => Set(ref _hexDocument, value);
    }

    private (int start, int length)? _selectedRange;
    public (int start, int length)? SelectedRange
    {
        get => _selectedRange;
        set
        {
            if (!Set(ref _selectedRange, value)) return;

            // при виборі вузла дерева — підсвічуємо hex
            RebuildHexDocument();
        }
    }

    // Відповідає за кореневий вузол дерева протоколів для вибраного пакета.
    private TreeViewItem? _protocolRoot;
    public TreeViewItem? ProtocolRoot
    {
        get => _protocolRoot;
        private set => Set(ref _protocolRoot, value);
    }

    // ===================== DEVICES / CAPTURE =====================

    public ObservableCollection<CaptureDeviceInfo> Devices { get; } = new();

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

    private readonly Channel<RawPacketCapturedEventArgs> _channel =
        Channel.CreateBounded<RawPacketCapturedEventArgs>(new BoundedChannelOptions(20_000)
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.DropOldest
        });

    private CancellationTokenSource? _captureCts;
    private Task? _uiReaderTask;

    // ===================== LEFT TABS =====================

    // Відповідає за вибрану вкладку зліва (0 = Packets, 1 = Flows, 2 = Stats...).
    private int _leftTabIndex;
    public int LeftTabIndex
    {
        get => _leftTabIndex;
        set => Set(ref _leftTabIndex, value);
    }

    // ===================== FILTERS (FLOW + UI) =====================

    // Відповідає за активний ключ flow-фільтра.
    private FlowKey? _activeFlowFilter;

    // Відповідає за режим reverse (обидва напрямки) чи ні.
    private bool _includeReverseFlow;

    // Відповідає за активний UI-фільтр (Fiddler-style).
    private PacketFilterModel _uiFilter = new();

    // Відповідає за текст активних фільтрів у UI (Flow + UI).
    private string _filtersText = "";
    public string FiltersText
    {
        get => _filtersText;
        private set => Set(ref _filtersText, value);
    }

    // Для сумісності з твоїм XAML (якщо там ще FlowFilterText)
    public string FlowFilterText => FiltersText;

    // Відповідає за команди Follow Flow / Follow Both Directions / Clear.
    public ICommand FollowFlowCommand { get; }
    public ICommand FollowFlowBothDirectionsCommand { get; }
    public ICommand ClearFlowFilterCommand { get; }

    // Відповідає за відкриття вікна Filters.
    public ICommand OpenFiltersCommand { get; }

    // ===================== STATS =====================


    public StatsViewModel Stats { get; }
    private long _capTotalPackets;
    private long _capTotalBytes;
    private DateTime? _capFirstSeen;
    private DateTime? _capLastSeen;
    private readonly Stopwatch _capSw = new();

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


        Stats = new StatsViewModel();


        StartCommand = new AsyncRelayCommand(StartAsync);
        StopCommand = new AsyncRelayCommand(StopAsync);

        // Відповідає за команду відкриття вікна Filters (модально по центру).
        OpenFiltersCommand = new RelayCommand(_ => OpenFiltersDialog());

        // Відповідає за команди фільтрації по flow.
        FollowFlowCommand = new RelayCommand(_ => ApplySelectedFlowFilter(includeReverse: false), _ => SelectedFlow is not null);
        FollowFlowBothDirectionsCommand = new RelayCommand(_ => ApplySelectedFlowFilter(includeReverse: true), _ => SelectedFlow is not null);
        ClearFlowFilterCommand = new RelayCommand(_ => ClearFlowFilter(), _ => _activeFlowFilter is not null || !_uiFilter.IsEmpty);

        LoadDevices();

        _captureService.PacketCaptured += (_, args) =>
        {
            _channel.Writer.TryWrite(args);
        };

        // Відповідає за створення view для фільтрації пакетів (ЄДИНИЙ комбінований фільтр).
        PacketsView = CollectionViewSource.GetDefaultView(Packets);
        PacketsView.Filter = obj =>
        {
            if (obj is not PacketInfo p) return false;
            return PassesCombinedFilters(p);
        };

        RefreshPacketsFilteringUi();
    }

    // ===================== DEVICES =====================

    private void LoadDevices()
    {
        Devices.Clear();
        foreach (var d in _deviceService.GetAllDevices())
            Devices.Add(d);

        SelectedDevice = Devices.FirstOrDefault();
    }

    // ===================== START/STOP =====================

    // Відповідає за запуск захоплення: reset UI, reset flows/stats, запуск reader task і старт capture.
    private async Task StartAsync(CancellationToken ct)
    {
        if (SelectedDevice is null) return;
        if (_captureService.IsRunning) return;

        StatusText = "Starting...";

        // Відповідає за повний reset перед новим захопленням
        _packetNo = 0;
        Packets.Clear();
        Flows.Clear();
        _flowAggregator.Reset();
        Stats.Reset();

        // Скидаємо фільтри
        _activeFlowFilter = null;
        _includeReverseFlow = false;
        _uiFilter = new PacketFilterModel();
        RefreshPacketsFilteringUi();


        _capTotalPackets = 0;
        _capTotalBytes = 0;
        _capFirstSeen = null;
        _capLastSeen = null;
        _capSw.Restart();

        // Скидаємо деталі
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
        _capSw.Stop();
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

    // ===================== READER / UI BATCH =====================

    private async Task RunUiBatchReaderAsync(CancellationToken ct)
    {
        var batch = new List<RawPacketCapturedEventArgs>(512);
        var lastFlowsUiUpdateUtc = DateTime.UtcNow;

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
                {
                    var p = _parser.Parse(e.Timestamp, e.Length, e.RawCapture);

                    // ✅ Номер пакета
                    p.No = Interlocked.Increment(ref _packetNo);

                    parsed.Add(p);
                }

                // parsed вже заповнений — можна рахувати totals
                if (parsed.Count > 0)
                {
                    _capTotalPackets += parsed.Count;

                    long add = 0;
                    for (int i = 0; i < parsed.Count; i++)
                        add += parsed[i].Length;

                    _capTotalBytes += add;

                    // якщо timestamp може бути "Unspecified" — краще нормалізувати тут
                    var min = parsed[0].Timestamp;
                    var max = parsed[0].Timestamp;

                    for (int i = 1; i < parsed.Count; i++)
                    {
                        var t = parsed[i].Timestamp;
                        if (t < min) min = t;
                        if (t > max) max = t;
                    }

                    if (!_capFirstSeen.HasValue || min < _capFirstSeen.Value) _capFirstSeen = min;
                    if (!_capLastSeen.HasValue || max > _capLastSeen.Value) _capLastSeen = max;
                }

                // Аггрегуємо flows (поза UI)
                foreach (var p in parsed)
                    _flowAggregator.Add(p);

                // Оновлюємо UI (Packets) пачкою
                await System.Windows.Application.Current.Dispatcher.InvokeAsync(() =>
                {
                    foreach (var p in parsed)
                        Packets.Add(p);

                    const int maxRows = 50_000;
                    while (Packets.Count > maxRows)
                        Packets.RemoveAt(0);
                });

                // Раз на ~1 секунду оновлюємо Flows і (за потреби) Stats
                var nowUtc = DateTime.UtcNow;
                if ((nowUtc - lastFlowsUiUpdateUtc).TotalMilliseconds >= 1000)
                {
                    var stats = new CaptureStats
                    {
                        TotalPackets = _capTotalPackets,
                        TotalBytes = _capTotalBytes,
                        FirstSeen = _capFirstSeen,
                        LastSeen = _capLastSeen,
                        Elapsed = _capSw.Elapsed
                    };

                    lastFlowsUiUpdateUtc = nowUtc;

                    var top = _flowAggregator.SnapshotTop(take: 500);

                    await System.Windows.Application.Current.Dispatcher.InvokeAsync(() =>
                    {
                        UpdateFlows(top);

                        // Stats перераховуємо тільки якщо dirty
                        Stats.Update(top, stats);

                        // Команда Clear має міняти доступність, якщо UI-фільтр активний
                        (ClearFlowFilterCommand as RelayCommand)?.RaiseCanExecuteChanged();
                    });
                }

                await Task.Yield();
            }
        }
        catch (OperationCanceledException)
        {
            // ok
        }
    }

    // ===================== DETAILS (PACKET) =====================

    private void UpdateDetails(PacketInfo? p)
    {
        ProtocolRoot = null;
        HexDump = "";
        HexDocument = new FlowDocument();

        if (p is null || p.RawBytes is null || p.RawBytes.Length == 0)
            return;

        HexDump = BuildHexDump(p.RawBytes, 16);

        // скидаємо виділення
        _selectedRange = null;
        OnPropertyChanged(nameof(SelectedRange));

        // будуємо документ (без підсвітки)
        HexDocument = BuildHexDocument(p.RawBytes, 16, null);

        try
        {
            var link = (LinkLayers)p.LinkLayerType;
            var parsedPacket = Packet.ParsePacket(link, p.RawBytes);
            ProtocolRoot = PacketTreeBuilder.Build(parsedPacket, p);
        }
        catch (Exception ex)
        {
            ProtocolRoot = new TreeViewItem { Header = $"Parse error: {ex.Message}" };
        }
    }

    private void RebuildHexDocument()
    {
        var bytes = SelectedPacket?.RawBytes;
        if (bytes is null || bytes.Length == 0)
        {
            HexDocument = new FlowDocument(new Paragraph(new Run("")));
            return;
        }

        int highlightStart = -1;
        int highlightEnd = -1;
        if (SelectedRange is { } r)
        {
            highlightStart = Math.Max(0, r.start);
            highlightEnd = Math.Min(bytes.Length, r.start + Math.Max(0, r.length)); // exclusive
            if (highlightStart >= highlightEnd)
            {
                highlightStart = highlightEnd = -1; // нічого
            }
        }

        const int bytesPerLine = 16;

        // Можеш вибрати інший колір, але цей виглядає нормально
        Brush hlBg = Brushes.Khaki;

        var doc = new FlowDocument
        {
            PageWidth = 2000, // щоб не переносило рядки
            LineHeight = 1,
        };

        for (int i = 0; i < bytes.Length; i += bytesPerLine)
        {
            int lineEnd = Math.Min(i + bytesPerLine, bytes.Length);

            var p = new Paragraph
            {
                Margin = new System.Windows.Thickness(0),
            };

            // Offset "0000: "
            p.Inlines.Add(new Run(i.ToString("X4") + ": "));

            // HEX bytes
            for (int j = i; j < i + bytesPerLine; j++)
            {
                if (j < lineEnd)
                {
                    bool isHl = highlightStart >= 0 && j >= highlightStart && j < highlightEnd;

                    var run = new Run(bytes[j].ToString("X2") + " ");
                    if (isHl) run.Background = hlBg;
                    p.Inlines.Add(run);
                }
                else
                {
                    // padding
                    p.Inlines.Add(new Run("   "));
                }
            }

            // Separator
            p.Inlines.Add(new Run(" |"));

            // ASCII
            for (int j = i; j < lineEnd; j++)
            {
                bool isHl = highlightStart >= 0 && j >= highlightStart && j < highlightEnd;

                char c = bytes[j] >= 32 && bytes[j] <= 126 ? (char)bytes[j] : '.';
                var run = new Run(c.ToString());
                if (isHl) run.Background = hlBg;
                p.Inlines.Add(run);
            }

            // Close
            p.Inlines.Add(new Run("|"));

            doc.Blocks.Add(p);
        }

        HexDocument = doc;
    }

    private static string BuildHexDump(byte[] data, int bytesPerLine)
    {
        if (data.Length == 0) return "";

        var sb = new System.Text.StringBuilder(data.Length * 4);

        for (int i = 0; i < data.Length; i += bytesPerLine)
        {
            sb.Append(i.ToString("X4"));
            sb.Append(": ");

            int lineEnd = Math.Min(i + bytesPerLine, data.Length);
            for (int j = i; j < lineEnd; j++)
            {
                sb.Append(data[j].ToString("X2"));
                sb.Append(' ');
            }

            for (int j = lineEnd; j < i + bytesPerLine; j++)
                sb.Append("   ");

            sb.Append(" |");

            for (int j = i; j < lineEnd; j++)
            {
                byte b = data[j];
                sb.Append(b >= 32 && b <= 126 ? (char)b : '.');
            }

            sb.AppendLine("|");
        }

        return sb.ToString();
    }

    private static FlowDocument BuildHexDocument(byte[] data, int bytesPerLine, (int start, int length)? sel)
    {
        int selStart = sel?.start ?? -1;
        int selEnd = sel is null ? -1 : sel.Value.start + Math.Max(0, sel.Value.length); // exclusive

        bool InSel(int idx) => sel is not null && idx >= selStart && idx < selEnd;

        var doc = new FlowDocument
        {
            PagePadding = new System.Windows.Thickness(0)
        };

        var p = new Paragraph
        {
            Margin = new System.Windows.Thickness(0),
            FontFamily = new FontFamily("Consolas"),
            FontSize = 12
        };

        for (int i = 0; i < data.Length; i += bytesPerLine)
        {
            // offset
            p.Inlines.Add(new Run(i.ToString("X4") + ": ") { Foreground = Brushes.Gray });

            int lineEnd = Math.Min(i + bytesPerLine, data.Length);

            // HEX part
            for (int j = i; j < i + bytesPerLine; j++)
            {
                if (j < lineEnd)
                {
                    var run = new Run(data[j].ToString("X2") + " ");
                    if (InSel(j)) run.Background = Brushes.Yellow;
                    p.Inlines.Add(run);
                }
                else
                {
                    p.Inlines.Add(new Run("   "));
                }
            }

            p.Inlines.Add(new Run(" |") { Foreground = Brushes.Gray });

            // ASCII part
            for (int j = i; j < lineEnd; j++)
            {
                byte b = data[j];
                char c = (b >= 32 && b <= 126) ? (char)b : '.';

                var run = new Run(c.ToString());
                if (InSel(j)) run.Background = Brushes.Yellow;
                p.Inlines.Add(run);
            }

            p.Inlines.Add(new Run("|") { Foreground = Brushes.Gray });
            p.Inlines.Add(new LineBreak());
        }

        doc.Blocks.Add(p);
        return doc;
    }



    // ===================== FLOWS (UI UPDATE) =====================

    private void UpdateFlows(IReadOnlyList<FlowInfo> snapshot)
    {
        var byKey = snapshot.ToDictionary(f => f.Key);

        foreach (var existing in Flows.ToList())
        {
            if (byKey.TryGetValue(existing.Key, out var fresh))
            {
                // totals
                existing.Packets = fresh.Packets;
                existing.Bytes = fresh.Bytes;
                existing.FirstSeen = fresh.FirstSeen;
                existing.LastSeen = fresh.LastSeen;

                // direction / local-remote
                existing.Direction = fresh.Direction;
                existing.LocalIp = fresh.LocalIp;
                existing.LocalPort = fresh.LocalPort;
                existing.RemoteIp = fresh.RemoteIp;
                existing.RemotePort = fresh.RemotePort;

                // bi-directional
                existing.PacketsAToB = fresh.PacketsAToB;
                existing.BytesAToB = fresh.BytesAToB;
                existing.PacketsBToA = fresh.PacketsBToA;
                existing.BytesBToA = fresh.BytesBToA;

                // local sent/recv
                existing.SentPackets = fresh.SentPackets;
                existing.SentBytes = fresh.SentBytes;
                existing.RecvPackets = fresh.RecvPackets;
                existing.RecvBytes = fresh.RecvBytes;

                byKey.Remove(existing.Key);
            }
            else
            {
                Flows.Remove(existing);
            }
        }

        foreach (var f in byKey.Values)
            Flows.Add(f);
    }

    // ===================== FLOW FILTER =====================

    private void ApplySelectedFlowFilter(bool includeReverse)
    {
        if (SelectedFlow is null) return;

        _activeFlowFilter = SelectedFlow.Key;
        _includeReverseFlow = includeReverse;

        // Переходимо на Packets вкладку
        LeftTabIndex = 0;

        RefreshPacketsFilteringUi();
        RaiseCanExecuteChangedForFlowCommands();
    }

    private void ClearFlowFilter()
    {
        _activeFlowFilter = null;
        _includeReverseFlow = false;

        // ВАЖЛИВО: також можна скидати UI фільтр тут
        // Зараз - скидаємо тільки flow, але Clear кнопка дозволяється і при UI фільтрі теж.

        RefreshPacketsFilteringUi();
        RaiseCanExecuteChangedForFlowCommands();
    }

    private void RaiseCanExecuteChangedForFlowCommands()
    {
        (FollowFlowCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (FollowFlowBothDirectionsCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (ClearFlowFilterCommand as RelayCommand)?.RaiseCanExecuteChanged();
    }

    private static bool MatchesFlow(PacketInfo p, FlowKey key, bool includeReverse)
    {
        if (!string.Equals(p.Protocol, key.Protocol, StringComparison.OrdinalIgnoreCase))
            return false;

        bool direct =
            p.SrcIp == key.SrcIp &&
            p.DstIp == key.DstIp &&
            p.SrcPort == key.SrcPort &&
            p.DstPort == key.DstPort;

        if (direct) return true;
        if (!includeReverse) return false;

        bool reverse =
            p.SrcIp == key.DstIp &&
            p.DstIp == key.SrcIp &&
            p.SrcPort == key.DstPort &&
            p.DstPort == key.SrcPort;

        return reverse;
    }

    private static string FormatFlow(FlowKey k)
        => $"{k.Protocol} {k.SrcIp}:{k.SrcPort} → {k.DstIp}:{k.DstPort}";

    // ===================== UI FILTER (Fiddler-style) =====================

    // Відповідає за відкриття модального вікна фільтрів і застосування _uiFilter.
    private void OpenFiltersDialog()
    {
        var vm = new Presentation.ViewModels.FiltersViewModel(_uiFilter);

        var win = new Presentation.Views.FiltersWindow
        {
            Owner = System.Windows.Application.Current.MainWindow,
            DataContext = vm
        };

        win.ShowDialog();

        if (!vm.IsApplied)
            return;

        _uiFilter = vm.GetAppliedFilter();
        RefreshPacketsFilteringUi();
        (ClearFlowFilterCommand as RelayCommand)?.RaiseCanExecuteChanged();
    }

    private bool PassesCombinedFilters(PacketInfo p)
    {
        // 1) Flow filter
        if (_activeFlowFilter.HasValue)
        {
            if (!MatchesFlow(p, _activeFlowFilter.Value, _includeReverseFlow))
                return false;
        }

        // 2) UI filter
        if (!_uiFilter.IsEmpty)
        {
            if (!MatchesUiFilter(p, _uiFilter))
                return false;
        }

        return true;
    }

    // Відповідає за синхронізацію тексту фільтрів + Refresh().
    private void RefreshPacketsFilteringUi()
    {
        var parts = new List<string>();

        if (_activeFlowFilter.HasValue)
        {
            parts.Add(_includeReverseFlow
                ? $"Flow(both): {FormatFlow(_activeFlowFilter.Value)}"
                : $"Flow: {FormatFlow(_activeFlowFilter.Value)}");
        }

        if (!_uiFilter.IsEmpty)
            parts.Add("UI Filter: active");

        FiltersText = parts.Count == 0 ? "" : string.Join(" | ", parts);

        PacketsView.Refresh();
        OnPropertyChanged(nameof(FlowFilterText)); // для сумісності
    }

    // Відповідає за перевірку, чи пакет проходить через критерії UI-фільтра (op + value).
    private static bool MatchesUiFilter(PacketInfo p, PacketFilterModel f)
    {
        // Відповідає за порівняння текстових полів (Equals / NotEquals / Contains / NotContains).
        static bool MatchText(string? value, TextMatchOp op, string? pattern)
        {
            if (op == TextMatchOp.Any || string.IsNullOrWhiteSpace(pattern))
                return true;

            value ??= "";
            pattern = pattern.Trim();

            return op switch
            {
                TextMatchOp.Equals => string.Equals(value, pattern, StringComparison.OrdinalIgnoreCase),
                TextMatchOp.NotEquals => !string.Equals(value, pattern, StringComparison.OrdinalIgnoreCase),
                TextMatchOp.Contains => value.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0,
                TextMatchOp.NotContains => value.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) < 0,
                _ => true
            };
        }

        // Відповідає за порівняння числових полів (Equals / NotEquals).
        static bool MatchNumber(int? value, NumberMatchOp op, int? pattern)
        {
            if (op == NumberMatchOp.Any || pattern is null)
                return true;

            return op switch
            {
                NumberMatchOp.Equals => value == pattern,
                NumberMatchOp.NotEquals => value != pattern,
                _ => true
            };
        }

        // ---- IP Src/Dst ----
        if (!MatchText(p.SrcIp, f.SrcIpOp, f.SrcIpValue)) return false;
        if (!MatchText(p.DstIp, f.DstIpOp, f.DstIpValue)) return false;

        // ---- Any IP (Src OR Dst) ----
        if (f.AnyIpOp != TextMatchOp.Any && !string.IsNullOrWhiteSpace(f.AnyIpValue))
        {
            bool srcOk = MatchText(p.SrcIp, f.AnyIpOp, f.AnyIpValue);
            bool dstOk = MatchText(p.DstIp, f.AnyIpOp, f.AnyIpValue);

            // Для "AnyIp" логіка: має співпасти хоча б одна сторона.
            // Навіть для NOT_CONTAINS — це ок: якщо Src не містить => srcOk = true і умова проходить.
            if (!srcOk && !dstOk) return false;
        }

        // ---- Ports ----
        if (!MatchNumber(p.SrcPort, f.SrcPortOp, f.SrcPortValue)) return false;
        if (!MatchNumber(p.DstPort, f.DstPortOp, f.DstPortValue)) return false;

        // ---- Any Port (Src OR Dst) ----
        if (f.AnyPortOp != NumberMatchOp.Any && f.AnyPortValue.HasValue)
        {
            bool srcOk = MatchNumber(p.SrcPort, f.AnyPortOp, f.AnyPortValue);
            bool dstOk = MatchNumber(p.DstPort, f.AnyPortOp, f.AnyPortValue);
            if (!srcOk && !dstOk) return false;
        }

        // ---- Protocol / Info ----
        if (!MatchText(p.Protocol, f.ProtocolOp, f.ProtocolValue)) return false;
        if (!MatchText(p.Info, f.InfoOp, f.InfoValue)) return false;

        // ---- Process ----
        if (!MatchNumber(p.Pid, f.PidOp, f.PidValue)) return false;
        if (!MatchText(p.ProcessName, f.ProcessNameOp, f.ProcessNameValue)) return false;

        // ---- Length range ----
        if (f.MinLength.HasValue && p.Length < f.MinLength.Value) return false;
        if (f.MaxLength.HasValue && p.Length > f.MaxLength.Value) return false;

        // Time range (inclusive) - compare in LOCAL TIME to match what user typed
        if (f.TimeFromUtc.HasValue || f.TimeToUtc.HasValue)
        {
            // Packet timestamp -> local
            var tLocal = p.Timestamp; // вже локальний

            // Filter values were stored as UTC in model, convert them to local for comparison
            DateTime? fromLocal = f.TimeFromUtc?.ToLocalTime();
            DateTime? toLocal = f.TimeToUtc?.ToLocalTime();

            if (fromLocal.HasValue && tLocal < fromLocal.Value) return false;
            if (toLocal.HasValue && tLocal > toLocal.Value) return false;
        }

        return true;
    }
}