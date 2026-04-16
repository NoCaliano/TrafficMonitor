// Відповідає за: прийом raw пакетів, парсинг через IPacketParser, батчинг і показ у DataGrid.
using Application.Abstractions;
using Application.Capture;
using Application.Filtering;
using Application.Networking;
using Domain.Models;
using Infrastructure.Capture;
using Infrastructure.Networking;
using Microsoft.Win32;
using PacketDotNet;
using Presentation.Abstractions;
using Presentation.Helpers;
using Presentation.Models;
using Presentation.Services;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Collections.Generic;

namespace Presentation.ViewModels;

public sealed class MainViewModel : ViewModelBase
{
    private const int PacketsTabIndex = 0;
    private const int FlowsTabIndex = 1;
    private const int EndpointsTabIndex = 2;
    private const int HistoryTabIndex = 3;
    private const int ProcessPacketsTabIndex = 4;
    private const int StatisticsTabIndex = 5;
    private const int PacketProtocolDetailsTabIndex = 0;
    private const int PacketHexDetailsTabIndex = 1;
    private const int PacketDetailsCacheCapacity = 24;

    private readonly ICaptureDeviceService _deviceService;
    private readonly IPacketCaptureService _captureService;
    private readonly IPacketParser _parser;

    // Відповідає за агрегатор потоків.
    private readonly IFlowAggregator _flowAggregator;
    private readonly HostResolutionService _hostResolutionService;
    private readonly IHexDumpService _hexDumpService;
    private readonly IPacketFilterService _packetFilterService;
    private readonly IFlowFilterService _flowFilterService;
    private readonly ICaptureController _captureController;
    private readonly Func<Func<bool>, Action, FlowsViewModel> _flowsFactory;
    private readonly Func<PacketFilterModel, FiltersViewModel> _filtersFactory;
    private readonly Func<NotificationSettingsViewModel> _notificationSettingsFactory;
    private readonly WindowsShellNotificationService _shellNotificationService;
    private readonly TrafficHistoryStore _trafficHistoryStore;

    private readonly RelayCommand _followFlowCommand;
    private readonly RelayCommand _followFlowBothDirectionsCommand;
    private readonly RelayCommand _clearFlowFilterCommand;
    private readonly RelayCommand _copyHexCommand;
    private readonly AsyncRelayCommand _startCommand;
    private readonly AsyncRelayCommand _stopCommand;

    // --- UI batching for incoming packets to avoid flooding the UI thread ---
    private readonly object _pendingLock = new();
    private readonly Queue<PacketInfo> _pendingPackets = new();
    private readonly System.Threading.Timer _flushTimer;
    private const int _flushIntervalMs = 200; // flush UI every 200ms
    private const int _maxPendingPackets = 50_000; // cap pending to avoid OOM
    private const int _maxUiAppendPerFlush = 750; // limit UI work per tick under heavy load
    private const int _collectionResetThreshold = 256; // large batches are cheaper as a single Reset than thousands of Add events
    private long _uiPacketsDropped;

    private bool _uiFilterIsEmpty = true;
    private bool _packetsViewHasFilter;
    private readonly Dictionary<long, int> _packetStorageIndexByNo = new();
    private readonly Dictionary<int, PidPacketIndex> _packetsByPid = new();
    private readonly Dictionary<long, PacketDetailsCacheEntry> _packetDetailsCache = new();
    private CancellationTokenSource? _packetProtocolLoadCts;
    private CancellationTokenSource? _packetHexLoadCts;

    private double _packetsTableFontSize = 12.0;
    public double PacketsTableFontSize
    {
        get => _packetsTableFontSize;
        set => Set(ref _packetsTableFontSize, value);
    }
    public HistoryViewModel History { get; }
    public EndpointsViewModel Endpoints { get; }
    public ProcessPacketsViewModel ProcessPackets { get; }

    private sealed class PidPacketIndex
    {
        private readonly List<PacketInfo> _packets = new();
        private readonly Dictionary<string, PacketInfo> _firstPacketsByDomain = new(StringComparer.OrdinalIgnoreCase);
        private bool _isSorted = true;

        public void Add(PacketInfo packet)
        {
            if (_packets.Count > 0 && ComparePacketsByTimestampAndNo(_packets[^1], packet) > 0)
                _isSorted = false;

            _packets.Add(packet);

            string? domain = NormalizeTimelineDomainKey(TryExtractTimelineDomain(packet));
            if (domain is null)
                return;

            if (!_firstPacketsByDomain.TryGetValue(domain, out var existing)
                || ComparePacketsByTimestampAndNo(packet, existing) < 0)
            {
                _firstPacketsByDomain[domain] = packet;
            }
        }

        public IReadOnlyList<PacketInfo> GetOrderedPackets()
        {
            if (!_isSorted)
            {
                _packets.Sort(ComparePacketsByTimestampAndNo);
                _isSorted = true;
            }

            return _packets;
        }

        public PacketInfo? GetFirstPacketForDomain(string? domain)
        {
            string? normalized = NormalizeTimelineDomainKey(domain);
            return normalized is not null && _firstPacketsByDomain.TryGetValue(normalized, out var packet)
                ? packet
                : null;
        }
    }

    private sealed class PacketDetailsCacheEntry
    {
        public required long PacketNo { get; init; }
        public DateTime LastAccessUtc { get; set; }
        public string? HexDump { get; set; }
        public FlowDocument? BaseHexDocument { get; set; }
        public ProtocolNode? ProtocolRoot { get; set; }
    }



    // ===================== MENUITEM VIEW (UI) =====================
    public bool IsNoColumnVisible { get => _isNoColumnVisible; set => Set(ref _isNoColumnVisible, value); }
    public bool IsTimeColumnVisible { get => _isTimeColumnVisible; set => Set(ref _isTimeColumnVisible, value); }
    public bool IsSrcColumnVisible { get => _isSrcColumnVisible; set => Set(ref _isSrcColumnVisible, value); }
    public bool IsDstColumnVisible { get => _isDstColumnVisible; set => Set(ref _isDstColumnVisible, value); }
    public bool IsProtoColumnVisible { get => _isProtoColumnVisible; set => Set(ref _isProtoColumnVisible, value); }
    public bool IsSPortColumnVisible { get => _isSPortColumnVisible; set => Set(ref _isSPortColumnVisible, value); }
    public bool IsDPortColumnVisible { get => _isDPortColumnVisible; set => Set(ref _isDPortColumnVisible, value); }
    public bool IsLenColumnVisible { get => _isLenColumnVisible; set => Set(ref _isLenColumnVisible, value); }
    public bool IsFlagsColumnVisible { get => _isFlagsColumnVisible; set => Set(ref _isFlagsColumnVisible, value); }
    public bool IsPidColumnVisible { get => _isPidColumnVisible; set => Set(ref _isPidColumnVisible, value); }
    public bool IsProcessColumnVisible { get => _isProcessColumnVisible; set => Set(ref _isProcessColumnVisible, value); }
    public bool IsInfoColumnVisible { get => _isInfoColumnVisible; set => Set(ref _isInfoColumnVisible, value); }

    private bool _isNoColumnVisible = true;
    private bool _isTimeColumnVisible = true;
    private bool _isSrcColumnVisible = true;
    private bool _isDstColumnVisible = true;
    private bool _isProtoColumnVisible = true;
    private bool _isSPortColumnVisible = true;
    private bool _isDPortColumnVisible = true;
    private bool _isLenColumnVisible = true;
    private bool _isFlagsColumnVisible = false;
    private bool _isPidColumnVisible = false;
    private bool _isProcessColumnVisible = false;
    private bool _isInfoColumnVisible = true;

    // ===================== PACKETS (UI) =====================

    public BulkObservableCollection<PacketInfo> Packets { get; } = new();

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
                SelectedFlow = null;
            }
            UpdateDetails(value);

            OnPropertyChanged(nameof(DetailsContext));
            OnPropertyChanged(nameof(DetailsTitle));
        }
    }

    // ===================== FLOWS (UI) =====================

    // Відповідає за список потоків для UI.
    private readonly FlowsViewModel _flowsVm;
    public ObservableCollection<FlowInfo> Flows => _flowsVm.Flows;

    // Відповідає за вибраний flow у вкладці Flows (delegated to _flowsVm).
    public FlowInfo? SelectedFlow
    {
        get => _flowsVm.SelectedFlow;
        set
        {
            _flowsVm.SelectedFlow = value;
            OnPropertyChanged(nameof(SelectedFlow));
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
        set
        {
            if (!Set(ref _hexDump, value))
                return;

            _copyHexCommand.RaiseCanExecuteChanged();
        }
    }

    private FlowDocument _hexDocument = new();
    public FlowDocument HexDocument
    {
        get => _hexDocument;
        private set => Set(ref _hexDocument, value);
    }

    private int _packetDetailsTabIndex;
    public int PacketDetailsTabIndex
    {
        get => _packetDetailsTabIndex;
        set
        {
            if (!Set(ref _packetDetailsTabIndex, value))
                return;

            CancelPendingPacketDetailsLoad();
            EnsureSelectedPacketDetailsLoaded(rebuildHexDocumentForCurrentRange: value == PacketHexDetailsTabIndex);
        }
    }

    private (int start, int length)? _selectedRange;
    public (int start, int length)? SelectedRange
    {
        get => _selectedRange;
        set => SetSelectedRange(value, refreshHexDocument: true);
    }

    // Відповідає за кореневий вузол дерева протоколів для вибраного пакета.
    private ProtocolNode? _protocolRoot;
    public ProtocolNode? ProtocolRoot
    {
        get => _protocolRoot;
        private set
        {
            if (!Set(ref _protocolRoot, value))
                return;

            OnPropertyChanged(nameof(ProtocolRoots));
        }
    }

    public IEnumerable<ProtocolNode> ProtocolRoots => ProtocolRoot is null
        ? Array.Empty<ProtocolNode>()
        : new[] { ProtocolRoot };

    // ===================== DEVICES / CAPTURE =====================

    public ObservableCollection<CaptureDeviceInfo> Devices { get; } = new();

    private CaptureDeviceInfo? _selectedDevice;
    public CaptureDeviceInfo? SelectedDevice
    {
        get => _selectedDevice;
        set
        {
            if (!Set(ref _selectedDevice, value))
                return;

            RefreshCaptureCommandStates();
        }
    }

    private string? _bpfFilter;
    public string? BpfFilter
    {
        get => _bpfFilter;
        set => Set(ref _bpfFilter, value);
    }

    private string _displayFilterText = "";
    public string DisplayFilterText
    {
        get => _displayFilterText;
        set
        {
            if (!Set(ref _displayFilterText, value))
                return;

            ApplyDisplayFilterText();
        }
    }

    private string _displayFilterError = "";
    public string DisplayFilterError
    {
        get => _displayFilterError;
        private set
        {
            if (!Set(ref _displayFilterError, value))
                return;

            OnPropertyChanged(nameof(HasDisplayFilterError));
            OnPropertyChanged(nameof(DisplayFilterHint));
        }
    }

    public bool HasDisplayFilterError => !string.IsNullOrWhiteSpace(DisplayFilterError);

    public string DisplayFilterHint => HasDisplayFilterError
        ? DisplayFilterError
        : "Examples: arp, dns, tcp && ip.addr == 1.1.1.1, tcp.port == 443, process contains chrome";

    public IReadOnlyList<string> DisplayFilterExamples { get; } =
    [
        "arp",
        "dns",
        "tcp && ip.addr == 1.1.1.1",
        "tcp.port == 443",
        "process contains chrome",
        "frame.len > 512 && not arp"
    ];

    private bool _isDisplayFilterExamplesOpen;
    public bool IsDisplayFilterExamplesOpen
    {
        get => _isDisplayFilterExamplesOpen;
        set => Set(ref _isDisplayFilterExamplesOpen, value);
    }

    private string? _selectedDisplayFilterExample;
    public string? SelectedDisplayFilterExample
    {
        get => _selectedDisplayFilterExample;
        set
        {
            if (!Set(ref _selectedDisplayFilterExample, value))
                return;

            if (string.IsNullOrWhiteSpace(value))
                return;

            DisplayFilterText = value;
            IsDisplayFilterExamplesOpen = false;
            _selectedDisplayFilterExample = null;
            OnPropertyChanged();
        }
    }

    private string _statusText = "Idle";
    public string StatusText
    {
        get => _statusText;
        set => Set(ref _statusText, value);
    }

    public ICommand StartCommand { get; }
    public ICommand StopCommand { get; }
    public ICommand ApplyBpfCommand { get; }
    public ICommand SaveCaptureCommand { get; }
    public ICommand OpenCaptureCommand { get; }
    public ICommand QuitApplicationCommand { get; }

    // ===================== LEFT TABS =====================

    // Відповідає за вибрану вкладку основного контенту.
    private int _leftTabIndex;
    public int LeftTabIndex
    {
        get => _leftTabIndex;
        set
        {
            if (!Set(ref _leftTabIndex, value))
                return;

            Stats.IsViewActive = value == StatisticsTabIndex;
        }
    }

    // ===================== FILTERS (FLOW + UI) =====================

    // Flow filter is handled by FlowFilterService

    private PacketFilterModel _uiFilter = new();
    private Func<PacketInfo, bool>? _uiFilterPredicate;
    private Func<PacketInfo, bool>? _displayFilterPredicate;
    private bool _hasValidDisplayFilter;

    // Відповідає за текст активних фільтрів у UI (Flow + UI).
    private string _filtersText = "";
    public string FiltersText
    {
        get => _filtersText;
        private set => Set(ref _filtersText, value);
    }

    // Для сумісності з твоїм XAML (якщо там ще FlowFilterText)
    public string FlowFilterText => FiltersText;

    public bool IsFlowFollowActive => _flowFilterService.IsActive;

    // Відповідає за команди Follow Flow / Follow Both Directions / Clear.
    public ICommand FollowFlowCommand => _followFlowCommand;
    public ICommand FollowFlowBothDirectionsCommand => _followFlowBothDirectionsCommand;
    public ICommand ClearFlowFilterCommand => _clearFlowFilterCommand;
    public ICommand ShowPacketsCommand { get; }
    public ICommand OpenFiltersCommand { get; }
    public ICommand OpenNotificationSettingsCommand { get; }
    public ICommand ShowFlowsCommand { get; }
    public ICommand ShowEndpointsCommand { get; }
    public ICommand ShowHistoryCommand { get; }
    public ICommand OpenStatisticsCommand { get; }
    public ICommand ShowProcessPacketsCommand { get; }
    public ICommand SelectPreviousPacketCommand { get; }
    public ICommand SelectNextPacketCommand { get; }
    public ICommand SelectFirstPacketCommand { get; }
    public ICommand SelectLastPacketCommand { get; }
    public ICommand ZoomInPacketsCommand { get; }
    public ICommand ZoomOutPacketsCommand { get; }
    public ICommand ToggleDisplayFilterExamplesCommand { get; }
    public ICommand CopyHexCommand => _copyHexCommand;

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
        HistoryViewModel history,
        EndpointsViewModel endpoints,
        ProcessPacketsViewModel processPackets,
        IFlowAggregator flowAggregator,
        HostResolutionService hostResolutionService,
        IHexDumpService hexDumpService,
        IPacketFilterService packetFilterService,
        IFlowFilterService flowFilterService,
        ICaptureController captureController,
        StatsViewModel stats,
        Func<Func<bool>, Action, FlowsViewModel> flowsFactory,
        Func<PacketFilterModel, FiltersViewModel> filtersFactory,
        Func<NotificationSettingsViewModel> notificationSettingsFactory,
        WindowsShellNotificationService shellNotificationService,
        TrafficHistoryStore trafficHistoryStore)
    {
        _deviceService = deviceService;
        _captureService = captureService;
        _flowAggregator = flowAggregator;
        _hostResolutionService = hostResolutionService;
        _parser = parser;
        History = history;
        Endpoints = endpoints;
        ProcessPackets = processPackets;
        _hexDumpService = hexDumpService;
        _packetFilterService = packetFilterService;
        _flowFilterService = flowFilterService;
        _captureController = captureController;
        Stats = stats;
        _flowsFactory = flowsFactory;
        _filtersFactory = filtersFactory;
        _notificationSettingsFactory = notificationSettingsFactory;
        _shellNotificationService = shellNotificationService;
        _trafficHistoryStore = trafficHistoryStore;


        _startCommand = new AsyncRelayCommand(StartAsync, CanStartCapture);
        _stopCommand = new AsyncRelayCommand(StopAsync, CanStopCapture);
        StartCommand = _startCommand;
        StopCommand = _stopCommand;
        ApplyBpfCommand = new AsyncRelayCommand(ApplyBpfAsync);
        SaveCaptureCommand = new AsyncRelayCommand(SaveCaptureAsync);
        OpenCaptureCommand = new AsyncRelayCommand(OpenCaptureAsync);
        QuitApplicationCommand = new AsyncRelayCommand(QuitApplicationAsync);
        _shellNotificationService.ConfigureMenu(
            isCapturing: () => _captureService.IsRunning,
            startCommand: StartCommand,
            stopCommand: StopCommand,
            quitCommand: QuitApplicationCommand);

        // Відповідає за команду відкриття вікна Filters (модально по центру).
        OpenFiltersCommand = new RelayCommand(_ => OpenFiltersDialog());
        OpenNotificationSettingsCommand = new RelayCommand(_ => OpenNotificationSettingsDialog());
        ShowFlowsCommand = new RelayCommand(_ => ShowFlows());
        ShowEndpointsCommand = new RelayCommand(_ => ShowEndpoints());
        ShowHistoryCommand = new RelayCommand(_ => ShowHistory());
        OpenStatisticsCommand = new RelayCommand(_ => ShowStatistics());
        ShowPacketsCommand = new RelayCommand(_ => ShowPackets());
        ShowProcessPacketsCommand = new RelayCommand(_ => ShowProcessPackets());
        SelectPreviousPacketCommand = new RelayCommand(_ => SelectPacketByOffset(-1));
        SelectNextPacketCommand = new RelayCommand(_ => SelectPacketByOffset(1));
        SelectFirstPacketCommand = new RelayCommand(_ => SelectFirstPacket());
        SelectLastPacketCommand = new RelayCommand(_ => SelectLastPacket());
        ZoomInPacketsCommand = new RelayCommand(_ => ZoomPackets(+1));
        ZoomOutPacketsCommand = new RelayCommand(_ => ZoomPackets(-1));
        ToggleDisplayFilterExamplesCommand = new RelayCommand(_ => ToggleDisplayFilterExamples());
        ProcessPackets.ConfigureActions(
            ApplyProcessPacketFilter,
            FocusPacketForTimelineEvent,
            ShowPacketsForConversation,
            ShowPacketsForSessionCluster,
            message => StatusText = message);
        Endpoints.ConfigureActions(ShowPacketsForHost);

        // FlowsViewModel will manage flow selection and flow commands
        _flowsVm = _flowsFactory(() => !_uiFilterIsEmpty, () => RefreshPacketsFilteringUi());

        _followFlowCommand = new RelayCommand(
            _ =>
            {
                if (_flowsVm.FollowFlowCommand.CanExecute(null))
                    _flowsVm.FollowFlowCommand.Execute(null);
                ShowPackets();
            },
            _ => _flowsVm.FollowFlowCommand.CanExecute(null));

        _followFlowBothDirectionsCommand = new RelayCommand(
            _ =>
            {
                if (_flowsVm.FollowFlowBothDirectionsCommand.CanExecute(null))
                    _flowsVm.FollowFlowBothDirectionsCommand.Execute(null);
                ShowPackets();
            },
            _ => _flowsVm.FollowFlowBothDirectionsCommand.CanExecute(null));

        _clearFlowFilterCommand = new RelayCommand(
            _ =>
            {
                if (_flowsVm.ClearFlowFilterCommand.CanExecute(null))
                    _flowsVm.ClearFlowFilterCommand.Execute(null);
            },
            _ => _flowFilterService.IsActive);

        _copyHexCommand = new RelayCommand(
            _ => CopyHexToClipboard(),
            _ => !string.IsNullOrWhiteSpace(HexDump));


        LoadDevices();
        // subscribe to capture controller events
        // We only enqueue parsed packets here to avoid heavy work on capture thread or UI thread.
        _captureController.PacketsParsed += parsed =>
        {
            lock (_pendingLock)
            {
                // avoid growing beyond cap
                int canAdd = Math.Max(0, _maxPendingPackets - _pendingPackets.Count);
                if (canAdd <= 0)
                {
                    Interlocked.Add(ref _uiPacketsDropped, parsed.Count);
                    return;
                }

                int accepted = Math.Min(parsed.Count, canAdd);
                for (int i = 0; i < accepted; i++)
                {
                    _pendingPackets.Enqueue(parsed[i]);
                }

                int dropped = parsed.Count - accepted;
                if (dropped > 0)
                    Interlocked.Add(ref _uiPacketsDropped, dropped);
            }
        };

        _captureController.FlowsAndStatsAvailable += (top, stats) =>
        {
            // flows/stats are less frequent; marshal to UI thread but keep lightweight
            System.Windows.Application.Current.Dispatcher.BeginInvoke(new Action(() =>
            {
                UpdateFlows(top);
                Stats.Update(top, stats);
                (ClearFlowFilterCommand as RelayCommand)?.RaiseCanExecuteChanged();
            }));
        };

        // create periodic flush timer (callbacks on ThreadPool)
        _flushTimer = new System.Threading.Timer(_ => FlushPending(), null, System.Threading.Timeout.Infinite, System.Threading.Timeout.Infinite);

        // Відповідає за створення view для фільтрації пакетів.
        // Важливо: не тримаємо активний Filter коли фільтрів немає (це дуже дорого на великій колекції).
        PacketsView = CollectionViewSource.GetDefaultView(Packets);

        RefreshPacketsFilteringUi();
        RefreshCaptureCommandStates();
    }

    private async Task SaveCaptureAsync(CancellationToken ct)
    {
        // Export currently displayed packets (i.e., what the CollectionView shows with filters applied).
        var snapshot = PacketsView.Cast<PacketInfo>().ToList();
        if (snapshot.Count == 0)
        {
            MessageBox.Show("No packets to save.", "TrafficMonitor", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var dlg = new SaveFileDialog
        {
            Title = "Save capture",
            Filter = "pcap (*.pcap)|*.pcap|All files (*.*)|*.*",
            DefaultExt = ".pcap",
            AddExtension = true,
            FileName = $"capture_{DateTime.Now:yyyyMMdd_HHmmss}.pcap"
        };

        if (dlg.ShowDialog(System.Windows.Application.Current.MainWindow) != true)
            return;

        string path = dlg.FileName;

        try
        {
            StatusText = $"Saving {snapshot.Count:N0} packets...";

            await Task.Run(() =>
            {
                ct.ThrowIfCancellationRequested();
                PcapFileWriter.Write(path, snapshot);
            }, ct);

            StatusText = $"Saved: {Path.GetFileName(path)}";
        }
        catch (OperationCanceledException)
        {
            StatusText = "Save canceled";
        }
        catch (Exception ex)
        {
            StatusText = "Save failed";
            MessageBox.Show(ex.Message, "Save capture failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async Task OpenCaptureAsync(CancellationToken ct)
    {
        var dlg = new OpenFileDialog
        {
            Title = "Open capture",
            Filter = "pcap (*.pcap)|*.pcap|All files (*.*)|*.*",
            DefaultExt = ".pcap",
            Multiselect = false
        };

        if (dlg.ShowDialog(System.Windows.Application.Current.MainWindow) != true)
            return;

        string path = dlg.FileName;

        try
        {
            if (_captureService.IsRunning)
                await StopAsync(CancellationToken.None);

            StatusText = "Opening...";

            ProcessPackets.FinalizeCurrentSession();

            // Reset UI/state (similar to StartAsync, but without starting capture)
            _packetNo = 0;
            _captureController.ResetSessionState();
            RawBytesStore.Clear();
            Packets.Clear();
            ResetPacketIndices();
            ClearPacketDetailsCache();
            ProcessPackets.BeginCaptureSession(emitNotifications: false);
            ProcessPackets.Reset();
            Endpoints.Reset();
            _flowsVm.Flows.Clear();
            _flowAggregator.Reset();
            Stats.Reset();

            _flowFilterService.Clear();
            _uiFilter = new PacketFilterModel();
            DisplayFilterText = "";
            RefreshPacketsFilteringUi();

            _uiPacketsDropped = 0;
            _capSw.Reset();
            lock (_pendingLock)
                _pendingPackets.Clear();

            SelectedPacket = null;
            ProtocolRoot = null;
            HexDump = "";

            var loaded = await Task.Run(() =>
            {
                ct.ThrowIfCancellationRequested();

                var packets = PcapFileReader.Read(path);
                var parsed = new List<PacketInfo>(packets.Count);

                long totalBytes = 0;
                DateTime? first = null;
                DateTime? last = null;

                foreach (var pkt in packets)
                {
                    ct.ThrowIfCancellationRequested();

                    var info = _parser.Parse(pkt.TimestampUtc, pkt.Data.Length, new RawPacketData(pkt.Data, pkt.LinkLayerType), PacketParseProfile.Full);
                    info.No = Interlocked.Increment(ref _packetNo);

                    parsed.Add(info);
                    totalBytes += info.Length;

                    first = first is null || info.Timestamp < first ? info.Timestamp : first;
                    last = last is null || info.Timestamp > last ? info.Timestamp : last;

                    _flowAggregator.Add(info);
                    _hostResolutionService.Observe(info);
                }

                return (parsed, totalBytes, first, last);
            }, ct);

            IndexPackets(loaded.parsed, 0);
            Packets.ReplaceAll(loaded.parsed);

            var pidAgg = loaded.parsed
                .Where(p => p.Pid is int pid && pid > 0 && !string.IsNullOrWhiteSpace(p.ProcessName))
                .GroupBy(p => new { Pid = p.Pid!.Value, p.ProcessName })
                .Select(g => new { g.Key.Pid, g.Key.ProcessName, Count = (long)g.Count(), Bytes = g.Sum(x => (long)x.Length) })
                .OrderByDescending(x => x.Bytes)
                .ToList();

            foreach (var a in pidAgg)
                ProcessPackets.SeedProcessSummary(a.Pid, a.ProcessName, a.Count, a.Bytes);

            Endpoints.ObservePackets(loaded.parsed);

            var top = _flowAggregator.SnapshotTop(take: 500);
            _flowsVm.UpdateFlows(top);

            var elapsed = (loaded.first.HasValue && loaded.last.HasValue)
                ? (loaded.last.Value - loaded.first.Value)
                : TimeSpan.Zero;

            Stats.Update(top, new CaptureStats
            {
                TotalPackets = loaded.parsed.Count,
                TotalBytes = loaded.totalBytes,
                FirstSeen = loaded.first,
                LastSeen = loaded.last,
                Elapsed = elapsed
            });

            StatusText = $"Loaded {loaded.parsed.Count:N0} packets";
        }
        catch (OperationCanceledException)
        {
            StatusText = "Open canceled";
        }
        catch (Exception ex)
        {
            StatusText = "Open failed";
            MessageBox.Show(ex.Message, "Open capture failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    // ===================== DEVICES =====================

    private void LoadDevices()
    {
        Devices.Clear();
        foreach (var d in _deviceService.GetAllDevices())
            Devices.Add(d);

        SelectedDevice = Devices.FirstOrDefault();
    }

    private bool CanStartCapture() => SelectedDevice is not null && !_captureService.IsRunning;

    private bool CanStopCapture() => _captureService.IsRunning;

    private void RefreshCaptureCommandStates()
    {
        _startCommand.RaiseCanExecuteChanged();
        _stopCommand.RaiseCanExecuteChanged();
    }

    private async Task QuitApplicationAsync(CancellationToken ct)
    {
        try
        {
            if (_captureService.IsRunning)
            {
                StatusText = "Stopping capture before exit...";
                await StopAsync(ct);
            }

            System.Windows.Application.Current.Shutdown();
        }
        catch (OperationCanceledException)
        {
            StatusText = "Quit canceled.";
        }
        catch (Exception ex)
        {
            StatusText = "Quit failed";
            MessageBox.Show(ex.Message, "Quit failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    // ===================== START/STOP =====================

    // Відповідає за запуск захоплення: reset UI, reset flows/stats, запуск reader task і старт capture.
    private async Task StartAsync(CancellationToken ct)
    {
        if (SelectedDevice is null) return;
        if (_captureService.IsRunning) return;

        try
        {
            StatusText = "Starting...";

            ProcessPackets.FinalizeCurrentSession();

            // Відповідає за повний reset перед новим захопленням
            _packetNo = 0;
            _captureController.ResetSessionState();
            RawBytesStore.Clear();
            Packets.Clear();
            ResetPacketIndices();
            ClearPacketDetailsCache();
            ProcessPackets.BeginCaptureSession(emitNotifications: true);
            ProcessPackets.Reset();
            Endpoints.Reset();
            _flowsVm.Flows.Clear();
            _flowAggregator.Reset();
            Stats.Reset();

            // Скидаємо фільтри
            _flowFilterService.Clear();
            _uiFilter = new PacketFilterModel();
            DisplayFilterText = "";
            RefreshPacketsFilteringUi();


            _capTotalPackets = 0;
            _capTotalBytes = 0;
            _capFirstSeen = null;
            _capLastSeen = null;
            _uiPacketsDropped = 0;
            _capSw.Restart();
            lock (_pendingLock)
                _pendingPackets.Clear();

            // Скидаємо деталі
            SelectedPacket = null;
            ProtocolRoot = null;
            HexDump = "";

            await _captureController.StartAsync(SelectedDevice.Id, BpfFilter, ct);

            // start periodic flush timer
            _flushTimer.Change(_flushIntervalMs, _flushIntervalMs);

            StatusText = "Capturing";
        }
        finally
        {
            RefreshCaptureCommandStates();
        }
    }

    private async Task StopAsync(CancellationToken ct)
    {
        if (!_captureService.IsRunning) return;

        try
        {
            StatusText = "Stopping...";
            _capSw.Stop();
            await _captureController.StopAsync(ct);

            // stop flush timer and flush remaining
            _flushTimer.Change(System.Threading.Timeout.Infinite, System.Threading.Timeout.Infinite);
            FlushPending(drainAll: true);
            ProcessPackets.FinalizeCurrentSession();
            PersistCurrentSessionHistory();

            StatusText = "Idle";
        }
        finally
        {
            RefreshCaptureCommandStates();
        }
    }

    private async Task ApplyBpfAsync(CancellationToken ct)
    {
        // Quick-apply BPF: restart capture controller with new filter while preserving UI state.
        if (SelectedDevice is null)
            return;

        try
        {
            if (_captureController.IsRunning)
            {
                // stop and restart capture with new filter
                await _captureController.StopAsync(CancellationToken.None);
                await _captureController.StartAsync(SelectedDevice.Id, BpfFilter, CancellationToken.None);

                StatusText = string.IsNullOrWhiteSpace(BpfFilter) ? "Capturing" : $"Capturing (BPF: {BpfFilter})";
            }
        }
        catch (Exception ex)
        {
            // keep UI responsive; show error
            StatusText = $"Error applying BPF: {ex.Message}";
        }
    }

    private void FlushPending(bool drainAll = false)
    {
        List<PacketInfo> toFlush;
        int pendingAfterDequeue;
        lock (_pendingLock)
        {
            if (_pendingPackets.Count == 0) return;

            int take = drainAll ? _pendingPackets.Count : Math.Min(_pendingPackets.Count, _maxUiAppendPerFlush);
            toFlush = new List<PacketInfo>(take);
            for (int i = 0; i < take; i++)
                toFlush.Add(_pendingPackets.Dequeue());

            pendingAfterDequeue = _pendingPackets.Count;
        }

        void flushAction()
        {
            ProcessPackets.PrepareForFlush();

            // Process analytics on the full batch first. Risk/timeline data should not depend
            // on whether a row survives UI throttling.
            for (int i = 0; i < toFlush.Count; i++)
                ProcessPackets.ObservePacket(toFlush[i]);

            Endpoints.ObservePackets(toFlush);

            if (toFlush.Count > 0)
            {
                int startStorageIndex = Packets.Count;
                IndexPackets(toFlush, startStorageIndex);
                bool useReset = !_packetsViewHasFilter && toFlush.Count >= _collectionResetThreshold;
                Packets.AddRange(toFlush, useReset: useReset);
            }


            // Add sparkline samples once per flush interval per PID (instead of per packet)
            ProcessPackets.CompleteSamplingWindow();

            if (!_captureService.IsRunning)
                return;

            var dropped = Interlocked.Read(ref _uiPacketsDropped);
            if (dropped > 0)
                StatusText = pendingAfterDequeue > 0
                    ? $"Capturing (render queue {pendingAfterDequeue:N0}, overflow skipped {dropped:N0})"
                    : $"Capturing (overflow skipped {dropped:N0})";
            else if (_captureService.IsRunning)
                StatusText = pendingAfterDequeue > 0
                    ? $"Capturing (render queue {pendingAfterDequeue:N0})"
                    : "Capturing";
        }

        var dispatcher = System.Windows.Application.Current.Dispatcher;
        if (drainAll)
        {
            if (dispatcher.CheckAccess())
                flushAction();
            else
                dispatcher.Invoke(flushAction);
            return;
        }

        dispatcher.BeginInvoke(new Action(flushAction));
    }



    // CaptureController.RunReaderAsync handles batching, parsing and flow aggregation.

    // ===================== DETAILS (PACKET) =====================

    private void UpdateDetails(PacketInfo? p)
    {
        CancelPendingPacketDetailsLoad();
        ProtocolRoot = null;
        HexDump = "";
        HexDocument = CreateStatusFlowDocument(string.Empty);
        SetSelectedRange(null, refreshHexDocument: false);

        if (p is null)
            return;

        EnsureSelectedPacketDetailsLoaded(rebuildHexDocumentForCurrentRange: true);
    }

    private void RebuildHexDocument()
    {
        if (SelectedPacket is null)
            return;

        EnsureSelectedPacketHexDetailsLoaded(SelectedPacket, rebuildHexDocumentForCurrentRange: true);
    }

    private void EnsureSelectedPacketDetailsLoaded(bool rebuildHexDocumentForCurrentRange = false)
    {
        if (SelectedPacket is null)
            return;

        EnsureSelectedPacketProtocolDetailsLoaded(SelectedPacket);
        EnsureSelectedPacketHexDetailsLoaded(SelectedPacket, rebuildHexDocumentForCurrentRange);
    }

    private async void EnsureSelectedPacketProtocolDetailsLoaded(PacketInfo packet)
    {
        var entry = GetOrCreatePacketDetailsCacheEntry(packet);
        if (entry.ProtocolRoot is not null)
        {
            if (IsSelectedPacket(packet))
                ProtocolRoot = entry.ProtocolRoot;

            return;
        }

        if (!TryGetPacketBytes(packet, out var bytes))
        {
            var noDataNode = CreateStatusProtocolNode("No packet data.");
            entry.ProtocolRoot = noDataNode;
            if (IsSelectedPacket(packet))
                ProtocolRoot = noDataNode;

            return;
        }

        if (IsSelectedPacket(packet))
            ProtocolRoot = CreateStatusProtocolNode("Loading packet structure...");

        var token = ResetPacketProtocolLoadToken();
        try
        {
            var protocolRoot = await Task.Run(() => BuildProtocolRoot(packet, bytes), token);
            if (token.IsCancellationRequested)
                return;

            entry.ProtocolRoot = protocolRoot;
            TouchPacketDetailsCacheEntry(entry);

            if (IsSelectedPacket(packet))
                ProtocolRoot = protocolRoot;
        }
        catch (OperationCanceledException)
        {
        }
    }

    private async void EnsureSelectedPacketHexDetailsLoaded(PacketInfo packet, bool rebuildHexDocumentForCurrentRange)
    {
        var entry = GetOrCreatePacketDetailsCacheEntry(packet);
        if (!TryGetPacketBytes(packet, out var bytes))
        {
            HexDump = "";
            HexDocument = CreateStatusFlowDocument("No packet data.");
            return;
        }

        if (entry.HexDump is null)
        {
            if (IsSelectedPacket(packet))
            {
                HexDump = "";
                HexDocument = CreateStatusFlowDocument("Loading hex dump...");
            }

            var token = ResetPacketHexLoadToken();
            try
            {
                entry.HexDump = await Task.Run(() => _hexDumpService.BuildHexDump(bytes, 16), token);
                if (token.IsCancellationRequested)
                    return;

                TouchPacketDetailsCacheEntry(entry);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }

        if (!IsSelectedPacket(packet))
            return;

        HexDump = entry.HexDump ?? string.Empty;
        HexDocument = BuildHexDocument(packet, entry, bytes, rebuildHexDocumentForCurrentRange);
    }

    private FlowDocument BuildHexDocument(PacketInfo packet, PacketDetailsCacheEntry entry, byte[] bytes, bool rebuildHexDocumentForCurrentRange)
    {
        TouchPacketDetailsCacheEntry(entry);

        if (SelectedRange is { } range)
            return _hexDumpService.BuildHexDocumentHighlighted(bytes, 16, range);

        if (rebuildHexDocumentForCurrentRange || entry.BaseHexDocument is null)
            entry.BaseHexDocument = _hexDumpService.BuildHexDocument(bytes, 16, null);

        return entry.BaseHexDocument;
    }

    private static ProtocolNode BuildProtocolRoot(PacketInfo packet, byte[] bytes)
    {
        try
        {
            var link = (LinkLayers)packet.LinkLayerType;
            var parsedPacket = Packet.ParsePacket(link, bytes);
            return PacketTreeBuilder.Build(parsedPacket, packet, bytes);
        }
        catch (Exception ex)
        {
            return CreateStatusProtocolNode($"Parse error: {ex.Message}");
        }
    }

    private static FlowDocument CreateStatusFlowDocument(string message)
        => new(new Paragraph(new Run(message ?? string.Empty)));

    private static ProtocolNode CreateStatusProtocolNode(string message)
        => new() { Header = message ?? string.Empty, IsExpanded = true };

    private void SetSelectedRange((int start, int length)? range, bool refreshHexDocument)
    {
        if (!Set(ref _selectedRange, range))
            return;

        if (refreshHexDocument)
            RebuildHexDocument();
    }

    private static bool TryGetPacketBytes(PacketInfo packet, out byte[] bytes)
    {
        bytes = packet.RawBytes ?? (packet.RawBytesId is null ? Array.Empty<byte>() : RawBytesStore.Get(packet.RawBytesId) ?? Array.Empty<byte>());
        return bytes.Length > 0;
    }

    private bool IsSelectedPacket(PacketInfo packet)
        => SelectedPacket?.No == packet.No;

    private PacketDetailsCacheEntry GetOrCreatePacketDetailsCacheEntry(PacketInfo packet)
    {
        if (!_packetDetailsCache.TryGetValue(packet.No, out var entry))
        {
            entry = new PacketDetailsCacheEntry
            {
                PacketNo = packet.No,
                LastAccessUtc = DateTime.UtcNow
            };
            _packetDetailsCache[packet.No] = entry;
            TrimPacketDetailsCacheIfNeeded();
            return entry;
        }

        TouchPacketDetailsCacheEntry(entry);
        return entry;
    }

    private void TouchPacketDetailsCacheEntry(PacketDetailsCacheEntry entry)
        => entry.LastAccessUtc = DateTime.UtcNow;

    private void TrimPacketDetailsCacheIfNeeded()
    {
        while (_packetDetailsCache.Count > PacketDetailsCacheCapacity)
        {
            var oldest = _packetDetailsCache.Values
                .OrderBy(candidate => candidate.LastAccessUtc)
                .FirstOrDefault();

            if (oldest is null)
                break;

            _packetDetailsCache.Remove(oldest.PacketNo);
        }
    }

    private void ClearPacketDetailsCache()
    {
        CancelPendingPacketDetailsLoad();
        _packetDetailsCache.Clear();
    }

    private CancellationToken ResetPacketProtocolLoadToken()
    {
        CancelPendingPacketProtocolLoad();
        _packetProtocolLoadCts = new CancellationTokenSource();
        return _packetProtocolLoadCts.Token;
    }

    private CancellationToken ResetPacketHexLoadToken()
    {
        CancelPendingPacketHexLoad();
        _packetHexLoadCts = new CancellationTokenSource();
        return _packetHexLoadCts.Token;
    }

    private void CancelPendingPacketDetailsLoad()
    {
        CancelPendingPacketProtocolLoad();
        CancelPendingPacketHexLoad();
    }

    private void CancelPendingPacketProtocolLoad()
    {
        if (_packetProtocolLoadCts is null)
            return;

        _packetProtocolLoadCts.Cancel();
        _packetProtocolLoadCts.Dispose();
        _packetProtocolLoadCts = null;
    }

    private void CancelPendingPacketHexLoad()
    {
        if (_packetHexLoadCts is null)
            return;

        _packetHexLoadCts.Cancel();
        _packetHexLoadCts.Dispose();
        _packetHexLoadCts = null;
    }


    // ===================== FLOWS (UI UPDATE) =====================
    private void UpdateFlows(IReadOnlyList<FlowInfo> snapshot)
    {
        _flowsVm.UpdateFlows(snapshot);
    }

    // ===================== FLOW FILTER =====================

    private void RaiseCanExecuteChangedForFlowCommands()
    {
        _flowsVm.RaiseCanExecuteChangedForFlowCommands();
    }



    // ===================== UI FILTER (Fiddler-style) =====================

    // Відповідає за відкриття модального вікна фільтрів і застосування _uiFilter.
    private void OpenFiltersDialog()
    {
        var vm = _filtersFactory(_uiFilter);

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

    private void PersistCurrentSessionHistory()
    {
        try
        {
            _trafficHistoryStore.AppendLiveSession(
                new CaptureStats
                {
                    TotalPackets = Stats.SummaryTotalPackets,
                    TotalBytes = Stats.SummaryTotalBytes,
                    FirstSeen = Stats.SummaryFirstSeen,
                    LastSeen = Stats.SummaryLastSeen,
                    Elapsed = Stats.SummaryDuration
                },
                SelectedDevice?.Name,
                BpfFilter,
                ProcessPackets.ProcessStats.ToArray(),
                Endpoints.Hosts.ToArray());
        }
        catch
        {
            // keep stopping capture resilient even if history persistence fails
        }
    }

    private void OpenNotificationSettingsDialog()
    {
        var vm = _notificationSettingsFactory();

        var win = new Presentation.Views.NotificationSettingsWindow
        {
            Owner = System.Windows.Application.Current.MainWindow,
            DataContext = vm
        };

        win.ShowDialog();
    }

    private bool PassesCombinedFilters(PacketInfo p)
    {
        // 1) Flow filter
        if (_flowFilterService.IsActive && !_flowFilterService.Matches(p))
            return false;

        // 2) Advanced UI filter
        if (_uiFilterPredicate is not null)
        {
            if (!_uiFilterPredicate(p))
                return false;
        }

        // 3) Quick display filter
        if (_hasValidDisplayFilter && _displayFilterPredicate is not null && !_displayFilterPredicate(p))
            return false;

        return true;
    }

    // Відповідає за синхронізацію тексту фільтрів + Refresh().
    private void RefreshPacketsFilteringUi()
    {
        _uiFilterIsEmpty = _uiFilter.IsEmpty;
        _uiFilterPredicate = _uiFilterIsEmpty ? null : _packetFilterService.CompileUiFilter(_uiFilter);
        bool hasDisplayFilter = _hasValidDisplayFilter && !string.IsNullOrWhiteSpace(DisplayFilterText);

        bool needFilter = _flowFilterService.IsActive || !_uiFilterIsEmpty || hasDisplayFilter;
        if (needFilter)
        {
            PacketsView.Filter = obj => obj is PacketInfo p && PassesCombinedFilters(p);
        }
        else
        {
            PacketsView.Filter = null;
        }

        var parts = new List<string>();

        var flowText = _flowFilterService.FormatFilterText();
        if (!string.IsNullOrEmpty(flowText)) parts.Add(flowText);

        if (!_uiFilter.IsEmpty)
            parts.Add("UI Filter: active");

        if (!string.IsNullOrWhiteSpace(DisplayFilterText))
            parts.Add(hasDisplayFilter ? $"Display: {DisplayFilterText}" : "Display: invalid");

        FiltersText = parts.Count == 0 ? "" : string.Join(" | ", parts);

        // Refreshing a large CollectionView is expensive; only do it when we actually have a filter.
        if (needFilter || _packetsViewHasFilter)
            PacketsView.Refresh();

        _packetsViewHasFilter = needFilter;
        OnPropertyChanged(nameof(FlowFilterText)); // для сумісності

        OnPropertyChanged(nameof(IsFlowFollowActive));
        _clearFlowFilterCommand.RaiseCanExecuteChanged();
    }

    private void ResetPacketIndices()
    {
        _packetStorageIndexByNo.Clear();
        _packetsByPid.Clear();
    }

    private void IndexPackets(IReadOnlyList<PacketInfo> packets, int startStorageIndex)
    {
        for (int i = 0; i < packets.Count; i++)
        {
            var packet = packets[i];
            _packetStorageIndexByNo[packet.No] = startStorageIndex + i;

            if (packet.Pid is not int pid || pid <= 0)
                continue;

            if (!_packetsByPid.TryGetValue(pid, out var index))
            {
                index = new PidPacketIndex();
                _packetsByPid[pid] = index;
            }

            index.Add(packet);
        }
    }

    private bool TryGetPacketStorageIndex(PacketInfo packet, out int storageIndex)
        => _packetStorageIndexByNo.TryGetValue(packet.No, out storageIndex);

    private bool IsPacketVisibleInView(PacketInfo packet)
        => !_packetsViewHasFilter || PassesCombinedFilters(packet);

    private static int ComparePacketsByTimestampAndNo(PacketInfo left, PacketInfo right)
    {
        int timestampComparison = left.Timestamp.CompareTo(right.Timestamp);
        return timestampComparison != 0
            ? timestampComparison
            : left.No.CompareTo(right.No);
    }

    private static string? NormalizeTimelineDomainKey(string? domain)
        => string.IsNullOrWhiteSpace(domain) ? null : domain.Trim();

    private bool TryGetOrderedPacketsForPid(int pid, out IReadOnlyList<PacketInfo> packets)
    {
        if (_packetsByPid.TryGetValue(pid, out var index))
        {
            packets = index.GetOrderedPackets();
            return true;
        }

        packets = Array.Empty<PacketInfo>();
        return false;
    }

    private void ApplyDisplayFilterText()
    {
        var text = (DisplayFilterText ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(text))
        {
            _displayFilterPredicate = null;
            _hasValidDisplayFilter = false;
            DisplayFilterError = "";
            RefreshPacketsFilteringUi();
            return;
        }

        if (_packetFilterService.TryCompileDisplayFilter(text, out var predicate, out var error))
        {
            _displayFilterPredicate = predicate;
            _hasValidDisplayFilter = predicate is not null;
            DisplayFilterError = "";
        }
        else
        {
            _displayFilterPredicate = null;
            _hasValidDisplayFilter = false;
            DisplayFilterError = error ?? "Invalid display filter.";
        }

        RefreshPacketsFilteringUi();
    }

    private void ToggleDisplayFilterExamples()
    {
        IsDisplayFilterExamplesOpen = !IsDisplayFilterExamplesOpen;
        if (IsDisplayFilterExamplesOpen)
            SelectedDisplayFilterExample = null;
    }

    private void CopyHexToClipboard()
    {
        if (string.IsNullOrWhiteSpace(HexDump))
        {
            StatusText = "No hex dump available to copy.";
            return;
        }

        try
        {
            Clipboard.SetText(HexDump);
            StatusText = "Hex copied to clipboard.";
        }
        catch (Exception ex)
        {
            StatusText = $"Copy failed: {ex.Message}";
        }
    }

    // Відповідає за перевірку, чи пакет проходить через критерії UI-фільтра (op + value).

    private void ShowPackets()
    {
        LeftTabIndex = PacketsTabIndex;
    }
    private void ShowFlows()
    {
        LeftTabIndex = FlowsTabIndex;
    }

    private void ShowEndpoints()
    {
        LeftTabIndex = EndpointsTabIndex;
    }

    private void ShowHistory()
    {
        LeftTabIndex = HistoryTabIndex;
    }

    private void ShowStatistics()
    {
        LeftTabIndex = StatisticsTabIndex;
    }

    private void ShowProcessPackets()
    {
        LeftTabIndex = ProcessPacketsTabIndex;
    }

    private void ApplyProcessPacketFilter(int pid)
    {
        if (pid <= 0)
            return;

        _flowFilterService.Clear();
        _uiFilter = new PacketFilterModel
        {
            PidOp = NumberMatchOp.Equals,
            PidValue = pid
        };

        DisplayFilterText = "";
        RefreshPacketsFilteringUi();
        LeftTabIndex = PacketsTabIndex;
    }

    private void ShowPacketsForHost(string ip)
    {
        string normalizedIp = (ip ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(normalizedIp))
            return;

        _flowFilterService.Clear();
        _uiFilter = new PacketFilterModel
        {
            AnyIpOp = TextMatchOp.Equals,
            AnyIpValue = normalizedIp
        };

        DisplayFilterText = "";
        RefreshPacketsFilteringUi();
        LeftTabIndex = PacketsTabIndex;

        var packet = Packets.FirstOrDefault(p =>
            string.Equals(p.SrcIp, normalizedIp, StringComparison.OrdinalIgnoreCase)
            || string.Equals(p.DstIp, normalizedIp, StringComparison.OrdinalIgnoreCase));

        if (packet is not null && IsPacketVisibleInView(packet))
            SelectedPacket = packet;

        StatusText = $"Filtered packets for host {normalizedIp}.";
    }

    private void FocusPacketForTimelineEvent(ProcessStatRow.InvestigationTimelineEvent timelineEvent)
    {
        if (timelineEvent.Pid <= 0 || !timelineEvent.CanFocusPacket)
            return;

        var packet = FindPacketForTimelineEvent(timelineEvent);
        if (packet is null)
        {
            StatusText = $"Timeline packet not found for {timelineEvent.Title.ToLowerInvariant()}.";
            LeftTabIndex = PacketsTabIndex;
            return;
        }

        LeftTabIndex = PacketsTabIndex;

        if (!IsPacketVisibleInView(packet))
        {
            _flowFilterService.Clear();
            _uiFilter = new PacketFilterModel
            {
                PidOp = NumberMatchOp.Equals,
                PidValue = timelineEvent.Pid
            };

            DisplayFilterText = "";
            RefreshPacketsFilteringUi();
            StatusText = $"Focused {timelineEvent.Title.ToLowerInvariant()} and applied PID filter to make the packet visible.";
        }

        SelectedPacket = packet;
    }

    private void ShowPacketsForConversation(ProcessConversationRow conversation)
    {
        if (conversation.Pid <= 0)
            return;

        var filter = new PacketFilterModel
        {
            PidOp = NumberMatchOp.Equals,
            PidValue = conversation.Pid,
            AnyIpOp = TextMatchOp.Equals,
            AnyIpValue = conversation.RemoteIp
        };

        if (conversation.RemotePort > 0)
        {
            filter.AnyPortOp = NumberMatchOp.Equals;
            filter.AnyPortValue = conversation.RemotePort;
        }

        if (!string.IsNullOrWhiteSpace(conversation.Protocol))
        {
            filter.ProtocolOp = TextMatchOp.Equals;
            filter.ProtocolValue = conversation.Protocol;
        }

        var packet = FindFirstPacketForConversation(conversation);

        ApplyPacketDrillDown(
            filter,
            $"Filtered packets for {conversation.ConversationLabel}.",
            packet);
    }

    private void ShowPacketsForSessionCluster(ProcessSessionClusterRow sessionCluster)
    {
        if (sessionCluster.Pid <= 0)
            return;

        var filter = new PacketFilterModel
        {
            PidOp = NumberMatchOp.Equals,
            PidValue = sessionCluster.Pid,
            TimeFromUtc = sessionCluster.FirstSeen == default ? null : sessionCluster.FirstSeen.ToUniversalTime(),
            TimeToUtc = sessionCluster.LastSeen == default ? null : sessionCluster.LastSeen.ToUniversalTime()
        };

        var packet = FindFirstPacketForSessionCluster(sessionCluster);

        ApplyPacketDrillDown(
            filter,
            $"Filtered packets for {sessionCluster.Title.ToLowerInvariant()}.",
            packet);
    }

    private void ApplyPacketDrillDown(PacketFilterModel filter, string successStatus, PacketInfo? packet)
    {
        _flowFilterService.Clear();
        _uiFilter = filter;
        DisplayFilterText = "";
        RefreshPacketsFilteringUi();
        LeftTabIndex = PacketsTabIndex;

        if (packet is null || !IsPacketVisibleInView(packet))
        {
            StatusText = "No packets matched the selected investigation slice.";
            return;
        }

        SelectedPacket = packet;
        StatusText = successStatus;
    }

    private PacketInfo? FindPacketForTimelineEvent(ProcessStatRow.InvestigationTimelineEvent timelineEvent)
    {
        if (!TryGetOrderedPacketsForPid(timelineEvent.Pid, out var packetsForProcess))
            return null;

        return timelineEvent.Target?.Kind switch
        {
            "first-packet" => packetsForProcess.FirstOrDefault(),
            "first-domain" => FindPacketForFirstDomain(timelineEvent, packetsForProcess),
            "first-outbound-connection" => FindPacketNearTimestamp(timelineEvent.Timestamp, packetsForProcess),
            "first-secure-handshake" => FindPacketNearTimestamp(timelineEvent.Timestamp, packetsForProcess),
            "first-suspicious-domain" => FindPacketForFirstDomain(timelineEvent, packetsForProcess),
            "beacon-detected" => FindPacketNearTimestamp(timelineEvent.Timestamp, packetsForProcess),
            "traffic-peak" => FindPacketNearTimestamp(timelineEvent.Timestamp, packetsForProcess),
            _ => null
        };
    }

    private PacketInfo? FindPacketForFirstDomain(ProcessStatRow.InvestigationTimelineEvent timelineEvent, IReadOnlyList<PacketInfo> packetsForProcess)
    {
        PacketInfo? match = null;
        if (_packetsByPid.TryGetValue(timelineEvent.Pid, out var index))
            match = index.GetFirstPacketForDomain(timelineEvent.Target?.Value);

        return match ?? FindPacketNearTimestamp(timelineEvent.Timestamp, packetsForProcess);
    }

    private static PacketInfo? FindPacketNearTimestamp(DateTime timestamp, IReadOnlyList<PacketInfo> packetsForProcess)
    {
        if (packetsForProcess.Count == 0)
            return null;

        int low = 0;
        int high = packetsForProcess.Count - 1;

        while (low <= high)
        {
            int mid = low + ((high - low) / 2);
            var packet = packetsForProcess[mid];
            int comparison = packet.Timestamp.CompareTo(timestamp);

            if (comparison < 0)
            {
                low = mid + 1;
            }
            else if (comparison > 0)
            {
                high = mid - 1;
            }
            else
            {
                while (mid > 0 && packetsForProcess[mid - 1].Timestamp == timestamp)
                    mid--;

                return packetsForProcess[mid];
            }
        }

        if (low >= packetsForProcess.Count)
            return packetsForProcess[^1];

        if (high < 0)
            return packetsForProcess[0];

        var before = packetsForProcess[high];
        var after = packetsForProcess[low];
        long beforeDistance = Math.Abs((before.Timestamp - timestamp).Ticks);
        long afterDistance = Math.Abs((after.Timestamp - timestamp).Ticks);

        return beforeDistance <= afterDistance ? before : after;
    }

    private PacketInfo? FindFirstPacketForConversation(ProcessConversationRow conversation)
    {
        if (!TryGetOrderedPacketsForPid(conversation.Pid, out var packetsForProcess))
            return null;

        for (int i = 0; i < packetsForProcess.Count; i++)
        {
            var packet = packetsForProcess[i];
            if (!string.Equals(packet.SrcIp, conversation.RemoteIp, StringComparison.OrdinalIgnoreCase)
                && !string.Equals(packet.DstIp, conversation.RemoteIp, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (conversation.RemotePort > 0
                && packet.SrcPort != conversation.RemotePort
                && packet.DstPort != conversation.RemotePort)
            {
                continue;
            }

            if (!string.IsNullOrWhiteSpace(conversation.Protocol)
                && !string.Equals(packet.Protocol, conversation.Protocol, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            return packet;
        }

        return null;
    }

    private PacketInfo? FindFirstPacketForSessionCluster(ProcessSessionClusterRow sessionCluster)
    {
        if (!TryGetOrderedPacketsForPid(sessionCluster.Pid, out var packetsForProcess))
            return null;

        for (int i = 0; i < packetsForProcess.Count; i++)
        {
            var packet = packetsForProcess[i];
            if (packet.Timestamp < sessionCluster.FirstSeen)
                continue;

            if (packet.Timestamp > sessionCluster.LastSeen)
                break;

            return packet;
        }

        return null;
    }

    private static string? TryExtractTimelineDomain(PacketInfo packet)
    {
        if (!string.IsNullOrWhiteSpace(packet.DnsQueryName))
            return packet.DnsQueryName;

        if (!string.Equals(packet.Protocol, "DNS", StringComparison.OrdinalIgnoreCase)
            && packet.SrcPort != 53
            && packet.DstPort != 53)
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(packet.Info))
            return null;

        string info = packet.Info.Trim();
        const string queryPrefix = "Query ";
        const string responsePrefix = "Response ";

        if (info.StartsWith(queryPrefix, StringComparison.OrdinalIgnoreCase))
            info = info[queryPrefix.Length..];
        else if (info.StartsWith(responsePrefix, StringComparison.OrdinalIgnoreCase))
            info = info[responsePrefix.Length..];
        else
            return null;

        int typeSeparator = info.IndexOf(' ');
        string candidate = typeSeparator > 0 ? info[..typeSeparator] : info;
        if (string.IsNullOrWhiteSpace(candidate) || !candidate.Contains('.'))
            return null;

        return candidate;
    }

    private void SelectPacketByOffset(int offset)
    {
        if (offset == 0)
            return;

        int direction = Math.Sign(offset);
        int remaining = Math.Abs(offset);
        int startIndex;

        if (SelectedPacket is not null && TryGetPacketStorageIndex(SelectedPacket, out var selectedStorageIndex))
            startIndex = selectedStorageIndex;
        else
            startIndex = direction > 0 ? -1 : Packets.Count;

        var packet = FindVisiblePacketFromIndex(startIndex, direction, remaining);
        if (packet is null)
            return;

        SelectedPacket = packet;
        LeftTabIndex = PacketsTabIndex;
    }

    private void SelectFirstPacket()
    {
        var packet = FindVisiblePacketFromIndex(-1, 1, 1);
        if (packet is null)
            return;

        SelectedPacket = packet;
        LeftTabIndex = PacketsTabIndex;
    }

    private void SelectLastPacket()
    {
        var packet = FindVisiblePacketFromIndex(Packets.Count, -1, 1);
        if (packet is null)
            return;

        SelectedPacket = packet;
        LeftTabIndex = PacketsTabIndex;
    }

    private PacketInfo? FindVisiblePacketFromIndex(int startIndex, int direction, int visibleOffset)
    {
        if (Packets.Count == 0 || direction == 0 || visibleOffset <= 0)
            return null;

        for (int index = startIndex + direction; index >= 0 && index < Packets.Count; index += direction)
        {
            var packet = Packets[index];
            if (!IsPacketVisibleInView(packet))
                continue;

            visibleOffset--;
            if (visibleOffset == 0)
                return packet;
        }

        return null;
    }

    private void ZoomPackets(int direction)
    {
        const double step = 1.0;
        const double min = 8.0;
        const double max = 24.0;

        var next = PacketsTableFontSize + (direction * step);
        PacketsTableFontSize = Math.Clamp(next, min, max);
    }
}
