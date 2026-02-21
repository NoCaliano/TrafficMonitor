// Відповідає за: прийом raw пакетів, парсинг через IPacketParser, батчинг і показ у DataGrid.
using Application.Abstractions;
using Domain.Models;
using PacketDotNet;
using Presentation.Helpers;
using Presentation.Services;
using Presentation.Models;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
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
    private readonly IHexDumpService _hexDumpService;
    private readonly IPacketFilterService _packetFilterService;
    private readonly IFlowFilterService _flowFilterService;
    private readonly ICaptureController _captureController;
    private readonly Func<Func<bool>, Action, FlowsViewModel> _flowsFactory;
    private readonly Func<PacketFilterModel, FiltersViewModel> _filtersFactory;

    // --- UI batching for incoming packets to avoid flooding the UI thread ---
    private readonly object _pendingLock = new();
    private readonly List<PacketInfo> _pendingPackets = new();
    private readonly System.Threading.Timer _flushTimer;
    private const int _flushIntervalMs = 200; // flush UI every 200ms
    private const int _maxPendingPackets = 50_000; // cap pending to avoid OOM
    private const int _maxUiAppendPerFlush = 2_000; // limit UI work per tick under heavy load
    private long _uiPacketsDropped;
    private readonly HashSet<int> _knownProcessIds = new();
    private readonly Dictionary<int, ProcessStatRow> _processStatsMap = new();

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
    private ProtocolNode? _protocolRoot;
    public ProtocolNode? ProtocolRoot
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

    // ===================== LEFT TABS =====================

    // Відповідає за вибрану вкладку зліва (0 = Packets, 1 = Flows, 2 = Stats...).
    private int _leftTabIndex;
    public int LeftTabIndex
    {
        get => _leftTabIndex;
        set => Set(ref _leftTabIndex, value);
    }

    // ===================== FILTERS (FLOW + UI) =====================

    // Flow filter is handled by FlowFilterService

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

    // Відповідає за команди Follow Flow / Follow Both Directions / Clear (delegated to FlowsViewModel).
    public ICommand FollowFlowCommand => _flowsVm.FollowFlowCommand;
    public ICommand FollowFlowBothDirectionsCommand => _flowsVm.FollowFlowBothDirectionsCommand;
    public ICommand ClearFlowFilterCommand => _flowsVm.ClearFlowFilterCommand;
    public ICommand ShowPacketsCommand { get; }
    // Відповідає за відкриття вікна Filters.
    public ICommand OpenFiltersCommand { get; }
    public ICommand ShowFlowsCommand { get; }
    public ICommand OpenStatisticsCommand { get; }

    public ICommand ShowProcessPacketsCommand { get; }
    public ICommand ShowPacketsForPidCommand { get; }
    public ICommand FocusOnPidCommand { get; }
    // ===================== STATS =====================
    public ICollectionView ProcessPacketsView { get; }
    public ObservableCollection<ProcessFilterOption> ProcessFilters { get; } = new();
    public ObservableCollection<ProcessStatRow> ProcessStats { get; } = new();
    public ICollectionView ProcessStatsView { get; }

    private ProcessFilterOption? _selectedProcessFilter;
    public ProcessFilterOption? SelectedProcessFilter
    {
        get => _selectedProcessFilter;
        set
        {
            if (!Set(ref _selectedProcessFilter, value))
                return;

            ProcessPacketsView.Refresh();
        }
    }

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
        IFlowAggregator flowAggregator,
        IHexDumpService hexDumpService,
        IPacketFilterService packetFilterService,
        IFlowFilterService flowFilterService,
        ICaptureController captureController,
        StatsViewModel stats,
        Func<Func<bool>, Action, FlowsViewModel> flowsFactory,
        Func<PacketFilterModel, FiltersViewModel> filtersFactory)
    {
        _deviceService = deviceService;
        _captureService = captureService;
        _flowAggregator = flowAggregator;
        _parser = parser;
        _hexDumpService = hexDumpService;
        _packetFilterService = packetFilterService;
        _flowFilterService = flowFilterService;
        _captureController = captureController;
        Stats = stats;
        _flowsFactory = flowsFactory;
        _filtersFactory = filtersFactory;


        StartCommand = new AsyncRelayCommand(StartAsync);
        StopCommand = new AsyncRelayCommand(StopAsync);

        // Відповідає за команду відкриття вікна Filters (модально по центру).
        OpenFiltersCommand = new RelayCommand(_ => OpenFiltersDialog());
        ShowFlowsCommand = new RelayCommand(_ => ShowFlows());
        OpenStatisticsCommand = new RelayCommand(_ => OpenStatisticsWindow());
        ShowPacketsCommand = new RelayCommand(_ => ShowPackets());
        ShowProcessPacketsCommand = new RelayCommand(_ => ShowProcessPackets());
        ShowPacketsForPidCommand = new RelayCommand(p => ShowPacketsForPid(p));
        FocusOnPidCommand = new RelayCommand(p => FocusOnPid(p));

        // FlowsViewModel will manage flow selection and flow commands
        _flowsVm = _flowsFactory(() => !_uiFilter.IsEmpty, () => RefreshPacketsFilteringUi());


        LoadDevices();
        // subscribe to capture controller events
        // We only enqueue parsed packets here to avoid heavy work on capture thread or UI thread.
        _captureController.PacketsParsed += parsed =>
        {
            lock (_pendingLock)
            {
                // avoid growing beyond cap
                int canAdd = Math.Max(0, _maxPendingPackets - _pendingPackets.Count);
                if (canAdd <= 0) return;
                foreach (var p in parsed)
                {
                    _pendingPackets.Add(p);
                    if (--canAdd <= 0) break;
                }
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

        // Відповідає за створення view для фільтрації пакетів (ЄДИНИЙ комбінований фільтр).
        PacketsView = CollectionViewSource.GetDefaultView(Packets);
        PacketsView.Filter = obj =>
        {
            if (obj is not PacketInfo p) return false;
            return PassesCombinedFilters(p);
        };
        ProcessPacketsView = new ListCollectionView(Packets)
        {
            Filter = obj =>
            {
                if (obj is not PacketInfo p) return false;
                if (p.Pid is null || string.IsNullOrWhiteSpace(p.ProcessName)) return false;

                if (SelectedProcessFilter?.Pid is int pid)
                    return p.Pid == pid;

                return true;
            }
        };

        ProcessFilters.Add(ProcessFilterOption.All);
        SelectedProcessFilter = ProcessFilterOption.All;

        ProcessStatsView = CollectionViewSource.GetDefaultView(ProcessStats);

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
        ProcessFilters.Clear();
        _knownProcessIds.Clear();
        ProcessStats.Clear();
        ProcessFilters.Add(ProcessFilterOption.All);
        SelectedProcessFilter = ProcessFilterOption.All;
        _flowsVm.Flows.Clear();
        _flowAggregator.Reset();
        Stats.Reset();

        // Скидаємо фільтри
        _flowFilterService.Clear();
        _uiFilter = new PacketFilterModel();
        RefreshPacketsFilteringUi();


        _capTotalPackets = 0;
        _capTotalBytes = 0;
        _capFirstSeen = null;
        _capLastSeen = null;
        _uiPacketsDropped = 0;
        _capSw.Restart();

        // Скидаємо деталі
        SelectedPacket = null;
        ProtocolRoot = null;
        HexDump = "";

        await _captureController.StartAsync(SelectedDevice.Id, BpfFilter, ct);

        // start periodic flush timer
        _flushTimer.Change(_flushIntervalMs, _flushIntervalMs);

        StatusText = "Capturing";
    }

    private async Task StopAsync(CancellationToken ct)
    {
        if (!_captureService.IsRunning) return;

        

        StatusText = "Stopping...";
        _capSw.Stop();
        await _captureController.StopAsync(ct);

        // stop flush timer and flush remaining
        _flushTimer.Change(System.Threading.Timeout.Infinite, System.Threading.Timeout.Infinite);
        FlushPending();

        StatusText = "Idle";
    }

    private void FlushPending()
    {
        // take snapshot of pending
        List<PacketInfo> toFlush;
        lock (_pendingLock)
        {
            if (_pendingPackets.Count == 0) return;
            toFlush = new List<PacketInfo>(_pendingPackets);
            _pendingPackets.Clear();
        }

        System.Windows.Application.Current.Dispatcher.BeginInvoke(new Action(() =>
        {
            // add to UI collection in one shot
            int startIndex = 0;
            if (toFlush.Count > _maxUiAppendPerFlush)
            {
                startIndex = toFlush.Count - _maxUiAppendPerFlush;
                Interlocked.Add(ref _uiPacketsDropped, startIndex);
            }

            // add a bounded amount of rows to keep UI responsive at very high pps
            for (int i = startIndex; i < toFlush.Count; i++)
            {
                var p = toFlush[i];
                Packets.Add(p);
                TryAddProcessFilter(p);
                UpdateProcessStats(p);
            }

            const int maxRows = 50_000;
            while (Packets.Count > maxRows)
                Packets.RemoveAt(0);

            ProcessPacketsView.Refresh();

            var dropped = Interlocked.Read(ref _uiPacketsDropped);
            if (dropped > 0)
                StatusText = $"Capturing (UI throttled, skipped {dropped:N0} packets)";
            else if (_captureService.IsRunning)
                StatusText = "Capturing";
        }));
    }

    

    // CaptureController.RunReaderAsync handles batching, parsing and flow aggregation.

    // ===================== DETAILS (PACKET) =====================

    private void UpdateDetails(PacketInfo? p)
    {
        ProtocolRoot = null;
        HexDump = "";
        HexDocument = new FlowDocument();

        if (p is null || p.RawBytes is null || p.RawBytes.Length == 0)
            return;

        HexDump = _hexDumpService.BuildHexDump(p.RawBytes, 16);

        // скидаємо виділення
        _selectedRange = null;
        OnPropertyChanged(nameof(SelectedRange));

        // будуємо документ (без підсвітки)
        HexDocument = _hexDumpService.BuildHexDocument(p.RawBytes, 16, null);

            try
            {
                var link = (LinkLayers)p.LinkLayerType;
                var parsedPacket = Packet.ParsePacket(link, p.RawBytes);
                ProtocolRoot = PacketTreeBuilder.Build(parsedPacket, p);
            }
            catch (Exception ex)
            {
                var node = new Presentation.Helpers.ProtocolNode { Header = $"Parse error: {ex.Message}" };
                ProtocolRoot = node;
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

        HexDocument = _hexDumpService.BuildHexDocumentHighlighted(bytes, 16, SelectedRange);
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

    private bool PassesCombinedFilters(PacketInfo p)
    {
        // 1) Flow filter
        if (!_flowFilterService.Matches(p))
            return false;

        // 2) UI filter
        if (!_uiFilter.IsEmpty)
        {
            if (!_packetFilterService.MatchesUiFilter(p, _uiFilter))
                return false;
        }

        return true;
    }

    // Відповідає за синхронізацію тексту фільтрів + Refresh().
    private void RefreshPacketsFilteringUi()
    {
        var parts = new List<string>();

        var flowText = _flowFilterService.FormatFilterText();
        if (!string.IsNullOrEmpty(flowText)) parts.Add(flowText);

        if (!_uiFilter.IsEmpty)
            parts.Add("UI Filter: active");

        FiltersText = parts.Count == 0 ? "" : string.Join(" | ", parts);

        PacketsView.Refresh();
        OnPropertyChanged(nameof(FlowFilterText)); // для сумісності
    }

    // Відповідає за перевірку, чи пакет проходить через критерії UI-фільтра (op + value).
    
    private void ShowPackets()
    {
        LeftTabIndex = 0;
    }
    private void ShowFlows()
    {
        LeftTabIndex = 1;
    }

    private void OpenStatisticsWindow()
    {
        var win = new Presentation.Views.StatsWindow
        {
            Owner = System.Windows.Application.Current.MainWindow,
            DataContext = Stats
        };

        win.Show();
        win.Activate();
    }

    private void ShowProcessPackets()
    {
        LeftTabIndex = 2;
    }

    private void TryAddProcessFilter(PacketInfo packet)
    {
        if (packet.Pid is not int pid || string.IsNullOrWhiteSpace(packet.ProcessName))
            return;

        if (!_knownProcessIds.Add(pid))
            return;

        ProcessFilters.Add(new ProcessFilterOption(pid, packet.ProcessName));
    }

    private void FocusOnPid(object? param)
    {
        if (param is not int pid) return;

        // find first packet with this pid and select it in PacketsView
        var first = Packets.FirstOrDefault(p => p.Pid == pid);
        if (first is null) return;

        SelectedPacket = first;
        LeftTabIndex = 0; // switch to Packets tab
    }

    private void UpdateProcessStats(PacketInfo p)
    {
        if (p.Pid is not int pid || string.IsNullOrWhiteSpace(p.ProcessName))
            return;
        if (!_processStatsMap.TryGetValue(pid, out var row))
        {
            row = new ProcessStatRow(pid, p.ProcessName, 0, 0);
            _processStatsMap[pid] = row;
            ProcessStats.Add(row);
        }

        row.PacketCount++;
        row.TotalBytes += p.Length;
        row.AddSample(1);
    }

    private void ShowPacketsForPid(object? param)
    {
        if (param is not int pid) return;

        _uiFilter.PidOp = NumberMatchOp.Equals;
        _uiFilter.PidValue = pid;
        RefreshPacketsFilteringUi();
        LeftTabIndex = 0;
    }

    public sealed record ProcessFilterOption(int? Pid, string ProcessName)
    {
        public static ProcessFilterOption All { get; } = new(null, "All processes");

        public string DisplayName => Pid is null ? ProcessName : $"{ProcessName} (PID: {Pid})";
    }
}