// Відповідає за: прийом raw пакетів, парсинг через IPacketParser, батчинг і показ у DataGrid.
using Application.Abstractions;
using Domain.Models;
using Microsoft.Win32;
using PacketDotNet;
using Presentation.Helpers;
using Presentation.Services;
using Presentation.Models;
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

    private readonly RelayCommand _followFlowCommand;
    private readonly RelayCommand _followFlowBothDirectionsCommand;
    private readonly RelayCommand _clearFlowFilterCommand;

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
    private readonly Dictionary<int, int> _processPacketsSinceLastSample = new();

    private bool _uiFilterIsEmpty = true;
    private bool _packetsViewHasFilter;

    private double _packetsTableFontSize = 12.0;
    public double PacketsTableFontSize
    {
        get => _packetsTableFontSize;
        set => Set(ref _packetsTableFontSize, value);
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
    public ICommand ApplyBpfCommand { get; }
    public ICommand SaveCaptureCommand { get; }
    public ICommand OpenCaptureCommand { get; }

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

    public bool IsFlowFollowActive => _flowFilterService.IsActive;

    // Відповідає за команди Follow Flow / Follow Both Directions / Clear.
    public ICommand FollowFlowCommand => _followFlowCommand;
    public ICommand FollowFlowBothDirectionsCommand => _followFlowBothDirectionsCommand;
    public ICommand ClearFlowFilterCommand => _clearFlowFilterCommand;
    public ICommand ShowPacketsCommand { get; }
    public ICommand OpenFiltersCommand { get; }
    public ICommand ShowFlowsCommand { get; }
    public ICommand OpenStatisticsCommand { get; }
    public ICommand ShowProcessPacketsCommand { get; }
    public ICommand ShowPacketsForPidCommand { get; }
    public ICommand FocusOnPidCommand { get; }
    public ICommand SelectPreviousPacketCommand { get; }
    public ICommand SelectNextPacketCommand { get; }
    public ICommand SelectFirstPacketCommand { get; }
    public ICommand SelectLastPacketCommand { get; }
    public ICommand ZoomInPacketsCommand { get; }
    public ICommand ZoomOutPacketsCommand { get; }
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
        ApplyBpfCommand = new AsyncRelayCommand(ApplyBpfAsync);
        SaveCaptureCommand = new AsyncRelayCommand(SaveCaptureAsync);
        OpenCaptureCommand = new AsyncRelayCommand(OpenCaptureAsync);

        // Відповідає за команду відкриття вікна Filters (модально по центру).
        OpenFiltersCommand = new RelayCommand(_ => OpenFiltersDialog());
        ShowFlowsCommand = new RelayCommand(_ => ShowFlows());
        OpenStatisticsCommand = new RelayCommand(_ => OpenStatisticsWindow());
        ShowPacketsCommand = new RelayCommand(_ => ShowPackets());
        ShowProcessPacketsCommand = new RelayCommand(_ => ShowProcessPackets());
        ShowPacketsForPidCommand = new RelayCommand(p => ShowPacketsForPid(p));
        FocusOnPidCommand = new RelayCommand(p => FocusOnPid(p));
        SelectPreviousPacketCommand = new RelayCommand(_ => SelectPacketByOffset(-1));
        SelectNextPacketCommand = new RelayCommand(_ => SelectPacketByOffset(1));
        SelectFirstPacketCommand = new RelayCommand(_ => SelectFirstPacket());
        SelectLastPacketCommand = new RelayCommand(_ => SelectLastPacket());
        ZoomInPacketsCommand = new RelayCommand(_ => ZoomPackets(+1));
        ZoomOutPacketsCommand = new RelayCommand(_ => ZoomPackets(-1));

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

        // Відповідає за створення view для фільтрації пакетів.
        // Важливо: не тримаємо активний Filter коли фільтрів немає (це дуже дорого на великій колекції).
        PacketsView = CollectionViewSource.GetDefaultView(Packets);
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

            // Reset UI/state (similar to StartAsync, but without starting capture)
            _packetNo = 0;
            RawBytesStore.Clear();
            Packets.Clear();
            ProcessFilters.Clear();
            _knownProcessIds.Clear();
            _processStatsMap.Clear();
            _processPacketsSinceLastSample.Clear();
            ProcessStats.Clear();
            ProcessFilters.Add(ProcessFilterOption.All);
            SelectedProcessFilter = ProcessFilterOption.All;
            _flowsVm.Flows.Clear();
            _flowAggregator.Reset();
            Stats.Reset();

            _flowFilterService.Clear();
            _uiFilter = new PacketFilterModel();
            RefreshPacketsFilteringUi();

            _uiPacketsDropped = 0;
            _capSw.Reset();

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

                    var info = _parser.Parse(pkt.TimestampUtc, pkt.Data.Length, new RawPacketData(pkt.Data, pkt.LinkLayerType));
                    info.No = Interlocked.Increment(ref _packetNo);

                    parsed.Add(info);
                    totalBytes += info.Length;

                    first = first is null || info.Timestamp < first ? info.Timestamp : first;
                    last = last is null || info.Timestamp > last ? info.Timestamp : last;

                    _flowAggregator.Add(info);
                }

                return (parsed, totalBytes, first, last);
            }, ct);

            Packets.ReplaceAll(loaded.parsed);

            var pidAgg = loaded.parsed
                .Where(p => p.Pid is int pid && pid > 0 && !string.IsNullOrWhiteSpace(p.ProcessName))
                .GroupBy(p => new { Pid = p.Pid!.Value, p.ProcessName })
                .Select(g => new { g.Key.Pid, g.Key.ProcessName, Count = (long)g.Count(), Bytes = g.Sum(x => (long)x.Length) })
                .OrderByDescending(x => x.Bytes)
                .ToList();

            foreach (var a in pidAgg)
            {
                _knownProcessIds.Add(a.Pid);
                ProcessFilters.Add(new ProcessFilterOption(a.Pid, a.ProcessName));

                var row = new ProcessStatRow(a.Pid, a.ProcessName, a.Count, a.Bytes);
                _processStatsMap[a.Pid] = row;
                ProcessStats.Add(row);
            }

            var top = _flowAggregator.SnapshotTop(take: 500);
            _flowsVm.UpdateFlows(top);

            var elapsed = (loaded.first.HasValue && loaded.last.HasValue)
                ? (loaded.last.Value - loaded.first.Value)
                : TimeSpan.Zero;

            Stats.Update(top, new Presentation.Models.CaptureStats
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

    // ===================== START/STOP =====================

    // Відповідає за запуск захоплення: reset UI, reset flows/stats, запуск reader task і старт capture.
    private async Task StartAsync(CancellationToken ct)
    {
        if (SelectedDevice is null) return;
        if (_captureService.IsRunning) return;

        StatusText = "Starting...";

        // Відповідає за повний reset перед новим захопленням
        _packetNo = 0;
        RawBytesStore.Clear();
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

            _processPacketsSinceLastSample.Clear();

            // add to UI collection in one shot
            int startIndex = 0;
            if (toFlush.Count > _maxUiAppendPerFlush)
            {
                startIndex = toFlush.Count - _maxUiAppendPerFlush;
                Interlocked.Add(ref _uiPacketsDropped, startIndex);
            }

            var toAdd = new List<PacketInfo>(Math.Max(0, toFlush.Count - startIndex));

            // Add a bounded amount of rows to keep UI responsive at very high pps.
            // We still update stats per packet, but append to the UI collection in one batch.
            for (int i = startIndex; i < toFlush.Count; i++)
            {
                var p = toFlush[i];
                toAdd.Add(p);
                TryAddProcessFilter(p);
                UpdateProcessStats(p);
            }

            Packets.AddRange(toAdd);


            // Add sparkline samples once per flush interval per PID (instead of per packet)
            foreach (var kvp in _processPacketsSinceLastSample)
            {
                if (_processStatsMap.TryGetValue(kvp.Key, out var row))
                    row.AddSample(kvp.Value);
            }

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
        if (p is null)
            return;

        var bytes = p.RawBytes ?? (p.RawBytesId is null ? null : RawBytesStore.Get(p.RawBytesId));
        if (bytes == null || bytes.Length == 0) return;

        HexDump = _hexDumpService.BuildHexDump(bytes, 16);

        // скидаємо виділення
        _selectedRange = null;
        OnPropertyChanged(nameof(SelectedRange));

        // будуємо документ (без підсвітки)
        HexDocument = _hexDumpService.BuildHexDocument(bytes, 16, null);

        try
        {
            var link = (LinkLayers)p.LinkLayerType;
            var parsedPacket = Packet.ParsePacket(link, bytes);
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
        if (SelectedPacket is null)
        {
            HexDocument = new FlowDocument(new Paragraph(new Run("")));
            return;
        }

        var bytes = SelectedPacket.RawBytes ?? (SelectedPacket.RawBytesId is null ? null : RawBytesStore.Get(SelectedPacket.RawBytesId));
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
        if (_flowFilterService.IsActive && !_flowFilterService.Matches(p))
            return false;

        // 2) UI filter
        if (!_uiFilterIsEmpty)
        {
            if (!_packetFilterService.MatchesUiFilter(p, _uiFilter))
                return false;
        }

        return true;
    }

    // Відповідає за синхронізацію тексту фільтрів + Refresh().
    private void RefreshPacketsFilteringUi()
    {
        _uiFilterIsEmpty = _uiFilter.IsEmpty;

        bool needFilter = _flowFilterService.IsActive || !_uiFilterIsEmpty;
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

        FiltersText = parts.Count == 0 ? "" : string.Join(" | ", parts);

        // Refreshing a large CollectionView is expensive; only do it when we actually have a filter.
        if (needFilter || _packetsViewHasFilter)
            PacketsView.Refresh();

        _packetsViewHasFilter = needFilter;
        OnPropertyChanged(nameof(FlowFilterText)); // для сумісності

        OnPropertyChanged(nameof(IsFlowFollowActive));
        _clearFlowFilterCommand.RaiseCanExecuteChanged();
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


        // Sampling for sparklines is batched in FlushPending() to avoid rebuilding geometry per packet.
        if (_processPacketsSinceLastSample.TryGetValue(pid, out var count))
            _processPacketsSinceLastSample[pid] = count + 1;
        else
            _processPacketsSinceLastSample[pid] = 1;
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
    private void SelectPacketByOffset(int offset)
    {
        if (offset == 0)
            return;

        var visiblePackets = PacketsView.Cast<PacketInfo>().ToList();
        if (visiblePackets.Count == 0)
            return;

        var currentIndex = SelectedPacket is null
            ? (offset > 0 ? -1 : visiblePackets.Count)
            : visiblePackets.IndexOf(SelectedPacket);

        if (currentIndex < 0)
            currentIndex = offset > 0 ? -1 : visiblePackets.Count;

        var nextIndex = Math.Clamp(currentIndex + offset, 0, visiblePackets.Count - 1);
        SelectedPacket = visiblePackets[nextIndex];
        LeftTabIndex = 0;
    }

    private void SelectFirstPacket()
    {
        var visiblePackets = PacketsView.Cast<PacketInfo>().ToList();
        if (visiblePackets.Count == 0)
            return;

        SelectedPacket = visiblePackets[0];
        LeftTabIndex = 0;
    }

    private void SelectLastPacket()
    {
        var visiblePackets = PacketsView.Cast<PacketInfo>().ToList();
        if (visiblePackets.Count == 0)
            return;

        SelectedPacket = visiblePackets[^1];
        LeftTabIndex = 0;
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