// Відповідає за: прийом raw пакетів, парсинг через IPacketParser, батчинг і показ у DataGrid.
using Application.Abstractions;
using Domain.Models;
using Infrastructure.Networking;
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
    private readonly Queue<PacketInfo> _pendingPackets = new();
    private readonly System.Threading.Timer _flushTimer;
    private const int _flushIntervalMs = 200; // flush UI every 200ms
    private const int _maxPendingPackets = 50_000; // cap pending to avoid OOM
    private const int _maxUiAppendPerFlush = 750; // limit UI work per tick under heavy load
    private const int _collectionResetThreshold = 256; // large batches are cheaper as a single Reset than thousands of Add events
    private long _uiPacketsDropped;

    private bool _uiFilterIsEmpty = true;
    private bool _packetsViewHasFilter;

    private double _packetsTableFontSize = 12.0;
    public double PacketsTableFontSize
    {
        get => _packetsTableFontSize;
        set => Set(ref _packetsTableFontSize, value);
    }
    public ProcessPacketsViewModel ProcessPackets { get; }



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
        : "Wireshark-like examples: arp, dns, tcp && ip.addr == 1.1.1.1, tcp.port == 443, process contains chrome";

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
    public ICommand ShowFlowsCommand { get; }
    public ICommand OpenStatisticsCommand { get; }
    public ICommand ShowProcessPacketsCommand { get; }
    public ICommand SelectPreviousPacketCommand { get; }
    public ICommand SelectNextPacketCommand { get; }
    public ICommand SelectFirstPacketCommand { get; }
    public ICommand SelectLastPacketCommand { get; }
    public ICommand ZoomInPacketsCommand { get; }
    public ICommand ZoomOutPacketsCommand { get; }
    public ICommand ToggleDisplayFilterExamplesCommand { get; }

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
        ProcessPacketsViewModel processPackets,
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
        ProcessPackets = processPackets;
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
            _captureController.ResetSessionState();
            RawBytesStore.Clear();
            Packets.Clear();
            ProcessPackets.Reset();
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
                ProcessPackets.SeedProcessSummary(a.Pid, a.ProcessName, a.Count, a.Bytes);

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
        _captureController.ResetSessionState();
        RawBytesStore.Clear();
        Packets.Clear();
        ProcessPackets.Reset();
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

    private async Task StopAsync(CancellationToken ct)
    {
        if (!_captureService.IsRunning) return;



        StatusText = "Stopping...";
        _capSw.Stop();
        await _captureController.StopAsync(ct);

        // stop flush timer and flush remaining
        _flushTimer.Change(System.Threading.Timeout.Infinite, System.Threading.Timeout.Infinite);
        FlushPending(drainAll: true);

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

        System.Windows.Application.Current.Dispatcher.BeginInvoke(new Action(() =>
        {
            ProcessPackets.PrepareForFlush();

            // Process analytics on the full batch first. Risk/timeline data should not depend
            // on whether a row survives UI throttling.
            for (int i = 0; i < toFlush.Count; i++)
                ProcessPackets.ObservePacket(toFlush[i]);

            if (toFlush.Count > 0)
            {
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

        // 2) Advanced UI filter
        if (!_uiFilterIsEmpty)
        {
            if (!_packetFilterService.MatchesUiFilter(p, _uiFilter))
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
        LeftTabIndex = 0;
    }

    private void FocusPacketForTimelineEvent(ProcessStatRow.InvestigationTimelineEvent timelineEvent)
    {
        if (timelineEvent.Pid <= 0 || !timelineEvent.CanFocusPacket)
            return;

        var packet = FindPacketForTimelineEvent(timelineEvent);
        if (packet is null)
        {
            StatusText = $"Timeline packet not found for {timelineEvent.Title.ToLowerInvariant()}.";
            LeftTabIndex = 0;
            return;
        }

        LeftTabIndex = 0;

        if (!PacketsView.Cast<PacketInfo>().Contains(packet))
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

        ApplyPacketDrillDown(
            filter,
            $"Filtered packets for {conversation.ConversationLabel}.",
            packets => packets
                .Where(packet => packet.Pid == conversation.Pid)
                .Where(packet => string.Equals(packet.SrcIp, conversation.RemoteIp, StringComparison.OrdinalIgnoreCase)
                    || string.Equals(packet.DstIp, conversation.RemoteIp, StringComparison.OrdinalIgnoreCase))
                .OrderBy(packet => packet.Timestamp)
                .ThenBy(packet => packet.No)
                .FirstOrDefault());
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

        ApplyPacketDrillDown(
            filter,
            $"Filtered packets for {sessionCluster.Title.ToLowerInvariant()}.",
            packets => packets
                .Where(packet => packet.Pid == sessionCluster.Pid)
                .Where(packet => packet.Timestamp >= sessionCluster.FirstSeen && packet.Timestamp <= sessionCluster.LastSeen)
                .OrderBy(packet => packet.Timestamp)
                .ThenBy(packet => packet.No)
                .FirstOrDefault());
    }

    private void ApplyPacketDrillDown(PacketFilterModel filter, string successStatus, Func<IEnumerable<PacketInfo>, PacketInfo?> packetSelector)
    {
        _flowFilterService.Clear();
        _uiFilter = filter;
        DisplayFilterText = "";
        RefreshPacketsFilteringUi();
        LeftTabIndex = 0;

        var packet = packetSelector(PacketsView.Cast<PacketInfo>());
        if (packet is null)
        {
            StatusText = "No packets matched the selected investigation slice.";
            return;
        }

        SelectedPacket = packet;
        StatusText = successStatus;
    }

    private PacketInfo? FindPacketForTimelineEvent(ProcessStatRow.InvestigationTimelineEvent timelineEvent)
    {
        var packetsForProcess = Packets
            .Where(packet => packet.Pid == timelineEvent.Pid)
            .OrderBy(packet => packet.Timestamp)
            .ThenBy(packet => packet.No);

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

    private static PacketInfo? FindPacketForFirstDomain(ProcessStatRow.InvestigationTimelineEvent timelineEvent, IEnumerable<PacketInfo> packetsForProcess)
    {
        if (string.IsNullOrWhiteSpace(timelineEvent.Target?.Value))
            return null;

        var match = packetsForProcess.FirstOrDefault(packet =>
            string.Equals(TryExtractTimelineDomain(packet), timelineEvent.Target.Value, StringComparison.OrdinalIgnoreCase));

        return match ?? FindPacketNearTimestamp(timelineEvent.Timestamp, packetsForProcess);
    }

    private static PacketInfo? FindPacketNearTimestamp(DateTime timestamp, IEnumerable<PacketInfo> packetsForProcess)
    {
        PacketInfo? bestPacket = null;
        long bestDistanceTicks = long.MaxValue;

        foreach (var packet in packetsForProcess)
        {
            long distance = Math.Abs((packet.Timestamp - timestamp).Ticks);
            if (distance >= bestDistanceTicks)
                continue;

            bestDistanceTicks = distance;
            bestPacket = packet;

            if (distance == 0)
                break;
        }

        return bestPacket;
    }

    private static string? TryExtractTimelineDomain(PacketInfo packet)
    {
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
