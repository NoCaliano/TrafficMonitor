using Domain.Models;
using Infrastructure.Networking;
using Presentation.Abstractions;
using Presentation.Models;
using Presentation.Services;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace Presentation.ViewModels;

public sealed class ProcessPacketsViewModel : ViewModelBase
{
    private readonly ProcessMapperService _processMapperService;
    private readonly ProcessForensicsTracker _forensicsTracker;
    private readonly ProcessLivenessTracker _livenessTracker;
    private readonly ProcessRemediationCoordinator _remediationCoordinator;
    private readonly ProcessBehaviorBaselineService _behaviorBaselineService;
    private readonly ProcessIncidentGraphBuilder _incidentGraphBuilder;
    private readonly IFileDialogService _fileDialogService;
    private readonly ProcessIncidentReportExportService _incidentReportExportService;
    private readonly RelayCommand _saveIncidentGraphImageCommand;

    private readonly Dictionary<int, ProcessStatRow> _processStatsMap = new();
    private readonly Dictionary<int, int> _processPacketsSinceLastSample = new();
    private readonly HashSet<int> _burstingPids = new();
    private readonly HashSet<ProcessStatRow> _baselineFinalizedRows = new();
    private bool _processStatsViewRefreshPending;

    private Action<int>? _showPacketsForPid;
    private Action<ProcessStatRow.InvestigationTimelineEvent>? _focusTimelineEvent;
    private Action<ProcessConversationRow>? _showPacketsForConversation;
    private Action<ProcessSessionClusterRow>? _showPacketsForSessionCluster;
    private Action<string>? _reportStatus;
    private readonly ThreatNotificationCoordinator _notificationCoordinator;
    private readonly TrafficControlManager _trafficControlManager;
    private bool _emitNotificationsForCurrentSession;
    private bool _isTimelineBlockPresetMenuOpen;
    private bool _isSelectedProcessBlockPresetMenuOpen;

    public ObservableCollection<ProcessStatRow> ProcessStats { get; } = new();
    public ObservableCollection<ProcessStatCardRow> VisibleProcessRows { get; } = new();
    public ICollectionView ProcessStatsView { get; }

    private ProcessIncidentGraph _selectedIncidentGraph = ProcessIncidentGraph.Empty;
    public ProcessIncidentGraph SelectedIncidentGraph
    {
        get => _selectedIncidentGraph;
        private set
        {
            if (!Set(ref _selectedIncidentGraph, value))
                return;

            _saveIncidentGraphImageCommand?.RaiseCanExecuteChanged();
        }
    }

    private bool _isProcessDetailsOpen;
    public bool IsProcessDetailsOpen
    {
        get => _isProcessDetailsOpen;
        private set
        {
            if (!Set(ref _isProcessDetailsOpen, value))
                return;

            OnPropertyChanged(nameof(IsOverviewMode));
        }
    }

    public bool IsOverviewMode => !IsProcessDetailsOpen;

    public bool IsTimelineBlockPresetMenuOpen
    {
        get => _isTimelineBlockPresetMenuOpen;
        set
        {
            if (!Set(ref _isTimelineBlockPresetMenuOpen, value))
                return;

            if (value)
                IsSelectedProcessBlockPresetMenuOpen = false;
        }
    }

    public bool IsSelectedProcessBlockPresetMenuOpen
    {
        get => _isSelectedProcessBlockPresetMenuOpen;
        set
        {
            if (!Set(ref _isSelectedProcessBlockPresetMenuOpen, value))
                return;

            if (value)
                IsTimelineBlockPresetMenuOpen = false;
        }
    }

    private ProcessStatRow? _selectedProcessStat;
    public ProcessStatRow? SelectedProcessStat
    {
        get => _selectedProcessStat;
        set
        {
            if (ReferenceEquals(_selectedProcessStat, value))
                return;

            var previous = _selectedProcessStat;
            if (!Set(ref _selectedProcessStat, value))
                return;

            if (previous is not null)
                previous.IsSelectedInProcessGrid = false;

            if (value is not null)
                value.IsSelectedInProcessGrid = true;

            CloseBlockPresetMenus();
            RefreshSelectedProcessDetails();
        }
    }

    public ICommand SelectProcessStatCommand { get; }
    public ICommand ShowPacketsForPidCommand { get; }
    public ICommand FocusTimelineEventCommand { get; }
    public ICommand ShowPacketsForConversationCommand { get; }
    public ICommand ShowPacketsForSessionClusterCommand { get; }
    public ICommand LocateProcessCommand { get; }
    public ICommand KillProcessCommand { get; }
    public ICommand BlockProcessFirewallCommand { get; }
    public ICommand BlockProcessFirewallFor15MinutesCommand { get; }
    public ICommand BlockProcessFirewallFor1HourCommand { get; }
    public ICommand BlockProcessFirewallUntilAppExitCommand { get; }
    public ICommand UnblockProcessFirewallCommand { get; }
    public ICommand ExportIncidentReportCommand { get; }
    public ICommand ToggleConversationsExpansionCommand { get; }
    public ICommand ToggleSessionClustersExpansionCommand { get; }
    public ICommand SaveIncidentGraphImageCommand => _saveIncidentGraphImageCommand;
    public ICommand BackToProcessGridCommand { get; }

    private string _searchText = "";
    public string SearchText
    {
        get => _searchText;
        set
        {
            if (!Set(ref _searchText, value))
                return;

            RefreshProcessStatsView();
        }
    }

    private bool _showHighRiskOnly;
    public bool ShowHighRiskOnly
    {
        get => _showHighRiskOnly;
        set
        {
            if (!Set(ref _showHighRiskOnly, value))
                return;

            RefreshProcessStatsView();
        }
    }

    private bool _showBeaconOnly;
    public bool ShowBeaconOnly
    {
        get => _showBeaconOnly;
        set
        {
            if (!Set(ref _showBeaconOnly, value))
                return;

            RefreshProcessStatsView();
        }
    }

    private bool _showUnsignedOnly;
    public bool ShowUnsignedOnly
    {
        get => _showUnsignedOnly;
        set
        {
            if (!Set(ref _showUnsignedOnly, value))
                return;

            RefreshProcessStatsView();
        }
    }

    private bool _showExitedOnly;
    public bool ShowExitedOnly
    {
        get => _showExitedOnly;
        set
        {
            if (!Set(ref _showExitedOnly, value))
                return;

            RefreshProcessStatsView();
        }
    }

    private bool _showBlockedOnly;
    public bool ShowBlockedOnly
    {
        get => _showBlockedOnly;
        set
        {
            if (!Set(ref _showBlockedOnly, value))
                return;

            RefreshProcessStatsView();
        }
    }

    private int _totalProcessCount;
    public int TotalProcessCount
    {
        get => _totalProcessCount;
        private set => Set(ref _totalProcessCount, value);
    }

    private int _visibleProcessCount;
    public int VisibleProcessCount
    {
        get => _visibleProcessCount;
        private set => Set(ref _visibleProcessCount, value);
    }

    private int _highRiskProcessCount;
    public int HighRiskProcessCount
    {
        get => _highRiskProcessCount;
        private set => Set(ref _highRiskProcessCount, value);
    }

    private int _beaconProcessCount;
    public int BeaconProcessCount
    {
        get => _beaconProcessCount;
        private set => Set(ref _beaconProcessCount, value);
    }

    private int _exitedProcessCount;
    public int ExitedProcessCount
    {
        get => _exitedProcessCount;
        private set => Set(ref _exitedProcessCount, value);
    }

    private int _blockedProcessCount;
    public int BlockedProcessCount
    {
        get => _blockedProcessCount;
        private set => Set(ref _blockedProcessCount, value);
    }

    public ProcessPacketsViewModel(
        ProcessMapperService processMapperService,
        ProcessForensicsTracker forensicsTracker,
        ProcessLivenessTracker livenessTracker,
        ProcessRemediationCoordinator remediationCoordinator,
        ProcessBehaviorBaselineService behaviorBaselineService,
        ProcessIncidentGraphBuilder incidentGraphBuilder,
        IFileDialogService fileDialogService,
        ProcessIncidentReportExportService incidentReportExportService,
        ThreatNotificationCoordinator notificationCoordinator,
        TrafficControlManager trafficControlManager)
    {
        _processMapperService = processMapperService;
        _forensicsTracker = forensicsTracker;
        _livenessTracker = livenessTracker;
        _remediationCoordinator = remediationCoordinator;
        _behaviorBaselineService = behaviorBaselineService;
        _incidentGraphBuilder = incidentGraphBuilder;
        _fileDialogService = fileDialogService;
        _incidentReportExportService = incidentReportExportService;
        _notificationCoordinator = notificationCoordinator;
        _trafficControlManager = trafficControlManager;

        SelectProcessStatCommand = new RelayCommand(p => OpenProcessDetails(p), p => p is ProcessStatRow);
        ShowPacketsForPidCommand = new RelayCommand(p => ShowPacketsForPid(p));
        FocusTimelineEventCommand = new RelayCommand(p => FocusTimelineEvent(p), p => p is ProcessStatRow.InvestigationTimelineEvent timelineEvent && timelineEvent.CanFocusPacket);
        ShowPacketsForConversationCommand = new RelayCommand(p => ShowPacketsForConversation(p), p => p is ProcessConversationRow conversation && conversation.Pid > 0);
        ShowPacketsForSessionClusterCommand = new RelayCommand(p => ShowPacketsForSessionCluster(p), p => p is ProcessSessionClusterRow sessionCluster && sessionCluster.Pid > 0);
        LocateProcessCommand = new RelayCommand(p => LocateProcess(p));
        KillProcessCommand = new RelayCommand(p => KillProcess(p));
        BlockProcessFirewallCommand = new RelayCommand(p => BlockProcessInFirewall(p));
        BlockProcessFirewallFor15MinutesCommand = new RelayCommand(p => BlockProcessInFirewall(p, ProcessRemediationCoordinator.FirewallBlockPreset.FifteenMinutes));
        BlockProcessFirewallFor1HourCommand = new RelayCommand(p => BlockProcessInFirewall(p, ProcessRemediationCoordinator.FirewallBlockPreset.OneHour));
        BlockProcessFirewallUntilAppExitCommand = new RelayCommand(p => BlockProcessInFirewall(p, ProcessRemediationCoordinator.FirewallBlockPreset.UntilAppExit));
        UnblockProcessFirewallCommand = new RelayCommand(p => UnblockProcessInFirewall(p));
        ExportIncidentReportCommand = new RelayCommand(p => ExportIncidentReport(p));
        ToggleConversationsExpansionCommand = new RelayCommand(p => ToggleConversationsExpansion(p));
        ToggleSessionClustersExpansionCommand = new RelayCommand(p => ToggleSessionClustersExpansion(p));
        _saveIncidentGraphImageCommand = new RelayCommand(
            p => SaveIncidentGraphImage(p),
            p => CanSaveIncidentGraphImage(p));
        BackToProcessGridCommand = new RelayCommand(_ => BackToProcessGrid());
        _remediationCoordinator.FirewallBlockStateChanged += OnFirewallBlockStateChanged;

        ProcessStatsView = CollectionViewSource.GetDefaultView(ProcessStats);
        ProcessStatsView.Filter = MatchesCurrentFilters;
        ProcessStatsView.SortDescriptions.Add(new SortDescription(nameof(ProcessStatRow.IsAlive), ListSortDirection.Descending));
        ProcessStatsView.SortDescriptions.Add(new SortDescription(nameof(ProcessStatRow.RiskScore), ListSortDirection.Descending));
        ProcessStatsView.SortDescriptions.Add(new SortDescription(nameof(ProcessStatRow.TotalBytes), ListSortDirection.Descending));
    }

    public void ConfigureActions(
        Action<int> showPacketsForPid,
        Action<ProcessStatRow.InvestigationTimelineEvent> focusTimelineEvent,
        Action<ProcessConversationRow> showPacketsForConversation,
        Action<ProcessSessionClusterRow> showPacketsForSessionCluster,
        Action<string> reportStatus)
    {
        _showPacketsForPid = showPacketsForPid;
        _focusTimelineEvent = focusTimelineEvent;
        _showPacketsForConversation = showPacketsForConversation;
        _showPacketsForSessionCluster = showPacketsForSessionCluster;
        _reportStatus = reportStatus;
    }

    public void BeginCaptureSession(bool emitNotifications)
    {
        _emitNotificationsForCurrentSession = emitNotifications;
        _notificationCoordinator.ResetSession();
        _trafficControlManager.BeginLiveSession();
    }

    public void Reset()
    {
        _processStatsMap.Clear();
        _processPacketsSinceLastSample.Clear();
        _burstingPids.Clear();
        _baselineFinalizedRows.Clear();
        _notificationCoordinator.ResetSession();
        _forensicsTracker.Reset();
        _livenessTracker.Reset();

        foreach (var row in ProcessStats)
            row.PropertyChanged -= OnProcessStatPropertyChanged;

        ProcessStats.Clear();
        VisibleProcessRows.Clear();
        SelectedProcessStat = null;
        SelectedIncidentGraph = ProcessIncidentGraph.Empty;
        IsProcessDetailsOpen = false;
        CloseBlockPresetMenus();
        SearchText = "";
        ShowHighRiskOnly = false;
        ShowBeaconOnly = false;
        ShowUnsignedOnly = false;
        ShowExitedOnly = false;
        ShowBlockedOnly = false;
        UpdateSummaryCounts();
    }

    public void SeedProcessSummary(int pid, string processName, long packetCount, long totalBytes)
    {
        if (pid <= 0 || string.IsNullOrWhiteSpace(processName))
            return;

        if (_processStatsMap.ContainsKey(pid))
            return;

        var row = new ProcessStatRow(pid, processName, packetCount, totalBytes);
        RegisterProcessRow(row);
    }

    public void PrepareForFlush()
    {
        _processPacketsSinceLastSample.Clear();
        _forensicsTracker.CleanupIfNeeded();

        foreach (var change in _livenessTracker.RefreshIfNeeded(ProcessStats))
        {
            if (!_processStatsMap.TryGetValue(change.Pid, out var row))
                continue;

            if (change.HasIdentityChangedEvent)
                row.RecordIdentityChanged(change.Timestamp, change.IdentityChangedDetail);

            if (change.HasExitedEvent)
                row.RecordProcessExited(change.Timestamp, change.ExitedDetail);
        }
    }

    public void ObservePacket(PacketInfo packet)
    {
        if (packet.Pid is not int pid || string.IsNullOrWhiteSpace(packet.ProcessName))
            return;

        var row = GetOrCreateProcessRow(pid, packet.ProcessName);
        bool isFirstPacket = row.PacketCount == 0;

        row.PacketCount++;
        row.TotalBytes += packet.Length;
        row.LastSeen = packet.Timestamp;
        row.ObserveActivityAt(packet.Timestamp);

        var forensicsUpdate = _forensicsTracker.Update(packet, row);
        bool hasDnsObservation = TryExtractDnsObservation(packet, out var dnsDomain, out var dnsQueryType, out var isDnsResponse);

        if (isFirstPacket)
        {
            row.RecordFirstPacket(packet.Timestamp, BuildPacketTimelineDetail(packet));
            if (_emitNotificationsForCurrentSession)
                _notificationCoordinator.NotifyNewProcess(row);
        }

        if (forensicsUpdate.HasFirstOutboundConnection)
            row.RecordFirstOutboundConnection(packet.Timestamp, forensicsUpdate.FirstOutboundConnectionDetail);

        if (hasDnsObservation)
        {
            row.RecordFirstDomain(packet.Timestamp, dnsDomain);

            if (!isDnsResponse)
                row.ObserveDnsQuery(dnsDomain, dnsQueryType, packet.Timestamp);

            if (TryGetSuspiciousDomainReason(dnsDomain, out var suspiciousDomainReason))
                row.RecordFirstSuspiciousDomain(packet.Timestamp, dnsDomain, suspiciousDomainReason);
        }

        if (TryBuildSecureHandshakeDetail(packet, out var handshakeDetail))
            row.RecordFirstSecureHandshake(packet.Timestamp, handshakeDetail);

        if (forensicsUpdate.HasBeaconDetected)
            row.RecordBeaconDetected(packet.Timestamp, forensicsUpdate.BeaconDetail);

        if (_emitNotificationsForCurrentSession)
            _trafficControlManager.ObservePacket(row, packet);

        if (_emitNotificationsForCurrentSession)
            _notificationCoordinator.ObserveSoftQuotas(row, packet, isDnsQuery: hasDnsObservation && !isDnsResponse);

        if (_processPacketsSinceLastSample.TryGetValue(pid, out var count))
            _processPacketsSinceLastSample[pid] = count + 1;
        else
            _processPacketsSinceLastSample[pid] = 1;
    }

    public void CompleteSamplingWindow()
    {
        foreach (var kvp in _processPacketsSinceLastSample)
        {
            if (!_processStatsMap.TryGetValue(kvp.Key, out var row))
                continue;

            int previousPeak = row.PeakSamplePackets;
            row.AddSample(kvp.Value);

            if (kvp.Value > previousPeak)
                row.RecordTrafficPeak(row.LastSeen == default ? DateTime.Now : row.LastSeen, kvp.Value);

            if (kvp.Value >= 300)
            {
                _burstingPids.Add(kvp.Key);
            }
            else if (_burstingPids.Remove(kvp.Key) && previousPeak >= 300)
            {
                string detail = $"Traffic cooled down to {kvp.Value:N0} packets per interval after peaking at {previousPeak:N0}.";
                row.RecordBurstEnded(row.LastSeen == default ? DateTime.Now : row.LastSeen, detail);
            }

            RefreshAdaptiveBaseline(row);
        }

        foreach (var row in ProcessStats)
            FinalizeAdaptiveBaseline(row);

        RefreshSelectedProcessDetails();
    }

    public void FinalizeCurrentSession()
    {
        foreach (var row in ProcessStats)
            FinalizeAdaptiveBaseline(row, force: true);
    }

    public IReadOnlyList<(ProcessStatRow Process, ProcessConversationRow Conversation)> GetTopConversations(int take = 200, int perProcessTake = 24)
    {
        if (take <= 0 || perProcessTake <= 0 || ProcessStats.Count == 0)
            return Array.Empty<(ProcessStatRow Process, ProcessConversationRow Conversation)>();

        return ProcessStats
            .Where(process => process.Pid > 0 && !string.IsNullOrWhiteSpace(process.ProcessName))
            .SelectMany(process => _forensicsTracker.GetConversationSnapshot(process.Pid, perProcessTake)
                .Select(conversation => (Process: process, Conversation: conversation)))
            .OrderByDescending(item => item.Conversation.TotalBytes)
            .ThenByDescending(item => item.Conversation.PacketCount)
            .ThenByDescending(item => item.Conversation.LastSeen)
            .Take(take)
            .ToArray();
    }

    public void SelectProcess(int pid)
    {
        if (pid <= 0)
            return;

        if (_processStatsMap.TryGetValue(pid, out var row))
            SelectedProcessStat = row;
    }

    private void RefreshSelectedProcessDetails()
    {
        if (SelectedProcessStat is null)
        {
            SelectedIncidentGraph = ProcessIncidentGraph.Empty;
            return;
        }

        SelectedProcessStat.UpdateConversations(_forensicsTracker.GetConversationSnapshot(SelectedProcessStat.Pid));
        SelectedProcessStat.UpdateSessionClusters(_forensicsTracker.GetSessionClusterSnapshot(SelectedProcessStat.Pid));
        SelectedIncidentGraph = _incidentGraphBuilder.Build(
            SelectedProcessStat,
            _forensicsTracker.GetIncidentGraphSnapshot(SelectedProcessStat.Pid));
    }

    private ProcessStatRow GetOrCreateProcessRow(int pid, string processName)
    {
        if (_processStatsMap.TryGetValue(pid, out var row))
            return row;

        row = new ProcessStatRow(pid, processName, 0, 0);

        var details = _processMapperService.GetProcessDetailsCached(pid);
        var parentName = details.ParentPid > 0 ? _processMapperService.GetProcessNameCached(details.ParentPid) : "";
        row.UpdateIdentity(details.ExePath, details.Publisher, details.IsSigned, details.SignerSubject, details.ParentPid, parentName);
        ApplyTrackedFirewallState(row);
        TryPopulateProcessStart(row);

        RegisterProcessRow(row);
        return row;
    }

    private void ShowPacketsForPid(object? parameter)
    {
        int pid = ResolvePid(parameter);
        if (pid <= 0)
            return;

        SelectProcess(pid);
        _showPacketsForPid?.Invoke(pid);
    }

    private void OpenProcessDetails(object? parameter)
    {
        if (parameter is ProcessStatRow row)
        {
            SelectedProcessStat = row;
            IsProcessDetailsOpen = true;
        }
    }

    private void BackToProcessGrid()
    {
        CloseBlockPresetMenus();
        IsProcessDetailsOpen = false;
    }

    private void FocusTimelineEvent(object? parameter)
    {
        if (parameter is not ProcessStatRow.InvestigationTimelineEvent timelineEvent || !timelineEvent.CanFocusPacket)
            return;

        SelectProcess(timelineEvent.Pid);
        _focusTimelineEvent?.Invoke(timelineEvent);
    }

    private void ShowPacketsForConversation(object? parameter)
    {
        if (parameter is not ProcessConversationRow conversation || conversation.Pid <= 0)
            return;

        SelectProcess(conversation.Pid);
        _showPacketsForConversation?.Invoke(conversation);
    }

    private void ShowPacketsForSessionCluster(object? parameter)
    {
        if (parameter is not ProcessSessionClusterRow sessionCluster || sessionCluster.Pid <= 0)
            return;

        SelectProcess(sessionCluster.Pid);
        _showPacketsForSessionCluster?.Invoke(sessionCluster);
    }

    private void LocateProcess(object? parameter)
    {
        int pid = ResolvePid(parameter);
        if (pid <= 0)
            return;

        SelectProcess(pid);
        ReportStatus(_remediationCoordinator.Locate(pid));
    }

    private void KillProcess(object? parameter)
    {
        int pid = ResolvePid(parameter);
        if (pid <= 0)
            return;

        SelectProcess(pid);
        ReportStatus(_remediationCoordinator.Kill(pid));
    }

    private void BlockProcessInFirewall(object? parameter)
        => BlockProcessInFirewall(parameter, ProcessRemediationCoordinator.FirewallBlockPreset.Permanent);

    private void BlockProcessInFirewall(object? parameter, ProcessRemediationCoordinator.FirewallBlockPreset preset)
    {
        int pid = ResolvePid(parameter);
        if (pid <= 0)
            return;

        CloseBlockPresetMenus();
        SelectProcess(pid);
        ReportStatus(_remediationCoordinator.BlockInFirewall(pid, preset));
    }

    private void UnblockProcessInFirewall(object? parameter)
    {
        int pid = ResolvePid(parameter);
        if (pid <= 0)
            return;

        CloseBlockPresetMenus();
        SelectProcess(pid);
        ReportStatus(_remediationCoordinator.UnblockInFirewall(pid));
    }

    private void CloseBlockPresetMenus()
    {
        IsTimelineBlockPresetMenuOpen = false;
        IsSelectedProcessBlockPresetMenuOpen = false;
    }

    private void OnFirewallBlockStateChanged(ProcessRemediationCoordinator.FirewallBlockStateChange change)
    {
        var dispatcher = System.Windows.Application.Current?.Dispatcher;
        if (dispatcher is null || dispatcher.CheckAccess())
        {
            ApplyFirewallBlockStateChange(change);
            return;
        }

        dispatcher.BeginInvoke(
            new Action(() => ApplyFirewallBlockStateChange(change)),
            DispatcherPriority.Background);
    }

    private void ApplyFirewallBlockStateChange(ProcessRemediationCoordinator.FirewallBlockStateChange change)
    {
        var affectedRows = GetAffectedRows(change).ToArray();
        foreach (var row in affectedRows)
        {
            switch (change.Scope)
            {
                case ProcessRemediationCoordinator.FirewallBlockScope.Permanent:
                    row.RecordFirewallBlock(change.TimestampLocal);
                    break;
                case ProcessRemediationCoordinator.FirewallBlockScope.UntilTime when change.ExpiresAtLocal.HasValue:
                    row.RecordTimedFirewallBlock(change.TimestampLocal, change.ExpiresAtLocal.Value);
                    break;
                case ProcessRemediationCoordinator.FirewallBlockScope.UntilAppExit:
                    row.RecordFirewallBlockUntilAppExit(change.TimestampLocal);
                    break;
                default:
                    row.RecordFirewallUnblock(change.TimestampLocal, change.TimelineDetail);
                    break;
            }
        }

        if (change.ReportStatusToUser)
            ReportStatus(change.StatusMessage);
    }

    private IEnumerable<ProcessStatRow> GetAffectedRows(ProcessRemediationCoordinator.FirewallBlockStateChange change)
    {
        var rows = ProcessStats
            .Where(row => HasSameExePath(row.ExePath, change.ExePath))
            .ToArray();

        if (rows.Length > 0)
            return rows;

        return change.SourcePid > 0 && _processStatsMap.TryGetValue(change.SourcePid, out var rowByPid)
            ? new[] { rowByPid }
            : Array.Empty<ProcessStatRow>();
    }

    private void ApplyTrackedFirewallState(ProcessStatRow row)
    {
        if (!_remediationCoordinator.TryGetFirewallBlockState(row.ExePath, out var snapshot))
            return;

        switch (snapshot.Scope)
        {
            case ProcessRemediationCoordinator.FirewallBlockScope.Permanent:
                row.SyncFirewallBlockState(isBlocked: true, blockedUntilLocal: null, blockedUntilAppExit: false);
                break;
            case ProcessRemediationCoordinator.FirewallBlockScope.UntilTime:
                row.SyncFirewallBlockState(isBlocked: true, blockedUntilLocal: snapshot.ExpiresAtLocal, blockedUntilAppExit: false);
                break;
            case ProcessRemediationCoordinator.FirewallBlockScope.UntilAppExit:
                row.SyncFirewallBlockState(isBlocked: true, blockedUntilLocal: null, blockedUntilAppExit: true);
                break;
            default:
                row.SyncFirewallBlockState(isBlocked: false, blockedUntilLocal: null, blockedUntilAppExit: false);
                break;
        }
    }

    private int ResolvePid(object? parameter)
    {
        if (parameter is int pid && pid > 0)
            return pid;

        if (parameter is ProcessStatRow row && row.Pid > 0)
            return row.Pid;

        return SelectedProcessStat?.Pid ?? 0;
    }

    private void ReportStatus(string? status)
    {
        if (!string.IsNullOrWhiteSpace(status))
            _reportStatus?.Invoke(status);
    }

    private void ExportIncidentReport(object? parameter)
    {
        var row = ResolveReportRow(parameter);
        if (row is null || row.Pid <= 0)
        {
            ReportStatus("No process selected for incident report export.");
            return;
        }

        SelectProcess(row.Pid);

        string suggestedFileName = BuildIncidentReportFileName(row);
        string? path = _fileDialogService.ShowSaveIncidentReportDialog(System.Windows.Application.Current?.MainWindow, suggestedFileName);
        if (string.IsNullOrWhiteSpace(path))
        {
            ReportStatus("Incident report export canceled.");
            return;
        }

        try
        {
            var report = new ProcessIncidentReportExportService.ProcessIncidentReport(
                ExportedAtLocal: DateTime.Now,
                GeneratedBy: "TrafficMonitor",
                MachineName: Environment.MachineName,
                ProcessDetails: _processMapperService.GetProcessDetailsCached(row.Pid),
                Process: row,
                IncidentGraph: _incidentGraphBuilder.Build(row, _forensicsTracker.GetIncidentGraphSnapshot(row.Pid)),
                Conversations: _forensicsTracker.GetConversationSnapshot(row.Pid),
                SessionClusters: _forensicsTracker.GetSessionClusterSnapshot(row.Pid));

            _incidentReportExportService.Export(path, report);
            ReportStatus($"Incident report exported: {Path.GetFileName(path)}");
        }
        catch (Exception ex)
        {
            ReportStatus("Incident report export failed.");
            MessageBox.Show(ex.Message, "Export incident report failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void ToggleConversationsExpansion(object? parameter)
    {
        if (parameter is not ProcessStatRow row)
            return;

        row.ToggleConversationsExpansion();
    }

    private void ToggleSessionClustersExpansion(object? parameter)
    {
        if (parameter is not ProcessStatRow row)
            return;

        row.ToggleSessionClustersExpansion();
    }

    private bool CanSaveIncidentGraphImage(object? parameter)
        => parameter is FrameworkElement && SelectedProcessStat is not null && SelectedIncidentGraph.HasGraph;

    private void SaveIncidentGraphImage(object? parameter)
    {
        if (parameter is not FrameworkElement graphElement)
        {
            ReportStatus("Incident graph is not ready to export yet.");
            return;
        }

        var row = SelectedProcessStat;
        if (row is null || row.Pid <= 0 || !SelectedIncidentGraph.HasGraph)
        {
            ReportStatus("No incident graph is available for export.");
            return;
        }

        SelectProcess(row.Pid);

        string suggestedFileName = BuildIncidentGraphImageFileName(row);
        string? path = _fileDialogService.ShowSaveImageDialog(System.Windows.Application.Current?.MainWindow, suggestedFileName);
        if (string.IsNullOrWhiteSpace(path))
        {
            ReportStatus("Incident graph export canceled.");
            return;
        }

        try
        {
            SaveFrameworkElementAsPng(graphElement, path);
            ReportStatus($"Incident graph exported: {Path.GetFileName(path)}");
        }
        catch (Exception ex)
        {
            ReportStatus("Incident graph export failed.");
            MessageBox.Show(ex.Message, "Export incident graph failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void RegisterProcessRow(ProcessStatRow row)
    {
        _processStatsMap[row.Pid] = row;
        row.PropertyChanged += OnProcessStatPropertyChanged;
        ProcessStats.Add(row);
        RefreshAdaptiveBaseline(row);
        SelectedProcessStat ??= row;
        RefreshProcessStatsView();
    }

    private bool MatchesCurrentFilters(object item)
        => item is ProcessStatRow row && MatchesCurrentFilters(row);

    private void RefreshProcessStatsView()
    {
        ScheduleProcessStatsViewRefresh();
    }

    private void UpdateSummaryCounts()
    {
        int total = ProcessStats.Count;
        int visible = 0;
        int highRisk = 0;
        int beacon = 0;
        int exited = 0;
        int blocked = 0;

        foreach (var row in ProcessStats)
        {
            if (row.RiskScore >= 70)
                highRisk++;

            if (row.BeaconSuspected)
                beacon++;

            if (!row.IsAlive)
                exited++;

            if (row.FirewallBlocked)
                blocked++;

            if (MatchesCurrentFilters(row))
                visible++;
        }

        TotalProcessCount = total;
        VisibleProcessCount = visible;
        HighRiskProcessCount = highRisk;
        BeaconProcessCount = beacon;
        ExitedProcessCount = exited;
        BlockedProcessCount = blocked;
    }

    private void OnProcessStatPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (sender is not ProcessStatRow row)
            return;

        if (_emitNotificationsForCurrentSession)
        {
            if (e.PropertyName == nameof(ProcessStatRow.RiskScore))
                _notificationCoordinator.ObserveRiskScore(row);
            else if (e.PropertyName == nameof(ProcessStatRow.BeaconSuspected))
                _notificationCoordinator.ObserveBeacon(row);
        }

        if (string.IsNullOrWhiteSpace(e.PropertyName)
            || e.PropertyName is nameof(ProcessStatRow.RiskScore)
            or nameof(ProcessStatRow.BeaconSuspected)
            or nameof(ProcessStatRow.IsSigned)
            or nameof(ProcessStatRow.IsAlive)
            or nameof(ProcessStatRow.FirewallBlocked)
            or nameof(ProcessStatRow.ProcessName)
            or nameof(ProcessStatRow.Publisher)
            or nameof(ProcessStatRow.ExePath)
            or nameof(ProcessStatRow.TopRemoteEndpoint)
            or nameof(ProcessStatRow.FirstSuspiciousDomain)
            or nameof(ProcessStatRow.DetectionScenarios)
            or nameof(ProcessStatRow.DetectionSummaryLabel)
            or nameof(ProcessStatRow.TlsDnsInsights)
            or nameof(ProcessStatRow.TlsDnsSummaryLabel)
            or nameof(ProcessStatRow.BehaviorDeviations)
            or nameof(ProcessStatRow.BehaviorDeviationSummaryLabel)
            or nameof(ProcessStatRow.BaselineStateLabel)
            or nameof(ProcessStatRow.BaselineSummary)
            or nameof(ProcessStatRow.BaselineLearningNote))
        {
            ScheduleProcessStatsViewRefresh();
        }
    }

    private bool MatchesCurrentFilters(ProcessStatRow row)
    {
        if (ShowHighRiskOnly && row.RiskScore < 70)
            return false;

        if (ShowBeaconOnly && !row.BeaconSuspected)
            return false;

        if (ShowUnsignedOnly && row.IsSigned)
            return false;

        if (ShowExitedOnly && row.IsAlive)
            return false;

        if (ShowBlockedOnly && !row.FirewallBlocked)
            return false;

        var search = SearchText?.Trim();
        if (string.IsNullOrWhiteSpace(search))
            return true;

        return ContainsIgnoreCase(row.ProcessName, search)
            || ContainsIgnoreCase(row.Publisher, search)
            || ContainsIgnoreCase(row.ExePath, search)
            || ContainsIgnoreCase(row.TopRemoteEndpoint, search)
            || ContainsIgnoreCase(row.FirstSuspiciousDomain, search)
            || ContainsIgnoreCase(row.DetectionSummaryLabel, search)
            || ContainsIgnoreCase(row.TlsDnsSummaryLabel, search)
            || ContainsIgnoreCase(row.BehaviorDeviationSummaryLabel, search)
            || ContainsIgnoreCase(row.BaselineStateLabel, search)
            || ContainsIgnoreCase(row.BaselineSummary, search)
            || ContainsIgnoreCase(row.BaselineLearningNote, search)
            || row.DetectionScenarios.Any(scenario =>
                ContainsIgnoreCase(scenario.Title, search)
                || ContainsIgnoreCase(scenario.Summary, search)
                || ContainsIgnoreCase(scenario.MitreTechnique, search)
                || ContainsIgnoreCase(scenario.MitreTactic, search)
                || scenario.Evidence.Any(evidence => ContainsIgnoreCase(evidence.Summary, search)))
            || row.TlsDnsInsights.Any(insight =>
                ContainsIgnoreCase(insight.Title, search)
                || ContainsIgnoreCase(insight.Summary, search)
                || insight.Evidence.Any(evidence => ContainsIgnoreCase(evidence.Summary, search)))
            || row.BehaviorDeviations.Any(deviation =>
                ContainsIgnoreCase(deviation.Title, search)
                || ContainsIgnoreCase(deviation.Summary, search)
                || deviation.Evidence.Any(evidence => ContainsIgnoreCase(evidence.Summary, search)));
    }

    private void RefreshAdaptiveBaseline(ProcessStatRow row)
    {
        if (!CanUseAdaptiveBaseline(row) || _baselineFinalizedRows.Contains(row))
            return;

        ApplyAdaptiveBaselineAssessment(row, _behaviorBaselineService.Evaluate(row));
    }

    private void FinalizeAdaptiveBaseline(ProcessStatRow row, bool force = false)
    {
        if (!CanUseAdaptiveBaseline(row) || _baselineFinalizedRows.Contains(row))
            return;

        if (!force && row.IsAlive)
            return;

        ApplyAdaptiveBaselineAssessment(row, _behaviorBaselineService.FinalizeSession(row));
        _baselineFinalizedRows.Add(row);
    }

    private static bool CanUseAdaptiveBaseline(ProcessStatRow row)
        => row.Pid > 0
            && (row.FirstObservedAt != default || row.LastSeen != default)
            && row.PacketCount > 0;

    private static void ApplyAdaptiveBaselineAssessment(ProcessStatRow row, ProcessBehaviorAssessment assessment)
    {
        var deviations = assessment.Deviations
            .Select(static deviation => new ProcessStatRow.BehaviorDeviation(
                deviation.Key,
                deviation.Title,
                deviation.Summary,
                deviation.Score,
                deviation.Evidence
                    .Select(static evidence => new ProcessStatRow.DetectionEvidence(evidence))
                    .ToArray()))
            .ToArray();

        row.ApplyBehaviorBaseline(
            assessment.BaselineStateLabel,
            assessment.BaselineSummary,
            assessment.LearningNote,
            deviations);
    }

    private void ScheduleProcessStatsViewRefresh()
    {
        if (_processStatsViewRefreshPending)
            return;

        var dispatcher = System.Windows.Application.Current?.Dispatcher;
        if (dispatcher is null)
        {
            ExecutePendingProcessStatsViewRefresh();
            return;
        }

        _processStatsViewRefreshPending = true;
        dispatcher.BeginInvoke(
            new Action(ExecutePendingProcessStatsViewRefresh),
            DispatcherPriority.Background);
    }

    private void ExecutePendingProcessStatsViewRefresh()
    {
        _processStatsViewRefreshPending = false;
        ProcessStatsView.Refresh();
        RebuildVisibleProcessRows();
        UpdateSummaryCounts();
    }

    private void RebuildVisibleProcessRows()
    {
        var visibleRows = ProcessStatsView.Cast<ProcessStatRow>().ToArray();
        VisibleProcessRows.Clear();

        for (int i = 0; i < visibleRows.Length; i += 4)
        {
            int count = Math.Min(4, visibleRows.Length - i);
            var chunk = new ProcessStatRow[count];
            Array.Copy(visibleRows, i, chunk, 0, count);
            VisibleProcessRows.Add(new ProcessStatCardRow(chunk));
        }
    }

    private static bool ContainsIgnoreCase(string? value, string search)
        => !string.IsNullOrWhiteSpace(value) && value.IndexOf(search, StringComparison.OrdinalIgnoreCase) >= 0;

    private static bool HasSameExePath(string? left, string? right)
        => !string.IsNullOrWhiteSpace(left)
            && !string.IsNullOrWhiteSpace(right)
            && string.Equals(left.Trim(), right.Trim(), StringComparison.OrdinalIgnoreCase);

    private ProcessStatRow? ResolveReportRow(object? parameter)
    {
        if (parameter is ProcessStatRow row)
            return row;

        if (parameter is int pid && _processStatsMap.TryGetValue(pid, out var rowByPid))
            return rowByPid;

        return SelectedProcessStat;
    }

    private static string BuildIncidentReportFileName(ProcessStatRow row)
        => BuildProcessArtifactFileName(row, "incident", "html");

    private static string BuildIncidentGraphImageFileName(ProcessStatRow row)
        => BuildProcessArtifactFileName(row, "incident_graph", "png");

    private static string BuildProcessArtifactFileName(ProcessStatRow row, string prefix, string extension)
    {
        string processName = string.IsNullOrWhiteSpace(row.ProcessName) ? "process" : row.ProcessName.Trim();
        var invalidChars = Path.GetInvalidFileNameChars();
        var sanitizedChars = processName.Select(ch => invalidChars.Contains(ch) ? '_' : ch).ToArray();
        string sanitizedName = new string(sanitizedChars).Trim();
        if (string.IsNullOrWhiteSpace(sanitizedName))
            sanitizedName = "process";

        return $"{prefix}_{sanitizedName}_{row.Pid}_{DateTime.Now:yyyyMMdd_HHmmss}.{extension}";
    }

    private static void SaveFrameworkElementAsPng(FrameworkElement element, string path)
    {
        element.UpdateLayout();

        var bounds = VisualTreeHelper.GetDescendantBounds(element);
        double width = Math.Max(element.ActualWidth, bounds.Width);
        double height = Math.Max(element.ActualHeight, bounds.Height);
        if (width <= 0 || height <= 0)
            throw new InvalidOperationException("Incident graph visual is not ready for export yet.");

        const double exportScale = 2.0;
        const double exportPadding = 12.0;
        double dpi = 96d * exportScale;

        int contentPixelWidth = Math.Max(1, (int)Math.Ceiling(width * exportScale));
        int contentPixelHeight = Math.Max(1, (int)Math.Ceiling(height * exportScale));

        var contentBitmap = new RenderTargetBitmap(
            contentPixelWidth,
            contentPixelHeight,
            dpi,
            dpi,
            PixelFormats.Pbgra32);
        contentBitmap.Render(element);

        double finalWidth = width + (exportPadding * 2);
        double finalHeight = height + (exportPadding * 2);
        int finalPixelWidth = Math.Max(1, (int)Math.Ceiling(finalWidth * exportScale));
        int finalPixelHeight = Math.Max(1, (int)Math.Ceiling(finalHeight * exportScale));

        var renderTarget = new RenderTargetBitmap(
            finalPixelWidth,
            finalPixelHeight,
            dpi,
            dpi,
            PixelFormats.Pbgra32);

        var drawingVisual = new DrawingVisual();
        using (var context = drawingVisual.RenderOpen())
        {
            Brush background = ResolveIncidentGraphExportBackground();
            context.DrawRectangle(background, null, new Rect(0, 0, finalWidth, finalHeight));
            context.DrawImage(contentBitmap, new Rect(exportPadding, exportPadding, width, height));
        }

        renderTarget.Render(drawingVisual);

        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(renderTarget));

        using var stream = File.Create(path);
        encoder.Save(stream);
    }

    private static Brush ResolveIncidentGraphExportBackground()
    {
        var resourceBrush = System.Windows.Application.Current?.TryFindResource("SurfaceBrush") as Brush;
        if (resourceBrush is null)
            return Brushes.White;

        if (resourceBrush is not Freezable freezable)
            return resourceBrush;

        var clone = (Brush)freezable.CloneCurrentValue();
        if (clone.CanFreeze)
            clone.Freeze();

        return clone;
    }

    private static string BuildPacketTimelineDetail(PacketInfo packet)
    {
        string protocol = string.IsNullOrWhiteSpace(packet.Protocol) ? "Packet" : packet.Protocol;
        string src = FormatEndpoint(packet.SrcIp, packet.SrcPort);
        string dst = FormatEndpoint(packet.DstIp, packet.DstPort);
        return $"{protocol} {src} -> {dst}";
    }

    private static string FormatEndpoint(string ip, int? port)
    {
        if (string.IsNullOrWhiteSpace(ip))
            return "?";

        return port is int value && value > 0 ? $"{ip}:{value}" : ip;
    }

    private static bool TryExtractDnsObservation(PacketInfo packet, out string domain, out string queryType, out bool isResponse)
    {
        domain = "";
        queryType = "";
        isResponse = false;

        if (!string.IsNullOrWhiteSpace(packet.DnsQueryName))
        {
            domain = packet.DnsQueryName.Trim().TrimEnd('.');
            if (string.IsNullOrWhiteSpace(domain))
                return false;

            queryType = TryExtractDnsQueryType(packet.Info);
            isResponse = packet.DnsAnswerIps.Count > 0
                || (packet.Info?.StartsWith("Response ", StringComparison.OrdinalIgnoreCase) ?? false);
            return true;
        }

        if (!string.Equals(packet.Protocol, "DNS", StringComparison.OrdinalIgnoreCase)
            && packet.SrcPort != 53
            && packet.DstPort != 53
            && packet.SrcPort != 5353
            && packet.DstPort != 5353)
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(packet.Info))
            return false;

        string info = packet.Info.Trim();
        const string queryPrefix = "Query ";
        const string responsePrefix = "Response ";

        if (info.StartsWith(queryPrefix, StringComparison.OrdinalIgnoreCase))
        {
            isResponse = false;
            info = info[queryPrefix.Length..];
        }
        else if (info.StartsWith(responsePrefix, StringComparison.OrdinalIgnoreCase))
        {
            isResponse = true;
            info = info[responsePrefix.Length..];
        }
        else
        {
            return false;
        }

        int typeSeparator = info.IndexOf(' ');
        string candidate = typeSeparator > 0 ? info[..typeSeparator] : info;
        if (string.IsNullOrWhiteSpace(candidate) || !candidate.Contains('.'))
            return false;

        domain = candidate.Trim().TrimEnd('.');
        queryType = typeSeparator > 0 ? TryExtractDnsQueryType(info) : "";
        return !string.IsNullOrWhiteSpace(domain);
    }

    private static string TryExtractDnsQueryType(string? info)
    {
        if (string.IsNullOrWhiteSpace(info))
            return "";

        string trimmed = info.Trim();
        const string queryPrefix = "Query ";
        const string responsePrefix = "Response ";

        if (trimmed.StartsWith(queryPrefix, StringComparison.OrdinalIgnoreCase))
            trimmed = trimmed[queryPrefix.Length..];
        else if (trimmed.StartsWith(responsePrefix, StringComparison.OrdinalIgnoreCase))
            trimmed = trimmed[responsePrefix.Length..];

        int domainSeparator = trimmed.IndexOf(' ');
        if (domainSeparator < 0 || domainSeparator == trimmed.Length - 1)
            return "";

        string remainder = trimmed[(domainSeparator + 1)..].Trim();
        if (string.IsNullOrWhiteSpace(remainder))
            return "";

        int secondSpace = remainder.IndexOf(' ');
        string candidate = secondSpace > 0
            ? remainder[..secondSpace]
            : remainder;

        int arrowIndex = candidate.IndexOf("->", StringComparison.Ordinal);
        if (arrowIndex >= 0)
            candidate = candidate[..arrowIndex];

        return candidate.Trim();
    }

    private static bool TryBuildSecureHandshakeDetail(PacketInfo packet, out string detail)
    {
        detail = "";

        if (!LooksLikeSecureHandshake(packet))
            return false;

        string protocol = string.IsNullOrWhiteSpace(packet.Protocol) ? "Secure protocol" : packet.Protocol;
        string eventInfo = string.IsNullOrWhiteSpace(packet.Info) ? "handshake" : packet.Info.Trim();
        string destination = FormatEndpoint(packet.DstIp, packet.DstPort);
        string hostSuffix = string.IsNullOrWhiteSpace(packet.ServerNameHint) ? "" : $" ({packet.ServerNameHint})";
        string fingerprintSuffix = string.IsNullOrWhiteSpace(packet.TlsClientFingerprint)
            || string.IsNullOrWhiteSpace(packet.TlsClientFingerprintKind)
            ? ""
            : $" [{packet.TlsClientFingerprintKind} {ShortenFingerprint(packet.TlsClientFingerprint)}]";
        string certificateSuffix = string.IsNullOrWhiteSpace(packet.TlsCertificateSubject)
            ? ""
            : $" cert {packet.TlsCertificateSubject}";
        detail = $"{protocol} {eventInfo} with {destination}{hostSuffix}{fingerprintSuffix}{certificateSuffix}";
        return true;
    }

    private static bool LooksLikeSecureHandshake(PacketInfo packet)
    {
        string protocol = packet.Protocol ?? "";
        string info = packet.Info ?? "";

        bool secureProtocol = protocol.StartsWith("TLS", StringComparison.OrdinalIgnoreCase)
            || protocol.Equals("SSL", StringComparison.OrdinalIgnoreCase)
            || protocol.Equals("QUIC", StringComparison.OrdinalIgnoreCase);

        if (!secureProtocol)
            return false;

        if (string.IsNullOrWhiteSpace(info))
            return true;

        return info.Contains("Hello", StringComparison.OrdinalIgnoreCase)
            || info.Contains("Handshake", StringComparison.OrdinalIgnoreCase)
            || info.Contains("Initial", StringComparison.OrdinalIgnoreCase)
            || info.Contains("CRYPTO", StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryGetSuspiciousDomainReason(string domain, out string reason)
    {
        reason = "";
        if (string.IsNullOrWhiteSpace(domain))
            return false;

        string normalized = domain.Trim().TrimEnd('.').ToLowerInvariant();
        string[] suspiciousTlds = [".zip", ".mov", ".top", ".xyz", ".click", ".gq", ".work", ".rest", ".cfd", ".country", ".stream", ".download"];

        if (normalized.StartsWith("xn--", StringComparison.OrdinalIgnoreCase) || normalized.Contains(".xn--", StringComparison.OrdinalIgnoreCase))
        {
            reason = "punycode domain";
            return true;
        }

        foreach (var tld in suspiciousTlds)
        {
            if (normalized.EndsWith(tld, StringComparison.OrdinalIgnoreCase))
            {
                reason = $"high-risk TLD {tld}";
                return true;
            }
        }

        var labels = normalized.Split('.', StringSplitOptions.RemoveEmptyEntries);
        foreach (var label in labels)
        {
            if (label.Length >= 28)
            {
                reason = "very long domain label";
                return true;
            }
        }

        int digitCount = 0;
        foreach (char ch in normalized)
        {
            if (char.IsDigit(ch))
                digitCount++;
        }

        if (digitCount >= 8)
        {
            reason = "digit-heavy domain";
            return true;
        }

        return false;
    }

    private static string ShortenFingerprint(string fingerprint)
        => string.IsNullOrWhiteSpace(fingerprint)
            ? ""
            : fingerprint.Length <= 12
                ? fingerprint
                : $"{fingerprint[..6]}...{fingerprint[^6..]}";

    private static void TryPopulateProcessStart(ProcessStatRow row)
    {
        if (row.Pid <= 0)
            return;

        try
        {
            using var proc = Process.GetProcessById(row.Pid);

            string liveExePath = "";
            try
            {
                liveExePath = proc.MainModule?.FileName ?? "";
            }
            catch
            {
                // ignore path access problems
            }

            if (!string.IsNullOrWhiteSpace(row.ExePath)
                && !string.IsNullOrWhiteSpace(liveExePath)
                && !string.Equals(row.ExePath, liveExePath, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            string detail = string.IsNullOrWhiteSpace(row.ExePathShort)
                ? $"{row.ProcessName} (PID {row.Pid}) started."
                : $"{row.ExePathShort} (PID {row.Pid}) started.";

            row.RecordProcessStart(proc.StartTime, detail);
        }
        catch
        {
            // ignore: process may have already exited or be inaccessible
        }
    }
}
