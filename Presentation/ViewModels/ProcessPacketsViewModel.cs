using Domain.Models;
using Infrastructure.Networking;
using Presentation.Models;
using Presentation.Services;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Threading;

namespace Presentation.ViewModels;

public sealed class ProcessPacketsViewModel : ViewModelBase
{
    private readonly ProcessMapperService _processMapperService;
    private readonly ProcessForensicsTracker _forensicsTracker;
    private readonly ProcessLivenessTracker _livenessTracker;
    private readonly ProcessRemediationCoordinator _remediationCoordinator;

    private readonly Dictionary<int, ProcessStatRow> _processStatsMap = new();
    private readonly Dictionary<int, int> _processPacketsSinceLastSample = new();
    private readonly HashSet<int> _burstingPids = new();
    private bool _processStatsViewRefreshPending;

    private Action<int>? _showPacketsForPid;
    private Action<ProcessStatRow.InvestigationTimelineEvent>? _focusTimelineEvent;
    private Action<ProcessConversationRow>? _showPacketsForConversation;
    private Action<ProcessSessionClusterRow>? _showPacketsForSessionCluster;
    private Action<string>? _reportStatus;

    public ObservableCollection<ProcessStatRow> ProcessStats { get; } = new();
    public ObservableCollection<ProcessStatCardRow> VisibleProcessRows { get; } = new();
    public ICollectionView ProcessStatsView { get; }

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
    public ICommand UnblockProcessFirewallCommand { get; }

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
        ProcessRemediationCoordinator remediationCoordinator)
    {
        _processMapperService = processMapperService;
        _forensicsTracker = forensicsTracker;
        _livenessTracker = livenessTracker;
        _remediationCoordinator = remediationCoordinator;

        SelectProcessStatCommand = new RelayCommand(p => SelectProcessStat(p), p => p is ProcessStatRow);
        ShowPacketsForPidCommand = new RelayCommand(p => ShowPacketsForPid(p));
        FocusTimelineEventCommand = new RelayCommand(p => FocusTimelineEvent(p), p => p is ProcessStatRow.InvestigationTimelineEvent timelineEvent && timelineEvent.CanFocusPacket);
        ShowPacketsForConversationCommand = new RelayCommand(p => ShowPacketsForConversation(p), p => p is ProcessConversationRow conversation && conversation.Pid > 0);
        ShowPacketsForSessionClusterCommand = new RelayCommand(p => ShowPacketsForSessionCluster(p), p => p is ProcessSessionClusterRow sessionCluster && sessionCluster.Pid > 0);
        LocateProcessCommand = new RelayCommand(p => LocateProcess(p));
        KillProcessCommand = new RelayCommand(p => KillProcess(p));
        BlockProcessFirewallCommand = new RelayCommand(p => BlockProcessInFirewall(p));
        UnblockProcessFirewallCommand = new RelayCommand(p => UnblockProcessInFirewall(p));

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

    public void Reset()
    {
        _processStatsMap.Clear();
        _processPacketsSinceLastSample.Clear();
        _burstingPids.Clear();
        _forensicsTracker.Reset();
        _livenessTracker.Reset();

        foreach (var row in ProcessStats)
            row.PropertyChanged -= OnProcessStatPropertyChanged;

        ProcessStats.Clear();
        VisibleProcessRows.Clear();
        SelectedProcessStat = null;
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

        var forensicsUpdate = _forensicsTracker.Update(packet, row);

        if (isFirstPacket)
            row.RecordFirstPacket(packet.Timestamp, BuildPacketTimelineDetail(packet));

        if (forensicsUpdate.HasFirstOutboundConnection)
            row.RecordFirstOutboundConnection(packet.Timestamp, forensicsUpdate.FirstOutboundConnectionDetail);

        var firstDomain = TryExtractDomain(packet);
        if (!string.IsNullOrWhiteSpace(firstDomain))
        {
            row.RecordFirstDomain(packet.Timestamp, firstDomain);

            if (TryGetSuspiciousDomainReason(firstDomain, out var suspiciousDomainReason))
                row.RecordFirstSuspiciousDomain(packet.Timestamp, firstDomain, suspiciousDomainReason);
        }

        if (TryBuildSecureHandshakeDetail(packet, out var handshakeDetail))
            row.RecordFirstSecureHandshake(packet.Timestamp, handshakeDetail);

        if (forensicsUpdate.HasBeaconDetected)
            row.RecordBeaconDetected(packet.Timestamp, forensicsUpdate.BeaconDetail);

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
        }

        RefreshSelectedProcessDetails();
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
            return;

        SelectedProcessStat.UpdateConversations(_forensicsTracker.GetConversationSnapshot(SelectedProcessStat.Pid));
        SelectedProcessStat.UpdateSessionClusters(_forensicsTracker.GetSessionClusterSnapshot(SelectedProcessStat.Pid));
    }

    private ProcessStatRow GetOrCreateProcessRow(int pid, string processName)
    {
        if (_processStatsMap.TryGetValue(pid, out var row))
            return row;

        row = new ProcessStatRow(pid, processName, 0, 0);

        var details = _processMapperService.GetProcessDetailsCached(pid);
        var parentName = details.ParentPid > 0 ? _processMapperService.GetProcessNameCached(details.ParentPid) : "";
        row.UpdateIdentity(details.ExePath, details.Publisher, details.IsSigned, details.SignerSubject, details.ParentPid, parentName);
        TryPopulateProcessStart(row);

        RegisterProcessRow(row);
        return row;
    }

    private void ShowPacketsForPid(object? parameter)
    {
        if (parameter is not int pid)
            return;

        SelectProcess(pid);
        _showPacketsForPid?.Invoke(pid);
    }

    private void SelectProcessStat(object? parameter)
    {
        if (parameter is ProcessStatRow row)
            SelectedProcessStat = row;
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
        if (parameter is not int pid)
            return;

        SelectProcess(pid);
        ReportStatus(_remediationCoordinator.Locate(pid));
    }

    private void KillProcess(object? parameter)
    {
        if (parameter is not int pid)
            return;

        SelectProcess(pid);
        ReportStatus(_remediationCoordinator.Kill(pid));
    }

    private void BlockProcessInFirewall(object? parameter)
    {
        if (parameter is not int pid)
            return;

        SelectProcess(pid);
        var status = _remediationCoordinator.BlockInFirewall(pid);
        if (!string.IsNullOrWhiteSpace(status)
            && status.StartsWith("Firewall: blocked", StringComparison.OrdinalIgnoreCase)
            && _processStatsMap.TryGetValue(pid, out var row))
        {
            row.RecordFirewallBlock(DateTime.Now);
        }

        ReportStatus(status);
    }

    private void UnblockProcessInFirewall(object? parameter)
    {
        if (parameter is not int pid)
            return;

        SelectProcess(pid);
        var status = _remediationCoordinator.UnblockInFirewall(pid);
        if (!string.IsNullOrWhiteSpace(status)
            && status.StartsWith("Firewall: unblocked", StringComparison.OrdinalIgnoreCase)
            && _processStatsMap.TryGetValue(pid, out var row))
        {
            row.RecordFirewallUnblock(DateTime.Now);
        }

        ReportStatus(status);
    }

    private void ReportStatus(string? status)
    {
        if (!string.IsNullOrWhiteSpace(status))
            _reportStatus?.Invoke(status);
    }

    private void RegisterProcessRow(ProcessStatRow row)
    {
        _processStatsMap[row.Pid] = row;
        row.PropertyChanged += OnProcessStatPropertyChanged;
        ProcessStats.Add(row);
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
        if (sender is not ProcessStatRow)
            return;

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
            or nameof(ProcessStatRow.FirstSuspiciousDomain))
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
            || ContainsIgnoreCase(row.FirstSuspiciousDomain, search);
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

        for (int i = 0; i < visibleRows.Length; i += 3)
        {
            int count = Math.Min(3, visibleRows.Length - i);
            var chunk = new ProcessStatRow[count];
            Array.Copy(visibleRows, i, chunk, 0, count);
            VisibleProcessRows.Add(new ProcessStatCardRow(chunk));
        }
    }

    private static bool ContainsIgnoreCase(string? value, string search)
        => !string.IsNullOrWhiteSpace(value) && value.IndexOf(search, StringComparison.OrdinalIgnoreCase) >= 0;

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

    private static string? TryExtractDomain(PacketInfo packet)
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

    private static bool TryBuildSecureHandshakeDetail(PacketInfo packet, out string detail)
    {
        detail = "";

        if (!LooksLikeSecureHandshake(packet))
            return false;

        string protocol = string.IsNullOrWhiteSpace(packet.Protocol) ? "Secure protocol" : packet.Protocol;
        string eventInfo = string.IsNullOrWhiteSpace(packet.Info) ? "handshake" : packet.Info.Trim();
        string destination = FormatEndpoint(packet.DstIp, packet.DstPort);
        string hostSuffix = string.IsNullOrWhiteSpace(packet.ServerNameHint) ? "" : $" ({packet.ServerNameHint})";
        detail = $"{protocol} {eventInfo} with {destination}{hostSuffix}";
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
