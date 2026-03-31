using Domain.Models;
using Infrastructure.Networking;
using Presentation.Models;
using Presentation.Services;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Windows.Data;
using System.Windows.Input;

namespace Presentation.ViewModels;

public sealed class ProcessPacketsViewModel : ViewModelBase
{
    private readonly ProcessMapperService _processMapperService;
    private readonly ProcessForensicsTracker _forensicsTracker;
    private readonly ProcessLivenessTracker _livenessTracker;
    private readonly ProcessRemediationCoordinator _remediationCoordinator;

    private readonly Dictionary<int, ProcessStatRow> _processStatsMap = new();
    private readonly Dictionary<int, int> _processPacketsSinceLastSample = new();

    private Action<int>? _showPacketsForPid;
    private Action<int>? _focusOnPid;
    private Action<string>? _reportStatus;

    public ObservableCollection<ProcessStatRow> ProcessStats { get; } = new();
    public ICollectionView ProcessStatsView { get; }

    private ProcessStatRow? _selectedProcessStat;
    public ProcessStatRow? SelectedProcessStat
    {
        get => _selectedProcessStat;
        set
        {
            if (!Set(ref _selectedProcessStat, value))
                return;

            RefreshSelectedProcessDetails();
        }
    }

    public ICommand ShowPacketsForPidCommand { get; }
    public ICommand FocusOnPidCommand { get; }
    public ICommand LocateProcessCommand { get; }
    public ICommand KillProcessCommand { get; }
    public ICommand BlockProcessFirewallCommand { get; }
    public ICommand UnblockProcessFirewallCommand { get; }

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

        ShowPacketsForPidCommand = new RelayCommand(p => ShowPacketsForPid(p));
        FocusOnPidCommand = new RelayCommand(p => FocusOnPid(p));
        LocateProcessCommand = new RelayCommand(p => LocateProcess(p));
        KillProcessCommand = new RelayCommand(p => KillProcess(p));
        BlockProcessFirewallCommand = new RelayCommand(p => BlockProcessInFirewall(p));
        UnblockProcessFirewallCommand = new RelayCommand(p => UnblockProcessInFirewall(p));

        ProcessStatsView = CollectionViewSource.GetDefaultView(ProcessStats);
        ProcessStatsView.SortDescriptions.Add(new SortDescription(nameof(ProcessStatRow.RiskScore), ListSortDirection.Descending));
        ProcessStatsView.SortDescriptions.Add(new SortDescription(nameof(ProcessStatRow.TotalBytes), ListSortDirection.Descending));

        if (ProcessStatsView is ICollectionViewLiveShaping liveShaping && liveShaping.CanChangeLiveSorting)
        {
            liveShaping.LiveSortingProperties.Add(nameof(ProcessStatRow.RiskScore));
            liveShaping.LiveSortingProperties.Add(nameof(ProcessStatRow.TotalBytes));
            liveShaping.IsLiveSorting = true;
        }
    }

    public void ConfigureActions(Action<int> showPacketsForPid, Action<int> focusOnPid, Action<string> reportStatus)
    {
        _showPacketsForPid = showPacketsForPid;
        _focusOnPid = focusOnPid;
        _reportStatus = reportStatus;
    }

    public void Reset()
    {
        _processStatsMap.Clear();
        _processPacketsSinceLastSample.Clear();
        _forensicsTracker.Reset();
        _livenessTracker.Reset();

        ProcessStats.Clear();
        SelectedProcessStat = null;
    }

    public void SeedProcessSummary(int pid, string processName, long packetCount, long totalBytes)
    {
        if (pid <= 0 || string.IsNullOrWhiteSpace(processName))
            return;

        if (_processStatsMap.ContainsKey(pid))
            return;

        var row = new ProcessStatRow(pid, processName, packetCount, totalBytes);
        _processStatsMap[pid] = row;
        ProcessStats.Add(row);
        SelectedProcessStat ??= row;
    }

    public void PrepareForFlush()
    {
        _processPacketsSinceLastSample.Clear();
        _forensicsTracker.CleanupIfNeeded();
        _livenessTracker.RefreshIfNeeded(ProcessStats);
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

        _forensicsTracker.Update(packet, row);

        if (isFirstPacket)
            row.RecordFirstPacket(packet.Timestamp, BuildPacketTimelineDetail(packet));

        var firstDomain = TryExtractDomain(packet);
        if (!string.IsNullOrWhiteSpace(firstDomain))
            row.RecordFirstDomain(packet.Timestamp, firstDomain);

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
        }

        RefreshSelectedProcessDetails();
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

        _processStatsMap[pid] = row;
        ProcessStats.Add(row);
        SelectedProcessStat ??= row;
        return row;
    }

    private void ShowPacketsForPid(object? parameter)
    {
        if (parameter is not int pid)
            return;

        SelectProcess(pid);
        _showPacketsForPid?.Invoke(pid);
    }

    private void FocusOnPid(object? parameter)
    {
        if (parameter is not int pid)
            return;

        SelectProcess(pid);
        _focusOnPid?.Invoke(pid);
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
