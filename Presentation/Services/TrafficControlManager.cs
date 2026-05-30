using Application.Abstractions;
using Domain.Models;
using Infrastructure.Remediation;
using Presentation.Abstractions;
using Presentation.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading;
using System.Windows;

namespace Presentation.Services;

public readonly record struct TrafficControlSaveResult(bool HasWarnings, string StatusMessage);

public enum HostQuickBlockPreset
{
    UntilAppExit,
    FifteenMinutes
}

public sealed class TrafficControlManager : IDisposable
{
    private static readonly TimeSpan RefreshInterval = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan LocalIpsRefreshInterval = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan QuickHostTemporaryBlockDuration = TimeSpan.FromMinutes(15);

    private readonly object _gate = new();
    private readonly TrafficControlRulesStore _store;
    private readonly TrafficHistoryStore _historyStore;
    private readonly WindowsShellNotificationService _shellNotificationService;
    private readonly WindowsRemediationService _remediationService;
    private readonly ILocalAddressService _localAddressService;
    private readonly IUserPromptService _prompt;
    private readonly Dictionary<string, AppliedQosPolicyEntry> _appliedQosPolicies = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, ActiveQuotaBlockEntry> _activeQuotaBlocks = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, ActiveHostFirewallBlockEntry> _activeHostFirewallBlocks = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, AppliedHostQosPolicyEntry> _activeHostQosPolicies = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, long> _liveBytesByRuleDay = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, long> _persistedBytesCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _suppressedQosEntryKeys = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _suppressedQuotaEntryKeys = new(StringComparer.OrdinalIgnoreCase);
    private readonly Timer _refreshTimer;

    private List<TrafficControlRule> _rules;
    private HashSet<string> _localIps = new(StringComparer.OrdinalIgnoreCase);
    private DateTime _lastLocalIpsRefreshUtc = DateTime.MinValue;
    private int _historyVersion;
    private int _refreshInProgress;
    private bool _disposed;

    public TrafficControlManager(
        TrafficControlRulesStore store,
        TrafficHistoryStore historyStore,
        WindowsShellNotificationService shellNotificationService,
        WindowsRemediationService remediationService,
        ILocalAddressService localAddressService,
        IUserPromptService prompt)
    {
        _store = store;
        _historyStore = historyStore;
        _shellNotificationService = shellNotificationService;
        _remediationService = remediationService;
        _localAddressService = localAddressService;
        _prompt = prompt;
        _rules = _store.Load()
            .Select(TrafficControlRule.CreateNormalized)
            .ToList();

        _historyStore.HistoryChanged += OnHistoryChanged;
        _refreshTimer = new Timer(OnRefreshTimer, null, RefreshInterval, RefreshInterval);

        RefreshAppliedQosPolicies();
    }

    public IReadOnlyList<TrafficControlRule> GetRulesSnapshot()
    {
        lock (_gate)
        {
            return _rules
                .Select(TrafficControlRule.CreateNormalized)
                .ToArray();
        }
    }

    public TrafficControlSaveResult SaveRules(IEnumerable<TrafficControlRule> rules)
    {
        ArgumentNullException.ThrowIfNull(rules);

        var normalizedRules = rules
            .Select(TrafficControlRule.CreateNormalized)
            .ToList();

        string warning = string.Empty;

        RemoveAllAppliedQosPolicies(ref warning);
        RemoveAllQuotaBlocks(ref warning);

        lock (_gate)
        {
            _rules = normalizedRules;
            _store.Save(_rules);
            _liveBytesByRuleDay.Clear();
            _persistedBytesCache.Clear();
            _suppressedQosEntryKeys.Clear();
            _suppressedQuotaEntryKeys.Clear();
        }

        RefreshAppliedQosPolicies();

        int activeRuleCount = normalizedRules.Count(static rule => rule.Enabled);
        string message = activeRuleCount == 0
            ? "Saved traffic control rules. No active rules are enabled."
            : $"Saved {activeRuleCount:N0} active traffic control rule(s). Windows may ask for admin approval when throttling, priority, or auto-block actions first apply.";

        if (!string.IsNullOrWhiteSpace(warning))
            message = $"{message}\n\nSome active controls still need attention: {warning}";

        return new TrafficControlSaveResult(
            HasWarnings: !string.IsNullOrWhiteSpace(warning),
            StatusMessage: message);
    }

    public void BeginLiveSession()
    {
        lock (_gate)
        {
            _liveBytesByRuleDay.Clear();
            _persistedBytesCache.Clear();
            _suppressedQuotaEntryKeys.Clear();
        }
    }

    public string? BlockHost(string remoteAddress, HostQuickBlockPreset preset = HostQuickBlockPreset.UntilAppExit)
    {
        if (!TryNormalizeHostRemoteAddress(remoteAddress, out string normalizedAddress))
            return "Host block failed: the selected endpoint does not have a valid IP address.";

        var response = _prompt.Show(
            BuildHostBlockPrompt(normalizedAddress, preset),
            GetHostBlockPromptTitle(preset),
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (response != MessageBoxResult.Yes)
            return null;

        string ruleBaseName = BuildQuickHostFirewallRuleBase(normalizedAddress);
        if (!_remediationService.TryBlockTrafficInFirewall(ruleBaseName, null, normalizedAddress, out string error))
            return $"Host block failed: {error}";

        DateTime nowLocal = DateTime.Now;
        DateTime? expiresAtLocal = preset == HostQuickBlockPreset.FifteenMinutes
            ? nowLocal.Add(QuickHostTemporaryBlockDuration)
            : null;

        TrackQuickHostFirewallBlock(normalizedAddress, ruleBaseName, preset, expiresAtLocal);
        return BuildHostBlockStatus(normalizedAddress, preset, expiresAtLocal);
    }

    public string? ThrottleHost(string remoteAddress, int throttleMbps)
    {
        if (!TryNormalizeHostRemoteAddress(remoteAddress, out string normalizedAddress))
            return "Host throttle failed: the selected endpoint does not have a valid IP address.";

        int normalizedThrottleMbps = Math.Clamp(throttleMbps, 1, 100_000);
        var response = _prompt.Show(
            BuildHostThrottlePrompt(normalizedAddress, normalizedThrottleMbps),
            "Throttle host",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (response != MessageBoxResult.Yes)
            return null;

        string hostKey = BuildQuickHostEntryKey(normalizedAddress);
        AppliedHostQosPolicyEntry? existingEntry;
        lock (_gate)
            _activeHostQosPolicies.TryGetValue(hostKey, out existingEntry);

        if (existingEntry is not null)
            _remediationService.TryRemoveQosPolicy(existingEntry.PolicyName, out _);

        string policyName = BuildQuickHostQosPolicyName(normalizedAddress);
        var spec = new WindowsRemediationService.QosPolicySpec(
            policyName,
            AppPath: null,
            RemoteAddress: normalizedAddress,
            ThrottleBitsPerSecond: (ulong)normalizedThrottleMbps * 1_000_000UL,
            DscpAction: null);

        if (!_remediationService.TryApplyQosPolicy(spec, out string error))
            return $"Host throttle failed: {error}";

        lock (_gate)
        {
            _activeHostQosPolicies[hostKey] = new AppliedHostQosPolicyEntry(
                hostKey,
                normalizedAddress,
                normalizedThrottleMbps,
                policyName,
                spec);
        }

        return $"Traffic control: throttling {normalizedAddress} to {normalizedThrottleMbps:N0} Mbps until TrafficMonitor exits.";
    }

    public TrafficControlRule BuildHostRuleDraft(string remoteAddress, string? displayHost)
    {
        string normalizedAddress = TryNormalizeHostRemoteAddress(remoteAddress, out string parsedAddress)
            ? parsedAddress
            : (remoteAddress ?? string.Empty).Trim();
        string friendlyHost = string.IsNullOrWhiteSpace(displayHost)
            ? normalizedAddress
            : displayHost.Trim();

        string ruleName = string.Equals(friendlyHost, normalizedAddress, StringComparison.OrdinalIgnoreCase)
            ? $"Host rule: {normalizedAddress}"
            : $"Host rule: {friendlyHost}";

        return TrafficControlRule.CreateNormalized(new TrafficControlRule
        {
            Name = ruleName,
            Enabled = true,
            TargetKind = TrafficControlTargetKinds.Host,
            RemoteAddress = normalizedAddress,
            NotifyOnTrigger = true,
            AutoBlockOnQuota = true
        });
    }

    public void ObservePacket(ProcessStatRow row, PacketInfo packet)
    {
        ArgumentNullException.ThrowIfNull(row);
        ArgumentNullException.ThrowIfNull(packet);

        if (_disposed)
            return;

        List<TrafficControlRule> rules;
        lock (_gate)
            rules = _rules.Select(TrafficControlRule.CreateNormalized).ToList();

        if (rules.Count == 0)
            return;

        DateTime nowLocal = packet.Timestamp == default ? DateTime.Now : packet.Timestamp;
        string remoteIp = GetRemoteIp(packet);

        foreach (var rule in rules)
        {
            if (!rule.Enabled || !IsScheduleActive(rule, nowLocal))
                continue;

            if (!RuleMatches(rule, row, remoteIp))
                continue;

            EnsureRuleQosForObservedProcess(rule, row);

            if (rule.DailyQuotaMb <= 0)
                continue;

            long totalBytes = AddLiveBytes(rule.Id, nowLocal.Date, packet.Length) + GetPersistedBytesForToday(rule, nowLocal.Date);
            long quotaBytes = rule.DailyQuotaMb * 1_048_576L;
            if (totalBytes < quotaBytes)
                continue;

            HandleQuotaExceeded(rule, row, remoteIp, totalBytes, nowLocal);
        }
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        _refreshTimer.Dispose();
        _historyStore.HistoryChanged -= OnHistoryChanged;

        string warning = string.Empty;
        RemoveAllAppliedQosPolicies(ref warning);
        RemoveAllQuotaBlocks(ref warning);
        RemoveAllQuickHostFirewallBlocks(ref warning);
        RemoveAllQuickHostQosPolicies(ref warning);
    }

    private void TrackQuickHostFirewallBlock(string remoteAddress, string ruleBaseName, HostQuickBlockPreset preset, DateTime? expiresAtLocal)
    {
        string hostKey = BuildQuickHostEntryKey(remoteAddress);
        ActiveHostFirewallBlockEntry? previous;
        var next = new ActiveHostFirewallBlockEntry(hostKey, remoteAddress, ruleBaseName, preset, expiresAtLocal);

        lock (_gate)
        {
            _activeHostFirewallBlocks.TryGetValue(hostKey, out previous);
            _activeHostFirewallBlocks[hostKey] = next;
        }

        previous?.Dispose();

        if (preset == HostQuickBlockPreset.FifteenMinutes && expiresAtLocal.HasValue)
            next.StartTimer(OnQuickHostFirewallBlockExpired, hostKey, GetDueTime(expiresAtLocal.Value));
    }

    private void OnQuickHostFirewallBlockExpired(object? state)
    {
        if (state is not string hostKey)
            return;

        ActiveHostFirewallBlockEntry? entry;
        lock (_gate)
        {
            if (!_activeHostFirewallBlocks.TryGetValue(hostKey, out entry)
                || entry.Preset != HostQuickBlockPreset.FifteenMinutes)
            {
                return;
            }
        }

        if (!_remediationService.TryRemoveTrafficFirewallRule(entry.RuleBaseName, out string error))
        {
            entry.Reschedule(GetDueTime(DateTime.Now.Add(TimeSpan.FromMinutes(1))));
            NotifyRuleStatus(
                title: $"Temporary host block still active: {entry.RemoteAddress}",
                message: error,
                severity: NotificationSeverity.Warning);
            return;
        }

        lock (_gate)
            _activeHostFirewallBlocks.Remove(hostKey);

        entry.Dispose();
        NotifyRuleStatus(
            title: $"Host block expired: {entry.RemoteAddress}",
            message: "TrafficMonitor restored access after the 15-minute block window ended.",
            severity: NotificationSeverity.Info);
    }

    private void RemoveAllQuickHostFirewallBlocks(ref string warning)
    {
        Dictionary<string, ActiveHostFirewallBlockEntry> blocks;
        lock (_gate)
        {
            blocks = _activeHostFirewallBlocks.ToDictionary(static entry => entry.Key, static entry => entry.Value, StringComparer.OrdinalIgnoreCase);
            _activeHostFirewallBlocks.Clear();
        }

        foreach (var entry in blocks.Values)
        {
            try
            {
                if (!_remediationService.TryRemoveTrafficFirewallRule(entry.RuleBaseName, out string error))
                    warning = AppendWarning(warning, error);
            }
            finally
            {
                entry.Dispose();
            }
        }
    }

    private void RemoveAllQuickHostQosPolicies(ref string warning)
    {
        Dictionary<string, AppliedHostQosPolicyEntry> policies;
        lock (_gate)
        {
            policies = _activeHostQosPolicies.ToDictionary(static entry => entry.Key, static entry => entry.Value, StringComparer.OrdinalIgnoreCase);
            _activeHostQosPolicies.Clear();
        }

        foreach (var entry in policies.Values)
        {
            if (_remediationService.TryRemoveQosPolicy(entry.PolicyName, out string error))
                continue;

            warning = AppendWarning(warning, error);
        }
    }

    private void OnHistoryChanged()
    {
        lock (_gate)
        {
            _persistedBytesCache.Clear();
            _historyVersion++;
        }
    }

    private void OnRefreshTimer(object? state)
        => RefreshAppliedQosPolicies();

    private void RefreshAppliedQosPolicies()
    {
        if (_disposed || Interlocked.Exchange(ref _refreshInProgress, 1) == 1)
            return;

        try
        {
            List<TrafficControlRule> rules;
            Dictionary<string, AppliedQosPolicyEntry> currentPolicies;
            HashSet<string> suppressedEntries;

            lock (_gate)
            {
                rules = _rules.Select(TrafficControlRule.CreateNormalized).ToList();
                currentPolicies = _appliedQosPolicies.ToDictionary(static entry => entry.Key, static entry => entry.Value, StringComparer.OrdinalIgnoreCase);
                suppressedEntries = new HashSet<string>(_suppressedQosEntryKeys, StringComparer.OrdinalIgnoreCase);
            }

            var desiredPolicies = BuildDesiredQosPolicies(rules, DateTime.Now);

            foreach (var existing in currentPolicies)
            {
                if (desiredPolicies.ContainsKey(existing.Key))
                    continue;

                if (_remediationService.TryRemoveQosPolicy(existing.Value.PolicyName, out _))
                {
                    lock (_gate)
                        _appliedQosPolicies.Remove(existing.Key);
                }
            }

            foreach (var desired in desiredPolicies)
            {
                if (currentPolicies.ContainsKey(desired.Key) || suppressedEntries.Contains(desired.Key))
                    continue;

                if (_remediationService.TryApplyQosPolicy(desired.Value.Spec, out string error))
                {
                    lock (_gate)
                        _appliedQosPolicies[desired.Key] = desired.Value;
                }
                else
                {
                    lock (_gate)
                        _suppressedQosEntryKeys.Add(desired.Key);

                    NotifyRuleStatus(
                        title: $"Traffic control rule pending: {desired.Value.RuleName}",
                        message: error,
                        severity: NotificationSeverity.Warning);
                }
            }
        }
        finally
        {
            Interlocked.Exchange(ref _refreshInProgress, 0);
        }
    }

    private Dictionary<string, AppliedQosPolicyEntry> BuildDesiredQosPolicies(IReadOnlyList<TrafficControlRule> rules, DateTime nowLocal)
    {
        var desired = new Dictionary<string, AppliedQosPolicyEntry>(StringComparer.OrdinalIgnoreCase);
        IReadOnlyList<RunningProcessPathEntry> runningProcesses = GetRunningProcessPaths();

        foreach (var rule in rules)
        {
            if (!rule.Enabled || !IsScheduleActive(rule, nowLocal) || !HasQosControl(rule))
                continue;

            ulong? throttleBits = rule.ThrottleMbps > 0
                ? (ulong)rule.ThrottleMbps * 1_000_000UL
                : null;
            sbyte? dscpAction = GetDscpAction(rule.Priority);

            if (TrafficControlTargetKinds.IncludesProcess(rule.TargetKind))
            {
                var processPaths = runningProcesses
                    .Where(process => MatchesProcessFilter(process.ProcessName, process.ExeName, rule.ProcessFilter))
                    .Select(static process => process.ExePath)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray();

                foreach (string processPath in processPaths)
                {
                    string key = BuildQosEntryKey(rule.Id, processPath, rule.RemoteAddress);
                    desired[key] = new AppliedQosPolicyEntry(
                        key,
                        BuildQosPolicyName(rule.Id, processPath, rule.RemoteAddress),
                        rule.Name,
                        processPath,
                        rule.RemoteAddress,
                        new WindowsRemediationService.QosPolicySpec(
                            BuildQosPolicyName(rule.Id, processPath, rule.RemoteAddress),
                            processPath,
                            string.IsNullOrWhiteSpace(rule.RemoteAddress) ? null : rule.RemoteAddress,
                            throttleBits,
                            dscpAction));
                }

                continue;
            }

            string hostKey = BuildQosEntryKey(rule.Id, null, rule.RemoteAddress);
            desired[hostKey] = new AppliedQosPolicyEntry(
                hostKey,
                BuildQosPolicyName(rule.Id, null, rule.RemoteAddress),
                rule.Name,
                null,
                rule.RemoteAddress,
                new WindowsRemediationService.QosPolicySpec(
                    BuildQosPolicyName(rule.Id, null, rule.RemoteAddress),
                    null,
                    rule.RemoteAddress,
                    throttleBits,
                    dscpAction));
        }

        return desired;
    }

    private IReadOnlyList<RunningProcessPathEntry> GetRunningProcessPaths()
    {
        var entries = new List<RunningProcessPathEntry>();

        foreach (var process in Process.GetProcesses())
        {
            try
            {
                using (process)
                {
                    if (process.HasExited)
                        continue;

                    string exePath;
                    try
                    {
                        exePath = process.MainModule?.FileName ?? string.Empty;
                    }
                    catch
                    {
                        continue;
                    }

                    if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath))
                        continue;

                    entries.Add(new RunningProcessPathEntry(
                        process.ProcessName ?? string.Empty,
                        Path.GetFileName(exePath),
                        exePath));
                }
            }
            catch
            {
                // ignore inaccessible processes
            }
        }

        return entries;
    }

    private void EnsureRuleQosForObservedProcess(TrafficControlRule rule, ProcessStatRow row)
    {
        if (!HasQosControl(rule)
            || !TrafficControlTargetKinds.IncludesProcess(rule.TargetKind)
            || string.IsNullOrWhiteSpace(row.ExePath)
            || !File.Exists(row.ExePath))
        {
            return;
        }

        string key = BuildQosEntryKey(rule.Id, row.ExePath, rule.RemoteAddress);
        lock (_gate)
        {
            if (_appliedQosPolicies.ContainsKey(key) || _suppressedQosEntryKeys.Contains(key))
                return;
        }

        ulong? throttleBits = rule.ThrottleMbps > 0
            ? (ulong)rule.ThrottleMbps * 1_000_000UL
            : null;
        sbyte? dscpAction = GetDscpAction(rule.Priority);

        string policyName = BuildQosPolicyName(rule.Id, row.ExePath, rule.RemoteAddress);
        var spec = new WindowsRemediationService.QosPolicySpec(
            policyName,
            row.ExePath,
            string.IsNullOrWhiteSpace(rule.RemoteAddress) ? null : rule.RemoteAddress,
            throttleBits,
            dscpAction);

        if (_remediationService.TryApplyQosPolicy(spec, out string error))
        {
            lock (_gate)
            {
                _appliedQosPolicies[key] = new AppliedQosPolicyEntry(
                    key,
                    policyName,
                    rule.Name,
                    row.ExePath,
                    rule.RemoteAddress,
                    spec);
            }

            return;
        }

        lock (_gate)
            _suppressedQosEntryKeys.Add(key);

        NotifyRuleStatus(
            title: $"Traffic control rule pending: {rule.Name}",
            message: error,
            severity: NotificationSeverity.Warning);
    }

    private void HandleQuotaExceeded(TrafficControlRule rule, ProcessStatRow row, string remoteIp, long totalBytes, DateTime nowLocal)
    {
        string dayKey = nowLocal.ToString("yyyyMMdd");
        string blockKey = string.Join("|", rule.Id, dayKey, NormalizeQuotaBlockKeyComponent(row.ExePath), NormalizeQuotaBlockKeyComponent(remoteIp));

        lock (_gate)
        {
            if (_activeQuotaBlocks.ContainsKey(blockKey) || _suppressedQuotaEntryKeys.Contains(blockKey))
                return;
        }

        string title = $"Daily quota reached: {rule.Name}";
        string detail = $"Observed {FormatBytes(totalBytes)} today. Rule target: {BuildRuleTargetLabel(rule, row, remoteIp)}.";

        if (rule.NotifyOnTrigger || rule.AutoBlockOnQuota)
        {
            NotifyRuleStatus(title, detail, rule.AutoBlockOnQuota ? NotificationSeverity.Warning : NotificationSeverity.Info);
        }

        row.RecordQuotaAlert(rule.Id, nowLocal, title, detail);

        if (!rule.AutoBlockOnQuota)
            return;

        if (!TryApplyQuotaBlock(rule, row, remoteIp, nowLocal, blockKey, out string blockDetail))
        {
            lock (_gate)
                _suppressedQuotaEntryKeys.Add(blockKey);

            NotifyRuleStatus(
                title: $"Traffic quota action pending: {rule.Name}",
                message: blockDetail,
                severity: NotificationSeverity.Warning);
            return;
        }

        row.RecordQuotaAlert(rule.Id + "-block", nowLocal, $"Traffic was auto-blocked: {rule.Name}", blockDetail);
        NotifyRuleStatus(
            title: $"Traffic was auto-blocked: {rule.Name}",
            message: blockDetail,
            severity: NotificationSeverity.Warning);
    }

    private bool TryApplyQuotaBlock(TrafficControlRule rule, ProcessStatRow row, string remoteIp, DateTime nowLocal, string blockKey, out string detail)
    {
        detail = string.Empty;

        string ruleBaseName = BuildQuotaFirewallRuleBase(rule.Id, nowLocal, row.ExePath, remoteIp);
        string? exePath = TrafficControlTargetKinds.IncludesProcess(rule.TargetKind) ? row.ExePath : null;
        string? remoteAddress = TrafficControlTargetKinds.IncludesHost(rule.TargetKind) ? remoteIp : null;

        if (TrafficControlTargetKinds.IncludesProcess(rule.TargetKind) && string.IsNullOrWhiteSpace(exePath))
        {
            detail = "The rule matched traffic, but the executable path was not available for auto-block.";
            return false;
        }

        if (TrafficControlTargetKinds.IncludesHost(rule.TargetKind) && string.IsNullOrWhiteSpace(remoteAddress))
        {
            detail = "The rule matched traffic, but the remote IP was not available for host-level auto-block.";
            return false;
        }

        if (!_remediationService.TryBlockTrafficInFirewall(ruleBaseName, exePath, remoteAddress, out string error))
        {
            detail = error;
            return false;
        }

        DateTime expiresAtLocal = nowLocal.Date.AddDays(1);
        var lease = new ActiveQuotaBlockEntry(
            blockKey,
            rule.Id,
            ruleBaseName,
            expiresAtLocal,
            Timer: new Timer(OnQuotaBlockExpired, blockKey, GetDueTime(expiresAtLocal), Timeout.InfiniteTimeSpan));

        lock (_gate)
            _activeQuotaBlocks[blockKey] = lease;

        detail = $"TrafficMonitor blocked {BuildRuleTargetLabel(rule, row, remoteIp)} until the daily quota resets at {expiresAtLocal:HH:mm}.";
        return true;
    }

    private void OnQuotaBlockExpired(object? state)
    {
        if (state is not string blockKey)
            return;

        ActiveQuotaBlockEntry? lease = null;
        lock (_gate)
        {
            if (_activeQuotaBlocks.TryGetValue(blockKey, out lease))
                _activeQuotaBlocks.Remove(blockKey);
        }

        if (lease is null)
            return;

        try
        {
            _remediationService.TryRemoveTrafficFirewallRule(lease.RuleBaseName, out _);
        }
        finally
        {
            lease.Timer.Dispose();
        }
    }

    private void RemoveAllAppliedQosPolicies(ref string warning)
    {
        Dictionary<string, AppliedQosPolicyEntry> applied;
        lock (_gate)
        {
            applied = _appliedQosPolicies.ToDictionary(static entry => entry.Key, static entry => entry.Value, StringComparer.OrdinalIgnoreCase);
            _appliedQosPolicies.Clear();
        }

        foreach (var entry in applied.Values)
        {
            if (_remediationService.TryRemoveQosPolicy(entry.PolicyName, out string error))
                continue;

            warning = AppendWarning(warning, error);
        }
    }

    private void RemoveAllQuotaBlocks(ref string warning)
    {
        Dictionary<string, ActiveQuotaBlockEntry> blocks;
        lock (_gate)
        {
            blocks = _activeQuotaBlocks.ToDictionary(static entry => entry.Key, static entry => entry.Value, StringComparer.OrdinalIgnoreCase);
            _activeQuotaBlocks.Clear();
        }

        foreach (var entry in blocks.Values)
        {
            try
            {
                if (!_remediationService.TryRemoveTrafficFirewallRule(entry.RuleBaseName, out string error))
                    warning = AppendWarning(warning, error);
            }
            finally
            {
                entry.Timer.Dispose();
            }
        }
    }

    private long AddLiveBytes(string ruleId, DateTime dayLocal, long bytes)
    {
        if (bytes <= 0)
            return 0;

        string key = $"{ruleId}|{dayLocal:yyyyMMdd}";
        lock (_gate)
        {
            if (_liveBytesByRuleDay.TryGetValue(key, out long current))
                _liveBytesByRuleDay[key] = current + bytes;
            else
                _liveBytesByRuleDay[key] = bytes;

            return _liveBytesByRuleDay[key];
        }
    }

    private long GetPersistedBytesForToday(TrafficControlRule rule, DateTime dayLocal)
    {
        string cacheKey = $"{rule.Id}|{dayLocal:yyyyMMdd}|{_historyVersion}";
        lock (_gate)
        {
            if (_persistedBytesCache.TryGetValue(cacheKey, out long cached))
                return cached;
        }

        var sessions = _historyStore.GetSessionsSnapshot();
        long total = 0;
        DateTime targetDay = dayLocal.Date;

        foreach (var session in sessions)
        {
            DateTime sessionDay = (session.StartedAtUtc ?? session.RecordedAtUtc).ToLocalTime().Date;
            if (sessionDay != targetDay)
                continue;

            total += rule.TargetKind switch
            {
                var kind when string.Equals(kind, TrafficControlTargetKinds.Process, StringComparison.OrdinalIgnoreCase)
                    => session.Processes
                        .Where(process => MatchesProcessFilter(process.ProcessName, Path.GetFileName(process.ExePath), rule.ProcessFilter))
                        .Sum(static process => process.TotalBytes),

                var kind when string.Equals(kind, TrafficControlTargetKinds.Host, StringComparison.OrdinalIgnoreCase)
                    => session.Hosts
                        .Where(host => MatchesRemoteAddress(rule.RemoteAddress, host.Ip))
                        .Sum(static host => host.Bytes),

                _ => 0L
            };
        }

        lock (_gate)
            _persistedBytesCache[cacheKey] = total;

        return total;
    }

    private string GetRemoteIp(PacketInfo packet)
    {
        RefreshLocalIpsIfNeeded();

        bool srcLocal = !string.IsNullOrWhiteSpace(packet.SrcIp) && _localIps.Contains(packet.SrcIp);
        bool dstLocal = !string.IsNullOrWhiteSpace(packet.DstIp) && _localIps.Contains(packet.DstIp);
        if (srcLocal == dstLocal)
            return string.Empty;

        return srcLocal ? packet.DstIp : packet.SrcIp;
    }

    private void RefreshLocalIpsIfNeeded()
    {
        DateTime nowUtc = DateTime.UtcNow;
        if ((nowUtc - _lastLocalIpsRefreshUtc) < LocalIpsRefreshInterval)
            return;

        _localIps = new HashSet<string>(_localAddressService.GetLocalIpStrings(), StringComparer.OrdinalIgnoreCase);
        _lastLocalIpsRefreshUtc = nowUtc;
    }

    private static bool RuleMatches(TrafficControlRule rule, ProcessStatRow row, string remoteIp)
    {
        if (TrafficControlTargetKinds.IncludesProcess(rule.TargetKind)
            && !MatchesProcessFilter(row.ProcessName, row.ExePathShort, rule.ProcessFilter))
        {
            return false;
        }

        if (TrafficControlTargetKinds.IncludesHost(rule.TargetKind)
            && !MatchesRemoteAddress(rule.RemoteAddress, remoteIp))
        {
            return false;
        }

        return true;
    }

    private static bool MatchesProcessFilter(string? processName, string? exeName, string? filter)
    {
        if (string.IsNullOrWhiteSpace(filter))
            return true;

        string normalizedProcessName = NormalizeProcessToken(processName);
        string normalizedExeName = NormalizeProcessToken(exeName);

        foreach (string token in filter.Split([',', ';', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            string normalizedToken = NormalizeProcessToken(token);
            if (string.IsNullOrWhiteSpace(normalizedToken))
                continue;

            if (string.Equals(normalizedToken, normalizedProcessName, StringComparison.OrdinalIgnoreCase)
                || string.Equals(normalizedToken, normalizedExeName, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static string NormalizeProcessToken(string? value)
    {
        string normalized = (value ?? string.Empty).Trim();
        if (normalized.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            normalized = normalized[..^4];

        return normalized.ToLowerInvariant();
    }

    private static bool MatchesRemoteAddress(string? pattern, string? ip)
    {
        if (string.IsNullOrWhiteSpace(pattern))
            return true;

        if (string.IsNullOrWhiteSpace(ip) || !IPAddress.TryParse(ip, out var candidate))
            return false;

        string normalized = pattern.Trim();
        if (!normalized.Contains('/', StringComparison.Ordinal))
            return string.Equals(normalized, ip, StringComparison.OrdinalIgnoreCase);

        string[] parts = normalized.Split('/', 2, StringSplitOptions.TrimEntries);
        if (parts.Length != 2
            || !IPAddress.TryParse(parts[0], out var network)
            || !int.TryParse(parts[1], out int prefixLength)
            || network.AddressFamily != candidate.AddressFamily)
        {
            return false;
        }

        byte[] networkBytes = network.GetAddressBytes();
        byte[] candidateBytes = candidate.GetAddressBytes();
        int maxBits = networkBytes.Length * 8;
        if (prefixLength < 0 || prefixLength > maxBits)
            return false;

        int fullBytes = prefixLength / 8;
        int remainingBits = prefixLength % 8;

        for (int i = 0; i < fullBytes; i++)
        {
            if (networkBytes[i] != candidateBytes[i])
                return false;
        }

        if (remainingBits == 0)
            return true;

        int mask = byte.MaxValue << (8 - remainingBits);
        return (networkBytes[fullBytes] & mask) == (candidateBytes[fullBytes] & mask);
    }

    private static bool IsScheduleActive(TrafficControlRule rule, DateTime nowLocal)
    {
        if (!rule.ScheduleEnabled)
            return true;

        bool todayEnabled = IsDayEnabled(rule, nowLocal.DayOfWeek);
        int currentMinutes = nowLocal.Hour * 60 + nowLocal.Minute;

        if (rule.StartMinutes == rule.EndMinutes)
            return todayEnabled;

        if (rule.StartMinutes < rule.EndMinutes)
            return todayEnabled && currentMinutes >= rule.StartMinutes && currentMinutes < rule.EndMinutes;

        if (todayEnabled && currentMinutes >= rule.StartMinutes)
            return true;

        DayOfWeek previousDay = nowLocal.DayOfWeek == DayOfWeek.Sunday
            ? DayOfWeek.Saturday
            : (DayOfWeek)((int)nowLocal.DayOfWeek - 1);
        return currentMinutes < rule.EndMinutes && IsDayEnabled(rule, previousDay);
    }

    private static bool IsDayEnabled(TrafficControlRule rule, DayOfWeek dayOfWeek)
        => dayOfWeek switch
        {
            DayOfWeek.Monday => rule.Monday,
            DayOfWeek.Tuesday => rule.Tuesday,
            DayOfWeek.Wednesday => rule.Wednesday,
            DayOfWeek.Thursday => rule.Thursday,
            DayOfWeek.Friday => rule.Friday,
            DayOfWeek.Saturday => rule.Saturday,
            DayOfWeek.Sunday => rule.Sunday,
            _ => false
        };

    private static bool HasQosControl(TrafficControlRule rule)
        => rule.ThrottleMbps > 0 || !string.Equals(rule.Priority, TrafficControlPriorityLevels.Normal, StringComparison.OrdinalIgnoreCase);

    private static sbyte? GetDscpAction(string? priority)
        => TrafficControlPriorityLevels.Normalize(priority) switch
        {
            TrafficControlPriorityLevels.Background => 8,
            TrafficControlPriorityLevels.High => 32,
            TrafficControlPriorityLevels.Critical => 46,
            _ => null
        };

    private static string BuildQosEntryKey(string ruleId, string? processPath, string? remoteAddress)
        => string.Join("|",
            ruleId.Trim(),
            NormalizeQuotaBlockKeyComponent(processPath),
            NormalizeQuotaBlockKeyComponent(remoteAddress));

    private static string BuildQosPolicyName(string ruleId, string? processPath, string? remoteAddress)
    {
        string suffix = string.IsNullOrWhiteSpace(processPath)
            ? NormalizeQuotaBlockKeyComponent(remoteAddress)
            : Path.GetFileNameWithoutExtension(processPath);

        if (string.IsNullOrWhiteSpace(suffix))
            suffix = "rule";

        return $"TrafficMonitor QoS {ruleId[..Math.Min(8, ruleId.Length)]} {suffix}";
    }

    private static string BuildQuotaFirewallRuleBase(string ruleId, DateTime nowLocal, string? exePath, string? remoteIp)
    {
        string suffix = !string.IsNullOrWhiteSpace(exePath)
            ? Path.GetFileNameWithoutExtension(exePath)
            : NormalizeQuotaBlockKeyComponent(remoteIp);

        if (string.IsNullOrWhiteSpace(suffix))
            suffix = "quota";

        return $"TrafficMonitor Quota {ruleId[..Math.Min(8, ruleId.Length)]} {nowLocal:yyyyMMdd} {suffix}";
    }

    private static string BuildRuleTargetLabel(TrafficControlRule rule, ProcessStatRow row, string remoteIp)
    {
        if (string.Equals(rule.TargetKind, TrafficControlTargetKinds.Process, StringComparison.OrdinalIgnoreCase))
            return $"{row.ProcessName} ({Path.GetFileName(row.ExePath)})";

        if (string.Equals(rule.TargetKind, TrafficControlTargetKinds.Host, StringComparison.OrdinalIgnoreCase))
            return string.IsNullOrWhiteSpace(remoteIp) ? rule.RemoteAddress : remoteIp;

        return $"{row.ProcessName} -> {(string.IsNullOrWhiteSpace(remoteIp) ? rule.RemoteAddress : remoteIp)}";
    }

    private static bool TryNormalizeHostRemoteAddress(string? remoteAddress, out string normalizedAddress)
    {
        normalizedAddress = string.Empty;
        if (string.IsNullOrWhiteSpace(remoteAddress) || !IPAddress.TryParse(remoteAddress.Trim(), out var parsed))
            return false;

        normalizedAddress = parsed.ToString();
        return true;
    }

    private static string BuildQuickHostEntryKey(string remoteAddress)
        => NormalizeQuotaBlockKeyComponent(remoteAddress);

    private static string BuildQuickHostFirewallRuleBase(string remoteAddress)
    {
        string suffix = BuildSafeHostNameToken(remoteAddress);
        return $"TrafficMonitor Host Block {suffix}";
    }

    private static string BuildQuickHostQosPolicyName(string remoteAddress)
    {
        string suffix = BuildSafeHostNameToken(remoteAddress);
        return $"TrafficMonitor Host QoS {suffix}";
    }

    private static string BuildSafeHostNameToken(string remoteAddress)
    {
        char[] chars = remoteAddress
            .Trim()
            .Select(static ch => char.IsLetterOrDigit(ch) ? ch : '-')
            .ToArray();

        string normalized = new string(chars).Trim('-');
        return string.IsNullOrWhiteSpace(normalized) ? "host" : normalized;
    }

    private static string BuildHostBlockPrompt(string remoteAddress, HostQuickBlockPreset preset)
    {
        string timing = preset switch
        {
            HostQuickBlockPreset.FifteenMinutes => "The host will be unblocked automatically after 15 minutes.",
            _ => "The host will stay blocked until TrafficMonitor exits."
        };

        return $"Block traffic to remote host {remoteAddress}?\n\n{timing}\n\nWindows may ask for admin approval.";
    }

    private static string GetHostBlockPromptTitle(HostQuickBlockPreset preset)
        => preset switch
        {
            HostQuickBlockPreset.FifteenMinutes => "Block host for 15 minutes",
            _ => "Block host"
        };

    private static string BuildHostBlockStatus(string remoteAddress, HostQuickBlockPreset preset, DateTime? expiresAtLocal)
        => preset switch
        {
            HostQuickBlockPreset.FifteenMinutes when expiresAtLocal.HasValue
                => $"Traffic control: blocked host {remoteAddress} until {expiresAtLocal.Value:HH:mm}.",
            _ => $"Traffic control: blocked host {remoteAddress} until TrafficMonitor exits."
        };

    private static string BuildHostThrottlePrompt(string remoteAddress, int throttleMbps)
        => $"Throttle traffic to remote host {remoteAddress} to {throttleMbps:N0} Mbps?\n\nThis temporary QoS policy stays active until TrafficMonitor exits.\n\nWindows may ask for admin approval.";

    private static string NormalizeQuotaBlockKeyComponent(string? value)
        => string.IsNullOrWhiteSpace(value) ? "-" : value.Trim().ToLowerInvariant();

    private static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double value = Math.Max(0, bytes);
        int unitIndex = 0;
        while (value >= 1024d && unitIndex < units.Length - 1)
        {
            value /= 1024d;
            unitIndex++;
        }

        return unitIndex == 0 ? $"{value:N0} {units[unitIndex]}" : $"{value:N1} {units[unitIndex]}";
    }

    private static TimeSpan GetDueTime(DateTime targetLocal)
    {
        TimeSpan due = targetLocal - DateTime.Now;
        return due <= TimeSpan.Zero ? TimeSpan.FromSeconds(1) : due;
    }

    private static string AppendWarning(string current, string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return current;

        if (string.IsNullOrWhiteSpace(current))
            return value.Trim();

        return $"{current.Trim()} {value.Trim()}";
    }

    private void NotifyRuleStatus(string title, string message, NotificationSeverity severity)
        => _shellNotificationService.Show(title, message, severity);

    private sealed record RunningProcessPathEntry(string ProcessName, string ExeName, string ExePath);

    private sealed record AppliedQosPolicyEntry(
        string Key,
        string PolicyName,
        string RuleName,
        string? ProcessPath,
        string? RemoteAddress,
        WindowsRemediationService.QosPolicySpec Spec);

    private sealed record AppliedHostQosPolicyEntry(
        string Key,
        string RemoteAddress,
        int ThrottleMbps,
        string PolicyName,
        WindowsRemediationService.QosPolicySpec Spec);

    private sealed record ActiveQuotaBlockEntry(
        string Key,
        string RuleId,
        string RuleBaseName,
        DateTime ExpiresAtLocal,
        Timer Timer);

    private sealed class ActiveHostFirewallBlockEntry : IDisposable
    {
        public ActiveHostFirewallBlockEntry(string key, string remoteAddress, string ruleBaseName, HostQuickBlockPreset preset, DateTime? expiresAtLocal)
        {
            Key = key;
            RemoteAddress = remoteAddress;
            RuleBaseName = ruleBaseName;
            Preset = preset;
            ExpiresAtLocal = expiresAtLocal;
        }

        public string Key { get; }
        public string RemoteAddress { get; }
        public string RuleBaseName { get; }
        public HostQuickBlockPreset Preset { get; }
        public DateTime? ExpiresAtLocal { get; }

        private Timer? _timer;

        public void StartTimer(TimerCallback callback, object state, TimeSpan dueTime)
            => _timer = new Timer(callback, state, dueTime, Timeout.InfiniteTimeSpan);

        public void Reschedule(TimeSpan dueTime)
            => _timer?.Change(dueTime, Timeout.InfiniteTimeSpan);

        public void Dispose()
        {
            _timer?.Dispose();
            _timer = null;
        }
    }
}
