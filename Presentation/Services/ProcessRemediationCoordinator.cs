using Infrastructure.Networking;
using System.Windows;
using Infrastructure.Remediation;
using Presentation.Abstractions;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace Presentation.Services;

public sealed class ProcessRemediationCoordinator : IDisposable
{
    public enum FirewallBlockScope
    {
        None,
        Permanent,
        UntilTime,
        UntilAppExit
    }

    public enum FirewallBlockPreset
    {
        Permanent,
        FifteenMinutes,
        OneHour,
        UntilAppExit
    }

    public sealed record FirewallBlockStateChange(
        int SourcePid,
        string ExePath,
        FirewallBlockScope Scope,
        DateTime TimestampLocal,
        DateTime? ExpiresAtLocal,
        string StatusMessage,
        bool ReportStatusToUser,
        string? TimelineDetail = null);

    public sealed record FirewallBlockStateSnapshot(
        FirewallBlockScope Scope,
        DateTime? ExpiresAtLocal);

    private readonly ProcessMapperService _processMapperService;
    private readonly WindowsRemediationService _remediationService;
    private readonly IUserPromptService _prompt;
    private readonly object _firewallRulesGate = new();
    private readonly Dictionary<string, ActiveFirewallRule> _firewallRulesByExePath = new(StringComparer.OrdinalIgnoreCase);

    private static readonly TimeSpan FifteenMinuteBlockDuration = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan OneHourBlockDuration = TimeSpan.FromHours(1);
    private static readonly TimeSpan AutoUnblockRetryDelay = TimeSpan.FromMinutes(1);

    public event Action<FirewallBlockStateChange>? FirewallBlockStateChanged;

    public ProcessRemediationCoordinator(
        ProcessMapperService processMapperService,
        WindowsRemediationService remediationService,
        IUserPromptService prompt)
    {
        _processMapperService = processMapperService;
        _remediationService = remediationService;
        _prompt = prompt;
    }

    public bool TryGetFirewallBlockState(string? exePath, out FirewallBlockStateSnapshot snapshot)
    {
        string key = NormalizeExePathKey(exePath);
        if (string.IsNullOrWhiteSpace(key))
        {
            snapshot = new FirewallBlockStateSnapshot(FirewallBlockScope.None, null);
            return false;
        }

        lock (_firewallRulesGate)
        {
            if (_firewallRulesByExePath.TryGetValue(key, out var rule))
            {
                snapshot = new FirewallBlockStateSnapshot(rule.Scope, rule.ExpiresAtLocal);
                return true;
            }
        }

        snapshot = new FirewallBlockStateSnapshot(FirewallBlockScope.None, null);
        return false;
    }

    public string? Locate(int pid)
    {
        if (pid <= 0) return null;

        var d = _processMapperService.GetProcessDetailsCached(pid);
        if (_remediationService.TryOpenProcessLocation(d.ExePath, out var err))
            return $"Opened location for {d.Name} (PID {pid})";

        return $"Open location failed: {err}";
    }

    public string? Kill(int pid)
    {
        if (pid <= 0) return null;

        var d = _processMapperService.GetProcessDetailsCached(pid);
        var res = _prompt.Show(
            $"Terminate process {d.Name} (PID {pid})?\n\nThis may cause data loss.",
            "Kill process",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (res != MessageBoxResult.Yes)
            return null;

        if (_remediationService.TryKillProcess(pid, out var err))
            return $"Terminated {d.Name} (PID {pid})";

        return $"Kill failed: {err}";
    }

    public string? BlockInFirewall(int pid)
        => BlockInFirewall(pid, FirewallBlockPreset.Permanent);

    public string? BlockInFirewall(int pid, FirewallBlockPreset preset)
    {
        if (pid <= 0) return null;

        var d = _processMapperService.GetProcessDetailsCached(pid);
        var res = _prompt.Show(
            BuildBlockPrompt(d.Name, pid, preset),
            GetBlockPromptTitle(preset),
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (res != MessageBoxResult.Yes)
            return null;

        if (_remediationService.TryBlockProgramInFirewall(d.ExePath, rulePrefix: "TrafficMonitor", out var err))
        {
            DateTime nowLocal = DateTime.Now;
            DateTime? expiresAtLocal = preset switch
            {
                FirewallBlockPreset.FifteenMinutes => nowLocal.Add(FifteenMinuteBlockDuration),
                FirewallBlockPreset.OneHour => nowLocal.Add(OneHourBlockDuration),
                _ => null
            };

            FirewallBlockScope scope = preset switch
            {
                FirewallBlockPreset.Permanent => FirewallBlockScope.Permanent,
                FirewallBlockPreset.UntilAppExit => FirewallBlockScope.UntilAppExit,
                _ => FirewallBlockScope.UntilTime
            };

            TrackFirewallRule(pid, d.Name, d.ExePath, scope, expiresAtLocal);

            string statusMessage = BuildBlockStatusMessage(d.Name, scope, expiresAtLocal);
            RaiseFirewallBlockStateChanged(new FirewallBlockStateChange(
                SourcePid: pid,
                ExePath: d.ExePath,
                Scope: scope,
                TimestampLocal: nowLocal,
                ExpiresAtLocal: expiresAtLocal,
                StatusMessage: statusMessage,
                ReportStatusToUser: false));

            return statusMessage;
        }

        return $"Firewall block failed: {err}";
    }

    public string? UnblockInFirewall(int pid)
    {
        if (pid <= 0) return null;

        var d = _processMapperService.GetProcessDetailsCached(pid);
        var res = _prompt.Show(
            $"Remove Windows Firewall rules added by TrafficMonitor for {d.Name} (PID {pid})?\n\nThis will prompt for admin rights.",
            "Unblock in Firewall",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (res != MessageBoxResult.Yes)
            return null;

        if (_remediationService.TryUnblockProgramInFirewall(d.ExePath, rulePrefix: "TrafficMonitor", out var err))
        {
            RemoveTrackedFirewallRule(d.ExePath);

            string statusMessage = $"Firewall: unblocked {d.Name}";
            RaiseFirewallBlockStateChanged(new FirewallBlockStateChange(
                SourcePid: pid,
                ExePath: d.ExePath,
                Scope: FirewallBlockScope.None,
                TimestampLocal: DateTime.Now,
                ExpiresAtLocal: null,
                StatusMessage: statusMessage,
                ReportStatusToUser: false));

            return statusMessage;
        }

        return $"Firewall unblock failed: {err}";
    }

    public void Dispose()
    {
        List<ActiveFirewallRule> temporaryRules;
        lock (_firewallRulesGate)
        {
            temporaryRules = _firewallRulesByExePath.Values
                .Where(static rule => rule.Scope != FirewallBlockScope.Permanent)
                .ToList();

            foreach (var rule in temporaryRules)
                _firewallRulesByExePath.Remove(rule.ExePathKey);
        }

        foreach (var rule in temporaryRules)
        {
            rule.Dispose();
            _remediationService.TryUnblockProgramInFirewall(rule.ExePath, rulePrefix: "TrafficMonitor", out _);
        }
    }

    private void TrackFirewallRule(int pid, string processName, string exePath, FirewallBlockScope scope, DateTime? expiresAtLocal)
    {
        string exePathKey = NormalizeExePathKey(exePath);
        if (string.IsNullOrWhiteSpace(exePathKey))
            return;

        var rule = new ActiveFirewallRule(pid, processName, exePath, exePathKey, scope, expiresAtLocal);

        lock (_firewallRulesGate)
        {
            if (_firewallRulesByExePath.TryGetValue(exePathKey, out var existing))
                existing.Dispose();

            _firewallRulesByExePath[exePathKey] = rule;
        }

        if (scope == FirewallBlockScope.UntilTime && expiresAtLocal.HasValue)
        {
            rule.StartTimer(
                OnTimedFirewallRuleExpired,
                new FirewallRuleTimerState(exePathKey, rule.Token),
                GetTimerDueTime(expiresAtLocal.Value));
        }
    }

    private void RemoveTrackedFirewallRule(string? exePath)
    {
        string exePathKey = NormalizeExePathKey(exePath);
        if (string.IsNullOrWhiteSpace(exePathKey))
            return;

        ActiveFirewallRule? rule = null;
        lock (_firewallRulesGate)
        {
            if (_firewallRulesByExePath.TryGetValue(exePathKey, out rule))
                _firewallRulesByExePath.Remove(exePathKey);
        }

        rule?.Dispose();
    }

    private void OnTimedFirewallRuleExpired(object? state)
    {
        if (state is not FirewallRuleTimerState timerState)
            return;

        ActiveFirewallRule? rule;
        lock (_firewallRulesGate)
        {
            if (!_firewallRulesByExePath.TryGetValue(timerState.ExePathKey, out rule)
                || rule.Token != timerState.Token
                || rule.Scope != FirewallBlockScope.UntilTime)
            {
                return;
            }
        }

        if (_remediationService.TryUnblockProgramInFirewall(rule.ExePath, rulePrefix: "TrafficMonitor", out _))
        {
            RemoveTrackedFirewallRule(rule.ExePath);

            RaiseFirewallBlockStateChanged(new FirewallBlockStateChange(
                SourcePid: rule.SourcePid,
                ExePath: rule.ExePath,
                Scope: FirewallBlockScope.None,
                TimestampLocal: DateTime.Now,
                ExpiresAtLocal: null,
                StatusMessage: $"Firewall: restored {rule.ProcessName} after the temporary block expired",
                ReportStatusToUser: true,
                TimelineDetail: "TrafficMonitor removed its temporary Windows Firewall rules after the scheduled block window expired."));

            return;
        }

        rule.Reschedule(GetTimerDueTime(DateTime.Now.Add(AutoUnblockRetryDelay)));
    }

    private void RaiseFirewallBlockStateChanged(FirewallBlockStateChange change)
        => FirewallBlockStateChanged?.Invoke(change);

    private static string BuildBlockPrompt(string processName, int pid, FirewallBlockPreset preset)
    {
        string timingNote = preset switch
        {
            FirewallBlockPreset.FifteenMinutes => "The rule will be removed automatically after 15 minutes.",
            FirewallBlockPreset.OneHour => "The rule will be removed automatically after 1 hour.",
            FirewallBlockPreset.UntilAppExit => "The rule will be removed automatically when TrafficMonitor exits.",
            _ => "The rule will stay active until you restore network access manually."
        };

        return $"Add Windows Firewall rules to block {processName} (PID {pid}) by program path?\n\n{timingNote}\n\nThis will prompt for admin rights.";
    }

    private static string GetBlockPromptTitle(FirewallBlockPreset preset)
        => preset switch
        {
            FirewallBlockPreset.FifteenMinutes => "Block in Firewall for 15 minutes",
            FirewallBlockPreset.OneHour => "Block in Firewall for 1 hour",
            FirewallBlockPreset.UntilAppExit => "Block in Firewall until app exit",
            _ => "Block in Firewall"
        };

    private static string BuildBlockStatusMessage(string processName, FirewallBlockScope scope, DateTime? expiresAtLocal)
        => scope switch
        {
            FirewallBlockScope.UntilTime when expiresAtLocal.HasValue
                => $"Firewall: blocked {processName} until {expiresAtLocal.Value:HH:mm}",
            FirewallBlockScope.UntilAppExit
                => $"Firewall: blocked {processName} until TrafficMonitor exits",
            _ => $"Firewall: blocked {processName}"
        };

    private static string NormalizeExePathKey(string? exePath)
        => string.IsNullOrWhiteSpace(exePath) ? string.Empty : exePath.Trim();

    private static TimeSpan GetTimerDueTime(DateTime dueAtLocal)
    {
        TimeSpan dueTime = dueAtLocal - DateTime.Now;
        return dueTime <= TimeSpan.Zero ? TimeSpan.Zero : dueTime;
    }

    private sealed class ActiveFirewallRule : IDisposable
    {
        public ActiveFirewallRule(
            int sourcePid,
            string processName,
            string exePath,
            string exePathKey,
            FirewallBlockScope scope,
            DateTime? expiresAtLocal)
        {
            SourcePid = sourcePid;
            ProcessName = processName;
            ExePath = exePath;
            ExePathKey = exePathKey;
            Scope = scope;
            ExpiresAtLocal = expiresAtLocal;
            Token = Guid.NewGuid();
        }

        public int SourcePid { get; }
        public string ProcessName { get; }
        public string ExePath { get; }
        public string ExePathKey { get; }
        public FirewallBlockScope Scope { get; }
        public DateTime? ExpiresAtLocal { get; }
        public Guid Token { get; }

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

    private sealed record FirewallRuleTimerState(string ExePathKey, Guid Token);
}
