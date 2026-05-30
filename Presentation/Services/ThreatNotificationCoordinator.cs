using Application.Abstractions;
using Application.Networking;
using Domain.Models;
using Presentation.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace Presentation.Services;

public sealed class ThreatNotificationCoordinator
{
    private static readonly TimeSpan LocalIpsRefreshInterval = TimeSpan.FromSeconds(5);

    private readonly NotificationSettingsStore _settingsStore;
    private readonly WindowsShellNotificationService _notificationService;
    private readonly TrafficHistoryStore _trafficHistoryStore;
    private readonly ILocalAddressService _localAddressService;
    private readonly HostResolutionService _hostResolutionService;

    private NotificationSettings _settings;
    private readonly HashSet<string> _notifiedProcessIdentities = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<int> _riskNotifiedPids = new();
    private readonly HashSet<int> _beaconNotifiedPids = new();
    private readonly HashSet<string> _dailyTrafficQuotaAlerts = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, long> _persistedDailyProcessBytes = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, long> _liveDailyProcessBytes = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<(int Pid, string RemoteIp), long> _unknownHostTrafficByProcessIp = new();
    private readonly HashSet<string> _unknownHostQuotaAlerts = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<int, Queue<DateTime>> _dnsQueryTimestampsByPid = new();
    private readonly HashSet<int> _dnsBurstNotifiedPids = new();

    private HashSet<string> _localIps = new(StringComparer.OrdinalIgnoreCase);
    private DateTime _lastLocalIpsRefreshUtc = DateTime.MinValue;
    private DateTime _activeLocalDay = DateTime.Today;

    public ThreatNotificationCoordinator(
        NotificationSettingsStore settingsStore,
        WindowsShellNotificationService notificationService,
        TrafficHistoryStore trafficHistoryStore,
        ILocalAddressService localAddressService,
        HostResolutionService hostResolutionService)
    {
        _settingsStore = settingsStore;
        _notificationService = notificationService;
        _trafficHistoryStore = trafficHistoryStore;
        _localAddressService = localAddressService;
        _hostResolutionService = hostResolutionService;
        _settings = _settingsStore.Load();

        RefreshLocalIpsIfNeeded(force: true);
        RefreshPersistedDailyProcessBytes(DateTime.Now.Date);
        _trafficHistoryStore.HistoryChanged += OnHistoryChanged;
    }

    public NotificationSettings GetSettingsSnapshot()
        => _settings.Clone();

    public void SaveSettings(NotificationSettings settings)
    {
        _settings = NotificationSettings.CreateNormalized(settings);
        _settingsStore.Save(_settings);
    }

    public void ResetSession()
    {
        _notifiedProcessIdentities.Clear();
        _riskNotifiedPids.Clear();
        _beaconNotifiedPids.Clear();
        _unknownHostTrafficByProcessIp.Clear();
        _unknownHostQuotaAlerts.Clear();
        _dnsQueryTimestampsByPid.Clear();
        _dnsBurstNotifiedPids.Clear();
        _liveDailyProcessBytes.Clear();
    }

    public void NotifyNewProcess(ProcessStatRow row)
    {
        if (!ShouldNotify(_settings.NewProcessNotificationsEnabled) || row.Pid <= 0)
            return;

        string identityKey = BuildProcessIdentityKey(row);
        if (string.IsNullOrWhiteSpace(identityKey) || !_notifiedProcessIdentities.Add(identityKey))
            return;

        string message = $"{row.DisplayName} started network activity.";
        if (!string.IsNullOrWhiteSpace(row.ExePath))
            message += $" Path: {row.ExePath}.";
        else if (!string.IsNullOrWhiteSpace(row.ExePathShort))
            message += $" Binary: {row.ExePathShort}.";

        if (!string.IsNullOrWhiteSpace(row.Publisher))
            message += $" Publisher: {row.Publisher}.";

        _notificationService.Show("New process observed", message, NotificationSeverity.Info);
    }

    public void ObserveRiskScore(ProcessStatRow row)
    {
        if (row.Pid <= 0)
            return;

        int threshold = _settings.RiskScoreThreshold;
        if (row.RiskScore < threshold)
        {
            _riskNotifiedPids.Remove(row.Pid);
            return;
        }

        if (!ShouldNotify(_settings.RiskScoreNotificationsEnabled) || !_riskNotifiedPids.Add(row.Pid))
            return;

        string message = $"{row.DisplayName} reached risk score {row.RiskScore}/100 (threshold {threshold}).";

        string topSignal = FirstNonEmpty(
            row.DetectionSummaryLabel,
            row.BehaviorDeviationSummaryLabel,
            row.TlsDnsSummaryLabel,
            row.FirstSuspiciousDomain,
            row.TopRemoteEndpoint);

        if (!string.IsNullOrWhiteSpace(topSignal))
            message += $" Signal: {topSignal}.";

        _notificationService.Show("Risk threshold exceeded", message, NotificationSeverity.Warning);
    }

    public void ObserveBeacon(ProcessStatRow row)
    {
        if (row.Pid <= 0)
            return;

        if (!row.BeaconSuspected)
        {
            _beaconNotifiedPids.Remove(row.Pid);
            return;
        }

        if (!ShouldNotify(_settings.BeaconNotificationsEnabled) || !_beaconNotifiedPids.Add(row.Pid))
            return;

        string message = $"{row.DisplayName} shows repeating outbound activity.";
        if (!string.IsNullOrWhiteSpace(row.BeaconEndpoint))
            message += $" Endpoint: {row.BeaconEndpoint}.";

        if (row.BeaconIntervalSec > 0)
            message += $" Interval ~{row.BeaconIntervalSec:0.#}s, cv {row.BeaconCv:0.##}, samples {row.BeaconSamples}.";

        _notificationService.Show("Beaconing detected", message, NotificationSeverity.Warning);
    }

    public void ObserveSoftQuotas(ProcessStatRow row, PacketInfo packet, bool isDnsQuery)
    {
        if (row.Pid <= 0 || packet.Length <= 0 || !ShouldNotify(_settings.QuotaNotificationsEnabled))
            return;

        EnsureActiveDay(packet.Timestamp);
        ObserveDailyProcessTrafficQuota(row, packet);
        ObserveUnknownHostTrafficQuota(row, packet);
        ObserveDnsBurstQuota(row, packet, isDnsQuery);
    }

    private void OnHistoryChanged()
        => RefreshPersistedDailyProcessBytes(_activeLocalDay);

    private void ObserveDailyProcessTrafficQuota(ProcessStatRow row, PacketInfo packet)
    {
        if (!_settings.DailyProcessTrafficQuotaEnabled)
            return;

        if (!MatchesProcessFilter(row, _settings.DailyProcessTrafficProcessFilter))
            return;

        string identityKey = BuildProcessIdentityKey(row);
        if (string.IsNullOrWhiteSpace(identityKey))
            return;

        AddBytes(_liveDailyProcessBytes, identityKey, packet.Length);

        long thresholdBytes = ToBytes(_settings.DailyProcessTrafficQuotaMb);
        long totalBytes = _liveDailyProcessBytes.GetValueOrDefault(identityKey) + _persistedDailyProcessBytes.GetValueOrDefault(identityKey);
        string alertKey = $"{_activeLocalDay:yyyyMMdd}|{identityKey}";
        if (totalBytes < thresholdBytes || !_dailyTrafficQuotaAlerts.Add(alertKey))
            return;

        string message = $"{row.DisplayName} used {FormatBytes(totalBytes)} on {_activeLocalDay:yyyy-MM-dd} (quota {FormatBytes(thresholdBytes)}).";
        if (!string.IsNullOrWhiteSpace(_settings.DailyProcessTrafficProcessFilter))
            message += $" Filter: {_settings.DailyProcessTrafficProcessFilter}.";

        row.RecordQuotaAlert(
            $"daily-traffic-{_activeLocalDay:yyyyMMdd}-{identityKey}",
            packet.Timestamp,
            "Daily traffic quota exceeded",
            message);

        _notificationService.Show("Daily traffic quota exceeded", message, NotificationSeverity.Warning);
    }

    private void ObserveUnknownHostTrafficQuota(ProcessStatRow row, PacketInfo packet)
    {
        if (!_settings.UnknownHostTrafficQuotaEnabled)
            return;

        if (!TryGetPublicRemoteIp(packet, out var remoteIp))
            return;

        if (_hostResolutionService.TryResolve(remoteIp, out _))
            return;

        var trafficKey = (row.Pid, remoteIp);
        if (_unknownHostTrafficByProcessIp.TryGetValue(trafficKey, out long bytes))
            _unknownHostTrafficByProcessIp[trafficKey] = bytes + packet.Length;
        else
            _unknownHostTrafficByProcessIp[trafficKey] = packet.Length;

        long totalBytes = _unknownHostTrafficByProcessIp[trafficKey];
        long thresholdBytes = ToBytes(_settings.UnknownHostTrafficQuotaMb);
        string alertKey = $"{row.Pid}|{remoteIp}";
        if (totalBytes < thresholdBytes || !_unknownHostQuotaAlerts.Add(alertKey))
            return;

        string message = $"{row.DisplayName} exchanged {FormatBytes(totalBytes)} with unresolved public host {remoteIp} (quota {FormatBytes(thresholdBytes)}).";
        row.RecordQuotaAlert(
            $"unknown-host-{row.Pid}-{remoteIp}",
            packet.Timestamp,
            "Unknown-host traffic quota exceeded",
            message);

        _notificationService.Show("Unknown-host traffic quota exceeded", message, NotificationSeverity.Warning);
    }

    private void ObserveDnsBurstQuota(ProcessStatRow row, PacketInfo packet, bool isDnsQuery)
    {
        if (!_settings.DnsBurstQuotaEnabled || !isDnsQuery)
            return;

        DateTime observedAtUtc = packet.Timestamp.Kind == DateTimeKind.Utc
            ? packet.Timestamp
            : packet.Timestamp.ToUniversalTime();

        if (!_dnsQueryTimestampsByPid.TryGetValue(row.Pid, out var timestamps))
        {
            timestamps = new Queue<DateTime>();
            _dnsQueryTimestampsByPid[row.Pid] = timestamps;
        }

        timestamps.Enqueue(observedAtUtc);

        TimeSpan window = TimeSpan.FromMinutes(_settings.DnsBurstWindowMinutes);
        while (timestamps.Count > 0 && observedAtUtc - timestamps.Peek() > window)
            timestamps.Dequeue();

        if (timestamps.Count < _settings.DnsBurstQueryThreshold || !_dnsBurstNotifiedPids.Add(row.Pid))
            return;

        string message = $"{row.DisplayName} sent {timestamps.Count:N0} DNS queries in {_settings.DnsBurstWindowMinutes:N0} min (quota {_settings.DnsBurstQueryThreshold:N0}).";
        if (!string.IsNullOrWhiteSpace(row.DominantDnsRoot))
            message += $" Dominant root: {row.DominantDnsRoot}.";

        row.RecordQuotaAlert(
            $"dns-burst-{_activeLocalDay:yyyyMMdd}-{row.Pid}",
            packet.Timestamp,
            "DNS burst quota exceeded",
            message);

        _notificationService.Show("DNS burst quota exceeded", message, NotificationSeverity.Warning);
    }

    private void EnsureActiveDay(DateTime timestamp)
    {
        DateTime localDay = (timestamp == default ? DateTime.Now : timestamp.ToLocalTime()).Date;
        if (localDay == _activeLocalDay)
            return;

        _activeLocalDay = localDay;
        _dailyTrafficQuotaAlerts.Clear();
        _liveDailyProcessBytes.Clear();
        RefreshPersistedDailyProcessBytes(localDay);
    }

    private void RefreshPersistedDailyProcessBytes(DateTime localDay)
    {
        _persistedDailyProcessBytes.Clear();

        foreach (var session in _trafficHistoryStore.GetSessionsSnapshot())
        {
            DateTime sessionLocalDate = (session.StartedAtUtc ?? session.RecordedAtUtc).ToLocalTime().Date;
            if (sessionLocalDate != localDay)
                continue;

            foreach (var process in session.Processes)
            {
                if (string.IsNullOrWhiteSpace(process.IdentityKey) || process.TotalBytes <= 0)
                    continue;

                AddBytes(_persistedDailyProcessBytes, process.IdentityKey, process.TotalBytes);
            }
        }
    }

    private void RefreshLocalIpsIfNeeded(bool force)
    {
        DateTime nowUtc = DateTime.UtcNow;
        if (!force && (nowUtc - _lastLocalIpsRefreshUtc) < LocalIpsRefreshInterval)
            return;

        _localIps = new HashSet<string>(_localAddressService.GetLocalIpStrings(), StringComparer.OrdinalIgnoreCase);
        _lastLocalIpsRefreshUtc = nowUtc;
    }

    private bool TryGetPublicRemoteIp(PacketInfo packet, out string remoteIp)
    {
        remoteIp = string.Empty;
        RefreshLocalIpsIfNeeded(force: false);

        bool srcLocal = !string.IsNullOrWhiteSpace(packet.SrcIp) && _localIps.Contains(packet.SrcIp);
        bool dstLocal = !string.IsNullOrWhiteSpace(packet.DstIp) && _localIps.Contains(packet.DstIp);
        if (srcLocal == dstLocal)
            return false;

        remoteIp = srcLocal ? packet.DstIp : packet.SrcIp;
        if (string.IsNullOrWhiteSpace(remoteIp) || !IsPublicIp(remoteIp))
        {
            remoteIp = string.Empty;
            return false;
        }

        return true;
    }

    private bool ShouldNotify(bool featureEnabled)
        => _settings.NotificationsEnabled && featureEnabled;

    private static void AddBytes(IDictionary<string, long> totals, string key, long bytes)
    {
        if (bytes <= 0 || string.IsNullOrWhiteSpace(key))
            return;

        if (totals.TryGetValue(key, out long current))
            totals[key] = current + bytes;
        else
            totals[key] = bytes;
    }

    private static string BuildProcessIdentityKey(ProcessStatRow row)
    {
        if (!string.IsNullOrWhiteSpace(row.ExePath))
            return row.ExePath.Trim().ToLowerInvariant();

        if (!string.IsNullOrWhiteSpace(row.ExePathShort))
            return row.ExePathShort.Trim().ToLowerInvariant();

        return row.ProcessName?.Trim().ToLowerInvariant() ?? string.Empty;
    }

    private static bool MatchesProcessFilter(ProcessStatRow row, string? filter)
    {
        if (string.IsNullOrWhiteSpace(filter))
            return true;

        string processName = NormalizeProcessToken(row.ProcessName);
        string exeName = NormalizeProcessToken(row.ExePathShort);
        string displayName = NormalizeProcessToken(row.DisplayName);

        string[] tokens = filter
            .Split([',', ';', '\n', '\r'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        for (int i = 0; i < tokens.Length; i++)
        {
            string token = NormalizeProcessToken(tokens[i]);
            if (string.IsNullOrWhiteSpace(token))
                continue;

            if (string.Equals(token, processName, StringComparison.OrdinalIgnoreCase)
                || string.Equals(token, exeName, StringComparison.OrdinalIgnoreCase)
                || string.Equals(token, displayName, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static string NormalizeProcessToken(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return string.Empty;

        string normalized = value.Trim();
        if (normalized.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            normalized = normalized[..^4];

        return normalized.Trim().ToLowerInvariant();
    }

    private static long ToBytes(int megaBytes)
        => Math.Max(1, megaBytes) * 1024L * 1024L;

    private static string FirstNonEmpty(params string?[] values)
    {
        for (int i = 0; i < values.Length; i++)
        {
            if (!string.IsNullOrWhiteSpace(values[i]))
                return values[i]!.Trim();
        }

        return string.Empty;
    }

    private static string FormatBytes(long bytes)
    {
        const double KB = 1024;
        const double MB = KB * 1024;
        const double GB = MB * 1024;

        if (bytes >= GB) return $"{bytes / GB:0.##} GB";
        if (bytes >= MB) return $"{bytes / MB:0.##} MB";
        if (bytes >= KB) return $"{bytes / KB:0.##} KB";
        return $"{bytes:N0} B";
    }

    private static bool IsPublicIp(string ip)
    {
        if (!IPAddress.TryParse(ip, out var address))
            return false;

        if (IPAddress.IsLoopback(address))
            return false;

        byte[] bytes = address.GetAddressBytes();
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            int first = bytes[0];
            int second = bytes[1];

            if (first == 0
                || first == 10
                || first == 127
                || first == 169 && second == 254
                || first == 172 && second >= 16 && second <= 31
                || first == 192 && second == 168
                || first == 100 && second >= 64 && second <= 127
                || first >= 224
                || first == 192 && second == 0 && bytes[2] == 2
                || first == 198 && second == 51 && bytes[2] == 100
                || first == 203 && second == 0 && bytes[2] == 113)
            {
                return false;
            }

            return true;
        }

        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            if (address.IsIPv6LinkLocal
                || address.IsIPv6Multicast
                || address.IsIPv6SiteLocal
                || address.IsIPv6Teredo)
            {
                return false;
            }

            return !(bytes[0] == 0xfc || bytes[0] == 0xfd || address.Equals(IPAddress.IPv6None));
        }

        return false;
    }
}
