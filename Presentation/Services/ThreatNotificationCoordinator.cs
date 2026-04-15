using Presentation.Models;
using System;
using System.Collections.Generic;

namespace Presentation.Services;

public sealed class ThreatNotificationCoordinator
{
    private readonly NotificationSettingsStore _settingsStore;
    private readonly WindowsShellNotificationService _notificationService;

    private NotificationSettings _settings;
    private readonly HashSet<string> _notifiedProcessIdentities = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<int> _riskNotifiedPids = new();
    private readonly HashSet<int> _beaconNotifiedPids = new();

    public ThreatNotificationCoordinator(
        NotificationSettingsStore settingsStore,
        WindowsShellNotificationService notificationService)
    {
        _settingsStore = settingsStore;
        _notificationService = notificationService;
        _settings = _settingsStore.Load();
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

    private bool ShouldNotify(bool featureEnabled)
        => _settings.NotificationsEnabled && featureEnabled;

    private static string BuildProcessIdentityKey(ProcessStatRow row)
    {
        if (!string.IsNullOrWhiteSpace(row.ExePath))
            return row.ExePath.Trim().ToLowerInvariant();

        if (!string.IsNullOrWhiteSpace(row.ExePathShort))
            return row.ExePathShort.Trim().ToLowerInvariant();

        return row.ProcessName?.Trim().ToLowerInvariant() ?? string.Empty;
    }

    private static string FirstNonEmpty(params string?[] values)
    {
        for (int i = 0; i < values.Length; i++)
        {
            if (!string.IsNullOrWhiteSpace(values[i]))
                return values[i]!.Trim();
        }

        return string.Empty;
    }
}
