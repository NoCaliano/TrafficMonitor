using System;

namespace Presentation.Models;

public sealed class NotificationSettings
{
    public bool NotificationsEnabled { get; set; } = true;
    public bool NewProcessNotificationsEnabled { get; set; } = true;
    public bool RiskScoreNotificationsEnabled { get; set; } = true;
    public int RiskScoreThreshold { get; set; } = 70;
    public bool BeaconNotificationsEnabled { get; set; } = true;
    public bool QuotaNotificationsEnabled { get; set; } = true;
    public bool DailyProcessTrafficQuotaEnabled { get; set; } = true;
    public string DailyProcessTrafficProcessFilter { get; set; } = "";
    public int DailyProcessTrafficQuotaMb { get; set; } = 500;
    public bool UnknownHostTrafficQuotaEnabled { get; set; } = true;
    public int UnknownHostTrafficQuotaMb { get; set; } = 50;
    public bool DnsBurstQuotaEnabled { get; set; } = true;
    public int DnsBurstQueryThreshold { get; set; } = 100;
    public int DnsBurstWindowMinutes { get; set; } = 5;

    public NotificationSettings Clone()
        => new()
        {
            NotificationsEnabled = NotificationsEnabled,
            NewProcessNotificationsEnabled = NewProcessNotificationsEnabled,
            RiskScoreNotificationsEnabled = RiskScoreNotificationsEnabled,
            RiskScoreThreshold = RiskScoreThreshold,
            BeaconNotificationsEnabled = BeaconNotificationsEnabled,
            QuotaNotificationsEnabled = QuotaNotificationsEnabled,
            DailyProcessTrafficQuotaEnabled = DailyProcessTrafficQuotaEnabled,
            DailyProcessTrafficProcessFilter = DailyProcessTrafficProcessFilter,
            DailyProcessTrafficQuotaMb = DailyProcessTrafficQuotaMb,
            UnknownHostTrafficQuotaEnabled = UnknownHostTrafficQuotaEnabled,
            UnknownHostTrafficQuotaMb = UnknownHostTrafficQuotaMb,
            DnsBurstQuotaEnabled = DnsBurstQuotaEnabled,
            DnsBurstQueryThreshold = DnsBurstQueryThreshold,
            DnsBurstWindowMinutes = DnsBurstWindowMinutes
        };

    public static NotificationSettings CreateNormalized(NotificationSettings? settings)
    {
        var normalized = settings?.Clone() ?? new NotificationSettings();
        normalized.RiskScoreThreshold = Math.Clamp(normalized.RiskScoreThreshold, 1, 100);
        normalized.DailyProcessTrafficProcessFilter = (normalized.DailyProcessTrafficProcessFilter ?? string.Empty).Trim();
        normalized.DailyProcessTrafficQuotaMb = Math.Clamp(normalized.DailyProcessTrafficQuotaMb, 10, 50_000);
        normalized.UnknownHostTrafficQuotaMb = Math.Clamp(normalized.UnknownHostTrafficQuotaMb, 1, 10_000);
        normalized.DnsBurstQueryThreshold = Math.Clamp(normalized.DnsBurstQueryThreshold, 5, 10_000);
        normalized.DnsBurstWindowMinutes = Math.Clamp(normalized.DnsBurstWindowMinutes, 1, 120);
        return normalized;
    }
}
