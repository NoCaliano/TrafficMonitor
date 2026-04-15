using System;

namespace Presentation.Models;

public sealed class NotificationSettings
{
    public bool NotificationsEnabled { get; set; } = true;
    public bool NewProcessNotificationsEnabled { get; set; } = true;
    public bool RiskScoreNotificationsEnabled { get; set; } = true;
    public int RiskScoreThreshold { get; set; } = 70;
    public bool BeaconNotificationsEnabled { get; set; } = true;

    public NotificationSettings Clone()
        => new()
        {
            NotificationsEnabled = NotificationsEnabled,
            NewProcessNotificationsEnabled = NewProcessNotificationsEnabled,
            RiskScoreNotificationsEnabled = RiskScoreNotificationsEnabled,
            RiskScoreThreshold = RiskScoreThreshold,
            BeaconNotificationsEnabled = BeaconNotificationsEnabled
        };

    public static NotificationSettings CreateNormalized(NotificationSettings? settings)
    {
        var normalized = settings?.Clone() ?? new NotificationSettings();
        normalized.RiskScoreThreshold = Math.Clamp(normalized.RiskScoreThreshold, 1, 100);
        return normalized;
    }
}
