using System;

namespace Presentation.Models;

public sealed class NotificationSnoozeState
{
    public DateTime? SnoozedUntilUtc { get; set; }

    public NotificationSnoozeState Clone()
        => new()
        {
            SnoozedUntilUtc = SnoozedUntilUtc
        };

    public static NotificationSnoozeState CreateNormalized(NotificationSnoozeState? state)
    {
        var normalized = state?.Clone() ?? new NotificationSnoozeState();

        if (normalized.SnoozedUntilUtc.HasValue)
        {
            DateTime utc = normalized.SnoozedUntilUtc.Value.Kind switch
            {
                DateTimeKind.Utc => normalized.SnoozedUntilUtc.Value,
                DateTimeKind.Local => normalized.SnoozedUntilUtc.Value.ToUniversalTime(),
                _ => DateTime.SpecifyKind(normalized.SnoozedUntilUtc.Value, DateTimeKind.Utc)
            };

            normalized.SnoozedUntilUtc = utc > DateTime.UtcNow ? utc : null;
        }

        return normalized;
    }
}
