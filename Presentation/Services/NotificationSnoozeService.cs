using Presentation.Models;
using System;
using System.Threading;

namespace Presentation.Services;

public sealed class NotificationSnoozeService : IDisposable
{
    private readonly object _gate = new();
    private readonly NotificationSnoozeStateStore _store;
    private Timer? _expirationTimer;
    private DateTime? _snoozedUntilUtc;

    public NotificationSnoozeService(NotificationSnoozeStateStore store)
    {
        _store = store;
        _snoozedUntilUtc = NotificationSnoozeState.CreateNormalized(_store.Load()).SnoozedUntilUtc;
        ScheduleExpirationTimer();
    }

    public bool IsSnoozed => GetSnoozedUntilUtc().HasValue;

    public DateTime? GetSnoozedUntilUtc()
    {
        lock (_gate)
        {
            if (_snoozedUntilUtc is not DateTime untilUtc)
                return null;

            if (untilUtc > DateTime.UtcNow)
                return untilUtc;

            ClearSnoozeCore(saveState: true);
            return null;
        }
    }

    public void SnoozeFor(TimeSpan duration)
    {
        if (duration <= TimeSpan.Zero)
            return;

        lock (_gate)
        {
            _snoozedUntilUtc = DateTime.UtcNow.Add(duration);
            PersistState();
            ScheduleExpirationTimer();
        }
    }

    public void ClearSnooze()
    {
        lock (_gate)
            ClearSnoozeCore(saveState: true);
    }

    public string GetStatusText()
    {
        DateTime? untilUtc = GetSnoozedUntilUtc();
        if (!untilUtc.HasValue)
            return "Notifications are active.";

        DateTime localUntil = untilUtc.Value.ToLocalTime();
        return $"Notifications muted until {localUntil:dd MMM HH:mm}.";
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _expirationTimer?.Dispose();
            _expirationTimer = null;
        }
    }

    private void OnExpirationTimer(object? state)
    {
        lock (_gate)
        {
            if (_snoozedUntilUtc is not DateTime untilUtc || untilUtc > DateTime.UtcNow)
            {
                ScheduleExpirationTimer();
                return;
            }

            ClearSnoozeCore(saveState: true);
        }
    }

    private void ClearSnoozeCore(bool saveState)
    {
        _snoozedUntilUtc = null;
        _expirationTimer?.Change(Timeout.Infinite, Timeout.Infinite);

        if (saveState)
            PersistState();
    }

    private void PersistState()
    {
        _store.Save(new NotificationSnoozeState
        {
            SnoozedUntilUtc = _snoozedUntilUtc
        });
    }

    private void ScheduleExpirationTimer()
    {
        if (_expirationTimer is null)
            _expirationTimer = new Timer(OnExpirationTimer);

        if (_snoozedUntilUtc is not DateTime untilUtc)
        {
            _expirationTimer.Change(Timeout.Infinite, Timeout.Infinite);
            return;
        }

        TimeSpan dueTime = untilUtc - DateTime.UtcNow;
        if (dueTime <= TimeSpan.Zero)
        {
            _expirationTimer.Change(TimeSpan.Zero, Timeout.InfiniteTimeSpan);
            return;
        }

        _expirationTimer.Change(dueTime, Timeout.InfiniteTimeSpan);
    }
}
