using Presentation.Models;
using Presentation.Services;
using System;
using System.Windows;
using System.Windows.Input;

namespace Presentation.ViewModels;

public sealed class NotificationSettingsViewModel : ViewModelBase
{
    private readonly ThreatNotificationCoordinator _notificationCoordinator;

    private bool _notificationsEnabled;
    private bool _newProcessNotificationsEnabled;
    private bool _riskScoreNotificationsEnabled;
    private int _riskScoreThreshold;
    private bool _beaconNotificationsEnabled;
    private bool _quotaNotificationsEnabled;
    private bool _dailyProcessTrafficQuotaEnabled;
    private string _dailyProcessTrafficProcessFilter = "";
    private int _dailyProcessTrafficQuotaMb;
    private bool _unknownHostTrafficQuotaEnabled;
    private int _unknownHostTrafficQuotaMb;
    private bool _dnsBurstQuotaEnabled;
    private int _dnsBurstQueryThreshold;
    private int _dnsBurstWindowMinutes;

    public bool NotificationsEnabled
    {
        get => _notificationsEnabled;
        set => Set(ref _notificationsEnabled, value);
    }

    public bool NewProcessNotificationsEnabled
    {
        get => _newProcessNotificationsEnabled;
        set => Set(ref _newProcessNotificationsEnabled, value);
    }

    public bool RiskScoreNotificationsEnabled
    {
        get => _riskScoreNotificationsEnabled;
        set => Set(ref _riskScoreNotificationsEnabled, value);
    }

    public int RiskScoreThreshold
    {
        get => _riskScoreThreshold;
        set
        {
            int normalized = Math.Clamp(value, 1, 100);
            if (!Set(ref _riskScoreThreshold, normalized))
                return;

            OnPropertyChanged(nameof(RiskScoreThresholdLabel));
        }
    }

    public string RiskScoreThresholdLabel => RiskScoreThreshold.ToString();

    public bool BeaconNotificationsEnabled
    {
        get => _beaconNotificationsEnabled;
        set => Set(ref _beaconNotificationsEnabled, value);
    }

    public bool QuotaNotificationsEnabled
    {
        get => _quotaNotificationsEnabled;
        set => Set(ref _quotaNotificationsEnabled, value);
    }

    public bool DailyProcessTrafficQuotaEnabled
    {
        get => _dailyProcessTrafficQuotaEnabled;
        set => Set(ref _dailyProcessTrafficQuotaEnabled, value);
    }

    public string DailyProcessTrafficProcessFilter
    {
        get => _dailyProcessTrafficProcessFilter;
        set => Set(ref _dailyProcessTrafficProcessFilter, value ?? "");
    }

    public int DailyProcessTrafficQuotaMb
    {
        get => _dailyProcessTrafficQuotaMb;
        set
        {
            int normalized = Math.Clamp(value, 10, 50_000);
            if (!Set(ref _dailyProcessTrafficQuotaMb, normalized))
                return;

            OnPropertyChanged(nameof(DailyProcessTrafficQuotaMbLabel));
        }
    }

    public string DailyProcessTrafficQuotaMbLabel => $"{DailyProcessTrafficQuotaMb:N0} MB";

    public bool UnknownHostTrafficQuotaEnabled
    {
        get => _unknownHostTrafficQuotaEnabled;
        set => Set(ref _unknownHostTrafficQuotaEnabled, value);
    }

    public int UnknownHostTrafficQuotaMb
    {
        get => _unknownHostTrafficQuotaMb;
        set
        {
            int normalized = Math.Clamp(value, 1, 10_000);
            if (!Set(ref _unknownHostTrafficQuotaMb, normalized))
                return;

            OnPropertyChanged(nameof(UnknownHostTrafficQuotaMbLabel));
        }
    }

    public string UnknownHostTrafficQuotaMbLabel => $"{UnknownHostTrafficQuotaMb:N0} MB";

    public bool DnsBurstQuotaEnabled
    {
        get => _dnsBurstQuotaEnabled;
        set => Set(ref _dnsBurstQuotaEnabled, value);
    }

    public int DnsBurstQueryThreshold
    {
        get => _dnsBurstQueryThreshold;
        set
        {
            int normalized = Math.Clamp(value, 5, 10_000);
            if (!Set(ref _dnsBurstQueryThreshold, normalized))
                return;

            OnPropertyChanged(nameof(DnsBurstQueryThresholdLabel));
        }
    }

    public string DnsBurstQueryThresholdLabel => $"{DnsBurstQueryThreshold:N0} queries";

    public int DnsBurstWindowMinutes
    {
        get => _dnsBurstWindowMinutes;
        set
        {
            int normalized = Math.Clamp(value, 1, 120);
            if (!Set(ref _dnsBurstWindowMinutes, normalized))
                return;

            OnPropertyChanged(nameof(DnsBurstWindowMinutesLabel));
        }
    }

    public string DnsBurstWindowMinutesLabel => $"{DnsBurstWindowMinutes:N0} min";

    public ICommand SaveCommand { get; }
    public ICommand CancelCommand { get; }

    public NotificationSettingsViewModel(ThreatNotificationCoordinator notificationCoordinator)
    {
        _notificationCoordinator = notificationCoordinator;

        var settings = _notificationCoordinator.GetSettingsSnapshot();
        NotificationsEnabled = settings.NotificationsEnabled;
        NewProcessNotificationsEnabled = settings.NewProcessNotificationsEnabled;
        RiskScoreNotificationsEnabled = settings.RiskScoreNotificationsEnabled;
        RiskScoreThreshold = settings.RiskScoreThreshold;
        BeaconNotificationsEnabled = settings.BeaconNotificationsEnabled;
        QuotaNotificationsEnabled = settings.QuotaNotificationsEnabled;
        DailyProcessTrafficQuotaEnabled = settings.DailyProcessTrafficQuotaEnabled;
        DailyProcessTrafficProcessFilter = settings.DailyProcessTrafficProcessFilter;
        DailyProcessTrafficQuotaMb = settings.DailyProcessTrafficQuotaMb;
        UnknownHostTrafficQuotaEnabled = settings.UnknownHostTrafficQuotaEnabled;
        UnknownHostTrafficQuotaMb = settings.UnknownHostTrafficQuotaMb;
        DnsBurstQuotaEnabled = settings.DnsBurstQuotaEnabled;
        DnsBurstQueryThreshold = settings.DnsBurstQueryThreshold;
        DnsBurstWindowMinutes = settings.DnsBurstWindowMinutes;

        SaveCommand = new RelayCommand(Save);
        CancelCommand = new RelayCommand(Cancel);
    }

    private void Save(object? parameter)
    {
        _notificationCoordinator.SaveSettings(new NotificationSettings
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
        });

        CloseWindow(parameter, dialogResult: true);
    }

    private static void Cancel(object? parameter)
        => CloseWindow(parameter, dialogResult: false);

    private static void CloseWindow(object? parameter, bool dialogResult)
    {
        if (parameter is not Window window)
            return;

        window.DialogResult = dialogResult;
        window.Close();
    }
}
