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
            BeaconNotificationsEnabled = BeaconNotificationsEnabled
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
