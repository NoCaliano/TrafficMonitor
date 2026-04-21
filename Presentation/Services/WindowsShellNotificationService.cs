using Microsoft.Extensions.Logging;
using System;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using Forms = System.Windows.Forms;

namespace Presentation.Services;

public enum NotificationSeverity
{
    Info,
    Warning,
    Error
}

public sealed class WindowsShellNotificationService : IDisposable
{
    private const int BalloonTimeoutMs = 5000;
    private static readonly TimeSpan SnoozeOneHour = TimeSpan.FromHours(1);
    private static readonly TimeSpan SnoozeTwentyFourHours = TimeSpan.FromHours(24);

    private readonly Dispatcher _dispatcher;
    private readonly ILogger<WindowsShellNotificationService> _logger;
    private readonly NotificationSnoozeService _notificationSnoozeService;
    private readonly Forms.NotifyIcon _notifyIcon;
    private readonly Forms.ContextMenuStrip _contextMenu;
    private readonly Forms.ToolStripMenuItem _toggleCaptureMenuItem;
    private readonly Forms.ToolStripMenuItem _notificationsMenuItem;
    private readonly Forms.ToolStripMenuItem _notificationStatusMenuItem;
    private readonly Forms.ToolStripMenuItem _muteForOneHourMenuItem;
    private readonly Forms.ToolStripMenuItem _muteForTwentyFourHoursMenuItem;
    private readonly Forms.ToolStripMenuItem _clearNotificationSnoozeMenuItem;
    private readonly Forms.ToolStripMenuItem _quitMenuItem;

    private Func<bool>? _isCapturing;
    private ICommand? _startCommand;
    private ICommand? _stopCommand;
    private ICommand? _quitCommand;

    public WindowsShellNotificationService(
        ILogger<WindowsShellNotificationService> logger,
        NotificationSnoozeService notificationSnoozeService)
    {
        _logger = logger;
        _notificationSnoozeService = notificationSnoozeService;
        _dispatcher = System.Windows.Application.Current?.Dispatcher ?? Dispatcher.CurrentDispatcher;

        _contextMenu = new Forms.ContextMenuStrip
        {
            ShowImageMargin = false
        };
        _contextMenu.Opening += OnContextMenuOpening;

        _toggleCaptureMenuItem = new Forms.ToolStripMenuItem("Start capture");
        _toggleCaptureMenuItem.Click += OnToggleCaptureMenuItemClick;
        _contextMenu.Items.Add(_toggleCaptureMenuItem);

        _contextMenu.Items.Add(new Forms.ToolStripSeparator());

        _notificationsMenuItem = new Forms.ToolStripMenuItem("Notifications");
        _notificationStatusMenuItem = new Forms.ToolStripMenuItem("Notifications are active")
        {
            Enabled = false
        };
        _muteForOneHourMenuItem = new Forms.ToolStripMenuItem("Mute for 1 hour");
        _muteForOneHourMenuItem.Click += OnMuteForOneHourMenuItemClick;
        _muteForTwentyFourHoursMenuItem = new Forms.ToolStripMenuItem("Mute for 24 hours");
        _muteForTwentyFourHoursMenuItem.Click += OnMuteForTwentyFourHoursMenuItemClick;
        _clearNotificationSnoozeMenuItem = new Forms.ToolStripMenuItem("Unmute notifications");
        _clearNotificationSnoozeMenuItem.Click += OnClearNotificationSnoozeMenuItemClick;

        _notificationsMenuItem.DropDownItems.Add(_notificationStatusMenuItem);
        _notificationsMenuItem.DropDownItems.Add(new Forms.ToolStripSeparator());
        _notificationsMenuItem.DropDownItems.Add(_muteForOneHourMenuItem);
        _notificationsMenuItem.DropDownItems.Add(_muteForTwentyFourHoursMenuItem);
        _notificationsMenuItem.DropDownItems.Add(_clearNotificationSnoozeMenuItem);
        _contextMenu.Items.Add(_notificationsMenuItem);

        _contextMenu.Items.Add(new Forms.ToolStripSeparator());

        _quitMenuItem = new Forms.ToolStripMenuItem("Quit");
        _quitMenuItem.Click += OnQuitMenuItemClick;
        _contextMenu.Items.Add(_quitMenuItem);

        _notifyIcon = new Forms.NotifyIcon
        {
            Visible = true,
            Text = "TrafficMonitor",
            Icon = LoadApplicationIcon() ?? SystemIcons.Shield,
            ContextMenuStrip = _contextMenu
        };
        _notifyIcon.MouseUp += OnNotifyIconMouseUp;
        UpdateNotifyIconTextCore();
    }

    public void ConfigureMenu(Func<bool> isCapturing, ICommand startCommand, ICommand stopCommand, ICommand quitCommand)
    {
        _isCapturing = isCapturing;
        _startCommand = startCommand;
        _stopCommand = stopCommand;
        _quitCommand = quitCommand;
        UpdateMenuState();
    }

    public void Show(string title, string message, NotificationSeverity severity = NotificationSeverity.Info)
    {
        if (string.IsNullOrWhiteSpace(title) || string.IsNullOrWhiteSpace(message))
            return;

        if (_notificationSnoozeService.IsSnoozed)
            return;

        void ShowCore()
        {
            try
            {
                if (_notificationSnoozeService.IsSnoozed)
                    return;

                _notifyIcon.Visible = true;
                _notifyIcon.BalloonTipTitle = Truncate(title.Trim(), 63);
                _notifyIcon.BalloonTipText = Truncate(message.Trim(), 255);
                _notifyIcon.BalloonTipIcon = severity switch
                {
                    NotificationSeverity.Warning => Forms.ToolTipIcon.Warning,
                    NotificationSeverity.Error => Forms.ToolTipIcon.Error,
                    _ => Forms.ToolTipIcon.Info
                };

                _notifyIcon.ShowBalloonTip(BalloonTimeoutMs);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to show shell notification.");
            }
        }

        if (_dispatcher.CheckAccess())
        {
            ShowCore();
            return;
        }

        _dispatcher.BeginInvoke((Action)ShowCore);
    }

    public void Dispose()
    {
        if (_dispatcher.CheckAccess())
        {
            DisposeCore();
            return;
        }

        _dispatcher.Invoke((Action)DisposeCore);
    }

    private void OnContextMenuOpening(object? sender, System.ComponentModel.CancelEventArgs e)
        => UpdateMenuStateCore();

    private void OnNotifyIconMouseUp(object? sender, Forms.MouseEventArgs e)
    {
        if (e.Button != Forms.MouseButtons.Left)
            return;

        if (_dispatcher.CheckAccess())
        {
            ShowMenuAtCursor();
            return;
        }

        _dispatcher.BeginInvoke((Action)ShowMenuAtCursor);
    }

    private void OnToggleCaptureMenuItemClick(object? sender, EventArgs e)
        => ExecuteToggleCapture();

    private void OnMuteForOneHourMenuItemClick(object? sender, EventArgs e)
        => ApplyNotificationSnooze(SnoozeOneHour);

    private void OnMuteForTwentyFourHoursMenuItemClick(object? sender, EventArgs e)
        => ApplyNotificationSnooze(SnoozeTwentyFourHours);

    private void OnClearNotificationSnoozeMenuItemClick(object? sender, EventArgs e)
        => ClearNotificationSnooze();

    private void OnQuitMenuItemClick(object? sender, EventArgs e)
        => ExecuteCommand(_quitCommand);

    private void ShowMenuAtCursor()
    {
        try
        {
            UpdateMenuStateCore();
            _contextMenu.Show(Forms.Cursor.Position);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to show tray menu.");
        }
    }

    private void ExecuteToggleCapture()
    {
        if (_dispatcher.CheckAccess())
        {
            ExecuteToggleCaptureCore();
            return;
        }

        _dispatcher.BeginInvoke((Action)ExecuteToggleCaptureCore);
    }

    private void ExecuteToggleCaptureCore()
    {
        var command = _isCapturing?.Invoke() == true
            ? _stopCommand
            : _startCommand;

        ExecuteCommand(command);
    }

    private void ApplyNotificationSnooze(TimeSpan duration)
    {
        if (_dispatcher.CheckAccess())
        {
            ApplyNotificationSnoozeCore(duration);
            return;
        }

        _dispatcher.BeginInvoke((Action)(() => ApplyNotificationSnoozeCore(duration)));
    }

    private void ApplyNotificationSnoozeCore(TimeSpan duration)
    {
        _notificationSnoozeService.SnoozeFor(duration);
        UpdateMenuStateCore();
    }

    private void ClearNotificationSnooze()
    {
        if (_dispatcher.CheckAccess())
        {
            ClearNotificationSnoozeCore();
            return;
        }

        _dispatcher.BeginInvoke((Action)ClearNotificationSnoozeCore);
    }

    private void ClearNotificationSnoozeCore()
    {
        _notificationSnoozeService.ClearSnooze();
        UpdateMenuStateCore();
    }

    private static void ExecuteCommand(ICommand? command)
    {
        if (command is null || !command.CanExecute(null))
            return;

        command.Execute(null);
    }

    private void UpdateMenuState()
    {
        if (_dispatcher.CheckAccess())
        {
            UpdateMenuStateCore();
            return;
        }

        _dispatcher.BeginInvoke((Action)UpdateMenuStateCore);
    }

    private void UpdateMenuStateCore()
    {
        bool isCapturing = _isCapturing?.Invoke() == true;
        _toggleCaptureMenuItem.Text = isCapturing ? "Stop capture" : "Start capture";
        _toggleCaptureMenuItem.Enabled = isCapturing
            ? _stopCommand?.CanExecute(null) == true
            : _startCommand?.CanExecute(null) == true;

        bool isSnoozed = _notificationSnoozeService.IsSnoozed;
        _notificationStatusMenuItem.Text = _notificationSnoozeService.GetStatusText();
        _muteForOneHourMenuItem.Enabled = true;
        _muteForTwentyFourHoursMenuItem.Enabled = true;
        _clearNotificationSnoozeMenuItem.Enabled = isSnoozed;
        UpdateNotifyIconTextCore();

        _quitMenuItem.Enabled = _quitCommand?.CanExecute(null) ?? true;
    }

    private void UpdateNotifyIconTextCore()
    {
        _notifyIcon.Text = _notificationSnoozeService.IsSnoozed
            ? Truncate("TrafficMonitor - notifications muted", 63)
            : "TrafficMonitor";
    }

    private void DisposeCore()
    {
        try
        {
            _notifyIcon.MouseUp -= OnNotifyIconMouseUp;
            _toggleCaptureMenuItem.Click -= OnToggleCaptureMenuItemClick;
            _muteForOneHourMenuItem.Click -= OnMuteForOneHourMenuItemClick;
            _muteForTwentyFourHoursMenuItem.Click -= OnMuteForTwentyFourHoursMenuItemClick;
            _clearNotificationSnoozeMenuItem.Click -= OnClearNotificationSnoozeMenuItemClick;
            _quitMenuItem.Click -= OnQuitMenuItemClick;
            _contextMenu.Opening -= OnContextMenuOpening;
            _notifyIcon.Visible = false;
            _notifyIcon.Dispose();
            _contextMenu.Dispose();
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to dispose shell notification resources.");
        }
    }

    private Icon? LoadApplicationIcon()
    {
        try
        {
            var resourceUri = new Uri("pack://application:,,,/Images/Icon1024by1024.png", UriKind.Absolute);
            var resource = System.Windows.Application.GetResourceStream(resourceUri);
            if (resource?.Stream is null)
                return null;

            using (resource.Stream)
            using (var bitmap = new Bitmap(resource.Stream))
            using (var resizedBitmap = new Bitmap(bitmap, new System.Drawing.Size(32, 32)))
            {
                IntPtr hIcon = resizedBitmap.GetHicon();
                try
                {
                    using var tempIcon = Icon.FromHandle(hIcon);
                    return (Icon)tempIcon.Clone();
                }
                finally
                {
                    DestroyIcon(hIcon);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to load custom application icon.");
            return null;
        }
    }

    private static string Truncate(string value, int maxLength)
        => string.IsNullOrWhiteSpace(value) || value.Length <= maxLength
            ? value
            : value[..Math.Max(0, maxLength - 1)] + "...";

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyIcon(IntPtr hIcon);
}
