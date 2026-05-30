using Microsoft.Extensions.DependencyInjection;
using System;
using System.Windows;

namespace Presentation.Services;

public sealed class MainWindowManager
{
    private readonly IServiceProvider _services;

    public MainWindowManager(IServiceProvider services)
    {
        _services = services;
    }

    public MainWindow CreateMainWindow()
    {
        var viewModel = _services.GetRequiredService<ViewModels.MainViewModel>();
        return new MainWindow
        {
            DataContext = viewModel
        };
    }

    public void ShowMainWindow()
    {
        var application = System.Windows.Application.Current;
        if (application is null)
            throw new InvalidOperationException("Main window manager requires an active WPF application instance.");

        var window = CreateMainWindow();
        application.MainWindow = window;
        window.Show();
    }

    public void RecreateMainWindow()
    {
        var application = System.Windows.Application.Current;
        if (application is null)
            return;

        var currentWindow = application.MainWindow;
        if (currentWindow is null)
        {
            ShowMainWindow();
            return;
        }

        var nextWindow = CreateMainWindow();
        CopyWindowBounds(currentWindow, nextWindow);

        application.MainWindow = nextWindow;
        nextWindow.Show();

        WindowState desiredWindowState = currentWindow.WindowState == WindowState.Minimized
            ? WindowState.Normal
            : currentWindow.WindowState;
        nextWindow.WindowState = desiredWindowState;
        nextWindow.Activate();

        currentWindow.Close();
    }

    private static void CopyWindowBounds(Window source, Window target)
    {
        Rect bounds = source.WindowState == WindowState.Normal
            ? new Rect(source.Left, source.Top, source.Width, source.Height)
            : source.RestoreBounds;

        target.WindowStartupLocation = WindowStartupLocation.Manual;
        target.Left = bounds.Left;
        target.Top = bounds.Top;
        target.Width = Math.Max(bounds.Width, target.MinWidth);
        target.Height = Math.Max(bounds.Height, target.MinHeight);
    }
}
