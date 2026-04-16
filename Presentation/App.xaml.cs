// Відповідає за старт застосунку, налаштування DI/логування та відкриття головного вікна через Host.
using Application.Abstractions;
using Application.Capture;
using Application.Filtering;
using Application.Networking;
using Infrastructure.Aggregation;
using Infrastructure.Capture;
using Infrastructure.Networking;
using Infrastructure.Parsing;
using Infrastructure.Remediation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Presentation.Abstractions;
using Presentation.Dialogs;
using Presentation.Formatting;
using Presentation.Services;
using Presentation.ViewModels;
using System.Windows;

namespace Presentation;

public partial class App : System.Windows.Application
{
    private IHost? _host;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        _host = Host.CreateDefaultBuilder(e.Args)
            .ConfigureServices(services =>
            {
                services.AddLogging(b => b.AddDebug().AddConsole());
                
                // Infrastructure
                services.AddSingleton<ICaptureDeviceService, SharpPcapDeviceService>();
                // Відповідає за реєстрацію сервісу захоплення пакетів
                services.AddSingleton<IPacketCaptureService, SharpPcapCaptureService>();
                // Відповідає за реєстрацію PacketDotNet парсера.
                services.AddSingleton<IPacketParser, PacketDotNetParser>();
                // Services (presentation)
                services.AddSingleton<IHexDumpService, HexDumpService>();
                services.AddSingleton<IPacketFilterService, PacketFilterService>();
                services.AddSingleton<IFlowFilterService, FlowFilterService>();
                services.AddSingleton<IFileDialogService, FileDialogService>();
                services.AddSingleton<IUserPromptService, UserPromptService>();
                services.AddSingleton<WindowsRemediationService>();
                services.AddSingleton<HostResolutionService>();
                services.AddSingleton<ProcessForensicsTracker>();
                services.AddSingleton<ProcessLivenessTracker>();
                services.AddSingleton<NotificationSettingsStore>();
                services.AddSingleton<TrafficHistoryStore>();
                services.AddSingleton<TrafficControlRulesStore>();
                services.AddSingleton<WindowsShellNotificationService>();
                services.AddSingleton<ThreatNotificationCoordinator>();
                services.AddSingleton<TrafficControlManager>();
                services.AddSingleton<ProcessRemediationCoordinator>();
                services.AddSingleton<ProcessIncidentReportExportService>();
                services.AddSingleton<IProcessBaselineStore, JsonProcessBaselineStore>();
                services.AddSingleton<ProcessBehaviorBaselineService>();
                services.AddSingleton<ProcessIncidentGraphBuilder>();

                // ViewModels
                services.AddSingleton<MainViewModel>();
                services.AddSingleton<HistoryViewModel>();
                services.AddSingleton<ProcessPacketsViewModel>();
                services.AddSingleton<EndpointsViewModel>();
                services.AddSingleton<StatsViewModel>();
                // FlowsViewModel requires delegates created by MainViewModel, register factory
                services.AddTransient<FlowsViewModel>();
                services.AddTransient<Func<Func<bool>, Action, FlowsViewModel>>(sp => (uiNonEmpty, onFilterChanged) => ActivatorUtilities.CreateInstance<FlowsViewModel>(sp, uiNonEmpty, onFilterChanged));
                // FiltersViewModel requires initial PacketFilterModel -> factory
                services.AddTransient(sp => (Func<PacketFilterModel, FiltersViewModel>)(p => ActivatorUtilities.CreateInstance<FiltersViewModel>(sp, p)));
                services.AddTransient<NotificationSettingsViewModel>();
                services.AddTransient<Func<NotificationSettingsViewModel>>(sp => () => ActivatorUtilities.CreateInstance<NotificationSettingsViewModel>(sp));
                services.AddTransient<TrafficControlRulesViewModel>();
                services.AddTransient<Func<TrafficControlRulesViewModel>>(sp => () => ActivatorUtilities.CreateInstance<TrafficControlRulesViewModel>(sp));

                // Capture controller (expose via interface)
                services.AddSingleton<ICaptureController, CaptureController>();
                // Відповідає за резолв endpoint -> PID/процес.
                services.AddSingleton<ProcessMapperService>();
                // Відповідає за агрегацію потоків (Flows)
                services.AddSingleton<IFlowAggregator, FlowAggregator>();
                // Відповідає за визначення локальних IP для Direction.
                services.AddSingleton<ILocalAddressService, LocalAddressService>();
                // Views
                services.AddSingleton<MainWindow>(sp =>
                {
                    var vm = sp.GetRequiredService<MainViewModel>();
                    return new MainWindow { DataContext = vm };
                });
            })
            .Build();

        await _host.StartAsync();

        _host.Services.GetRequiredService<MainWindow>().Show();
    }

    protected override async void OnExit(ExitEventArgs e)
    {
        if (_host is not null)
        {
            await _host.StopAsync();
            _host.Dispose();
        }

        base.OnExit(e);
    }
}
