// Відповідає за старт застосунку, налаштування DI/логування та відкриття головного вікна через Host.
using Application.Abstractions;
using Infrastructure.Aggregation;
using Infrastructure.Capture;
using Infrastructure.Parsing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
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
                // ViewModels
                services.AddSingleton<MainViewModel>();
                // Відповідає за агрегацію потоків (Flows)
                services.AddSingleton<IFlowAggregator, FlowAggregator>();

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
