// Відповідає за логіку головного екрану: завантаження і відображення списку мережевих адаптерів.
using System.Collections.ObjectModel;
using Application.Abstractions;

namespace Presentation.ViewModels;

public sealed class MainViewModel : ViewModelBase
{
    private readonly ICaptureDeviceService _deviceService;

    public ObservableCollection<CaptureDeviceInfo> Devices { get; } = new();

    private CaptureDeviceInfo? _selectedDevice;
    public CaptureDeviceInfo? SelectedDevice
    {
        get => _selectedDevice;
        set => Set(ref _selectedDevice, value);
    }

    public MainViewModel(ICaptureDeviceService deviceService)
    {
        _deviceService = deviceService;

        LoadDevices();
    }

    private void LoadDevices()
    {
        Devices.Clear();
        foreach (var d in _deviceService.GetAllDevices())
            Devices.Add(d);

        SelectedDevice = Devices.FirstOrDefault();
    }
}
