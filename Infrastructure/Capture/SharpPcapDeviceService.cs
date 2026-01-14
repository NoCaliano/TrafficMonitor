using Application.Abstractions;
using SharpPcap;
using Domain.Models;
namespace Infrastructure.Capture;

public sealed class SharpPcapDeviceService : ICaptureDeviceService
{
    public IReadOnlyList<CaptureDeviceInfo> GetAllDevices()
    {
        var devices = CaptureDeviceList.Instance;

        return devices
            .Select(d => new CaptureDeviceInfo(
                Id: d.Name,
                Name: d.Description ?? d.Name,
                Description: d.Description ?? string.Empty))
            .ToList();
    }
}
