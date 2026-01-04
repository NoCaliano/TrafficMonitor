using System;
using System.Collections.Generic;
using System.Text;

namespace Application.Abstractions
{
    public interface ICaptureDeviceService
    {
        IReadOnlyList<CaptureDeviceInfo> GetAllDevices();
    }
}
