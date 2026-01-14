using System;
using System.Collections.Generic;
using System.Text;
using Domain.Models;
namespace Application.Abstractions
{
    public interface ICaptureDeviceService
    {
        IReadOnlyList<CaptureDeviceInfo> GetAllDevices();
    }
}
