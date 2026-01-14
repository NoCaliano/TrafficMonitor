using System;
using System.Collections.Generic;
using System.Text;

// Відповідає за DTO для відображення мережевого адаптера в UI.
namespace Domain.Models;

public sealed record CaptureDeviceInfo(
    string Id,
    string Name,
    string Description
);
