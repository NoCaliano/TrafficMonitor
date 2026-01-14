using System;
using System.Collections.Generic;
using System.Text;
// Відповідає за напрямок потоку відносно локального ПК.
namespace Domain.Models;

public enum FlowDirection
{
    Unknown = 0,
    Outbound = 1,
    Inbound = 2,
    Local = 3
}
