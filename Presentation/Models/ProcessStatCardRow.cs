using System;
using System.Collections.Generic;
using System.Linq;

namespace Presentation.Models;

public sealed class ProcessStatCardRow
{
    public ProcessStatCardRow(IEnumerable<ProcessStatRow> items)
    {
        ArgumentNullException.ThrowIfNull(items);
        Items = items.ToArray();
    }

    public IReadOnlyList<ProcessStatRow> Items { get; }
}
