using Infrastructure.Networking;
using Presentation.Models;
using System;
using System.Collections.Generic;

namespace Presentation.Services;

public sealed class ProcessLivenessTracker
{
    private readonly ProcessMapperService _processMapperService;
    private DateTime _lastRefreshUtc = DateTime.MinValue;
    private static readonly TimeSpan RefreshInterval = TimeSpan.FromSeconds(1);

    public ProcessLivenessTracker(ProcessMapperService processMapperService)
    {
        _processMapperService = processMapperService;
    }

    public void RefreshIfNeeded(IEnumerable<ProcessStatRow> rows)
    {
        var now = DateTime.UtcNow;
        if ((now - _lastRefreshUtc) < RefreshInterval)
            return;

        _lastRefreshUtc = now;

        foreach (var row in rows)
        {
            if (row.Pid <= 0)
                continue;

            var live = _processMapperService.GetProcessLivenessCached(row.Pid);
            bool alive = live.IsAlive;

            if (alive
                && !string.IsNullOrWhiteSpace(row.ExePath)
                && !string.IsNullOrWhiteSpace(live.ExePath)
                && !string.Equals(row.ExePath, live.ExePath, StringComparison.OrdinalIgnoreCase))
            {
                alive = false;
            }

            row.IsAlive = alive;
        }
    }
}
