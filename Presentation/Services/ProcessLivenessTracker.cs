using Infrastructure.Networking;
using Presentation.Models;
using System;
using System.Collections.Generic;

namespace Presentation.Services;

public sealed class ProcessLivenessTracker
{
    public readonly record struct ProcessRuntimeChange(
        int Pid,
        bool HasExitedEvent,
        string ExitedDetail,
        bool HasIdentityChangedEvent,
        string IdentityChangedDetail,
        DateTime Timestamp);

    private readonly ProcessMapperService _processMapperService;
    private DateTime _lastRefreshUtc = DateTime.MinValue;
    private static readonly TimeSpan RefreshInterval = TimeSpan.FromSeconds(1);

    public ProcessLivenessTracker(ProcessMapperService processMapperService)
    {
        _processMapperService = processMapperService;
    }

    public IReadOnlyList<ProcessRuntimeChange> RefreshIfNeeded(IEnumerable<ProcessStatRow> rows)
    {
        var now = DateTime.UtcNow;
        if ((now - _lastRefreshUtc) < RefreshInterval)
            return Array.Empty<ProcessRuntimeChange>();

        _lastRefreshUtc = now;
        var changes = new List<ProcessRuntimeChange>();

        foreach (var row in rows)
        {
            if (row.Pid <= 0)
                continue;

            bool wasAlive = row.IsAlive;
            var live = _processMapperService.GetProcessLivenessCached(row.Pid);
            bool alive = live.IsAlive;

            if (alive)
            {
                var details = _processMapperService.GetProcessDetailsCached(row.Pid);
                var parentName = details.ParentPid > 0 ? _processMapperService.GetProcessNameCached(details.ParentPid) : "";

                if (TryBuildIdentityChangedDetail(row, details, out var identityChangedDetail))
                {
                    row.UpdateIdentity(details.ExePath, details.Publisher, details.IsSigned, details.SignerSubject, details.ParentPid, parentName);
                    changes.Add(new ProcessRuntimeChange(
                        Pid: row.Pid,
                        HasExitedEvent: false,
                        ExitedDetail: "",
                        HasIdentityChangedEvent: true,
                        IdentityChangedDetail: identityChangedDetail,
                        Timestamp: DateTime.Now));
                }
            }

            row.IsAlive = alive;

            if (wasAlive && !alive)
            {
                string detail = string.IsNullOrWhiteSpace(row.ExePathShort)
                    ? $"{row.ProcessName} (PID {row.Pid}) is no longer running."
                    : $"{row.ExePathShort} (PID {row.Pid}) is no longer running.";

                changes.Add(new ProcessRuntimeChange(
                    Pid: row.Pid,
                    HasExitedEvent: true,
                    ExitedDetail: detail,
                    HasIdentityChangedEvent: false,
                    IdentityChangedDetail: "",
                    Timestamp: DateTime.Now));
            }
        }

        return changes;
    }

    public void Reset()
    {
        _lastRefreshUtc = DateTime.MinValue;
    }

    private static bool TryBuildIdentityChangedDetail(ProcessStatRow row, ProcessMapperService.ProcessDetails details, out string detail)
    {
        var parts = new List<string>();

        if (!string.Equals(row.ExePath, details.ExePath, StringComparison.OrdinalIgnoreCase))
        {
            parts.Add($"Path: {FormatPathLabel(row.ExePath)} -> {FormatPathLabel(details.ExePath)}");
        }

        if (row.IsSigned != details.IsSigned)
        {
            parts.Add(details.IsSigned ? "Binary is now signed." : "Binary is now unsigned.");
        }
        else if (details.IsSigned && !string.Equals(row.SignerSubject, details.SignerSubject, StringComparison.OrdinalIgnoreCase))
        {
            parts.Add($"Signer: {FormatLabel(row.SignerSubject)} -> {FormatLabel(details.SignerSubject)}");
        }

        if (!string.Equals(row.Publisher, details.Publisher, StringComparison.OrdinalIgnoreCase)
            && !string.IsNullOrWhiteSpace(details.Publisher))
        {
            parts.Add($"Publisher: {FormatLabel(row.Publisher)} -> {FormatLabel(details.Publisher)}");
        }

        detail = string.Join(" ", parts);
        return parts.Count > 0;
    }

    private static string FormatPathLabel(string value)
        => string.IsNullOrWhiteSpace(value) ? "unresolved path" : value;

    private static string FormatLabel(string value)
        => string.IsNullOrWhiteSpace(value) ? "unknown" : value;
}
