using System;
using System.Collections.Generic;
using System.Linq;

namespace Presentation.Models;

public static class TrafficControlTargetKinds
{
    public const string Process = "Process";
    public const string Host = "Host";
    public const string ProcessAndHost = "Process + host";

    public static IReadOnlyList<string> All { get; } =
    [
        Process,
        Host,
        ProcessAndHost
    ];

    public static string Normalize(string? value)
        => All.Contains(value, StringComparer.OrdinalIgnoreCase)
            ? All.First(item => string.Equals(item, value, StringComparison.OrdinalIgnoreCase))
            : Process;

    public static bool IncludesProcess(string? value)
        => string.Equals(Normalize(value), Process, StringComparison.OrdinalIgnoreCase)
            || string.Equals(Normalize(value), ProcessAndHost, StringComparison.OrdinalIgnoreCase);

    public static bool IncludesHost(string? value)
        => string.Equals(Normalize(value), Host, StringComparison.OrdinalIgnoreCase)
            || string.Equals(Normalize(value), ProcessAndHost, StringComparison.OrdinalIgnoreCase);
}

public static class TrafficControlPriorityLevels
{
    public const string Normal = "Normal";
    public const string Background = "Background";
    public const string High = "High";
    public const string Critical = "Critical";

    public static IReadOnlyList<string> All { get; } =
    [
        Normal,
        Background,
        High,
        Critical
    ];

    public static string Normalize(string? value)
        => All.Contains(value, StringComparer.OrdinalIgnoreCase)
            ? All.First(item => string.Equals(item, value, StringComparison.OrdinalIgnoreCase))
            : Normal;
}

public sealed class TrafficControlRulesDocument
{
    public int SchemaVersion { get; set; } = 1;
    public List<TrafficControlRule> Rules { get; set; } = new();
}

public sealed class TrafficControlRule
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Name { get; set; } = "New traffic rule";
    public bool Enabled { get; set; } = true;
    public string TargetKind { get; set; } = TrafficControlTargetKinds.Process;
    public string ProcessFilter { get; set; } = "";
    public string RemoteAddress { get; set; } = "";
    public int ThrottleMbps { get; set; }
    public string Priority { get; set; } = TrafficControlPriorityLevels.Normal;
    public int DailyQuotaMb { get; set; }
    public bool AutoBlockOnQuota { get; set; } = true;
    public bool NotifyOnTrigger { get; set; } = true;
    public bool ScheduleEnabled { get; set; }
    public bool Monday { get; set; } = true;
    public bool Tuesday { get; set; } = true;
    public bool Wednesday { get; set; } = true;
    public bool Thursday { get; set; } = true;
    public bool Friday { get; set; } = true;
    public bool Saturday { get; set; }
    public bool Sunday { get; set; }
    public int StartMinutes { get; set; } = 9 * 60;
    public int EndMinutes { get; set; } = 18 * 60;

    public TrafficControlRule Clone()
        => new()
        {
            Id = Id,
            Name = Name,
            Enabled = Enabled,
            TargetKind = TargetKind,
            ProcessFilter = ProcessFilter,
            RemoteAddress = RemoteAddress,
            ThrottleMbps = ThrottleMbps,
            Priority = Priority,
            DailyQuotaMb = DailyQuotaMb,
            AutoBlockOnQuota = AutoBlockOnQuota,
            NotifyOnTrigger = NotifyOnTrigger,
            ScheduleEnabled = ScheduleEnabled,
            Monday = Monday,
            Tuesday = Tuesday,
            Wednesday = Wednesday,
            Thursday = Thursday,
            Friday = Friday,
            Saturday = Saturday,
            Sunday = Sunday,
            StartMinutes = StartMinutes,
            EndMinutes = EndMinutes
        };

    public static TrafficControlRule CreateNormalized(TrafficControlRule? rule)
    {
        var normalized = rule?.Clone() ?? new TrafficControlRule();
        normalized.Id = string.IsNullOrWhiteSpace(normalized.Id)
            ? Guid.NewGuid().ToString("N")
            : normalized.Id.Trim();
        normalized.Name = string.IsNullOrWhiteSpace(normalized.Name)
            ? "New traffic rule"
            : normalized.Name.Trim();
        normalized.TargetKind = TrafficControlTargetKinds.Normalize(normalized.TargetKind);
        normalized.ProcessFilter = (normalized.ProcessFilter ?? string.Empty).Trim();
        normalized.RemoteAddress = (normalized.RemoteAddress ?? string.Empty).Trim();
        normalized.ThrottleMbps = Math.Clamp(normalized.ThrottleMbps, 0, 100_000);
        normalized.Priority = TrafficControlPriorityLevels.Normalize(normalized.Priority);
        normalized.DailyQuotaMb = Math.Clamp(normalized.DailyQuotaMb, 0, 500_000);
        normalized.StartMinutes = Math.Clamp(normalized.StartMinutes, 0, 1_439);
        normalized.EndMinutes = Math.Clamp(normalized.EndMinutes, 0, 1_439);
        return normalized;
    }
}
