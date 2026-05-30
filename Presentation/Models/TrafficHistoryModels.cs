using System;
using System.Collections.Generic;

namespace Presentation.Models;

public sealed class TrafficHistoryDocument
{
    public int SchemaVersion { get; set; } = 1;
    public List<TrafficHistorySessionRecord> Sessions { get; set; } = new();
}

public sealed class TrafficHistorySessionRecord
{
    public string Id { get; set; } = "";
    public string SourceKind { get; set; } = "live";
    public DateTime RecordedAtUtc { get; set; }
    public DateTime? StartedAtUtc { get; set; }
    public DateTime? EndedAtUtc { get; set; }
    public string DeviceName { get; set; } = "";
    public string BpfFilter { get; set; } = "";
    public long TotalPackets { get; set; }
    public long TotalBytes { get; set; }
    public List<string> NewHosts { get; set; } = new();
    public List<string> NewProcesses { get; set; } = new();
    public List<TrafficHistoryProcessRecord> Processes { get; set; } = new();
    public List<TrafficHistoryHostRecord> Hosts { get; set; } = new();
}

public sealed class TrafficHistoryProcessRecord
{
    public string IdentityKey { get; set; } = "";
    public string ProcessName { get; set; } = "";
    public string ExePath { get; set; } = "";
    public string Publisher { get; set; } = "";
    public bool IsSigned { get; set; }
    public DateTime? FirstSeenUtc { get; set; }
    public DateTime? LastSeenUtc { get; set; }
    public long PacketCount { get; set; }
    public long TotalBytes { get; set; }
    public int DistinctRemoteEndpoints { get; set; }
    public string TopRemoteEndpoint { get; set; } = "";
    public int RiskScore { get; set; }
    public bool HasSuspiciousDomain { get; set; }
    public string DetectionSummaryLabel { get; set; } = "";
    public string TlsDnsSummaryLabel { get; set; } = "";
    public string BehaviorDeviationSummaryLabel { get; set; } = "";
    public string BaselineStateLabel { get; set; } = "";
}

public sealed class TrafficHistoryHostRecord
{
    public string Ip { get; set; } = "";
    public string DisplayHost { get; set; } = "";
    public string Scope { get; set; } = "";
    public DateTime? FirstSeenUtc { get; set; }
    public DateTime? LastSeenUtc { get; set; }
    public long Packets { get; set; }
    public long Bytes { get; set; }
    public List<string> ProcessNames { get; set; } = new();
    public List<string> ProcessDisplayNames { get; set; } = new();
    public List<string> ResolutionHints { get; set; } = new();
    public List<string> DnsNames { get; set; } = new();
    public List<string> TlsNames { get; set; } = new();
    public List<string> CertificateNames { get; set; } = new();
}

public sealed class TrafficHistoryDetailRow
{
    public string Title { get; init; } = "";
    public string Subtitle { get; init; } = "";
    public string BadgeText { get; init; } = "";
}

public sealed class TrafficHistorySessionRow
{
    public string Id { get; init; } = "";
    public string SessionLabel { get; init; } = "";
    public string SourceLabel { get; init; } = "";
    public string DeviceName { get; init; } = "";
    public string BpfFilter { get; init; } = "";
    public DateTime SortTimestamp { get; init; }
    public string StartedLabel { get; init; } = "";
    public string EndedLabel { get; init; } = "";
    public string DurationLabel { get; init; } = "";
    public long TotalPackets { get; init; }
    public string TotalPacketsLabel { get; init; } = "";
    public long TotalBytes { get; init; }
    public string TotalBytesLabel { get; init; } = "";
    public string NewHostsSummary { get; init; } = "";
    public string NewProcessesSummary { get; init; } = "";
    public string SearchText { get; init; } = "";
    public IReadOnlyList<TrafficHistoryDetailRow> NewHostDetails { get; init; } = Array.Empty<TrafficHistoryDetailRow>();
    public IReadOnlyList<TrafficHistoryDetailRow> NewProcessDetails { get; init; } = Array.Empty<TrafficHistoryDetailRow>();
    public IReadOnlyList<TrafficHistoryDetailRow> TopProcessDetails { get; init; } = Array.Empty<TrafficHistoryDetailRow>();
    public IReadOnlyList<TrafficHistoryDetailRow> TopHostDetails { get; init; } = Array.Empty<TrafficHistoryDetailRow>();

    public bool HasNewHosts => NewHostDetails.Count > 0;
    public bool HasNewProcesses => NewProcessDetails.Count > 0;
    public bool HasTopProcesses => TopProcessDetails.Count > 0;
    public bool HasTopHosts => TopHostDetails.Count > 0;
    public bool HasBpfFilter => !string.IsNullOrWhiteSpace(BpfFilter);
}

public sealed class TrafficHistoryProcessRow
{
    public string IdentityKey { get; init; } = "";
    public string DisplayName { get; init; } = "";
    public string ExePath { get; init; } = "";
    public string Publisher { get; init; } = "";
    public string SignatureLabel { get; init; } = "";
    public DateTime SortTimestamp { get; init; }
    public string FirstSeenLabel { get; init; } = "";
    public string LastSeenLabel { get; init; } = "";
    public int SessionsCount { get; init; }
    public long TotalPackets { get; init; }
    public string TotalPacketsLabel { get; init; } = "";
    public long TotalBytes { get; init; }
    public string TotalBytesLabel { get; init; } = "";
    public string TopRemoteEndpoint { get; init; } = "";
    public string RiskSummary { get; init; } = "";
    public string SearchText { get; init; } = "";
    public IReadOnlyList<TrafficHistoryDetailRow> SessionAppearances { get; init; } = Array.Empty<TrafficHistoryDetailRow>();
    public IReadOnlyList<TrafficHistoryDetailRow> KnownHosts { get; init; } = Array.Empty<TrafficHistoryDetailRow>();

    public bool HasSessionAppearances => SessionAppearances.Count > 0;
    public bool HasKnownHosts => KnownHosts.Count > 0;
}

public sealed class TrafficHistoryHostRow
{
    public string Ip { get; init; } = "";
    public string DisplayHost { get; init; } = "";
    public string Scope { get; init; } = "";
    public DateTime SortTimestamp { get; init; }
    public string FirstSeenLabel { get; init; } = "";
    public string LastSeenLabel { get; init; } = "";
    public int SessionsCount { get; init; }
    public int ProcessCount { get; init; }
    public long TotalPackets { get; init; }
    public string TotalPacketsLabel { get; init; } = "";
    public long TotalBytes { get; init; }
    public string TotalBytesLabel { get; init; } = "";
    public string ProcessSummary { get; init; } = "";
    public string DnsSummary { get; init; } = "";
    public string TlsSummary { get; init; } = "";
    public string SearchText { get; init; } = "";
    public IReadOnlyList<TrafficHistoryDetailRow> SessionAppearances { get; init; } = Array.Empty<TrafficHistoryDetailRow>();
    public IReadOnlyList<TrafficHistoryDetailRow> Processes { get; init; } = Array.Empty<TrafficHistoryDetailRow>();
    public IReadOnlyList<TrafficHistoryDetailRow> DnsNames { get; init; } = Array.Empty<TrafficHistoryDetailRow>();
    public IReadOnlyList<TrafficHistoryDetailRow> TlsNames { get; init; } = Array.Empty<TrafficHistoryDetailRow>();

    public bool HasSessionAppearances => SessionAppearances.Count > 0;
    public bool HasProcesses => Processes.Count > 0;
    public bool HasDnsNames => DnsNames.Count > 0;
    public bool HasTlsNames => TlsNames.Count > 0;
}
