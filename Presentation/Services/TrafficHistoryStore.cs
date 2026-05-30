using Application.Capture;
using Presentation.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace Presentation.Services;

public sealed class TrafficHistoryStore
{
    private const int SchemaVersion = 1;
    private const int MaxStoredSessions = 180;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    private readonly object _gate = new();
    private readonly string _filePath;
    private TrafficHistoryDocument _document;

    public event Action? HistoryChanged;

    public TrafficHistoryStore()
    {
        string appDataRoot = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string dataDirectory = Path.Combine(appDataRoot, "TrafficMonitor");
        _filePath = Path.Combine(dataDirectory, "traffic-history.json");
        _document = LoadUnsafe();
    }

    public IReadOnlyList<TrafficHistorySessionRecord> GetSessionsSnapshot()
    {
        lock (_gate)
            return _document.Sessions.Select(CloneSession).ToArray();
    }

    public bool AppendLiveSession(
        CaptureStats stats,
        string? deviceName,
        string? bpfFilter,
        IEnumerable<ProcessStatRow> processStats,
        IEnumerable<EndpointHostRow> hosts)
    {
        ArgumentNullException.ThrowIfNull(stats);
        ArgumentNullException.ThrowIfNull(processStats);
        ArgumentNullException.ThrowIfNull(hosts);

        var processRows = processStats
            .Where(static row => row.PacketCount > 0 || row.TotalBytes > 0)
            .ToArray();

        var hostRows = hosts
            .Where(static row => row.Packets > 0 || row.Bytes > 0)
            .ToArray();

        if (stats.TotalPackets <= 0 && stats.TotalBytes <= 0 && processRows.Length == 0 && hostRows.Length == 0)
            return false;

        var session = new TrafficHistorySessionRecord
        {
            Id = Guid.NewGuid().ToString("N"),
            SourceKind = "live",
            RecordedAtUtc = DateTime.UtcNow,
            StartedAtUtc = stats.FirstSeen?.ToUniversalTime(),
            EndedAtUtc = stats.LastSeen?.ToUniversalTime(),
            DeviceName = (deviceName ?? string.Empty).Trim(),
            BpfFilter = (bpfFilter ?? string.Empty).Trim(),
            TotalPackets = stats.TotalPackets,
            TotalBytes = stats.TotalBytes,
            Processes = BuildProcessRecords(processRows),
            Hosts = BuildHostRecords(hostRows)
        };

        lock (_gate)
        {
            var knownProcessKeys = new HashSet<string>(
                _document.Sessions.SelectMany(static session => session.Processes)
                    .Select(static process => process.IdentityKey),
                StringComparer.OrdinalIgnoreCase);

            var knownPublicHostIps = new HashSet<string>(
                _document.Sessions.SelectMany(static session => session.Hosts)
                    .Where(static host => string.Equals(host.Scope, "Public", StringComparison.OrdinalIgnoreCase))
                    .Select(static host => host.Ip),
                StringComparer.OrdinalIgnoreCase);

            session.NewProcesses = session.Processes
                .Where(process => !knownProcessKeys.Contains(process.IdentityKey))
                .OrderByDescending(static process => process.TotalBytes)
                .ThenBy(static process => process.ProcessName, StringComparer.OrdinalIgnoreCase)
                .Select(static process => process.ProcessName)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(12)
                .ToList();

            session.NewHosts = session.Hosts
                .Where(host => string.Equals(host.Scope, "Public", StringComparison.OrdinalIgnoreCase) && !knownPublicHostIps.Contains(host.Ip))
                .OrderByDescending(static host => host.Bytes)
                .ThenBy(static host => host.DisplayHost, StringComparer.OrdinalIgnoreCase)
                .Select(static host => string.IsNullOrWhiteSpace(host.DisplayHost) ? host.Ip : $"{host.DisplayHost} ({host.Ip})")
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(12)
                .ToList();

            _document.Sessions.Add(session);
            _document.Sessions = _document.Sessions
                .OrderByDescending(static item => item.StartedAtUtc ?? item.RecordedAtUtc)
                .Take(MaxStoredSessions)
                .Select(CloneSession)
                .ToList();
            _document.SchemaVersion = SchemaVersion;
            SaveUnsafe();
        }

        HistoryChanged?.Invoke();
        return true;
    }

    private static List<TrafficHistoryProcessRecord> BuildProcessRecords(IEnumerable<ProcessStatRow> processRows)
    {
        return processRows
            .Select(static row => new TrafficHistoryProcessRecord
            {
                IdentityKey = BuildProcessIdentityKey(row),
                ProcessName = row.ProcessName,
                ExePath = row.ExePath,
                Publisher = row.Publisher,
                IsSigned = row.IsSigned,
                FirstSeenUtc = row.FirstObservedAt == default ? null : row.FirstObservedAt.ToUniversalTime(),
                LastSeenUtc = row.LastSeen == default ? null : row.LastSeen.ToUniversalTime(),
                PacketCount = row.PacketCount,
                TotalBytes = row.TotalBytes,
                DistinctRemoteEndpoints = row.DistinctRemoteEndpoints,
                TopRemoteEndpoint = row.TopRemoteEndpoint,
                RiskScore = row.RiskScore,
                HasSuspiciousDomain = row.HasSuspiciousDomain,
                DetectionSummaryLabel = row.DetectionSummaryLabel,
                TlsDnsSummaryLabel = row.TlsDnsSummaryLabel,
                BehaviorDeviationSummaryLabel = row.BehaviorDeviationSummaryLabel,
                BaselineStateLabel = row.BaselineStateLabel
            })
            .OrderByDescending(static row => row.TotalBytes)
            .ThenBy(static row => row.ProcessName, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static List<TrafficHistoryHostRecord> BuildHostRecords(IEnumerable<EndpointHostRow> hostRows)
    {
        return hostRows
            .Select(static row => new TrafficHistoryHostRecord
            {
                Ip = row.Ip,
                DisplayHost = row.DisplayHost,
                Scope = row.Scope,
                FirstSeenUtc = row.FirstSeen == default ? null : row.FirstSeen.ToUniversalTime(),
                LastSeenUtc = row.LastSeen == default ? null : row.LastSeen.ToUniversalTime(),
                Packets = row.Packets,
                Bytes = row.Bytes,
                ProcessNames = row.OwningProcesses
                    .Select(static process => NormalizeProcessName(process.Title))
                    .Where(static value => !string.IsNullOrWhiteSpace(value))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList(),
                ProcessDisplayNames = row.OwningProcesses
                    .Select(static process => process.Title)
                    .Where(static value => !string.IsNullOrWhiteSpace(value))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList(),
                ResolutionHints = row.ResolutionHints
                    .Select(static item => item.Title)
                    .Where(static value => !string.IsNullOrWhiteSpace(value))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList(),
                DnsNames = row.DnsHistory
                    .Select(static item => item.Title)
                    .Where(static value => !string.IsNullOrWhiteSpace(value))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList(),
                TlsNames = row.TlsHistory
                    .Select(static item => item.Title)
                    .Where(static value => !string.IsNullOrWhiteSpace(value))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList(),
                CertificateNames = row.CertificateHistory
                    .Select(static item => item.Title)
                    .Where(static value => !string.IsNullOrWhiteSpace(value))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList()
            })
            .OrderByDescending(static row => row.Bytes)
            .ThenBy(static row => row.DisplayHost, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private TrafficHistoryDocument LoadUnsafe()
    {
        try
        {
            if (!File.Exists(_filePath))
                return new TrafficHistoryDocument { SchemaVersion = SchemaVersion };

            string json = File.ReadAllText(_filePath, Encoding.UTF8);
            if (string.IsNullOrWhiteSpace(json))
                return new TrafficHistoryDocument { SchemaVersion = SchemaVersion };

            var document = JsonSerializer.Deserialize<TrafficHistoryDocument>(json, JsonOptions);
            if (document is null)
                return new TrafficHistoryDocument { SchemaVersion = SchemaVersion };

            document.SchemaVersion = SchemaVersion;
            document.Sessions ??= new List<TrafficHistorySessionRecord>();
            return document;
        }
        catch
        {
            return new TrafficHistoryDocument { SchemaVersion = SchemaVersion };
        }
    }

    private void SaveUnsafe()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_filePath)!);
        string json = JsonSerializer.Serialize(_document, JsonOptions);
        File.WriteAllText(_filePath, json, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
    }

    private static TrafficHistorySessionRecord CloneSession(TrafficHistorySessionRecord session)
    {
        return new TrafficHistorySessionRecord
        {
            Id = session.Id,
            SourceKind = session.SourceKind,
            RecordedAtUtc = session.RecordedAtUtc,
            StartedAtUtc = session.StartedAtUtc,
            EndedAtUtc = session.EndedAtUtc,
            DeviceName = session.DeviceName,
            BpfFilter = session.BpfFilter,
            TotalPackets = session.TotalPackets,
            TotalBytes = session.TotalBytes,
            NewHosts = session.NewHosts.ToList(),
            NewProcesses = session.NewProcesses.ToList(),
            Processes = session.Processes.Select(CloneProcess).ToList(),
            Hosts = session.Hosts.Select(CloneHost).ToList()
        };
    }

    private static TrafficHistoryProcessRecord CloneProcess(TrafficHistoryProcessRecord process)
    {
        return new TrafficHistoryProcessRecord
        {
            IdentityKey = process.IdentityKey,
            ProcessName = process.ProcessName,
            ExePath = process.ExePath,
            Publisher = process.Publisher,
            IsSigned = process.IsSigned,
            FirstSeenUtc = process.FirstSeenUtc,
            LastSeenUtc = process.LastSeenUtc,
            PacketCount = process.PacketCount,
            TotalBytes = process.TotalBytes,
            DistinctRemoteEndpoints = process.DistinctRemoteEndpoints,
            TopRemoteEndpoint = process.TopRemoteEndpoint,
            RiskScore = process.RiskScore,
            HasSuspiciousDomain = process.HasSuspiciousDomain,
            DetectionSummaryLabel = process.DetectionSummaryLabel,
            TlsDnsSummaryLabel = process.TlsDnsSummaryLabel,
            BehaviorDeviationSummaryLabel = process.BehaviorDeviationSummaryLabel,
            BaselineStateLabel = process.BaselineStateLabel
        };
    }

    private static TrafficHistoryHostRecord CloneHost(TrafficHistoryHostRecord host)
    {
        return new TrafficHistoryHostRecord
        {
            Ip = host.Ip,
            DisplayHost = host.DisplayHost,
            Scope = host.Scope,
            FirstSeenUtc = host.FirstSeenUtc,
            LastSeenUtc = host.LastSeenUtc,
            Packets = host.Packets,
            Bytes = host.Bytes,
            ProcessNames = host.ProcessNames.ToList(),
            ProcessDisplayNames = host.ProcessDisplayNames.ToList(),
            ResolutionHints = host.ResolutionHints.ToList(),
            DnsNames = host.DnsNames.ToList(),
            TlsNames = host.TlsNames.ToList(),
            CertificateNames = host.CertificateNames.ToList()
        };
    }

    private static string BuildProcessIdentityKey(ProcessStatRow row)
    {
        if (!string.IsNullOrWhiteSpace(row.ExePath))
            return row.ExePath.Trim().ToLowerInvariant();

        if (!string.IsNullOrWhiteSpace(row.ProcessName))
            return row.ProcessName.Trim().ToLowerInvariant();

        return $"pid:{row.Pid}";
    }

    private static string NormalizeProcessName(string displayTitle)
    {
        if (string.IsNullOrWhiteSpace(displayTitle))
            return string.Empty;

        int pidIndex = displayTitle.IndexOf(" (PID ", StringComparison.OrdinalIgnoreCase);
        return pidIndex > 0
            ? displayTitle[..pidIndex].Trim()
            : displayTitle.Trim();
    }
}
