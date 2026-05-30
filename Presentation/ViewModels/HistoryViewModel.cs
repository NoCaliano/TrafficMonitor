using Presentation.Helpers;
using Presentation.Models;
using Presentation.Services;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Windows;
using System.Windows.Data;

namespace Presentation.ViewModels;

public sealed class HistoryViewModel : ViewModelBase
{
    private readonly TrafficHistoryStore _store;

    public BulkObservableCollection<TrafficHistorySessionRow> Sessions { get; } = new();
    public BulkObservableCollection<TrafficHistoryProcessRow> Processes { get; } = new();
    public BulkObservableCollection<TrafficHistoryHostRow> Hosts { get; } = new();

    public ICollectionView SessionsView { get; }
    public ICollectionView ProcessesView { get; }
    public ICollectionView HostsView { get; }

    private string _sessionSearchText = "";
    public string SessionSearchText
    {
        get => _sessionSearchText;
        set
        {
            if (!Set(ref _sessionSearchText, value))
                return;

            SessionsView.Refresh();
            UpdateSummaryCounts();
        }
    }

    private string _processSearchText = "";
    public string ProcessSearchText
    {
        get => _processSearchText;
        set
        {
            if (!Set(ref _processSearchText, value))
                return;

            ProcessesView.Refresh();
            UpdateSummaryCounts();
        }
    }

    private string _hostSearchText = "";
    public string HostSearchText
    {
        get => _hostSearchText;
        set
        {
            if (!Set(ref _hostSearchText, value))
                return;

            HostsView.Refresh();
            UpdateSummaryCounts();
        }
    }

    private TrafficHistorySessionRow? _selectedSession;
    public TrafficHistorySessionRow? SelectedSession
    {
        get => _selectedSession;
        set
        {
            if (!Set(ref _selectedSession, value))
                return;

            OnPropertyChanged(nameof(HasSelectedSession));
        }
    }

    public bool HasSelectedSession => SelectedSession is not null;

    private TrafficHistoryProcessRow? _selectedProcess;
    public TrafficHistoryProcessRow? SelectedProcess
    {
        get => _selectedProcess;
        set
        {
            if (!Set(ref _selectedProcess, value))
                return;

            OnPropertyChanged(nameof(HasSelectedProcess));
        }
    }

    public bool HasSelectedProcess => SelectedProcess is not null;

    private TrafficHistoryHostRow? _selectedHost;
    public TrafficHistoryHostRow? SelectedHost
    {
        get => _selectedHost;
        set
        {
            if (!Set(ref _selectedHost, value))
                return;

            OnPropertyChanged(nameof(HasSelectedHost));
        }
    }

    public bool HasSelectedHost => SelectedHost is not null;

    private int _sessionCount;
    public int SessionCount
    {
        get => _sessionCount;
        private set => Set(ref _sessionCount, value);
    }

    private int _processCount;
    public int ProcessCount
    {
        get => _processCount;
        private set => Set(ref _processCount, value);
    }

    private int _hostCount;
    public int HostCount
    {
        get => _hostCount;
        private set => Set(ref _hostCount, value);
    }

    public HistoryViewModel(TrafficHistoryStore store)
    {
        _store = store;

        SessionsView = CollectionViewSource.GetDefaultView(Sessions);
        SessionsView.Filter = MatchesSessionFilters;
        SessionsView.SortDescriptions.Add(new SortDescription(nameof(TrafficHistorySessionRow.SortTimestamp), ListSortDirection.Descending));

        ProcessesView = CollectionViewSource.GetDefaultView(Processes);
        ProcessesView.Filter = MatchesProcessFilters;
        ProcessesView.SortDescriptions.Add(new SortDescription(nameof(TrafficHistoryProcessRow.SortTimestamp), ListSortDirection.Descending));
        ProcessesView.SortDescriptions.Add(new SortDescription(nameof(TrafficHistoryProcessRow.TotalBytes), ListSortDirection.Descending));

        HostsView = CollectionViewSource.GetDefaultView(Hosts);
        HostsView.Filter = MatchesHostFilters;
        HostsView.SortDescriptions.Add(new SortDescription(nameof(TrafficHistoryHostRow.SortTimestamp), ListSortDirection.Descending));
        HostsView.SortDescriptions.Add(new SortDescription(nameof(TrafficHistoryHostRow.TotalBytes), ListSortDirection.Descending));

        _store.HistoryChanged += OnHistoryChanged;
        Reload();
    }

    private void OnHistoryChanged()
    {
        var dispatcher = System.Windows.Application.Current?.Dispatcher;
        if (dispatcher is null || dispatcher.CheckAccess())
        {
            Reload();
            return;
        }

        dispatcher.BeginInvoke(new Action(Reload));
    }

    private void Reload()
    {
        string? selectedSessionId = SelectedSession?.Id;
        string? selectedProcessKey = SelectedProcess?.IdentityKey;
        string? selectedHostIp = SelectedHost?.Ip;

        var sessions = _store.GetSessionsSnapshot()
            .OrderByDescending(static session => session.StartedAtUtc ?? session.RecordedAtUtc)
            .ToArray();

        var sessionRows = BuildSessionRows(sessions);
        var processRows = BuildProcessRows(sessions);
        var hostRows = BuildHostRows(sessions);

        Sessions.ReplaceAll(sessionRows);
        Processes.ReplaceAll(processRows);
        Hosts.ReplaceAll(hostRows);

        SelectedSession = !string.IsNullOrWhiteSpace(selectedSessionId)
            ? Sessions.FirstOrDefault(row => string.Equals(row.Id, selectedSessionId, StringComparison.OrdinalIgnoreCase))
            : Sessions.FirstOrDefault();

        SelectedProcess = !string.IsNullOrWhiteSpace(selectedProcessKey)
            ? Processes.FirstOrDefault(row => string.Equals(row.IdentityKey, selectedProcessKey, StringComparison.OrdinalIgnoreCase))
            : Processes.FirstOrDefault();

        SelectedHost = !string.IsNullOrWhiteSpace(selectedHostIp)
            ? Hosts.FirstOrDefault(row => string.Equals(row.Ip, selectedHostIp, StringComparison.OrdinalIgnoreCase))
            : Hosts.FirstOrDefault();

        SessionsView.Refresh();
        ProcessesView.Refresh();
        HostsView.Refresh();
        UpdateSummaryCounts();
    }

    private static IReadOnlyList<TrafficHistorySessionRow> BuildSessionRows(IReadOnlyList<TrafficHistorySessionRecord> sessions)
    {
        return sessions.Select(static session =>
        {
            DateTime startedLocal = (session.StartedAtUtc ?? session.RecordedAtUtc).ToLocalTime();
            DateTime endedLocal = (session.EndedAtUtc ?? session.StartedAtUtc ?? session.RecordedAtUtc).ToLocalTime();
            TimeSpan duration = endedLocal >= startedLocal ? endedLocal - startedLocal : TimeSpan.Zero;

            var newHostDetails = session.NewHosts
                .Take(12)
                .Select(static host => new TrafficHistoryDetailRow
                {
                    Title = host,
                    Subtitle = "First observed in this session.",
                    BadgeText = "NEW"
                })
                .ToArray();

            var newProcessDetails = session.NewProcesses
                .Take(12)
                .Select(static process => new TrafficHistoryDetailRow
                {
                    Title = process,
                    Subtitle = "First observed in this session.",
                    BadgeText = "NEW"
                })
                .ToArray();

            var topProcesses = session.Processes
                .OrderByDescending(static process => process.TotalBytes)
                .Take(8)
                .Select(static process => new TrafficHistoryDetailRow
                {
                    Title = process.ProcessName,
                    Subtitle = $"{FormatBytes(process.TotalBytes)} | {process.PacketCount:N0} pkt | {FormatOrDefault(process.TopRemoteEndpoint, "No top remote")}",
                    BadgeText = process.RiskScore > 0 ? $"{process.RiskScore}" : "PROC"
                })
                .ToArray();

            var topHosts = session.Hosts
                .OrderByDescending(static host => host.Bytes)
                .Take(8)
                .Select(static host => new TrafficHistoryDetailRow
                {
                    Title = string.IsNullOrWhiteSpace(host.DisplayHost) ? host.Ip : host.DisplayHost,
                    Subtitle = $"{host.Ip} | {FormatBytes(host.Bytes)} | {host.Packets:N0} pkt",
                    BadgeText = string.IsNullOrWhiteSpace(host.Scope) ? "HOST" : host.Scope
                })
                .ToArray();

            return new TrafficHistorySessionRow
            {
                Id = session.Id,
                SessionLabel = startedLocal.ToString("yyyy-MM-dd HH:mm"),
                SourceLabel = string.Equals(session.SourceKind, "live", StringComparison.OrdinalIgnoreCase) ? "Live capture" : session.SourceKind,
                DeviceName = FormatOrDefault(session.DeviceName, "Unknown device"),
                BpfFilter = session.BpfFilter,
                SortTimestamp = startedLocal,
                StartedLabel = startedLocal.ToString("yyyy-MM-dd HH:mm:ss"),
                EndedLabel = endedLocal.ToString("yyyy-MM-dd HH:mm:ss"),
                DurationLabel = duration == TimeSpan.Zero ? "-" : duration.ToString(@"hh\:mm\:ss"),
                TotalPackets = session.TotalPackets,
                TotalPacketsLabel = $"{session.TotalPackets:N0} packets",
                TotalBytes = session.TotalBytes,
                TotalBytesLabel = FormatBytes(session.TotalBytes),
                NewHostsSummary = SummarizeValues(session.NewHosts, "No new public hosts"),
                NewProcessesSummary = SummarizeValues(session.NewProcesses, "No new processes"),
                SearchText = string.Join(" | ", new[]
                {
                    session.DeviceName,
                    session.BpfFilter,
                    startedLocal.ToString("yyyy-MM-dd HH:mm:ss"),
                    string.Join(", ", session.NewHosts),
                    string.Join(", ", session.NewProcesses),
                    string.Join(", ", session.Processes.Select(static process => process.ProcessName)),
                    string.Join(", ", session.Hosts.Select(static host => string.IsNullOrWhiteSpace(host.DisplayHost) ? host.Ip : host.DisplayHost))
                }),
                NewHostDetails = newHostDetails,
                NewProcessDetails = newProcessDetails,
                TopProcessDetails = topProcesses,
                TopHostDetails = topHosts
            };
        }).ToArray();
    }

    private static IReadOnlyList<TrafficHistoryProcessRow> BuildProcessRows(IReadOnlyList<TrafficHistorySessionRecord> sessions)
    {
        var aggregates = new Dictionary<string, ProcessAggregate>(StringComparer.OrdinalIgnoreCase);

        foreach (var session in sessions)
        {
            string sessionLabel = FormatSessionLabel(session);

            foreach (var process in session.Processes)
            {
                if (!aggregates.TryGetValue(process.IdentityKey, out var aggregate))
                {
                    aggregate = new ProcessAggregate(process.IdentityKey);
                    aggregates[process.IdentityKey] = aggregate;
                }

                aggregate.Observe(process, sessionLabel);

                foreach (var host in session.Hosts)
                {
                    if (!host.ProcessNames.Any(name => string.Equals(name, process.ProcessName, StringComparison.OrdinalIgnoreCase)))
                        continue;

                    aggregate.ObserveHost(host);
                }
            }
        }

        return aggregates.Values
            .Select(static aggregate => aggregate.ToRow())
            .OrderByDescending(static row => row.SortTimestamp)
            .ThenByDescending(static row => row.TotalBytes)
            .ToArray();
    }

    private static IReadOnlyList<TrafficHistoryHostRow> BuildHostRows(IReadOnlyList<TrafficHistorySessionRecord> sessions)
    {
        var aggregates = new Dictionary<string, HostAggregate>(StringComparer.OrdinalIgnoreCase);

        foreach (var session in sessions)
        {
            string sessionLabel = FormatSessionLabel(session);

            foreach (var host in session.Hosts)
            {
                if (string.IsNullOrWhiteSpace(host.Ip))
                    continue;

                if (!aggregates.TryGetValue(host.Ip, out var aggregate))
                {
                    aggregate = new HostAggregate(host.Ip);
                    aggregates[host.Ip] = aggregate;
                }

                aggregate.Observe(host, sessionLabel);
            }
        }

        return aggregates.Values
            .Select(static aggregate => aggregate.ToRow())
            .OrderByDescending(static row => row.SortTimestamp)
            .ThenByDescending(static row => row.TotalBytes)
            .ToArray();
    }

    private bool MatchesSessionFilters(object item)
        => item is TrafficHistorySessionRow row && MatchesText(row.SearchText, SessionSearchText);

    private bool MatchesProcessFilters(object item)
        => item is TrafficHistoryProcessRow row && MatchesText(row.SearchText, ProcessSearchText);

    private bool MatchesHostFilters(object item)
        => item is TrafficHistoryHostRow row && MatchesText(row.SearchText, HostSearchText);

    private static bool MatchesText(string searchText, string needle)
        => string.IsNullOrWhiteSpace(needle) || searchText.IndexOf(needle.Trim(), StringComparison.OrdinalIgnoreCase) >= 0;

    private void UpdateSummaryCounts()
    {
        SessionCount = SessionsView.Cast<object>().Count();
        ProcessCount = ProcessesView.Cast<object>().Count();
        HostCount = HostsView.Cast<object>().Count();
    }

    private static string FormatSessionLabel(TrafficHistorySessionRecord session)
    {
        DateTime startedLocal = (session.StartedAtUtc ?? session.RecordedAtUtc).ToLocalTime();
        return startedLocal.ToString("yyyy-MM-dd HH:mm");
    }

    private static string SummarizeValues(IEnumerable<string> values, string emptyValue)
    {
        var list = values
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(2)
            .ToArray();

        if (list.Length == 0)
            return emptyValue;

        return string.Join(", ", list);
    }

    private static string FormatOrDefault(string? value, string emptyValue)
        => string.IsNullOrWhiteSpace(value) ? emptyValue : value.Trim();

    private static string FormatBytes(long bytes)
    {
        const double KB = 1024;
        const double MB = KB * 1024;
        const double GB = MB * 1024;

        if (bytes >= GB) return $"{bytes / GB:0.##} GB";
        if (bytes >= MB) return $"{bytes / MB:0.##} MB";
        if (bytes >= KB) return $"{bytes / KB:0.##} KB";
        return $"{bytes:N0} B";
    }

    private sealed class ProcessAggregate
    {
        private readonly HashSet<string> _sessionLabels = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, (string Title, long Bytes, DateTime SeenUtc)> _hosts = new(StringComparer.OrdinalIgnoreCase);
        private readonly List<TrafficHistoryDetailRow> _appearances = new();

        public ProcessAggregate(string identityKey)
        {
            IdentityKey = identityKey;
        }

        public string IdentityKey { get; }
        public string DisplayName { get; private set; } = "";
        public string ExePath { get; private set; } = "";
        public string Publisher { get; private set; } = "";
        public bool IsSigned { get; private set; }
        public DateTime FirstSeenLocal { get; private set; }
        public DateTime LastSeenLocal { get; private set; }
        public long TotalPackets { get; private set; }
        public long TotalBytes { get; private set; }
        public string TopRemoteEndpoint { get; private set; } = "";
        public int MaxRiskScore { get; private set; }
        public string RiskSummary { get; private set; } = "";
        private long _topRemoteBytes;

        public void Observe(TrafficHistoryProcessRecord process, string sessionLabel)
        {
            DisplayName = string.IsNullOrWhiteSpace(DisplayName) ? process.ProcessName : DisplayName;
            ExePath = string.IsNullOrWhiteSpace(ExePath) ? process.ExePath : ExePath;
            Publisher = string.IsNullOrWhiteSpace(Publisher) ? process.Publisher : Publisher;
            IsSigned = IsSigned || process.IsSigned;

            DateTime firstSeenLocal = (process.FirstSeenUtc ?? process.LastSeenUtc ?? DateTime.UtcNow).ToLocalTime();
            DateTime lastSeenLocal = (process.LastSeenUtc ?? process.FirstSeenUtc ?? DateTime.UtcNow).ToLocalTime();

            if (FirstSeenLocal == default || firstSeenLocal < FirstSeenLocal)
                FirstSeenLocal = firstSeenLocal;

            if (lastSeenLocal > LastSeenLocal)
                LastSeenLocal = lastSeenLocal;

            TotalPackets += process.PacketCount;
            TotalBytes += process.TotalBytes;
            _sessionLabels.Add(sessionLabel);

            if (!string.IsNullOrWhiteSpace(process.TopRemoteEndpoint) && (string.IsNullOrWhiteSpace(TopRemoteEndpoint) || process.TotalBytes >= _topRemoteBytes))
            {
                TopRemoteEndpoint = process.TopRemoteEndpoint;
                _topRemoteBytes = process.TotalBytes;
            }

            if (process.RiskScore >= MaxRiskScore)
            {
                MaxRiskScore = process.RiskScore;
                RiskSummary = BuildRiskSummary(process);
            }

            _appearances.Add(new TrafficHistoryDetailRow
            {
                Title = sessionLabel,
                Subtitle = $"{FormatBytes(process.TotalBytes)} | {process.PacketCount:N0} pkt | {FormatOrDefault(process.TopRemoteEndpoint, "No top remote")} | Risk {process.RiskScore}",
                BadgeText = "SEEN"
            });
        }

        public void ObserveHost(TrafficHistoryHostRecord host)
        {
            string title = string.IsNullOrWhiteSpace(host.DisplayHost) ? host.Ip : $"{host.DisplayHost} ({host.Ip})";
            DateTime seenUtc = host.LastSeenUtc ?? host.FirstSeenUtc ?? DateTime.UtcNow;

            if (_hosts.TryGetValue(host.Ip, out var existing))
            {
                _hosts[host.Ip] = (existing.Title, existing.Bytes + host.Bytes, seenUtc > existing.SeenUtc ? seenUtc : existing.SeenUtc);
                return;
            }

            _hosts[host.Ip] = (title, host.Bytes, seenUtc);
        }

        public TrafficHistoryProcessRow ToRow()
        {
            var knownHosts = _hosts.Values
                .OrderByDescending(static host => host.Bytes)
                .ThenByDescending(static host => host.SeenUtc)
                .Take(10)
                .Select(static host => new TrafficHistoryDetailRow
                {
                    Title = host.Title,
                    Subtitle = $"{FormatBytes(host.Bytes)} | Last {host.SeenUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}",
                    BadgeText = "HOST"
                })
                .ToArray();

            _appearances.Sort(static (left, right) => string.Compare(right.Title, left.Title, StringComparison.OrdinalIgnoreCase));

            string searchText = string.Join(" | ", new[]
            {
                DisplayName,
                ExePath,
                Publisher,
                TopRemoteEndpoint,
                RiskSummary,
                string.Join(", ", knownHosts.Select(static host => host.Title)),
                string.Join(", ", _appearances.Select(static item => item.Title))
            });

            return new TrafficHistoryProcessRow
            {
                IdentityKey = IdentityKey,
                DisplayName = DisplayName,
                ExePath = ExePath,
                Publisher = Publisher,
                SignatureLabel = IsSigned ? "Signed" : "Unsigned",
                SortTimestamp = LastSeenLocal,
                FirstSeenLabel = FirstSeenLocal == default ? "-" : FirstSeenLocal.ToString("yyyy-MM-dd HH:mm:ss"),
                LastSeenLabel = LastSeenLocal == default ? "-" : LastSeenLocal.ToString("yyyy-MM-dd HH:mm:ss"),
                SessionsCount = _sessionLabels.Count,
                TotalPackets = TotalPackets,
                TotalPacketsLabel = $"{TotalPackets:N0} packets",
                TotalBytes = TotalBytes,
                TotalBytesLabel = FormatBytes(TotalBytes),
                TopRemoteEndpoint = TopRemoteEndpoint,
                RiskSummary = string.IsNullOrWhiteSpace(RiskSummary) ? "No major risk signals captured in history." : RiskSummary,
                SearchText = searchText,
                SessionAppearances = _appearances.ToArray(),
                KnownHosts = knownHosts
            };
        }

        private static string BuildRiskSummary(TrafficHistoryProcessRecord process)
        {
            string summary = FormatOrDefault(process.DetectionSummaryLabel, "");
            if (string.IsNullOrWhiteSpace(summary))
                summary = FormatOrDefault(process.TlsDnsSummaryLabel, "");
            if (string.IsNullOrWhiteSpace(summary))
                summary = FormatOrDefault(process.BehaviorDeviationSummaryLabel, "");
            if (string.IsNullOrWhiteSpace(summary))
                summary = process.HasSuspiciousDomain ? "Suspicious domain activity observed." : "";

            return string.IsNullOrWhiteSpace(summary)
                ? $"Historical max risk score: {process.RiskScore}."
                : $"{summary} (max historical risk {process.RiskScore}).";
        }
    }

    private sealed class HostAggregate
    {
        private readonly HashSet<string> _sessionLabels = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, long> _processNames = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, DateTime> _dnsNames = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, DateTime> _tlsNames = new(StringComparer.OrdinalIgnoreCase);
        private readonly List<TrafficHistoryDetailRow> _appearances = new();

        public HostAggregate(string ip)
        {
            Ip = ip;
        }

        public string Ip { get; }
        public string DisplayHost { get; private set; } = "";
        public string Scope { get; private set; } = "";
        public DateTime FirstSeenLocal { get; private set; }
        public DateTime LastSeenLocal { get; private set; }
        public long TotalPackets { get; private set; }
        public long TotalBytes { get; private set; }
        private long _topHostBytes;

        public void Observe(TrafficHistoryHostRecord host, string sessionLabel)
        {
            if (string.IsNullOrWhiteSpace(DisplayHost) || host.Bytes >= _topHostBytes)
            {
                DisplayHost = string.IsNullOrWhiteSpace(host.DisplayHost) ? host.Ip : host.DisplayHost;
                _topHostBytes = host.Bytes;
            }

            if (string.IsNullOrWhiteSpace(Scope))
                Scope = host.Scope;

            DateTime firstSeenLocal = (host.FirstSeenUtc ?? host.LastSeenUtc ?? DateTime.UtcNow).ToLocalTime();
            DateTime lastSeenLocal = (host.LastSeenUtc ?? host.FirstSeenUtc ?? DateTime.UtcNow).ToLocalTime();

            if (FirstSeenLocal == default || firstSeenLocal < FirstSeenLocal)
                FirstSeenLocal = firstSeenLocal;

            if (lastSeenLocal > LastSeenLocal)
                LastSeenLocal = lastSeenLocal;

            TotalPackets += host.Packets;
            TotalBytes += host.Bytes;
            _sessionLabels.Add(sessionLabel);

            foreach (var processName in host.ProcessNames)
            {
                _processNames.TryGetValue(processName, out long count);
                _processNames[processName] = count + host.Bytes;
            }

            foreach (var dns in host.DnsNames)
                _dnsNames[dns] = host.LastSeenUtc ?? host.FirstSeenUtc ?? DateTime.UtcNow;

            foreach (var tls in host.TlsNames.Concat(host.CertificateNames).Concat(host.ResolutionHints))
                _tlsNames[tls] = host.LastSeenUtc ?? host.FirstSeenUtc ?? DateTime.UtcNow;

            _appearances.Add(new TrafficHistoryDetailRow
            {
                Title = sessionLabel,
                Subtitle = $"{FormatBytes(host.Bytes)} | {host.Packets:N0} pkt | {host.Scope}",
                BadgeText = "SEEN"
            });
        }

        public TrafficHistoryHostRow ToRow()
        {
            var processDetails = _processNames
                .OrderByDescending(static item => item.Value)
                .Take(10)
                .Select(static item => new TrafficHistoryDetailRow
                {
                    Title = item.Key,
                    Subtitle = $"{FormatBytes(item.Value)} observed with this host across history.",
                    BadgeText = "PROC"
                })
                .ToArray();

            var dnsDetails = _dnsNames
                .OrderByDescending(static item => item.Value)
                .Take(10)
                .Select(static item => new TrafficHistoryDetailRow
                {
                    Title = item.Key,
                    Subtitle = $"Last seen {item.Value.ToLocalTime():yyyy-MM-dd HH:mm:ss}",
                    BadgeText = "DNS"
                })
                .ToArray();

            var tlsDetails = _tlsNames
                .OrderByDescending(static item => item.Value)
                .Take(10)
                .Select(static item => new TrafficHistoryDetailRow
                {
                    Title = item.Key,
                    Subtitle = $"Last seen {item.Value.ToLocalTime():yyyy-MM-dd HH:mm:ss}",
                    BadgeText = "TLS"
                })
                .ToArray();

            _appearances.Sort(static (left, right) => string.Compare(right.Title, left.Title, StringComparison.OrdinalIgnoreCase));

            string processSummary = SummarizeValues(_processNames.Keys, "No processes");
            string dnsSummary = SummarizeValues(_dnsNames.Keys, "No DNS names");
            string tlsSummary = SummarizeValues(_tlsNames.Keys, "No TLS names");

            string searchText = string.Join(" | ", new[]
            {
                Ip,
                DisplayHost,
                Scope,
                processSummary,
                dnsSummary,
                tlsSummary,
                string.Join(", ", _appearances.Select(static item => item.Title))
            });

            return new TrafficHistoryHostRow
            {
                Ip = Ip,
                DisplayHost = DisplayHost,
                Scope = Scope,
                SortTimestamp = LastSeenLocal,
                FirstSeenLabel = FirstSeenLocal == default ? "-" : FirstSeenLocal.ToString("yyyy-MM-dd HH:mm:ss"),
                LastSeenLabel = LastSeenLocal == default ? "-" : LastSeenLocal.ToString("yyyy-MM-dd HH:mm:ss"),
                SessionsCount = _sessionLabels.Count,
                ProcessCount = _processNames.Count,
                TotalPackets = TotalPackets,
                TotalPacketsLabel = $"{TotalPackets:N0} packets",
                TotalBytes = TotalBytes,
                TotalBytesLabel = FormatBytes(TotalBytes),
                ProcessSummary = processSummary,
                DnsSummary = dnsSummary,
                TlsSummary = tlsSummary,
                SearchText = searchText,
                SessionAppearances = _appearances.ToArray(),
                Processes = processDetails,
                DnsNames = dnsDetails,
                TlsNames = tlsDetails
            };
        }
    }
}
