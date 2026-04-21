using Application.Networking;
using Domain.Models;
using Presentation.Helpers;
using Presentation.Models;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Windows.Data;
using System.Windows.Input;

namespace Presentation.ViewModels;

public sealed class EndpointsViewModel : ViewModelBase
{
    private readonly HostResolutionService _hostResolutionService;
    private readonly Dictionary<string, EndpointAggregate> _aggregatesByIp = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, EndpointHostRow> _rowsByIp = new(StringComparer.OrdinalIgnoreCase);

    private Action<string>? _showPacketsForIp;
    private Action<EndpointHostRow>? _blockHost;
    private Action<EndpointHostRow>? _blockHostFor15Minutes;
    private Action<EndpointHostRow, int>? _throttleHost;
    private Action<EndpointHostRow>? _createRuleFromHost;

    public BulkObservableCollection<EndpointHostRow> Hosts { get; } = new();
    public ICollectionView HostsView { get; }

    public ICommand ShowPacketsForSelectedHostCommand { get; }
    public ICommand BlockSelectedHostCommand { get; }
    public ICommand BlockSelectedHostFor15MinutesCommand { get; }
    public ICommand ThrottleSelectedHostTo1MbpsCommand { get; }
    public ICommand ThrottleSelectedHostTo5MbpsCommand { get; }
    public ICommand ThrottleSelectedHostTo25MbpsCommand { get; }
    public ICommand CreateRuleFromSelectedHostCommand { get; }

    private string _searchText = "";
    public string SearchText
    {
        get => _searchText;
        set
        {
            if (!Set(ref _searchText, value))
                return;

            RefreshHostsView();
        }
    }

    private bool _hideLocalPrivate;
    public bool HideLocalPrivate
    {
        get => _hideLocalPrivate;
        set
        {
            if (!Set(ref _hideLocalPrivate, value))
                return;

            RefreshHostsView();
        }
    }

    private bool _hideMulticastBroadcast = true;
    public bool HideMulticastBroadcast
    {
        get => _hideMulticastBroadcast;
        set
        {
            if (!Set(ref _hideMulticastBroadcast, value))
                return;

            RefreshHostsView();
        }
    }

    private int _totalHostCount;
    public int TotalHostCount
    {
        get => _totalHostCount;
        private set => Set(ref _totalHostCount, value);
    }

    private int _visibleHostCount;
    public int VisibleHostCount
    {
        get => _visibleHostCount;
        private set => Set(ref _visibleHostCount, value);
    }

    private int _resolvedHostCount;
    public int ResolvedHostCount
    {
        get => _resolvedHostCount;
        private set => Set(ref _resolvedHostCount, value);
    }

    private int _publicHostCount;
    public int PublicHostCount
    {
        get => _publicHostCount;
        private set => Set(ref _publicHostCount, value);
    }

    private EndpointHostRow? _selectedEndpoint;
    public EndpointHostRow? SelectedEndpoint
    {
        get => _selectedEndpoint;
        set
        {
            if (!Set(ref _selectedEndpoint, value))
                return;

            OnPropertyChanged(nameof(HasSelectedEndpoint));
            (ShowPacketsForSelectedHostCommand as RelayCommand)?.RaiseCanExecuteChanged();
            (BlockSelectedHostCommand as RelayCommand)?.RaiseCanExecuteChanged();
            (BlockSelectedHostFor15MinutesCommand as RelayCommand)?.RaiseCanExecuteChanged();
            (ThrottleSelectedHostTo1MbpsCommand as RelayCommand)?.RaiseCanExecuteChanged();
            (ThrottleSelectedHostTo5MbpsCommand as RelayCommand)?.RaiseCanExecuteChanged();
            (ThrottleSelectedHostTo25MbpsCommand as RelayCommand)?.RaiseCanExecuteChanged();
            (CreateRuleFromSelectedHostCommand as RelayCommand)?.RaiseCanExecuteChanged();
            OnPropertyChanged(nameof(CanManageSelectedEndpoint));
        }
    }

    public bool HasSelectedEndpoint => SelectedEndpoint is not null;
    public bool CanManageSelectedEndpoint => ResolveManageableHost(null) is not null;

    public EndpointsViewModel(HostResolutionService hostResolutionService)
    {
        _hostResolutionService = hostResolutionService;

        ShowPacketsForSelectedHostCommand = new RelayCommand(
            parameter => ShowPacketsForHost(parameter),
            parameter => ResolveTargetHost(parameter) is not null);
        BlockSelectedHostCommand = new RelayCommand(
            parameter => BlockHost(parameter),
            parameter => ResolveManageableHost(parameter) is not null);
        BlockSelectedHostFor15MinutesCommand = new RelayCommand(
            parameter => BlockHostFor15Minutes(parameter),
            parameter => ResolveManageableHost(parameter) is not null);
        ThrottleSelectedHostTo1MbpsCommand = new RelayCommand(
            parameter => ThrottleHost(parameter, 1),
            parameter => ResolveManageableHost(parameter) is not null);
        ThrottleSelectedHostTo5MbpsCommand = new RelayCommand(
            parameter => ThrottleHost(parameter, 5),
            parameter => ResolveManageableHost(parameter) is not null);
        ThrottleSelectedHostTo25MbpsCommand = new RelayCommand(
            parameter => ThrottleHost(parameter, 25),
            parameter => ResolveManageableHost(parameter) is not null);
        CreateRuleFromSelectedHostCommand = new RelayCommand(
            parameter => CreateRuleFromHost(parameter),
            parameter => ResolveManageableHost(parameter) is not null);

        HostsView = CollectionViewSource.GetDefaultView(Hosts);
        HostsView.Filter = MatchesCurrentFilters;
        HostsView.SortDescriptions.Add(new SortDescription(nameof(EndpointHostRow.Bytes), ListSortDirection.Descending));
        HostsView.SortDescriptions.Add(new SortDescription(nameof(EndpointHostRow.LastSeen), ListSortDirection.Descending));
        HostsView.SortDescriptions.Add(new SortDescription(nameof(EndpointHostRow.DisplayHost), ListSortDirection.Ascending));

        UpdateSummaryCounts();
    }

    public void ConfigureActions(
        Action<string> showPacketsForIp,
        Action<EndpointHostRow> blockHost,
        Action<EndpointHostRow> blockHostFor15Minutes,
        Action<EndpointHostRow, int> throttleHost,
        Action<EndpointHostRow> createRuleFromHost)
    {
        _showPacketsForIp = showPacketsForIp;
        _blockHost = blockHost;
        _blockHostFor15Minutes = blockHostFor15Minutes;
        _throttleHost = throttleHost;
        _createRuleFromHost = createRuleFromHost;
    }

    public void Reset()
    {
        _aggregatesByIp.Clear();
        _rowsByIp.Clear();
        Hosts.Clear();
        SelectedEndpoint = null;
        SearchText = "";
        HideLocalPrivate = false;
        HideMulticastBroadcast = true;
        UpdateSummaryCounts();
    }

    public void ObservePackets(IReadOnlyList<PacketInfo> packets)
    {
        if (packets is null || packets.Count == 0)
            return;

        var touchedIps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < packets.Count; i++)
        {
            ObservePacketCore(packets[i], touchedIps);
        }

        if (touchedIps.Count == 0)
            return;

        string? selectedIp = SelectedEndpoint?.Ip;
        var newRows = new List<EndpointHostRow>();

        foreach (var ip in touchedIps)
        {
            if (!_aggregatesByIp.TryGetValue(ip, out var aggregate))
                continue;

            EndpointHostSnapshot snapshot = BuildSnapshot(aggregate);

            if (!_rowsByIp.TryGetValue(ip, out var row))
            {
                row = new EndpointHostRow(ip);
                _rowsByIp[ip] = row;
                newRows.Add(row);
            }

            row.Apply(snapshot);
        }

        if (newRows.Count > 0)
            Hosts.AddRange(newRows, useReset: newRows.Count >= 64);

        HostsView.Refresh();

        if (!string.IsNullOrWhiteSpace(selectedIp) && _rowsByIp.TryGetValue(selectedIp, out var selectedRow))
            SelectedEndpoint = selectedRow;

        UpdateSummaryCounts();
    }

    private void ObservePacketCore(PacketInfo packet, HashSet<string> touchedIps)
    {
        ObserveTraffic(packet.SrcIp, packet.SrcPort, packet, isSource: true, touchedIps);
        ObserveTraffic(packet.DstIp, packet.DstPort, packet, isSource: false, touchedIps);

        if (!string.IsNullOrWhiteSpace(packet.DnsQueryName) && packet.DnsAnswerIps.Count > 0)
        {
            for (int i = 0; i < packet.DnsAnswerIps.Count; i++)
            {
                string answerIp = NormalizeIp(packet.DnsAnswerIps[i]);
                if (string.IsNullOrWhiteSpace(answerIp))
                    continue;

                GetOrCreateAggregate(answerIp).ObserveDns(packet.DnsQueryName, packet.Timestamp);
                touchedIps.Add(answerIp);
            }
        }

        if (!string.IsNullOrWhiteSpace(packet.DstIp) && !string.IsNullOrWhiteSpace(packet.ServerNameHint))
        {
            string dstIp = NormalizeIp(packet.DstIp);
            if (!string.IsNullOrWhiteSpace(dstIp))
            {
                GetOrCreateAggregate(dstIp).ObserveTlsName(packet.ServerNameHint, packet.Timestamp);
                touchedIps.Add(dstIp);
            }
        }

        if (!string.IsNullOrWhiteSpace(packet.DstIp))
        {
            string dstIp = NormalizeIp(packet.DstIp);
            if (!string.IsNullOrWhiteSpace(dstIp))
            {
                if (!string.IsNullOrWhiteSpace(packet.TlsCertificateSubject))
                {
                    GetOrCreateAggregate(dstIp).ObserveCertificate(packet.TlsCertificateSubject, "Subject", packet.Timestamp);
                    touchedIps.Add(dstIp);
                }

                for (int i = 0; i < packet.TlsCertificateNames.Count; i++)
                {
                    GetOrCreateAggregate(dstIp).ObserveCertificate(packet.TlsCertificateNames[i], "Name", packet.Timestamp);
                    touchedIps.Add(dstIp);
                }
            }
        }
    }

    private void ObserveTraffic(string ip, int? port, PacketInfo packet, bool isSource, HashSet<string> touchedIps)
    {
        string normalizedIp = NormalizeIp(ip);
        if (string.IsNullOrWhiteSpace(normalizedIp))
            return;

        var aggregate = GetOrCreateAggregate(normalizedIp);
        aggregate.ObserveTraffic(packet, port, isSource);
        touchedIps.Add(normalizedIp);
    }

    private EndpointAggregate GetOrCreateAggregate(string ip)
    {
        if (_aggregatesByIp.TryGetValue(ip, out var aggregate))
            return aggregate;

        aggregate = new EndpointAggregate(ip);
        _aggregatesByIp[ip] = aggregate;
        return aggregate;
    }

    private EndpointHostSnapshot BuildSnapshot(EndpointAggregate aggregate)
    {
        IpMetadata metadata = IpMetadataClassifier.Classify(aggregate.Ip);
        var resolutionHints = _hostResolutionService.GetHints(aggregate.Ip, take: 6);

        string hostname = resolutionHints.Count > 0
            ? resolutionHints[0].Host
            : aggregate.GetFallbackDisplayName();

        string displayHost = string.IsNullOrWhiteSpace(hostname) ? aggregate.Ip : hostname;
        string hostSourceSummary = resolutionHints.Count > 0
            ? $"{resolutionHints[0].SourceLabel} | {resolutionHints[0].ConfidenceLabel} confidence"
            : string.IsNullOrWhiteSpace(hostname)
                ? "No hostname hints observed yet."
                : "Observed from packet metadata.";

        EndpointDetailRow[] hintRows = resolutionHints
            .Select(static hint => new EndpointDetailRow
            {
                Title = hint.Host,
                Subtitle = $"{hint.SourceLabel} | {hint.ConfidenceLabel} confidence | {hint.ObservationCount:N0} obs | Last {hint.LastSeenUtc.ToLocalTime():HH:mm:ss}",
                BadgeText = hint.ConfidenceLabel
            })
            .ToArray();

        EndpointDetailRow[] processRows = aggregate.Processes.Values
            .OrderByDescending(static process => process.Bytes)
            .ThenByDescending(static process => process.Packets)
            .ThenBy(static process => process.ProcessName, StringComparer.OrdinalIgnoreCase)
            .Take(12)
            .Select(static process => new EndpointDetailRow
            {
                Title = process.Pid > 0 ? $"{process.ProcessName} (PID {process.Pid})" : process.ProcessName,
                Subtitle = $"{FormatBytes(process.Bytes)} | {process.Packets:N0} pkt | First {process.FirstSeen:HH:mm:ss} | Last {process.LastSeen:HH:mm:ss}",
                BadgeText = "PROC"
            })
            .ToArray();

        EndpointDetailRow[] dnsRows = aggregate.DnsHistory.Values
            .OrderByDescending(static row => row.LastSeen)
            .ThenByDescending(static row => row.Count)
            .ThenBy(static row => row.Value, StringComparer.OrdinalIgnoreCase)
            .Take(12)
            .Select(static row => row.ToDetailRow("DNS"))
            .ToArray();

        EndpointDetailRow[] tlsRows = aggregate.TlsNames.Values
            .OrderByDescending(static row => row.LastSeen)
            .ThenByDescending(static row => row.Count)
            .ThenBy(static row => row.Value, StringComparer.OrdinalIgnoreCase)
            .Take(12)
            .Select(static row => row.ToDetailRow("TLS"))
            .ToArray();

        EndpointDetailRow[] certificateRows = aggregate.CertificateHistory.Values
            .OrderByDescending(static row => row.LastSeen)
            .ThenByDescending(static row => row.Count)
            .ThenBy(static row => row.Value, StringComparer.OrdinalIgnoreCase)
            .Take(12)
            .Select(static row => row.ToDetailRow("CERT"))
            .ToArray();

        string processesSummary = FormatSummary(
            aggregate.Processes.Values
                .OrderByDescending(static process => process.Bytes)
                .Select(static process => process.ProcessName),
            aggregate.Processes.Count,
            emptyValue: "No owning processes resolved");

        string dnsSummary = FormatSummary(
            aggregate.DnsHistory.Values
                .OrderByDescending(static value => value.LastSeen)
                .Select(static value => value.Value),
            aggregate.DnsHistory.Count,
            emptyValue: "No DNS history");

        string tlsSummary = FormatSummary(
            aggregate.TlsNames.Values
                .OrderByDescending(static value => value.LastSeen)
                .Select(static value => value.Value)
                .Concat(aggregate.CertificateHistory.Values
                    .OrderByDescending(static value => value.LastSeen)
                    .Select(static value => value.Value)),
            aggregate.TlsNames.Count + aggregate.CertificateHistory.Count,
            emptyValue: "No TLS hints");

        string portSummary = FormatSummary(
            aggregate.PortCounts
                .OrderByDescending(static port => port.Value)
                .ThenBy(static port => port.Key)
                .Select(static port => port.Key.ToString()),
            aggregate.PortCounts.Count,
            emptyValue: "No ports observed");

        string protocolSummary = FormatSummary(
            aggregate.ProtocolCounts
                .OrderByDescending(static protocol => protocol.Value)
                .ThenBy(static protocol => protocol.Key, StringComparer.OrdinalIgnoreCase)
                .Select(static protocol => protocol.Key),
            aggregate.ProtocolCounts.Count,
            emptyValue: "No protocols observed");

        string searchText = string.Join(" | ", new[]
        {
            aggregate.Ip,
            displayHost,
            metadata.Scope,
            processesSummary,
            dnsSummary,
            tlsSummary,
            portSummary,
            protocolSummary
        }.Where(static value => !string.IsNullOrWhiteSpace(value)));

        return new EndpointHostSnapshot
        {
            DisplayHost = displayHost,
            Hostname = hostname,
            Country = metadata.Country,
            Asn = metadata.Asn,
            Scope = metadata.Scope,
            IsLocalPrivate = metadata.IsLocalPrivate,
            IsMulticastBroadcast = metadata.IsMulticastBroadcast,
            Packets = aggregate.Packets,
            Bytes = aggregate.Bytes,
            SentBytes = aggregate.SentBytes,
            RecvBytes = aggregate.RecvBytes,
            FirstSeen = aggregate.FirstSeen,
            LastSeen = aggregate.LastSeen,
            ProcessCount = aggregate.Processes.Count,
            ResolutionHintCount = resolutionHints.Count,
            DnsHistoryCount = aggregate.DnsHistory.Count,
            TlsHistoryCount = aggregate.TlsNames.Count,
            CertificateHistoryCount = aggregate.CertificateHistory.Count,
            PacketsLabel = $"{aggregate.Packets:N0} packets",
            BytesLabel = FormatBytes(aggregate.Bytes),
            SentRecvLabel = $"Sent {FormatBytes(aggregate.SentBytes)} | Recv {FormatBytes(aggregate.RecvBytes)}",
            FirstSeenLabel = aggregate.FirstSeen == default ? "-" : aggregate.FirstSeen.ToString("yyyy-MM-dd HH:mm:ss"),
            LastSeenLabel = aggregate.LastSeen == default ? "-" : aggregate.LastSeen.ToString("yyyy-MM-dd HH:mm:ss"),
            ProcessesSummary = processesSummary,
            DnsSummary = dnsSummary,
            TlsSummary = tlsSummary,
            PortSummary = portSummary,
            ProtocolSummary = protocolSummary,
            HostnameSourceSummary = hostSourceSummary,
            SearchText = searchText,
            ResolutionHints = hintRows,
            OwningProcesses = processRows,
            DnsHistory = dnsRows,
            TlsHistory = tlsRows,
            CertificateHistory = certificateRows
        };
    }

    private bool MatchesCurrentFilters(object item)
    {
        if (item is not EndpointHostRow row)
            return false;

        if (HideLocalPrivate && row.IsLocalPrivate)
            return false;

        if (HideMulticastBroadcast && row.IsMulticastBroadcast)
            return false;

        string search = SearchText?.Trim() ?? "";
        if (string.IsNullOrWhiteSpace(search))
            return true;

        return row.SearchText.IndexOf(search, StringComparison.OrdinalIgnoreCase) >= 0;
    }

    private void RefreshHostsView()
    {
        HostsView.Refresh();
        UpdateSummaryCounts();
    }

    private void UpdateSummaryCounts()
    {
        TotalHostCount = _rowsByIp.Count;
        ResolvedHostCount = _rowsByIp.Values.Count(static row => row.HasHostname);
        PublicHostCount = _rowsByIp.Values.Count(static row => string.Equals(row.Scope, "Public", StringComparison.OrdinalIgnoreCase));
        VisibleHostCount = HostsView.Cast<object>().Count();
    }

    private void ShowPacketsForHost(object? parameter)
    {
        string? ip = ResolveTargetHost(parameter);
        if (string.IsNullOrWhiteSpace(ip))
            return;

        _showPacketsForIp?.Invoke(ip);
    }

    private void BlockHost(object? parameter)
    {
        var row = ResolveManageableHost(parameter);
        if (row is null)
            return;

        _blockHost?.Invoke(row);
    }

    private void BlockHostFor15Minutes(object? parameter)
    {
        var row = ResolveManageableHost(parameter);
        if (row is null)
            return;

        _blockHostFor15Minutes?.Invoke(row);
    }

    private void ThrottleHost(object? parameter, int throttleMbps)
    {
        var row = ResolveManageableHost(parameter);
        if (row is null)
            return;

        _throttleHost?.Invoke(row, throttleMbps);
    }

    private void CreateRuleFromHost(object? parameter)
    {
        var row = ResolveManageableHost(parameter);
        if (row is null)
            return;

        _createRuleFromHost?.Invoke(row);
    }

    private string? ResolveTargetHost(object? parameter)
        => parameter switch
        {
            EndpointHostRow row when !string.IsNullOrWhiteSpace(row.Ip) => row.Ip,
            string ip when !string.IsNullOrWhiteSpace(ip) => ip.Trim(),
            _ => SelectedEndpoint?.Ip
        };

    private EndpointHostRow? ResolveManageableHost(object? parameter)
    {
        EndpointHostRow? row = parameter as EndpointHostRow ?? SelectedEndpoint;
        if (row is null || string.IsNullOrWhiteSpace(row.Ip))
            return null;

        return !row.IsMulticastBroadcast && IPAddress.TryParse(row.Ip, out _)
            ? row
            : null;
    }

    private static string NormalizeIp(string? ip)
        => string.IsNullOrWhiteSpace(ip) ? "" : ip.Trim();

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

    private static string FormatSummary(IEnumerable<string> values, int totalCount, string emptyValue)
    {
        var topValues = values
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(2)
            .ToArray();

        if (topValues.Length == 0)
            return emptyValue;

        if (totalCount > topValues.Length)
            return $"{string.Join(", ", topValues)} +{totalCount - topValues.Length}";

        return string.Join(", ", topValues);
    }

    private sealed class EndpointAggregate
    {
        public EndpointAggregate(string ip)
        {
            Ip = ip;
        }

        public string Ip { get; }
        public long Packets { get; private set; }
        public long Bytes { get; private set; }
        public long SentBytes { get; private set; }
        public long RecvBytes { get; private set; }
        public DateTime FirstSeen { get; private set; }
        public DateTime LastSeen { get; private set; }

        public Dictionary<EndpointProcessKey, EndpointProcessAggregate> Processes { get; } = new();
        public Dictionary<string, ObservationAggregate> DnsHistory { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, ObservationAggregate> TlsNames { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, ObservationAggregate> CertificateHistory { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, int> ProtocolCounts { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<int, int> PortCounts { get; } = new();

        public void ObserveTraffic(PacketInfo packet, int? port, bool isSource)
        {
            Packets++;
            Bytes += packet.Length;

            if (isSource)
                SentBytes += packet.Length;
            else
                RecvBytes += packet.Length;

            if (FirstSeen == default || packet.Timestamp < FirstSeen)
                FirstSeen = packet.Timestamp;

            if (packet.Timestamp > LastSeen)
                LastSeen = packet.Timestamp;

            string protocol = string.IsNullOrWhiteSpace(packet.Protocol)
                ? packet.TransportProtocol
                : packet.Protocol;
            protocol = string.IsNullOrWhiteSpace(protocol) ? "Unknown" : protocol.Trim();

            ProtocolCounts.TryGetValue(protocol, out int protocolCount);
            ProtocolCounts[protocol] = protocolCount + 1;

            if (port is int portValue && portValue > 0)
            {
                PortCounts.TryGetValue(portValue, out int portCount);
                PortCounts[portValue] = portCount + 1;
            }

            if (packet.Pid is int pid && pid > 0 || !string.IsNullOrWhiteSpace(packet.ProcessName))
            {
                string processName = string.IsNullOrWhiteSpace(packet.ProcessName)
                    ? $"PID {packet.Pid}"
                    : packet.ProcessName.Trim();

                var key = new EndpointProcessKey(packet.Pid ?? 0, processName);
                if (!Processes.TryGetValue(key, out var aggregate))
                {
                    aggregate = new EndpointProcessAggregate(key.Pid, processName, packet.Timestamp);
                    Processes[key] = aggregate;
                }

                aggregate.Observe(packet.Length, packet.Timestamp);
            }
        }

        public void ObserveDns(string domain, DateTime timestamp)
            => ObserveNamedValue(DnsHistory, domain, "DNS answer", timestamp);

        public void ObserveTlsName(string host, DateTime timestamp)
            => ObserveNamedValue(TlsNames, host, "TLS SNI", timestamp);

        public void ObserveCertificate(string value, string kind, DateTime timestamp)
            => ObserveNamedValue(CertificateHistory, value, $"Certificate {kind}", timestamp);

        public string GetFallbackDisplayName()
        {
            return DnsHistory.Values
                .OrderByDescending(static value => value.LastSeen)
                .ThenByDescending(static value => value.Count)
                .Select(static value => value.Value)
                .Concat(TlsNames.Values
                    .OrderByDescending(static value => value.LastSeen)
                    .ThenByDescending(static value => value.Count)
                    .Select(static value => value.Value))
                .Concat(CertificateHistory.Values
                    .OrderByDescending(static value => value.LastSeen)
                    .ThenByDescending(static value => value.Count)
                    .Select(static value => value.Value))
                .FirstOrDefault()
                ?? "";
        }

        private static void ObserveNamedValue(
            Dictionary<string, ObservationAggregate> target,
            string value,
            string sourceLabel,
            DateTime timestamp)
        {
            string normalizedValue = string.IsNullOrWhiteSpace(value) ? "" : value.Trim();
            if (string.IsNullOrWhiteSpace(normalizedValue))
                return;

            if (!target.TryGetValue(normalizedValue, out var aggregate))
            {
                aggregate = new ObservationAggregate(normalizedValue, sourceLabel);
                target[normalizedValue] = aggregate;
            }

            aggregate.Observe(timestamp);
        }
    }

    private readonly record struct EndpointProcessKey(int Pid, string ProcessName);

    private sealed class EndpointProcessAggregate
    {
        public EndpointProcessAggregate(int pid, string processName, DateTime firstSeen)
        {
            Pid = pid;
            ProcessName = processName;
            FirstSeen = firstSeen;
            LastSeen = firstSeen;
        }

        public int Pid { get; }
        public string ProcessName { get; }
        public long Bytes { get; private set; }
        public long Packets { get; private set; }
        public DateTime FirstSeen { get; }
        public DateTime LastSeen { get; private set; }

        public void Observe(int length, DateTime timestamp)
        {
            Bytes += length;
            Packets++;
            if (timestamp > LastSeen)
                LastSeen = timestamp;
        }
    }

    private sealed class ObservationAggregate
    {
        public ObservationAggregate(string value, string sourceLabel)
        {
            Value = value;
            SourceLabel = sourceLabel;
        }

        public string Value { get; }
        public string SourceLabel { get; }
        public int Count { get; private set; }
        public DateTime LastSeen { get; private set; }

        public void Observe(DateTime timestamp)
        {
            Count++;
            if (timestamp > LastSeen)
                LastSeen = timestamp;
        }

        public EndpointDetailRow ToDetailRow(string badgeText)
            => new()
            {
                Title = Value,
                Subtitle = $"{SourceLabel} | {Count:N0} obs | Last {LastSeen:HH:mm:ss}",
                BadgeText = badgeText
            };
    }

    private readonly record struct IpMetadata(
        string Country,
        string Asn,
        string Scope,
        bool IsLocalPrivate,
        bool IsMulticastBroadcast);

    private static class IpMetadataClassifier
    {
        public static IpMetadata Classify(string ip)
        {
            if (!IPAddress.TryParse(ip, out var address))
            {
                return new IpMetadata(
                    Country: "Unknown",
                    Asn: "Unknown ASN",
                    Scope: "Unknown",
                    IsLocalPrivate: false,
                    IsMulticastBroadcast: false);
            }

            if (address.AddressFamily == AddressFamily.InterNetwork)
                return ClassifyIpv4(address);

            if (address.AddressFamily == AddressFamily.InterNetworkV6)
                return ClassifyIpv6(address);

            return new IpMetadata(
                Country: "Unknown",
                Asn: "Unknown ASN",
                Scope: "Unknown",
                IsLocalPrivate: false,
                IsMulticastBroadcast: false);
        }

        private static IpMetadata ClassifyIpv4(IPAddress address)
        {
            byte[] bytes = address.GetAddressBytes();
            string ip = address.ToString();

            if (ip == "255.255.255.255")
                return Reserved("Broadcast", isMulticastBroadcast: true);

            if (bytes[0] == 127)
                return Local("Loopback", "Local host");

            if (bytes[0] == 10
                || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                || (bytes[0] == 192 && bytes[1] == 168))
            {
                return Local("Private", "Local network");
            }

            if (bytes[0] == 169 && bytes[1] == 254)
                return Local("Link-local", "Local network");

            if (bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127)
                return Local("Carrier-grade NAT", "Provider local");

            if (bytes[0] >= 224 && bytes[0] <= 239)
                return Reserved("Multicast", isMulticastBroadcast: true);

            if (bytes[0] >= 240 || bytes[0] == 0)
                return Reserved("Reserved");

            if ((bytes[0] == 192 && bytes[1] == 0 && bytes[2] == 2)
                || (bytes[0] == 198 && bytes[1] == 51 && bytes[2] == 100)
                || (bytes[0] == 203 && bytes[1] == 0 && bytes[2] == 113))
            {
                return Reserved("Documentation");
            }

            return new IpMetadata(
                Country: "Unknown",
                Asn: "Unknown ASN",
                Scope: "Public",
                IsLocalPrivate: false,
                IsMulticastBroadcast: false);
        }

        private static IpMetadata ClassifyIpv6(IPAddress address)
        {
            if (IPAddress.IsLoopback(address))
                return Local("Loopback", "Local host");

            if (address.IsIPv6LinkLocal)
                return Local("Link-local", "Local network");

            if (address.IsIPv6Multicast)
                return Reserved("Multicast", isMulticastBroadcast: true);

            byte[] bytes = address.GetAddressBytes();
            if ((bytes[0] & 0xFE) == 0xFC)
                return Local("Unique local", "Local network");

            if (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0D && bytes[3] == 0xB8)
                return Reserved("Documentation");

            if (address.Equals(IPAddress.IPv6Any))
                return Reserved("Unspecified");

            return new IpMetadata(
                Country: "Unknown",
                Asn: "Unknown ASN",
                Scope: "Public",
                IsLocalPrivate: false,
                IsMulticastBroadcast: false);
        }

        private static IpMetadata Local(string scope, string country)
            => new(
                Country: country,
                Asn: "Local / RFC",
                Scope: scope,
                IsLocalPrivate: true,
                IsMulticastBroadcast: false);

        private static IpMetadata Reserved(string scope, bool isMulticastBroadcast = false)
            => new(
                Country: "Reserved",
                Asn: "Reserved / RFC",
                Scope: scope,
                IsLocalPrivate: false,
                IsMulticastBroadcast: isMulticastBroadcast);
    }
}
