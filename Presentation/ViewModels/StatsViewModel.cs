using Application.Capture;
using Application.Networking;
using Domain.Models;
using Presentation.Models;
using System.Collections.ObjectModel;
using System.Net;
using System.Net.Sockets;

namespace Presentation.ViewModels;

public sealed class StatsViewModel : ViewModelBase
{
    private static readonly TimeSpan ActiveTopListsRefreshInterval = TimeSpan.FromMilliseconds(1500);
    private const int MaxTopProcesses = 40;
    private const int MaxTopHosts = 40;
    private const int MaxTopTrafficTypes = 24;
    private const int MaxTopConversations = 40;
    private const int MaxTopConversationsPerProcess = 8;

    private readonly ProcessPacketsViewModel _processPackets;
    private readonly HostResolutionService _hostResolutionService;

    private static readonly IReadOnlyDictionary<(string Transport, int Port), (string Key, string Title, string Badge)> TrafficPortMap
        = new Dictionary<(string Transport, int Port), (string Key, string Title, string Badge)>
        {
            [("TCP", 80)] = ("http", "Hypertext Transfer Protocol (HTTP)", "HTTP"),
            [("TCP", 443)] = ("https", "Hypertext Transfer Protocol over SSL/TLS (HTTPS)", "TLS"),
            [("UDP", 443)] = ("quic", "Quick UDP Internet Connections (QUIC)", "QUIC"),
            [("UDP", 53)] = ("dns", "Domain Name System (DNS)", "DNS"),
            [("TCP", 53)] = ("dns", "Domain Name System (DNS)", "DNS"),
            [("UDP", 5353)] = ("mdns", "Multicast DNS (mDNS)", "mDNS"),
            [("UDP", 1900)] = ("ssdp", "Simple Service Discovery Protocol (SSDP)", "SSDP"),
            [("UDP", 161)] = ("snmp", "Simple Network Management Protocol (SNMP)", "SNMP"),
            [("UDP", 162)] = ("snmp", "Simple Network Management Protocol (SNMP)", "SNMP"),
            [("TCP", 8080)] = ("http-alt", "HTTP Alternate", "HTTP"),
            [("TCP", 8443)] = ("https-alt", "HTTPS Alternate", "TLS"),
            [("UDP", 67)] = ("dhcp", "Dynamic Host Configuration Protocol (DHCP)", "DHCP"),
            [("UDP", 68)] = ("dhcp", "Dynamic Host Configuration Protocol (DHCP)", "DHCP"),
        };

    private IReadOnlyList<FlowInfo> _lastFlowsTop = Array.Empty<FlowInfo>();

    public ObservableCollection<ConversationTrafficRow> TopConversations { get; } = new();
    public ObservableCollection<ProcessTrafficRow> TopProcesses { get; } = new();
    public ObservableCollection<HostStatRow> TopHosts { get; } = new();
    public ObservableCollection<TrafficTypeStatRow> TopTrafficTypes { get; } = new();

    private bool _isViewActive;
    public bool IsViewActive
    {
        get => _isViewActive;
        set
        {
            if (!Set(ref _isViewActive, value))
                return;

            if (value)
                RefreshTopLists(force: true);
        }
    }

    private bool _hideMulticastBroadcast = true;
    public bool HideMulticastBroadcast
    {
        get => _hideMulticastBroadcast;
        set
        {
            if (Set(ref _hideMulticastBroadcast, value))
                RefreshTopLists(force: true);
        }
    }

    private long _summaryTotalPackets;
    public long SummaryTotalPackets { get => _summaryTotalPackets; private set => Set(ref _summaryTotalPackets, value); }

    private long _summaryTotalBytes;
    public long SummaryTotalBytes { get => _summaryTotalBytes; private set => Set(ref _summaryTotalBytes, value); }

    private int _summaryFlowsShown;
    public int SummaryFlowsShown { get => _summaryFlowsShown; private set => Set(ref _summaryFlowsShown, value); }

    private DateTime? _summaryFirstSeen;
    public DateTime? SummaryFirstSeen { get => _summaryFirstSeen; private set => Set(ref _summaryFirstSeen, value); }

    private DateTime? _summaryLastSeen;
    public DateTime? SummaryLastSeen { get => _summaryLastSeen; private set => Set(ref _summaryLastSeen, value); }

    private TimeSpan _summaryDuration;
    public TimeSpan SummaryDuration { get => _summaryDuration; private set => Set(ref _summaryDuration, value); }

    private string _summaryTotalBytesHuman = "-";
    public string SummaryTotalBytesHuman { get => _summaryTotalBytesHuman; private set => Set(ref _summaryTotalBytesHuman, value); }

    private string _summaryPacketsPerSec = "-";
    public string SummaryPacketsPerSec { get => _summaryPacketsPerSec; private set => Set(ref _summaryPacketsPerSec, value); }

    private string _summaryBytesPerSec = "-";
    public string SummaryBytesPerSec { get => _summaryBytesPerSec; private set => Set(ref _summaryBytesPerSec, value); }

    private DateTime _lastTopListsRefreshUtc = DateTime.MinValue;

    public StatsViewModel(ProcessPacketsViewModel processPackets, HostResolutionService hostResolutionService)
    {
        _processPackets = processPackets;
        _hostResolutionService = hostResolutionService;
    }

    public void Reset()
    {
        _lastFlowsTop = Array.Empty<FlowInfo>();

        SummaryTotalPackets = 0;
        SummaryTotalBytes = 0;
        SummaryFlowsShown = 0;
        SummaryFirstSeen = null;
        SummaryLastSeen = null;
        SummaryDuration = TimeSpan.Zero;
        SummaryTotalBytesHuman = "-";
        SummaryPacketsPerSec = "-";
        SummaryBytesPerSec = "-";
        _lastTopListsRefreshUtc = DateTime.MinValue;

        TopProcesses.Clear();
        TopConversations.Clear();
        TopHosts.Clear();
        TopTrafficTypes.Clear();
    }

    public void Update(IReadOnlyList<FlowInfo> flowsTop, CaptureStats stats)
    {
        _lastFlowsTop = flowsTop ?? Array.Empty<FlowInfo>();

        SummaryTotalPackets = stats.TotalPackets;
        SummaryTotalBytes = stats.TotalBytes;
        SummaryTotalBytesHuman = FormatBytes(stats.TotalBytes);
        SummaryFirstSeen = stats.FirstSeen;
        SummaryLastSeen = stats.LastSeen;
        SummaryDuration = stats.FirstSeen.HasValue && stats.LastSeen.HasValue
            ? stats.LastSeen.Value - stats.FirstSeen.Value
            : TimeSpan.Zero;
        SummaryFlowsShown = _lastFlowsTop.Count;

        var seconds = Math.Max(0.0001, stats.Elapsed.TotalSeconds);
        SummaryPacketsPerSec = $"{(stats.TotalPackets / seconds):0.0} pkt/s";
        SummaryBytesPerSec = $"{FormatBytes((long)(stats.TotalBytes / seconds))}/s";

        RefreshTopLists();
    }

    private void RefreshTopLists(bool force = false)
    {
        if (!force)
        {
            if (!IsViewActive)
                return;

            var nowUtc = DateTime.UtcNow;
            if ((nowUtc - _lastTopListsRefreshUtc) < ActiveTopListsRefreshInterval)
                return;

            _lastTopListsRefreshUtc = nowUtc;
        }
        else
        {
            _lastTopListsRefreshUtc = DateTime.UtcNow;
        }

        UpdateTopConversations();
        UpdateTopProcesses();
        UpdateTopHosts(_lastFlowsTop);
        UpdateTopTrafficTypes(_lastFlowsTop);
    }

    private void UpdateTopConversations()
    {
        var top = _processPackets.GetTopConversations(MaxTopConversations, MaxTopConversationsPerProcess)
            .ToList();

        long maxBytes = top.Count == 0 ? 1 : top.Max(item => item.Conversation.TotalBytes);

        ReplaceWith(
            TopConversations,
            top.Select(item => new ConversationTrafficRow
            {
                Pid = item.Process.Pid,
                ProcessName = item.Process.ProcessName,
                EndpointLabel = item.Conversation.DisplayEndpointLabel,
                Title = $"{item.Process.ProcessName} -> {item.Conversation.DisplayEndpointLabel}",
                Subtitle = string.IsNullOrWhiteSpace(item.Conversation.Protocol)
                    ? item.Conversation.DirectionLabel
                    : $"{item.Conversation.Protocol} | {item.Conversation.DirectionLabel}",
                PacketCountLabel = item.Conversation.PacketCountLabel,
                DirectionLabel = item.Conversation.DirectionLabel,
                Bytes = item.Conversation.TotalBytes,
                BytesLabel = item.Conversation.BytesLabel,
                RelativePercent = ToRelativePercent(item.Conversation.TotalBytes, maxBytes)
            }));
    }

    private void UpdateTopProcesses()
    {
        var top = _processPackets.ProcessStats
            .Where(row => row.TotalBytes > 0 && !string.IsNullOrWhiteSpace(row.ProcessName))
            .OrderByDescending(row => row.TotalBytes)
            .Take(MaxTopProcesses)
            .ToList();

        long maxBytes = top.Count == 0 ? 1 : top.Max(row => row.TotalBytes);

        ReplaceWith(
            TopProcesses,
            top.Select(row => new ProcessTrafficRow
            {
                Pid = row.Pid,
                Title = row.ProcessName,
                Subtitle = BuildProcessSubtitle(row),
                Bytes = row.TotalBytes,
                BytesLabel = row.TotalBytesHuman,
                RelativePercent = ToRelativePercent(row.TotalBytes, maxBytes)
            }));
    }

    private void UpdateTopHosts(IReadOnlyList<FlowInfo> flows)
    {
        var hostAgg = new Dictionary<string, (long Bytes, int Flows, string Type)>(StringComparer.OrdinalIgnoreCase);

        foreach (var flow in flows)
        {
            string hostIp = ResolveHostIp(flow);
            string host = ResolveHost(flow);
            if (string.IsNullOrWhiteSpace(host))
                continue;

            string type = GetIpType(hostIp);
            if (HideMulticastBroadcast && (type == "Multicast" || type == "Broadcast"))
                continue;

            if (!hostAgg.TryGetValue(host, out var aggregate))
                aggregate = (0, 0, type);

            aggregate.Bytes += flow.Bytes;
            aggregate.Flows += 1;
            hostAgg[host] = aggregate;
        }

        var top = hostAgg
            .Select(kv => new
            {
                Host = kv.Key,
                kv.Value.Type,
                kv.Value.Flows,
                kv.Value.Bytes
            })
            .OrderByDescending(item => item.Bytes)
            .Take(MaxTopHosts)
            .ToList();

        long maxBytes = top.Count == 0 ? 1 : top.Max(item => item.Bytes);

        ReplaceWith(
            TopHosts,
            top.Select(item => new HostStatRow
            {
                Title = item.Host,
                Subtitle = item.Flows == 1 ? item.Type : $"{item.Type} | {item.Flows:N0} flows",
                Type = item.Type,
                BadgeText = GetHostBadge(item.Type),
                Bytes = item.Bytes,
                BytesLabel = FormatBytes(item.Bytes),
                RelativePercent = ToRelativePercent(item.Bytes, maxBytes)
            }));
    }

    private void UpdateTopTrafficTypes(IReadOnlyList<FlowInfo> flows)
    {
        var trafficAgg = new Dictionary<string, (string Title, string Badge, long Bytes, int Flows)>(StringComparer.OrdinalIgnoreCase);

        foreach (var flow in flows)
        {
            var trafficType = ResolveTrafficType(flow);

            if (!trafficAgg.TryGetValue(trafficType.Key, out var aggregate))
                aggregate = (trafficType.Title, trafficType.Badge, 0, 0);

            aggregate.Bytes += flow.Bytes;
            aggregate.Flows += 1;
            trafficAgg[trafficType.Key] = aggregate;
        }

        var top = trafficAgg
            .Select(kv => new
            {
                Key = kv.Key,
                kv.Value.Title,
                kv.Value.Badge,
                kv.Value.Bytes,
                kv.Value.Flows
            })
            .OrderByDescending(item => item.Bytes)
            .Take(MaxTopTrafficTypes)
            .ToList();

        long maxBytes = top.Count == 0 ? 1 : top.Max(item => item.Bytes);

        ReplaceWith(
            TopTrafficTypes,
            top.Select(item => new TrafficTypeStatRow
            {
                Key = item.Key,
                Title = item.Title,
                Subtitle = item.Flows == 1 ? "1 flow" : $"{item.Flows:N0} flows",
                BadgeText = item.Badge,
                Bytes = item.Bytes,
                BytesLabel = FormatBytes(item.Bytes),
                RelativePercent = ToRelativePercent(item.Bytes, maxBytes)
            }));
    }

    private static string BuildProcessSubtitle(ProcessStatRow row)
    {
        string pid = row.Pid > 0 ? $"PID {row.Pid}" : "";
        string liveness = string.IsNullOrWhiteSpace(row.LivenessLabel) ? "" : row.LivenessLabel;

        if (string.IsNullOrWhiteSpace(pid))
            return liveness;

        if (string.IsNullOrWhiteSpace(liveness))
            return pid;

        return $"{pid} | {liveness}";
    }

    private string ResolveHost(FlowInfo flow)
    {
        if (!string.IsNullOrWhiteSpace(flow.RemoteIp))
            return _hostResolutionService.ResolveHostOrOriginal(flow.RemoteIp);

        if (!string.IsNullOrWhiteSpace(flow.DstIp))
            return _hostResolutionService.ResolveHostOrOriginal(flow.DstIp);

        string endpointIp = ExtractIp(flow.RemoteEndpoint);
        if (!string.IsNullOrWhiteSpace(endpointIp))
            return _hostResolutionService.ResolveHostOrOriginal(endpointIp);

        return _hostResolutionService.ResolveHostOrOriginal(flow.Key.DstIp);
    }

    private static string ResolveHostIp(FlowInfo flow)
    {
        if (!string.IsNullOrWhiteSpace(flow.RemoteIp))
            return flow.RemoteIp;

        if (!string.IsNullOrWhiteSpace(flow.DstIp))
            return flow.DstIp;

        string endpointIp = ExtractIp(flow.RemoteEndpoint);
        if (!string.IsNullOrWhiteSpace(endpointIp))
            return endpointIp;

        return flow.Key.DstIp;
    }

    private static (string Key, string Title, string Badge) ResolveTrafficType(FlowInfo flow)
    {
        string transport = NormalizeTransport(flow.Protocol);
        int? port = flow.RemotePort ?? flow.DstPort ?? flow.Key.DstPort;

        if (port is > 0 && TrafficPortMap.TryGetValue((transport, port.Value), out var mapped))
            return mapped;

        return transport switch
        {
            "ICMPV4" or "ICMPV6" => ("icmp", "Internet Control Message Protocol (ICMP)", "ICMP"),
            "IGMP" => ("igmp", "Internet Group Management Protocol (IGMP)", "IGMP"),
            "ARP" => ("arp", "Address Resolution Protocol (ARP)", "ARP"),
            "TCP" => ("other", "Other", "TCP"),
            "UDP" => ("other", "Other", "UDP"),
            _ => ("other", "Other", "NET"),
        };
    }

    private static string NormalizeTransport(string protocol)
    {
        if (string.IsNullOrWhiteSpace(protocol))
            return "";

        return protocol.Trim().ToUpperInvariant();
    }

    private static string GetHostBadge(string type)
        => type switch
        {
            "Multicast" => "MC",
            "Broadcast" => "BC",
            "Unicast" => "IP",
            _ => "?"
        };

    private static double ToRelativePercent(long bytes, long maxBytes)
    {
        if (bytes <= 0 || maxBytes <= 0)
            return 0;

        return Math.Clamp((bytes * 100d) / maxBytes, 0, 100);
    }

    private static void ReplaceWith<T>(ObservableCollection<T> target, IEnumerable<T> items)
    {
        var list = items as IList<T> ?? items.ToList();
        int shared = Math.Min(target.Count, list.Count);

        for (int i = 0; i < shared; i++)
            target[i] = list[i];

        while (target.Count > list.Count)
            target.RemoveAt(target.Count - 1);

        for (int i = shared; i < list.Count; i++)
            target.Add(list[i]);
    }

    private static string GetIpType(string ip)
    {
        if (!IPAddress.TryParse(ip, out var address))
            return "Unknown";

        var bytes = address.GetAddressBytes();

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            if (ip == "255.255.255.255")
                return "Broadcast";

            if (bytes[0] >= 224 && bytes[0] <= 239)
                return "Multicast";

            return "Unicast";
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (bytes.Length > 0 && bytes[0] == 0xFF)
                return "Multicast";

            return "Unicast";
        }

        return "Unknown";
    }

    private static string ExtractIp(string endpoint)
    {
        if (string.IsNullOrWhiteSpace(endpoint))
            return "";

        int idx = endpoint.LastIndexOf(':');
        return idx > 0 ? endpoint[..idx] : endpoint;
    }

    private static string FormatBytes(long bytes)
    {
        const double KB = 1024.0;
        const double MB = KB * 1024.0;
        const double GB = MB * 1024.0;

        if (bytes >= GB) return $"{bytes / GB:0.00} GB";
        if (bytes >= MB) return $"{bytes / MB:0.00} MB";
        if (bytes >= KB) return $"{bytes / KB:0.00} KB";
        return $"{bytes} B";
    }
}
