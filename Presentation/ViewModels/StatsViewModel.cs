using Domain.Models;
using Presentation.Models;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace Presentation.ViewModels;

public sealed class StatsViewModel : ViewModelBase
{
    // Top tables
    public ObservableCollection<HostStatRow> TopHosts { get; } = new();
    public ObservableCollection<PortStatRow> TopPorts { get; } = new();

    // Settings
    private int _statsTopN = 25;
    public int StatsTopN
    {
        get => _statsTopN;
        set { if (Set(ref _statsTopN, value)) _dirty = true; }
    }

    private bool _hideMulticastBroadcast = true;
    public bool HideMulticastBroadcast
    {
        get => _hideMulticastBroadcast;
        set { if (Set(ref _hideMulticastBroadcast, value)) _dirty = true; }
    }

    private volatile bool _dirty = true;

    // Summary
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

    private string _summaryTotalBytesHuman = "—";
    public string SummaryTotalBytesHuman { get => _summaryTotalBytesHuman; private set => Set(ref _summaryTotalBytesHuman, value); }

    private string _summaryPacketsPerSec = "—";
    public string SummaryPacketsPerSec { get => _summaryPacketsPerSec; private set => Set(ref _summaryPacketsPerSec, value); }

    private string _summaryBytesPerSec = "—";
    public string SummaryBytesPerSec { get => _summaryBytesPerSec; private set => Set(ref _summaryBytesPerSec, value); }

    public void Reset()
    {
        SummaryTotalPackets = 0;
        SummaryTotalBytes = 0;
        SummaryFlowsShown = 0;
        SummaryFirstSeen = null;
        SummaryLastSeen = null;
        SummaryDuration = TimeSpan.Zero;
        SummaryTotalBytesHuman = "—";
        SummaryPacketsPerSec = "—";
        SummaryBytesPerSec = "—";

        TopHosts.Clear();
        TopPorts.Clear();
        _dirty = true;
    }

    /// <summary>
    /// Викликається з MainViewModel раз на ~1с.
    /// flowsTop - snapshot top flows (як зараз), stats - загальні лічильники з capture.
    /// </summary>
    public void Update(IReadOnlyList<FlowInfo> flowsTop, CaptureStats stats)
    {
        // Summary: totals із capture
        SummaryTotalPackets = stats.TotalPackets;
        SummaryTotalBytes = stats.TotalBytes;
        SummaryTotalBytesHuman = FormatBytes(stats.TotalBytes);

        SummaryFirstSeen = stats.FirstSeen;
        SummaryLastSeen = stats.LastSeen;

        if (stats.FirstSeen.HasValue && stats.LastSeen.HasValue)
            SummaryDuration = stats.LastSeen.Value - stats.FirstSeen.Value;
        else
            SummaryDuration = TimeSpan.Zero;

        SummaryFlowsShown = flowsTop?.Count ?? 0;

        var sec = Math.Max(0.0001, stats.Elapsed.TotalSeconds);
        SummaryPacketsPerSec = $"{(stats.TotalPackets / sec):0.0} pkt/s";
        SummaryBytesPerSec = $"{FormatBytes((long)(stats.TotalBytes / sec))}/s";

        // Tables: перераховуємо якщо dirty або якщо хочеш завжди “живі” — прибрати if
        if (!_dirty)
            return;

        UpdateTopHosts(flowsTop);
        UpdateTopPorts(flowsTop);

        _dirty = false;
    }

    private void UpdateTopHosts(IReadOnlyList<FlowInfo> flows)
    {
        var hostAgg = new Dictionary<string, (int flows, int packets, long bytes, long sent, long recv, DateTime lastSeen, string role, string type)>(StringComparer.OrdinalIgnoreCase);

        foreach (var f in flows)
        {
            string host = !string.IsNullOrWhiteSpace(f.RemoteIp)
                ? f.RemoteIp
                : (ExtractIp(f.RemoteEndpoint) != "" ? ExtractIp(f.RemoteEndpoint) : f.Key.DstIp);

            if (string.IsNullOrWhiteSpace(host))
                continue;

            var type = GetIpType(host);
            if (HideMulticastBroadcast && (type == "Multicast" || type == "Broadcast"))
                continue;

            string role = !string.IsNullOrWhiteSpace(f.RemoteIp) ? "Remote" : "Unknown";

            if (!hostAgg.TryGetValue(host, out var a))
                a = (0, 0, 0, 0, 0, DateTime.MinValue, role, type);

            a.flows += 1;
            a.packets += f.Packets;
            a.bytes += f.Bytes;
            a.sent += f.SentBytes;
            a.recv += f.RecvBytes;
            if (f.LastSeen > a.lastSeen) a.lastSeen = f.LastSeen;

            hostAgg[host] = a;
        }

        var top = hostAgg
            .Select(kv => new HostStatRow
            {
                Host = kv.Key,
                Type = kv.Value.type,
                Role = kv.Value.role,
                Flows = kv.Value.flows,
                Packets = kv.Value.packets,
                Bytes = kv.Value.bytes,
                SentBytes = kv.Value.sent,
                RecvBytes = kv.Value.recv,
                LastSeen = kv.Value.lastSeen
            })
            .OrderByDescending(x => x.Bytes)
            .Take(StatsTopN)
            .ToList();

        TopHosts.Clear();
        foreach (var r in top)
            TopHosts.Add(r);
    }

    private void UpdateTopPorts(IReadOnlyList<FlowInfo> flows)
    {
        var portAgg = new Dictionary<(string proto, int port), (int flows, int packets, long bytes, long sent, long recv, DateTime lastSeen)>();

        foreach (var f in flows)
        {
            var proto = f.Protocol ?? "";
            int? port = f.RemotePort ?? f.DstPort ?? f.Key.DstPort;

            if (port is null || port <= 0)
                continue;

            var key = (proto, port.Value);

            if (!portAgg.TryGetValue(key, out var a))
                a = (0, 0, 0, 0, 0, DateTime.MinValue);

            a.flows += 1;
            a.packets += f.Packets;
            a.bytes += f.Bytes;
            a.sent += f.SentBytes;
            a.recv += f.RecvBytes;
            if (f.LastSeen > a.lastSeen) a.lastSeen = f.LastSeen;

            portAgg[key] = a;
        }

        var top = portAgg
            .Select(kv => new PortStatRow
            {
                Protocol = kv.Key.proto,
                Port = kv.Key.port,
                Service = GuessService(kv.Key.proto, kv.Key.port),
                Flows = kv.Value.flows,
                Packets = kv.Value.packets,
                Bytes = kv.Value.bytes,
                SentBytes = kv.Value.sent,
                RecvBytes = kv.Value.recv,
                LastSeen = kv.Value.lastSeen
            })
            .OrderByDescending(x => x.Bytes)
            .Take(StatsTopN)
            .ToList();

        TopPorts.Clear();
        foreach (var r in top)
            TopPorts.Add(r);
    }

    private static string GuessService(string proto, int port)
    {
        return (proto?.ToUpperInvariant(), port) switch
        {
            ("TCP", 80) => "HTTP",
            ("TCP", 443) => "HTTPS",
            ("UDP", 443) => "QUIC",
            ("UDP", 53) => "DNS",
            ("TCP", 53) => "DNS",
            ("UDP", 123) => "NTP",
            ("UDP", 1900) => "SSDP",
            ("UDP", 5353) => "mDNS",
            ("TCP", 22) => "SSH",
            ("TCP", 25) => "SMTP",
            ("TCP", 110) => "POP3",
            ("TCP", 143) => "IMAP",
            _ => ""
        };
    }

    private static string GetIpType(string ip)
    {
        if (!IPAddress.TryParse(ip, out var addr))
            return "Unknown";

        var bytes = addr.GetAddressBytes();

        if (addr.AddressFamily == AddressFamily.InterNetwork)
        {
            if (ip == "255.255.255.255") return "Broadcast";
            if (bytes[0] >= 224 && bytes[0] <= 239) return "Multicast";
            return "Unicast";
        }

        if (addr.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (bytes.Length > 0 && bytes[0] == 0xFF) return "Multicast";
            return "Unicast";
        }

        return "Unknown";
    }

    private static string ExtractIp(string endpoint)
    {
        if (string.IsNullOrWhiteSpace(endpoint)) return "";
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