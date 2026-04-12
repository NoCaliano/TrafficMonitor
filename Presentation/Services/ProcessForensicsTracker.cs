using Application.Abstractions;
using Domain.Models;
using Presentation.Models;
using System;
using System.Collections.Generic;
using Application.Networking;

namespace Presentation.Services;

public sealed class ProcessForensicsTracker
{
    public readonly record struct ProcessForensicsUpdate(
        bool HasFirstOutboundConnection,
        string FirstOutboundConnectionDetail,
        bool HasBeaconDetected,
        string BeaconDetail);

    private readonly ILocalAddressService _localAddressService;
    private readonly HostResolutionService _hostResolutionService;

    private HashSet<string> _localIps = new(StringComparer.OrdinalIgnoreCase);
    private DateTime _lastLocalIpsRefreshUtc = DateTime.MinValue;
    private static readonly TimeSpan LocalIpsRefreshInterval = TimeSpan.FromSeconds(5);

    private readonly Dictionary<int, HashSet<RemoteEndpointKey>> _distinctRemotes = new();
    private readonly Dictionary<(int Pid, RemoteEndpointKey Endpoint), long> _endpointBytes = new();
    private readonly Dictionary<int, (RemoteEndpointKey Endpoint, long Bytes)> _topRemoteByBytes = new();
    private readonly Dictionary<int, Dictionary<RemoteEndpointKey, ConversationState>> _conversationsByPid = new();
    private readonly Dictionary<int, List<ConversationState>> _topConversationSnapshotsByPid = new();
    private readonly Dictionary<int, List<SessionClusterState>> _sessionClusters = new();

    private readonly Dictionary<(int Pid, RemoteEndpointKey Endpoint), BeaconState> _beaconStates = new();
    private readonly Dictionary<int, BeaconSummary> _bestBeaconByPid = new();
    private readonly HashSet<int> _pidsWithFirstOutboundConnection = new();
    private readonly HashSet<int> _pidsWithBeaconTimelineEvent = new();

    private readonly Dictionary<(int Pid, UdpFlowKey Flow), DateTime> _udpFlowLastSeenUtc = new();
    private DateTime _lastCleanupUtc = DateTime.MinValue;

    private static readonly TimeSpan UdpFlowInactivityThreshold = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan SessionClusterGapThreshold = TimeSpan.FromSeconds(20);
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan FlowTtl = TimeSpan.FromMinutes(10);

    private const int MaxDistinctRemoteEndpointsPerPid = 5000;
    private const int MaxConversationSnapshotEntriesPerPid = 128;

    public ProcessForensicsTracker(ILocalAddressService localAddressService, HostResolutionService hostResolutionService)
    {
        _localAddressService = localAddressService;
        _hostResolutionService = hostResolutionService;
        RefreshLocalIpsIfNeeded(force: true);
    }

    public ProcessForensicsUpdate Update(PacketInfo p, ProcessStatRow row)
    {
        var update = default(ProcessForensicsUpdate);

        _hostResolutionService.Observe(p);

        if (row.Pid <= 0)
            return update;

        if (string.IsNullOrWhiteSpace(p.SrcIp) || string.IsNullOrWhiteSpace(p.DstIp))
            return update;

        RefreshLocalIpsIfNeeded(force: false);

        bool srcLocal = _localIps.Contains(p.SrcIp);
        bool dstLocal = _localIps.Contains(p.DstIp);

        row.ObserveDirectionalTraffic(srcLocal && !dstLocal, !srcLocal && dstLocal, p.Length);

        if (!srcLocal && !dstLocal)
            return update;

        string remoteIp = srcLocal ? p.DstIp : p.SrcIp;
        int remotePort = srcLocal ? (p.DstPort ?? -1) : (p.SrcPort ?? -1);

        var endpoint = new RemoteEndpointKey(p.Protocol, remoteIp, remotePort);
        row.ObserveSecureEndpointIntelligence(
            p.Timestamp,
            endpoint.ToString(),
            p.ServerNameHint,
            p.TlsClientFingerprintKind,
            p.TlsClientFingerprint,
            p.TlsCertificateFingerprint,
            p.TlsCertificateNames,
            p.TlsCertificateSubject);

        if (!_distinctRemotes.TryGetValue(row.Pid, out var set))
        {
            set = new HashSet<RemoteEndpointKey>();
            _distinctRemotes[row.Pid] = set;
        }

        if (set.Count < MaxDistinctRemoteEndpointsPerPid && set.Add(endpoint))
            row.DistinctRemoteEndpoints = set.Count;

        var epKey = (row.Pid, endpoint);
        if (!_endpointBytes.TryGetValue(epKey, out var bytes)) bytes = 0;
        bytes += p.Length;
        _endpointBytes[epKey] = bytes;

        UpdateConversation(epKey, p, srcLocal, dstLocal);
        UpdateSessionCluster(row.Pid, endpoint, p, srcLocal, dstLocal);

        if (!_topRemoteByBytes.TryGetValue(row.Pid, out var best) || bytes > best.Bytes)
        {
            _topRemoteByBytes[row.Pid] = (endpoint, bytes);
            row.TopRemoteEndpoint = endpoint.ToString();
        }

        // Beaconing based on new outbound flow starts.
        if (!(srcLocal && !dstLocal))
            return update;

        DateTime utc = p.Timestamp.Kind == DateTimeKind.Utc ? p.Timestamp : p.Timestamp.ToUniversalTime();
        if (!IsNewOutboundFlowStart(row.Pid, p, endpoint, utc))
            return update;

        if (_pidsWithFirstOutboundConnection.Add(row.Pid))
        {
            update = update with
            {
                HasFirstOutboundConnection = true,
                FirstOutboundConnectionDetail = BuildOutboundConnectionDetail(p)
            };
        }

        var bKey = (row.Pid, endpoint);
        if (!_beaconStates.TryGetValue(bKey, out var st))
        {
            st = new BeaconState();
            _beaconStates[bKey] = st;
        }

        bool beaconWasDetected = row.BeaconSuspected;
        if (st.HasLast)
        {
            double deltaSec = (utc - st.LastUtc).TotalSeconds;
            if (deltaSec >= 1 && deltaSec <= 600)
            {
                st.AddSample(deltaSec);
                TryUpdateBeaconSummary(row, endpoint, st);
            }
        }

        st.HasLast = true;
        st.LastUtc = utc;

        if (!beaconWasDetected && row.BeaconSuspected && _pidsWithBeaconTimelineEvent.Add(row.Pid))
        {
            update = update with
            {
                HasBeaconDetected = true,
                BeaconDetail = BuildBeaconDetail(endpoint, row)
            };
        }

        return update;
    }

    public void CleanupIfNeeded()
    {
        var now = DateTime.UtcNow;
        if ((now - _lastCleanupUtc) < CleanupInterval)
            return;

        _lastCleanupUtc = now;
        var cutoff = now - FlowTtl;

        if (_udpFlowLastSeenUtc.Count == 0)
            return;

        var toRemove = new List<(int, UdpFlowKey)>();
        foreach (var kv in _udpFlowLastSeenUtc)
        {
            if (kv.Value < cutoff)
                toRemove.Add(kv.Key);
        }

        foreach (var k in toRemove)
            _udpFlowLastSeenUtc.Remove(k);
    }

    public void Reset()
    {
        _distinctRemotes.Clear();
        _endpointBytes.Clear();
        _topRemoteByBytes.Clear();
        _conversationsByPid.Clear();
        _topConversationSnapshotsByPid.Clear();
        _sessionClusters.Clear();
        _beaconStates.Clear();
        _bestBeaconByPid.Clear();
        _pidsWithFirstOutboundConnection.Clear();
        _pidsWithBeaconTimelineEvent.Clear();
        _udpFlowLastSeenUtc.Clear();
        _lastCleanupUtc = DateTime.MinValue;
        _lastLocalIpsRefreshUtc = DateTime.MinValue;
        _hostResolutionService.Reset();
        RefreshLocalIpsIfNeeded(force: true);
    }

    public IReadOnlyList<ProcessConversationRow> GetConversationSnapshot(int pid, int take = 100)
    {
        if (pid <= 0 || take <= 0 || !_conversationsByPid.TryGetValue(pid, out var conversationsForPid) || conversationsForPid.Count == 0)
            return Array.Empty<ProcessConversationRow>();

        IReadOnlyList<ConversationState> snapshotStates;
        if (take <= MaxConversationSnapshotEntriesPerPid
            && _topConversationSnapshotsByPid.TryGetValue(pid, out var topStates)
            && topStates.Count > 0)
        {
            snapshotStates = topStates;
        }
        else
        {
            snapshotStates = conversationsForPid.Values
                .OrderByDescending(state => state.Bytes)
                .ThenByDescending(state => state.Packets)
                .ThenByDescending(state => state.LastSeen)
                .Take(take)
                .ToArray();
        }

        int count = Math.Min(take, snapshotStates.Count);
        if (count == 0)
            return Array.Empty<ProcessConversationRow>();

        var rows = new ProcessConversationRow[count];
        for (int i = 0; i < count; i++)
        {
            var state = snapshotStates[i];
            _hostResolutionService.TryResolve(state.Endpoint.Ip, out var resolvedHost);
            rows[i] = new ProcessConversationRow
            {
                Pid = pid,
                Protocol = state.Endpoint.Protocol,
                RemoteIp = state.Endpoint.Ip,
                ResolvedHost = resolvedHost,
                RemotePort = state.Endpoint.Port,
                PacketCount = state.Packets,
                TotalBytes = state.Bytes,
                FirstSeen = state.FirstSeen,
                LastSeen = state.LastSeen,
                OutboundPackets = state.OutboundPackets,
                InboundPackets = state.InboundPackets
            };
        }

        return rows;
    }

    public IReadOnlyList<ProcessSessionClusterRow> GetSessionClusterSnapshot(int pid, int take = 24)
    {
        if (pid <= 0 || take <= 0 || !_sessionClusters.TryGetValue(pid, out var clusters) || clusters.Count == 0)
            return Array.Empty<ProcessSessionClusterRow>();

        int total = clusters.Count;
        int count = Math.Min(take, total);
        var rows = new ProcessSessionClusterRow[count];
        int rowIndex = 0;

        for (int clusterIndex = total - 1; clusterIndex >= total - count; clusterIndex--)
        {
            var cluster = clusters[clusterIndex];
            rows[rowIndex++] = new ProcessSessionClusterRow
            {
                Pid = pid,
                Index = cluster.Index,
                FirstSeen = cluster.FirstSeen,
                LastSeen = cluster.LastSeen,
                PacketCount = cluster.Packets,
                TotalBytes = cluster.Bytes,
                DistinctRemoteEndpoints = cluster.DistinctEndpoints.Count,
                TopRemoteEndpoint = cluster.TopRemoteEndpoint?.ToString() ?? "",
                OutboundPackets = cluster.OutboundPackets,
                InboundPackets = cluster.InboundPackets,
                IsActive = cluster.Index == total
            };
        }

        return rows;
    }

    private void RefreshLocalIpsIfNeeded(bool force)
    {
        var now = DateTime.UtcNow;
        if (!force && (now - _lastLocalIpsRefreshUtc) < LocalIpsRefreshInterval)
            return;

        var fresh = _localAddressService.GetLocalIpStrings();
        _localIps = new HashSet<string>(fresh, StringComparer.OrdinalIgnoreCase);
        _lastLocalIpsRefreshUtc = now;
    }

    private void UpdateConversation((int Pid, RemoteEndpointKey Endpoint) key, PacketInfo packet, bool srcLocal, bool dstLocal)
    {
        if (!_conversationsByPid.TryGetValue(key.Pid, out var conversationsForPid))
        {
            conversationsForPid = new Dictionary<RemoteEndpointKey, ConversationState>();
            _conversationsByPid[key.Pid] = conversationsForPid;
        }

        if (!conversationsForPid.TryGetValue(key.Endpoint, out var state))
        {
            state = new ConversationState(key.Endpoint, packet.Timestamp);
            conversationsForPid[key.Endpoint] = state;
        }

        state.Packets++;
        state.Bytes += packet.Length;

        if (state.FirstSeen == default || packet.Timestamp < state.FirstSeen)
            state.FirstSeen = packet.Timestamp;

        if (packet.Timestamp > state.LastSeen)
            state.LastSeen = packet.Timestamp;

        if (srcLocal && !dstLocal)
            state.OutboundPackets++;
        else if (dstLocal && !srcLocal)
            state.InboundPackets++;

        UpdateTopConversationSnapshot(key.Pid, state);
    }

    private void UpdateSessionCluster(int pid, RemoteEndpointKey endpoint, PacketInfo packet, bool srcLocal, bool dstLocal)
    {
        if (!_sessionClusters.TryGetValue(pid, out var clusters))
        {
            clusters = new List<SessionClusterState>();
            _sessionClusters[pid] = clusters;
        }

        var timestamp = packet.Timestamp;
        SessionClusterState? cluster = clusters.Count > 0 ? clusters[^1] : null;

        if (cluster is null || ShouldStartNewSessionCluster(cluster, timestamp))
        {
            cluster = new SessionClusterState
            {
                Index = clusters.Count + 1,
                FirstSeen = timestamp,
                LastSeen = timestamp
            };
            clusters.Add(cluster);
        }

        cluster.Packets++;
        cluster.Bytes += packet.Length;

        if (cluster.FirstSeen == default || timestamp < cluster.FirstSeen)
            cluster.FirstSeen = timestamp;

        if (timestamp > cluster.LastSeen)
            cluster.LastSeen = timestamp;

        cluster.DistinctEndpoints.Add(endpoint);

        if (!cluster.EndpointBytes.TryGetValue(endpoint, out var endpointBytes))
            endpointBytes = 0;

        endpointBytes += packet.Length;
        cluster.EndpointBytes[endpoint] = endpointBytes;

        if (cluster.TopRemoteEndpoint is null || endpointBytes > cluster.TopRemoteBytes)
        {
            cluster.TopRemoteEndpoint = endpoint;
            cluster.TopRemoteBytes = endpointBytes;
        }

        if (srcLocal && !dstLocal)
            cluster.OutboundPackets++;
        else if (dstLocal && !srcLocal)
            cluster.InboundPackets++;
    }

    private static bool ShouldStartNewSessionCluster(SessionClusterState cluster, DateTime timestamp)
    {
        if (cluster.LastSeen == default)
            return false;

        if (timestamp <= cluster.LastSeen)
            return false;

        return (timestamp - cluster.LastSeen) >= SessionClusterGapThreshold;
    }

    private void UpdateTopConversationSnapshot(int pid, ConversationState state)
    {
        if (!_topConversationSnapshotsByPid.TryGetValue(pid, out var topStates))
        {
            topStates = new List<ConversationState>(Math.Min(MaxConversationSnapshotEntriesPerPid, 32));
            _topConversationSnapshotsByPid[pid] = topStates;
        }

        int existingIndex = topStates.FindIndex(candidate => ReferenceEquals(candidate, state));
        if (existingIndex >= 0)
            topStates.RemoveAt(existingIndex);

        int insertIndex = 0;
        while (insertIndex < topStates.Count && CompareConversationSnapshotOrder(state, topStates[insertIndex]) >= 0)
            insertIndex++;

        if (insertIndex >= MaxConversationSnapshotEntriesPerPid && topStates.Count >= MaxConversationSnapshotEntriesPerPid)
            return;

        topStates.Insert(insertIndex, state);
        if (topStates.Count > MaxConversationSnapshotEntriesPerPid)
            topStates.RemoveAt(topStates.Count - 1);
    }

    private static int CompareConversationSnapshotOrder(ConversationState left, ConversationState right)
    {
        int comparison = right.Bytes.CompareTo(left.Bytes);
        if (comparison != 0)
            return comparison;

        comparison = right.Packets.CompareTo(left.Packets);
        if (comparison != 0)
            return comparison;

        comparison = right.LastSeen.CompareTo(left.LastSeen);
        if (comparison != 0)
            return comparison;

        comparison = string.Compare(left.Endpoint.Protocol, right.Endpoint.Protocol, StringComparison.OrdinalIgnoreCase);
        if (comparison != 0)
            return comparison;

        comparison = string.Compare(left.Endpoint.Ip, right.Endpoint.Ip, StringComparison.OrdinalIgnoreCase);
        if (comparison != 0)
            return comparison;

        return left.Endpoint.Port.CompareTo(right.Endpoint.Port);
    }

    private bool IsNewOutboundFlowStart(int pid, PacketInfo p, RemoteEndpointKey endpoint, DateTime utc)
    {
        if (endpoint.Port <= 0)
            return false;

        var transportProtocol = string.IsNullOrWhiteSpace(p.TransportProtocol) ? p.Protocol : p.TransportProtocol;

        if (transportProtocol == "TCP")
        {
            if (!IsTcpSynStart(p.TcpFlags))
                return false;

            return true;
        }

        if (transportProtocol == "UDP")
        {
            if (p.SrcPort is not int localPort || p.DstPort is not int remotePort)
                return false;

            if (string.IsNullOrWhiteSpace(p.SrcIp) || string.IsNullOrWhiteSpace(p.DstIp))
                return false;

            var flow = new UdpFlowKey(LocalIp: p.SrcIp, LocalPort: localPort, RemoteIp: p.DstIp, RemotePort: remotePort);
            var key = (pid, flow);

            if (_udpFlowLastSeenUtc.TryGetValue(key, out var last))
            {
                _udpFlowLastSeenUtc[key] = utc;
                return (utc - last) >= UdpFlowInactivityThreshold;
            }

            _udpFlowLastSeenUtc[key] = utc;
            return true;
        }

        return false;
    }

    private static bool IsTcpSynStart(string flags)
    {
        if (string.IsNullOrWhiteSpace(flags))
            return false;

        return flags.Contains("SYN", StringComparison.OrdinalIgnoreCase)
            && !flags.Contains("ACK", StringComparison.OrdinalIgnoreCase);
    }

    private static string BuildOutboundConnectionDetail(PacketInfo packet)
    {
        string protocol = string.IsNullOrWhiteSpace(packet.TransportProtocol) ? packet.Protocol : packet.TransportProtocol;
        string src = FormatEndpoint(packet.SrcIp, packet.SrcPort);
        string dst = FormatEndpoint(packet.DstIp, packet.DstPort);
        return $"{protocol} {src} -> {dst}";
    }

    private static string BuildBeaconDetail(RemoteEndpointKey endpoint, ProcessStatRow row)
    {
        if (row.BeaconIntervalSec > 0)
            return $"{endpoint} repeats every ~{row.BeaconIntervalSec:0.#}s (cv {row.BeaconCv:0.##}, n={row.BeaconSamples}).";

        return $"{endpoint} shows a repeating outbound cadence.";
    }

    private static string FormatEndpoint(string ip, int? port)
    {
        if (string.IsNullOrWhiteSpace(ip))
            return "?";

        return port is int value && value > 0 ? $"{ip}:{value}" : ip;
    }

    private void TryUpdateBeaconSummary(ProcessStatRow row, RemoteEndpointKey endpoint, BeaconState st)
    {
        if (st.Samples < 6)
            return;

        if (!st.TryGetCv(out var cv))
            return;

        double mean = st.Mean;
        if (mean < 2 || mean > 120)
            return;

        if (cv > 0.20)
            return;

        var candidate = new BeaconSummary(endpoint, mean, cv, st.Samples);

        if (!_bestBeaconByPid.TryGetValue(row.Pid, out var current)
            || candidate.Cv < current.Cv
            || (Math.Abs(candidate.Cv - current.Cv) < 0.001 && candidate.Samples > current.Samples))
        {
            _bestBeaconByPid[row.Pid] = candidate;
            row.UpdateBeaconSignal(candidate.Endpoint.ToString(), candidate.MeanSec, candidate.Cv, candidate.Samples);
        }
    }

    private readonly record struct RemoteEndpointKey(string Protocol, string Ip, int Port)
    {
        public override string ToString()
            => Port > 0 ? $"{Protocol} {Ip}:{Port}" : $"{Protocol} {Ip}";
    }

    private sealed class ConversationState
    {
        public ConversationState(RemoteEndpointKey endpoint, DateTime timestamp)
        {
            Endpoint = endpoint;
            FirstSeen = timestamp;
            LastSeen = timestamp;
        }

        public RemoteEndpointKey Endpoint { get; }
        public long Packets;
        public long Bytes;
        public DateTime FirstSeen;
        public DateTime LastSeen;
        public int OutboundPackets;
        public int InboundPackets;
    }

    private sealed class SessionClusterState
    {
        public int Index;
        public long Packets;
        public long Bytes;
        public DateTime FirstSeen;
        public DateTime LastSeen;
        public int OutboundPackets;
        public int InboundPackets;
        public HashSet<RemoteEndpointKey> DistinctEndpoints { get; } = new();
        public Dictionary<RemoteEndpointKey, long> EndpointBytes { get; } = new();
        public RemoteEndpointKey? TopRemoteEndpoint;
        public long TopRemoteBytes;
    }

    private sealed class BeaconState
    {
        public bool HasLast;
        public DateTime LastUtc;

        public int Samples;
        public double Mean;
        public double M2;

        public void AddSample(double x)
        {
            Samples++;
            double delta = x - Mean;
            Mean += delta / Samples;
            double delta2 = x - Mean;
            M2 += delta * delta2;
        }

        public bool TryGetCv(out double cv)
        {
            cv = double.PositiveInfinity;
            if (Samples < 2 || Mean <= 0)
                return false;

            double variance = M2 / (Samples - 1);
            if (variance < 0) variance = 0;
            double std = Math.Sqrt(variance);
            cv = std / Mean;
            return true;
        }
    }

    private readonly record struct UdpFlowKey(string LocalIp, int LocalPort, string RemoteIp, int RemotePort);

    private readonly record struct BeaconSummary(RemoteEndpointKey Endpoint, double MeanSec, double Cv, int Samples);
}
