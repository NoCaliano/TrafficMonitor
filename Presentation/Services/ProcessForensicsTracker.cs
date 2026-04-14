using Application.Abstractions;
using Domain.Models;
using Presentation.Models;
using System;
using System.Collections.Generic;
using Application.Networking;
using System.Linq;

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
    private readonly Dictionary<int, Dictionary<string, IncidentDomainState>> _incidentDomainsByPid = new();
    private readonly Dictionary<int, Dictionary<string, IncidentIpState>> _incidentIpsByPid = new();
    private readonly Dictionary<int, Dictionary<string, IncidentCertificateState>> _incidentCertificatesByPid = new();
    private readonly Dictionary<int, Dictionary<(string Domain, string Ip), int>> _incidentDomainIpLinksByPid = new();
    private readonly Dictionary<int, Dictionary<(string Ip, string CertificateFingerprint), int>> _incidentIpCertificateLinksByPid = new();

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
        ObserveIncidentGraphTelemetry(row.Pid, p, remoteIp);

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
        _incidentDomainsByPid.Clear();
        _incidentIpsByPid.Clear();
        _incidentCertificatesByPid.Clear();
        _incidentDomainIpLinksByPid.Clear();
        _incidentIpCertificateLinksByPid.Clear();
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

    public ProcessIncidentGraphSnapshot GetIncidentGraphSnapshot(int pid, int takeDomains = 16, int takeIps = 20, int takeCertificates = 12)
    {
        if (pid <= 0)
            return ProcessIncidentGraphSnapshot.Empty;

        var domains = _incidentDomainsByPid.TryGetValue(pid, out var domainsByPid)
            ? domainsByPid.Values
                .OrderByDescending(static state => state.TotalBytes)
                .ThenByDescending(static state => state.ObservationCount)
                .ThenBy(static state => state.Domain, StringComparer.OrdinalIgnoreCase)
                .Take(takeDomains)
                .Select(static state => new ProcessIncidentGraphDomainObservation(
                    state.Domain,
                    state.ObservationCount,
                    state.DnsHits,
                    state.SniHits,
                    state.TotalBytes,
                    state.FirstSeen,
                    state.LastSeen,
                    state.LinkedIps
                        .OrderBy(static value => value, StringComparer.OrdinalIgnoreCase)
                        .ToArray()))
                .ToArray()
            : Array.Empty<ProcessIncidentGraphDomainObservation>();

        var ips = _incidentIpsByPid.TryGetValue(pid, out var ipsByPid)
            ? ipsByPid.Values
                .OrderByDescending(static state => state.TotalBytes)
                .ThenByDescending(static state => state.PacketCount)
                .ThenBy(static state => state.Ip, StringComparer.OrdinalIgnoreCase)
                .Take(takeIps)
                .Select(state =>
                {
                    var resolutionHints = BuildIncidentGraphResolutionHints(state.Ip);
                    string resolvedHost = resolutionHints.Length > 0
                        ? resolutionHints[0].Host
                        : state.ResolvedHost;

                    return new ProcessIncidentGraphIpObservation(
                        state.Ip,
                        resolvedHost,
                        state.PacketCount,
                        state.TotalBytes,
                        state.FirstSeen,
                        state.LastSeen,
                        state.LinkedDomains
                            .OrderBy(static value => value, StringComparer.OrdinalIgnoreCase)
                            .ToArray(),
                        state.CertificateFingerprints
                            .OrderBy(static value => value, StringComparer.OrdinalIgnoreCase)
                            .ToArray(),
                        resolutionHints);
                })
                .ToArray()
            : Array.Empty<ProcessIncidentGraphIpObservation>();

        var certificates = _incidentCertificatesByPid.TryGetValue(pid, out var certificatesByPid)
            ? certificatesByPid.Values
                .OrderByDescending(static state => state.ObservationCount)
                .ThenByDescending(static state => state.LinkedDomains.Count)
                .ThenBy(static state => state.Fingerprint, StringComparer.OrdinalIgnoreCase)
                .Take(takeCertificates)
                .Select(static state => new ProcessIncidentGraphCertificateObservation(
                    state.Fingerprint,
                    state.Subject,
                    state.Names
                        .OrderBy(static value => value, StringComparer.OrdinalIgnoreCase)
                        .ToArray(),
                    state.ObservationCount,
                    state.FirstSeen,
                    state.LastSeen,
                    state.LinkedIps
                        .OrderBy(static value => value, StringComparer.OrdinalIgnoreCase)
                        .ToArray(),
                    state.LinkedDomains
                        .OrderBy(static value => value, StringComparer.OrdinalIgnoreCase)
                        .ToArray()))
                .ToArray()
            : Array.Empty<ProcessIncidentGraphCertificateObservation>();

        var domainSet = new HashSet<string>(domains.Select(static domain => domain.Domain), StringComparer.OrdinalIgnoreCase);
        var ipSet = new HashSet<string>(ips.Select(static ip => ip.Ip), StringComparer.OrdinalIgnoreCase);
        var certificateSet = new HashSet<string>(certificates.Select(static certificate => certificate.Fingerprint), StringComparer.OrdinalIgnoreCase);

        var domainIpLinks = _incidentDomainIpLinksByPid.TryGetValue(pid, out var domainIpLinksByPid)
            ? domainIpLinksByPid
                .Where(kvp => domainSet.Contains(kvp.Key.Domain) && ipSet.Contains(kvp.Key.Ip))
                .OrderByDescending(static kvp => kvp.Value)
                .ThenBy(static kvp => kvp.Key.Domain, StringComparer.OrdinalIgnoreCase)
                .ThenBy(static kvp => kvp.Key.Ip, StringComparer.OrdinalIgnoreCase)
                .Select(static kvp => new ProcessIncidentGraphDomainIpLink(
                    kvp.Key.Domain,
                    kvp.Key.Ip,
                    kvp.Value))
                .ToArray()
            : Array.Empty<ProcessIncidentGraphDomainIpLink>();

        var ipCertificateLinks = _incidentIpCertificateLinksByPid.TryGetValue(pid, out var ipCertificateLinksByPid)
            ? ipCertificateLinksByPid
                .Where(kvp => ipSet.Contains(kvp.Key.Ip) && certificateSet.Contains(kvp.Key.CertificateFingerprint))
                .OrderByDescending(static kvp => kvp.Value)
                .ThenBy(static kvp => kvp.Key.Ip, StringComparer.OrdinalIgnoreCase)
                .ThenBy(static kvp => kvp.Key.CertificateFingerprint, StringComparer.OrdinalIgnoreCase)
                .Select(static kvp => new ProcessIncidentGraphIpCertificateLink(
                    kvp.Key.Ip,
                    kvp.Key.CertificateFingerprint,
                    kvp.Value))
                .ToArray()
            : Array.Empty<ProcessIncidentGraphIpCertificateLink>();

        return new ProcessIncidentGraphSnapshot(domains, ips, certificates, domainIpLinks, ipCertificateLinks);
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

    private void ObserveIncidentGraphTelemetry(int pid, PacketInfo packet, string remoteIp)
    {
        if (pid <= 0)
            return;

        if (!string.IsNullOrWhiteSpace(remoteIp))
            ObserveIncidentGraphIp(pid, remoteIp, packet);

        string dnsDomain = NormalizeDomain(packet.DnsQueryName);
        if (!string.IsNullOrWhiteSpace(dnsDomain))
        {
            ObserveIncidentGraphDomain(pid, dnsDomain, packet.Timestamp, packet.Length, fromDns: true, fromSni: false);

            for (int i = 0; i < packet.DnsAnswerIps.Count; i++)
            {
                string answerIp = packet.DnsAnswerIps[i]?.Trim() ?? string.Empty;
                if (string.IsNullOrWhiteSpace(answerIp))
                    continue;

                LinkIncidentGraphDomainToIp(pid, dnsDomain, answerIp, packet.Timestamp);
            }
        }

        string serverName = NormalizeDomain(packet.ServerNameHint);
        if (!string.IsNullOrWhiteSpace(serverName))
        {
            ObserveIncidentGraphDomain(pid, serverName, packet.Timestamp, packet.Length, fromDns: false, fromSni: true);

            if (!string.IsNullOrWhiteSpace(remoteIp))
                LinkIncidentGraphDomainToIp(pid, serverName, remoteIp, packet.Timestamp);
        }

        string certificateFingerprint = string.IsNullOrWhiteSpace(packet.TlsCertificateFingerprint)
            ? string.Empty
            : packet.TlsCertificateFingerprint.Trim().ToLowerInvariant();
        if (!string.IsNullOrWhiteSpace(certificateFingerprint) && !string.IsNullOrWhiteSpace(remoteIp))
        {
            ObserveIncidentGraphCertificate(pid, certificateFingerprint, packet, remoteIp, serverName);
            LinkIncidentGraphIpToCertificate(pid, remoteIp, certificateFingerprint);
        }
    }

    private void ObserveIncidentGraphDomain(int pid, string domain, DateTime timestamp, int packetLength, bool fromDns, bool fromSni)
    {
        if (string.IsNullOrWhiteSpace(domain))
            return;

        var state = GetOrCreateIncidentDomainState(pid, domain);
        state.ObservationCount++;
        state.TotalBytes += Math.Max(0, packetLength);

        if (fromDns)
            state.DnsHits++;

        if (fromSni)
            state.SniHits++;

        if (state.FirstSeen == default || timestamp < state.FirstSeen)
            state.FirstSeen = timestamp;

        if (timestamp > state.LastSeen)
            state.LastSeen = timestamp;
    }

    private void ObserveIncidentGraphIp(int pid, string ip, PacketInfo packet)
    {
        if (string.IsNullOrWhiteSpace(ip))
            return;

        var state = GetOrCreateIncidentIpState(pid, ip);
        state.PacketCount++;
        state.TotalBytes += packet.Length;

        if (state.FirstSeen == default || packet.Timestamp < state.FirstSeen)
            state.FirstSeen = packet.Timestamp;

        if (packet.Timestamp > state.LastSeen)
            state.LastSeen = packet.Timestamp;

        if (string.IsNullOrWhiteSpace(state.ResolvedHost)
            && _hostResolutionService.TryResolve(ip, out var resolvedHost)
            && !string.IsNullOrWhiteSpace(resolvedHost)
            && !string.Equals(resolvedHost, ip, StringComparison.OrdinalIgnoreCase))
        {
            state.ResolvedHost = resolvedHost;
        }
    }

    private void LinkIncidentGraphDomainToIp(int pid, string domain, string ip, DateTime timestamp)
    {
        if (string.IsNullOrWhiteSpace(domain) || string.IsNullOrWhiteSpace(ip))
            return;

        var domainState = GetOrCreateIncidentDomainState(pid, domain);
        var ipState = GetOrCreateIncidentIpState(pid, ip);

        domainState.LinkedIps.Add(ip);
        ipState.LinkedDomains.Add(domain);

        if (ipState.FirstSeen == default || timestamp < ipState.FirstSeen)
            ipState.FirstSeen = timestamp;

        if (timestamp > ipState.LastSeen)
            ipState.LastSeen = timestamp;

        if (!_incidentDomainIpLinksByPid.TryGetValue(pid, out var linksByPid))
        {
            linksByPid = new Dictionary<(string Domain, string Ip), int>();
            _incidentDomainIpLinksByPid[pid] = linksByPid;
        }

        var key = (domain, ip);
        linksByPid.TryGetValue(key, out int hitCount);
        linksByPid[key] = hitCount + 1;
    }

    private void ObserveIncidentGraphCertificate(int pid, string fingerprint, PacketInfo packet, string remoteIp, string primaryDomain)
    {
        var state = GetOrCreateIncidentCertificateState(pid, fingerprint);
        state.ObservationCount++;

        if (state.FirstSeen == default || packet.Timestamp < state.FirstSeen)
            state.FirstSeen = packet.Timestamp;

        if (packet.Timestamp > state.LastSeen)
            state.LastSeen = packet.Timestamp;

        if (!string.IsNullOrWhiteSpace(packet.TlsCertificateSubject))
            state.Subject = packet.TlsCertificateSubject.Trim();

        for (int i = 0; i < packet.TlsCertificateNames.Count; i++)
        {
            string name = NormalizeDomain(packet.TlsCertificateNames[i]);
            if (!string.IsNullOrWhiteSpace(name))
                state.Names.Add(name);
        }

        state.LinkedIps.Add(remoteIp);

        if (!string.IsNullOrWhiteSpace(primaryDomain))
            state.LinkedDomains.Add(primaryDomain);

        var ipState = GetOrCreateIncidentIpState(pid, remoteIp);
        ipState.CertificateFingerprints.Add(fingerprint);
    }

    private void LinkIncidentGraphIpToCertificate(int pid, string ip, string fingerprint)
    {
        if (string.IsNullOrWhiteSpace(ip) || string.IsNullOrWhiteSpace(fingerprint))
            return;

        if (!_incidentIpCertificateLinksByPid.TryGetValue(pid, out var linksByPid))
        {
            linksByPid = new Dictionary<(string Ip, string CertificateFingerprint), int>();
            _incidentIpCertificateLinksByPid[pid] = linksByPid;
        }

        var key = (ip, fingerprint);
        linksByPid.TryGetValue(key, out int hitCount);
        linksByPid[key] = hitCount + 1;
    }

    private IncidentDomainState GetOrCreateIncidentDomainState(int pid, string domain)
    {
        if (!_incidentDomainsByPid.TryGetValue(pid, out var domainsByPid))
        {
            domainsByPid = new Dictionary<string, IncidentDomainState>(StringComparer.OrdinalIgnoreCase);
            _incidentDomainsByPid[pid] = domainsByPid;
        }

        if (domainsByPid.TryGetValue(domain, out var state))
            return state;

        state = new IncidentDomainState { Domain = domain };
        domainsByPid[domain] = state;
        return state;
    }

    private IncidentIpState GetOrCreateIncidentIpState(int pid, string ip)
    {
        if (!_incidentIpsByPid.TryGetValue(pid, out var ipsByPid))
        {
            ipsByPid = new Dictionary<string, IncidentIpState>(StringComparer.OrdinalIgnoreCase);
            _incidentIpsByPid[pid] = ipsByPid;
        }

        if (ipsByPid.TryGetValue(ip, out var state))
            return state;

        state = new IncidentIpState { Ip = ip };
        ipsByPid[ip] = state;
        return state;
    }

    private IncidentCertificateState GetOrCreateIncidentCertificateState(int pid, string fingerprint)
    {
        if (!_incidentCertificatesByPid.TryGetValue(pid, out var certificatesByPid))
        {
            certificatesByPid = new Dictionary<string, IncidentCertificateState>(StringComparer.OrdinalIgnoreCase);
            _incidentCertificatesByPid[pid] = certificatesByPid;
        }

        if (certificatesByPid.TryGetValue(fingerprint, out var state))
            return state;

        state = new IncidentCertificateState { Fingerprint = fingerprint };
        certificatesByPid[fingerprint] = state;
        return state;
    }

    private ProcessIncidentGraphResolutionHint[] BuildIncidentGraphResolutionHints(string ip, int take = 3)
        => _hostResolutionService.GetHints(ip, take)
            .Select(static hint => new ProcessIncidentGraphResolutionHint(
                hint.Host,
                hint.SourceLabel,
                hint.ConfidenceScore,
                hint.ConfidenceLabel,
                hint.SummaryLabel))
            .ToArray();

    private static string NormalizeDomain(string? value)
        => string.IsNullOrWhiteSpace(value)
            ? string.Empty
            : value.Trim().TrimEnd('.').ToLowerInvariant();

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

    private sealed class IncidentDomainState
    {
        public string Domain = "";
        public int ObservationCount;
        public int DnsHits;
        public int SniHits;
        public long TotalBytes;
        public DateTime FirstSeen;
        public DateTime LastSeen;
        public HashSet<string> LinkedIps { get; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private sealed class IncidentIpState
    {
        public string Ip = "";
        public string ResolvedHost = "";
        public long PacketCount;
        public long TotalBytes;
        public DateTime FirstSeen;
        public DateTime LastSeen;
        public HashSet<string> LinkedDomains { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> CertificateFingerprints { get; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private sealed class IncidentCertificateState
    {
        public string Fingerprint = "";
        public string Subject = "";
        public long ObservationCount;
        public DateTime FirstSeen;
        public DateTime LastSeen;
        public HashSet<string> Names { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> LinkedIps { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> LinkedDomains { get; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private readonly record struct UdpFlowKey(string LocalIp, int LocalPort, string RemoteIp, int RemotePort);

    private readonly record struct BeaconSummary(RemoteEndpointKey Endpoint, double MeanSec, double Cv, int Samples);
}
