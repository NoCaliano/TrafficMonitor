using Application.Abstractions;
using Domain.Models;
using Presentation.Models;
using System;
using System.Collections.Generic;

namespace Presentation.Services;

public sealed class ProcessForensicsTracker
{
    private readonly ILocalAddressService _localAddressService;

    private HashSet<string> _localIps = new(StringComparer.OrdinalIgnoreCase);
    private DateTime _lastLocalIpsRefreshUtc = DateTime.MinValue;
    private static readonly TimeSpan LocalIpsRefreshInterval = TimeSpan.FromSeconds(5);

    private readonly Dictionary<int, HashSet<RemoteEndpointKey>> _distinctRemotes = new();
    private readonly Dictionary<(int Pid, RemoteEndpointKey Endpoint), long> _endpointBytes = new();
    private readonly Dictionary<int, (RemoteEndpointKey Endpoint, long Bytes)> _topRemoteByBytes = new();

    private readonly Dictionary<(int Pid, RemoteEndpointKey Endpoint), BeaconState> _beaconStates = new();
    private readonly Dictionary<int, BeaconSummary> _bestBeaconByPid = new();

    private readonly Dictionary<(int Pid, UdpFlowKey Flow), DateTime> _udpFlowLastSeenUtc = new();
    private DateTime _lastCleanupUtc = DateTime.MinValue;

    private static readonly TimeSpan UdpFlowInactivityThreshold = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan FlowTtl = TimeSpan.FromMinutes(10);

    private const int MaxDistinctRemoteEndpointsPerPid = 5000;

    public ProcessForensicsTracker(ILocalAddressService localAddressService)
    {
        _localAddressService = localAddressService;
        RefreshLocalIpsIfNeeded(force: true);
    }

    public void Update(PacketInfo p, ProcessStatRow row)
    {
        if (row.Pid <= 0)
            return;

        if (string.IsNullOrWhiteSpace(p.SrcIp) || string.IsNullOrWhiteSpace(p.DstIp))
            return;

        RefreshLocalIpsIfNeeded(force: false);

        bool srcLocal = _localIps.Contains(p.SrcIp);
        bool dstLocal = _localIps.Contains(p.DstIp);

        if (!srcLocal && !dstLocal)
            return;

        string remoteIp = srcLocal ? p.DstIp : p.SrcIp;
        int remotePort = srcLocal ? (p.DstPort ?? -1) : (p.SrcPort ?? -1);

        var endpoint = new RemoteEndpointKey(p.Protocol, remoteIp, remotePort);

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

        if (!_topRemoteByBytes.TryGetValue(row.Pid, out var best) || bytes > best.Bytes)
        {
            _topRemoteByBytes[row.Pid] = (endpoint, bytes);
            row.TopRemoteEndpoint = endpoint.ToString();
        }

        // Beaconing based on new outbound flow starts.
        if (!(srcLocal && !dstLocal))
            return;

        DateTime utc = p.Timestamp.Kind == DateTimeKind.Utc ? p.Timestamp : p.Timestamp.ToUniversalTime();
        if (!IsNewOutboundFlowStart(row.Pid, p, endpoint, utc))
            return;

        var bKey = (row.Pid, endpoint);
        if (!_beaconStates.TryGetValue(bKey, out var st))
        {
            st = new BeaconState();
            _beaconStates[bKey] = st;
        }

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

    private void RefreshLocalIpsIfNeeded(bool force)
    {
        var now = DateTime.UtcNow;
        if (!force && (now - _lastLocalIpsRefreshUtc) < LocalIpsRefreshInterval)
            return;

        var fresh = _localAddressService.GetLocalIpStrings();
        _localIps = new HashSet<string>(fresh, StringComparer.OrdinalIgnoreCase);
        _lastLocalIpsRefreshUtc = now;
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

            row.BeaconSuspected = true;
            row.BeaconIntervalSec = candidate.MeanSec;
            row.BeaconCv = candidate.Cv;
            row.BeaconSamples = candidate.Samples;
        }
    }

    private readonly record struct RemoteEndpointKey(string Protocol, string Ip, int Port)
    {
        public override string ToString()
            => Port > 0 ? $"{Protocol} {Ip}:{Port}" : $"{Protocol} {Ip}";
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
