using Domain.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace Application.Networking;

public enum HostResolutionSource
{
    DnsAnswer,
    TlsSni,
    CertificateName
}

public sealed record HostResolutionHint(
    string Host,
    HostResolutionSource Source,
    int ConfidenceScore,
    string ConfidenceLabel,
    DateTime LastSeenUtc,
    int ObservationCount)
{
    public string SourceLabel => Source switch
    {
        HostResolutionSource.DnsAnswer => "DNS answer",
        HostResolutionSource.TlsSni => "TLS SNI",
        HostResolutionSource.CertificateName => "Certificate name",
        _ => "Observed hint"
    };

    public string SummaryLabel => $"{SourceLabel} • {ConfidenceLabel}";
}

public sealed class HostResolutionService
{
    private static readonly TimeSpan EntryTtl = TimeSpan.FromMinutes(20);

    private readonly object _gate = new();
    private readonly Dictionary<string, Dictionary<string, ResolutionEntry>> _ipToHosts = new(StringComparer.OrdinalIgnoreCase);

    public void Observe(PacketInfo packet)
    {
        DateTime observedAtUtc = packet.Timestamp.Kind == DateTimeKind.Utc
            ? packet.Timestamp
            : packet.Timestamp.ToUniversalTime();

        lock (_gate)
        {
            if (packet.DnsAnswerIps.Count > 0 && !string.IsNullOrWhiteSpace(packet.DnsQueryName))
            {
                string dnsHost = NormalizeHost(packet.DnsQueryName);
                foreach (var candidate in packet.DnsAnswerIps)
                    ObserveHost(candidate, dnsHost, HostResolutionSource.DnsAnswer, observedAtUtc);
            }

            if (!string.IsNullOrWhiteSpace(packet.ServerNameHint) && !string.IsNullOrWhiteSpace(packet.DstIp))
            {
                ObserveHost(
                    packet.DstIp,
                    packet.ServerNameHint,
                    HostResolutionSource.TlsSni,
                    observedAtUtc);
            }

            if (!string.IsNullOrWhiteSpace(packet.DstIp) && packet.TlsCertificateNames.Count > 0)
            {
                for (int i = 0; i < packet.TlsCertificateNames.Count; i++)
                {
                    ObserveHost(
                        packet.DstIp,
                        packet.TlsCertificateNames[i],
                        HostResolutionSource.CertificateName,
                        observedAtUtc);
                }
            }

            CleanupExpiredUnsafe(observedAtUtc);
        }
    }

    public bool TryResolve(string ip, out string host)
    {
        host = string.Empty;
        if (!TryResolveBest(ip, out var bestHint))
            return false;

        host = bestHint.Host;
        return true;
    }

    public bool TryResolveBest(string ip, out HostResolutionHint hint)
    {
        hint = default!;
        string normalizedIp = NormalizeIp(ip);
        if (string.IsNullOrWhiteSpace(normalizedIp))
            return false;

        lock (_gate)
        {
            var hints = BuildHintsUnsafe(normalizedIp, DateTime.UtcNow, take: 1);
            if (hints.Count == 0)
                return false;

            hint = hints[0];
            return true;
        }
    }

    public IReadOnlyList<HostResolutionHint> GetHints(string ip, int take = 3)
    {
        string normalizedIp = NormalizeIp(ip);
        if (string.IsNullOrWhiteSpace(normalizedIp) || take <= 0)
            return Array.Empty<HostResolutionHint>();

        lock (_gate)
            return BuildHintsUnsafe(normalizedIp, DateTime.UtcNow, take);
    }

    public string ResolveHostOrOriginal(string hostOrIp)
    {
        if (string.IsNullOrWhiteSpace(hostOrIp))
            return string.Empty;

        return TryResolve(hostOrIp, out var resolvedHost) ? resolvedHost : hostOrIp;
    }

    public void Reset()
    {
        lock (_gate)
            _ipToHosts.Clear();
    }

    private void ObserveHost(string ip, string host, HostResolutionSource source, DateTime observedAtUtc)
    {
        string normalizedIp = NormalizeIp(ip);
        string normalizedHost = NormalizeHost(host);
        if (string.IsNullOrWhiteSpace(normalizedIp) || string.IsNullOrWhiteSpace(normalizedHost))
            return;

        if (IPAddress.TryParse(normalizedHost, out _))
            return;

        if (!_ipToHosts.TryGetValue(normalizedIp, out var hostsByIp))
        {
            hostsByIp = new Dictionary<string, ResolutionEntry>(StringComparer.OrdinalIgnoreCase);
            _ipToHosts[normalizedIp] = hostsByIp;
        }

        if (!hostsByIp.TryGetValue(normalizedHost, out var entry))
        {
            entry = new ResolutionEntry(normalizedHost);
            hostsByIp[normalizedHost] = entry;
        }

        entry.Observe(source, observedAtUtc);
    }

    private IReadOnlyList<HostResolutionHint> BuildHintsUnsafe(string normalizedIp, DateTime nowUtc, int take)
    {
        CleanupExpiredUnsafe(nowUtc);

        if (!_ipToHosts.TryGetValue(normalizedIp, out var hostsByIp) || hostsByIp.Count == 0)
            return Array.Empty<HostResolutionHint>();

        return hostsByIp.Values
            .Select(static entry => entry.ToHint())
            .OrderByDescending(static hint => hint.ConfidenceScore)
            .ThenByDescending(static hint => hint.ObservationCount)
            .ThenByDescending(static hint => hint.LastSeenUtc)
            .ThenBy(static hint => GetSourcePriority(hint.Source))
            .ThenBy(static hint => IsWildcardHost(hint.Host))
            .ThenBy(static hint => hint.Host, StringComparer.OrdinalIgnoreCase)
            .Take(take)
            .ToArray();
    }

    private void CleanupExpiredUnsafe(DateTime nowUtc)
    {
        if (_ipToHosts.Count == 0)
            return;

        List<string>? emptyIps = null;
        foreach (var pair in _ipToHosts)
        {
            List<string>? expiredHosts = null;
            foreach (var hostPair in pair.Value)
            {
                if ((nowUtc - hostPair.Value.LastSeenUtc) <= EntryTtl)
                    continue;

                expiredHosts ??= new List<string>();
                expiredHosts.Add(hostPair.Key);
            }

            if (expiredHosts is not null)
            {
                foreach (var host in expiredHosts)
                    pair.Value.Remove(host);
            }

            if (pair.Value.Count == 0)
            {
                emptyIps ??= new List<string>();
                emptyIps.Add(pair.Key);
            }
        }

        if (emptyIps is null)
            return;

        foreach (var ip in emptyIps)
            _ipToHosts.Remove(ip);
    }

    private static int GetSourcePriority(HostResolutionSource source)
        => source switch
        {
            HostResolutionSource.DnsAnswer => 3,
            HostResolutionSource.TlsSni => 2,
            HostResolutionSource.CertificateName => 1,
            _ => 0
        };

    private static int GetConfidenceScore(HostResolutionSource source, string host)
        => source switch
        {
            HostResolutionSource.DnsAnswer => 96,
            HostResolutionSource.TlsSni => 88,
            HostResolutionSource.CertificateName => IsWildcardHost(host) ? 52 : 64,
            _ => 35
        };

    private static string GetConfidenceLabel(int confidenceScore)
        => confidenceScore >= 85
            ? "High"
            : confidenceScore >= 60
                ? "Medium"
                : "Low";

    private static bool IsWildcardHost(string host)
        => !string.IsNullOrWhiteSpace(host) && host.StartsWith("*.", StringComparison.Ordinal);

    private static string NormalizeHost(string host)
        => string.IsNullOrWhiteSpace(host)
            ? string.Empty
            : host.Trim().TrimEnd('.').ToLowerInvariant();

    private static string NormalizeIp(string ip)
        => string.IsNullOrWhiteSpace(ip)
            ? string.Empty
            : ip.Trim();

    private sealed class ResolutionEntry
    {
        private readonly HashSet<HostResolutionSource> _sources = new();

        public ResolutionEntry(string host)
        {
            Host = host;
        }

        public string Host { get; }
        public DateTime LastSeenUtc { get; private set; }
        public int ObservationCount { get; private set; }

        public void Observe(HostResolutionSource source, DateTime observedAtUtc)
        {
            ObservationCount++;
            _sources.Add(source);

            if (observedAtUtc > LastSeenUtc)
                LastSeenUtc = observedAtUtc;
        }

        public HostResolutionHint ToHint()
        {
            HostResolutionSource bestSource = _sources
                .OrderByDescending(source => GetConfidenceScore(source, Host))
                .ThenByDescending(GetSourcePriority)
                .FirstOrDefault();

            int confidenceScore = GetConfidenceScore(bestSource, Host);
            return new HostResolutionHint(
                Host,
                bestSource,
                confidenceScore,
                GetConfidenceLabel(confidenceScore),
                LastSeenUtc,
                ObservationCount);
        }
    }
}
