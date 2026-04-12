using Domain.Models;
using System;
using System.Collections.Generic;

namespace Presentation.Services;

public sealed class HostResolutionService
{
    private static readonly TimeSpan EntryTtl = TimeSpan.FromMinutes(20);

    private readonly object _gate = new();
    private readonly Dictionary<string, ResolutionEntry> _ipToHost = new(StringComparer.OrdinalIgnoreCase);

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
                if (!string.IsNullOrWhiteSpace(dnsHost))
                {
                    foreach (var candidate in packet.DnsAnswerIps)
                    {
                        string ip = NormalizeIp(candidate);
                        if (string.IsNullOrWhiteSpace(ip))
                            continue;

                        _ipToHost[ip] = new ResolutionEntry(dnsHost, observedAtUtc);
                    }
                }
            }

            if (!string.IsNullOrWhiteSpace(packet.ServerNameHint) && !string.IsNullOrWhiteSpace(packet.DstIp))
            {
                string serverName = NormalizeHost(packet.ServerNameHint);
                string remoteIp = NormalizeIp(packet.DstIp);
                if (!string.IsNullOrWhiteSpace(serverName) && !string.IsNullOrWhiteSpace(remoteIp))
                    _ipToHost[remoteIp] = new ResolutionEntry(serverName, observedAtUtc);
            }

            CleanupExpiredUnsafe(observedAtUtc);
        }
    }

    public bool TryResolve(string ip, out string host)
    {
        host = string.Empty;
        string normalizedIp = NormalizeIp(ip);
        if (string.IsNullOrWhiteSpace(normalizedIp))
            return false;

        lock (_gate)
        {
            CleanupExpiredUnsafe(DateTime.UtcNow);

            if (!_ipToHost.TryGetValue(normalizedIp, out var entry))
                return false;

            host = entry.Host;
            return !string.IsNullOrWhiteSpace(host);
        }
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
            _ipToHost.Clear();
    }

    private void CleanupExpiredUnsafe(DateTime nowUtc)
    {
        if (_ipToHost.Count == 0)
            return;

        List<string>? expiredKeys = null;
        foreach (var pair in _ipToHost)
        {
            if ((nowUtc - pair.Value.LastSeenUtc) <= EntryTtl)
                continue;

            expiredKeys ??= new List<string>();
            expiredKeys.Add(pair.Key);
        }

        if (expiredKeys is null)
            return;

        foreach (var key in expiredKeys)
            _ipToHost.Remove(key);
    }

    private static string NormalizeHost(string host)
        => string.IsNullOrWhiteSpace(host)
            ? string.Empty
            : host.Trim().TrimEnd('.').ToLowerInvariant();

    private static string NormalizeIp(string ip)
        => string.IsNullOrWhiteSpace(ip)
            ? string.Empty
            : ip.Trim();

    private readonly record struct ResolutionEntry(string Host, DateTime LastSeenUtc);
}
