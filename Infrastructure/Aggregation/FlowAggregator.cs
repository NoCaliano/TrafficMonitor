// Відповідає за потокобезпечну агрегацію пакетів у bi-directional flows + визначення Direction.
using Application.Abstractions;
using Domain.Models;
using System.Collections.Concurrent;

namespace Infrastructure.Aggregation;

public sealed class FlowAggregator : IFlowAggregator
{
    private readonly ConcurrentDictionary<FlowKey, FlowInfo> _flows = new();

    // Відповідає за сервіс локальних IP адрес.
    private readonly ILocalAddressService _localAddressService;

    // Відповідає за кеш локальних IP (щоб не рахувати на кожному пакеті).
    private HashSet<string> _localIps = new(StringComparer.OrdinalIgnoreCase);
    private DateTime _lastLocalIpsRefreshUtc = DateTime.MinValue;
    private static readonly TimeSpan LocalIpsRefreshInterval = TimeSpan.FromSeconds(5);

    public FlowAggregator(ILocalAddressService localAddressService)
    {
        _localAddressService = localAddressService;
        RefreshLocalIpsIfNeeded(force: true);
    }

    public void Add(PacketInfo packet)
    {
        if (string.IsNullOrWhiteSpace(packet.SrcIp) || string.IsNullOrWhiteSpace(packet.DstIp))
            return;

        RefreshLocalIpsIfNeeded(force: false);

        // Відповідає за створення нормалізованого ключа A<=B (1 ключ на A<->B).
        var key = MakeNormalizedKey(packet);

        // Відповідає за визначення, чи цей пакет йде в напрямку A->B або B->A у рамках key.
        bool aToB = IsPacketAToB(packet, key);

        // Відповідає за визначення локальності сторін (для Sent/Recv та Direction).
        bool srcLocal = _localIps.Contains(packet.SrcIp);
        bool dstLocal = _localIps.Contains(packet.DstIp);

        _flows.AddOrUpdate(
            key,
            _ =>
            {
                var t = packet.Timestamp;

                var fi = new FlowInfo
                {
                    Key = key,
                    Packets = 1,
                    Bytes = packet.Length,
                    FirstSeen = t,
                    LastSeen = t,

                    // Відповідає за напрямок відносно локального ПК (по першому пакету).
                    Direction = DetermineDirectionFromLocals(srcLocal, dstLocal),
                };

                // Відповідає за A->B / B->A лічильники.
                if (aToB) { fi.PacketsAToB = 1; fi.BytesAToB = packet.Length; }
                else { fi.PacketsBToA = 1; fi.BytesBToA = packet.Length; }

                // Відповідає за Sent/Recv лічильники (відносно локального ПК).
                if (srcLocal) { fi.SentPackets = 1; fi.SentBytes = packet.Length; }
                else if (dstLocal) { fi.RecvPackets = 1; fi.RecvBytes = packet.Length; }

                // Відповідає за заповнення Local/Remote endpoint, якщо можемо визначити.
                TryFillLocalRemote(fi, packet, srcLocal, dstLocal);

                return fi;
            },
            (_, existing) =>
            {
                lock (existing)
                {
                    existing.Packets += 1;
                    existing.Bytes += packet.Length;
                    existing.LastSeen = packet.Timestamp;

                    // Відповідає за A->B / B->A лічильники.
                    if (aToB) { existing.PacketsAToB += 1; existing.BytesAToB += packet.Length; }
                    else { existing.PacketsBToA += 1; existing.BytesBToA += packet.Length; }

                    // Відповідає за Sent/Recv лічильники.
                    if (srcLocal) { existing.SentPackets += 1; existing.SentBytes += packet.Length; }
                    else if (dstLocal) { existing.RecvPackets += 1; existing.RecvBytes += packet.Length; }

                    // Якщо раніше не визначили Local/Remote — пробуємо визначити тепер.
                    if (string.IsNullOrWhiteSpace(existing.LocalIp))
                        TryFillLocalRemote(existing, packet, srcLocal, dstLocal);

                    // Якщо direction ще unknown, пробуємо уточнити (може локальні IP з'явились/оновились).
                    if (existing.Direction == FlowDirection.Unknown)
                    {
                        var d = DetermineDirectionFromLocals(srcLocal, dstLocal);
                        if (d != FlowDirection.Unknown)
                            existing.Direction = d;
                    }
                }
                return existing;
            });
    }

    public IReadOnlyList<FlowInfo> SnapshotTop(int take) =>
        _flows.Values
            .OrderByDescending(f => f.Bytes)
            .Take(take)
            .ToList();

    public void Reset() => _flows.Clear();

    // -------------------- Direction helpers --------------------

    // Відповідає за визначення напрямку (In/Out/Local/Unknown) за локальністю сторін конкретного пакета.
    private static FlowDirection DetermineDirectionFromLocals(bool srcLocal, bool dstLocal)
    {
        if (srcLocal && !dstLocal) return FlowDirection.Outbound;
        if (!srcLocal && dstLocal) return FlowDirection.Inbound;
        if (srcLocal && dstLocal) return FlowDirection.Local;
        return FlowDirection.Unknown;
    }

    // Відповідає за заповнення Local/Remote endpoint в FlowInfo.
    private static void TryFillLocalRemote(FlowInfo fi, PacketInfo p, bool srcLocal, bool dstLocal)
    {
        if (srcLocal && !dstLocal)
        {
            fi.LocalIp = p.SrcIp;
            fi.LocalPort = p.SrcPort;
            fi.RemoteIp = p.DstIp;
            fi.RemotePort = p.DstPort;
            fi.Direction = FlowDirection.Outbound;
        }
        else if (!srcLocal && dstLocal)
        {
            fi.LocalIp = p.DstIp;
            fi.LocalPort = p.DstPort;
            fi.RemoteIp = p.SrcIp;
            fi.RemotePort = p.SrcPort;
            fi.Direction = FlowDirection.Inbound;
        }
        else if (srcLocal && dstLocal)
        {
            // Для Local можемо визначити Local/Remote умовно, але зазвичай це мало корисно
            fi.Direction = FlowDirection.Local;
        }
    }

    // -------------------- Key normalization --------------------

    // Відповідає за порівняння endpoint-ів, щоб нормалізувати ключ (A<=B).
    private static int CompareEndpoint(string ip1, int? port1, string ip2, int? port2)
    {
        int c = string.CompareOrdinal(ip1 ?? "", ip2 ?? "");
        if (c != 0) return c;

        int p1 = port1 ?? -1;
        int p2 = port2 ?? -1;
        return p1.CompareTo(p2);
    }

    // Відповідає за створення НОРМАЛІЗОВАНОГО bi-directional ключа (один ключ на A<->B).
    private static FlowKey MakeNormalizedKey(PacketInfo p)
    {
        var aIp = p.SrcIp;
        var aPort = p.SrcPort;
        var bIp = p.DstIp;
        var bPort = p.DstPort;

        // Якщо (src,srcPort) > (dst,dstPort) — міняємо місцями.
        if (CompareEndpoint(aIp, aPort, bIp, bPort) > 0)
        {
            (aIp, bIp) = (bIp, aIp);
            (aPort, bPort) = (bPort, aPort);
        }

        return new FlowKey(p.Protocol, aIp, aPort, bIp, bPort);
    }

    // Відповідає за перевірку, чи пакет іде A->B у нормалізованому ключі.
    private static bool IsPacketAToB(PacketInfo p, FlowKey normalizedKey)
    {
        return p.SrcIp == normalizedKey.SrcIp
            && p.SrcPort == normalizedKey.SrcPort
            && p.DstIp == normalizedKey.DstIp
            && p.DstPort == normalizedKey.DstPort;
    }

    // -------------------- Local IP cache --------------------

    // Відповідає за періодичне оновлення кешу локальних IP.
    private void RefreshLocalIpsIfNeeded(bool force)
    {
        var now = DateTime.UtcNow;
        if (!force && (now - _lastLocalIpsRefreshUtc) < LocalIpsRefreshInterval)
            return;

        var fresh = _localAddressService.GetLocalIpStrings();
        _localIps = new HashSet<string>(fresh, StringComparer.OrdinalIgnoreCase);
        _lastLocalIpsRefreshUtc = now;
    }
}
