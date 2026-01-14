// Відповідає за потокобезпечну агрегацію пакетів у flows + визначення напрямку (Direction).
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

        var key = new FlowKey(packet.Protocol, packet.SrcIp, packet.SrcPort, packet.DstIp, packet.DstPort);
        var dir = DetermineDirection(key);

        _flows.AddOrUpdate(
            key,
            _ =>
            {
                var t = packet.Timestamp;
                return new FlowInfo
                {
                    Key = key,
                    Direction = dir,
                    Packets = 1,
                    Bytes = packet.Length,
                    FirstSeen = t,
                    LastSeen = t
                };
            },
            (_, existing) =>
            {
                // Відповідає за оновлення лічильників потоку
                lock (existing)
                {
                    existing.Packets += 1;
                    existing.Bytes += packet.Length;
                    existing.LastSeen = packet.Timestamp;
                    // Direction не змінюємо: він визначається для цього ключа стабільно
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

    // Відповідає за визначення напрямку (In/Out/Local/Unknown) для flow key.
    private FlowDirection DetermineDirection(FlowKey key)
    {
        bool srcLocal = _localIps.Contains(key.SrcIp);
        bool dstLocal = _localIps.Contains(key.DstIp);

        if (srcLocal && !dstLocal) return FlowDirection.Outbound;
        if (!srcLocal && dstLocal) return FlowDirection.Inbound;
        if (srcLocal && dstLocal) return FlowDirection.Local;
        return FlowDirection.Unknown;
    }

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
