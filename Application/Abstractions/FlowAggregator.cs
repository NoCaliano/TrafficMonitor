// Відповідає за агрегацію пакетів у flows.
using Application.Abstractions;
using Domain.Models;
using System.Collections.Concurrent;

namespace Infrastructure.Aggregation;

public sealed class FlowAggregator : IFlowAggregator
{
    private readonly ConcurrentDictionary<FlowKey, FlowInfo> _flows = new();

    public void Add(PacketInfo packet)
    {
        if (string.IsNullOrWhiteSpace(packet.SrcIp) || string.IsNullOrWhiteSpace(packet.DstIp))
            return;

        var key = new FlowKey(packet.Protocol, packet.SrcIp, packet.SrcPort, packet.DstIp, packet.DstPort);

        _flows.AddOrUpdate(
            key,
            _ =>
            {
                var t = packet.Timestamp;
                return new FlowInfo
                {
                    Key = key,
                    Packets = 1,
                    Bytes = packet.Length,
                    FirstSeen = t,
                    LastSeen = t
                };
            },
            (_, existing) =>
            {
                existing.Packets += 1;
                existing.Bytes += packet.Length;
                existing.LastSeen = packet.Timestamp;
                return existing;
            });
    }

    public IReadOnlyList<FlowInfo> SnapshotTop(int take) =>
        _flows.Values
            .OrderByDescending(f => f.Bytes)
            .Take(take)
            .ToList();

    public void Reset() => _flows.Clear();
}
