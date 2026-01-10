// Відповідає за агрегацію пакетів у потоки (flows).
using Domain.Models;

namespace Application.Abstractions;

public interface IFlowAggregator
{
    void Add(PacketInfo packet);
    IReadOnlyList<FlowInfo> SnapshotTop(int take);
    void Reset();
}
