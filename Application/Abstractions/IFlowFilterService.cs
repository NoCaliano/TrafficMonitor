using Domain.Models;

namespace Application.Abstractions;

public interface IFlowFilterService
{
    bool IsActive { get; }
    FlowKey? ActiveFilter { get; }
    void ApplyFilter(FlowKey key, bool includeReverse);
    void Clear();
    bool Matches(PacketInfo p);
    string FormatFilterText();
}
