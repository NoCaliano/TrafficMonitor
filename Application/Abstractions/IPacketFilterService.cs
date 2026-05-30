using Application.Filtering;
using Domain.Models;

namespace Application.Abstractions;

public interface IPacketFilterService
{
    bool MatchesUiFilter(PacketInfo p, PacketFilterModel f);
    Func<PacketInfo, bool>? CompileUiFilter(PacketFilterModel f);
    bool TryCompileDisplayFilter(string? expression, out Func<PacketInfo, bool>? predicate, out string? error);
}
