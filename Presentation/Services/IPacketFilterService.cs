using Domain.Models;
using Presentation.Models;

namespace Presentation.Services;

public interface IPacketFilterService
{
    bool MatchesUiFilter(PacketInfo p, PacketFilterModel f);
}
