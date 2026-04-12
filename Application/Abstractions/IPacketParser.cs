using Domain.Models;

namespace Application.Abstractions;

public enum PacketParseProfile
{
    Live,
    Full
}

public interface IPacketParser
{
    PacketInfo Parse(DateTime timestamp, int length, object rawCapture, PacketParseProfile profile = PacketParseProfile.Live);
}
