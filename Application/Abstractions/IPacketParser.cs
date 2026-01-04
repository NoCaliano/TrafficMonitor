using Domain.Models;

namespace Application.Abstractions;

public interface IPacketParser
{
    PacketInfo Parse(DateTime timestamp, int length, object rawCapture);
}