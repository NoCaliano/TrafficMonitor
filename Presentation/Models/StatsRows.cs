// Відповідає за рядки статистики для вкладки Stats (Top Hosts / Top Ports).
namespace Presentation.Models;

public sealed class HostStatRow
{
    public string Host { get; init; } = "";
    public string Role { get; init; } = ""; // "Remote" / "Local" / "Unknown" (опційно)
    public int Flows { get; init; }
    public int Packets { get; init; }
    public long Bytes { get; init; }
    public DateTime LastSeen { get; init; }
}

public sealed class PortStatRow
{
    public string Protocol { get; init; } = "";
    public int Port { get; init; }
    public string Service { get; init; } = "";
    public int Flows { get; init; }
    public int Packets { get; init; }
    public long Bytes { get; init; }
    public DateTime LastSeen { get; init; }
}
