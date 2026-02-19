using Domain.Models;

namespace Presentation.Services;

internal sealed class FlowFilterService : IFlowFilterService
{
    private FlowKey? _active;
    private bool _includeReverse;

    public bool IsActive => _active.HasValue;
    public FlowKey? ActiveFilter => _active;

    public void ApplyFilter(FlowKey key, bool includeReverse)
    {
        _active = key;
        _includeReverse = includeReverse;
    }

    public void Clear()
    {
        _active = null;
        _includeReverse = false;
    }

    public bool Matches(PacketInfo p)
    {
        if (!_active.HasValue) return true;

        var key = _active.Value;

        if (!string.Equals(p.Protocol, key.Protocol, StringComparison.OrdinalIgnoreCase))
            return false;

        bool direct =
            p.SrcIp == key.SrcIp &&
            p.DstIp == key.DstIp &&
            p.SrcPort == key.SrcPort &&
            p.DstPort == key.DstPort;

        if (direct) return true;
        if (!_includeReverse) return false;

        bool reverse =
            p.SrcIp == key.DstIp &&
            p.DstIp == key.SrcIp &&
            p.SrcPort == key.DstPort &&
            p.DstPort == key.SrcPort;

        return reverse;
    }

    public string FormatFilterText()
    {
        if (!_active.HasValue) return string.Empty;
        var k = _active.Value;
        return _includeReverse
            ? $"Flow(both): {FormatFlow(k)}"
            : $"Flow: {FormatFlow(k)}";
    }

    private static string FormatFlow(FlowKey k)
        => $"{k.Protocol} {k.SrcIp}:{k.SrcPort} → {k.DstIp}:{k.DstPort}";
}
