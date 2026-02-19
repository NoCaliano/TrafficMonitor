using Domain.Models;
using Presentation.Models;

namespace Presentation.Services;

internal sealed class PacketFilterService : IPacketFilterService
{
    public bool MatchesUiFilter(PacketInfo p, PacketFilterModel f)
    {
        static bool MatchText(string? value, TextMatchOp op, string? pattern)
        {
            if (op == TextMatchOp.Any || string.IsNullOrWhiteSpace(pattern))
                return true;

            value ??= "";
            pattern = pattern.Trim();

            return op switch
            {
                TextMatchOp.Equals => string.Equals(value, pattern, StringComparison.OrdinalIgnoreCase),
                TextMatchOp.NotEquals => !string.Equals(value, pattern, StringComparison.OrdinalIgnoreCase),
                TextMatchOp.Contains => value.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0,
                TextMatchOp.NotContains => value.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) < 0,
                _ => true
            };
        }

        static bool MatchNumber(int? value, NumberMatchOp op, int? pattern)
        {
            if (op == NumberMatchOp.Any || pattern is null)
                return true;

            return op switch
            {
                NumberMatchOp.Equals => value == pattern,
                NumberMatchOp.NotEquals => value != pattern,
                _ => true
            };
        }

        // ---- IP Src/Dst ----
        if (!MatchText(p.SrcIp, f.SrcIpOp, f.SrcIpValue)) return false;
        if (!MatchText(p.DstIp, f.DstIpOp, f.DstIpValue)) return false;

        // ---- Any IP (Src OR Dst) ----
        if (f.AnyIpOp != TextMatchOp.Any && !string.IsNullOrWhiteSpace(f.AnyIpValue))
        {
            bool srcOk = MatchText(p.SrcIp, f.AnyIpOp, f.AnyIpValue);
            bool dstOk = MatchText(p.DstIp, f.AnyIpOp, f.AnyIpValue);
            if (!srcOk && !dstOk) return false;
        }

        // ---- Ports ----
        if (!MatchNumber(p.SrcPort, f.SrcPortOp, f.SrcPortValue)) return false;
        if (!MatchNumber(p.DstPort, f.DstPortOp, f.DstPortValue)) return false;

        // ---- Any Port (Src OR Dst) ----
        if (f.AnyPortOp != NumberMatchOp.Any && f.AnyPortValue.HasValue)
        {
            bool srcOk = MatchNumber(p.SrcPort, f.AnyPortOp, f.AnyPortValue);
            bool dstOk = MatchNumber(p.DstPort, f.AnyPortOp, f.AnyPortValue);
            if (!srcOk && !dstOk) return false;
        }

        // ---- Protocol / Info ----
        if (!MatchText(p.Protocol, f.ProtocolOp, f.ProtocolValue)) return false;
        if (!MatchText(p.Info, f.InfoOp, f.InfoValue)) return false;

        // ---- Process ----
        if (!MatchNumber(p.Pid, f.PidOp, f.PidValue)) return false;
        if (!MatchText(p.ProcessName, f.ProcessNameOp, f.ProcessNameValue)) return false;

        // ---- Length range ----
        if (f.MinLength.HasValue && p.Length < f.MinLength.Value) return false;
        if (f.MaxLength.HasValue && p.Length > f.MaxLength.Value) return false;

        // Time range (inclusive) - compare in LOCAL TIME to match what user typed
        if (f.TimeFromUtc.HasValue || f.TimeToUtc.HasValue)
        {
            var tLocal = p.Timestamp; // already local
            DateTime? fromLocal = f.TimeFromUtc?.ToLocalTime();
            DateTime? toLocal = f.TimeToUtc?.ToLocalTime();

            if (fromLocal.HasValue && tLocal < fromLocal.Value) return false;
            if (toLocal.HasValue && tLocal > toLocal.Value) return false;
        }

        return true;
    }
}
