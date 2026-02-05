// Відповідає за модель UI-фільтра (поля + оператори) для PacketsView.Filter.
namespace Presentation.Models;

public enum TextMatchOp
{
    Any = 0,
    Equals = 1,
    NotEquals = 2,
    Contains = 3,
    NotContains = 4
}

public enum NumberMatchOp
{
    Any = 0,
    Equals = 1,
    NotEquals = 2
}

public sealed class PacketFilterModel
{
    // ---- IP ----
    public TextMatchOp SrcIpOp { get; set; } = TextMatchOp.Any;
    public string SrcIpValue { get; set; } = "";

    public TextMatchOp DstIpOp { get; set; } = TextMatchOp.Any;
    public string DstIpValue { get; set; } = "";

    // Any IP працює як: (Src OR Dst) match
    public TextMatchOp AnyIpOp { get; set; } = TextMatchOp.Any;
    public string AnyIpValue { get; set; } = "";

    // ---- Ports ----
    public NumberMatchOp SrcPortOp { get; set; } = NumberMatchOp.Any;
    public int? SrcPortValue { get; set; }

    public NumberMatchOp DstPortOp { get; set; } = NumberMatchOp.Any;
    public int? DstPortValue { get; set; }

    public NumberMatchOp AnyPortOp { get; set; } = NumberMatchOp.Any;
    public int? AnyPortValue { get; set; }

    // ---- Protocol ----
    public TextMatchOp ProtocolOp { get; set; } = TextMatchOp.Any;
    public string ProtocolValue { get; set; } = "";

    // ---- Info ----
    public TextMatchOp InfoOp { get; set; } = TextMatchOp.Any;
    public string InfoValue { get; set; } = "";

    // ---- Length ----
    public int? MinLength { get; set; }
    public int? MaxLength { get; set; }

    // Time range (UTC). Inclusive: [from..to]
    public DateTime? TimeFromUtc { get; set; }
    public DateTime? TimeToUtc { get; set; }

    // Відповідає за швидку перевірку "фільтр порожній"
    public bool IsEmpty =>
        SrcIpOp == TextMatchOp.Any && string.IsNullOrWhiteSpace(SrcIpValue) &&
        DstIpOp == TextMatchOp.Any && string.IsNullOrWhiteSpace(DstIpValue) &&
        AnyIpOp == TextMatchOp.Any && string.IsNullOrWhiteSpace(AnyIpValue) &&
        SrcPortOp == NumberMatchOp.Any && SrcPortValue is null &&
        DstPortOp == NumberMatchOp.Any && DstPortValue is null &&
        AnyPortOp == NumberMatchOp.Any && AnyPortValue is null &&
        ProtocolOp == TextMatchOp.Any && string.IsNullOrWhiteSpace(ProtocolValue) &&
        InfoOp == TextMatchOp.Any && string.IsNullOrWhiteSpace(InfoValue) &&
        MinLength is null &&
        MaxLength is null &&
        TimeFromUtc is null &&
        TimeToUtc is null;
}