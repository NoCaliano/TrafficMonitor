using System;
using System.Collections.Generic;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace Presentation.Helpers;

public sealed class ProtocolBrushConverter : IValueConverter
{
    private static readonly Brush DefaultChipBrush = Create("#FFE8EEF4");
    private static readonly Brush DefaultBorderBrush = Create("#FFD5E0E9");

    private static readonly IReadOnlyDictionary<string, (Brush Fill, Brush Border)> Palette =
        new Dictionary<string, (Brush Fill, Brush Border)>(StringComparer.OrdinalIgnoreCase)
        {
            ["ARP"] = (Create("#FFF7E7C7"), Create("#FFE7C98B")),
            ["DNS"] = (Create("#FFE0F0D8"), Create("#FFBAD6AC")),
            ["TCP"] = (Create("#FFDCEAF9"), Create("#FFB7CFE8")),
            ["UDP"] = (Create("#FFE7E0F7"), Create("#FFCCC0E7")),
            ["HTTP"] = (Create("#FFF8E0D2"), Create("#FFE8C0A7")),
            ["TLS"] = (Create("#FFE3F1EA"), Create("#FFC0DCCF")),
            ["TLSV1.0"] = (Create("#FFE3F1EA"), Create("#FFC0DCCF")),
            ["TLSV1.1"] = (Create("#FFE3F1EA"), Create("#FFC0DCCF")),
            ["TLSV1.2"] = (Create("#FFE3F1EA"), Create("#FFC0DCCF")),
            ["TLSV1.3"] = (Create("#FFE3F1EA"), Create("#FFC0DCCF")),
            ["SSL"] = (Create("#FFE3F1EA"), Create("#FFC0DCCF")),
            ["QUIC"] = (Create("#FFF8E1EA"), Create("#FFE7BED0")),
            ["ICMPV4"] = (Create("#FFFBE6CC"), Create("#FFEED0A2")),
            ["ICMPV6"] = (Create("#FFFBE6CC"), Create("#FFEED0A2")),
            ["ICMP"] = (Create("#FFFBE6CC"), Create("#FFEED0A2")),
            ["IPV4"] = (Create("#FFE7F3F5"), Create("#FFC2DDE2")),
            ["IPV6"] = (Create("#FFE3EDF8"), Create("#FFC1D5EC")),
            ["DHCP"] = (Create("#FFF3E5D9"), Create("#FFE2C4AF")),
            ["NTP"] = (Create("#FFE3F2EE"), Create("#FFC0DDD3")),
            ["SSH"] = (Create("#FFE7E6F6"), Create("#FFC8C5E7")),
            ["RDP"] = (Create("#FFF0E4F6"), Create("#FFD8C1E7")),
            ["IGMP"] = (Create("#FFF1ECD8"), Create("#FFDFD0A7")),
        };

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        string protocol = (value as string)?.Trim() ?? string.Empty;
        string normalized = protocol.ToUpperInvariant();

        if (!Palette.TryGetValue(normalized, out var brushes))
        {
            if (normalized.StartsWith("TLS", StringComparison.OrdinalIgnoreCase))
                brushes = Palette["TLS"];
            else if (normalized.StartsWith("ICMP", StringComparison.OrdinalIgnoreCase))
                brushes = Palette["ICMP"];
            else
                brushes = (DefaultChipBrush, DefaultBorderBrush);
        }

        string mode = (parameter as string) ?? "Fill";
        return string.Equals(mode, "Border", StringComparison.OrdinalIgnoreCase)
            ? brushes.Border
            : brushes.Fill;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => Binding.DoNothing;

    private static SolidColorBrush Create(string hex)
    {
        var brush = (SolidColorBrush)new BrushConverter().ConvertFromString(hex)!;
        brush.Freeze();
        return brush;
    }
}
