using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace Presentation.Helpers;

public sealed class BoolToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        bool isVisible = value is bool visible && visible;
        bool invert = parameter is string s && s.Equals("Invert", StringComparison.OrdinalIgnoreCase);
        if (invert)
            isVisible = !isVisible;

        return isVisible ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => value is Visibility visibility && visibility == Visibility.Visible;
}
