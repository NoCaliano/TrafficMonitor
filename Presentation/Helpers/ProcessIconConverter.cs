using System;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace Presentation.Helpers;

public sealed class ProcessIconConverter : IValueConverter
{
    public object? Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is int pid)
        {
            try
            {
                var img = ProcessIconHelper.GetIcon(pid);
                if (img is not null) return img;
            }
            catch { }
        }
        return null;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotSupportedException();
    }
}
