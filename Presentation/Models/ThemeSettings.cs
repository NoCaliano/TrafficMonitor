using System;

namespace Presentation.Models;

public enum AppThemeKind
{
    Light,
    Night
}

public sealed class ThemeSettings
{
    public string Theme { get; set; } = AppThemeKind.Light.ToString();

    public AppThemeKind GetThemeKind()
        => Enum.TryParse<AppThemeKind>(Theme, ignoreCase: true, out var themeKind)
            ? themeKind
            : AppThemeKind.Light;

    public static ThemeSettings CreateNormalized(ThemeSettings? settings)
    {
        AppThemeKind themeKind = settings?.GetThemeKind() ?? AppThemeKind.Light;
        return new ThemeSettings
        {
            Theme = themeKind.ToString()
        };
    }
}
