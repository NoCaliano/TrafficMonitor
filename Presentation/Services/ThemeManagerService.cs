using Presentation.Models;
using System;
using System.Windows;

namespace Presentation.Services;

public sealed class ThemeManagerService
{
    private static readonly Uri LightThemeUri = new("Themes/SlateBlueTheme.xaml", UriKind.Relative);
    private static readonly Uri NightThemeUri = new("Themes/NightTheme.xaml", UriKind.Relative);

    private readonly ThemeSettingsStore _themeSettingsStore;
    private readonly MainWindowManager _mainWindowManager;
    private bool _isInitialized;

    public event EventHandler? ThemeChanged;

    public AppThemeKind CurrentTheme { get; private set; } = AppThemeKind.Light;

    public ThemeManagerService(
        ThemeSettingsStore themeSettingsStore,
        MainWindowManager mainWindowManager)
    {
        _themeSettingsStore = themeSettingsStore;
        _mainWindowManager = mainWindowManager;
    }

    public void Initialize()
    {
        if (_isInitialized)
            return;

        var settings = _themeSettingsStore.Load();
        ApplyThemeResources(settings.GetThemeKind());
        _isInitialized = true;
    }

    public bool ApplyTheme(AppThemeKind themeKind)
    {
        if (!_isInitialized)
            Initialize();

        if (CurrentTheme == themeKind && IsThemeDictionaryApplied(themeKind))
            return false;

        ApplyThemeResources(themeKind);
        _themeSettingsStore.Save(new ThemeSettings
        {
            Theme = themeKind.ToString()
        });

        ThemeChanged?.Invoke(this, EventArgs.Empty);

        if (System.Windows.Application.Current?.MainWindow is not null)
            _mainWindowManager.RecreateMainWindow();

        return true;
    }

    private void ApplyThemeResources(AppThemeKind themeKind)
    {
        var application = System.Windows.Application.Current
            ?? throw new InvalidOperationException("Theme manager requires an active WPF application instance.");

        var themeDictionary = new ResourceDictionary
        {
            Source = GetThemeUri(themeKind)
        };

        var dictionaries = application.Resources.MergedDictionaries;
        if (dictionaries.Count == 0)
            dictionaries.Add(themeDictionary);
        else
            dictionaries[0] = themeDictionary;

        CurrentTheme = themeKind;
    }

    private bool IsThemeDictionaryApplied(AppThemeKind themeKind)
    {
        var source = System.Windows.Application.Current?.Resources.MergedDictionaries.Count > 0
            ? System.Windows.Application.Current.Resources.MergedDictionaries[0].Source
            : null;

        return source == GetThemeUri(themeKind);
    }

    private static Uri GetThemeUri(AppThemeKind themeKind)
        => themeKind == AppThemeKind.Night
            ? NightThemeUri
            : LightThemeUri;
}
