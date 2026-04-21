using Presentation.Models;
using System;
using System.IO;
using System.Text;
using System.Text.Json;

namespace Presentation.Services;

public sealed class ThemeSettingsStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    private readonly string _filePath;

    public ThemeSettingsStore()
    {
        string appDataRoot = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string dataDirectory = Path.Combine(appDataRoot, "TrafficMonitor");
        _filePath = Path.Combine(dataDirectory, "theme-settings.json");
    }

    public ThemeSettings Load()
    {
        try
        {
            if (!File.Exists(_filePath))
                return ThemeSettings.CreateNormalized(null);

            string json = File.ReadAllText(_filePath, Encoding.UTF8);
            if (string.IsNullOrWhiteSpace(json))
                return ThemeSettings.CreateNormalized(null);

            var settings = JsonSerializer.Deserialize<ThemeSettings>(json, JsonOptions);
            return ThemeSettings.CreateNormalized(settings);
        }
        catch
        {
            return ThemeSettings.CreateNormalized(null);
        }
    }

    public void Save(ThemeSettings settings)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_filePath)!);
        string json = JsonSerializer.Serialize(ThemeSettings.CreateNormalized(settings), JsonOptions);
        File.WriteAllText(_filePath, json, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
    }
}
