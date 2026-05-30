using Presentation.Models;
using System;
using System.IO;
using System.Text;
using System.Text.Json;

namespace Presentation.Services;

public sealed class NotificationSettingsStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    private readonly string _filePath;

    public NotificationSettingsStore()
    {
        string appDataRoot = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string dataDirectory = Path.Combine(appDataRoot, "TrafficMonitor");
        _filePath = Path.Combine(dataDirectory, "notification-settings.json");
    }

    public NotificationSettings Load()
    {
        try
        {
            if (!File.Exists(_filePath))
                return NotificationSettings.CreateNormalized(null);

            string json = File.ReadAllText(_filePath, Encoding.UTF8);
            if (string.IsNullOrWhiteSpace(json))
                return NotificationSettings.CreateNormalized(null);

            var settings = JsonSerializer.Deserialize<NotificationSettings>(json, JsonOptions);
            return NotificationSettings.CreateNormalized(settings);
        }
        catch
        {
            return NotificationSettings.CreateNormalized(null);
        }
    }

    public void Save(NotificationSettings settings)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_filePath)!);
        string json = JsonSerializer.Serialize(NotificationSettings.CreateNormalized(settings), JsonOptions);
        File.WriteAllText(_filePath, json, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
    }
}
