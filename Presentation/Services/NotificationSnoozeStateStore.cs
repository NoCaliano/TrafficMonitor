using Presentation.Models;
using System;
using System.IO;
using System.Text;
using System.Text.Json;

namespace Presentation.Services;

public sealed class NotificationSnoozeStateStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    private readonly string _filePath;

    public NotificationSnoozeStateStore()
    {
        string appDataRoot = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string dataDirectory = Path.Combine(appDataRoot, "TrafficMonitor");
        _filePath = Path.Combine(dataDirectory, "notification-snooze.json");
    }

    public NotificationSnoozeState Load()
    {
        try
        {
            if (!File.Exists(_filePath))
                return NotificationSnoozeState.CreateNormalized(null);

            string json = File.ReadAllText(_filePath, Encoding.UTF8);
            if (string.IsNullOrWhiteSpace(json))
                return NotificationSnoozeState.CreateNormalized(null);

            var state = JsonSerializer.Deserialize<NotificationSnoozeState>(json, JsonOptions);
            return NotificationSnoozeState.CreateNormalized(state);
        }
        catch
        {
            return NotificationSnoozeState.CreateNormalized(null);
        }
    }

    public void Save(NotificationSnoozeState state)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_filePath)!);
        string json = JsonSerializer.Serialize(NotificationSnoozeState.CreateNormalized(state), JsonOptions);
        File.WriteAllText(_filePath, json, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
    }
}
