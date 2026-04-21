using Presentation.Models;
using System;
using System.IO;
using System.Text;
using System.Text.Json;

namespace Presentation.Services;

public sealed class DisplayFilterLibraryStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    private readonly string _filePath;

    public DisplayFilterLibraryStore()
    {
        string appDataRoot = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string dataDirectory = Path.Combine(appDataRoot, "TrafficMonitor");
        _filePath = Path.Combine(dataDirectory, "display-filters.json");
    }

    public DisplayFilterLibrary Load()
    {
        try
        {
            if (!File.Exists(_filePath))
                return DisplayFilterLibrary.CreateNormalized(null);

            string json = File.ReadAllText(_filePath, Encoding.UTF8);
            if (string.IsNullOrWhiteSpace(json))
                return DisplayFilterLibrary.CreateNormalized(null);

            var library = JsonSerializer.Deserialize<DisplayFilterLibrary>(json, JsonOptions);
            return DisplayFilterLibrary.CreateNormalized(library);
        }
        catch
        {
            return DisplayFilterLibrary.CreateNormalized(null);
        }
    }

    public void Save(DisplayFilterLibrary library)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_filePath)!);
        string json = JsonSerializer.Serialize(DisplayFilterLibrary.CreateNormalized(library), JsonOptions);
        File.WriteAllText(_filePath, json, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
    }
}
