using Application.Abstractions;
using Domain.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;

namespace Infrastructure.Networking;

public sealed class JsonProcessBaselineStore : IProcessBaselineStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    private readonly string _filePath;

    public JsonProcessBaselineStore()
    {
        string appDataRoot = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string dataDirectory = Path.Combine(appDataRoot, "TrafficMonitor");
        _filePath = Path.Combine(dataDirectory, "process-behavior-baselines.json");
    }

    public IReadOnlyList<ProcessBehaviorBaseline> Load()
    {
        try
        {
            if (!File.Exists(_filePath))
                return Array.Empty<ProcessBehaviorBaseline>();

            string json = File.ReadAllText(_filePath, Encoding.UTF8);
            if (string.IsNullOrWhiteSpace(json))
                return Array.Empty<ProcessBehaviorBaseline>();

            var baselines = JsonSerializer.Deserialize<List<ProcessBehaviorBaseline>>(json, JsonOptions);
            return baselines is null
                ? Array.Empty<ProcessBehaviorBaseline>()
                : baselines;
        }
        catch
        {
            return Array.Empty<ProcessBehaviorBaseline>();
        }
    }

    public void Save(IReadOnlyList<ProcessBehaviorBaseline> baselines)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_filePath)!);
        string json = JsonSerializer.Serialize(baselines, JsonOptions);
        File.WriteAllText(_filePath, json, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
    }
}
