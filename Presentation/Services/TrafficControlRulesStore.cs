using Presentation.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace Presentation.Services;

public sealed class TrafficControlRulesStore
{
    private const int SchemaVersion = 1;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    private readonly string _filePath;

    public TrafficControlRulesStore()
    {
        string appDataRoot = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string dataDirectory = Path.Combine(appDataRoot, "TrafficMonitor");
        _filePath = Path.Combine(dataDirectory, "traffic-control-rules.json");
    }

    public IReadOnlyList<TrafficControlRule> Load()
    {
        try
        {
            if (!File.Exists(_filePath))
                return Array.Empty<TrafficControlRule>();

            string json = File.ReadAllText(_filePath, Encoding.UTF8);
            if (string.IsNullOrWhiteSpace(json))
                return Array.Empty<TrafficControlRule>();

            var document = JsonSerializer.Deserialize<TrafficControlRulesDocument>(json, JsonOptions);
            if (document?.Rules is null || document.Rules.Count == 0)
                return Array.Empty<TrafficControlRule>();

            return document.Rules
                .Select(TrafficControlRule.CreateNormalized)
                .ToArray();
        }
        catch
        {
            return Array.Empty<TrafficControlRule>();
        }
    }

    public void Save(IEnumerable<TrafficControlRule> rules)
    {
        ArgumentNullException.ThrowIfNull(rules);

        var document = new TrafficControlRulesDocument
        {
            SchemaVersion = SchemaVersion,
            Rules = rules
                .Select(TrafficControlRule.CreateNormalized)
                .ToList()
        };

        Directory.CreateDirectory(Path.GetDirectoryName(_filePath)!);
        string json = JsonSerializer.Serialize(document, JsonOptions);
        File.WriteAllText(_filePath, json, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
    }
}
