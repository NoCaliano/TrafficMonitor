using System;
using System.Collections.Generic;
using System.Linq;

namespace Presentation.Models;

public sealed class DisplayFilterLibrary
{
    public const int MaxSavedFilters = 20;
    public const int MaxRecentFilters = 12;

    public List<string> SavedFilters { get; set; } = [];
    public List<string> RecentFilters { get; set; } = [];

    public DisplayFilterLibrary Clone()
        => new()
        {
            SavedFilters = [.. SavedFilters],
            RecentFilters = [.. RecentFilters]
        };

    public static DisplayFilterLibrary CreateNormalized(DisplayFilterLibrary? library)
    {
        var normalized = library?.Clone() ?? new DisplayFilterLibrary();
        normalized.SavedFilters = NormalizeList(normalized.SavedFilters, MaxSavedFilters);
        normalized.RecentFilters = NormalizeList(normalized.RecentFilters, MaxRecentFilters);
        return normalized;
    }

    private static List<string> NormalizeList(IEnumerable<string>? values, int maxCount)
    {
        var result = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (string value in values ?? Enumerable.Empty<string>())
        {
            string normalized = (value ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(normalized))
                continue;

            if (!seen.Add(normalized))
                continue;

            result.Add(normalized);
            if (result.Count >= maxCount)
                break;
        }

        return result;
    }
}
