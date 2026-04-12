using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Windows.Media;
using System.Windows.Interop;
using System.Drawing;

namespace Presentation.Helpers;

public static class ProcessIconHelper
{
    private static readonly ConcurrentDictionary<int, CacheEntry> Cache = new();
    private static readonly TimeSpan SuccessTtl = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan FailureTtl = TimeSpan.FromSeconds(20);
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromMinutes(1);
    private static long _nextCleanupTicks = DateTime.UtcNow.Add(CleanupInterval).Ticks;

    public static ImageSource? GetIcon(int pid)
    {
        if (pid <= 0)
            return null;

        var now = DateTime.UtcNow;
        CleanupExpiredIfNeeded(now);

        if (Cache.TryGetValue(pid, out var cached) && cached.ExpiresAtUtc > now)
            return cached.Icon;

        var icon = LoadIcon(pid);
        Cache[pid] = new CacheEntry(
            icon,
            now + (icon is null ? FailureTtl : SuccessTtl));

        return icon;
    }

    public static void ClearCache()
    {
        Cache.Clear();
        Interlocked.Exchange(ref _nextCleanupTicks, DateTime.UtcNow.Add(CleanupInterval).Ticks);
    }

    private static ImageSource? LoadIcon(int pid)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            string? path = null;
            try
            {
                path = proc.MainModule?.FileName;
            }
            catch
            {
                // ignore - fallback
            }

            if (string.IsNullOrWhiteSpace(path) && !string.IsNullOrEmpty(proc.ProcessName))
            {
                // try to locate exe in Program Files or System
                var candidate = proc.ProcessName + ".exe";
                // no reliable lookup - bail out
                return null;
            }

            if (!string.IsNullOrWhiteSpace(path) && File.Exists(path))
            {
                using var ico = Icon.ExtractAssociatedIcon(path);
                if (ico != null)
                {
                    var img = Imaging.CreateBitmapSourceFromHIcon(
                        ico.Handle,
                        System.Windows.Int32Rect.Empty,
                        System.Windows.Media.Imaging.BitmapSizeOptions.FromWidthAndHeight(32, 32));
                    img.Freeze();
                    return img;
                }
            }
        }
        catch
        {
            // ignore
        }

        return null;
    }

    private static void CleanupExpiredIfNeeded(DateTime nowUtc)
    {
        long nowTicks = nowUtc.Ticks;
        long nextCleanupTicks = Interlocked.Read(ref _nextCleanupTicks);
        if (nowTicks < nextCleanupTicks)
            return;

        if (Interlocked.CompareExchange(ref _nextCleanupTicks, nowUtc.Add(CleanupInterval).Ticks, nextCleanupTicks) != nextCleanupTicks)
            return;

        foreach (var pair in Cache)
        {
            if (pair.Value.ExpiresAtUtc <= nowUtc)
                Cache.TryRemove(pair.Key, out _);
        }
    }

    private readonly record struct CacheEntry(ImageSource? Icon, DateTime ExpiresAtUtc);
}
