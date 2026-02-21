using System;
using System.Diagnostics;
using System.IO;
using System.Windows.Media;
using System.Windows.Interop;
using System.Drawing;

namespace Presentation.Helpers;

public static class ProcessIconHelper
{
    public static ImageSource? GetIcon(int pid)
    {
        try
        {
            var proc = Process.GetProcessById(pid);
            string path = null;
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
}
