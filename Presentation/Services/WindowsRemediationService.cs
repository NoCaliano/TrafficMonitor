using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;

namespace Presentation.Services;

public sealed class WindowsRemediationService
{
    public bool TryOpenProcessLocation(string exePath, out string error)
    {
        error = "";

        try
        {
            if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath))
            {
                error = "Executable path is not available.";
                return false;
            }

            var psi = new ProcessStartInfo("explorer.exe", $"/select,\"{exePath}\"")
            {
                UseShellExecute = true,
            };

            Process.Start(psi);
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    public bool TryKillProcess(int pid, out string error)
    {
        error = "";

        try
        {
            using var p = Process.GetProcessById(pid);
            p.Kill(entireProcessTree: true);
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    public bool TryBlockProgramInFirewall(string exePath, string rulePrefix, out string error)
    {
        error = "";

        try
        {
            if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath))
            {
                error = "Executable path is not available.";
                return false;
            }

            string baseName = Path.GetFileName(exePath);
            string safePrefix = string.IsNullOrWhiteSpace(rulePrefix) ? "TrafficMonitor" : rulePrefix;

            string outRule = $"{safePrefix} Block {baseName} (out)";
            string inRule = $"{safePrefix} Block {baseName} (in)";

            // Single UAC prompt: run all commands in one elevated cmd.exe.
            string cmd = string.Join(" & ",
                $"netsh advfirewall firewall delete rule name=\"{outRule}\"",
                $"netsh advfirewall firewall delete rule name=\"{inRule}\"",
                $"netsh advfirewall firewall add rule name=\"{outRule}\" dir=out action=block program=\"{exePath}\" enable=yes profile=any",
                $"netsh advfirewall firewall add rule name=\"{inRule}\" dir=in action=block program=\"{exePath}\" enable=yes profile=any");

            int code = RunProcess("cmd.exe", $"/c {cmd}", elevate: true);
            if (code != 0)
            {
                error = $"Failed to update firewall rules (exit {code}).";
                return false;
            }

            return true;
        }
        catch (Win32Exception ex) when ((uint)ex.NativeErrorCode == 1223)
        {
            // ERROR_CANCELLED (user cancelled UAC prompt)
            error = "Operation cancelled.";
            return false;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    public bool TryUnblockProgramInFirewall(string exePath, string rulePrefix, out string error)
    {
        error = "";

        try
        {
            if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath))
            {
                error = "Executable path is not available.";
                return false;
            }

            string baseName = Path.GetFileName(exePath);
            string safePrefix = string.IsNullOrWhiteSpace(rulePrefix) ? "TrafficMonitor" : rulePrefix;

            string outRule = $"{safePrefix} Block {baseName} (out)";
            string inRule = $"{safePrefix} Block {baseName} (in)";

            string cmd = string.Join(" & ",
                $"netsh advfirewall firewall delete rule name=\"{outRule}\"",
                $"netsh advfirewall firewall delete rule name=\"{inRule}\"");

            int code = RunProcess("cmd.exe", $"/c {cmd}", elevate: true);
            if (code != 0)
            {
                error = $"Failed to remove firewall rules (exit {code}).";
                return false;
            }

            return true;
        }
        catch (Win32Exception ex) when ((uint)ex.NativeErrorCode == 1223)
        {
            error = "Operation cancelled.";
            return false;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static int RunProcess(string fileName, string args, bool elevate = false)
    {
        var psi = new ProcessStartInfo(fileName, args)
        {
            UseShellExecute = elevate,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
        };

        if (elevate)
            psi.Verb = "runas";

        using var p = Process.Start(psi);
        if (p is null)
            return -1;

        p.WaitForExit();
        return p.ExitCode;
    }
}
