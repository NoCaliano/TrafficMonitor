using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace Infrastructure.Remediation;

public sealed class WindowsRemediationService
{
    public sealed record QosPolicySpec(
        string PolicyName,
        string? AppPath,
        string? RemoteAddress,
        ulong? ThrottleBitsPerSecond,
        sbyte? DscpAction);

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

    public bool TryApplyQosPolicy(QosPolicySpec spec, out string error)
    {
        error = "";

        try
        {
            if (string.IsNullOrWhiteSpace(spec.PolicyName))
            {
                error = "QoS policy name is required.";
                return false;
            }

            if (string.IsNullOrWhiteSpace(spec.AppPath) && string.IsNullOrWhiteSpace(spec.RemoteAddress))
            {
                error = "QoS policy requires an app path or a remote address.";
                return false;
            }

            if (!string.IsNullOrWhiteSpace(spec.AppPath) && !File.Exists(spec.AppPath))
            {
                error = "Executable path is not available.";
                return false;
            }

            if (spec.ThrottleBitsPerSecond is null && spec.DscpAction is null)
            {
                error = "QoS policy does not define a throttle or a priority action.";
                return false;
            }

            string script = BuildApplyQosPolicyScript(spec);
            int code = RunPowerShell(script, elevate: true);
            if (code != 0)
            {
                error = $"Failed to apply QoS policy (exit {code}).";
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

    public bool TryRemoveQosPolicy(string policyName, out string error)
    {
        error = "";

        try
        {
            if (string.IsNullOrWhiteSpace(policyName))
                return true;

            string escapedName = EscapePowerShellLiteral(policyName);
            string script = "$ErrorActionPreference='SilentlyContinue'; "
                + $"Remove-NetQosPolicy -Name '{escapedName}' -PolicyStore ActiveStore -Confirm:$false | Out-Null";

            int code = RunPowerShell(script, elevate: true);
            if (code != 0)
            {
                error = $"Failed to remove QoS policy (exit {code}).";
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

    public bool TryBlockTrafficInFirewall(string ruleBaseName, string? exePath, string? remoteAddress, out string error)
    {
        error = "";

        try
        {
            if (string.IsNullOrWhiteSpace(ruleBaseName))
            {
                error = "Firewall rule name is required.";
                return false;
            }

            if (string.IsNullOrWhiteSpace(exePath) && string.IsNullOrWhiteSpace(remoteAddress))
            {
                error = "Firewall rule requires an executable path or a remote address.";
                return false;
            }

            if (!string.IsNullOrWhiteSpace(exePath) && !File.Exists(exePath))
            {
                error = "Executable path is not available.";
                return false;
            }

            string script = BuildApplyFirewallTrafficRuleScript(ruleBaseName, exePath, remoteAddress);
            int code = RunPowerShell(script, elevate: true);
            if (code != 0)
            {
                error = $"Failed to apply firewall rule (exit {code}).";
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

    public bool TryRemoveTrafficFirewallRule(string ruleBaseName, out string error)
    {
        error = "";

        try
        {
            if (string.IsNullOrWhiteSpace(ruleBaseName))
                return true;

            string outRule = EscapePowerShellLiteral($"{ruleBaseName} (out)");
            string inRule = EscapePowerShellLiteral($"{ruleBaseName} (in)");
            string script = "$ErrorActionPreference='SilentlyContinue'; "
                + $"Remove-NetFirewallRule -DisplayName '{outRule}' -PolicyStore ActiveStore | Out-Null; "
                + $"Remove-NetFirewallRule -DisplayName '{inRule}' -PolicyStore ActiveStore | Out-Null;";

            int code = RunPowerShell(script, elevate: true);
            if (code != 0)
            {
                error = $"Failed to remove firewall rule (exit {code}).";
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

    private static int RunPowerShell(string script, bool elevate)
    {
        string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        return RunProcess(
            "powershell.exe",
            $"-NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}",
            elevate);
    }

    private static string BuildApplyQosPolicyScript(QosPolicySpec spec)
    {
        string policyName = EscapePowerShellLiteral(spec.PolicyName);
        string? appPath = string.IsNullOrWhiteSpace(spec.AppPath) ? null : EscapePowerShellLiteral(spec.AppPath);
        string? remoteAddress = string.IsNullOrWhiteSpace(spec.RemoteAddress) ? null : EscapePowerShellLiteral(spec.RemoteAddress);

        var sb = new StringBuilder();
        sb.Append("$ErrorActionPreference='Stop'; ");
        sb.Append($"Remove-NetQosPolicy -Name '{policyName}' -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue | Out-Null; ");
        sb.Append("$params=@{ Name='");
        sb.Append(policyName);
        sb.Append("'; PolicyStore='ActiveStore'; NetworkProfile='All'");

        if (!string.IsNullOrWhiteSpace(appPath))
        {
            sb.Append("; AppPathNameMatchCondition='");
            sb.Append(appPath);
            sb.Append("'");
        }

        if (!string.IsNullOrWhiteSpace(remoteAddress))
        {
            sb.Append("; IPDstPrefixMatchCondition='");
            sb.Append(remoteAddress);
            sb.Append("'");
        }

        if (spec.ThrottleBitsPerSecond is ulong throttleBitsPerSecond)
        {
            sb.Append("; ThrottleRateActionBitsPerSecond=");
            sb.Append(throttleBitsPerSecond.ToString(System.Globalization.CultureInfo.InvariantCulture));
        }

        if (spec.DscpAction is sbyte dscpAction)
        {
            sb.Append("; DSCPAction=");
            sb.Append(dscpAction.ToString(System.Globalization.CultureInfo.InvariantCulture));
        }

        sb.Append(" }; New-NetQosPolicy @params | Out-Null;");
        return sb.ToString();
    }

    private static string BuildApplyFirewallTrafficRuleScript(string ruleBaseName, string? exePath, string? remoteAddress)
    {
        string outRule = EscapePowerShellLiteral($"{ruleBaseName} (out)");
        string inRule = EscapePowerShellLiteral($"{ruleBaseName} (in)");
        string? escapedExePath = string.IsNullOrWhiteSpace(exePath) ? null : EscapePowerShellLiteral(exePath);
        string? escapedRemoteAddress = string.IsNullOrWhiteSpace(remoteAddress) ? null : EscapePowerShellLiteral(remoteAddress);

        var sb = new StringBuilder();
        sb.Append("$ErrorActionPreference='Stop'; ");
        sb.Append($"Remove-NetFirewallRule -DisplayName '{outRule}' -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null; ");
        sb.Append($"Remove-NetFirewallRule -DisplayName '{inRule}' -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null; ");
        sb.Append("$common=@{ Enabled='True'; Profile='Any'; Action='Block'; PolicyStore='ActiveStore'");

        if (!string.IsNullOrWhiteSpace(escapedExePath))
        {
            sb.Append("; Program='");
            sb.Append(escapedExePath);
            sb.Append("'");
        }

        if (!string.IsNullOrWhiteSpace(escapedRemoteAddress))
        {
            sb.Append("; RemoteAddress='");
            sb.Append(escapedRemoteAddress);
            sb.Append("'");
        }

        sb.Append(" }; ");
        sb.Append($"New-NetFirewallRule @common -DisplayName '{outRule}' -Direction Outbound | Out-Null; ");
        sb.Append($"New-NetFirewallRule @common -DisplayName '{inRule}' -Direction Inbound | Out-Null;");
        return sb.ToString();
    }

    private static string EscapePowerShellLiteral(string value)
        => string.IsNullOrEmpty(value) ? string.Empty : value.Replace("'", "''", StringComparison.Ordinal);
}
