using Infrastructure.Networking;
using System.Windows;

namespace Presentation.Services;

public sealed class ProcessRemediationCoordinator
{
    private readonly ProcessMapperService _processMapperService;
    private readonly WindowsRemediationService _remediationService;
    private readonly IUserPromptService _prompt;

    public ProcessRemediationCoordinator(
        ProcessMapperService processMapperService,
        WindowsRemediationService remediationService,
        IUserPromptService prompt)
    {
        _processMapperService = processMapperService;
        _remediationService = remediationService;
        _prompt = prompt;
    }

    public string? Locate(int pid)
    {
        if (pid <= 0) return null;

        var d = _processMapperService.GetProcessDetailsCached(pid);
        if (_remediationService.TryOpenProcessLocation(d.ExePath, out var err))
            return $"Opened location for {d.Name} (PID {pid})";

        return $"Open location failed: {err}";
    }

    public string? Kill(int pid)
    {
        if (pid <= 0) return null;

        var d = _processMapperService.GetProcessDetailsCached(pid);
        var res = _prompt.Show(
            $"Terminate process {d.Name} (PID {pid})?\n\nThis may cause data loss.",
            "Kill process",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (res != MessageBoxResult.Yes)
            return null;

        if (_remediationService.TryKillProcess(pid, out var err))
            return $"Terminated {d.Name} (PID {pid})";

        return $"Kill failed: {err}";
    }

    public string? BlockInFirewall(int pid)
    {
        if (pid <= 0) return null;

        var d = _processMapperService.GetProcessDetailsCached(pid);
        var res = _prompt.Show(
            $"Add Windows Firewall rules to block {d.Name} (PID {pid}) by program path?\n\nThis will prompt for admin rights.",
            "Block in Firewall",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (res != MessageBoxResult.Yes)
            return null;

        if (_remediationService.TryBlockProgramInFirewall(d.ExePath, rulePrefix: "TrafficMonitor", out var err))
            return $"Firewall: blocked {d.Name}";

        return $"Firewall block failed: {err}";
    }

    public string? UnblockInFirewall(int pid)
    {
        if (pid <= 0) return null;

        var d = _processMapperService.GetProcessDetailsCached(pid);
        var res = _prompt.Show(
            $"Remove Windows Firewall rules added by TrafficMonitor for {d.Name} (PID {pid})?\n\nThis will prompt for admin rights.",
            "Unblock in Firewall",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (res != MessageBoxResult.Yes)
            return null;

        if (_remediationService.TryUnblockProgramInFirewall(d.ExePath, rulePrefix: "TrafficMonitor", out var err))
            return $"Firewall: unblocked {d.Name}";

        return $"Firewall unblock failed: {err}";
    }
}
