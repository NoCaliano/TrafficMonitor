using Presentation.Models;
using Presentation.Services;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Net;
using System.Windows;
using System.Windows.Input;

namespace Presentation.ViewModels;

public sealed class TrafficControlRulesViewModel : ViewModelBase
{
    private readonly TrafficControlManager _manager;

    public ObservableCollection<EditableTrafficControlRuleViewModel> Rules { get; } = new();
    public IReadOnlyList<string> TargetOptions => TrafficControlTargetKinds.All;
    public IReadOnlyList<string> PriorityOptions => TrafficControlPriorityLevels.All;

    private EditableTrafficControlRuleViewModel? _selectedRule;
    public EditableTrafficControlRuleViewModel? SelectedRule
    {
        get => _selectedRule;
        set
        {
            if (!Set(ref _selectedRule, value))
                return;

            OnPropertyChanged(nameof(HasSelectedRule));
            (DeleteRuleCommand as RelayCommand)?.RaiseCanExecuteChanged();
            (DuplicateRuleCommand as RelayCommand)?.RaiseCanExecuteChanged();
        }
    }

    public bool HasSelectedRule => SelectedRule is not null;

    private string _validationMessage = "";
    public string ValidationMessage
    {
        get => _validationMessage;
        private set => Set(ref _validationMessage, value);
    }

    public ICommand AddRuleCommand { get; }
    public ICommand DuplicateRuleCommand { get; }
    public ICommand DeleteRuleCommand { get; }
    public ICommand SaveCommand { get; }
    public ICommand CancelCommand { get; }

    public TrafficControlRulesViewModel(TrafficControlManager manager)
    {
        _manager = manager;

        AddRuleCommand = new RelayCommand(_ => AddRule());
        DuplicateRuleCommand = new RelayCommand(_ => DuplicateRule(), _ => SelectedRule is not null);
        DeleteRuleCommand = new RelayCommand(_ => DeleteRule(), _ => SelectedRule is not null);
        SaveCommand = new RelayCommand(w => Save(w));
        CancelCommand = new RelayCommand(w =>
        {
            if (w is Window window)
                window.Close();
        });

        Reload();
    }

    private void Reload()
    {
        Rules.Clear();

        foreach (var rule in _manager.GetRulesSnapshot())
            Rules.Add(new EditableTrafficControlRuleViewModel(rule));

        if (Rules.Count == 0)
            Rules.Add(new EditableTrafficControlRuleViewModel(new TrafficControlRule()));

        SelectedRule = Rules[0];
    }

    public void AppendDraftRule(TrafficControlRule rule)
    {
        var draft = new EditableTrafficControlRuleViewModel(TrafficControlRule.CreateNormalized(rule));
        Rules.Add(draft);
        SelectedRule = draft;
        ValidationMessage = "";
    }

    private void AddRule()
    {
        var rule = new EditableTrafficControlRuleViewModel(new TrafficControlRule
        {
            Name = $"Traffic rule {Rules.Count + 1}",
            NotifyOnTrigger = true,
            AutoBlockOnQuota = true
        });

        Rules.Add(rule);
        SelectedRule = rule;
        ValidationMessage = "";
    }

    private void DuplicateRule()
    {
        if (SelectedRule is null)
            return;

        var clone = new EditableTrafficControlRuleViewModel(SelectedRule.ToModel());
        clone.Id = Guid.NewGuid().ToString("N");
        clone.Name = $"{SelectedRule.Name} copy";

        Rules.Add(clone);
        SelectedRule = clone;
        ValidationMessage = "";
    }

    private void DeleteRule()
    {
        if (SelectedRule is null)
            return;

        int index = Rules.IndexOf(SelectedRule);
        Rules.Remove(SelectedRule);

        if (Rules.Count == 0)
            Rules.Add(new EditableTrafficControlRuleViewModel(new TrafficControlRule()));

        SelectedRule = Rules[Math.Clamp(index, 0, Rules.Count - 1)];
        ValidationMessage = "";
    }

    private void Save(object? parameter)
    {
        ValidationMessage = "";

        var models = Rules
            .Select(static rule => TrafficControlRule.CreateNormalized(rule.ToModel()))
            .ToArray();

        for (int i = 0; i < models.Length; i++)
        {
            if (TryValidateRule(models[i], out string error))
                continue;

            SelectedRule = Rules[i];
            ValidationMessage = error;
            return;
        }

        var result = _manager.SaveRules(models);
        MessageBox.Show(
            result.StatusMessage,
            "Traffic Control Rules",
            MessageBoxButton.OK,
            result.HasWarnings ? MessageBoxImage.Warning : MessageBoxImage.Information);

        if (parameter is Window window)
            window.Close();
    }

    private static bool TryValidateRule(TrafficControlRule rule, out string error)
    {
        error = string.Empty;

        if (string.IsNullOrWhiteSpace(rule.Name))
        {
            error = "Each rule needs a name.";
            return false;
        }

        if (TrafficControlTargetKinds.IncludesProcess(rule.TargetKind)
            && string.IsNullOrWhiteSpace(rule.ProcessFilter))
        {
            error = $"Rule '{rule.Name}' needs a process filter.";
            return false;
        }

        if (TrafficControlTargetKinds.IncludesHost(rule.TargetKind))
        {
            if (string.IsNullOrWhiteSpace(rule.RemoteAddress))
            {
                error = $"Rule '{rule.Name}' needs a remote IP or CIDR.";
                return false;
            }

            if (!TryValidateRemoteAddress(rule.RemoteAddress))
            {
                error = $"Rule '{rule.Name}' has an invalid remote IP or CIDR.";
                return false;
            }
        }

        bool hasThrottle = rule.ThrottleMbps > 0;
        bool hasPriority = !string.Equals(rule.Priority, TrafficControlPriorityLevels.Normal, StringComparison.OrdinalIgnoreCase);
        bool hasDailyQuota = rule.DailyQuotaMb > 0;
        if (!hasThrottle && !hasPriority && !hasDailyQuota)
        {
            error = $"Rule '{rule.Name}' does not define any control action yet.";
            return false;
        }

        if (rule.ScheduleEnabled)
        {
            bool hasAnyDay = rule.Monday || rule.Tuesday || rule.Wednesday || rule.Thursday || rule.Friday || rule.Saturday || rule.Sunday;
            if (!hasAnyDay)
            {
                error = $"Rule '{rule.Name}' has scheduling enabled, but no days were selected.";
                return false;
            }
        }

        return true;
    }

    private static bool TryValidateRemoteAddress(string value)
    {
        string normalized = value.Trim();
        if (!normalized.Contains('/', StringComparison.Ordinal))
            return IPAddress.TryParse(normalized, out _);

        string[] parts = normalized.Split('/', 2, StringSplitOptions.TrimEntries);
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var address) || !int.TryParse(parts[1], out int prefixLength))
            return false;

        int maxPrefix = address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128;
        return prefixLength >= 0 && prefixLength <= maxPrefix;
    }
}

public sealed class EditableTrafficControlRuleViewModel : ViewModelBase
{
    private string _id = Guid.NewGuid().ToString("N");
    private string _name = "New traffic rule";
    private bool _enabled = true;
    private string _targetKind = TrafficControlTargetKinds.Process;
    private string _processFilter = "";
    private string _remoteAddress = "";
    private int _throttleMbps;
    private string _priority = TrafficControlPriorityLevels.Normal;
    private int _dailyQuotaMb;
    private bool _autoBlockOnQuota = true;
    private bool _notifyOnTrigger = true;
    private bool _scheduleEnabled;
    private bool _monday = true;
    private bool _tuesday = true;
    private bool _wednesday = true;
    private bool _thursday = true;
    private bool _friday = true;
    private bool _saturday;
    private bool _sunday;
    private string _scheduleStartText = "09:00";
    private string _scheduleEndText = "18:00";

    public EditableTrafficControlRuleViewModel(TrafficControlRule rule)
    {
        Load(rule);
    }

    public string Id
    {
        get => _id;
        set => Set(ref _id, value);
    }

    public string Name
    {
        get => _name;
        set
        {
            if (!Set(ref _name, value))
                return;

            RaiseSummaryProperties();
        }
    }

    public bool Enabled
    {
        get => _enabled;
        set => Set(ref _enabled, value);
    }

    public string TargetKind
    {
        get => _targetKind;
        set
        {
            if (!Set(ref _targetKind, TrafficControlTargetKinds.Normalize(value)))
                return;

            OnPropertyChanged(nameof(ShowsProcessFields));
            OnPropertyChanged(nameof(ShowsHostFields));
            RaiseSummaryProperties();
        }
    }

    public string ProcessFilter
    {
        get => _processFilter;
        set
        {
            if (!Set(ref _processFilter, value))
                return;

            RaiseSummaryProperties();
        }
    }

    public string RemoteAddress
    {
        get => _remoteAddress;
        set
        {
            if (!Set(ref _remoteAddress, value))
                return;

            RaiseSummaryProperties();
        }
    }

    public int ThrottleMbps
    {
        get => _throttleMbps;
        set
        {
            int normalized = Math.Clamp(value, 0, 100_000);
            if (!Set(ref _throttleMbps, normalized))
                return;

            RaiseSummaryProperties();
        }
    }

    public string Priority
    {
        get => _priority;
        set
        {
            if (!Set(ref _priority, TrafficControlPriorityLevels.Normalize(value)))
                return;

            RaiseSummaryProperties();
        }
    }

    public int DailyQuotaMb
    {
        get => _dailyQuotaMb;
        set
        {
            int normalized = Math.Clamp(value, 0, 500_000);
            if (!Set(ref _dailyQuotaMb, normalized))
                return;

            RaiseSummaryProperties();
        }
    }

    public bool AutoBlockOnQuota
    {
        get => _autoBlockOnQuota;
        set => Set(ref _autoBlockOnQuota, value);
    }

    public bool NotifyOnTrigger
    {
        get => _notifyOnTrigger;
        set => Set(ref _notifyOnTrigger, value);
    }

    public bool ScheduleEnabled
    {
        get => _scheduleEnabled;
        set
        {
            if (!Set(ref _scheduleEnabled, value))
                return;

            RaiseSummaryProperties();
        }
    }

    public bool Monday
    {
        get => _monday;
        set
        {
            if (!Set(ref _monday, value))
                return;

            RaiseSummaryProperties();
        }
    }

    public bool Tuesday
    {
        get => _tuesday;
        set
        {
            if (!Set(ref _tuesday, value))
                return;

            RaiseSummaryProperties();
        }
    }

    public bool Wednesday
    {
        get => _wednesday;
        set
        {
            if (!Set(ref _wednesday, value))
                return;

            RaiseSummaryProperties();
        }
    }

    public bool Thursday
    {
        get => _thursday;
        set
        {
            if (!Set(ref _thursday, value))
                return;

            RaiseSummaryProperties();
        }
    }

    public bool Friday
    {
        get => _friday;
        set
        {
            if (!Set(ref _friday, value))
                return;

            RaiseSummaryProperties();
        }
    }

    public bool Saturday
    {
        get => _saturday;
        set
        {
            if (!Set(ref _saturday, value))
                return;

            RaiseSummaryProperties();
        }
    }

    public bool Sunday
    {
        get => _sunday;
        set
        {
            if (!Set(ref _sunday, value))
                return;

            RaiseSummaryProperties();
        }
    }

    public string ScheduleStartText
    {
        get => _scheduleStartText;
        set
        {
            if (!Set(ref _scheduleStartText, value))
                return;

            RaiseSummaryProperties();
        }
    }

    public string ScheduleEndText
    {
        get => _scheduleEndText;
        set
        {
            if (!Set(ref _scheduleEndText, value))
                return;

            RaiseSummaryProperties();
        }
    }

    public bool ShowsProcessFields => TrafficControlTargetKinds.IncludesProcess(TargetKind);
    public bool ShowsHostFields => TrafficControlTargetKinds.IncludesHost(TargetKind);

    public string TargetSummary
    {
        get
        {
            if (string.Equals(TargetKind, TrafficControlTargetKinds.Process, StringComparison.OrdinalIgnoreCase))
                return $"Process: {FormatOrDefault(ProcessFilter, "any")}";

            if (string.Equals(TargetKind, TrafficControlTargetKinds.Host, StringComparison.OrdinalIgnoreCase))
                return $"Host: {FormatOrDefault(RemoteAddress, "not set")}";

            return $"{FormatOrDefault(ProcessFilter, "process")} -> {FormatOrDefault(RemoteAddress, "host")}";
        }
    }

    public string ControlSummary
    {
        get
        {
            string throttle = ThrottleMbps > 0 ? $"{ThrottleMbps:N0} Mbps" : "no throttle";
            string priority = string.Equals(Priority, TrafficControlPriorityLevels.Normal, StringComparison.OrdinalIgnoreCase)
                ? "normal priority"
                : Priority;
            string quota = DailyQuotaMb > 0 ? $"{DailyQuotaMb:N0} MB/day" : "no daily quota";
            return $"{throttle} | {priority} | {quota}";
        }
    }

    public string ScheduleSummary
    {
        get
        {
            if (!ScheduleEnabled)
                return "Always active";

            string days = string.Join(", ", new[]
            {
                Monday ? "Mon" : null,
                Tuesday ? "Tue" : null,
                Wednesday ? "Wed" : null,
                Thursday ? "Thu" : null,
                Friday ? "Fri" : null,
                Saturday ? "Sat" : null,
                Sunday ? "Sun" : null
            }.Where(static value => value is not null));

            return $"{days} {ScheduleStartText}-{ScheduleEndText}";
        }
    }

    public TrafficControlRule ToModel()
    {
        int startMinutes = ParseMinutesOrDefault(ScheduleStartText, 9 * 60);
        int endMinutes = ParseMinutesOrDefault(ScheduleEndText, 18 * 60);

        return new TrafficControlRule
        {
            Id = Id,
            Name = Name,
            Enabled = Enabled,
            TargetKind = TargetKind,
            ProcessFilter = ProcessFilter,
            RemoteAddress = RemoteAddress,
            ThrottleMbps = ThrottleMbps,
            Priority = Priority,
            DailyQuotaMb = DailyQuotaMb,
            AutoBlockOnQuota = AutoBlockOnQuota,
            NotifyOnTrigger = NotifyOnTrigger,
            ScheduleEnabled = ScheduleEnabled,
            Monday = Monday,
            Tuesday = Tuesday,
            Wednesday = Wednesday,
            Thursday = Thursday,
            Friday = Friday,
            Saturday = Saturday,
            Sunday = Sunday,
            StartMinutes = startMinutes,
            EndMinutes = endMinutes
        };
    }

    private void Load(TrafficControlRule rule)
    {
        var normalized = TrafficControlRule.CreateNormalized(rule);
        Id = normalized.Id;
        Name = normalized.Name;
        Enabled = normalized.Enabled;
        TargetKind = normalized.TargetKind;
        ProcessFilter = normalized.ProcessFilter;
        RemoteAddress = normalized.RemoteAddress;
        ThrottleMbps = normalized.ThrottleMbps;
        Priority = normalized.Priority;
        DailyQuotaMb = normalized.DailyQuotaMb;
        AutoBlockOnQuota = normalized.AutoBlockOnQuota;
        NotifyOnTrigger = normalized.NotifyOnTrigger;
        ScheduleEnabled = normalized.ScheduleEnabled;
        Monday = normalized.Monday;
        Tuesday = normalized.Tuesday;
        Wednesday = normalized.Wednesday;
        Thursday = normalized.Thursday;
        Friday = normalized.Friday;
        Saturday = normalized.Saturday;
        Sunday = normalized.Sunday;
        ScheduleStartText = FormatMinutes(normalized.StartMinutes);
        ScheduleEndText = FormatMinutes(normalized.EndMinutes);
        RaiseSummaryProperties();
    }

    private void RaiseSummaryProperties()
    {
        OnPropertyChanged(nameof(TargetSummary));
        OnPropertyChanged(nameof(ControlSummary));
        OnPropertyChanged(nameof(ScheduleSummary));
    }

    private static int ParseMinutesOrDefault(string value, int fallback)
    {
        if (!TimeSpan.TryParse(value, out var parsed))
            return fallback;

        return Math.Clamp((int)parsed.TotalMinutes, 0, 1_439);
    }

    private static string FormatMinutes(int value)
    {
        int normalized = Math.Clamp(value, 0, 1_439);
        int hours = normalized / 60;
        int minutes = normalized % 60;
        return $"{hours:00}:{minutes:00}";
    }

    private static string FormatOrDefault(string? value, string fallback)
        => string.IsNullOrWhiteSpace(value) ? fallback : value.Trim();
}
