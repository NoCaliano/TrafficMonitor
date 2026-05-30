using Presentation.Models;
using System.Globalization;
using System.Windows;
using System.Windows.Input;
using Application.Filtering;

namespace Presentation.ViewModels;

public sealed class FiltersViewModel : ViewModelBase
{
    public PacketFilterModel Filter { get; }

    public bool IsApplied { get; private set; }

    public string[] ProtocolOptions { get; } =
        ["TCP", "UDP", "ICMP", "ARP", "IPv4", "IPv6", "DNS", "HTTP", "HTTPS", "QUIC"];

    // ===== Time range inputs (text) =====
    private string? _timeFromText;
    public string? TimeFromText
    {
        get => _timeFromText;
        set => Set(ref _timeFromText, value);
    }

    private string? _timeToText;
    public string? TimeToText
    {
        get => _timeToText;
        set => Set(ref _timeToText, value);
    }

    public ICommand ApplyCommand { get; }
    public ICommand ClearCommand { get; }
    public ICommand CancelCommand { get; }

    public FiltersViewModel(PacketFilterModel initial)
    {
        // Відповідає за: копію, щоб Cancel не міняв активний фільтр.
        Filter = Clone(initial);

        // Показуємо поточний збережений фільтр часу у текстових полях (LOCAL time)
        TimeFromText = Filter.TimeFromUtc?.ToLocalTime().ToString("HH:mm:ss");
        TimeToText = Filter.TimeToUtc?.ToLocalTime().ToString("HH:mm:ss");

        ApplyCommand = new RelayCommand(w =>
        {
            // 1) Парсимо час із текстових полів у Filter.TimeFromUtc/TimeToUtc
            if (!TryApplyTimeRangeFromText(Filter, TimeFromText, TimeToText, out var timeErr))
            {
                MessageBox.Show(timeErr, "Invalid filter", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            // 2) Інша валідація (порти/довжина)
            if (!Validate(Filter, out var error))
            {
                MessageBox.Show(error, "Invalid filter", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            IsApplied = true;
            if (w is Window win) win.Close();
        });

        ClearCommand = new RelayCommand(_ =>
        {
            // Відповідає за: скидання всіх полів фільтра.
            Filter.SrcIpOp = TextMatchOp.Any;
            Filter.SrcIpValue = "";

            Filter.DstIpOp = TextMatchOp.Any;
            Filter.DstIpValue = "";

            Filter.AnyIpOp = TextMatchOp.Any;
            Filter.AnyIpValue = "";

            Filter.SrcPortOp = NumberMatchOp.Any;
            Filter.SrcPortValue = null;

            Filter.DstPortOp = NumberMatchOp.Any;
            Filter.DstPortValue = null;

            Filter.AnyPortOp = NumberMatchOp.Any;
            Filter.AnyPortValue = null;

            Filter.ProtocolOp = TextMatchOp.Any;
            Filter.ProtocolValue = "";

            Filter.InfoOp = TextMatchOp.Any;
            Filter.InfoValue = "";

            Filter.PidOp = NumberMatchOp.Any;
            Filter.PidValue = null;

            Filter.ProcessNameOp = TextMatchOp.Any;
            Filter.ProcessNameValue = "";

            Filter.MinLength = null;
            Filter.MaxLength = null;

            Filter.TimeFromUtc = null;
            Filter.TimeToUtc = null;

            TimeFromText = "";
            TimeToText = "";

            OnPropertyChanged(nameof(Filter));
        });

        CancelCommand = new RelayCommand(w =>
        {
            IsApplied = false;
            if (w is Window win) win.Close();
        });
    }

    // Відповідає за: отримання застосованого фільтра після Apply.
    public PacketFilterModel GetAppliedFilter() => Clone(Filter);

    // Відповідає за: валідацію.
    private static bool Validate(PacketFilterModel f, out string error)
    {
        error = "";

        bool ValidPort(int? p) => p is null || (p >= 1 && p <= 65535);
        bool ValidLen(int? l) => l is null || l >= 0;

        if (!ValidPort(f.AnyPortValue) || !ValidPort(f.SrcPortValue) || !ValidPort(f.DstPortValue))
        {
            error = "Port must be in range 1..65535.";
            return false;
        }

        if (!ValidLen(f.MinLength) || !ValidLen(f.MaxLength))
        {
            error = "Length must be >= 0.";
            return false;
        }

        if (f.PidValue.HasValue && f.PidValue.Value < 0)
        {
            error = "PID must be >= 0.";
            return false;
        }

        if (f.MinLength.HasValue && f.MaxLength.HasValue && f.MinLength > f.MaxLength)
        {
            error = "MinLength cannot be greater than MaxLength.";
            return false;
        }

        // ✅ Time range basic check (already parsed into UTC in Apply)
        if (f.TimeFromUtc.HasValue && f.TimeToUtc.HasValue && f.TimeFromUtc > f.TimeToUtc)
        {
            error = "Time From must be <= Time To.";
            return false;
        }

        return true;
    }

    // ===== Time parsing =====
    // Accepts: "HH:mm:ss" OR "yyyy-MM-dd HH:mm:ss"
    // If only time is provided -> uses today's local date.

    private static bool TryApplyTimeRangeFromText(PacketFilterModel f, string fromText, string toText, out string error)
    {
        error = "";

        if (!TryParseLocalDateTime(fromText, out var fromLocal, out var err1))
        {
            error = "Time From: " + err1;
            return false;
        }

        if (!TryParseLocalDateTime(toText, out var toLocal, out var err2))
        {
            error = "Time To: " + err2;
            return false;
        }

        // store UTC in model
        f.TimeFromUtc = fromLocal?.ToUniversalTime();
        f.TimeToUtc = toLocal?.ToUniversalTime();

        return true;
    }

    private static bool TryParseLocalDateTime(string? text, out DateTime? localDt, out string error)
    {
        error = "";
        localDt = null;

        text = (text ?? "").Trim();
        if (string.IsNullOrWhiteSpace(text))
            return true;

        // 1) HH:mm:ss or HH:mm
        if (TimeSpan.TryParseExact(text, @"hh\:mm\:ss", CultureInfo.InvariantCulture, out var ts) ||
            TimeSpan.TryParseExact(text, @"hh\:mm", CultureInfo.InvariantCulture, out ts))
        {
            var todayLocal = DateTime.Now.Date; // LOCAL date
            localDt = DateTime.SpecifyKind(todayLocal.Add(ts), DateTimeKind.Local);
            return true;
        }

        // 2) Full datetime
        var formats = new[]
        {
            "yyyy-MM-dd HH:mm:ss",
            "yyyy-MM-dd HH:mm",
            "yyyy-MM-ddTHH:mm:ss",
            "yyyy-MM-ddTHH:mm"
        };

        if (DateTime.TryParseExact(text, formats, CultureInfo.InvariantCulture,
                DateTimeStyles.AllowWhiteSpaces, out var dt))
        {
            localDt = DateTime.SpecifyKind(dt, DateTimeKind.Local);
            return true;
        }

        error = "Use HH:mm[:ss] or yyyy-MM-dd HH:mm[:ss].";
        return false;
    }
    private static PacketFilterModel Clone(PacketFilterModel s) => new()
    {
        // ---- IP ----
        SrcIpOp = s.SrcIpOp,
        SrcIpValue = s.SrcIpValue,
        DstIpOp = s.DstIpOp,
        DstIpValue = s.DstIpValue,

        AnyIpOp = s.AnyIpOp,
        AnyIpValue = s.AnyIpValue,

        // ---- Ports ----
        SrcPortOp = s.SrcPortOp,
        SrcPortValue = s.SrcPortValue,

        DstPortOp = s.DstPortOp,
        DstPortValue = s.DstPortValue,

        AnyPortOp = s.AnyPortOp,
        AnyPortValue = s.AnyPortValue,

        // ---- Protocol / Info ----
        ProtocolOp = s.ProtocolOp,
        ProtocolValue = s.ProtocolValue,

        // ---- Process ----
        PidOp = s.PidOp,
        PidValue = s.PidValue,

        ProcessNameOp = s.ProcessNameOp,
        ProcessNameValue = s.ProcessNameValue,

        InfoOp = s.InfoOp,
        InfoValue = s.InfoValue,

        // ---- Length ----
        MinLength = s.MinLength,
        MaxLength = s.MaxLength,

        TimeFromUtc = s.TimeFromUtc,
        TimeToUtc = s.TimeToUtc
    };
}
