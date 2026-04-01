using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Media;

namespace Presentation.Models;

public sealed class ProcessStatRow : INotifyPropertyChanged
{
    private const int MaxSamples = 30;

    public sealed record RiskReason(string Summary, int Points)
    {
        public string PointsLabel => $"+{Points}";
    }

    private readonly record struct RiskSignal(string Summary, int Points);

    public sealed record InvestigationTimelineTarget(string Kind, string? Value = null);

    public sealed record InvestigationTimelineEvent(
        int Pid,
        string Key,
        DateTime Timestamp,
        string Title,
        string Detail,
        InvestigationTimelineTarget? Target = null)
    {
        public string TimeLabel => Timestamp == default ? "" : Timestamp.ToString("HH:mm:ss");
        public string DateLabel => Timestamp == default ? "" : Timestamp.ToString("dd MMM");
        public bool CanFocusPacket => Target is not null;
        public string FocusPacketLabel => "Show packet";
    }

    public int Pid { get; }
    public string ProcessName { get; }

    private bool _isAlive;
    public bool IsAlive { get => _isAlive; set { if (_isAlive != value) { _isAlive = value; OnPropertyChanged(); OnPropertyChanged(nameof(LivenessLabel)); OnPropertyChanged(nameof(LivenessBrush)); } } }

    public string LivenessLabel => Pid <= 0 ? "" : (IsAlive ? "Active" : "Exited");

    public Brush LivenessBrush => IsAlive ? Brushes.SeaGreen : Brushes.Gray;

    private DateTime _lastSeen;
    public DateTime LastSeen { get => _lastSeen; set { if (_lastSeen != value) { _lastSeen = value; OnPropertyChanged(); OnPropertyChanged(nameof(LastSeenLabel)); } } }

    public string LastSeenLabel => LastSeen == default ? "" : $"Last: {LastSeen:HH:mm:ss}";

    private string _exePath = "";
    public string ExePath { get => _exePath; set { if (_exePath != value) { _exePath = value; OnPropertyChanged(); OnPropertyChanged(nameof(ExePathShort)); OnPropertyChanged(nameof(ExePathIsEmpty)); RecomputeRisk(); } } }
    public bool ExePathIsEmpty => string.IsNullOrWhiteSpace(_exePath);
    public string ExePathShort => string.IsNullOrWhiteSpace(_exePath) ? "" : Path.GetFileName(_exePath);

    private string _publisher = "";
    public string Publisher { get => _publisher; set { if (_publisher != value) { _publisher = value; OnPropertyChanged(); RecomputeRisk(); } } }

    private bool _isSigned;
    public bool IsSigned { get => _isSigned; set { if (_isSigned != value) { _isSigned = value; OnPropertyChanged(); OnPropertyChanged(nameof(SignedLabel)); RecomputeRisk(); } } }
    public string SignedLabel => Pid <= 0 ? "" : (IsSigned ? "Signed" : "Unsigned");

    private string _signerSubject = "";
    public string SignerSubject { get => _signerSubject; set { if (_signerSubject != value) { _signerSubject = value; OnPropertyChanged(); } } }

    private int _parentPid;
    public int ParentPid { get => _parentPid; set { if (_parentPid != value) { _parentPid = value; OnPropertyChanged(); OnPropertyChanged(nameof(ParentDisplay)); } } }

    private string _parentName = "";
    public string ParentName { get => _parentName; set { if (_parentName != value) { _parentName = value; OnPropertyChanged(); OnPropertyChanged(nameof(ParentDisplay)); } } }

    public string ParentDisplay => ParentPid > 0
        ? (string.IsNullOrWhiteSpace(ParentName) ? $"Parent PID: {ParentPid}" : $"Parent: {ParentName} (PID: {ParentPid})")
        : "";

    private int _riskScore;
    public int RiskScore { get => _riskScore; private set { if (_riskScore != value) { _riskScore = value; OnPropertyChanged(); OnPropertyChanged(nameof(RiskLabel)); OnPropertyChanged(nameof(RiskBrush)); } } }

    private IReadOnlyList<RiskReason> _riskReasons = Array.Empty<RiskReason>();
    public IReadOnlyList<RiskReason> RiskReasons
    {
        get => _riskReasons;
        private set
        {
            _riskReasons = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(HasRiskReasons));
            OnPropertyChanged(nameof(RiskEmptyState));
        }
    }

    public bool HasRiskReasons => _riskReasons.Count > 0;
    public string WhyFlaggedLabel => "Why flagged";
    public string RiskEmptyState => HasRiskReasons ? "" : "No active risk signals.";
    public ObservableCollection<InvestigationTimelineEvent> TimelineEvents { get; } = new();
    public bool HasTimelineEvents => TimelineEvents.Count > 0;
    public string TimelineEmptyState => HasTimelineEvents ? "" : "No investigation events recorded yet.";
    public string TimelineTitle => "Investigation timeline";
    public ObservableCollection<ProcessConversationRow> Conversations { get; } = new();
    public bool HasConversations => Conversations.Count > 0;
    public string ConversationTitle => "Conversation view";
    public string ConversationEmptyState => HasConversations ? "" : "No conversation partners recorded yet.";
    public ObservableCollection<ProcessSessionClusterRow> SessionClusters { get; } = new();
    public bool HasSessionClusters => SessionClusters.Count > 0;
    public string SessionClustersTitle => "Session clusters";
    public string SessionClustersEmptyState => HasSessionClusters ? "" : "No activity sessions recorded yet.";

    public string RiskLabel
    {
        get
        {
            if (Pid <= 0) return "";
            if (RiskScore >= 70) return $"Risk: High ({RiskScore})";
            if (RiskScore >= 40) return $"Risk: Medium ({RiskScore})";
            if (RiskScore > 0) return $"Risk: Low ({RiskScore})";
            return "Risk: None";
        }
    }

    public Brush RiskBrush
    {
        get
        {
            if (RiskScore >= 70) return Brushes.IndianRed;
            if (RiskScore >= 40) return Brushes.DarkOrange;
            if (RiskScore > 0) return Brushes.OliveDrab;
            return Brushes.Gray;
        }
    }
    private long _packetCount;
    public long PacketCount { get => _packetCount; set { if (_packetCount != value) { _packetCount = value; OnPropertyChanged(); } } }

    private long _totalBytes;
    public long TotalBytes { get => _totalBytes; set { if (_totalBytes != value) { _totalBytes = value; OnPropertyChanged(); OnPropertyChanged(nameof(TrafficMb)); OnPropertyChanged(nameof(TotalBytesHuman)); } } }

    private int _distinctRemoteEndpoints;
    public int DistinctRemoteEndpoints { get => _distinctRemoteEndpoints; set { if (_distinctRemoteEndpoints != value) { _distinctRemoteEndpoints = value; OnPropertyChanged(); RecomputeRisk(); } } }

    private string _topRemoteEndpoint = "";
    public string TopRemoteEndpoint { get => _topRemoteEndpoint; set { if (_topRemoteEndpoint != value) { _topRemoteEndpoint = value; OnPropertyChanged(); } } }

    private bool _beaconSuspected;
    public bool BeaconSuspected { get => _beaconSuspected; set { if (_beaconSuspected != value) { _beaconSuspected = value; OnPropertyChanged(); OnPropertyChanged(nameof(BeaconLabel)); RecomputeRisk(); } } }

    private double _beaconIntervalSec;
    public double BeaconIntervalSec { get => _beaconIntervalSec; set { if (Math.Abs(_beaconIntervalSec - value) > 0.001) { _beaconIntervalSec = value; OnPropertyChanged(); OnPropertyChanged(nameof(BeaconLabel)); } } }

    private double _beaconCv;
    public double BeaconCv { get => _beaconCv; set { if (Math.Abs(_beaconCv - value) > 0.001) { _beaconCv = value; OnPropertyChanged(); OnPropertyChanged(nameof(BeaconLabel)); } } }

    private int _beaconSamples;
    public int BeaconSamples { get => _beaconSamples; set { if (_beaconSamples != value) { _beaconSamples = value; OnPropertyChanged(); OnPropertyChanged(nameof(BeaconLabel)); } } }

    public string BeaconLabel => !BeaconSuspected
        ? ""
        : $"Beacon: ~{BeaconIntervalSec:0.#}s (cv {BeaconCv:0.##}, n={BeaconSamples})";

    private string _firstSuspiciousDomain = "";
    public string FirstSuspiciousDomain
    {
        get => _firstSuspiciousDomain;
        private set
        {
            if (_firstSuspiciousDomain != value)
            {
                _firstSuspiciousDomain = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(HasSuspiciousDomain));
                RecomputeRisk();
            }
        }
    }

    public bool HasSuspiciousDomain => !string.IsNullOrWhiteSpace(FirstSuspiciousDomain);

    private string _suspiciousDomainReason = "";
    public string SuspiciousDomainReason
    {
        get => _suspiciousDomainReason;
        private set
        {
            if (_suspiciousDomainReason != value)
            {
                _suspiciousDomainReason = value;
                OnPropertyChanged();
                RecomputeRisk();
            }
        }
    }

    private int _identityChangeCount;
    public int IdentityChangeCount
    {
        get => _identityChangeCount;
        private set
        {
            if (_identityChangeCount != value)
            {
                _identityChangeCount = value;
                OnPropertyChanged();
                RecomputeRisk();
            }
        }
    }

    private bool _firewallBlocked;
    public bool FirewallBlocked
    {
        get => _firewallBlocked;
        private set
        {
            if (_firewallBlocked != value)
            {
                _firewallBlocked = value;
                OnPropertyChanged();
            }
        }
    }

    private DateTime? _lastTrafficPeakAt;
    private bool _exitedAfterTrafficPeak;
    public bool ExitedAfterTrafficPeak
    {
        get => _exitedAfterTrafficPeak;
        private set
        {
            if (_exitedAfterTrafficPeak != value)
            {
                _exitedAfterTrafficPeak = value;
                OnPropertyChanged();
                RecomputeRisk();
            }
        }
    }

    // rolling samples of packets per update interval
    private readonly Queue<int> _samples = new();
    public IReadOnlyList<int> Samples => _samples.ToArray();

    public int LastSamplePackets => _samples.Count == 0 ? 0 : _samples.Last();
    public double AvgSamplePackets => _samples.Count == 0 ? 0 : _samples.Average();
    public int PeakSamplePackets => _samples.Count == 0 ? 0 : _samples.Max();

    public Geometry? SparklineGeometry { get => _sparklineGeometry; private set { _sparklineGeometry = value; OnPropertyChanged(); } }
    private Geometry? _sparklineGeometry;

    public double TrafficMb => TotalBytes / 1024.0 / 1024.0;
    public string TotalBytesHuman => FormatBytes(TotalBytes);

    public string DisplayName => Pid > 0 ? $"{ProcessName} (PID: {Pid})" : ProcessName;

    public ProcessStatRow(int pid, string name, long count, long totalBytes)
    {
        Pid = pid;
        ProcessName = name;
        _packetCount = count;
        _totalBytes = totalBytes;

        _isAlive = true;

        RecomputeRisk();
    }

    public void UpdateIdentity(string exePath, string publisher, bool isSigned, string signerSubject, int parentPid, string parentName)
    {
        ExePath = exePath;
        Publisher = publisher;
        IsSigned = isSigned;
        SignerSubject = signerSubject;
        ParentPid = parentPid;
        ParentName = parentName;
    }

    public void AddSample(int value)
    {
        if (_samples.Count >= MaxSamples)
            _samples.Dequeue();
        _samples.Enqueue(value);
        RebuildGeometry();

        RecomputeRisk();

        OnPropertyChanged(nameof(LastSamplePackets));
        OnPropertyChanged(nameof(AvgSamplePackets));
        OnPropertyChanged(nameof(PeakSamplePackets));
    }

    private static string FormatBytes(long bytes)
    {
        const double KB = 1024;
        const double MB = KB * 1024;
        const double GB = MB * 1024;

        if (bytes >= GB) return $"{bytes / GB:0.##} GB";
        if (bytes >= MB) return $"{bytes / MB:0.##} MB";
        if (bytes >= KB) return $"{bytes / KB:0.##} KB";
        return $"{bytes:N0} B";
    }

    private void RebuildGeometry()
    {
        if (_samples.Count == 0)
        {
            SparklineGeometry = null;
            return;
        }

        double width = 180; // fits column
        double height = 24;
        var pts = _samples.ToArray();
        int n = pts.Length;
        int max = pts.Max();
        if (max == 0) max = 1;

        var geom = new StreamGeometry();
        using (var ctx = geom.Open())
        {
            for (int i = 0; i < n; i++)
            {
                double x = (i * width) / (MaxSamples - 1);
                double y = height - ((double)pts[i] / max) * height;
                if (i == 0)
                    ctx.BeginFigure(new Point(x, y), false, false);
                else
                    ctx.LineTo(new Point(x, y), true, false);
            }
        }
        geom.Freeze();
        SparklineGeometry = geom;
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    private void RecomputeRisk()
    {
        // Explainable heuristics: every score contribution must map to a visible reason in the UI.
        var signals = new List<RiskSignal>(5);

        if (Pid <= 0)
        {
            RiskReasons = Array.Empty<RiskReason>();
            RiskScore = 0;
            return;
        }

        if (!string.IsNullOrWhiteSpace(ExePath))
        {
            if (!IsSigned)
                signals.Add(new RiskSignal("Unsigned executable", 25));

            var riskyLocation = GetRiskyLocationLabel(ExePath);
            if (!string.IsNullOrWhiteSpace(riskyLocation))
                signals.Add(new RiskSignal(riskyLocation, 15));
        }
        else
        {
            signals.Add(new RiskSignal("Executable path could not be resolved", 5));
        }

        // Packet burst heuristic based on the last sampling interval.
        if (LastSamplePackets >= 2000)
            signals.Add(new RiskSignal($"Extreme burst in the last interval ({LastSamplePackets:N0} packets)", 25));
        else if (LastSamplePackets >= 800)
            signals.Add(new RiskSignal($"Large burst in the last interval ({LastSamplePackets:N0} packets)", 20));
        else if (LastSamplePackets >= 300)
            signals.Add(new RiskSignal($"Noticeable burst in the last interval ({LastSamplePackets:N0} packets)", 10));

        if (DistinctRemoteEndpoints >= 1000)
            signals.Add(new RiskSignal($"Talks to a very wide set of remote endpoints ({DistinctRemoteEndpoints:N0})", 15));
        else if (DistinctRemoteEndpoints >= 200)
            signals.Add(new RiskSignal($"Talks to many remote endpoints ({DistinctRemoteEndpoints:N0})", 10));

        if (BeaconSuspected)
        {
            string summary = BeaconIntervalSec > 0
                ? $"Beacon-like periodic traffic (~{BeaconIntervalSec:0.#}s cadence)"
                : "Beacon-like periodic traffic pattern";

            signals.Add(new RiskSignal(summary, 20));
        }

        if (HasSuspiciousDomain)
        {
            string summary = string.IsNullOrWhiteSpace(SuspiciousDomainReason)
                ? $"Resolved suspicious domain {FirstSuspiciousDomain}"
                : $"Resolved suspicious domain {FirstSuspiciousDomain} ({SuspiciousDomainReason})";

            signals.Add(new RiskSignal(summary, 15));
        }

        if (IdentityChangeCount >= 2)
            signals.Add(new RiskSignal($"Process identity changed {IdentityChangeCount} times while observed", 15));
        else if (IdentityChangeCount == 1)
            signals.Add(new RiskSignal("Process identity changed while observed", 10));

        if (ExitedAfterTrafficPeak)
            signals.Add(new RiskSignal("Exited shortly after a traffic burst", 10));

        RiskReasons = signals
            .Select(signal => new RiskReason(signal.Summary, signal.Points))
            .ToArray();

        RiskScore = signals.Sum(signal => signal.Points);
    }

    public void RecordProcessStart(DateTime timestamp, string detail)
        => UpsertTimelineEvent("process-start", timestamp, "Process start", detail);

    public void RecordFirstPacket(DateTime timestamp, string detail)
        => AddTimelineEventIfMissing("first-packet", timestamp, "First packet", detail, new InvestigationTimelineTarget("first-packet"));

    public void RecordFirstOutboundConnection(DateTime timestamp, string detail)
        => AddTimelineEventIfMissing("first-outbound-connection", timestamp, "First outbound connection", detail, new InvestigationTimelineTarget("first-outbound-connection"));

    public void RecordFirstDomain(DateTime timestamp, string domain)
        => AddTimelineEventIfMissing("first-domain", timestamp, "First domain", domain, new InvestigationTimelineTarget("first-domain", domain));

    public void RecordFirstSecureHandshake(DateTime timestamp, string detail)
        => AddTimelineEventIfMissing("first-secure-handshake", timestamp, "First TLS/QUIC handshake", detail, new InvestigationTimelineTarget("first-secure-handshake"));

    public void RecordFirstSuspiciousDomain(DateTime timestamp, string domain, string reason)
    {
        if (!HasSuspiciousDomain)
        {
            FirstSuspiciousDomain = domain;
            SuspiciousDomainReason = reason;
        }

        AddTimelineEventIfMissing("first-suspicious-domain", timestamp, "First suspicious domain", $"{domain} ({reason})", new InvestigationTimelineTarget("first-suspicious-domain", domain));
    }

    public void RecordTrafficPeak(DateTime timestamp, int packetsPerInterval)
    {
        if (packetsPerInterval <= 0)
            return;

        _lastTrafficPeakAt = timestamp;

        string detail = AvgSamplePackets > 0
            ? $"Burst of {packetsPerInterval:N0} packets in one interval (avg {AvgSamplePackets:0.#})."
            : $"Burst of {packetsPerInterval:N0} packets in one interval.";

        UpsertTimelineEvent("traffic-peak", timestamp, "Traffic peak", detail, new InvestigationTimelineTarget("traffic-peak"));
    }

    public void RecordBurstEnded(DateTime timestamp, string detail)
        => AppendTimelineEvent($"burst-ended-{timestamp.Ticks}", timestamp, "Burst ended", detail);

    public void RecordBeaconDetected(DateTime timestamp, string detail)
        => AddTimelineEventIfMissing("beacon-detected", timestamp, "Beaconing detected", detail, new InvestigationTimelineTarget("beacon-detected"));

    public void RecordProcessExited(DateTime timestamp, string detail)
    {
        if (_lastTrafficPeakAt.HasValue && timestamp >= _lastTrafficPeakAt.Value && (timestamp - _lastTrafficPeakAt.Value) <= TimeSpan.FromMinutes(2))
            ExitedAfterTrafficPeak = true;

        AddTimelineEventIfMissing("process-exited", timestamp, "Process exited", detail);
    }

    public void RecordIdentityChanged(DateTime timestamp, string detail)
    {
        IdentityChangeCount++;
        AppendTimelineEvent($"process-identity-{timestamp.Ticks}", timestamp, "Process identity changed", detail);
    }

    public void RecordFirewallBlock(DateTime timestamp)
    {
        FirewallBlocked = true;
        AppendTimelineEvent($"firewall-block-{timestamp.Ticks}", timestamp, "Firewall block applied", "TrafficMonitor added Windows Firewall rules for this executable.");
    }

    public void RecordFirewallUnblock(DateTime timestamp)
    {
        FirewallBlocked = false;
        AppendTimelineEvent($"firewall-unblock-{timestamp.Ticks}", timestamp, "Firewall block removed", "TrafficMonitor removed its Windows Firewall rules for this executable.");
    }

    public void UpdateConversations(IEnumerable<ProcessConversationRow> conversations)
    {
        Conversations.Clear();
        foreach (var conversation in conversations)
            Conversations.Add(conversation);

        OnPropertyChanged(nameof(HasConversations));
        OnPropertyChanged(nameof(ConversationEmptyState));
    }

    public void UpdateSessionClusters(IEnumerable<ProcessSessionClusterRow> sessionClusters)
    {
        SessionClusters.Clear();
        foreach (var sessionCluster in sessionClusters)
            SessionClusters.Add(sessionCluster);

        OnPropertyChanged(nameof(HasSessionClusters));
        OnPropertyChanged(nameof(SessionClustersEmptyState));
    }

    private void AddTimelineEventIfMissing(string key, DateTime timestamp, string title, string detail, InvestigationTimelineTarget? target = null)
    {
        if (HasTimelineEvent(key))
            return;

        AppendTimelineEvent(key, timestamp, title, detail, target);
    }

    private void UpsertTimelineEvent(string key, DateTime timestamp, string title, string detail, InvestigationTimelineTarget? target = null)
    {
        if (timestamp == default)
            return;

        var entry = new InvestigationTimelineEvent(Pid, key, timestamp, title, detail, target);
        int existingIndex = FindTimelineEventIndex(key);
        if (existingIndex >= 0)
            TimelineEvents.RemoveAt(existingIndex);

        InsertTimelineEvent(entry);
    }

    private void AppendTimelineEvent(string key, DateTime timestamp, string title, string detail, InvestigationTimelineTarget? target = null)
    {
        if (timestamp == default)
            return;

        InsertTimelineEvent(new InvestigationTimelineEvent(Pid, key, timestamp, title, detail, target));
    }

    private void InsertTimelineEvent(InvestigationTimelineEvent entry)
    {
        int insertIndex = 0;
        while (insertIndex < TimelineEvents.Count && TimelineEvents[insertIndex].Timestamp <= entry.Timestamp)
            insertIndex++;

        TimelineEvents.Insert(insertIndex, entry);
        OnPropertyChanged(nameof(HasTimelineEvents));
        OnPropertyChanged(nameof(TimelineEmptyState));
    }

    private bool HasTimelineEvent(string key) => FindTimelineEventIndex(key) >= 0;

    private int FindTimelineEventIndex(string key)
    {
        for (int i = 0; i < TimelineEvents.Count; i++)
        {
            if (string.Equals(TimelineEvents[i].Key, key, StringComparison.Ordinal))
                return i;
        }

        return -1;
    }

    private static string? GetRiskyLocationLabel(string exePath)
    {
        var path = exePath.Replace('/', '\\');

        if (path.Contains("\\AppData\\", StringComparison.OrdinalIgnoreCase))
            return "Runs from AppData (user-writable path)";

        if (path.Contains("\\Temp\\", StringComparison.OrdinalIgnoreCase))
            return "Runs from Temp (user-writable path)";

        if (path.Contains("\\Downloads\\", StringComparison.OrdinalIgnoreCase))
            return "Runs from Downloads (user-writable path)";

        if (path.Contains("\\Desktop\\", StringComparison.OrdinalIgnoreCase))
            return "Runs from Desktop (user-writable path)";

        return null;
    }
}
