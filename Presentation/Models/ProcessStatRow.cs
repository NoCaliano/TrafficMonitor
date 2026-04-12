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

    public sealed record DetectionEvidence(string Summary);

    public sealed record DetectionScenario(
        string Key,
        string Title,
        string MitreTechnique,
        string MitreTactic,
        string Summary,
        int Confidence,
        int RiskPoints,
        IReadOnlyList<DetectionEvidence> Evidence)
    {
        public string MitreLabel => string.IsNullOrWhiteSpace(MitreTechnique)
            ? $"ATT&CK {MitreTactic}"
            : $"ATT&CK {MitreTechnique} · {MitreTactic}";

        public string ConfidenceBucket => Confidence switch
        {
            >= 85 => "High confidence",
            >= 70 => "Medium confidence",
            _ => "Low confidence"
        };

        public string MitreDisplayLabel => string.IsNullOrWhiteSpace(MitreTechnique)
            ? $"ATT&CK {MitreTactic}"
            : $"ATT&CK {MitreTechnique} / {MitreTactic}";

        public string ConfidenceLabel => $"{ConfidenceBucket} ({Confidence}%)";
        public string ConfidenceBadge => $"{Confidence}%";

        public Brush ConfidenceBrush => Confidence switch
        {
            >= 85 => Brushes.IndianRed,
            >= 70 => Brushes.DarkOrange,
            _ => Brushes.OliveDrab
        };
    }

    private readonly List<string> _pendingPropertyNames = new();
    private int _deferNotificationsDepth;
    private bool _riskDirty = true;

    public int Pid { get; }
    public string ProcessName { get; }

    private bool _isSelectedInProcessGrid;
    public bool IsSelectedInProcessGrid
    {
        get => _isSelectedInProcessGrid;
        set
        {
            if (_isSelectedInProcessGrid == value)
                return;

            _isSelectedInProcessGrid = value;
            OnPropertyChanged();
        }
    }

    private bool _isAlive;
    public bool IsAlive { get => _isAlive; set { if (_isAlive != value) { _isAlive = value; OnPropertyChanged(); OnPropertyChanged(nameof(LivenessLabel)); OnPropertyChanged(nameof(LivenessBrush)); } } }

    public string LivenessLabel => Pid <= 0 ? "" : (IsAlive ? "Active" : "Exited");

    public Brush LivenessBrush => IsAlive ? Brushes.SeaGreen : Brushes.Gray;

    private DateTime _lastSeen;
    public DateTime LastSeen { get => _lastSeen; set { if (_lastSeen != value) { _lastSeen = value; OnPropertyChanged(); OnPropertyChanged(nameof(LastSeenLabel)); } } }

    public string LastSeenLabel => LastSeen == default ? "" : $"Last: {LastSeen:HH:mm:ss}";

    private string _exePath = "";
    public string ExePath { get => _exePath; set { if (_exePath != value) { _exePath = value; OnPropertyChanged(); OnPropertyChanged(nameof(ExePathShort)); OnPropertyChanged(nameof(ExePathIsEmpty)); InvalidateRisk(); } } }
    public bool ExePathIsEmpty => string.IsNullOrWhiteSpace(_exePath);
    public string ExePathShort => string.IsNullOrWhiteSpace(_exePath) ? "" : Path.GetFileName(_exePath);

    private string _publisher = "";
    public string Publisher { get => _publisher; set { if (_publisher != value) { _publisher = value; OnPropertyChanged(); InvalidateRisk(); } } }

    private bool _isSigned;
    public bool IsSigned { get => _isSigned; set { if (_isSigned != value) { _isSigned = value; OnPropertyChanged(); OnPropertyChanged(nameof(SignedLabel)); InvalidateRisk(); } } }
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
            if (AreEquivalentRiskReasons(_riskReasons, value))
                return;

            _riskReasons = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(HasRiskReasons));
            OnPropertyChanged(nameof(RiskEmptyState));
        }
    }

    public bool HasRiskReasons => _riskReasons.Count > 0;
    public string WhyFlaggedLabel => "Why flagged";
    public string RiskEmptyState => HasRiskReasons ? "" : "No active risk signals.";

    private IReadOnlyList<DetectionScenario> _detectionScenarios = Array.Empty<DetectionScenario>();
    public IReadOnlyList<DetectionScenario> DetectionScenarios
    {
        get => _detectionScenarios;
        private set
        {
            if (AreEquivalentDetectionScenarios(_detectionScenarios, value))
                return;

            _detectionScenarios = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(HasDetectionScenarios));
            OnPropertyChanged(nameof(DetectionScenariosEmptyState));
            OnPropertyChanged(nameof(DetectionSummaryLabel));
        }
    }

    public bool HasDetectionScenarios => _detectionScenarios.Count > 0;
    public string DetectionScenariosTitle => "Detection scenarios";
    public string DetectionScenariosEmptyState => HasDetectionScenarios ? "" : "No ATT&CK-style scenarios crossed the current confidence thresholds yet.";
    public string DetectionSummaryLabel => _detectionScenarios.Count switch
    {
        0 => "",
        1 => _detectionScenarios[0].Title,
        _ => $"{_detectionScenarios[0].Title} +{_detectionScenarios.Count - 1}"
    };

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
    public int DistinctRemoteEndpoints { get => _distinctRemoteEndpoints; set { if (_distinctRemoteEndpoints != value) { _distinctRemoteEndpoints = value; OnPropertyChanged(); InvalidateRisk(); } } }

    private string _topRemoteEndpoint = "";
    public string TopRemoteEndpoint { get => _topRemoteEndpoint; set { if (_topRemoteEndpoint != value) { _topRemoteEndpoint = value; OnPropertyChanged(); } } }

    private bool _beaconSuspected;
    public bool BeaconSuspected { get => _beaconSuspected; set { if (_beaconSuspected != value) { _beaconSuspected = value; OnPropertyChanged(); OnPropertyChanged(nameof(BeaconLabel)); InvalidateRisk(); } } }

    private string _beaconEndpoint = "";

    private double _beaconIntervalSec;
    public double BeaconIntervalSec { get => _beaconIntervalSec; set { if (Math.Abs(_beaconIntervalSec - value) > 0.001) { _beaconIntervalSec = value; OnPropertyChanged(); OnPropertyChanged(nameof(BeaconLabel)); InvalidateRisk(); } } }

    private double _beaconCv;
    public double BeaconCv { get => _beaconCv; set { if (Math.Abs(_beaconCv - value) > 0.001) { _beaconCv = value; OnPropertyChanged(); OnPropertyChanged(nameof(BeaconLabel)); InvalidateRisk(); } } }

    private int _beaconSamples;
    public int BeaconSamples { get => _beaconSamples; set { if (_beaconSamples != value) { _beaconSamples = value; OnPropertyChanged(); OnPropertyChanged(nameof(BeaconLabel)); InvalidateRisk(); } } }

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
                InvalidateRisk();
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
                InvalidateRisk();
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
                InvalidateRisk();
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
    private DateTime? _processExitedAt;
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
                InvalidateRisk();
            }
        }
    }

    private long _outboundBytes;
    private long _inboundBytes;
    private long _outboundPacketsObserved;
    private long _inboundPacketsObserved;

    private const int MaxTrackedDnsQueries = 4096;
    private const int MaxTrackedDnsRoots = 512;
    private readonly HashSet<string> _distinctDnsQueries = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, int> _dnsRootQueryCounts = new(StringComparer.OrdinalIgnoreCase);
    private int _dnsQueryCount;
    private int _dnsTxtQueryCount;
    private int _dnsEncodedQueryCount;
    private int _dnsLongestLabelLength;
    private string _dominantDnsRoot = "";
    private int _dominantDnsRootCount;

    public long OutboundBytes => _outboundBytes;
    public long InboundBytes => _inboundBytes;
    public long OutboundPacketsObserved => _outboundPacketsObserved;
    public long InboundPacketsObserved => _inboundPacketsObserved;
    public int DnsQueryCount => _dnsQueryCount;
    public int UniqueDnsQueryCount => _distinctDnsQueries.Count;
    public int DnsTxtQueryCount => _dnsTxtQueryCount;
    public int DnsEncodedQueryCount => _dnsEncodedQueryCount;
    public int DnsLongestLabelLength => _dnsLongestLabelLength;
    public string DominantDnsRoot => _dominantDnsRoot;
    public int DominantDnsRootCount => _dominantDnsRootCount;
    public string BeaconEndpoint => _beaconEndpoint;

    // rolling samples of packets per update interval
    private readonly List<int> _samples = new(MaxSamples);
    private int _lastSamplePackets;
    private double _avgSamplePackets;
    private int _peakSamplePackets;

    public IReadOnlyList<int> Samples => _samples;

    public int LastSamplePackets => _lastSamplePackets;
    public double AvgSamplePackets => _avgSamplePackets;
    public int PeakSamplePackets => _peakSamplePackets;

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

        RecomputeRiskIfNeeded();
    }

    public void UpdateIdentity(string exePath, string publisher, bool isSigned, string signerSubject, int parentPid, string parentName)
        => DeferNotifications(() =>
        {
            ExePath = exePath;
            Publisher = publisher;
            IsSigned = isSigned;
            SignerSubject = signerSubject;
            ParentPid = parentPid;
            ParentName = parentName;
        });

    public void ObserveDirectionalTraffic(bool isOutbound, bool isInbound, int bytes)
    {
        if (bytes <= 0)
            return;

        if (isOutbound)
        {
            _outboundBytes += bytes;
            _outboundPacketsObserved++;
        }

        if (isInbound)
        {
            _inboundBytes += bytes;
            _inboundPacketsObserved++;
        }
    }

    public void ObserveDnsQuery(string domain, string? queryType)
    {
        string normalized = NormalizeDomain(domain);
        if (string.IsNullOrWhiteSpace(normalized))
            return;

        _dnsQueryCount++;
        if (string.Equals(queryType, "TXT", StringComparison.OrdinalIgnoreCase))
            _dnsTxtQueryCount++;

        if (_distinctDnsQueries.Count < MaxTrackedDnsQueries)
            _distinctDnsQueries.Add(normalized);

        int longestLabel = GetLongestDnsLabelLength(normalized);
        if (longestLabel > _dnsLongestLabelLength)
            _dnsLongestLabelLength = longestLabel;

        if (LooksEncodedDnsQuery(normalized))
            _dnsEncodedQueryCount++;

        string root = GetDnsRootDomain(normalized);
        if (string.IsNullOrWhiteSpace(root))
            return;

        if (_dnsRootQueryCounts.TryGetValue(root, out var currentCount))
        {
            currentCount++;
            _dnsRootQueryCounts[root] = currentCount;
        }
        else
        {
            if (_dnsRootQueryCounts.Count >= MaxTrackedDnsRoots)
                return;

            currentCount = 1;
            _dnsRootQueryCounts[root] = currentCount;
        }

        if (currentCount > _dominantDnsRootCount
            || (currentCount == _dominantDnsRootCount
                && string.Compare(root, _dominantDnsRoot, StringComparison.OrdinalIgnoreCase) < 0))
        {
            _dominantDnsRoot = root;
            _dominantDnsRootCount = currentCount;
        }
    }

    public void UpdateBeaconSignal(string endpoint, double intervalSec, double cv, int samples)
        => DeferNotifications(() =>
        {
            BeaconSuspected = true;
            BeaconIntervalSec = intervalSec;
            BeaconCv = cv;
            BeaconSamples = samples;
            _beaconEndpoint = endpoint ?? "";
        });

    public void AddSample(int value)
    {
        DeferNotifications(() =>
        {
            if (_samples.Count >= MaxSamples)
                _samples.RemoveAt(0);

            _samples.Add(value);
            RecomputeSampleStats();
            RebuildGeometry();
            InvalidateRisk();

            OnPropertyChanged(nameof(Samples));
            OnPropertyChanged(nameof(LastSamplePackets));
            OnPropertyChanged(nameof(AvgSamplePackets));
            OnPropertyChanged(nameof(PeakSamplePackets));
        });
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
        int n = _samples.Count;
        int max = PeakSamplePackets;
        if (max == 0) max = 1;

        var geom = new StreamGeometry();
        using (var ctx = geom.Open())
        {
            for (int i = 0; i < n; i++)
            {
                double x = (i * width) / (MaxSamples - 1);
                double y = height - ((double)_samples[i] / max) * height;
                if (i == 0)
                    ctx.BeginFigure(new Point(x, y), false, false);
                else
                    ctx.LineTo(new Point(x, y), true, false);
            }
        }
        geom.Freeze();
        SparklineGeometry = geom;
    }

    private void RecomputeSampleStats()
    {
        if (_samples.Count == 0)
        {
            _lastSamplePackets = 0;
            _avgSamplePackets = 0;
            _peakSamplePackets = 0;
            return;
        }

        long sum = 0;
        int peak = 0;
        for (int i = 0; i < _samples.Count; i++)
        {
            int sample = _samples[i];
            sum += sample;
            if (sample > peak)
                peak = sample;
        }

        _lastSamplePackets = _samples[^1];
        _avgSamplePackets = sum / (double)_samples.Count;
        _peakSamplePackets = peak;
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null)
    {
        if (string.IsNullOrWhiteSpace(name))
            return;

        if (_deferNotificationsDepth > 0)
        {
            bool exists = false;
            for (int i = 0; i < _pendingPropertyNames.Count; i++)
            {
                if (string.Equals(_pendingPropertyNames[i], name, StringComparison.Ordinal))
                {
                    exists = true;
                    break;
                }
            }

            if (!exists)
                _pendingPropertyNames.Add(name);

            return;
        }

        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }

    private void DeferNotifications(Action action)
    {
        _deferNotificationsDepth++;
        try
        {
            action();
        }
        finally
        {
            _deferNotificationsDepth--;
            if (_deferNotificationsDepth == 0)
            {
                RecomputeRiskIfNeeded();
                FlushDeferredPropertyChanges();
            }
        }
    }

    private void FlushDeferredPropertyChanges()
    {
        if (_pendingPropertyNames.Count == 0)
            return;

        for (int i = 0; i < _pendingPropertyNames.Count; i++)
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(_pendingPropertyNames[i]));

        _pendingPropertyNames.Clear();
    }

    private void InvalidateRisk()
    {
        _riskDirty = true;
        if (_deferNotificationsDepth == 0)
            RecomputeRiskIfNeeded();
    }

    private void RecomputeRiskIfNeeded()
    {
        if (!_riskDirty)
            return;

        _riskDirty = false;
        RecomputeRisk();
    }

    private void RecomputeRisk()
    {
        // Explainable heuristics: every score contribution must map to a visible reason in the UI.
        var signals = new List<RiskSignal>(8);

        if (Pid <= 0)
        {
            DetectionScenarios = Array.Empty<DetectionScenario>();
            RiskReasons = Array.Empty<RiskReason>();
            RiskScore = 0;
            return;
        }

        var scenarios = BuildDetectionScenarios();
        bool hasFanOutScenario = scenarios.Any(static scenario => scenario.Key == "scan-like-fan-out");
        bool hasBurstExitScenario = scenarios.Any(static scenario => scenario.Key == "burst-and-exit");

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

        if (!hasFanOutScenario)
        {
            if (DistinctRemoteEndpoints >= 1000)
                signals.Add(new RiskSignal($"Talks to a very wide set of remote endpoints ({DistinctRemoteEndpoints:N0})", 15));
            else if (DistinctRemoteEndpoints >= 200)
                signals.Add(new RiskSignal($"Talks to many remote endpoints ({DistinctRemoteEndpoints:N0})", 10));
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

        if (!hasBurstExitScenario && ExitedAfterTrafficPeak)
            signals.Add(new RiskSignal("Exited shortly after a traffic burst", 10));

        foreach (var scenario in scenarios)
            signals.Add(new RiskSignal($"{scenario.Title} ({scenario.ConfidenceLabel})", scenario.RiskPoints));

        DetectionScenarios = scenarios;
        SyncDetectionScenarioTimeline(scenarios);

        RiskReasons = signals
            .OrderByDescending(signal => signal.Points)
            .ThenBy(signal => signal.Summary, StringComparer.Ordinal)
            .Select(signal => new RiskReason(signal.Summary, signal.Points))
            .ToArray();

        RiskScore = Math.Min(100, signals.Sum(signal => signal.Points));
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
        DeferNotifications(() =>
        {
            if (!HasSuspiciousDomain)
            {
                FirstSuspiciousDomain = domain;
                SuspiciousDomainReason = reason;
            }

            AddTimelineEventIfMissing("first-suspicious-domain", timestamp, "First suspicious domain", $"{domain} ({reason})", new InvestigationTimelineTarget("first-suspicious-domain", domain));
        });
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
        _processExitedAt = timestamp;

        if (_lastTrafficPeakAt.HasValue && timestamp >= _lastTrafficPeakAt.Value && (timestamp - _lastTrafficPeakAt.Value) <= TimeSpan.FromMinutes(2))
            ExitedAfterTrafficPeak = true;

        AddTimelineEventIfMissing("process-exited", timestamp, "Process exited", detail);
    }

    public void RecordIdentityChanged(DateTime timestamp, string detail)
        => DeferNotifications(() =>
        {
            IdentityChangeCount++;
            AppendTimelineEvent($"process-identity-{timestamp.Ticks}", timestamp, "Process identity changed", detail);
        });

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
        ReplaceCollection(Conversations, conversations, AreEquivalentConversations);
        OnPropertyChanged(nameof(HasConversations));
        OnPropertyChanged(nameof(ConversationEmptyState));
    }

    public void UpdateSessionClusters(IEnumerable<ProcessSessionClusterRow> sessionClusters)
    {
        ReplaceCollection(SessionClusters, sessionClusters, AreEquivalentSessionClusters);
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

    private static void ReplaceCollection<T>(ObservableCollection<T> target, IEnumerable<T> source, Func<T, T, bool> areEquivalent)
    {
        var desired = source as IReadOnlyList<T> ?? source.ToArray();
        if (HasSameContent(target, desired, areEquivalent))
            return;

        int sharedCount = Math.Min(target.Count, desired.Count);
        for (int i = 0; i < sharedCount; i++)
        {
            if (!areEquivalent(target[i], desired[i]))
                target[i] = desired[i];
        }

        while (target.Count > desired.Count)
            target.RemoveAt(target.Count - 1);

        for (int i = target.Count; i < desired.Count; i++)
            target.Add(desired[i]);
    }

    private static bool HasSameContent<T>(ObservableCollection<T> current, IReadOnlyList<T> desired, Func<T, T, bool> areEquivalent)
    {
        if (current.Count != desired.Count)
            return false;

        for (int i = 0; i < current.Count; i++)
        {
            if (!areEquivalent(current[i], desired[i]))
                return false;
        }

        return true;
    }

    private static bool AreEquivalentRiskReasons(IReadOnlyList<RiskReason> left, IReadOnlyList<RiskReason> right)
    {
        if (ReferenceEquals(left, right))
            return true;

        if (left.Count != right.Count)
            return false;

        for (int i = 0; i < left.Count; i++)
        {
            if (left[i].Points != right[i].Points
                || !string.Equals(left[i].Summary, right[i].Summary, StringComparison.Ordinal))
            {
                return false;
            }
        }

        return true;
    }

    private static bool AreEquivalentDetectionScenarios(IReadOnlyList<DetectionScenario> left, IReadOnlyList<DetectionScenario> right)
    {
        if (ReferenceEquals(left, right))
            return true;

        if (left.Count != right.Count)
            return false;

        for (int i = 0; i < left.Count; i++)
        {
            var leftScenario = left[i];
            var rightScenario = right[i];

            if (leftScenario.Confidence != rightScenario.Confidence
                || leftScenario.RiskPoints != rightScenario.RiskPoints
                || !string.Equals(leftScenario.Key, rightScenario.Key, StringComparison.Ordinal)
                || !string.Equals(leftScenario.Title, rightScenario.Title, StringComparison.Ordinal)
                || !string.Equals(leftScenario.MitreTechnique, rightScenario.MitreTechnique, StringComparison.Ordinal)
                || !string.Equals(leftScenario.MitreTactic, rightScenario.MitreTactic, StringComparison.Ordinal)
                || !string.Equals(leftScenario.Summary, rightScenario.Summary, StringComparison.Ordinal)
                || leftScenario.Evidence.Count != rightScenario.Evidence.Count)
            {
                return false;
            }

            for (int evidenceIndex = 0; evidenceIndex < leftScenario.Evidence.Count; evidenceIndex++)
            {
                if (!string.Equals(leftScenario.Evidence[evidenceIndex].Summary, rightScenario.Evidence[evidenceIndex].Summary, StringComparison.Ordinal))
                    return false;
            }
        }

        return true;
    }

    private static bool AreEquivalentConversations(ProcessConversationRow left, ProcessConversationRow right)
        => left.Pid == right.Pid
            && left.RemotePort == right.RemotePort
            && left.PacketCount == right.PacketCount
            && left.TotalBytes == right.TotalBytes
            && left.FirstSeen == right.FirstSeen
            && left.LastSeen == right.LastSeen
            && left.OutboundPackets == right.OutboundPackets
            && left.InboundPackets == right.InboundPackets
            && string.Equals(left.Protocol, right.Protocol, StringComparison.Ordinal)
            && string.Equals(left.RemoteIp, right.RemoteIp, StringComparison.Ordinal)
            && string.Equals(left.ResolvedHost, right.ResolvedHost, StringComparison.Ordinal);

    private static bool AreEquivalentSessionClusters(ProcessSessionClusterRow left, ProcessSessionClusterRow right)
        => left.Pid == right.Pid
            && left.Index == right.Index
            && left.FirstSeen == right.FirstSeen
            && left.LastSeen == right.LastSeen
            && left.PacketCount == right.PacketCount
            && left.TotalBytes == right.TotalBytes
            && left.DistinctRemoteEndpoints == right.DistinctRemoteEndpoints
            && left.OutboundPackets == right.OutboundPackets
            && left.InboundPackets == right.InboundPackets
            && left.IsActive == right.IsActive
            && string.Equals(left.TopRemoteEndpoint, right.TopRemoteEndpoint, StringComparison.Ordinal);

    private IReadOnlyList<DetectionScenario> BuildDetectionScenarios()
    {
        var scenarios = new List<DetectionScenario>(capacity: 5);

        TryAddPossibleExfiltrationScenario(scenarios);
        TryAddDnsTunnelingScenario(scenarios);
        TryAddScanLikeFanOutScenario(scenarios);
        TryAddPeriodicBeaconScenario(scenarios);
        TryAddBurstAndExitScenario(scenarios);

        scenarios.Sort(static (left, right) =>
        {
            int comparison = right.Confidence.CompareTo(left.Confidence);
            if (comparison != 0)
                return comparison;

            comparison = right.RiskPoints.CompareTo(left.RiskPoints);
            if (comparison != 0)
                return comparison;

            return string.Compare(left.Title, right.Title, StringComparison.Ordinal);
        });

        return scenarios;
    }

    private void TryAddPossibleExfiltrationScenario(List<DetectionScenario> scenarios)
    {
        const long MinimumOutboundBytes = 8L * 1024 * 1024;
        if (_outboundBytes < MinimumOutboundBytes || _outboundPacketsObserved < 40)
            return;

        double outboundInboundRatio = _inboundBytes <= 0
            ? (_outboundBytes > 0 ? double.PositiveInfinity : 0)
            : _outboundBytes / (double)_inboundBytes;

        if (outboundInboundRatio < 4.0)
            return;

        int confidence = 58;
        if (_outboundBytes >= 32L * 1024 * 1024) confidence += 18;
        else if (_outboundBytes >= 16L * 1024 * 1024) confidence += 12;
        else confidence += 6;

        if (outboundInboundRatio >= 12) confidence += 12;
        else if (outboundInboundRatio >= 8) confidence += 8;
        else confidence += 4;

        if (DistinctRemoteEndpoints > 0 && DistinctRemoteEndpoints <= 3) confidence += 10;
        else if (DistinctRemoteEndpoints > 0 && DistinctRemoteEndpoints <= 8) confidence += 5;

        if (HasSuspiciousDomain) confidence += 4;
        if (BeaconSuspected) confidence += 4;

        confidence = Math.Clamp(confidence, 60, 96);
        int riskPoints = confidence >= 85 ? 30 : confidence >= 75 ? 24 : 18;

        var evidence = new List<DetectionEvidence>
        {
            new($"Outbound volume reached {FormatBytes(_outboundBytes)} vs {FormatBytes(_inboundBytes)} inbound (ratio {FormatRatio(outboundInboundRatio)})."),
            new($"Observed {_outboundPacketsObserved:N0} outbound packets across {Math.Max(1, DistinctRemoteEndpoints):N0} remote endpoints.")
        };

        if (!string.IsNullOrWhiteSpace(TopRemoteEndpoint))
            evidence.Add(new($"Primary remote endpoint by traffic: {TopRemoteEndpoint}."));

        if (HasSuspiciousDomain)
            evidence.Add(new($"Domain activity included {FirstSuspiciousDomain} ({SuspiciousDomainReason})."));

        scenarios.Add(new DetectionScenario(
            Key: "possible-exfiltration",
            Title: "Possible exfiltration",
            MitreTechnique: "T1041",
            MitreTactic: "Exfiltration",
            Summary: "Predominantly outbound transfer volume suggests staging or exfiltration behavior.",
            Confidence: confidence,
            RiskPoints: riskPoints,
            Evidence: evidence));
    }

    private void TryAddDnsTunnelingScenario(List<DetectionScenario> scenarios)
    {
        int uniqueQueryCount = _distinctDnsQueries.Count;
        if (_dnsQueryCount < 24 || uniqueQueryCount < 16 || _dominantDnsRootCount < 12)
            return;

        bool hasEncodedSignal = _dnsEncodedQueryCount >= 6 || _dnsLongestLabelLength >= 28 || _dnsTxtQueryCount >= 6;
        if (!hasEncodedSignal)
            return;

        double uniquenessRatio = uniqueQueryCount / (double)Math.Max(1, _dnsQueryCount);
        if (uniquenessRatio < 0.55)
            return;

        int confidence = 60;
        if (_dnsQueryCount >= 60) confidence += 8;
        else if (_dnsQueryCount >= 40) confidence += 4;

        if (_dnsEncodedQueryCount >= 12) confidence += 12;
        else if (_dnsEncodedQueryCount >= 8) confidence += 8;
        else confidence += 4;

        if (_dnsLongestLabelLength >= 36) confidence += 10;
        else if (_dnsLongestLabelLength >= 28) confidence += 6;

        if (_dnsTxtQueryCount >= 10) confidence += 8;
        else if (_dnsTxtQueryCount >= 6) confidence += 4;

        if (_dominantDnsRootCount >= 24) confidence += 6;
        else if (_dominantDnsRootCount >= 16) confidence += 3;

        confidence = Math.Clamp(confidence, 62, 96);
        int riskPoints = confidence >= 85 ? 28 : confidence >= 75 ? 22 : 16;

        var evidence = new List<DetectionEvidence>
        {
            new($"{_dnsQueryCount:N0} DNS queries observed with {uniqueQueryCount:N0} unique names (uniqueness {uniquenessRatio:P0})."),
            new($"Dominant root domain {_dominantDnsRoot} accounted for {_dominantDnsRootCount:N0} queries."),
            new($"Longest DNS label reached {_dnsLongestLabelLength} characters; {_dnsEncodedQueryCount:N0} queries looked encoded.")
        };

        if (_dnsTxtQueryCount > 0)
            evidence.Add(new($"{_dnsTxtQueryCount:N0} TXT queries were issued in the same process context."));

        scenarios.Add(new DetectionScenario(
            Key: "dns-tunneling",
            Title: "DNS tunneling",
            MitreTechnique: "T1071.004",
            MitreTactic: "Command and Control",
            Summary: "High-churn, encoded-looking DNS queries resemble tunneling over subdomains.",
            Confidence: confidence,
            RiskPoints: riskPoints,
            Evidence: evidence));
    }

    private void TryAddScanLikeFanOutScenario(List<DetectionScenario> scenarios)
    {
        if (DistinctRemoteEndpoints < 40 || PacketCount <= 0 || TotalBytes <= 0)
            return;

        double avgBytesPerRemote = TotalBytes / (double)DistinctRemoteEndpoints;
        double avgPacketsPerRemote = PacketCount / (double)DistinctRemoteEndpoints;

        if (avgBytesPerRemote > 64 * 1024 || avgPacketsPerRemote > 10)
            return;

        int confidence = 58;
        if (DistinctRemoteEndpoints >= 160) confidence += 20;
        else if (DistinctRemoteEndpoints >= 90) confidence += 12;
        else confidence += 6;

        if (avgPacketsPerRemote <= 3) confidence += 8;
        else if (avgPacketsPerRemote <= 5) confidence += 4;

        if (avgBytesPerRemote <= 8 * 1024) confidence += 8;
        else if (avgBytesPerRemote <= 24 * 1024) confidence += 4;

        if (LastSamplePackets >= 300) confidence += 4;

        confidence = Math.Clamp(confidence, 60, 93);
        int riskPoints = confidence >= 85 ? 22 : confidence >= 75 ? 18 : 14;

        var evidence = new List<DetectionEvidence>
        {
            new($"{DistinctRemoteEndpoints:N0} distinct remote endpoints were touched by the process."),
            new($"Average traffic per remote stayed low at {FormatBytes((long)avgBytesPerRemote)} and {avgPacketsPerRemote:0.#} packets."),
        };

        if (!string.IsNullOrWhiteSpace(TopRemoteEndpoint))
            evidence.Add(new($"No single destination dominated beyond {TopRemoteEndpoint}."));

        scenarios.Add(new DetectionScenario(
            Key: "scan-like-fan-out",
            Title: "Scan-like fan-out",
            MitreTechnique: "T1046",
            MitreTactic: "Discovery",
            Summary: "Wide, low-volume fan-out resembles service discovery or scanning behavior.",
            Confidence: confidence,
            RiskPoints: riskPoints,
            Evidence: evidence));
    }

    private void TryAddPeriodicBeaconScenario(List<DetectionScenario> scenarios)
    {
        if (!BeaconSuspected || BeaconSamples < 6)
            return;

        int confidence = 68;
        if (BeaconSamples >= 14) confidence += 14;
        else if (BeaconSamples >= 10) confidence += 10;
        else confidence += 6;

        if (BeaconCv <= 0.08) confidence += 10;
        else if (BeaconCv <= 0.12) confidence += 6;
        else if (BeaconCv <= 0.20) confidence += 2;

        if (!string.IsNullOrWhiteSpace(_beaconEndpoint))
            confidence += 4;

        confidence = Math.Clamp(confidence, 68, 97);
        int riskPoints = confidence >= 85 ? 28 : confidence >= 75 ? 22 : 16;

        var evidence = new List<DetectionEvidence>
        {
            new($"Recurring outbound cadence of ~{BeaconIntervalSec:0.#} seconds was observed."),
            new($"Jitter stayed low at cv {BeaconCv:0.##} across {BeaconSamples} repeated flow starts.")
        };

        if (!string.IsNullOrWhiteSpace(_beaconEndpoint))
            evidence.Insert(0, new($"Primary repeating endpoint: {_beaconEndpoint}."));

        if (HasSuspiciousDomain)
            evidence.Add(new($"The process also touched suspicious domain {FirstSuspiciousDomain}."));

        scenarios.Add(new DetectionScenario(
            Key: "periodic-beacon",
            Title: "Periodic beacon",
            MitreTechnique: "T1071",
            MitreTactic: "Command and Control",
            Summary: "Low-jitter periodic outbound activity resembles beaconing to a control endpoint.",
            Confidence: confidence,
            RiskPoints: riskPoints,
            Evidence: evidence));
    }

    private void TryAddBurstAndExitScenario(List<DetectionScenario> scenarios)
    {
        if (!ExitedAfterTrafficPeak || !_lastTrafficPeakAt.HasValue || !_processExitedAt.HasValue)
            return;

        var exitDelay = _processExitedAt.Value - _lastTrafficPeakAt.Value;
        if (exitDelay < TimeSpan.Zero || exitDelay > TimeSpan.FromMinutes(2))
            return;

        int confidence = PeakSamplePackets >= 2000 ? 86
            : PeakSamplePackets >= 800 ? 78
            : 70;

        if (exitDelay <= TimeSpan.FromSeconds(30)) confidence += 8;
        else if (exitDelay <= TimeSpan.FromSeconds(60)) confidence += 4;

        if (_outboundBytes > _inboundBytes * 2)
            confidence += 4;

        confidence = Math.Clamp(confidence, 70, 95);
        int riskPoints = confidence >= 85 ? 18 : confidence >= 75 ? 14 : 10;

        var evidence = new List<DetectionEvidence>
        {
            new($"Peak traffic reached {PeakSamplePackets:N0} packets in a single sampling interval."),
            new($"The process exited {FormatCompactDuration(exitDelay)} after the peak."),
            new($"Traffic before exit totaled {FormatBytes(_outboundBytes)} outbound and {FormatBytes(_inboundBytes)} inbound.")
        };

        scenarios.Add(new DetectionScenario(
            Key: "burst-and-exit",
            Title: "Burst-and-exit",
            MitreTechnique: "T1070",
            MitreTactic: "Defense Evasion",
            Summary: "A sharp burst followed by a quick exit resembles smash-and-grab or cleanup behavior.",
            Confidence: confidence,
            RiskPoints: riskPoints,
            Evidence: evidence));
    }

    private void SyncDetectionScenarioTimeline(IReadOnlyList<DetectionScenario> scenarios)
    {
        if (scenarios.Count == 0)
            return;

        DateTime timestamp = LastSeen != default ? LastSeen : DateTime.Now;
        foreach (var scenario in scenarios)
        {
            AddTimelineEventIfMissing(
                $"scenario-{scenario.Key}",
                timestamp,
                $"Scenario: {scenario.Title}",
                $"{scenario.Summary} {scenario.MitreLabel}. {scenario.ConfidenceLabel}.");
        }
    }

    private static string NormalizeDomain(string domain)
        => string.IsNullOrWhiteSpace(domain)
            ? string.Empty
            : domain.Trim().TrimEnd('.').ToLowerInvariant();

    private static string GetDnsRootDomain(string normalizedDomain)
    {
        if (string.IsNullOrWhiteSpace(normalizedDomain))
            return string.Empty;

        var labels = normalizedDomain.Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (labels.Length >= 2)
            return $"{labels[^2]}.{labels[^1]}";

        return normalizedDomain;
    }

    private static int GetLongestDnsLabelLength(string normalizedDomain)
    {
        int longest = 0;
        var labels = normalizedDomain.Split('.', StringSplitOptions.RemoveEmptyEntries);
        for (int i = 0; i < labels.Length; i++)
        {
            if (labels[i].Length > longest)
                longest = labels[i].Length;
        }

        return longest;
    }

    private static bool LooksEncodedDnsQuery(string normalizedDomain)
    {
        var labels = normalizedDomain.Split('.', StringSplitOptions.RemoveEmptyEntries);
        for (int i = 0; i < labels.Length; i++)
        {
            string label = labels[i];
            if (label.Length < 12)
                continue;

            int digitCount = 0;
            for (int j = 0; j < label.Length; j++)
            {
                if (char.IsDigit(label[j]))
                    digitCount++;
            }

            double entropy = ComputeShannonEntropy(label);
            if (label.Length >= 24 && entropy >= 3.2)
                return true;

            if (label.Length >= 16 && digitCount >= Math.Max(4, label.Length / 3))
                return true;
        }

        return false;
    }

    private static double ComputeShannonEntropy(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return 0;

        var counts = new Dictionary<char, int>();
        for (int i = 0; i < value.Length; i++)
        {
            char key = value[i];
            counts.TryGetValue(key, out int count);
            counts[key] = count + 1;
        }

        double entropy = 0;
        foreach (var pair in counts)
        {
            double probability = pair.Value / (double)value.Length;
            entropy -= probability * Math.Log2(probability);
        }

        return entropy;
    }

    private static string FormatRatio(double value)
        => double.IsPositiveInfinity(value) ? "outbound-only"
            : double.IsNaN(value) ? "n/a"
            : $"{value:0.#}x";

    private static string FormatCompactDuration(TimeSpan value)
    {
        if (value <= TimeSpan.Zero)
            return "<1s";

        if (value.TotalMinutes >= 1)
            return $"{(int)value.TotalMinutes}m {value.Seconds}s";

        return $"{Math.Max(1, (int)Math.Round(value.TotalSeconds))}s";
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
