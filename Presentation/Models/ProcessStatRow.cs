using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Media;

namespace Presentation.Models;

public sealed class ProcessStatRow : INotifyPropertyChanged
{
    private const int MaxSamples = 30;
    private const int DefaultConversationPreviewCount = 4;
    private const int DefaultSessionClusterPreviewCount = 3;

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

    public sealed record TlsDnsInsight(
        string Key,
        string Title,
        string Summary,
        int Score,
        IReadOnlyList<DetectionEvidence> Evidence)
    {
        public string ScoreLabel => Score > 0 ? $"+{Score}" : "Context";

        public string SeverityLabel => Score switch
        {
            >= 16 => "High signal",
            >= 8 => "Medium signal",
            > 0 => "Low signal",
            _ => "Context"
        };

        public Brush SeverityBrush => Score switch
        {
            >= 16 => Brushes.IndianRed,
            >= 8 => Brushes.DarkOrange,
            > 0 => Brushes.OliveDrab,
            _ => Brushes.SteelBlue
        };
    }

    public sealed record BehaviorDeviation(
        string Key,
        string Title,
        string Summary,
        int Score,
        IReadOnlyList<DetectionEvidence> Evidence)
    {
        public string ScoreLabel => Score > 0 ? $"+{Score}" : "Info";

        public string SeverityLabel => Score switch
        {
            >= 12 => "High deviation",
            >= 7 => "Medium deviation",
            > 0 => "Low deviation",
            _ => "Context"
        };

        public Brush SeverityBrush => Score switch
        {
            >= 12 => Brushes.IndianRed,
            >= 7 => Brushes.DarkOrange,
            > 0 => Brushes.OliveDrab,
            _ => Brushes.SteelBlue
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

    private IReadOnlyList<TlsDnsInsight> _tlsDnsInsights = Array.Empty<TlsDnsInsight>();
    public IReadOnlyList<TlsDnsInsight> TlsDnsInsights
    {
        get => _tlsDnsInsights;
        private set
        {
            if (AreEquivalentTlsDnsInsights(_tlsDnsInsights, value))
                return;

            _tlsDnsInsights = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(HasTlsDnsInsights));
            OnPropertyChanged(nameof(TlsDnsInsightsEmptyState));
            OnPropertyChanged(nameof(TlsDnsSummaryLabel));
        }
    }

    public bool HasTlsDnsInsights => _tlsDnsInsights.Count > 0;
    public string TlsDnsInsightsTitle => "TLS / DNS intelligence";
    public string TlsDnsInsightsEmptyState => HasTlsDnsInsights ? "" : "No TLS or DNS intelligence findings were derived for this process yet.";
    public string TlsDnsSummaryLabel => _tlsDnsInsights.Count switch
    {
        0 => "",
        1 => _tlsDnsInsights[0].Title,
        _ => $"{_tlsDnsInsights[0].Title} +{_tlsDnsInsights.Count - 1}"
    };

    private IReadOnlyList<BehaviorDeviation> _behaviorDeviations = Array.Empty<BehaviorDeviation>();
    public IReadOnlyList<BehaviorDeviation> BehaviorDeviations
    {
        get => _behaviorDeviations;
        private set
        {
            if (AreEquivalentBehaviorDeviations(_behaviorDeviations, value))
                return;

            _behaviorDeviations = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(HasBehaviorDeviations));
            OnPropertyChanged(nameof(HasBaselineState));
            OnPropertyChanged(nameof(BehaviorDeviationsEmptyState));
            OnPropertyChanged(nameof(BehaviorDeviationSummaryLabel));
        }
    }

    public bool HasBehaviorDeviations => _behaviorDeviations.Count > 0;
    public string BehaviorDeviationsTitle => "Adaptive baseline";
    public string BehaviorDeviationsEmptyState => HasBehaviorDeviations ? "" : "No behavioral deviations from the local baseline were derived for this process yet.";
    public string BehaviorDeviationSummaryLabel => _behaviorDeviations.Count switch
    {
        0 => "",
        1 => _behaviorDeviations[0].Title,
        _ => $"{_behaviorDeviations[0].Title} +{_behaviorDeviations.Count - 1}"
    };

    private string _baselineStateLabel = "Baseline: none";
    public string BaselineStateLabel
    {
        get => _baselineStateLabel;
        private set
        {
            if (_baselineStateLabel == value)
                return;

            _baselineStateLabel = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(HasBaselineState));
        }
    }

    public bool HasBaselineState =>
        !string.IsNullOrWhiteSpace(BaselineStateLabel)
        && (!string.Equals(BaselineStateLabel, "Baseline: none", StringComparison.Ordinal) || HasBehaviorDeviations);

    private string _baselineSummary = "No trusted baseline exists for this process identity yet.";
    public string BaselineSummary
    {
        get => _baselineSummary;
        private set
        {
            if (_baselineSummary == value)
                return;

            _baselineSummary = value;
            OnPropertyChanged();
        }
    }

    private string _baselineLearningNote = "If this session stays low-risk, it can initialize a future baseline.";
    public string BaselineLearningNote
    {
        get => _baselineLearningNote;
        private set
        {
            if (_baselineLearningNote == value)
                return;

            _baselineLearningNote = value;
            OnPropertyChanged();
        }
    }

    public ObservableCollection<InvestigationTimelineEvent> TimelineEvents { get; } = new();
    public bool HasTimelineEvents => TimelineEvents.Count > 0;
    public string TimelineEmptyState => HasTimelineEvents ? "" : "No investigation events recorded yet.";
    public string TimelineTitle => "Investigation timeline";
    private IReadOnlyList<ProcessConversationRow> _allConversations = Array.Empty<ProcessConversationRow>();
    private bool _showAllConversations;
    public ObservableCollection<ProcessConversationRow> VisibleConversations { get; } = new();
    public bool HasConversations => _allConversations.Count > 0;
    public bool CanToggleConversations => _allConversations.Count > DefaultConversationPreviewCount;
    public string ConversationTitle => "Conversation view";
    public string ConversationEmptyState => HasConversations ? "" : "No conversation partners recorded yet.";
    public string ConversationToggleLabel => _showAllConversations ? "Show less" : $"Show all ({_allConversations.Count})";
    private IReadOnlyList<ProcessSessionClusterRow> _allSessionClusters = Array.Empty<ProcessSessionClusterRow>();
    private bool _showAllSessionClusters;
    public ObservableCollection<ProcessSessionClusterRow> VisibleSessionClusters { get; } = new();
    public bool HasSessionClusters => _allSessionClusters.Count > 0;
    public bool CanToggleSessionClusters => _allSessionClusters.Count > DefaultSessionClusterPreviewCount;
    public string SessionClustersTitle => "Session clusters";
    public string SessionClustersEmptyState => HasSessionClusters ? "" : "No activity sessions recorded yet.";
    public string SessionClustersToggleLabel => _showAllSessionClusters ? "Show less" : $"Show all ({_allSessionClusters.Count})";

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
                OnPropertyChanged(nameof(HasFirewallBlockBadge));
                OnPropertyChanged(nameof(FirewallBlockBadgeLabel));
            }
        }
    }

    private DateTime? _firewallBlockedUntilLocal;
    public DateTime? FirewallBlockedUntilLocal
    {
        get => _firewallBlockedUntilLocal;
        private set
        {
            if (_firewallBlockedUntilLocal != value)
            {
                _firewallBlockedUntilLocal = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(HasTimedFirewallBlock));
                OnPropertyChanged(nameof(FirewallBlockBadgeLabel));
            }
        }
    }

    private bool _firewallBlockedUntilAppExit;
    public bool FirewallBlockedUntilAppExit
    {
        get => _firewallBlockedUntilAppExit;
        private set
        {
            if (_firewallBlockedUntilAppExit != value)
            {
                _firewallBlockedUntilAppExit = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(FirewallBlockBadgeLabel));
            }
        }
    }

    public bool HasTimedFirewallBlock => FirewallBlocked && FirewallBlockedUntilLocal.HasValue;
    public bool HasFirewallBlockBadge => FirewallBlocked;
    public string FirewallBlockBadgeLabel
    {
        get
        {
            if (!FirewallBlocked)
                return "";

            if (FirewallBlockedUntilLocal.HasValue)
                return $"Blocked until {FirewallBlockedUntilLocal.Value:HH:mm}";

            if (FirewallBlockedUntilAppExit)
                return "Blocked until app exit";

            return "Blocked";
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

    private const int MaxTrackedObservedDomains = 2048;
    private const int MaxTrackedTlsEndpoints = 512;
    private const int MaxTrackedFingerprints = 256;
    private const int MaxTrackedCertificateReuseEntries = 256;
    private readonly HashSet<string> _observedDomains = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, SecureEndpointState> _secureEndpoints = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, int> _ja3LiteCounts = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, int> _ja4LiteCounts = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, HashSet<string>> _certificateDomains = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _sniCertificateMismatchKeys = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<int> _observedActiveHours = new();
    private DateTime _firstObservedAt;
    private string _latestNewDomain = "";
    private int _rareTldScore;
    private string _rareTldDomain = "";
    private string _rareTld = "";
    private int _dgaLikeDomainCount;
    private string _topDgaLikeDomain = "";
    private int _topDgaLikeScore;
    private string _topJa3Lite = "";
    private int _topJa3LiteCount;
    private string _topJa4Lite = "";
    private int _topJa4LiteCount;
    private int _sniCertificateMismatchCount;
    private string _lastSniCertificateMismatch = "";
    private string _mostReusedCertificateFingerprint = "";
    private int _mostReusedCertificateDomainCount;
    private string _mostReusedCertificateDomainsSummary = "";

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
    public int UniqueDomainCount => _observedDomains.Count;
    public string LatestNewDomain => _latestNewDomain;
    public int RareTldScore => _rareTldScore;
    public string RareTldDomain => _rareTldDomain;
    public string RareTld => _rareTld;
    public int DgaLikeDomainCount => _dgaLikeDomainCount;
    public string TopDgaLikeDomain => _topDgaLikeDomain;
    public int TopDgaLikeScore => _topDgaLikeScore;
    public string PrimaryJa3Lite => _topJa3Lite;
    public int PrimaryJa3LiteCount => _topJa3LiteCount;
    public string PrimaryJa4Lite => _topJa4Lite;
    public int PrimaryJa4LiteCount => _topJa4LiteCount;
    public int SniCertificateMismatchCount => _sniCertificateMismatchCount;
    public string LastSniCertificateMismatch => _lastSniCertificateMismatch;
    public string MostReusedCertificateFingerprint => _mostReusedCertificateFingerprint;
    public int MostReusedCertificateDomainCount => _mostReusedCertificateDomainCount;
    public string MostReusedCertificateDomainsSummary => _mostReusedCertificateDomainsSummary;
    public DateTime FirstObservedAt => _firstObservedAt;

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

    public void ObserveActivityAt(DateTime timestamp)
    {
        if (timestamp == default)
            return;

        if (_firstObservedAt == default || timestamp < _firstObservedAt)
            _firstObservedAt = timestamp;

        _observedActiveHours.Add(timestamp.Hour);
    }

    public void ObserveDnsQuery(string domain, string? queryType, DateTime timestamp)
    {
        string normalized = NormalizeDomain(domain);
        if (string.IsNullOrWhiteSpace(normalized))
            return;

        ObserveDomainActivity(normalized, timestamp, source: "DNS");

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

    public void ObserveSecureEndpointIntelligence(
        DateTime timestamp,
        string remoteEndpoint,
        string? serverName,
        string? tlsClientFingerprintKind,
        string? tlsClientFingerprint,
        string? tlsCertificateFingerprint,
        IReadOnlyList<string>? tlsCertificateNames,
        string? tlsCertificateSubject)
    {
        bool hasRelevantTelemetry =
            !string.IsNullOrWhiteSpace(serverName)
            || !string.IsNullOrWhiteSpace(tlsClientFingerprint)
            || !string.IsNullOrWhiteSpace(tlsCertificateFingerprint)
            || (tlsCertificateNames?.Count ?? 0) > 0;
        if (!hasRelevantTelemetry)
            return;

        string endpointKey = string.IsNullOrWhiteSpace(remoteEndpoint) ? string.Empty : remoteEndpoint.Trim();
        SecureEndpointState? endpointState = null;
        if (!string.IsNullOrWhiteSpace(endpointKey))
            endpointState = GetOrCreateSecureEndpointState(endpointKey);

        string normalizedServerName = NormalizeDomain(serverName ?? string.Empty);
        if (!string.IsNullOrWhiteSpace(normalizedServerName))
        {
            ObserveDomainActivity(normalizedServerName, timestamp, source: "SNI");

            if (endpointState is not null)
                endpointState.ServerName = normalizedServerName;
        }

        TrackFingerprint(tlsClientFingerprintKind, tlsClientFingerprint);

        string normalizedCertificateFingerprint = string.IsNullOrWhiteSpace(tlsCertificateFingerprint)
            ? string.Empty
            : tlsCertificateFingerprint.Trim().ToLowerInvariant();

        var normalizedCertificateNames = NormalizeCertificateNames(tlsCertificateNames);
        if (endpointState is not null)
        {
            if (!string.IsNullOrWhiteSpace(normalizedCertificateFingerprint))
                endpointState.CertificateFingerprint = normalizedCertificateFingerprint;

            endpointState.CertificateNames = normalizedCertificateNames;
            endpointState.CertificateSubject = tlsCertificateSubject?.Trim() ?? string.Empty;
        }

        string domainForCertificate = !string.IsNullOrWhiteSpace(normalizedServerName)
            ? normalizedServerName
            : endpointState?.ServerName ?? string.Empty;

        if (!string.IsNullOrWhiteSpace(normalizedCertificateFingerprint) && !string.IsNullOrWhiteSpace(domainForCertificate))
            TrackCertificateReuse(timestamp, normalizedCertificateFingerprint, domainForCertificate);

        if (!string.IsNullOrWhiteSpace(domainForCertificate) && normalizedCertificateNames.Count > 0)
            TrackSniCertificateMismatch(timestamp, domainForCertificate, normalizedCertificateNames, tlsCertificateSubject ?? string.Empty);
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

    public IReadOnlyList<string> GetDominantRootDomainsSnapshot()
        => _dnsRootQueryCounts.Count == 0
            ? Array.Empty<string>()
            : _dnsRootQueryCounts
                .OrderByDescending(static pair => pair.Value)
                .ThenBy(static pair => pair.Key, StringComparer.OrdinalIgnoreCase)
                .Take(12)
                .Select(static pair => pair.Key)
                .ToArray();

    public IReadOnlyList<string> GetObservedActiveHoursSnapshot()
        => _observedActiveHours.Count == 0
            ? Array.Empty<string>()
            : _observedActiveHours
                .OrderBy(static hour => hour)
                .Select(static hour => hour.ToString("00", CultureInfo.InvariantCulture))
                .ToArray();

    public IReadOnlyList<string> GetObservedClientFingerprintsSnapshot()
    {
        string[] ja3 = _ja3LiteCounts
            .OrderByDescending(static pair => pair.Value)
            .ThenBy(static pair => pair.Key, StringComparer.OrdinalIgnoreCase)
            .Take(2)
            .Select(static pair => "ja3:" + pair.Key)
            .ToArray();
        string[] ja4 = _ja4LiteCounts
            .OrderByDescending(static pair => pair.Value)
            .ThenBy(static pair => pair.Key, StringComparer.OrdinalIgnoreCase)
            .Take(2)
            .Select(static pair => "ja4:" + pair.Key)
            .ToArray();

        return ja3.Concat(ja4).ToArray();
    }

    public IReadOnlyList<string> GetObservedCertificateFingerprintsSnapshot()
        => _certificateDomains.Count == 0
            ? Array.Empty<string>()
            : _certificateDomains.Keys
                .OrderBy(static value => value, StringComparer.OrdinalIgnoreCase)
                .Take(6)
                .ToArray();

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
            TlsDnsInsights = Array.Empty<TlsDnsInsight>();
            BehaviorDeviations = Array.Empty<BehaviorDeviation>();
            RiskReasons = Array.Empty<RiskReason>();
            RiskScore = 0;
            return;
        }

        var scenarios = BuildDetectionScenarios();
        var tlsDnsInsights = BuildTlsDnsInsights();
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
        TlsDnsInsights = tlsDnsInsights;

        foreach (var insight in tlsDnsInsights)
        {
            if (insight.Score > 0)
                signals.Add(new RiskSignal(insight.Title, insight.Score));
        }

        foreach (var deviation in BehaviorDeviations)
        {
            if (deviation.Score > 0)
                signals.Add(new RiskSignal(deviation.Title, deviation.Score));
        }

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

    public void SyncFirewallBlockState(bool isBlocked, DateTime? blockedUntilLocal, bool blockedUntilAppExit)
    {
        FirewallBlocked = isBlocked;
        FirewallBlockedUntilLocal = isBlocked ? blockedUntilLocal : null;
        FirewallBlockedUntilAppExit = isBlocked && blockedUntilAppExit;
    }

    public void RecordFirewallBlock(DateTime timestamp, string? detail = null)
    {
        SyncFirewallBlockState(isBlocked: true, blockedUntilLocal: null, blockedUntilAppExit: false);
        AppendTimelineEvent(
            $"firewall-block-{timestamp.Ticks}",
            timestamp,
            "Firewall block applied",
            detail ?? "TrafficMonitor added Windows Firewall rules for this executable.");
    }

    public void RecordTimedFirewallBlock(DateTime timestamp, DateTime blockedUntilLocal, string? detail = null)
    {
        SyncFirewallBlockState(isBlocked: true, blockedUntilLocal: blockedUntilLocal, blockedUntilAppExit: false);
        AppendTimelineEvent(
            $"firewall-block-{timestamp.Ticks}",
            timestamp,
            "Temporary firewall block applied",
            detail ?? $"TrafficMonitor added Windows Firewall rules for this executable until {blockedUntilLocal:HH:mm}.");
    }

    public void RecordFirewallBlockUntilAppExit(DateTime timestamp, string? detail = null)
    {
        SyncFirewallBlockState(isBlocked: true, blockedUntilLocal: null, blockedUntilAppExit: true);
        AppendTimelineEvent(
            $"firewall-block-{timestamp.Ticks}",
            timestamp,
            "Firewall block applied",
            detail ?? "TrafficMonitor added Windows Firewall rules for this executable until the app exits.");
    }

    public void RecordFirewallUnblock(DateTime timestamp, string? detail = null)
    {
        SyncFirewallBlockState(isBlocked: false, blockedUntilLocal: null, blockedUntilAppExit: false);
        AppendTimelineEvent(
            $"firewall-unblock-{timestamp.Ticks}",
            timestamp,
            "Firewall block removed",
            detail ?? "TrafficMonitor removed its Windows Firewall rules for this executable.");
    }

    public void UpdateConversations(IEnumerable<ProcessConversationRow> conversations)
    {
        _allConversations = conversations as IReadOnlyList<ProcessConversationRow> ?? conversations.ToArray();
        if (_allConversations.Count <= DefaultConversationPreviewCount)
            _showAllConversations = false;

        RefreshVisibleConversations();
        OnPropertyChanged(nameof(HasConversations));
        OnPropertyChanged(nameof(CanToggleConversations));
        OnPropertyChanged(nameof(ConversationToggleLabel));
        OnPropertyChanged(nameof(ConversationEmptyState));
    }

    public void UpdateSessionClusters(IEnumerable<ProcessSessionClusterRow> sessionClusters)
    {
        _allSessionClusters = sessionClusters as IReadOnlyList<ProcessSessionClusterRow> ?? sessionClusters.ToArray();
        if (_allSessionClusters.Count <= DefaultSessionClusterPreviewCount)
            _showAllSessionClusters = false;

        RefreshVisibleSessionClusters();
        OnPropertyChanged(nameof(HasSessionClusters));
        OnPropertyChanged(nameof(CanToggleSessionClusters));
        OnPropertyChanged(nameof(SessionClustersToggleLabel));
        OnPropertyChanged(nameof(SessionClustersEmptyState));
    }

    public void ToggleConversationsExpansion()
    {
        if (!CanToggleConversations)
            return;

        _showAllConversations = !_showAllConversations;
        RefreshVisibleConversations();
        OnPropertyChanged(nameof(ConversationToggleLabel));
    }

    public void ToggleSessionClustersExpansion()
    {
        if (!CanToggleSessionClusters)
            return;

        _showAllSessionClusters = !_showAllSessionClusters;
        RefreshVisibleSessionClusters();
        OnPropertyChanged(nameof(SessionClustersToggleLabel));
    }

    public void ApplyBehaviorBaseline(
        string baselineStateLabel,
        string baselineSummary,
        string baselineLearningNote,
        IReadOnlyList<BehaviorDeviation> deviations)
        => DeferNotifications(() =>
        {
            BaselineStateLabel = string.IsNullOrWhiteSpace(baselineStateLabel) ? "Baseline: none" : baselineStateLabel;
            BaselineSummary = string.IsNullOrWhiteSpace(baselineSummary)
                ? "No trusted baseline exists for this process identity yet."
                : baselineSummary;
            BaselineLearningNote = string.IsNullOrWhiteSpace(baselineLearningNote)
                ? "No learning recommendation is currently available."
                : baselineLearningNote;
            BehaviorDeviations = deviations ?? Array.Empty<BehaviorDeviation>();
            SyncBehaviorDeviationTimeline(BehaviorDeviations);
        });

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

    private void RefreshVisibleConversations()
    {
        var preview = _showAllConversations || _allConversations.Count <= DefaultConversationPreviewCount
            ? _allConversations
            : _allConversations.Take(DefaultConversationPreviewCount).ToArray();

        ReplaceCollection(VisibleConversations, preview, AreEquivalentConversations);
    }

    private void RefreshVisibleSessionClusters()
    {
        var preview = _showAllSessionClusters || _allSessionClusters.Count <= DefaultSessionClusterPreviewCount
            ? _allSessionClusters
            : _allSessionClusters.Take(DefaultSessionClusterPreviewCount).ToArray();

        ReplaceCollection(VisibleSessionClusters, preview, AreEquivalentSessionClusters);
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

    private static bool AreEquivalentTlsDnsInsights(IReadOnlyList<TlsDnsInsight> left, IReadOnlyList<TlsDnsInsight> right)
    {
        if (ReferenceEquals(left, right))
            return true;

        if (left.Count != right.Count)
            return false;

        for (int i = 0; i < left.Count; i++)
        {
            var leftInsight = left[i];
            var rightInsight = right[i];

            if (leftInsight.Score != rightInsight.Score
                || !string.Equals(leftInsight.Key, rightInsight.Key, StringComparison.Ordinal)
                || !string.Equals(leftInsight.Title, rightInsight.Title, StringComparison.Ordinal)
                || !string.Equals(leftInsight.Summary, rightInsight.Summary, StringComparison.Ordinal)
                || leftInsight.Evidence.Count != rightInsight.Evidence.Count)
            {
                return false;
            }

            for (int evidenceIndex = 0; evidenceIndex < leftInsight.Evidence.Count; evidenceIndex++)
            {
                if (!string.Equals(leftInsight.Evidence[evidenceIndex].Summary, rightInsight.Evidence[evidenceIndex].Summary, StringComparison.Ordinal))
                    return false;
            }
        }

        return true;
    }

    private static bool AreEquivalentBehaviorDeviations(IReadOnlyList<BehaviorDeviation> left, IReadOnlyList<BehaviorDeviation> right)
    {
        if (ReferenceEquals(left, right))
            return true;

        if (left.Count != right.Count)
            return false;

        for (int i = 0; i < left.Count; i++)
        {
            var leftDeviation = left[i];
            var rightDeviation = right[i];

            if (leftDeviation.Score != rightDeviation.Score
                || !string.Equals(leftDeviation.Key, rightDeviation.Key, StringComparison.Ordinal)
                || !string.Equals(leftDeviation.Title, rightDeviation.Title, StringComparison.Ordinal)
                || !string.Equals(leftDeviation.Summary, rightDeviation.Summary, StringComparison.Ordinal)
                || leftDeviation.Evidence.Count != rightDeviation.Evidence.Count)
            {
                return false;
            }

            for (int evidenceIndex = 0; evidenceIndex < leftDeviation.Evidence.Count; evidenceIndex++)
            {
                if (!string.Equals(leftDeviation.Evidence[evidenceIndex].Summary, rightDeviation.Evidence[evidenceIndex].Summary, StringComparison.Ordinal))
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

    private IReadOnlyList<TlsDnsInsight> BuildTlsDnsInsights()
    {
        var insights = new List<TlsDnsInsight>(capacity: 6);

        if (!string.IsNullOrWhiteSpace(_topJa3Lite) || !string.IsNullOrWhiteSpace(_topJa4Lite))
        {
            var evidence = new List<DetectionEvidence>(2);
            if (!string.IsNullOrWhiteSpace(_topJa3Lite))
                evidence.Add(new($"Primary JA3-lite fingerprint {_topJa3Lite} appeared {_topJa3LiteCount:N0} time(s)."));
            if (!string.IsNullOrWhiteSpace(_topJa4Lite))
                evidence.Add(new($"Primary JA4-lite fingerprint {_topJa4Lite} appeared {_topJa4LiteCount:N0} time(s)."));

            insights.Add(new TlsDnsInsight(
                Key: "client-fingerprints",
                Title: "Client TLS fingerprints",
                Summary: "Stable client TLS/QUIC fingerprints were observed for this process.",
                Score: 0,
                Evidence: evidence));
        }

        if (_observedDomains.Count > 0)
        {
            int score = _observedDomains.Count >= 12 ? 8
                : _observedDomains.Count >= 6 ? 4
                : 0;

            var evidence = new List<DetectionEvidence>
            {
                new($"{_observedDomains.Count:N0} unique domain(s) were first seen for this process in the current session.")
            };

            if (!string.IsNullOrWhiteSpace(_latestNewDomain))
                evidence.Add(new($"Latest new domain: {_latestNewDomain}."));

            if (!string.IsNullOrWhiteSpace(_dominantDnsRoot))
                evidence.Add(new($"DNS activity concentrated on {_dominantDnsRoot} ({_dominantDnsRootCount:N0} query hits)."));

            insights.Add(new TlsDnsInsight(
                Key: "new-domains",
                Title: score > 0 ? "High domain churn" : "New domains for this process",
                Summary: score > 0
                    ? "The process kept introducing new domains during the capture window."
                    : "The process established a domain baseline for the current session.",
                Score: score,
                Evidence: evidence));
        }

        if (_rareTldScore > 0)
        {
            int score = _rareTldScore >= 24 ? 14
                : _rareTldScore >= 12 ? 9
                : 5;

            var evidence = new List<DetectionEvidence>
            {
                new($"Rare-TLD score accumulated to {_rareTldScore:N0} for this process.")
            };

            if (!string.IsNullOrWhiteSpace(_rareTldDomain))
                evidence.Add(new($"Representative domain: {_rareTldDomain} ({_rareTld})."));

            insights.Add(new TlsDnsInsight(
                Key: "rare-tld",
                Title: "Rare-TLD activity",
                Summary: "Observed domains used rare or frequently abused top-level domains.",
                Score: score,
                Evidence: evidence));
        }

        if (_dgaLikeDomainCount > 0)
        {
            int score = _topDgaLikeScore >= 80 ? 18
                : _topDgaLikeScore >= 65 ? 12
                : 6;

            var evidence = new List<DetectionEvidence>
            {
                new($"{_dgaLikeDomainCount:N0} domain(s) crossed the DGA-like scoring threshold.")
            };

            if (!string.IsNullOrWhiteSpace(_topDgaLikeDomain))
                evidence.Add(new($"Highest-scoring example: {_topDgaLikeDomain} (score {_topDgaLikeScore}/100)."));

            insights.Add(new TlsDnsInsight(
                Key: "dga-like-domains",
                Title: "DGA-like domains",
                Summary: "One or more observed domains looked algorithmically generated.",
                Score: score,
                Evidence: evidence));
        }

        if (_sniCertificateMismatchCount > 0)
        {
            int score = _sniCertificateMismatchCount >= 3 ? 20 : 14;
            var evidence = new List<DetectionEvidence>
            {
                new($"{_sniCertificateMismatchCount:N0} SNI / certificate mismatch event(s) were recorded.")
            };

            if (!string.IsNullOrWhiteSpace(_lastSniCertificateMismatch))
                evidence.Add(new($"Latest mismatch: {_lastSniCertificateMismatch}."));

            insights.Add(new TlsDnsInsight(
                Key: "sni-cert-mismatch",
                Title: "SNI / certificate mismatch",
                Summary: "The requested server name did not match the certificate names presented by the peer.",
                Score: score,
                Evidence: evidence));
        }

        if (_mostReusedCertificateDomainCount >= 2)
        {
            int score = _mostReusedCertificateDomainCount >= 5 ? 16
                : _mostReusedCertificateDomainCount >= 3 ? 10
                : 6;

            var evidence = new List<DetectionEvidence>
            {
                new($"One certificate fingerprint was reused across {_mostReusedCertificateDomainCount:N0} distinct domains.")
            };

            if (!string.IsNullOrWhiteSpace(_mostReusedCertificateFingerprint))
                evidence.Add(new($"Fingerprint: {ShortenFingerprint(_mostReusedCertificateFingerprint)}."));

            if (!string.IsNullOrWhiteSpace(_mostReusedCertificateDomainsSummary))
                evidence.Add(new($"Observed domains: {_mostReusedCertificateDomainsSummary}."));

            insights.Add(new TlsDnsInsight(
                Key: "certificate-reuse",
                Title: "Certificate reused across domains",
                Summary: "The same server certificate fingerprint backed multiple domains contacted by this process.",
                Score: score,
                Evidence: evidence));
        }

        insights.Sort(static (left, right) =>
        {
            int comparison = right.Score.CompareTo(left.Score);
            if (comparison != 0)
                return comparison;

            return string.Compare(left.Title, right.Title, StringComparison.Ordinal);
        });

        return insights;
    }

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

    private void SyncBehaviorDeviationTimeline(IReadOnlyList<BehaviorDeviation> deviations)
    {
        if (deviations.Count == 0)
            return;

        DateTime timestamp = LastSeen != default ? LastSeen : DateTime.Now;
        for (int i = 0; i < deviations.Count; i++)
        {
            var deviation = deviations[i];
            AddTimelineEventIfMissing(
                $"baseline-{deviation.Key}",
                timestamp,
                $"Baseline deviation: {deviation.Title}",
                $"{deviation.Summary} {deviation.SeverityLabel}.");
        }
    }

    private void ObserveDomainActivity(string normalizedDomain, DateTime timestamp, string source)
    {
        if (string.IsNullOrWhiteSpace(normalizedDomain))
            return;

        if (_observedDomains.Count >= MaxTrackedObservedDomains && !_observedDomains.Contains(normalizedDomain))
            return;

        if (!_observedDomains.Add(normalizedDomain))
            return;

        _latestNewDomain = normalizedDomain;
        if (_observedDomains.Count >= 2)
        {
            AddTimelineEventIfMissing(
                "new-domain-observed",
                timestamp,
                "New domain observed",
                $"{normalizedDomain} was first seen for this process via {source}.",
                new InvestigationTimelineTarget("new-domain-observed", normalizedDomain));
        }

        TrackRareTld(timestamp, normalizedDomain);
        TrackDgaLikeDomain(timestamp, normalizedDomain);
        InvalidateRisk();
    }

    private void TrackRareTld(DateTime timestamp, string normalizedDomain)
    {
        string tld = GetTopLevelDomain(normalizedDomain);
        if (!TryGetRareTldWeight(tld, out int weight))
            return;

        _rareTldScore += weight;
        if (weight > 0 && (string.IsNullOrWhiteSpace(_rareTldDomain) || weight >= GetRareTldWeightForDisplay(_rareTld)))
        {
            _rareTldDomain = normalizedDomain;
            _rareTld = tld;
        }

        AddTimelineEventIfMissing(
            "rare-tld-activity",
            timestamp,
            "Rare-TLD activity",
            $"{normalizedDomain} used rare or frequently abused TLD {tld}.",
            new InvestigationTimelineTarget("rare-tld-activity", normalizedDomain));
    }

    private static bool TryGetRareTldWeight(string tld, out int weight)
    {
        weight = tld switch
        {
            ".zip" or ".mov" => 12,
            ".top" or ".xyz" or ".click" or ".cfd" or ".stream" or ".download" => 8,
            ".gq" or ".work" or ".rest" or ".country" or ".cam" or ".monster" or ".party" => 6,
            ".account" or ".support" or ".ink" or ".fit" => 4,
            _ => 0
        };

        return weight > 0;
    }

    private static int GetRareTldWeightForDisplay(string tld)
        => TryGetRareTldWeight(tld, out int weight) ? weight : 0;

    private void TrackDgaLikeDomain(DateTime timestamp, string normalizedDomain)
    {
        int score = ComputeDgaLikeScore(normalizedDomain);
        if (score < 55)
            return;

        _dgaLikeDomainCount++;
        if (score > _topDgaLikeScore
            || (score == _topDgaLikeScore && string.Compare(normalizedDomain, _topDgaLikeDomain, StringComparison.OrdinalIgnoreCase) < 0))
        {
            _topDgaLikeScore = score;
            _topDgaLikeDomain = normalizedDomain;
        }

        AddTimelineEventIfMissing(
            "dga-like-domain",
            timestamp,
            "DGA-like domain",
            $"{normalizedDomain} scored {_topDgaLikeScore}/100 on the DGA-like heuristic.",
            new InvestigationTimelineTarget("dga-like-domain", normalizedDomain));
    }

    private static int ComputeDgaLikeScore(string normalizedDomain)
    {
        if (string.IsNullOrWhiteSpace(normalizedDomain))
            return 0;

        string label = GetPrimaryDomainLabel(normalizedDomain);
        if (label.Length < 8)
            return 0;

        int score = 0;
        int letters = 0;
        int digits = 0;
        int vowels = 0;
        var uniqueChars = new HashSet<char>();

        for (int i = 0; i < label.Length; i++)
        {
            char ch = label[i];
            uniqueChars.Add(ch);

            if (char.IsLetter(ch))
            {
                letters++;
                if ("aeiou".IndexOf(char.ToLowerInvariant(ch)) >= 0)
                    vowels++;
            }
            else if (char.IsDigit(ch))
            {
                digits++;
            }
        }

        double entropy = ComputeShannonEntropy(label);
        double uniqueRatio = uniqueChars.Count / (double)label.Length;
        double digitRatio = digits / (double)label.Length;
        double vowelRatio = letters <= 0 ? 0 : vowels / (double)letters;
        int maxConsonantRun = GetMaxConsonantRun(label);

        if (label.Length >= 16) score += 15;
        else if (label.Length >= 12) score += 8;

        if (entropy >= 3.9) score += 35;
        else if (entropy >= 3.5) score += 22;
        else if (entropy >= 3.2) score += 10;

        if (digitRatio >= 0.25) score += 20;
        else if (digitRatio >= 0.15) score += 10;

        if (uniqueRatio >= 0.78) score += 10;
        else if (uniqueRatio >= 0.68) score += 5;

        if (letters >= 6 && vowelRatio <= 0.22) score += 12;
        if (maxConsonantRun >= 5) score += 10;
        else if (maxConsonantRun >= 4) score += 6;

        return Math.Clamp(score, 0, 100);
    }

    private void TrackFingerprint(string? fingerprintKind, string? fingerprint)
    {
        string normalizedFingerprint = string.IsNullOrWhiteSpace(fingerprint)
            ? string.Empty
            : fingerprint.Trim().ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(normalizedFingerprint))
            return;

        if (string.Equals(fingerprintKind, "JA3-lite", StringComparison.OrdinalIgnoreCase))
        {
            if (_ja3LiteCounts.Count >= MaxTrackedFingerprints && !_ja3LiteCounts.ContainsKey(normalizedFingerprint))
                return;

            _ja3LiteCounts.TryGetValue(normalizedFingerprint, out int count);
            count++;
            _ja3LiteCounts[normalizedFingerprint] = count;
            if (count > _topJa3LiteCount
                || (count == _topJa3LiteCount && string.Compare(normalizedFingerprint, _topJa3Lite, StringComparison.OrdinalIgnoreCase) < 0))
            {
                _topJa3Lite = normalizedFingerprint;
                _topJa3LiteCount = count;
                InvalidateRisk();
            }

            return;
        }

        if (string.Equals(fingerprintKind, "JA4-lite", StringComparison.OrdinalIgnoreCase))
        {
            if (_ja4LiteCounts.Count >= MaxTrackedFingerprints && !_ja4LiteCounts.ContainsKey(normalizedFingerprint))
                return;

            _ja4LiteCounts.TryGetValue(normalizedFingerprint, out int count);
            count++;
            _ja4LiteCounts[normalizedFingerprint] = count;
            if (count > _topJa4LiteCount
                || (count == _topJa4LiteCount && string.Compare(normalizedFingerprint, _topJa4Lite, StringComparison.OrdinalIgnoreCase) < 0))
            {
                _topJa4Lite = normalizedFingerprint;
                _topJa4LiteCount = count;
                InvalidateRisk();
            }
        }
    }

    private void TrackCertificateReuse(DateTime timestamp, string certificateFingerprint, string domain)
    {
        if (_certificateDomains.Count >= MaxTrackedCertificateReuseEntries && !_certificateDomains.ContainsKey(certificateFingerprint))
            return;

        if (!_certificateDomains.TryGetValue(certificateFingerprint, out var domains))
        {
            domains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _certificateDomains[certificateFingerprint] = domains;
        }

        if (!domains.Add(domain))
            return;

        if (domains.Count > _mostReusedCertificateDomainCount)
        {
            _mostReusedCertificateFingerprint = certificateFingerprint;
            _mostReusedCertificateDomainCount = domains.Count;
            _mostReusedCertificateDomainsSummary = string.Join(", ", domains.OrderBy(static value => value, StringComparer.OrdinalIgnoreCase).Take(4));
            InvalidateRisk();
        }

        if (domains.Count >= 2)
        {
            string domainsSummary = string.Join(", ", domains.OrderBy(static value => value, StringComparer.OrdinalIgnoreCase).Take(4));
            AddTimelineEventIfMissing(
                "certificate-reuse",
                timestamp,
                "Certificate reused across domains",
                $"{ShortenFingerprint(certificateFingerprint)} backed {domains.Count:N0} domain(s): {domainsSummary}.",
                new InvestigationTimelineTarget("certificate-reuse", domain));
        }
    }

    private void TrackSniCertificateMismatch(DateTime timestamp, string domain, IReadOnlyList<string> certificateNames, string certificateSubject)
    {
        if (CertificateMatchesDomain(domain, certificateNames))
            return;

        string mismatchKey = $"{domain}|{string.Join("|", certificateNames)}";
        if (!_sniCertificateMismatchKeys.Add(mismatchKey))
            return;

        _sniCertificateMismatchCount++;
        string namesPreview = string.Join(", ", certificateNames.Take(3));
        _lastSniCertificateMismatch = string.IsNullOrWhiteSpace(certificateSubject)
            ? $"{domain} vs {namesPreview}"
            : $"{domain} vs {namesPreview} ({certificateSubject})";

        AddTimelineEventIfMissing(
            "sni-cert-mismatch",
            timestamp,
            "SNI / certificate mismatch",
            $"{domain} did not match certificate names {namesPreview}.",
            new InvestigationTimelineTarget("sni-cert-mismatch", domain));

        InvalidateRisk();
    }

    private SecureEndpointState GetOrCreateSecureEndpointState(string endpointKey)
    {
        if (_secureEndpoints.TryGetValue(endpointKey, out var state))
            return state;

        if (_secureEndpoints.Count >= MaxTrackedTlsEndpoints)
            return new SecureEndpointState();

        state = new SecureEndpointState();
        _secureEndpoints[endpointKey] = state;
        return state;
    }

    private static IReadOnlyList<string> NormalizeCertificateNames(IReadOnlyList<string>? certificateNames)
    {
        if (certificateNames is null || certificateNames.Count == 0)
            return Array.Empty<string>();

        var unique = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < certificateNames.Count; i++)
        {
            string normalized = NormalizeCertificatePattern(certificateNames[i]);
            if (!string.IsNullOrWhiteSpace(normalized))
                unique.Add(normalized);
        }

        return unique
            .OrderBy(static value => value, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static bool CertificateMatchesDomain(string domain, IReadOnlyList<string> certificateNames)
    {
        for (int i = 0; i < certificateNames.Count; i++)
        {
            if (HostMatchesCertificatePattern(domain, certificateNames[i]))
                return true;
        }

        return false;
    }

    private static bool HostMatchesCertificatePattern(string domain, string pattern)
    {
        string normalizedDomain = NormalizeDomain(domain);
        string normalizedPattern = NormalizeCertificatePattern(pattern);
        if (string.IsNullOrWhiteSpace(normalizedDomain) || string.IsNullOrWhiteSpace(normalizedPattern))
            return false;

        if (string.Equals(normalizedDomain, normalizedPattern, StringComparison.OrdinalIgnoreCase))
            return true;

        if (!normalizedPattern.StartsWith("*.", StringComparison.Ordinal))
            return false;

        string suffix = normalizedPattern[1..];
        if (!normalizedDomain.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
            return false;

        return normalizedDomain.Count(static ch => ch == '.') == normalizedPattern.Count(static ch => ch == '.');
    }

    private static string NormalizeCertificatePattern(string pattern)
        => string.IsNullOrWhiteSpace(pattern)
            ? string.Empty
            : pattern.Trim().TrimEnd('.').ToLowerInvariant();

    private static string GetTopLevelDomain(string normalizedDomain)
    {
        if (string.IsNullOrWhiteSpace(normalizedDomain))
            return string.Empty;

        int lastDot = normalizedDomain.LastIndexOf('.');
        return lastDot >= 0 && lastDot < normalizedDomain.Length - 1
            ? normalizedDomain[lastDot..]
            : string.Empty;
    }

    private static string GetPrimaryDomainLabel(string normalizedDomain)
    {
        if (string.IsNullOrWhiteSpace(normalizedDomain))
            return string.Empty;

        var labels = normalizedDomain.Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (labels.Length == 0)
            return string.Empty;

        return labels[0];
    }

    private static int GetMaxConsonantRun(string value)
    {
        int current = 0;
        int best = 0;

        for (int i = 0; i < value.Length; i++)
        {
            char ch = char.ToLowerInvariant(value[i]);
            bool consonant = ch is >= 'a' and <= 'z' && "aeiou".IndexOf(ch) < 0;
            if (consonant)
            {
                current++;
                if (current > best)
                    best = current;
            }
            else
            {
                current = 0;
            }
        }

        return best;
    }

    private static string ShortenFingerprint(string fingerprint)
        => string.IsNullOrWhiteSpace(fingerprint)
            ? string.Empty
            : fingerprint.Length <= 16
                ? fingerprint
                : $"{fingerprint[..8]}...{fingerprint[^8..]}";

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

    private sealed class SecureEndpointState
    {
        public string ServerName = "";
        public string CertificateFingerprint = "";
        public IReadOnlyList<string> CertificateNames = Array.Empty<string>();
        public string CertificateSubject = "";
    }
}
