using System;
using System.Collections.Generic;

namespace Domain.Models;

public sealed class ProcessBehaviorSnapshot
{
    public string BaselineKey { get; set; } = "";
    public DateTime ObservedAtLocal { get; set; }
    public string ProcessName { get; set; } = "";
    public string ExePath { get; set; } = "";
    public string Publisher { get; set; } = "";
    public string SignerSubject { get; set; } = "";
    public bool IsSigned { get; set; }
    public long PacketCount { get; set; }
    public long TotalBytes { get; set; }
    public int DistinctRemoteEndpoints { get; set; }
    public int DnsQueryCount { get; set; }
    public int UniqueDomainCount { get; set; }
    public double OutboundInboundRatio { get; set; }
    public int RareTldScore { get; set; }
    public int DgaLikeDomainCount { get; set; }
    public string[] RootDomains { get; set; } = Array.Empty<string>();
    public string[] ActiveHours { get; set; } = Array.Empty<string>();
    public string[] ClientFingerprints { get; set; } = Array.Empty<string>();
    public string[] CertificateFingerprints { get; set; } = Array.Empty<string>();
}

public sealed class ProcessBehaviorBaseline
{
    public string BaselineKey { get; set; } = "";
    public string ProcessName { get; set; } = "";
    public string ExePath { get; set; } = "";
    public string Publisher { get; set; } = "";
    public string SignerSubject { get; set; } = "";
    public bool IsSigned { get; set; }
    public int LearnedSessionCount { get; set; }
    public DateTime? FirstLearnedAtLocal { get; set; }
    public DateTime? LastLearnedAtLocal { get; set; }
    public BehaviorMetricProfile PacketCount { get; set; } = new();
    public BehaviorMetricProfile TotalBytes { get; set; } = new();
    public BehaviorMetricProfile DistinctRemoteEndpoints { get; set; } = new();
    public BehaviorMetricProfile DnsQueryCount { get; set; } = new();
    public BehaviorMetricProfile UniqueDomainCount { get; set; } = new();
    public BehaviorMetricProfile OutboundInboundRatio { get; set; } = new();
    public BehaviorMetricProfile RareTldScore { get; set; } = new();
    public BehaviorMetricProfile DgaLikeDomainCount { get; set; } = new();
    public Dictionary<string, int> RootDomainCounts { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, int> ActiveHourCounts { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, int> ClientFingerprintCounts { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, int> CertificateFingerprintCounts { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

public sealed class BehaviorMetricProfile
{
    public int Samples { get; set; }
    public double Mean { get; set; }
    public double M2 { get; set; }
    public double Min { get; set; }
    public double Max { get; set; }
}

public sealed class ProcessBehaviorDeviation
{
    public string Key { get; set; } = "";
    public string Title { get; set; } = "";
    public string Summary { get; set; } = "";
    public int Score { get; set; }
    public string[] Evidence { get; set; } = Array.Empty<string>();
}

public sealed class ProcessBehaviorAssessment
{
    public int LearnedSessionCount { get; set; }
    public string BaselineStateLabel { get; set; } = "";
    public string BaselineSummary { get; set; } = "";
    public string LearningNote { get; set; } = "";
    public bool IsLearningEligible { get; set; }
    public string LearningDecision { get; set; } = "";
    public ProcessBehaviorDeviation[] Deviations { get; set; } = Array.Empty<ProcessBehaviorDeviation>();
}
