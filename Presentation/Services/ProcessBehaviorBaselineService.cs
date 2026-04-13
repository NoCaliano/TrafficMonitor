using Application.Abstractions;
using Domain.Models;
using Presentation.Models;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Presentation.Services;

public sealed class ProcessBehaviorBaselineService
{
    private const int MaxStoredFrequencyEntries = 64;

    private readonly object _gate = new();
    private readonly IProcessBaselineStore _store;
    private readonly Dictionary<string, ProcessBehaviorBaseline> _baselines;

    public ProcessBehaviorBaselineService(IProcessBaselineStore store)
    {
        _store = store;
        _baselines = _store.Load()
            .Where(static baseline => !string.IsNullOrWhiteSpace(baseline.BaselineKey))
            .GroupBy(static baseline => baseline.BaselineKey, StringComparer.OrdinalIgnoreCase)
            .Select(static group => group.OrderByDescending(baseline => baseline.LearnedSessionCount).First())
            .ToDictionary(static baseline => baseline.BaselineKey, StringComparer.OrdinalIgnoreCase);
    }

    public ProcessBehaviorAssessment Evaluate(ProcessStatRow row)
    {
        ArgumentNullException.ThrowIfNull(row);

        lock (_gate)
        {
            var snapshot = BuildSnapshot(row);
            _baselines.TryGetValue(snapshot.BaselineKey, out var baseline);
            return Assess(row, snapshot, baseline);
        }
    }

    public ProcessBehaviorAssessment FinalizeSession(ProcessStatRow row)
    {
        ArgumentNullException.ThrowIfNull(row);

        lock (_gate)
        {
            var snapshot = BuildSnapshot(row);
            _baselines.TryGetValue(snapshot.BaselineKey, out var baseline);

            var assessment = Assess(row, snapshot, baseline);
            if (!assessment.IsLearningEligible)
                return assessment;

            baseline ??= CreateBaseline(snapshot);
            UpdateBaseline(baseline, snapshot);
            _baselines[snapshot.BaselineKey] = baseline;
            PersistUnsafe();

            var learnedAssessment = Assess(row, snapshot, baseline);
            learnedAssessment.LearningDecision = $"Learned into baseline ({baseline.LearnedSessionCount} trusted session(s)).";
            learnedAssessment.LearningNote = baseline.LearnedSessionCount switch
            {
                1 => "Baseline initialized from one trusted session.",
                < 6 => "Baseline warmed up with another trusted session.",
                _ => "Stable baseline refreshed with this trusted session."
            };
            return learnedAssessment;
        }
    }

    public void ResetBaseline(ProcessStatRow row)
    {
        ArgumentNullException.ThrowIfNull(row);

        lock (_gate)
        {
            string key = BuildBaselineKey(row);
            if (string.IsNullOrWhiteSpace(key))
                return;

            if (_baselines.Remove(key))
                PersistUnsafe();
        }
    }

    private void PersistUnsafe()
    {
        var orderedBaselines = _baselines.Values
            .OrderByDescending(static baseline => baseline.LearnedSessionCount)
            .ThenBy(static baseline => baseline.ProcessName, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        _store.Save(orderedBaselines);
    }

    private static ProcessBehaviorSnapshot BuildSnapshot(ProcessStatRow row)
    {
        double outboundInboundRatio = row.InboundBytes <= 0
            ? (row.OutboundBytes > 0 ? double.PositiveInfinity : 0)
            : row.OutboundBytes / (double)row.InboundBytes;

        return new ProcessBehaviorSnapshot
        {
            BaselineKey = BuildBaselineKey(row),
            ObservedAtLocal = row.LastSeen == default ? DateTime.Now : row.LastSeen,
            ProcessName = row.ProcessName,
            ExePath = row.ExePath,
            Publisher = row.Publisher,
            SignerSubject = row.SignerSubject,
            IsSigned = row.IsSigned,
            PacketCount = row.PacketCount,
            TotalBytes = row.TotalBytes,
            DistinctRemoteEndpoints = row.DistinctRemoteEndpoints,
            DnsQueryCount = row.DnsQueryCount,
            UniqueDomainCount = row.UniqueDomainCount,
            OutboundInboundRatio = outboundInboundRatio,
            RareTldScore = row.RareTldScore,
            DgaLikeDomainCount = row.DgaLikeDomainCount,
            RootDomains = row.GetDominantRootDomainsSnapshot().ToArray(),
            ActiveHours = row.GetObservedActiveHoursSnapshot().ToArray(),
            ClientFingerprints = row.GetObservedClientFingerprintsSnapshot().ToArray(),
            CertificateFingerprints = row.GetObservedCertificateFingerprintsSnapshot().ToArray()
        };
    }

    private static string BuildBaselineKey(ProcessStatRow row)
    {
        string normalizedPath = NormalizeIdentityComponent(row.ExePath);
        string normalizedPublisher = NormalizeIdentityComponent(row.Publisher);
        string normalizedSigner = NormalizeIdentityComponent(row.SignerSubject);
        string normalizedProcessName = NormalizeIdentityComponent(row.ProcessName);

        return string.Join("|", new[]
        {
            normalizedPath,
            normalizedPublisher,
            normalizedSigner,
            normalizedProcessName,
            row.IsSigned ? "signed" : "unsigned"
        });
    }

    private static string NormalizeIdentityComponent(string? value)
        => string.IsNullOrWhiteSpace(value)
            ? "<unknown>"
            : value.Trim().ToLowerInvariant();

    private static ProcessBehaviorBaseline CreateBaseline(ProcessBehaviorSnapshot snapshot)
        => new()
        {
            BaselineKey = snapshot.BaselineKey,
            ProcessName = snapshot.ProcessName,
            ExePath = snapshot.ExePath,
            Publisher = snapshot.Publisher,
            SignerSubject = snapshot.SignerSubject,
            IsSigned = snapshot.IsSigned,
            LearnedSessionCount = 0
        };

    private static void UpdateBaseline(ProcessBehaviorBaseline baseline, ProcessBehaviorSnapshot snapshot)
    {
        baseline.ProcessName = snapshot.ProcessName;
        baseline.ExePath = snapshot.ExePath;
        baseline.Publisher = snapshot.Publisher;
        baseline.SignerSubject = snapshot.SignerSubject;
        baseline.IsSigned = snapshot.IsSigned;
        baseline.LearnedSessionCount++;
        baseline.FirstLearnedAtLocal ??= snapshot.ObservedAtLocal;
        baseline.LastLearnedAtLocal = snapshot.ObservedAtLocal;

        UpdateMetric(baseline.PacketCount, snapshot.PacketCount);
        UpdateMetric(baseline.TotalBytes, snapshot.TotalBytes);
        UpdateMetric(baseline.DistinctRemoteEndpoints, snapshot.DistinctRemoteEndpoints);
        UpdateMetric(baseline.DnsQueryCount, snapshot.DnsQueryCount);
        UpdateMetric(baseline.UniqueDomainCount, snapshot.UniqueDomainCount);
        UpdateMetric(baseline.OutboundInboundRatio, snapshot.OutboundInboundRatio);
        UpdateMetric(baseline.RareTldScore, snapshot.RareTldScore);
        UpdateMetric(baseline.DgaLikeDomainCount, snapshot.DgaLikeDomainCount);

        MergeFrequencies(baseline.RootDomainCounts, snapshot.RootDomains, MaxStoredFrequencyEntries);
        MergeFrequencies(baseline.ActiveHourCounts, snapshot.ActiveHours, 24);
        MergeFrequencies(baseline.ClientFingerprintCounts, snapshot.ClientFingerprints, 32);
        MergeFrequencies(baseline.CertificateFingerprintCounts, snapshot.CertificateFingerprints, 32);
    }

    private static void UpdateMetric(BehaviorMetricProfile profile, double sample)
    {
        if (profile.Samples == 0)
        {
            profile.Samples = 1;
            profile.Mean = sample;
            profile.M2 = 0;
            profile.Min = sample;
            profile.Max = sample;
            return;
        }

        profile.Samples++;
        double delta = sample - profile.Mean;
        profile.Mean += delta / profile.Samples;
        double delta2 = sample - profile.Mean;
        profile.M2 += delta * delta2;
        profile.Min = Math.Min(profile.Min, sample);
        profile.Max = Math.Max(profile.Max, sample);
    }

    private static void MergeFrequencies(Dictionary<string, int> target, IReadOnlyList<string> values, int maxEntries)
    {
        for (int i = 0; i < values.Count; i++)
        {
            string value = values[i];
            if (string.IsNullOrWhiteSpace(value))
                continue;

            target.TryGetValue(value, out int count);
            target[value] = count + 1;
        }

        if (target.Count <= maxEntries)
            return;

        var trimmed = target
            .OrderByDescending(static pair => pair.Value)
            .ThenBy(static pair => pair.Key, StringComparer.OrdinalIgnoreCase)
            .Take(maxEntries)
            .ToArray();

        target.Clear();
        for (int i = 0; i < trimmed.Length; i++)
            target[trimmed[i].Key] = trimmed[i].Value;
    }

    private static ProcessBehaviorAssessment Assess(ProcessStatRow row, ProcessBehaviorSnapshot snapshot, ProcessBehaviorBaseline? baseline)
    {
        var deviations = new List<ProcessBehaviorDeviation>(capacity: 8);
        int learnedSessions = baseline?.LearnedSessionCount ?? 0;

        if (baseline is not null && learnedSessions > 0)
        {
            TryAddMetricDeviation(
                deviations,
                key: "traffic-volume",
                title: "Traffic volume above baseline",
                summary: "The process transferred significantly more traffic than usual.",
                currentValue: snapshot.TotalBytes,
                profile: baseline.TotalBytes,
                absoluteFloor: 1.5 * 1024 * 1024,
                mediumMultiplier: 2.5,
                highMultiplier: 4.0,
                units: "bytes",
                formatter: FormatBytes);

            TryAddMetricDeviation(
                deviations,
                key: "fanout",
                title: "Remote fan-out above baseline",
                summary: "The process contacted more distinct remote endpoints than usual.",
                currentValue: snapshot.DistinctRemoteEndpoints,
                profile: baseline.DistinctRemoteEndpoints,
                absoluteFloor: 8,
                mediumMultiplier: 2.0,
                highMultiplier: 3.5,
                units: "remotes",
                formatter: static value => $"{value:0.#}");

            TryAddMetricDeviation(
                deviations,
                key: "dns-volume",
                title: "DNS activity above baseline",
                summary: "The process issued more DNS lookups than normal for this host.",
                currentValue: snapshot.DnsQueryCount,
                profile: baseline.DnsQueryCount,
                absoluteFloor: 12,
                mediumMultiplier: 2.5,
                highMultiplier: 4.0,
                units: "queries",
                formatter: static value => $"{value:0.#}");

            TryAddMetricDeviation(
                deviations,
                key: "rare-tld-spike",
                title: "Rare-TLD score above baseline",
                summary: "The session leaned harder into rare or frequently abused TLDs than usual.",
                currentValue: snapshot.RareTldScore,
                profile: baseline.RareTldScore,
                absoluteFloor: 4,
                mediumMultiplier: 2.0,
                highMultiplier: 3.0,
                units: "score",
                formatter: static value => $"{value:0.#}");

            TryAddMetricDeviation(
                deviations,
                key: "dga-spike",
                title: "DGA-like domain activity above baseline",
                summary: "Algorithmically-generated domain signals were stronger than in prior trusted sessions.",
                currentValue: snapshot.DgaLikeDomainCount,
                profile: baseline.DgaLikeDomainCount,
                absoluteFloor: 1,
                mediumMultiplier: 2.0,
                highMultiplier: 3.0,
                units: "domains",
                formatter: static value => $"{value:0.#}");

            if (learnedSessions >= 3)
            {
                TryAddNovelSetDeviation(
                    deviations,
                    key: "new-root-domains",
                    title: "New root domains for this process",
                    summary: "This session reached root domains that were absent from prior trusted runs.",
                    currentValues: snapshot.RootDomains,
                    baselineValues: baseline.RootDomainCounts.Keys,
                    maxExamples: 4,
                    lowScore: 4,
                    mediumScore: 8,
                    highScore: 12);

                TryAddNovelSetDeviation(
                    deviations,
                    key: "new-fingerprint",
                    title: "New client fingerprint",
                    summary: "The process presented a TLS/QUIC client fingerprint that was not part of its baseline.",
                    currentValues: snapshot.ClientFingerprints,
                    baselineValues: baseline.ClientFingerprintCounts.Keys,
                    maxExamples: 3,
                    lowScore: 6,
                    mediumScore: 10,
                    highScore: 14);

                TryAddNovelSetDeviation(
                    deviations,
                    key: "new-certificate",
                    title: "New certificate fingerprint",
                    summary: "The session encountered a server certificate fingerprint that was absent from trusted history.",
                    currentValues: snapshot.CertificateFingerprints,
                    baselineValues: baseline.CertificateFingerprintCounts.Keys,
                    maxExamples: 3,
                    lowScore: 6,
                    mediumScore: 10,
                    highScore: 14);

                TryAddNovelSetDeviation(
                    deviations,
                    key: "unusual-hour",
                    title: "Unusual activity hour",
                    summary: "The process became active at hours that do not appear in its baseline.",
                    currentValues: snapshot.ActiveHours,
                    baselineValues: baseline.ActiveHourCounts.Keys,
                    maxExamples: 4,
                    lowScore: 3,
                    mediumScore: 6,
                    highScore: 9,
                    formatter: static hour => $"{hour}:00");
            }
        }

        deviations.Sort(static (left, right) =>
        {
            int comparison = right.Score.CompareTo(left.Score);
            if (comparison != 0)
                return comparison;

            return string.Compare(left.Title, right.Title, StringComparison.Ordinal);
        });

        bool learningEligible = IsLearningEligible(row);
        string baselineState = GetBaselineStateLabel(learnedSessions);
        string baselineSummary = learnedSessions <= 0
            ? "No trusted baseline exists for this process identity yet."
            : learnedSessions == 1
                ? "One trusted session is available; anomaly thresholds are still warming up."
                : $"Learned from {learnedSessions} trusted session(s).";

        string learningNote = learningEligible
            ? learnedSessions <= 0
                ? "If this session stays low-risk, it will initialize the baseline when capture ends."
                : "If this session stays low-risk, it can extend the baseline when capture ends."
            : "This session is currently excluded from baseline learning because risk signals are active.";

        return new ProcessBehaviorAssessment
        {
            LearnedSessionCount = learnedSessions,
            BaselineStateLabel = baselineState,
            BaselineSummary = baselineSummary,
            LearningNote = learningNote,
            IsLearningEligible = learningEligible,
            LearningDecision = learningEligible ? "Eligible for learning at session end." : "Learning skipped for this session.",
            Deviations = deviations.ToArray()
        };
    }

    private static bool IsLearningEligible(ProcessStatRow row)
    {
        if (row.Pid <= 0 || row.PacketCount < 20 || row.TotalBytes < 32 * 1024)
            return false;

        if (row.RiskScore >= 40)
            return false;

        if (row.DetectionScenarios.Count > 0)
            return false;

        if (row.HasSuspiciousDomain || row.BeaconSuspected)
            return false;

        return !row.TlsDnsInsights.Any(static insight => insight.Score >= 10);
    }

    private static string GetBaselineStateLabel(int learnedSessions)
        => learnedSessions switch
        {
            <= 0 => "Baseline: none",
            1 or 2 => $"Baseline: learning ({learnedSessions} session{(learnedSessions == 1 ? "" : "s")})",
            <= 5 => $"Baseline: warm ({learnedSessions} sessions)",
            _ => $"Baseline: stable ({learnedSessions} sessions)"
        };

    private static void TryAddMetricDeviation(
        List<ProcessBehaviorDeviation> deviations,
        string key,
        string title,
        string summary,
        double currentValue,
        BehaviorMetricProfile profile,
        double absoluteFloor,
        double mediumMultiplier,
        double highMultiplier,
        string units,
        Func<double, string> formatter)
    {
        if (profile.Samples < 2 || currentValue < absoluteFloor || profile.Mean <= 0)
            return;

        double ratio = currentValue / profile.Mean;
        int score = ratio >= highMultiplier ? 14
            : ratio >= mediumMultiplier ? 8
            : 0;
        if (score <= 0)
            return;

        deviations.Add(new ProcessBehaviorDeviation
        {
            Key = key,
            Title = title,
            Summary = summary,
            Score = score,
            Evidence =
            [
                $"Current value reached {formatter(currentValue)} {units} vs baseline mean {formatter(profile.Mean)}.",
                $"Historical range across trusted sessions stayed between {formatter(profile.Min)} and {formatter(profile.Max)}."
            ]
        });
    }

    private static void TryAddNovelSetDeviation(
        List<ProcessBehaviorDeviation> deviations,
        string key,
        string title,
        string summary,
        IReadOnlyList<string> currentValues,
        IEnumerable<string> baselineValues,
        int maxExamples,
        int lowScore,
        int mediumScore,
        int highScore,
        Func<string, string>? formatter = null)
    {
        if (currentValues.Count == 0)
            return;

        var baselineSet = new HashSet<string>(baselineValues, StringComparer.OrdinalIgnoreCase);
        var novelValues = currentValues
            .Where(value => !string.IsNullOrWhiteSpace(value) && !baselineSet.Contains(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (novelValues.Length == 0)
            return;

        int score = novelValues.Length >= 4 ? highScore
            : novelValues.Length >= 2 ? mediumScore
            : lowScore;

        formatter ??= static value => value;
        string[] formattedExamples = novelValues
            .Take(maxExamples)
            .Select(formatter)
            .ToArray();

        deviations.Add(new ProcessBehaviorDeviation
        {
            Key = key,
            Title = title,
            Summary = summary,
            Score = score,
            Evidence =
            [
                $"{novelValues.Length} novel value(s) were absent from trusted history.",
                $"Examples: {string.Join(", ", formattedExamples)}."
            ]
        });
    }

    private static string FormatBytes(double bytes)
    {
        const double KB = 1024;
        const double MB = KB * 1024;
        const double GB = MB * 1024;

        if (bytes >= GB) return $"{bytes / GB:0.##} GB";
        if (bytes >= MB) return $"{bytes / MB:0.##} MB";
        if (bytes >= KB) return $"{bytes / KB:0.##} KB";
        return $"{bytes:0.#} B";
    }
}
