using Presentation.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Media;

namespace Presentation.Services;

public sealed class ProcessIncidentGraphBuilder
{
    private const double HorizontalCanvasPadding = 18;
    private const double LaneWidth = 216;
    private const double NodeWidth = 188;
    private const double NodeHeight = 96;
    private const double VerticalGap = 18;
    private const double TopMargin = 16;
    private const int MaxDomainNodes = 6;
    private const int MaxIpNodes = 6;
    private const int MaxCertificateNodes = 5;
    private const int MaxFindingNodes = 5;

    public ProcessIncidentGraph Build(ProcessStatRow? row, ProcessIncidentGraphSnapshot snapshot)
    {
        if (row is null || row.Pid <= 0)
            return ProcessIncidentGraph.Empty;

        var processSeed = CreateProcessSeed(row);
        var domainObservations = SelectDomainObservations(snapshot);
        var ipObservations = SelectIpObservations(snapshot, domainObservations);
        var certificateObservations = SelectCertificateObservations(snapshot, ipObservations);
        var findingDescriptors = BuildFindingDescriptors(row).Take(MaxFindingNodes).ToArray();

        bool hasTelemetry = domainObservations.Length > 0 || ipObservations.Length > 0 || certificateObservations.Length > 0;
        bool hasFindings = findingDescriptors.Length > 0;
        if (!hasTelemetry && !hasFindings)
        {
            return new ProcessIncidentGraph
            {
                EmptyState = "Graph populates after DNS, TLS, or ATT&CK evidence is observed for this process."
            };
        }

        var lanes = new List<(string Label, NodeSeed[] Seeds)>(capacity: 5)
        {
            ("Process", new[] { processSeed })
        };

        if (domainObservations.Length > 0)
            lanes.Add(("Domains", domainObservations.Select(CreateDomainSeed).ToArray()));

        if (ipObservations.Length > 0)
            lanes.Add(("IPs", ipObservations.Select(CreateIpSeed).ToArray()));

        if (certificateObservations.Length > 0)
            lanes.Add(("Certificates", certificateObservations.Select(CreateCertificateSeed).ToArray()));

        if (findingDescriptors.Length > 0)
            lanes.Add(("Findings", findingDescriptors.Select(CreateFindingSeed).ToArray()));

        var columns = lanes.Select(static lane => lane.Seeds).ToArray();

        int maxRows = columns.Max(static column => Math.Max(1, column.Length));
        double canvasWidth = (HorizontalCanvasPadding * 2.0) + (LaneWidth * columns.Length);
        double canvasHeight = Math.Max(180, (maxRows * NodeHeight) + ((maxRows - 1) * VerticalGap) + (TopMargin * 2));

        var nodes = new List<ProcessIncidentGraphNode>(capacity: columns.Sum(static column => column.Length));
        for (int laneIndex = 0; laneIndex < columns.Length; laneIndex++)
            nodes.AddRange(LayoutLaneNodes(columns[laneIndex], laneIndex, maxRows));

        var nodeById = nodes.ToDictionary(static node => node.Id, StringComparer.Ordinal);
        var edges = BuildEdges(row, snapshot, domainObservations, ipObservations, certificateObservations, findingDescriptors, nodeById);

        string summary = BuildSummary(domainObservations.Length, ipObservations.Length, certificateObservations.Length, findingDescriptors.Length, edges.Count);
        return new ProcessIncidentGraph
        {
            Lanes = lanes
                .Select(static lane => new ProcessIncidentGraphLane(lane.Label, LaneWidth - 8))
                .ToArray(),
            Nodes = nodes,
            Edges = edges,
            CanvasWidth = canvasWidth,
            CanvasHeight = canvasHeight,
            SummaryLabel = summary,
            EmptyState = "Graph populates after DNS, TLS, or ATT&CK evidence is observed for this process."
        };
    }

    private static ProcessIncidentGraphDomainObservation[] SelectDomainObservations(ProcessIncidentGraphSnapshot snapshot)
        => snapshot.Domains
            .OrderByDescending(static domain => domain.TotalBytes)
            .ThenByDescending(static domain => domain.ObservationCount)
            .ThenBy(static domain => domain.Domain, StringComparer.OrdinalIgnoreCase)
            .Take(MaxDomainNodes)
            .ToArray();

    private static ProcessIncidentGraphIpObservation[] SelectIpObservations(
        ProcessIncidentGraphSnapshot snapshot,
        IReadOnlyList<ProcessIncidentGraphDomainObservation> selectedDomains)
    {
        var selectedDomainSet = new HashSet<string>(selectedDomains.Select(static domain => domain.Domain), StringComparer.OrdinalIgnoreCase);
        var preferredIps = snapshot.DomainIpLinks
            .Where(link => selectedDomainSet.Contains(link.Domain))
            .GroupBy(static link => link.Ip, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(group => group.Sum(static link => link.HitCount))
            .ThenBy(static group => group.Key, StringComparer.OrdinalIgnoreCase)
            .Select(static group => group.Key)
            .ToList();

        foreach (var ip in snapshot.Ips
            .OrderByDescending(static observation => observation.TotalBytes)
            .ThenByDescending(static observation => observation.PacketCount)
            .ThenBy(static observation => observation.Ip, StringComparer.OrdinalIgnoreCase)
            .Select(static observation => observation.Ip))
        {
            if (!preferredIps.Contains(ip, StringComparer.OrdinalIgnoreCase))
                preferredIps.Add(ip);
        }

        var selectedIpSet = new HashSet<string>(preferredIps.Take(MaxIpNodes), StringComparer.OrdinalIgnoreCase);
        return snapshot.Ips
            .Where(observation => selectedIpSet.Contains(observation.Ip))
            .OrderByDescending(static observation => observation.TotalBytes)
            .ThenByDescending(static observation => observation.PacketCount)
            .ThenBy(static observation => observation.Ip, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static ProcessIncidentGraphCertificateObservation[] SelectCertificateObservations(
        ProcessIncidentGraphSnapshot snapshot,
        IReadOnlyList<ProcessIncidentGraphIpObservation> selectedIps)
    {
        var selectedIpSet = new HashSet<string>(selectedIps.Select(static ip => ip.Ip), StringComparer.OrdinalIgnoreCase);
        var preferredCertificates = snapshot.IpCertificateLinks
            .Where(link => selectedIpSet.Contains(link.Ip))
            .GroupBy(static link => link.CertificateFingerprint, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(group => group.Sum(static link => link.HitCount))
            .ThenBy(static group => group.Key, StringComparer.OrdinalIgnoreCase)
            .Select(static group => group.Key)
            .ToList();

        foreach (var fingerprint in snapshot.Certificates
            .OrderByDescending(static certificate => certificate.ObservationCount)
            .ThenByDescending(static certificate => certificate.LinkedDomains.Count)
            .ThenBy(static certificate => certificate.Fingerprint, StringComparer.OrdinalIgnoreCase)
            .Select(static certificate => certificate.Fingerprint))
        {
            if (!preferredCertificates.Contains(fingerprint, StringComparer.OrdinalIgnoreCase))
                preferredCertificates.Add(fingerprint);
        }

        var selectedCertificateSet = new HashSet<string>(preferredCertificates.Take(MaxCertificateNodes), StringComparer.OrdinalIgnoreCase);
        return snapshot.Certificates
            .Where(observation => selectedCertificateSet.Contains(observation.Fingerprint))
            .OrderByDescending(static observation => observation.ObservationCount)
            .ThenByDescending(static observation => observation.LinkedDomains.Count)
            .ThenBy(static observation => observation.Fingerprint, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static IReadOnlyList<ProcessIncidentGraphNode> LayoutLaneNodes(IReadOnlyList<NodeSeed> seeds, int laneIndex, int maxRows)
    {
        if (seeds.Count == 0)
            return Array.Empty<ProcessIncidentGraphNode>();

        double left = HorizontalCanvasPadding + (laneIndex * LaneWidth) + ((LaneWidth - NodeWidth) / 2.0);
        double laneHeight = NodeHeight + VerticalGap;
        double topOffset = TopMargin + ((maxRows - seeds.Count) * laneHeight / 2.0);

        var nodes = new ProcessIncidentGraphNode[seeds.Count];
        for (int index = 0; index < seeds.Count; index++)
        {
            var seed = seeds[index];
            nodes[index] = new ProcessIncidentGraphNode
            {
                Id = seed.Id,
                KindLabel = seed.KindLabel,
                Title = seed.Title,
                Subtitle = seed.Subtitle,
                MetricLabel = seed.MetricLabel,
                Tooltip = seed.Tooltip,
                LaneIndex = laneIndex,
                Left = left,
                Top = topOffset + (index * laneHeight),
                Width = NodeWidth,
                Height = NodeHeight,
                BackgroundBrush = seed.BackgroundBrush,
                BorderBrush = seed.BorderBrush,
                AccentBrush = seed.AccentBrush,
                SecondaryBrush = seed.SecondaryBrush
            };
        }

        return nodes;
    }

    private static List<ProcessIncidentGraphEdge> BuildEdges(
        ProcessStatRow row,
        ProcessIncidentGraphSnapshot snapshot,
        IReadOnlyList<ProcessIncidentGraphDomainObservation> domains,
        IReadOnlyList<ProcessIncidentGraphIpObservation> ips,
        IReadOnlyList<ProcessIncidentGraphCertificateObservation> certificates,
        IReadOnlyList<FindingDescriptor> findings,
        IReadOnlyDictionary<string, ProcessIncidentGraphNode> nodeById)
    {
        var edges = new List<ProcessIncidentGraphEdge>(capacity: 32);
        if (!nodeById.TryGetValue("process", out var processNode))
            return edges;

        for (int i = 0; i < domains.Count; i++)
        {
            string domainNodeId = GetDomainNodeId(domains[i].Domain);
            if (!nodeById.TryGetValue(domainNodeId, out var domainNode))
                continue;

            string domainTooltip = $"{row.ProcessName} observed {domains[i].Domain} {domains[i].ObservationCount:N0} time(s).";
            edges.Add(CreateEdge(processNode, domainNode, domainTooltip, domains[i].ObservationCount, domainNode.BorderBrush));
        }

        if (domains.Count == 0)
        {
            foreach (var ip in ips)
            {
                string ipNodeId = GetIpNodeId(ip.Ip);
                if (!nodeById.TryGetValue(ipNodeId, out var ipNode))
                    continue;

                string ipTooltip = $"{row.ProcessName} exchanged {ip.PacketCount:N0} packet(s) with {ip.Ip}.";
                edges.Add(CreateEdge(processNode, ipNode, ipTooltip, (int)Math.Min(int.MaxValue, Math.Max(1, ip.PacketCount)), ipNode.BorderBrush));
            }
        }

        var domainNodeSet = new HashSet<string>(domains.Select(static domain => domain.Domain), StringComparer.OrdinalIgnoreCase);
        var ipNodeSet = new HashSet<string>(ips.Select(static ip => ip.Ip), StringComparer.OrdinalIgnoreCase);
        foreach (var link in snapshot.DomainIpLinks)
        {
            if (!domainNodeSet.Contains(link.Domain) || !ipNodeSet.Contains(link.Ip))
                continue;

            if (!nodeById.TryGetValue(GetDomainNodeId(link.Domain), out var domainNode)
                || !nodeById.TryGetValue(GetIpNodeId(link.Ip), out var ipNode))
            {
                continue;
            }

            string tooltip = $"{link.Domain} resolved or connected to {link.Ip} ({link.HitCount:N0} observed link(s)).";
            edges.Add(CreateEdge(domainNode, ipNode, tooltip, link.HitCount, ipNode.BorderBrush));
        }

        var certificateNodeSet = new HashSet<string>(certificates.Select(static certificate => certificate.Fingerprint), StringComparer.OrdinalIgnoreCase);
        foreach (var link in snapshot.IpCertificateLinks)
        {
            if (!ipNodeSet.Contains(link.Ip) || !certificateNodeSet.Contains(link.CertificateFingerprint))
                continue;

            if (!nodeById.TryGetValue(GetIpNodeId(link.Ip), out var ipNode)
                || !nodeById.TryGetValue(GetCertificateNodeId(link.CertificateFingerprint), out var certificateNode))
            {
                continue;
            }

            string tooltip = $"{link.Ip} presented certificate {ShortenFingerprint(link.CertificateFingerprint)} ({link.HitCount:N0} TLS observation(s)).";
            edges.Add(CreateEdge(ipNode, certificateNode, tooltip, link.HitCount, certificateNode.BorderBrush));
        }

        for (int i = 0; i < findings.Count; i++)
        {
            string findingNodeId = GetFindingNodeId(findings[i].Id);
            if (!nodeById.TryGetValue(findingNodeId, out var findingNode))
                continue;

            var anchors = ResolveFindingAnchors(row, findings[i], domains, ips, certificates, nodeById, processNode);
            foreach (var anchor in anchors)
                edges.Add(CreateEdge(anchor, findingNode, findingNode.Tooltip, findings[i].Strength, findingNode.BorderBrush));
        }

        return edges;
    }

    private static IReadOnlyList<ProcessIncidentGraphNode> ResolveFindingAnchors(
        ProcessStatRow row,
        FindingDescriptor descriptor,
        IReadOnlyList<ProcessIncidentGraphDomainObservation> domains,
        IReadOnlyList<ProcessIncidentGraphIpObservation> ips,
        IReadOnlyList<ProcessIncidentGraphCertificateObservation> certificates,
        IReadOnlyDictionary<string, ProcessIncidentGraphNode> nodeById,
        ProcessIncidentGraphNode processNode)
    {
        switch (descriptor.AnchorKind)
        {
            case FindingAnchorKind.Domains:
            {
                var nodes = domains
                    .Take(2)
                    .Select(domain => nodeById.TryGetValue(GetDomainNodeId(domain.Domain), out var node) ? node : null)
                    .Where(static node => node is not null)
                    .Select(static node => node!)
                    .ToArray();
                return nodes.Length > 0 ? nodes : new[] { processNode };
            }
            case FindingAnchorKind.Ips:
            {
                string beaconIp = TryExtractBeaconIp(row.BeaconEndpoint);
                if (!string.IsNullOrWhiteSpace(beaconIp) && nodeById.TryGetValue(GetIpNodeId(beaconIp), out var beaconNode))
                    return new[] { beaconNode };

                var nodes = ips
                    .Take(descriptor.Key.Contains("fan-out", StringComparison.OrdinalIgnoreCase) ? 3 : 2)
                    .Select(ip => nodeById.TryGetValue(GetIpNodeId(ip.Ip), out var node) ? node : null)
                    .Where(static node => node is not null)
                    .Select(static node => node!)
                    .ToArray();
                return nodes.Length > 0 ? nodes : new[] { processNode };
            }
            case FindingAnchorKind.Certificates:
            {
                var nodes = certificates
                    .Take(2)
                    .Select(certificate => nodeById.TryGetValue(GetCertificateNodeId(certificate.Fingerprint), out var node) ? node : null)
                    .Where(static node => node is not null)
                    .Select(static node => node!)
                    .ToArray();
                if (nodes.Length > 0)
                    return nodes;

                if (ips.Count > 0 && nodeById.TryGetValue(GetIpNodeId(ips[0].Ip), out var fallbackIpNode))
                    return new[] { fallbackIpNode };

                return new[] { processNode };
            }
            default:
                return new[] { processNode };
        }
    }

    private static NodeSeed CreateProcessSeed(ProcessStatRow row)
    {
        string subtitle = row.Pid > 0
            ? $"PID {row.Pid} • {(row.IsSigned ? "Signed" : "Unsigned")}"
            : row.SignedLabel;
        string metric = $"{row.RiskLabel} • {row.PacketCount:N0} pkt";
        string tooltip = string.Join(Environment.NewLine, new[]
        {
            row.DisplayName,
            string.IsNullOrWhiteSpace(row.ExePath) ? "Executable path unavailable." : row.ExePath,
            row.TopRemoteEndpoint,
            row.LastSeen == default ? "No last-seen timestamp yet." : $"Last seen {row.LastSeen:yyyy-MM-dd HH:mm:ss}"
        }.Where(static value => !string.IsNullOrWhiteSpace(value)));

        return new NodeSeed(
            Id: "process",
            KindLabel: "Process",
            Title: row.ProcessName,
            Subtitle: subtitle,
            MetricLabel: metric,
            Tooltip: tooltip,
            BackgroundBrush: CreateBrush(236, 246, 255),
            BorderBrush: Brushes.SteelBlue,
            AccentBrush: Brushes.SteelBlue,
            SecondaryBrush: Brushes.SlateGray);
    }

    private static NodeSeed CreateDomainSeed(ProcessIncidentGraphDomainObservation observation)
    {
        string subtitle = observation.SniHits > 0 && observation.DnsHits > 0
            ? $"DNS {observation.DnsHits:N0} • SNI {observation.SniHits:N0}"
            : observation.DnsHits > 0
                ? $"DNS {observation.DnsHits:N0}"
                : observation.SniHits > 0
                    ? $"SNI {observation.SniHits:N0}"
                    : $"{observation.ObservationCount:N0} observation(s)";
        string metric = $"{observation.LinkedIps.Count:N0} IP(s) • {FormatBytes(observation.TotalBytes)}";
        string tooltip = string.Join(Environment.NewLine, new[]
        {
            observation.Domain,
            $"Observed {observation.ObservationCount:N0} time(s).",
            $"Linked IPs: {string.Join(", ", observation.LinkedIps.Take(5))}",
            observation.FirstSeen == default ? string.Empty : $"Window: {observation.FirstSeen:HH:mm:ss} - {observation.LastSeen:HH:mm:ss}"
        }.Where(static value => !string.IsNullOrWhiteSpace(value)));

        return new NodeSeed(
            Id: GetDomainNodeId(observation.Domain),
            KindLabel: "Domain",
            Title: observation.Domain,
            Subtitle: subtitle,
            MetricLabel: metric,
            Tooltip: tooltip,
            BackgroundBrush: CreateBrush(234, 250, 245),
            BorderBrush: Brushes.Teal,
            AccentBrush: Brushes.Teal,
            SecondaryBrush: Brushes.DarkSlateGray);
    }

    private static NodeSeed CreateIpSeed(ProcessIncidentGraphIpObservation observation)
    {
        string title = string.IsNullOrWhiteSpace(observation.ResolvedHost) || string.Equals(observation.ResolvedHost, observation.Ip, StringComparison.OrdinalIgnoreCase)
            ? observation.Ip
            : observation.ResolvedHost;
        string subtitle = string.Equals(title, observation.Ip, StringComparison.OrdinalIgnoreCase)
            ? $"{observation.LinkedDomains.Count:N0} domain(s)"
            : observation.Ip;
        string metric = $"{observation.PacketCount:N0} pkt • {FormatBytes(observation.TotalBytes)}";
        string tooltip = string.Join(Environment.NewLine, new[]
        {
            observation.Ip,
            string.IsNullOrWhiteSpace(observation.ResolvedHost) ? string.Empty : $"Resolved host: {observation.ResolvedHost}",
            observation.LinkedDomains.Count == 0 ? string.Empty : $"Domains: {string.Join(", ", observation.LinkedDomains.Take(4))}",
            observation.CertificateFingerprints.Count == 0 ? string.Empty : $"Certificates: {string.Join(", ", observation.CertificateFingerprints.Select(ShortenFingerprint).Take(3))}"
        }.Where(static value => !string.IsNullOrWhiteSpace(value)));

        return new NodeSeed(
            Id: GetIpNodeId(observation.Ip),
            KindLabel: "IP",
            Title: title,
            Subtitle: subtitle,
            MetricLabel: metric,
            Tooltip: tooltip,
            BackgroundBrush: CreateBrush(237, 248, 251),
            BorderBrush: Brushes.CadetBlue,
            AccentBrush: Brushes.CadetBlue,
            SecondaryBrush: Brushes.DarkSlateGray);
    }

    private static NodeSeed CreateCertificateSeed(ProcessIncidentGraphCertificateObservation observation)
    {
        string title = !string.IsNullOrWhiteSpace(observation.Subject)
            ? observation.Subject
            : ShortenFingerprint(observation.Fingerprint);
        string subtitle = ShortenFingerprint(observation.Fingerprint);
        string metric = $"{observation.LinkedIps.Count:N0} IP(s) • {observation.LinkedDomains.Count:N0} domain(s)";
        string tooltip = string.Join(Environment.NewLine, new[]
        {
            observation.Subject,
            $"Fingerprint: {observation.Fingerprint}",
            observation.Names.Count == 0 ? string.Empty : $"Names: {string.Join(", ", observation.Names.Take(4))}",
            observation.LinkedDomains.Count == 0 ? string.Empty : $"Observed domains: {string.Join(", ", observation.LinkedDomains.Take(4))}"
        }.Where(static value => !string.IsNullOrWhiteSpace(value)));

        return new NodeSeed(
            Id: GetCertificateNodeId(observation.Fingerprint),
            KindLabel: "Certificate",
            Title: title,
            Subtitle: subtitle,
            MetricLabel: metric,
            Tooltip: tooltip,
            BackgroundBrush: CreateBrush(255, 248, 232),
            BorderBrush: Brushes.DarkGoldenrod,
            AccentBrush: Brushes.DarkGoldenrod,
            SecondaryBrush: Brushes.SaddleBrown);
    }

    private static NodeSeed CreateFindingSeed(FindingDescriptor descriptor)
    {
        var (backgroundBrush, borderBrush) = descriptor.Strength >= 12
            ? (CreateBrush(255, 241, 241), Brushes.IndianRed)
            : descriptor.Strength >= 7
                ? (CreateBrush(255, 246, 235), Brushes.DarkOrange)
                : (CreateBrush(244, 248, 236), Brushes.OliveDrab);

        return new NodeSeed(
            Id: GetFindingNodeId(descriptor.Id),
            KindLabel: descriptor.KindLabel,
            Title: descriptor.Title,
            Subtitle: descriptor.Subtitle,
            MetricLabel: descriptor.MetricLabel,
            Tooltip: descriptor.Tooltip,
            BackgroundBrush: backgroundBrush,
            BorderBrush: borderBrush,
            AccentBrush: borderBrush,
            SecondaryBrush: Brushes.DimGray);
    }

    private static IReadOnlyList<FindingDescriptor> BuildFindingDescriptors(ProcessStatRow row)
    {
        var descriptors = new List<FindingDescriptor>(capacity: MaxFindingNodes);

        foreach (var scenario in row.DetectionScenarios)
        {
            descriptors.Add(new FindingDescriptor(
                Id: $"scenario-{scenario.Key}",
                Key: scenario.Key,
                KindLabel: "ATT&CK finding",
                Title: scenario.Title,
                Subtitle: scenario.MitreDisplayLabel,
                MetricLabel: $"{scenario.Confidence}% • +{scenario.RiskPoints}",
                Tooltip: BuildTooltip(scenario.Title, scenario.Summary, scenario.Evidence.Select(static evidence => evidence.Summary)),
                Strength: Math.Max(scenario.RiskPoints, scenario.Confidence >= 85 ? 14 : scenario.Confidence >= 70 ? 10 : 6),
                AnchorKind: GetScenarioAnchorKind(scenario.Key)));
        }

        if (descriptors.Count > 0)
            return descriptors;

        foreach (var insight in row.TlsDnsInsights.Where(static insight => insight.Score > 0))
        {
            descriptors.Add(new FindingDescriptor(
                Id: $"tlsdns-{insight.Key}",
                Key: insight.Key,
                KindLabel: "TLS / DNS signal",
                Title: insight.Title,
                Subtitle: insight.SeverityLabel,
                MetricLabel: insight.ScoreLabel,
                Tooltip: BuildTooltip(insight.Title, insight.Summary, insight.Evidence.Select(static evidence => evidence.Summary)),
                Strength: Math.Max(4, insight.Score),
                AnchorKind: GetInsightAnchorKind(insight.Key)));
        }

        foreach (var deviation in row.BehaviorDeviations.Where(static deviation => deviation.Score > 0))
        {
            descriptors.Add(new FindingDescriptor(
                Id: $"baseline-{deviation.Key}",
                Key: deviation.Key,
                KindLabel: "Baseline deviation",
                Title: deviation.Title,
                Subtitle: deviation.SeverityLabel,
                MetricLabel: deviation.ScoreLabel,
                Tooltip: BuildTooltip(deviation.Title, deviation.Summary, deviation.Evidence.Select(static evidence => evidence.Summary)),
                Strength: Math.Max(4, deviation.Score),
                AnchorKind: GetDeviationAnchorKind(deviation.Key)));
        }

        return descriptors
            .OrderByDescending(static descriptor => descriptor.Strength)
            .ThenBy(static descriptor => descriptor.Title, StringComparer.Ordinal)
            .ToArray();
    }

    private static string BuildSummary(int domains, int ips, int certificates, int findings, int edges)
    {
        var parts = new List<string>(capacity: 5);
        if (domains > 0)
            parts.Add($"{domains} domain{(domains == 1 ? "" : "s")}");
        if (ips > 0)
            parts.Add($"{ips} IP{(ips == 1 ? "" : "s")}");
        if (certificates > 0)
            parts.Add($"{certificates} cert{(certificates == 1 ? "" : "s")}");
        if (findings > 0)
            parts.Add($"{findings} finding{(findings == 1 ? "" : "s")}");
        if (edges > 0)
            parts.Add($"{edges} links");

        return parts.Count == 0
            ? "Graph telemetry is not available for this process yet."
            : string.Join(" • ", parts);
    }

    private static string BuildTooltip(string title, string summary, IEnumerable<string> evidence)
    {
        var parts = new List<string>(capacity: 6);
        if (!string.IsNullOrWhiteSpace(title))
            parts.Add(title);
        if (!string.IsNullOrWhiteSpace(summary))
            parts.Add(summary);

        foreach (var entry in evidence)
        {
            if (!string.IsNullOrWhiteSpace(entry))
                parts.Add(entry);
        }

        return string.Join(Environment.NewLine, parts);
    }

    private static FindingAnchorKind GetScenarioAnchorKind(string key)
    {
        if (key.Contains("dns", StringComparison.OrdinalIgnoreCase))
            return FindingAnchorKind.Domains;
        if (key.Contains("beacon", StringComparison.OrdinalIgnoreCase) || key.Contains("fan-out", StringComparison.OrdinalIgnoreCase))
            return FindingAnchorKind.Ips;
        if (key.Contains("exfil", StringComparison.OrdinalIgnoreCase))
            return FindingAnchorKind.Certificates;
        return FindingAnchorKind.Process;
    }

    private static FindingAnchorKind GetInsightAnchorKind(string key)
    {
        if (key.Contains("domain", StringComparison.OrdinalIgnoreCase)
            || key.Contains("rare-tld", StringComparison.OrdinalIgnoreCase)
            || key.Contains("dga", StringComparison.OrdinalIgnoreCase))
        {
            return FindingAnchorKind.Domains;
        }

        if (key.Contains("certificate", StringComparison.OrdinalIgnoreCase)
            || key.Contains("fingerprint", StringComparison.OrdinalIgnoreCase)
            || key.Contains("sni", StringComparison.OrdinalIgnoreCase))
        {
            return FindingAnchorKind.Certificates;
        }

        return FindingAnchorKind.Process;
    }

    private static FindingAnchorKind GetDeviationAnchorKind(string key)
    {
        if (key.Contains("domain", StringComparison.OrdinalIgnoreCase))
            return FindingAnchorKind.Domains;
        if (key.Contains("certificate", StringComparison.OrdinalIgnoreCase))
            return FindingAnchorKind.Certificates;
        if (key.Contains("fanout", StringComparison.OrdinalIgnoreCase))
            return FindingAnchorKind.Ips;
        return FindingAnchorKind.Process;
    }

    private static ProcessIncidentGraphEdge CreateEdge(ProcessIncidentGraphNode source, ProcessIncidentGraphNode target, string tooltip, int weight, Brush stroke)
    {
        double startX = source.RightX;
        double startY = source.CenterY;
        double endX = target.LeftX;
        double endY = target.CenterY;
        double horizontalDistance = Math.Max(56, (endX - startX) * 0.45);

        var figure = new PathFigure
        {
            StartPoint = new Point(startX, startY),
            Segments =
            {
                new BezierSegment(
                    new Point(startX + horizontalDistance, startY),
                    new Point(endX - horizontalDistance, endY),
                    new Point(endX, endY),
                    isStroked: true)
            }
        };
        var geometry = new PathGeometry(new[] { figure });
        geometry.Freeze();

        return new ProcessIncidentGraphEdge
        {
            SourceId = source.Id,
            TargetId = target.Id,
            Tooltip = tooltip,
            Geometry = geometry,
            Stroke = stroke,
            Thickness = weight >= 12 ? 3.0 : weight >= 6 ? 2.2 : 1.6,
            Opacity = weight >= 12 ? 0.95 : 0.75
        };
    }

    private static SolidColorBrush CreateBrush(byte r, byte g, byte b)
    {
        var brush = new SolidColorBrush(Color.FromRgb(r, g, b));
        brush.Freeze();
        return brush;
    }

    private static string ShortenFingerprint(string fingerprint)
        => string.IsNullOrWhiteSpace(fingerprint)
            ? string.Empty
            : fingerprint.Length <= 12
                ? fingerprint
                : $"{fingerprint[..6]}...{fingerprint[^6..]}";

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

    private static string GetDomainNodeId(string domain) => $"domain:{domain}";
    private static string GetIpNodeId(string ip) => $"ip:{ip}";
    private static string GetCertificateNodeId(string fingerprint) => $"cert:{fingerprint}";
    private static string GetFindingNodeId(string id) => $"finding:{id}";

    private static string TryExtractBeaconIp(string beaconEndpoint)
    {
        if (string.IsNullOrWhiteSpace(beaconEndpoint))
            return string.Empty;

        string[] parts = beaconEndpoint.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        string endpoint = parts.Length == 0 ? beaconEndpoint : parts[^1];
        int separatorIndex = endpoint.LastIndexOf(':');
        return separatorIndex > 0 ? endpoint[..separatorIndex] : endpoint;
    }

    private sealed record NodeSeed(
        string Id,
        string KindLabel,
        string Title,
        string Subtitle,
        string MetricLabel,
        string Tooltip,
        Brush BackgroundBrush,
        Brush BorderBrush,
        Brush AccentBrush,
        Brush SecondaryBrush);

    private sealed record FindingDescriptor(
        string Id,
        string Key,
        string KindLabel,
        string Title,
        string Subtitle,
        string MetricLabel,
        string Tooltip,
        int Strength,
        FindingAnchorKind AnchorKind);

    private enum FindingAnchorKind
    {
        Process,
        Domains,
        Ips,
        Certificates
    }
}
