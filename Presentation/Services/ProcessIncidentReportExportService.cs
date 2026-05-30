using Infrastructure.Networking;
using Presentation.Models;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Windows.Media;

namespace Presentation.Services;

public sealed class ProcessIncidentReportExportService
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    public sealed record ProcessIncidentReport(
        DateTime ExportedAtLocal,
        string GeneratedBy,
        string MachineName,
        ProcessMapperService.ProcessDetails ProcessDetails,
        ProcessStatRow Process,
        ProcessIncidentGraph IncidentGraph,
        IReadOnlyList<ProcessConversationRow> Conversations,
        IReadOnlyList<ProcessSessionClusterRow> SessionClusters);

    public void Export(string filePath, ProcessIncidentReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        string extension = Path.GetExtension(filePath);
        if (string.Equals(extension, ".json", StringComparison.OrdinalIgnoreCase))
        {
            ExportJson(filePath, report);
            return;
        }

        ExportHtml(filePath, report);
    }

    private static void ExportJson(string filePath, ProcessIncidentReport report)
    {
        var document = BuildDocument(report);
        string json = JsonSerializer.Serialize(document, JsonOptions);
        File.WriteAllText(filePath, json, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
    }

    private static void ExportHtml(string filePath, ProcessIncidentReport report)
    {
        var document = BuildDocument(report);
        string html = BuildHtml(document);
        File.WriteAllText(filePath, html, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
    }

    private static IncidentReportDocument BuildDocument(ProcessIncidentReport report)
    {
        var process = report.Process;
        var details = report.ProcessDetails;

        var summary = new IncidentSummaryDocument(
            ProcessName: process.ProcessName,
            Pid: process.Pid,
            RiskScore: process.RiskScore,
            RiskLabel: process.RiskLabel,
            IsAlive: process.IsAlive,
            LivenessLabel: process.LivenessLabel,
            IsSigned: process.IsSigned,
            SignedLabel: process.SignedLabel,
            Publisher: process.Publisher,
            SignerSubject: process.SignerSubject,
            ExePath: process.ExePath,
            ParentPid: process.ParentPid,
            ParentName: process.ParentName,
            PacketCount: process.PacketCount,
            TotalBytes: process.TotalBytes,
            TotalBytesHuman: process.TotalBytesHuman,
            DistinctRemoteEndpoints: process.DistinctRemoteEndpoints,
            TopRemoteEndpoint: process.TopRemoteEndpoint,
            LastSeen: process.LastSeen == default ? null : process.LastSeen,
            OutboundBytes: process.OutboundBytes,
            InboundBytes: process.InboundBytes,
            OutboundPackets: process.OutboundPacketsObserved,
            InboundPackets: process.InboundPacketsObserved,
            BeaconEndpoint: process.BeaconEndpoint,
            BeaconLabel: process.BeaconLabel,
            FirstSuspiciousDomain: process.FirstSuspiciousDomain,
            SuspiciousDomainReason: process.SuspiciousDomainReason,
            DetectionSummary: process.DetectionSummaryLabel,
            BaselineState: process.BaselineStateLabel,
            BaselineSummary: process.BaselineSummary,
            BaselineLearningNote: process.BaselineLearningNote,
            BehaviorDeviationSummary: process.BehaviorDeviationSummaryLabel,
            LastSamplePackets: process.LastSamplePackets,
            PeakSamplePackets: process.PeakSamplePackets,
            AvgSamplePackets: process.AvgSamplePackets,
            DnsQueryCount: process.DnsQueryCount,
            UniqueDnsQueryCount: process.UniqueDnsQueryCount,
            DnsTxtQueryCount: process.DnsTxtQueryCount,
            DnsEncodedQueryCount: process.DnsEncodedQueryCount,
            DnsLongestLabelLength: process.DnsLongestLabelLength,
            DominantDnsRoot: process.DominantDnsRoot,
            DominantDnsRootCount: process.DominantDnsRootCount,
            UniqueDomainCount: process.UniqueDomainCount,
            LatestNewDomain: process.LatestNewDomain,
            RareTldScore: process.RareTldScore,
            RareTldDomain: process.RareTldDomain,
            RareTld: process.RareTld,
            DgaLikeDomainCount: process.DgaLikeDomainCount,
            TopDgaLikeDomain: process.TopDgaLikeDomain,
            TopDgaLikeScore: process.TopDgaLikeScore,
            PrimaryJa3Lite: process.PrimaryJa3Lite,
            PrimaryJa3LiteCount: process.PrimaryJa3LiteCount,
            PrimaryJa4Lite: process.PrimaryJa4Lite,
            PrimaryJa4LiteCount: process.PrimaryJa4LiteCount,
            SniCertificateMismatchCount: process.SniCertificateMismatchCount,
            LastSniCertificateMismatch: process.LastSniCertificateMismatch,
            MostReusedCertificateFingerprint: process.MostReusedCertificateFingerprint,
            MostReusedCertificateDomainCount: process.MostReusedCertificateDomainCount,
            MostReusedCertificateDomainsSummary: process.MostReusedCertificateDomainsSummary,
            DetailsName: details.Name,
            DetailsExePath: details.ExePath,
            DetailsPublisher: details.Publisher,
            DetailsIsSigned: details.IsSigned);

        return new IncidentReportDocument(
            ExportedAtLocal: report.ExportedAtLocal,
            GeneratedBy: report.GeneratedBy,
            MachineName: report.MachineName,
            Summary: summary,
            IncidentGraph: BuildIncidentGraphDocument(report.IncidentGraph),
            DetectionScenarios: process.DetectionScenarios
                .Select(scenario => new DetectionScenarioDocument(
                    Title: scenario.Title,
                    MitreTechnique: scenario.MitreTechnique,
                    MitreTactic: scenario.MitreTactic,
                    Summary: scenario.Summary,
                    Confidence: scenario.Confidence,
                    ConfidenceLabel: scenario.ConfidenceLabel,
                    RiskPoints: scenario.RiskPoints,
                    Evidence: scenario.Evidence.Select(evidence => evidence.Summary).ToArray()))
                .ToArray(),
            TlsDnsInsights: process.TlsDnsInsights
                .Select(insight => new TlsDnsInsightDocument(
                    Title: insight.Title,
                    Summary: insight.Summary,
                    Score: insight.Score,
                    ScoreLabel: insight.ScoreLabel,
                    SeverityLabel: insight.SeverityLabel,
                    Evidence: insight.Evidence.Select(evidence => evidence.Summary).ToArray()))
                .ToArray(),
            BehaviorDeviations: process.BehaviorDeviations
                .Select(deviation => new BehaviorDeviationDocument(
                    Title: deviation.Title,
                    Summary: deviation.Summary,
                    Score: deviation.Score,
                    ScoreLabel: deviation.ScoreLabel,
                    SeverityLabel: deviation.SeverityLabel,
                    Evidence: deviation.Evidence.Select(evidence => evidence.Summary).ToArray()))
                .ToArray(),
            RiskReasons: process.RiskReasons
                .Select(reason => new RiskReasonDocument(reason.Summary, reason.Points))
                .ToArray(),
            Timeline: process.TimelineEvents
                .Select(entry => new TimelineEventDocument(entry.Timestamp, entry.Title, entry.Detail))
                .ToArray(),
            Conversations: report.Conversations
                .Select(conversation => new ConversationDocument(
                    Protocol: conversation.Protocol,
                    RemoteHost: conversation.DisplayHost,
                    RemoteEndpoint: conversation.DisplayEndpointLabel,
                    PacketCount: conversation.PacketCount,
                    TotalBytes: conversation.TotalBytes,
                    BytesLabel: conversation.BytesLabel,
                    DirectionLabel: conversation.DirectionLabel,
                    FirstSeen: conversation.FirstSeen,
                    LastSeen: conversation.LastSeen))
                .ToArray(),
            SessionClusters: report.SessionClusters
                .Select(cluster => new SessionClusterDocument(
                    Title: cluster.Title,
                    WindowLabel: cluster.WindowLabel,
                    DurationLabel: cluster.DurationLabel,
                    PacketCount: cluster.PacketCount,
                    TotalBytes: cluster.TotalBytes,
                    BytesLabel: cluster.BytesLabel,
                    DistinctRemoteEndpoints: cluster.DistinctRemoteEndpoints,
                    RemoteSummaryLabel: cluster.RemoteSummaryLabel,
                    DirectionLabel: cluster.DirectionLabel))
                .ToArray());
    }

    private static string BuildHtml(IncidentReportDocument document)
    {
        var sb = new StringBuilder(capacity: 32 * 1024);
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html lang=\"en\">");
        sb.AppendLine("<head>");
        sb.AppendLine("  <meta charset=\"utf-8\">");
        sb.AppendLine("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
        sb.AppendLine($"  <title>{Html(document.Summary.ProcessName)} incident report</title>");
        sb.AppendLine("  <style>");
        sb.AppendLine("    :root { color-scheme: light; --bg:#f4f6f8; --surface:#ffffff; --muted:#5c6b7a; --text:#1a2733; --line:#d7dee6; --accent:#0f766e; --risk:#b45309; --high:#b91c1c; }");
        sb.AppendLine("    * { box-sizing:border-box; }");
        sb.AppendLine("    body { margin:0; padding:24px; background:var(--bg); color:var(--text); font:14px/1.5 'Segoe UI', Tahoma, sans-serif; }");
        sb.AppendLine("    h1,h2,h3 { margin:0 0 12px; }");
        sb.AppendLine("    h1 { font-size:28px; }");
        sb.AppendLine("    h2 { font-size:18px; margin-top:24px; }");
        sb.AppendLine("    h3 { font-size:15px; }");
        sb.AppendLine("    p { margin:0 0 10px; }");
        sb.AppendLine("    .meta { color:var(--muted); margin-bottom:18px; }");
        sb.AppendLine("    .grid { display:grid; gap:16px; grid-template-columns:repeat(auto-fit, minmax(220px, 1fr)); }");
        sb.AppendLine("    .card { background:var(--surface); border:1px solid var(--line); border-radius:14px; padding:16px; }");
        sb.AppendLine("    .metric { font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:0.04em; }");
        sb.AppendLine("    .value { font-size:19px; font-weight:700; margin-top:4px; }");
        sb.AppendLine("    .subtle { color:var(--muted); }");
        sb.AppendLine("    .tag { display:inline-block; padding:3px 8px; border-radius:999px; border:1px solid var(--line); background:#f9fafb; font-size:12px; color:var(--muted); margin-right:6px; margin-bottom:6px; }");
        sb.AppendLine("    .scenario { border-left:4px solid var(--accent); padding-left:12px; margin-bottom:18px; }");
        sb.AppendLine("    .confidence { color:var(--accent); font-weight:700; }");
        sb.AppendLine("    .risk { color:var(--risk); font-weight:700; }");
        sb.AppendLine("    .high { color:var(--high); font-weight:700; }");
        sb.AppendLine("    table { width:100%; border-collapse:collapse; background:var(--surface); border:1px solid var(--line); border-radius:12px; overflow:hidden; }");
        sb.AppendLine("    th, td { padding:10px 12px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; }");
        sb.AppendLine("    th { font-size:12px; text-transform:uppercase; letter-spacing:0.04em; color:var(--muted); background:#f8fafc; }");
        sb.AppendLine("    tr:last-child td { border-bottom:none; }");
        sb.AppendLine("    ul { margin:8px 0 0 18px; padding:0; }");
        sb.AppendLine("    li { margin-bottom:6px; }");
        sb.AppendLine("    .incident-graph-summary { margin-bottom:12px; }");
        sb.AppendLine("    .incident-graph-scroll { overflow-x:auto; padding-bottom:4px; }");
        sb.AppendLine("    .incident-graph-frame { min-width:100%; }");
        sb.AppendLine("    .incident-graph-lanes { display:grid; gap:12px; margin-bottom:10px; }");
        sb.AppendLine("    .incident-graph-lane { padding:8px 12px; border:1px solid var(--line); border-radius:999px; background:#f3f6fa; text-align:center; font-size:12px; font-weight:700; color:#304252; }");
        sb.AppendLine("    .incident-graph-svg { display:block; background:#f8fafc; border:1px solid var(--line); border-radius:14px; }");
        sb.AppendLine("    .graph-node { width:100%; height:100%; border:1.4px solid; border-radius:10px; padding:12px 10px; font:12px/1.35 'Segoe UI', Tahoma, sans-serif; overflow:hidden; display:flex; flex-direction:column; }");
        sb.AppendLine("    .graph-node-head { display:flex; justify-content:space-between; align-items:flex-start; gap:8px; }");
        sb.AppendLine("    .graph-node-kind { font-size:10px; font-weight:700; }");
        sb.AppendLine("    .graph-node-badge { padding:2px 6px; border:1px solid; border-radius:999px; font-size:9px; font-weight:700; white-space:nowrap; }");
        sb.AppendLine("    .graph-node-title { margin-top:5px; font-size:13px; font-weight:700; color:var(--text); display:-webkit-box; -webkit-line-clamp:2; -webkit-box-orient:vertical; overflow:hidden; }");
        sb.AppendLine("    .graph-node-subtitle { margin-top:3px; font-size:10px; display:-webkit-box; -webkit-line-clamp:2; -webkit-box-orient:vertical; overflow:hidden; }");
        sb.AppendLine("    .graph-node-metric { margin-top:auto; padding-top:6px; font-size:10px; font-weight:700; }");
        sb.AppendLine("  </style>");
        sb.AppendLine("</head>");
        sb.AppendLine("<body>");
        sb.AppendLine($"  <h1>Incident report: {Html(document.Summary.ProcessName)} (PID {document.Summary.Pid})</h1>");
        sb.AppendLine($"  <p class=\"meta\">Generated by {Html(document.GeneratedBy)} on {Html(document.MachineName)} at {Html(FormatDateTime(document.ExportedAtLocal))}</p>");

        sb.AppendLine("  <div class=\"grid\">");
        AppendMetricCard(sb, "Risk", document.Summary.RiskLabel, $"Score {document.Summary.RiskScore}/100");
        AppendMetricCard(sb, "Traffic", document.Summary.TotalBytesHuman, $"{document.Summary.PacketCount:N0} packets observed");
        AppendMetricCard(sb, "Liveness", document.Summary.LivenessLabel, document.Summary.LastSeen is null ? "No last-seen timestamp" : $"Last seen {FormatDateTime(document.Summary.LastSeen.Value)}");
        AppendMetricCard(sb, "Detections", string.IsNullOrWhiteSpace(document.Summary.DetectionSummary) ? "None" : document.Summary.DetectionSummary, $"{document.DetectionScenarios.Length} scenario(s)");
        AppendMetricCard(sb, "Baseline", document.Summary.BaselineState, string.IsNullOrWhiteSpace(document.Summary.BehaviorDeviationSummary) ? "No active deviations" : document.Summary.BehaviorDeviationSummary);
        sb.AppendLine("  </div>");

        sb.AppendLine("  <h2>Process profile</h2>");
        sb.AppendLine("  <div class=\"card\">");
        AppendDefinitionLine(sb, "Executable", document.Summary.ExePath);
        AppendDefinitionLine(sb, "Publisher", document.Summary.Publisher);
        AppendDefinitionLine(sb, "Signature", document.Summary.SignedLabel);
        AppendDefinitionLine(sb, "Parent", FormatParent(document.Summary.ParentName, document.Summary.ParentPid));
        AppendDefinitionLine(sb, "Adaptive baseline", document.Summary.BaselineState);
        AppendDefinitionLine(sb, "Top remote", document.Summary.TopRemoteEndpoint);
        AppendDefinitionLine(sb, "Outbound / inbound bytes", $"{FormatBytes(document.Summary.OutboundBytes)} / {FormatBytes(document.Summary.InboundBytes)}");
        AppendDefinitionLine(sb, "Outbound / inbound packets", $"{document.Summary.OutboundPackets:N0} / {document.Summary.InboundPackets:N0}");
        AppendDefinitionLine(sb, "Distinct remotes", $"{document.Summary.DistinctRemoteEndpoints:N0}");
        AppendDefinitionLine(sb, "Burst metrics", $"recent {document.Summary.LastSamplePackets:N0}, peak {document.Summary.PeakSamplePackets:N0}, avg {document.Summary.AvgSamplePackets:0.#}");
        if (!string.IsNullOrWhiteSpace(document.Summary.BeaconLabel))
            AppendDefinitionLine(sb, "Beacon", document.Summary.BeaconLabel);
        if (!string.IsNullOrWhiteSpace(document.Summary.FirstSuspiciousDomain))
            AppendDefinitionLine(sb, "Suspicious domain", $"{document.Summary.FirstSuspiciousDomain} ({document.Summary.SuspiciousDomainReason})");
        if (document.Summary.DnsQueryCount > 0)
            AppendDefinitionLine(sb, "DNS activity", $"{document.Summary.DnsQueryCount:N0} queries, {document.Summary.UniqueDnsQueryCount:N0} unique, {document.Summary.DnsTxtQueryCount:N0} TXT, {document.Summary.DnsEncodedQueryCount:N0} encoded-looking");
        if (!string.IsNullOrWhiteSpace(document.Summary.PrimaryJa3Lite))
            AppendDefinitionLine(sb, "JA3-lite", $"{document.Summary.PrimaryJa3Lite} ({document.Summary.PrimaryJa3LiteCount:N0} hits)");
        if (!string.IsNullOrWhiteSpace(document.Summary.PrimaryJa4Lite))
            AppendDefinitionLine(sb, "JA4-lite", $"{document.Summary.PrimaryJa4Lite} ({document.Summary.PrimaryJa4LiteCount:N0} hits)");
        if (document.Summary.UniqueDomainCount > 0)
            AppendDefinitionLine(sb, "Observed domains", $"{document.Summary.UniqueDomainCount:N0} unique; latest {document.Summary.LatestNewDomain}");
        if (document.Summary.RareTldScore > 0)
            AppendDefinitionLine(sb, "Rare-TLD score", $"{document.Summary.RareTldScore:N0} ({document.Summary.RareTldDomain} / {document.Summary.RareTld})");
        if (document.Summary.DgaLikeDomainCount > 0)
            AppendDefinitionLine(sb, "DGA-like domains", $"{document.Summary.DgaLikeDomainCount:N0} seen; top {document.Summary.TopDgaLikeDomain} ({document.Summary.TopDgaLikeScore}/100)");
        if (document.Summary.SniCertificateMismatchCount > 0)
            AppendDefinitionLine(sb, "SNI / certificate mismatch", $"{document.Summary.SniCertificateMismatchCount:N0} event(s); latest {document.Summary.LastSniCertificateMismatch}");
        if (document.Summary.MostReusedCertificateDomainCount > 0)
            AppendDefinitionLine(sb, "Certificate reuse", $"{document.Summary.MostReusedCertificateDomainCount:N0} domains on {document.Summary.MostReusedCertificateFingerprint}");
        if (!string.IsNullOrWhiteSpace(document.Summary.BaselineSummary))
            AppendDefinitionLine(sb, "Baseline summary", document.Summary.BaselineSummary);
        if (!string.IsNullOrWhiteSpace(document.Summary.BaselineLearningNote))
            AppendDefinitionLine(sb, "Learning note", document.Summary.BaselineLearningNote);
        sb.AppendLine("  </div>");

        sb.AppendLine("  <h2>Detection scenarios</h2>");
        if (document.DetectionScenarios.Length == 0)
        {
            sb.AppendLine("  <div class=\"card\"><p class=\"subtle\">No ATT&CK-style scenarios crossed the current thresholds.</p></div>");
        }
        else
        {
            sb.AppendLine("  <div class=\"card\">");
            foreach (var scenario in document.DetectionScenarios)
            {
                sb.AppendLine("    <div class=\"scenario\">");
                sb.AppendLine($"      <h3>{Html(scenario.Title)}</h3>");
                sb.AppendLine($"      <p><span class=\"tag\">ATT&CK {Html(scenario.MitreTechnique)} / {Html(scenario.MitreTactic)}</span><span class=\"tag\">{Html(scenario.ConfidenceLabel)}</span><span class=\"tag\">+{scenario.RiskPoints} risk</span></p>");
                sb.AppendLine($"      <p>{Html(scenario.Summary)}</p>");
                if (scenario.Evidence.Length > 0)
                {
                    sb.AppendLine("      <ul>");
                    for (int i = 0; i < scenario.Evidence.Length; i++)
                        sb.AppendLine($"        <li>{Html(scenario.Evidence[i])}</li>");
                    sb.AppendLine("      </ul>");
                }
                sb.AppendLine("    </div>");
            }
            sb.AppendLine("  </div>");
        }

        sb.AppendLine("  <h2>TLS / DNS intelligence</h2>");
        if (document.TlsDnsInsights.Length == 0)
        {
            sb.AppendLine("  <div class=\"card\"><p class=\"subtle\">No TLS or DNS intelligence findings were derived.</p></div>");
        }
        else
        {
            sb.AppendLine("  <div class=\"card\">");
            foreach (var insight in document.TlsDnsInsights)
            {
                sb.AppendLine("    <div class=\"scenario\">");
                sb.AppendLine($"      <h3>{Html(insight.Title)}</h3>");
                sb.AppendLine($"      <p><span class=\"tag\">{Html(insight.SeverityLabel)}</span><span class=\"tag\">{Html(insight.ScoreLabel)}</span></p>");
                sb.AppendLine($"      <p>{Html(insight.Summary)}</p>");
                if (insight.Evidence.Length > 0)
                {
                    sb.AppendLine("      <ul>");
                    for (int i = 0; i < insight.Evidence.Length; i++)
                        sb.AppendLine($"        <li>{Html(insight.Evidence[i])}</li>");
                    sb.AppendLine("      </ul>");
                }
                sb.AppendLine("    </div>");
            }
            sb.AppendLine("  </div>");
        }

        sb.AppendLine("  <h2>Adaptive baseline</h2>");
        sb.AppendLine("  <div class=\"card\">");
        sb.AppendLine($"    <p><strong>State:</strong> {Html(document.Summary.BaselineState)}</p>");
        if (!string.IsNullOrWhiteSpace(document.Summary.BaselineSummary))
            sb.AppendLine($"    <p>{Html(document.Summary.BaselineSummary)}</p>");
        if (!string.IsNullOrWhiteSpace(document.Summary.BaselineLearningNote))
            sb.AppendLine($"    <p class=\"subtle\">{Html(document.Summary.BaselineLearningNote)}</p>");

        if (document.BehaviorDeviations.Length == 0)
        {
            sb.AppendLine("    <p class=\"subtle\">No behavioral deviations from the local baseline were derived.</p>");
        }
        else
        {
            foreach (var deviation in document.BehaviorDeviations)
            {
                sb.AppendLine("    <div class=\"scenario\">");
                sb.AppendLine($"      <h3>{Html(deviation.Title)}</h3>");
                sb.AppendLine($"      <p><span class=\"tag\">{Html(deviation.SeverityLabel)}</span><span class=\"tag\">{Html(deviation.ScoreLabel)}</span></p>");
                sb.AppendLine($"      <p>{Html(deviation.Summary)}</p>");
                if (deviation.Evidence.Length > 0)
                {
                    sb.AppendLine("      <ul>");
                    for (int i = 0; i < deviation.Evidence.Length; i++)
                        sb.AppendLine($"        <li>{Html(deviation.Evidence[i])}</li>");
                    sb.AppendLine("      </ul>");
                }
                sb.AppendLine("    </div>");
            }
        }
        sb.AppendLine("  </div>");

        AppendIncidentGraphSection(sb, document.IncidentGraph);

        sb.AppendLine("  <h2>Risk signals</h2>");
        sb.AppendLine("  <div class=\"card\">");
        if (document.RiskReasons.Length == 0)
        {
            sb.AppendLine("    <p class=\"subtle\">No risk signals recorded.</p>");
        }
        else
        {
            sb.AppendLine("    <ul>");
            for (int i = 0; i < document.RiskReasons.Length; i++)
                sb.AppendLine($"      <li>{Html(document.RiskReasons[i].Summary)} (+{document.RiskReasons[i].Points})</li>");
            sb.AppendLine("    </ul>");
        }
        sb.AppendLine("  </div>");

        AppendTimelineTable(sb, document.Timeline);
        AppendConversationsTable(sb, document.Conversations);
        AppendSessionClustersTable(sb, document.SessionClusters);

        sb.AppendLine("</body>");
        sb.AppendLine("</html>");
        return sb.ToString();
    }

    private static IncidentGraphDocument BuildIncidentGraphDocument(ProcessIncidentGraph graph)
    {
        ArgumentNullException.ThrowIfNull(graph);

        return new IncidentGraphDocument(
            HasGraph: graph.HasGraph,
            SummaryLabel: graph.SummaryLabel,
            EmptyState: graph.EmptyState,
            CanvasWidth: graph.CanvasWidth,
            CanvasHeight: graph.CanvasHeight,
            Lanes: graph.Lanes
                .Select(lane => new IncidentGraphLaneDocument(lane.Label))
                .ToArray(),
            Nodes: graph.Nodes
                .Select(node => new IncidentGraphNodeDocument(
                    KindLabel: node.KindLabel,
                    Title: node.Title,
                    Subtitle: node.Subtitle,
                    MetricLabel: node.MetricLabel,
                    Tooltip: node.Tooltip,
                    BadgeText: node.BadgeText,
                    Left: node.Left,
                    Top: node.Top,
                    Width: node.Width,
                    Height: node.Height,
                    BackgroundColor: BrushToCss(node.BackgroundBrush),
                    BorderColor: BrushToCss(node.BorderBrush),
                    AccentColor: BrushToCss(node.AccentBrush),
                    SecondaryColor: BrushToCss(node.SecondaryBrush),
                    BadgeBackgroundColor: BrushToCss(node.BadgeBackgroundBrush),
                    BadgeBorderColor: BrushToCss(node.BadgeBorderBrush),
                    BadgeForegroundColor: BrushToCss(node.BadgeForegroundBrush),
                    HasBadge: node.HasBadge))
                .ToArray(),
            Edges: graph.Edges
                .Select(edge => new IncidentGraphEdgeDocument(
                    PathData: edge.Geometry.ToString(CultureInfo.InvariantCulture),
                    Tooltip: edge.Tooltip,
                    StrokeColor: BrushToCss(edge.Stroke),
                    StrokeDashArray: edge.StrokeDashArray is null
                        ? ""
                        : string.Join(" ", edge.StrokeDashArray.Select(value => value.ToString("0.###", CultureInfo.InvariantCulture))),
                    Thickness: edge.Thickness,
                    Opacity: edge.Opacity))
                .ToArray());
    }

    private static void AppendIncidentGraphSection(StringBuilder sb, IncidentGraphDocument graph)
    {
        sb.AppendLine("  <h2>Incident graph</h2>");
        sb.AppendLine("  <div class=\"card\">");

        if (!string.IsNullOrWhiteSpace(graph.SummaryLabel))
            sb.AppendLine($"    <p class=\"subtle incident-graph-summary\">{Html(graph.SummaryLabel)}</p>");

        if (!graph.HasGraph || graph.Nodes.Length == 0)
        {
            sb.AppendLine($"    <p class=\"subtle\">{Html(graph.EmptyState)}</p>");
            sb.AppendLine("  </div>");
            return;
        }

        int laneCount = Math.Max(1, graph.Lanes.Length);
        sb.AppendLine("    <div class=\"incident-graph-scroll\">");
        sb.AppendLine($"      <div class=\"incident-graph-frame\" style=\"width:{FormatNumber(graph.CanvasWidth)}px;\">");
        sb.AppendLine($"        <div class=\"incident-graph-lanes\" style=\"grid-template-columns:repeat({laneCount}, minmax(0, 1fr));\">");
        for (int i = 0; i < graph.Lanes.Length; i++)
            sb.AppendLine($"          <div class=\"incident-graph-lane\">{Html(graph.Lanes[i].Label)}</div>");
        sb.AppendLine("        </div>");
        sb.AppendLine($"        <svg class=\"incident-graph-svg\" width=\"{FormatNumber(graph.CanvasWidth)}\" height=\"{FormatNumber(graph.CanvasHeight)}\" viewBox=\"0 0 {FormatNumber(graph.CanvasWidth)} {FormatNumber(graph.CanvasHeight)}\" xmlns=\"http://www.w3.org/2000/svg\">");

        for (int i = 0; i < graph.Edges.Length; i++)
        {
            var edge = graph.Edges[i];
            sb.Append($"          <path d=\"{HtmlAttribute(edge.PathData)}\" fill=\"none\" stroke=\"{HtmlAttribute(edge.StrokeColor)}\" stroke-width=\"{FormatNumber(edge.Thickness)}\" opacity=\"{FormatNumber(edge.Opacity)}\" stroke-linecap=\"round\"");
            if (!string.IsNullOrWhiteSpace(edge.StrokeDashArray))
                sb.Append($" stroke-dasharray=\"{HtmlAttribute(edge.StrokeDashArray)}\"");
            sb.AppendLine(">");
            if (!string.IsNullOrWhiteSpace(edge.Tooltip))
                sb.AppendLine($"            <title>{Html(edge.Tooltip)}</title>");
            sb.AppendLine("          </path>");
        }

        for (int i = 0; i < graph.Nodes.Length; i++)
        {
            var node = graph.Nodes[i];
            sb.AppendLine($"          <foreignObject x=\"{FormatNumber(node.Left)}\" y=\"{FormatNumber(node.Top)}\" width=\"{FormatNumber(node.Width)}\" height=\"{FormatNumber(node.Height)}\">");
            sb.AppendLine($"            <div xmlns=\"http://www.w3.org/1999/xhtml\" class=\"graph-node\" style=\"background:{HtmlAttribute(node.BackgroundColor)}; border-color:{HtmlAttribute(node.BorderColor)};\" title=\"{HtmlAttribute(node.Tooltip)}\">");
            sb.AppendLine("              <div class=\"graph-node-head\">");
            sb.AppendLine($"                <span class=\"graph-node-kind\" style=\"color:{HtmlAttribute(node.AccentColor)};\">{Html(node.KindLabel)}</span>");
            if (node.HasBadge)
                sb.AppendLine($"                <span class=\"graph-node-badge\" style=\"background:{HtmlAttribute(node.BadgeBackgroundColor)}; border-color:{HtmlAttribute(node.BadgeBorderColor)}; color:{HtmlAttribute(node.BadgeForegroundColor)};\">{Html(node.BadgeText)}</span>");
            sb.AppendLine("              </div>");
            sb.AppendLine($"              <div class=\"graph-node-title\">{Html(node.Title)}</div>");
            if (!string.IsNullOrWhiteSpace(node.Subtitle))
                sb.AppendLine($"              <div class=\"graph-node-subtitle\" style=\"color:{HtmlAttribute(node.SecondaryColor)};\">{Html(node.Subtitle)}</div>");
            sb.AppendLine($"              <div class=\"graph-node-metric\" style=\"color:{HtmlAttribute(node.AccentColor)};\">{Html(node.MetricLabel)}</div>");
            sb.AppendLine("            </div>");
            sb.AppendLine("          </foreignObject>");
        }

        sb.AppendLine("        </svg>");
        sb.AppendLine("      </div>");
        sb.AppendLine("    </div>");
        sb.AppendLine("  </div>");
    }

    private static void AppendMetricCard(StringBuilder sb, string label, string value, string caption)
    {
        sb.AppendLine("    <div class=\"card\">");
        sb.AppendLine($"      <div class=\"metric\">{Html(label)}</div>");
        sb.AppendLine($"      <div class=\"value\">{Html(value)}</div>");
        sb.AppendLine($"      <div class=\"subtle\">{Html(caption)}</div>");
        sb.AppendLine("    </div>");
    }

    private static void AppendDefinitionLine(StringBuilder sb, string label, string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return;

        sb.AppendLine($"    <p><strong>{Html(label)}:</strong> {Html(value)}</p>");
    }

    private static void AppendTimelineTable(StringBuilder sb, IReadOnlyList<TimelineEventDocument> timeline)
    {
        sb.AppendLine("  <h2>Timeline</h2>");
        if (timeline.Count == 0)
        {
            sb.AppendLine("  <div class=\"card\"><p class=\"subtle\">No investigation events recorded.</p></div>");
            return;
        }

        sb.AppendLine("  <table>");
        sb.AppendLine("    <thead><tr><th>Time</th><th>Title</th><th>Detail</th></tr></thead>");
        sb.AppendLine("    <tbody>");
        for (int i = 0; i < timeline.Count; i++)
        {
            var entry = timeline[i];
            sb.AppendLine($"      <tr><td>{Html(FormatDateTime(entry.Timestamp))}</td><td>{Html(entry.Title)}</td><td>{Html(entry.Detail)}</td></tr>");
        }
        sb.AppendLine("    </tbody>");
        sb.AppendLine("  </table>");
    }

    private static void AppendConversationsTable(StringBuilder sb, IReadOnlyList<ConversationDocument> conversations)
    {
        sb.AppendLine("  <h2>Conversation view</h2>");
        if (conversations.Count == 0)
        {
            sb.AppendLine("  <div class=\"card\"><p class=\"subtle\">No conversation partners recorded.</p></div>");
            return;
        }

        sb.AppendLine("  <table>");
        sb.AppendLine("    <thead><tr><th>Protocol</th><th>Remote</th><th>Packets</th><th>Bytes</th><th>Direction</th><th>First seen</th><th>Last seen</th></tr></thead>");
        sb.AppendLine("    <tbody>");
        for (int i = 0; i < conversations.Count; i++)
        {
            var conversation = conversations[i];
            sb.AppendLine($"      <tr><td>{Html(conversation.Protocol)}</td><td>{Html(conversation.RemoteEndpoint)}</td><td>{conversation.PacketCount:N0}</td><td>{Html(conversation.BytesLabel)}</td><td>{Html(conversation.DirectionLabel)}</td><td>{Html(FormatDateTime(conversation.FirstSeen))}</td><td>{Html(FormatDateTime(conversation.LastSeen))}</td></tr>");
        }
        sb.AppendLine("    </tbody>");
        sb.AppendLine("  </table>");
    }

    private static void AppendSessionClustersTable(StringBuilder sb, IReadOnlyList<SessionClusterDocument> sessionClusters)
    {
        sb.AppendLine("  <h2>Session clusters</h2>");
        if (sessionClusters.Count == 0)
        {
            sb.AppendLine("  <div class=\"card\"><p class=\"subtle\">No session clusters recorded.</p></div>");
            return;
        }

        sb.AppendLine("  <table>");
        sb.AppendLine("    <thead><tr><th>Session</th><th>Window</th><th>Duration</th><th>Packets</th><th>Bytes</th><th>Remotes</th><th>Direction</th></tr></thead>");
        sb.AppendLine("    <tbody>");
        for (int i = 0; i < sessionClusters.Count; i++)
        {
            var cluster = sessionClusters[i];
            sb.AppendLine($"      <tr><td>{Html(cluster.Title)}</td><td>{Html(cluster.WindowLabel)}</td><td>{Html(cluster.DurationLabel)}</td><td>{cluster.PacketCount:N0}</td><td>{Html(cluster.BytesLabel)}</td><td>{Html(cluster.RemoteSummaryLabel)}</td><td>{Html(cluster.DirectionLabel)}</td></tr>");
        }
        sb.AppendLine("    </tbody>");
        sb.AppendLine("  </table>");
    }

    private static string FormatParent(string parentName, int parentPid)
    {
        if (parentPid <= 0)
            return "";

        return string.IsNullOrWhiteSpace(parentName)
            ? $"PID {parentPid}"
            : $"{parentName} (PID {parentPid})";
    }

    private static string FormatDateTime(DateTime value)
        => value == default ? "" : value.ToString("yyyy-MM-dd HH:mm:ss");

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

    private static string FormatNumber(double value) => value.ToString("0.###", CultureInfo.InvariantCulture);

    private static string Html(string? value) => WebUtility.HtmlEncode(value ?? "");

    private static string HtmlAttribute(string? value)
        => Html(value)
            .Replace("\r", string.Empty, StringComparison.Ordinal)
            .Replace("\n", "&#10;", StringComparison.Ordinal);

    private static string BrushToCss(Brush? brush)
    {
        if (brush is SolidColorBrush solidColorBrush)
        {
            var color = solidColorBrush.Color;
            if (color.A == byte.MaxValue)
                return $"#{color.R:X2}{color.G:X2}{color.B:X2}";

            string alpha = (color.A / 255d).ToString("0.###", CultureInfo.InvariantCulture);
            return $"rgba({color.R}, {color.G}, {color.B}, {alpha})";
        }

        return "#000000";
    }

    private sealed record IncidentReportDocument(
        DateTime ExportedAtLocal,
        string GeneratedBy,
        string MachineName,
        IncidentSummaryDocument Summary,
        IncidentGraphDocument IncidentGraph,
        DetectionScenarioDocument[] DetectionScenarios,
        TlsDnsInsightDocument[] TlsDnsInsights,
        BehaviorDeviationDocument[] BehaviorDeviations,
        RiskReasonDocument[] RiskReasons,
        TimelineEventDocument[] Timeline,
        ConversationDocument[] Conversations,
        SessionClusterDocument[] SessionClusters);

    private sealed record IncidentSummaryDocument(
        string ProcessName,
        int Pid,
        int RiskScore,
        string RiskLabel,
        bool IsAlive,
        string LivenessLabel,
        bool IsSigned,
        string SignedLabel,
        string Publisher,
        string SignerSubject,
        string ExePath,
        int ParentPid,
        string ParentName,
        long PacketCount,
        long TotalBytes,
        string TotalBytesHuman,
        int DistinctRemoteEndpoints,
        string TopRemoteEndpoint,
        DateTime? LastSeen,
        long OutboundBytes,
        long InboundBytes,
        long OutboundPackets,
        long InboundPackets,
        string BeaconEndpoint,
        string BeaconLabel,
        string FirstSuspiciousDomain,
        string SuspiciousDomainReason,
        string DetectionSummary,
        string BaselineState,
        string BaselineSummary,
        string BaselineLearningNote,
        string BehaviorDeviationSummary,
        int LastSamplePackets,
        int PeakSamplePackets,
        double AvgSamplePackets,
        int DnsQueryCount,
        int UniqueDnsQueryCount,
        int DnsTxtQueryCount,
        int DnsEncodedQueryCount,
        int DnsLongestLabelLength,
        string DominantDnsRoot,
        int DominantDnsRootCount,
        int UniqueDomainCount,
        string LatestNewDomain,
        int RareTldScore,
        string RareTldDomain,
        string RareTld,
        int DgaLikeDomainCount,
        string TopDgaLikeDomain,
        int TopDgaLikeScore,
        string PrimaryJa3Lite,
        int PrimaryJa3LiteCount,
        string PrimaryJa4Lite,
        int PrimaryJa4LiteCount,
        int SniCertificateMismatchCount,
        string LastSniCertificateMismatch,
        string MostReusedCertificateFingerprint,
        int MostReusedCertificateDomainCount,
        string MostReusedCertificateDomainsSummary,
        string DetailsName,
        string DetailsExePath,
        string DetailsPublisher,
        bool DetailsIsSigned);

    private sealed record DetectionScenarioDocument(
        string Title,
        string MitreTechnique,
        string MitreTactic,
        string Summary,
        int Confidence,
        string ConfidenceLabel,
        int RiskPoints,
        string[] Evidence);

    private sealed record TlsDnsInsightDocument(
        string Title,
        string Summary,
        int Score,
        string ScoreLabel,
        string SeverityLabel,
        string[] Evidence);

    private sealed record BehaviorDeviationDocument(
        string Title,
        string Summary,
        int Score,
        string ScoreLabel,
        string SeverityLabel,
        string[] Evidence);

    private sealed record RiskReasonDocument(string Summary, int Points);

    private sealed record IncidentGraphDocument(
        bool HasGraph,
        string SummaryLabel,
        string EmptyState,
        double CanvasWidth,
        double CanvasHeight,
        IncidentGraphLaneDocument[] Lanes,
        IncidentGraphNodeDocument[] Nodes,
        IncidentGraphEdgeDocument[] Edges);

    private sealed record IncidentGraphLaneDocument(string Label);

    private sealed record IncidentGraphNodeDocument(
        string KindLabel,
        string Title,
        string Subtitle,
        string MetricLabel,
        string Tooltip,
        string BadgeText,
        double Left,
        double Top,
        double Width,
        double Height,
        string BackgroundColor,
        string BorderColor,
        string AccentColor,
        string SecondaryColor,
        string BadgeBackgroundColor,
        string BadgeBorderColor,
        string BadgeForegroundColor,
        bool HasBadge);

    private sealed record IncidentGraphEdgeDocument(
        string PathData,
        string Tooltip,
        string StrokeColor,
        string StrokeDashArray,
        double Thickness,
        double Opacity);

    private sealed record TimelineEventDocument(DateTime Timestamp, string Title, string Detail);

    private sealed record ConversationDocument(
        string Protocol,
        string RemoteHost,
        string RemoteEndpoint,
        long PacketCount,
        long TotalBytes,
        string BytesLabel,
        string DirectionLabel,
        DateTime FirstSeen,
        DateTime LastSeen);

    private sealed record SessionClusterDocument(
        string Title,
        string WindowLabel,
        string DurationLabel,
        long PacketCount,
        long TotalBytes,
        string BytesLabel,
        int DistinctRemoteEndpoints,
        string RemoteSummaryLabel,
        string DirectionLabel);
}
