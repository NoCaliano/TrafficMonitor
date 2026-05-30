using System;
using System.Collections.Generic;
using System.Windows.Media;

namespace Presentation.Models;

public sealed record ProcessIncidentGraphDomainObservation(
    string Domain,
    int ObservationCount,
    int DnsHits,
    int SniHits,
    long TotalBytes,
    DateTime FirstSeen,
    DateTime LastSeen,
    IReadOnlyList<string> LinkedIps);

public sealed record ProcessIncidentGraphIpObservation(
    string Ip,
    string ResolvedHost,
    long PacketCount,
    long TotalBytes,
    DateTime FirstSeen,
    DateTime LastSeen,
    IReadOnlyList<string> LinkedDomains,
    IReadOnlyList<string> CertificateFingerprints,
    IReadOnlyList<ProcessIncidentGraphResolutionHint> ResolutionHints);

public sealed record ProcessIncidentGraphResolutionHint(
    string Host,
    string SourceLabel,
    int ConfidenceScore,
    string ConfidenceLabel,
    string SummaryLabel);

public sealed record ProcessIncidentGraphCertificateObservation(
    string Fingerprint,
    string Subject,
    IReadOnlyList<string> Names,
    long ObservationCount,
    DateTime FirstSeen,
    DateTime LastSeen,
    IReadOnlyList<string> LinkedIps,
    IReadOnlyList<string> LinkedDomains);

public sealed record ProcessIncidentGraphDomainIpLink(
    string Domain,
    string Ip,
    int HitCount);

public sealed record ProcessIncidentGraphIpCertificateLink(
    string Ip,
    string CertificateFingerprint,
    int HitCount);

public sealed record ProcessIncidentGraphSnapshot(
    IReadOnlyList<ProcessIncidentGraphDomainObservation> Domains,
    IReadOnlyList<ProcessIncidentGraphIpObservation> Ips,
    IReadOnlyList<ProcessIncidentGraphCertificateObservation> Certificates,
    IReadOnlyList<ProcessIncidentGraphDomainIpLink> DomainIpLinks,
    IReadOnlyList<ProcessIncidentGraphIpCertificateLink> IpCertificateLinks)
{
    public static ProcessIncidentGraphSnapshot Empty { get; } = new(
        Array.Empty<ProcessIncidentGraphDomainObservation>(),
        Array.Empty<ProcessIncidentGraphIpObservation>(),
        Array.Empty<ProcessIncidentGraphCertificateObservation>(),
        Array.Empty<ProcessIncidentGraphDomainIpLink>(),
        Array.Empty<ProcessIncidentGraphIpCertificateLink>());
}

public sealed class ProcessIncidentGraph
{
    public static ProcessIncidentGraph Empty { get; } = new();

    public IReadOnlyList<ProcessIncidentGraphLane> Lanes { get; init; } = Array.Empty<ProcessIncidentGraphLane>();
    public IReadOnlyList<ProcessIncidentGraphNode> Nodes { get; init; } = Array.Empty<ProcessIncidentGraphNode>();
    public IReadOnlyList<ProcessIncidentGraphEdge> Edges { get; init; } = Array.Empty<ProcessIncidentGraphEdge>();
    public double CanvasWidth { get; init; }
    public double CanvasHeight { get; init; }
    public string SummaryLabel { get; init; } = "";
    public string EmptyState { get; init; } = "Graph telemetry is not available for this process yet.";

    public bool HasGraph => Nodes.Count > 1;
}

public sealed record ProcessIncidentGraphLane(
    string Label,
    double Width);

public sealed class ProcessIncidentGraphNode
{
    public string Id { get; init; } = "";
    public string KindLabel { get; init; } = "";
    public string Title { get; init; } = "";
    public string Subtitle { get; init; } = "";
    public string MetricLabel { get; init; } = "";
    public string Tooltip { get; init; } = "";
    public string BadgeText { get; init; } = "";
    public double Left { get; init; }
    public double Top { get; init; }
    public double Width { get; init; } = 176;
    public double Height { get; init; } = 88;
    public Brush BackgroundBrush { get; init; } = Brushes.White;
    public Brush BorderBrush { get; init; } = Brushes.SteelBlue;
    public Brush AccentBrush { get; init; } = Brushes.SteelBlue;
    public Brush SecondaryBrush { get; init; } = Brushes.DimGray;
    public Brush BadgeBackgroundBrush { get; init; } = Brushes.Transparent;
    public Brush BadgeBorderBrush { get; init; } = Brushes.Transparent;
    public Brush BadgeForegroundBrush { get; init; } = Brushes.DimGray;
    public int LaneIndex { get; init; }
    public bool HasSubtitle => !string.IsNullOrWhiteSpace(Subtitle);
    public bool HasBadge => !string.IsNullOrWhiteSpace(BadgeText);

    public double CenterX => Left + (Width / 2.0);
    public double CenterY => Top + (Height / 2.0);
    public double RightX => Left + Width;
    public double LeftX => Left;
}

public sealed class ProcessIncidentGraphEdge
{
    public string SourceId { get; init; } = "";
    public string TargetId { get; init; } = "";
    public string Tooltip { get; init; } = "";
    public Geometry Geometry { get; init; } = Geometry.Empty;
    public Brush Stroke { get; init; } = Brushes.LightSlateGray;
    public DoubleCollection? StrokeDashArray { get; init; }
    public double Thickness { get; init; } = 1.8;
    public double Opacity { get; init; } = 0.9;
}
