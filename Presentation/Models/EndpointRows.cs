using Presentation.ViewModels;
using System;
using System.Collections.Generic;

namespace Presentation.Models;

public sealed class EndpointDetailRow
{
    public string Title { get; init; } = "";
    public string Subtitle { get; init; } = "";
    public string BadgeText { get; init; } = "";
}

internal sealed class EndpointHostSnapshot
{
    public required string DisplayHost { get; init; }
    public required string Hostname { get; init; }
    public required string Country { get; init; }
    public required string Asn { get; init; }
    public required string Scope { get; init; }
    public required bool IsLocalPrivate { get; init; }
    public required bool IsMulticastBroadcast { get; init; }
    public required long Packets { get; init; }
    public required long Bytes { get; init; }
    public required long SentBytes { get; init; }
    public required long RecvBytes { get; init; }
    public required DateTime FirstSeen { get; init; }
    public required DateTime LastSeen { get; init; }
    public required int ProcessCount { get; init; }
    public required int ResolutionHintCount { get; init; }
    public required int DnsHistoryCount { get; init; }
    public required int TlsHistoryCount { get; init; }
    public required int CertificateHistoryCount { get; init; }
    public required string PacketsLabel { get; init; }
    public required string BytesLabel { get; init; }
    public required string SentRecvLabel { get; init; }
    public required string FirstSeenLabel { get; init; }
    public required string LastSeenLabel { get; init; }
    public required string ProcessesSummary { get; init; }
    public required string DnsSummary { get; init; }
    public required string TlsSummary { get; init; }
    public required string PortSummary { get; init; }
    public required string ProtocolSummary { get; init; }
    public required string HostnameSourceSummary { get; init; }
    public required string SearchText { get; init; }
    public IReadOnlyList<EndpointDetailRow> ResolutionHints { get; init; } = Array.Empty<EndpointDetailRow>();
    public IReadOnlyList<EndpointDetailRow> OwningProcesses { get; init; } = Array.Empty<EndpointDetailRow>();
    public IReadOnlyList<EndpointDetailRow> DnsHistory { get; init; } = Array.Empty<EndpointDetailRow>();
    public IReadOnlyList<EndpointDetailRow> TlsHistory { get; init; } = Array.Empty<EndpointDetailRow>();
    public IReadOnlyList<EndpointDetailRow> CertificateHistory { get; init; } = Array.Empty<EndpointDetailRow>();
}

public sealed class EndpointHostRow : ViewModelBase
{
    public EndpointHostRow(string ip)
    {
        Ip = ip;
    }

    public string Ip { get; }

    private string _displayHost = "";
    public string DisplayHost
    {
        get => _displayHost;
        private set => Set(ref _displayHost, value);
    }

    private string _hostname = "";
    public string Hostname
    {
        get => _hostname;
        private set
        {
            if (!Set(ref _hostname, value))
                return;

            OnPropertyChanged(nameof(HasHostname));
        }
    }

    public bool HasHostname => !string.IsNullOrWhiteSpace(Hostname);

    private string _country = "";
    public string Country
    {
        get => _country;
        private set => Set(ref _country, value);
    }

    private string _asn = "";
    public string Asn
    {
        get => _asn;
        private set => Set(ref _asn, value);
    }

    private string _scope = "";
    public string Scope
    {
        get => _scope;
        private set => Set(ref _scope, value);
    }

    private bool _isLocalPrivate;
    public bool IsLocalPrivate
    {
        get => _isLocalPrivate;
        private set => Set(ref _isLocalPrivate, value);
    }

    private bool _isMulticastBroadcast;
    public bool IsMulticastBroadcast
    {
        get => _isMulticastBroadcast;
        private set => Set(ref _isMulticastBroadcast, value);
    }

    private long _packets;
    public long Packets
    {
        get => _packets;
        private set => Set(ref _packets, value);
    }

    private long _bytes;
    public long Bytes
    {
        get => _bytes;
        private set => Set(ref _bytes, value);
    }

    private long _sentBytes;
    public long SentBytes
    {
        get => _sentBytes;
        private set => Set(ref _sentBytes, value);
    }

    private long _recvBytes;
    public long RecvBytes
    {
        get => _recvBytes;
        private set => Set(ref _recvBytes, value);
    }

    private DateTime _firstSeen;
    public DateTime FirstSeen
    {
        get => _firstSeen;
        private set => Set(ref _firstSeen, value);
    }

    private DateTime _lastSeen;
    public DateTime LastSeen
    {
        get => _lastSeen;
        private set => Set(ref _lastSeen, value);
    }

    private int _processCount;
    public int ProcessCount
    {
        get => _processCount;
        private set => Set(ref _processCount, value);
    }

    private int _resolutionHintCount;
    public int ResolutionHintCount
    {
        get => _resolutionHintCount;
        private set => Set(ref _resolutionHintCount, value);
    }

    private int _dnsHistoryCount;
    public int DnsHistoryCount
    {
        get => _dnsHistoryCount;
        private set => Set(ref _dnsHistoryCount, value);
    }

    private int _tlsHistoryCount;
    public int TlsHistoryCount
    {
        get => _tlsHistoryCount;
        private set => Set(ref _tlsHistoryCount, value);
    }

    private int _certificateHistoryCount;
    public int CertificateHistoryCount
    {
        get => _certificateHistoryCount;
        private set => Set(ref _certificateHistoryCount, value);
    }

    private string _packetsLabel = "";
    public string PacketsLabel
    {
        get => _packetsLabel;
        private set => Set(ref _packetsLabel, value);
    }

    private string _bytesLabel = "";
    public string BytesLabel
    {
        get => _bytesLabel;
        private set => Set(ref _bytesLabel, value);
    }

    private string _sentRecvLabel = "";
    public string SentRecvLabel
    {
        get => _sentRecvLabel;
        private set => Set(ref _sentRecvLabel, value);
    }

    private string _firstSeenLabel = "";
    public string FirstSeenLabel
    {
        get => _firstSeenLabel;
        private set => Set(ref _firstSeenLabel, value);
    }

    private string _lastSeenLabel = "";
    public string LastSeenLabel
    {
        get => _lastSeenLabel;
        private set => Set(ref _lastSeenLabel, value);
    }

    private string _processesSummary = "";
    public string ProcessesSummary
    {
        get => _processesSummary;
        private set => Set(ref _processesSummary, value);
    }

    private string _dnsSummary = "";
    public string DnsSummary
    {
        get => _dnsSummary;
        private set => Set(ref _dnsSummary, value);
    }

    private string _tlsSummary = "";
    public string TlsSummary
    {
        get => _tlsSummary;
        private set => Set(ref _tlsSummary, value);
    }

    private string _portSummary = "";
    public string PortSummary
    {
        get => _portSummary;
        private set => Set(ref _portSummary, value);
    }

    private string _protocolSummary = "";
    public string ProtocolSummary
    {
        get => _protocolSummary;
        private set => Set(ref _protocolSummary, value);
    }

    private string _hostnameSourceSummary = "";
    public string HostnameSourceSummary
    {
        get => _hostnameSourceSummary;
        private set => Set(ref _hostnameSourceSummary, value);
    }

    private string _searchText = "";
    public string SearchText
    {
        get => _searchText;
        private set => Set(ref _searchText, value);
    }

    private IReadOnlyList<EndpointDetailRow> _resolutionHints = Array.Empty<EndpointDetailRow>();
    public IReadOnlyList<EndpointDetailRow> ResolutionHints
    {
        get => _resolutionHints;
        private set
        {
            if (!Set(ref _resolutionHints, value))
                return;

            OnPropertyChanged(nameof(HasResolutionHints));
        }
    }

    public bool HasResolutionHints => ResolutionHints.Count > 0;

    private IReadOnlyList<EndpointDetailRow> _owningProcesses = Array.Empty<EndpointDetailRow>();
    public IReadOnlyList<EndpointDetailRow> OwningProcesses
    {
        get => _owningProcesses;
        private set
        {
            if (!Set(ref _owningProcesses, value))
                return;

            OnPropertyChanged(nameof(HasOwningProcesses));
        }
    }

    public bool HasOwningProcesses => OwningProcesses.Count > 0;

    private IReadOnlyList<EndpointDetailRow> _dnsHistory = Array.Empty<EndpointDetailRow>();
    public IReadOnlyList<EndpointDetailRow> DnsHistory
    {
        get => _dnsHistory;
        private set
        {
            if (!Set(ref _dnsHistory, value))
                return;

            OnPropertyChanged(nameof(HasDnsHistory));
        }
    }

    public bool HasDnsHistory => DnsHistory.Count > 0;

    private IReadOnlyList<EndpointDetailRow> _tlsHistory = Array.Empty<EndpointDetailRow>();
    public IReadOnlyList<EndpointDetailRow> TlsHistory
    {
        get => _tlsHistory;
        private set
        {
            if (!Set(ref _tlsHistory, value))
                return;

            OnPropertyChanged(nameof(HasTlsHistory));
        }
    }

    public bool HasTlsHistory => TlsHistory.Count > 0;

    private IReadOnlyList<EndpointDetailRow> _certificateHistory = Array.Empty<EndpointDetailRow>();
    public IReadOnlyList<EndpointDetailRow> CertificateHistory
    {
        get => _certificateHistory;
        private set
        {
            if (!Set(ref _certificateHistory, value))
                return;

            OnPropertyChanged(nameof(HasCertificateHistory));
        }
    }

    public bool HasCertificateHistory => CertificateHistory.Count > 0;

    internal void Apply(EndpointHostSnapshot snapshot)
    {
        DisplayHost = snapshot.DisplayHost;
        Hostname = snapshot.Hostname;
        Country = snapshot.Country;
        Asn = snapshot.Asn;
        Scope = snapshot.Scope;
        IsLocalPrivate = snapshot.IsLocalPrivate;
        IsMulticastBroadcast = snapshot.IsMulticastBroadcast;
        Packets = snapshot.Packets;
        Bytes = snapshot.Bytes;
        SentBytes = snapshot.SentBytes;
        RecvBytes = snapshot.RecvBytes;
        FirstSeen = snapshot.FirstSeen;
        LastSeen = snapshot.LastSeen;
        ProcessCount = snapshot.ProcessCount;
        ResolutionHintCount = snapshot.ResolutionHintCount;
        DnsHistoryCount = snapshot.DnsHistoryCount;
        TlsHistoryCount = snapshot.TlsHistoryCount;
        CertificateHistoryCount = snapshot.CertificateHistoryCount;
        PacketsLabel = snapshot.PacketsLabel;
        BytesLabel = snapshot.BytesLabel;
        SentRecvLabel = snapshot.SentRecvLabel;
        FirstSeenLabel = snapshot.FirstSeenLabel;
        LastSeenLabel = snapshot.LastSeenLabel;
        ProcessesSummary = snapshot.ProcessesSummary;
        DnsSummary = snapshot.DnsSummary;
        TlsSummary = snapshot.TlsSummary;
        PortSummary = snapshot.PortSummary;
        ProtocolSummary = snapshot.ProtocolSummary;
        HostnameSourceSummary = snapshot.HostnameSourceSummary;
        SearchText = snapshot.SearchText;
        ResolutionHints = snapshot.ResolutionHints;
        OwningProcesses = snapshot.OwningProcesses;
        DnsHistory = snapshot.DnsHistory;
        TlsHistory = snapshot.TlsHistory;
        CertificateHistory = snapshot.CertificateHistory;
    }
}
