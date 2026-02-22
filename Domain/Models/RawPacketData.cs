namespace Domain.Models;

/// <summary>
/// Raw packet payload + link-layer type for offline parsing/export without SharpPcap types.
/// </summary>
public sealed record RawPacketData(byte[] Data, int LinkLayerType);
