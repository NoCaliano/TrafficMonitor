// Відповідає за ключ потоку (5-tuple) для агрегації.
namespace Domain.Models;

public readonly record struct FlowKey(
    string Protocol,
    string SrcIp,
    int? SrcPort,
    string DstIp,
    int? DstPort
);
