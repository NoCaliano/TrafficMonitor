using Domain.Models;
using Presentation.Models;
using System.Globalization;

namespace Presentation.Services;

internal sealed class PacketFilterService : IPacketFilterService
{
    public bool MatchesUiFilter(PacketInfo p, PacketFilterModel f)
    {
        static bool MatchText(string? value, TextMatchOp op, string? pattern)
        {
            if (op == TextMatchOp.Any || string.IsNullOrWhiteSpace(pattern))
                return true;

            value ??= "";
            pattern = pattern.Trim();

            return op switch
            {
                TextMatchOp.Equals => string.Equals(value, pattern, StringComparison.OrdinalIgnoreCase),
                TextMatchOp.NotEquals => !string.Equals(value, pattern, StringComparison.OrdinalIgnoreCase),
                TextMatchOp.Contains => value.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0,
                TextMatchOp.NotContains => value.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) < 0,
                _ => true
            };
        }

        static bool MatchNumber(int? value, NumberMatchOp op, int? pattern)
        {
            if (op == NumberMatchOp.Any || pattern is null)
                return true;

            return op switch
            {
                NumberMatchOp.Equals => value == pattern,
                NumberMatchOp.NotEquals => value != pattern,
                _ => true
            };
        }

        if (!MatchText(p.SrcIp, f.SrcIpOp, f.SrcIpValue)) return false;
        if (!MatchText(p.DstIp, f.DstIpOp, f.DstIpValue)) return false;

        if (f.AnyIpOp != TextMatchOp.Any && !string.IsNullOrWhiteSpace(f.AnyIpValue))
        {
            bool srcOk = MatchText(p.SrcIp, f.AnyIpOp, f.AnyIpValue);
            bool dstOk = MatchText(p.DstIp, f.AnyIpOp, f.AnyIpValue);
            if (!srcOk && !dstOk) return false;
        }

        if (!MatchNumber(p.SrcPort, f.SrcPortOp, f.SrcPortValue)) return false;
        if (!MatchNumber(p.DstPort, f.DstPortOp, f.DstPortValue)) return false;

        if (f.AnyPortOp != NumberMatchOp.Any && f.AnyPortValue.HasValue)
        {
            bool srcOk = MatchNumber(p.SrcPort, f.AnyPortOp, f.AnyPortValue);
            bool dstOk = MatchNumber(p.DstPort, f.AnyPortOp, f.AnyPortValue);
            if (!srcOk && !dstOk) return false;
        }

        if (!MatchText(p.Protocol, f.ProtocolOp, f.ProtocolValue)) return false;
        if (!MatchText(p.Info, f.InfoOp, f.InfoValue)) return false;

        if (!MatchNumber(p.Pid, f.PidOp, f.PidValue)) return false;
        if (!MatchText(p.ProcessName, f.ProcessNameOp, f.ProcessNameValue)) return false;

        if (f.MinLength.HasValue && p.Length < f.MinLength.Value) return false;
        if (f.MaxLength.HasValue && p.Length > f.MaxLength.Value) return false;

        if (f.TimeFromUtc.HasValue || f.TimeToUtc.HasValue)
        {
            var tLocal = p.Timestamp;
            DateTime? fromLocal = f.TimeFromUtc?.ToLocalTime();
            DateTime? toLocal = f.TimeToUtc?.ToLocalTime();

            if (fromLocal.HasValue && tLocal < fromLocal.Value) return false;
            if (toLocal.HasValue && tLocal > toLocal.Value) return false;
        }

        return true;
    }

    public bool TryCompileDisplayFilter(string? expression, out Func<PacketInfo, bool>? predicate, out string? error)
    {
        predicate = null;
        error = null;

        expression = expression?.Trim();
        if (string.IsNullOrWhiteSpace(expression))
            return true;

        try
        {
            var parser = new DisplayFilterParser(expression);
            var root = parser.Parse();
            predicate = root.Evaluate;
            return true;
        }
        catch (DisplayFilterParseException ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private enum TokenKind
    {
        End,
        Word,
        String,
        LParen,
        RParen,
        And,
        Or,
        Not,
        Eq,
        Ne,
        Gt,
        Gte,
        Lt,
        Lte,
        Contains
    }

    private readonly record struct Token(TokenKind Kind, string Text, int Position);

    private interface IFilterNode
    {
        bool Evaluate(PacketInfo packet);
    }

    private sealed class ProtocolNode(string protocolToken) : IFilterNode
    {
        private readonly string _protocolToken = protocolToken;

        public bool Evaluate(PacketInfo packet) => MatchesProtocolToken(packet, _protocolToken);
    }

    private sealed class NotNode(IFilterNode inner) : IFilterNode
    {
        public bool Evaluate(PacketInfo packet) => !inner.Evaluate(packet);
    }

    private sealed class BinaryNode(IFilterNode left, IFilterNode right, bool isAnd) : IFilterNode
    {
        public bool Evaluate(PacketInfo packet)
            => isAnd ? left.Evaluate(packet) && right.Evaluate(packet)
                     : left.Evaluate(packet) || right.Evaluate(packet);
    }

    private sealed class ComparisonNode : IFilterNode
    {
        private readonly string _field;
        private readonly TokenKind _op;
        private readonly string _rawValue;
        private readonly FieldValueKind _fieldKind;

        public ComparisonNode(string field, TokenKind op, string rawValue)
        {
            _field = field;
            _op = op;
            _rawValue = rawValue;
            _fieldKind = GetFieldValueKind(field);

            if (_fieldKind == FieldValueKind.Unknown)
                throw new DisplayFilterParseException($"Unsupported display filter field '{field}'.");

            if (_fieldKind == FieldValueKind.Numeric && op == TokenKind.Contains)
                throw new DisplayFilterParseException($"Operator 'contains' is not supported for '{field}'.");
        }

        public bool Evaluate(PacketInfo packet)
        {
            var normalizedField = NormalizeField(_field);

            if (_fieldKind == FieldValueKind.Numeric)
            {
                var numericValues = GetNumericValues(packet, normalizedField);
                return numericValues.Any() && EvaluateNumeric(numericValues, _op, _rawValue, _field);
            }

            if (_fieldKind == FieldValueKind.String)
            {
                var stringValues = GetStringValues(packet, normalizedField);
                return stringValues.Any() && EvaluateString(stringValues, _op, _rawValue, normalizedField);
            }

            return false;
        }
    }

    private sealed class DisplayFilterParser
    {
        private readonly string _expression;
        private readonly List<Token> _tokens;
        private int _index;

        public DisplayFilterParser(string expression)
        {
            _expression = expression;
            _tokens = Tokenize(expression);
        }

        public IFilterNode Parse()
        {
            var node = ParseOr();
            Expect(TokenKind.End, "Unexpected token after end of display filter.");
            return node;
        }

        private IFilterNode ParseOr()
        {
            var left = ParseAnd();
            while (Match(TokenKind.Or))
            {
                var right = ParseAnd();
                left = new BinaryNode(left, right, isAnd: false);
            }

            return left;
        }

        private IFilterNode ParseAnd()
        {
            var left = ParseUnary();
            while (Match(TokenKind.And))
            {
                var right = ParseUnary();
                left = new BinaryNode(left, right, isAnd: true);
            }

            return left;
        }

        private IFilterNode ParseUnary()
        {
            if (Match(TokenKind.Not))
                return new NotNode(ParseUnary());

            return ParsePrimary();
        }

        private IFilterNode ParsePrimary()
        {
            if (Match(TokenKind.LParen))
            {
                var nested = ParseOr();
                Expect(TokenKind.RParen, "Expected ')'.");
                return nested;
            }

            var identifier = ExpectAny(TokenKind.Word, TokenKind.String, "Expected protocol name or field name.");
            if (Current.Kind is TokenKind.Eq or TokenKind.Ne or TokenKind.Gt or TokenKind.Gte or TokenKind.Lt or TokenKind.Lte or TokenKind.Contains)
            {
                var op = Advance().Kind;
                var value = ExpectAny(TokenKind.Word, TokenKind.String, "Expected filter value after operator.");
                return new ComparisonNode(identifier.Text, op, value.Text);
            }

            if (identifier.Kind == TokenKind.String)
                throw new DisplayFilterParseException($"Unexpected string literal at position {identifier.Position + 1}.");

            return new ProtocolNode(identifier.Text);
        }

        private bool Match(TokenKind kind)
        {
            if (Current.Kind != kind)
                return false;

            _index++;
            return true;
        }

        private Token Expect(TokenKind kind, string message)
        {
            if (Current.Kind != kind)
                throw new DisplayFilterParseException(message);

            return Advance();
        }

        private Token ExpectAny(TokenKind first, TokenKind second, string message)
        {
            if (Current.Kind != first && Current.Kind != second)
                throw new DisplayFilterParseException(message);

            return Advance();
        }

        private Token Advance() => _tokens[_index++];

        private Token Current => _tokens[Math.Min(_index, _tokens.Count - 1)];

        private static List<Token> Tokenize(string expression)
        {
            var tokens = new List<Token>();
            int index = 0;

            while (index < expression.Length)
            {
                char ch = expression[index];
                if (char.IsWhiteSpace(ch))
                {
                    index++;
                    continue;
                }

                if (ch == '(')
                {
                    tokens.Add(new Token(TokenKind.LParen, "(", index++));
                    continue;
                }

                if (ch == ')')
                {
                    tokens.Add(new Token(TokenKind.RParen, ")", index++));
                    continue;
                }

                if (ch == '!' && Peek(expression, index + 1) == '=')
                {
                    tokens.Add(new Token(TokenKind.Ne, "!=", index));
                    index += 2;
                    continue;
                }

                if (ch == '=' && Peek(expression, index + 1) == '=')
                {
                    tokens.Add(new Token(TokenKind.Eq, "==", index));
                    index += 2;
                    continue;
                }

                if (ch == '>' && Peek(expression, index + 1) == '=')
                {
                    tokens.Add(new Token(TokenKind.Gte, ">=", index));
                    index += 2;
                    continue;
                }

                if (ch == '<' && Peek(expression, index + 1) == '=')
                {
                    tokens.Add(new Token(TokenKind.Lte, "<=", index));
                    index += 2;
                    continue;
                }

                if (ch == '>')
                {
                    tokens.Add(new Token(TokenKind.Gt, ">", index++));
                    continue;
                }

                if (ch == '<')
                {
                    tokens.Add(new Token(TokenKind.Lt, "<", index++));
                    continue;
                }

                if (ch == '!' )
                {
                    tokens.Add(new Token(TokenKind.Not, "!", index++));
                    continue;
                }

                if (ch == '&' && Peek(expression, index + 1) == '&')
                {
                    tokens.Add(new Token(TokenKind.And, "&&", index));
                    index += 2;
                    continue;
                }

                if (ch == '|' && Peek(expression, index + 1) == '|')
                {
                    tokens.Add(new Token(TokenKind.Or, "||", index));
                    index += 2;
                    continue;
                }

                if (ch is '"' or '\'')
                {
                    int start = index;
                    char quote = ch;
                    index++;
                    int valueStart = index;
                    while (index < expression.Length && expression[index] != quote)
                        index++;

                    if (index >= expression.Length)
                        throw new DisplayFilterParseException("Unterminated quoted string in display filter.");

                    string value = expression[valueStart..index];
                    index++;
                    tokens.Add(new Token(TokenKind.String, value, start));
                    continue;
                }

                int wordStart = index;
                while (index < expression.Length && !char.IsWhiteSpace(expression[index]) && !"()".Contains(expression[index]))
                {
                    if (IsTwoCharOperatorStart(expression, index) || IsSingleCharOperator(expression[index]))
                        break;

                    index++;
                }

                if (wordStart == index)
                    throw new DisplayFilterParseException($"Unexpected character '{expression[index]}' in display filter.");

                string word = expression[wordStart..index];
                var kind = word.ToLowerInvariant() switch
                {
                    "and" => TokenKind.And,
                    "or" => TokenKind.Or,
                    "not" => TokenKind.Not,
                    "contains" => TokenKind.Contains,
                    _ => TokenKind.Word
                };

                tokens.Add(new Token(kind, word, wordStart));
            }

            tokens.Add(new Token(TokenKind.End, string.Empty, expression.Length));
            return tokens;
        }

        private static bool IsSingleCharOperator(char ch) => ch is '!' or '=' or '>' or '<' or '&' or '|';

        private static bool IsTwoCharOperatorStart(string text, int index)
        {
            char current = text[index];
            char next = Peek(text, index + 1);
            return (current == '!' && next == '=')
                || (current == '=' && next == '=')
                || (current == '>' && next == '=')
                || (current == '<' && next == '=')
                || (current == '&' && next == '&')
                || (current == '|' && next == '|');
        }

        private static char Peek(string text, int index) => index >= 0 && index < text.Length ? text[index] : '\0';
    }

    private sealed class DisplayFilterParseException(string message) : Exception(message);

    private enum FieldValueKind
    {
        Unknown,
        Numeric,
        String
    }

    private static IEnumerable<long?> GetNumericValues(PacketInfo packet, string field)
        => field switch
        {
            "frame.len" or "len" => [packet.Length],
            "pid" => [packet.Pid],
            "port" => [packet.SrcPort, packet.DstPort],
            "srcport" => [packet.SrcPort],
            "dstport" => [packet.DstPort],
            "tcp.srcport" => IsTransport(packet, "tcp") ? [packet.SrcPort] : Array.Empty<long?>(),
            "tcp.dstport" => IsTransport(packet, "tcp") ? [packet.DstPort] : Array.Empty<long?>(),
            "udp.srcport" => IsTransport(packet, "udp") ? [packet.SrcPort] : Array.Empty<long?>(),
            "udp.dstport" => IsTransport(packet, "udp") ? [packet.DstPort] : Array.Empty<long?>(),
            "tcp.port" => IsTransport(packet, "tcp") ? [packet.SrcPort, packet.DstPort] : Array.Empty<long?>(),
            "udp.port" => IsTransport(packet, "udp") ? [packet.SrcPort, packet.DstPort] : Array.Empty<long?>(),
            _ => Array.Empty<long?>()
        };

    private static IEnumerable<string> GetStringValues(PacketInfo packet, string field)
        => field switch
        {
            "protocol" or "proto" => GetProtocolFields(packet),
            "transport" => GetNonEmpty(packet.TransportProtocol),
            "ip.addr" => GetNonEmpty(packet.SrcIp, packet.DstIp),
            "ip.src" => GetNonEmpty(packet.SrcIp),
            "ip.dst" => GetNonEmpty(packet.DstIp),
            "ipv4.addr" => IsProtocolFamily(packet, "ipv4") ? GetNonEmpty(packet.SrcIp, packet.DstIp) : Array.Empty<string>(),
            "ipv6.addr" => IsProtocolFamily(packet, "ipv6") ? GetNonEmpty(packet.SrcIp, packet.DstIp) : Array.Empty<string>(),
            "eth.addr" or "mac.addr" => GetNonEmpty(packet.SrcMac, packet.DstMac),
            "eth.src" or "mac.src" => GetNonEmpty(packet.SrcMac),
            "eth.dst" or "mac.dst" => GetNonEmpty(packet.DstMac),
            "process" or "process.name" => GetNonEmpty(packet.ProcessName),
            "info" => GetNonEmpty(packet.Info),
            _ => Array.Empty<string>()
        };

    private static bool EvaluateNumeric(IEnumerable<long?> values, TokenKind op, string rawValue, string field)
    {
        if (!long.TryParse(rawValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out var expected))
            throw new DisplayFilterParseException($"Field '{field}' expects a numeric value.");

        return values.Where(v => v.HasValue).Any(v => CompareNumbers(v!.Value, expected, op));
    }

    private static bool EvaluateString(IEnumerable<string> values, TokenKind op, string rawValue, string field)
    {
        string candidate = rawValue.Trim();
        if (string.IsNullOrEmpty(candidate))
            return false;

        if (field == "protocol" || field == "proto")
        {
            return op switch
            {
                TokenKind.Eq => values.Any(v => MatchesProtocolString(v, candidate)),
                TokenKind.Ne => values.All(v => !MatchesProtocolString(v, candidate)),
                TokenKind.Contains => values.Any(v => ContainsIgnoreCase(v, candidate)),
                _ => throw new DisplayFilterParseException($"Operator '{FormatOperator(op)}' is not supported for '{field}'.")
            };
        }

        return op switch
        {
            TokenKind.Eq => values.Any(v => string.Equals(v, candidate, StringComparison.OrdinalIgnoreCase)),
            TokenKind.Ne => values.All(v => !string.Equals(v, candidate, StringComparison.OrdinalIgnoreCase)),
            TokenKind.Contains => values.Any(v => ContainsIgnoreCase(v, candidate)),
            _ => throw new DisplayFilterParseException($"Operator '{FormatOperator(op)}' is not supported for '{field}'.")
        };
    }

    private static bool CompareNumbers(long actual, long expected, TokenKind op) => op switch
    {
        TokenKind.Eq => actual == expected,
        TokenKind.Ne => actual != expected,
        TokenKind.Gt => actual > expected,
        TokenKind.Gte => actual >= expected,
        TokenKind.Lt => actual < expected,
        TokenKind.Lte => actual <= expected,
        _ => throw new DisplayFilterParseException($"Operator '{FormatOperator(op)}' requires a string field.")
    };

    private static IEnumerable<string> GetProtocolFields(PacketInfo packet)
    {
        var values = new List<string>(4);
        AddIfNotEmpty(values, packet.Protocol);
        AddIfNotEmpty(values, packet.TransportProtocol);

        if (IsProtocolFamily(packet, "ipv4"))
            AddIfNotEmpty(values, "IPv4");

        if (IsProtocolFamily(packet, "ipv6"))
            AddIfNotEmpty(values, "IPv6");

        return values;
    }

    private static bool MatchesProtocolToken(PacketInfo packet, string token)
    {
        string normalized = token.Trim().ToLowerInvariant();
        if (string.IsNullOrEmpty(normalized))
            return true;

        return normalized switch
        {
            "arp" => EqualsIgnoreCase(packet.Protocol, "ARP"),
            "tcp" => IsTransport(packet, "tcp"),
            "udp" => IsTransport(packet, "udp"),
            "icmp" => StartsWithIgnoreCase(packet.Protocol, "ICMP") || StartsWithIgnoreCase(packet.TransportProtocol, "ICMP"),
            "icmpv4" => EqualsIgnoreCase(packet.Protocol, "ICMPv4") || EqualsIgnoreCase(packet.TransportProtocol, "ICMPv4"),
            "icmpv6" => EqualsIgnoreCase(packet.Protocol, "ICMPv6") || EqualsIgnoreCase(packet.TransportProtocol, "ICMPv6"),
            "ip" or "ipv4" => IsProtocolFamily(packet, "ipv4"),
            "ipv6" => IsProtocolFamily(packet, "ipv6"),
            "dns" => EqualsIgnoreCase(packet.Protocol, "DNS"),
            "http" => EqualsIgnoreCase(packet.Protocol, "HTTP"),
            "https" => StartsWithIgnoreCase(packet.Protocol, "TLS") || EqualsIgnoreCase(packet.Protocol, "SSL"),
            "tls" or "ssl" => StartsWithIgnoreCase(packet.Protocol, "TLS") || EqualsIgnoreCase(packet.Protocol, "SSL"),
            "quic" => EqualsIgnoreCase(packet.Protocol, "QUIC"),
            _ => GetProtocolFields(packet).Any(v => MatchesProtocolString(v, normalized))
        };
    }

    private static bool MatchesProtocolString(string value, string token)
    {
        string normalizedValue = value.Trim().ToLowerInvariant();
        string normalizedToken = token.Trim().ToLowerInvariant();

        if (normalizedToken is "https" or "tls")
            return normalizedValue.StartsWith("tls", StringComparison.OrdinalIgnoreCase) || normalizedValue == "ssl";

        if (normalizedToken == "icmp")
            return normalizedValue.StartsWith("icmp", StringComparison.OrdinalIgnoreCase);

        if (normalizedToken == "ip")
            return normalizedValue == "ipv4";

        return normalizedValue == normalizedToken;
    }

    private static string NormalizeField(string field) => field.Trim().ToLowerInvariant() switch
    {
        "frame.len" => "frame.len",
        "len" => "len",
        "tcp.port" => "tcp.port",
        "udp.port" => "udp.port",
        "tcp.srcport" => "tcp.srcport",
        "tcp.dstport" => "tcp.dstport",
        "udp.srcport" => "udp.srcport",
        "udp.dstport" => "udp.dstport",
        "srcport" => "srcport",
        "dstport" => "dstport",
        "port" => "port",
        "ip.addr" => "ip.addr",
        "ip.src" => "ip.src",
        "ip.dst" => "ip.dst",
        "ipv4.addr" => "ipv4.addr",
        "ipv6.addr" => "ipv6.addr",
        "eth.addr" => "eth.addr",
        "eth.src" => "eth.src",
        "eth.dst" => "eth.dst",
        "mac.addr" => "mac.addr",
        "mac.src" => "mac.src",
        "mac.dst" => "mac.dst",
        "protocol" => "protocol",
        "proto" => "proto",
        "transport" => "transport",
        "pid" => "pid",
        "process" => "process",
        "process.name" => "process.name",
        "info" => "info",
        _ => field.Trim().ToLowerInvariant()
    };

    private static FieldValueKind GetFieldValueKind(string field) => NormalizeField(field) switch
    {
        "frame.len" or "len" or "pid" or "port" or "srcport" or "dstport" or "tcp.port" or "udp.port" or "tcp.srcport" or "tcp.dstport" or "udp.srcport" or "udp.dstport" => FieldValueKind.Numeric,
        "protocol" or "proto" or "transport" or "ip.addr" or "ip.src" or "ip.dst" or "ipv4.addr" or "ipv6.addr" or "eth.addr" or "eth.src" or "eth.dst" or "mac.addr" or "mac.src" or "mac.dst" or "process" or "process.name" or "info" => FieldValueKind.String,
        _ => FieldValueKind.Unknown
    };

    private static IEnumerable<string> GetNonEmpty(params string?[] values)
        => values.Where(v => !string.IsNullOrWhiteSpace(v))!.Select(v => v!.Trim());

    private static void AddIfNotEmpty(ICollection<string> values, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
            values.Add(value.Trim());
    }

    private static bool IsTransport(PacketInfo packet, string transport)
        => string.Equals(packet.TransportProtocol, transport, StringComparison.OrdinalIgnoreCase);

    private static bool IsProtocolFamily(PacketInfo packet, string family)
        => string.Equals(packet.Protocol, family, StringComparison.OrdinalIgnoreCase)
        || string.Equals(packet.Protocol, family == "ipv4" ? "IP" : family, StringComparison.OrdinalIgnoreCase)
        || string.Equals(packet.TransportProtocol, family, StringComparison.OrdinalIgnoreCase);

    private static bool ContainsIgnoreCase(string source, string value)
        => source.IndexOf(value, StringComparison.OrdinalIgnoreCase) >= 0;

    private static bool EqualsIgnoreCase(string? left, string right)
        => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);

    private static bool StartsWithIgnoreCase(string? value, string prefix)
        => value?.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) == true;

    private static string FormatOperator(TokenKind op) => op switch
    {
        TokenKind.Eq => "==",
        TokenKind.Ne => "!=",
        TokenKind.Gt => ">",
        TokenKind.Gte => ">=",
        TokenKind.Lt => "<",
        TokenKind.Lte => "<=",
        TokenKind.Contains => "contains",
        _ => op.ToString()
    };
}
