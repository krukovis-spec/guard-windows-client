using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text;

namespace Guard.Protocol.WebProxy
{
    /// <summary>
    /// Strict, header-only parser for a future local explicit proxy. This class
    /// never opens a socket, resolves DNS, decrypts TLS, or authorizes a host.
    /// Its output is only an observed, normalized request target.
    /// </summary>
    public static class WebProxyRequestParser
    {
        private static readonly Encoding Ascii = Encoding.GetEncoding(
            "us-ascii",
            new EncoderExceptionFallback(),
            new DecoderExceptionFallback());

        public static ObservedWebProxyRequest ParseHeaderFrame(byte[] frame)
        {
            if (frame == null)
            {
                throw new ArgumentNullException(nameof(frame));
            }

            if (frame.Length == 0 ||
                frame.Length > WebProxyProtocolLimits.MaximumHeaderFrameBytes)
            {
                throw Invalid("The proxy header frame is empty or oversized.");
            }

            var snapshot = (byte[])frame.Clone();
            var headerEnd = FindHeaderEnd(snapshot);
            if (headerEnd < 0 || headerEnd != snapshot.Length)
            {
                throw Invalid("The proxy header frame must contain exactly one complete header section.");
            }

            string text;
            try
            {
                text = Ascii.GetString(snapshot);
            }
            catch (DecoderFallbackException exception)
            {
                throw new InvalidDataException("The proxy header frame is not strict ASCII.", exception);
            }

            var lines = text.Split(new[] { "\r\n" }, StringSplitOptions.None);
            if (lines.Length < 4 || lines[lines.Length - 1].Length != 0 ||
                lines[lines.Length - 2].Length != 0 ||
                lines.Length - 3 > WebProxyProtocolLimits.MaximumHeaderCount)
            {
                throw Invalid("The proxy header frame has an invalid line count.");
            }

            var requestLine = lines[0];
            if (requestLine.Length == 0 || requestLine.Length > WebProxyProtocolLimits.MaximumRequestLineCharacters)
            {
                throw Invalid("The proxy request line is empty or oversized.");
            }

            var requestParts = requestLine.Split(' ');
            if (requestParts.Length != 3 ||
                requestParts[0].Length == 0 || requestParts[1].Length == 0 ||
                !string.Equals(requestParts[2], "HTTP/1.1", StringComparison.Ordinal))
            {
                throw Invalid("Only an unambiguous HTTP/1.1 request line is accepted.");
            }

            var method = ValidateMethod(requestParts[0]);
            var headers = ParseHeaders(lines);
            RejectUnsupportedFraming(headers);

            var isConnect = string.Equals(method, "CONNECT", StringComparison.Ordinal);
            Authority target;
            if (isConnect)
            {
                target = ParseAuthority(requestParts[1], requirePort: true);
                if (target.Port != 443)
                {
                    throw Invalid("CONNECT is restricted to the default HTTPS port.");
                }
            }
            else
            {
                target = ParseAbsoluteHttpTarget(requestParts[1]);
            }

            var targetPort = target.Port;
            if (targetPort == null)
            {
                throw Invalid("The proxy request target has no resolved port.");
            }

            var hostHeader = GetRequiredSingleHeader(headers, "host");
            var declared = ParseAuthority(hostHeader, requirePort: false);
            if (declared.Port == null)
            {
                declared = new Authority(declared.Host, targetPort);
            }

            if (!string.Equals(declared.Host, target.Host, StringComparison.Ordinal) ||
                declared.Port != targetPort)
            {
                throw Invalid("The Host header does not match the request target.");
            }

            var isWebSocketUpgrade = !isConnect &&
                HeaderHasToken(headers, "connection", "upgrade") &&
                string.Equals(GetOptionalSingleHeader(headers, "upgrade"), "websocket", StringComparison.OrdinalIgnoreCase);

            return new ObservedWebProxyRequest(
                method,
                target.Host,
                targetPort.Value,
                isConnect,
                isWebSocketUpgrade);
        }

        private static int FindHeaderEnd(byte[] bytes)
        {
            for (var index = 0; index <= bytes.Length - 4; index++)
            {
                if (bytes[index] == '\r' && bytes[index + 1] == '\n' &&
                    bytes[index + 2] == '\r' && bytes[index + 3] == '\n')
                {
                    return index + 4;
                }
            }

            return -1;
        }

        private static Dictionary<string, List<string>> ParseHeaders(string[] lines)
        {
            var headers = new Dictionary<string, List<string>>(StringComparer.Ordinal);
            for (var index = 1; index < lines.Length - 2; index++)
            {
                var line = lines[index];
                if (line.Length == 0 || line.Length > WebProxyProtocolLimits.MaximumHeaderLineCharacters ||
                    line[0] == ' ' || line[0] == '\t')
                {
                    throw Invalid("Empty, oversized, or folded proxy headers are not accepted.");
                }

                var colon = line.IndexOf(':');
                if (colon <= 0 || colon == line.Length - 1)
                {
                    throw Invalid("The proxy header syntax is invalid.");
                }

                var name = line.Substring(0, colon);
                var value = line.Substring(colon + 1);
                if (!IsHeaderName(name))
                {
                    throw Invalid("The proxy header name is invalid.");
                }

                value = NormalizeHeaderValue(value);
                var key = name.ToLowerInvariant();
                List<string> values;
                if (!headers.TryGetValue(key, out values))
                {
                    values = new List<string>();
                    headers.Add(key, values);
                }

                values.Add(value);
            }

            return headers;
        }

        private static void RejectUnsupportedFraming(Dictionary<string, List<string>> headers)
        {
            List<string> values;
            if (headers.TryGetValue("transfer-encoding", out values))
            {
                throw Invalid("Transfer-Encoding is not accepted by the header-only proxy parser.");
            }

            if (headers.TryGetValue("content-length", out values))
            {
                if (values.Count != 1 || !string.Equals(values[0], "0", StringComparison.Ordinal))
                {
                    throw Invalid("Only a single Content-Length: 0 is accepted by the header-only proxy parser.");
                }
            }
        }

        private static string ValidateMethod(string method)
        {
            if (method.Length > WebProxyProtocolLimits.MaximumMethodCharacters)
            {
                throw Invalid("The proxy method is oversized.");
            }

            for (var index = 0; index < method.Length; index++)
            {
                var character = method[index];
                if (character < 'A' || character > 'Z')
                {
                    throw Invalid("The proxy method must be uppercase ASCII letters.");
                }
            }

            return method;
        }

        private static Authority ParseAbsoluteHttpTarget(string target)
        {
            if (!target.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
            {
                throw Invalid("Only absolute-form http targets are accepted.");
            }

            var authorityStart = "http://".Length;
            var pathStart = target.IndexOf('/', authorityStart);
            var authority = pathStart < 0 ? target.Substring(authorityStart) : target.Substring(authorityStart, pathStart - authorityStart);
            var path = pathStart < 0 ? string.Empty : target.Substring(pathStart);
            if (authority.Length == 0 || target.IndexOf('#', authorityStart) >= 0 || path.IndexOf('#') >= 0 ||
                ContainsUnsafeWhitespace(target) || ContainsInvalidPercentEscape(target))
            {
                throw Invalid("The absolute-form target is ambiguous or malformed.");
            }

            var parsed = ParseAuthority(authority, requirePort: false);
            if (parsed.Port != null && parsed.Port != 80)
            {
                throw Invalid("Absolute HTTP targets are restricted to the default HTTP port.");
            }

            return new Authority(parsed.Host, parsed.Port ?? 80);
        }

        private static Authority ParseAuthority(string authority, bool requirePort)
        {
            if (authority.Length == 0 || authority.Length > WebProxyProtocolLimits.MaximumAuthorityCharacters ||
                authority.IndexOf('@') >= 0 || authority.IndexOf('[') >= 0 || authority.IndexOf(']') >= 0 ||
                authority.IndexOf('%') >= 0 || authority.IndexOf('/') >= 0 || authority.IndexOf('?') >= 0 ||
                authority.IndexOf('#') >= 0 || ContainsUnsafeWhitespace(authority))
            {
                throw Invalid("The proxy authority is malformed.");
            }

            var colon = authority.LastIndexOf(':');
            string host;
            int? port = null;
            if (colon >= 0)
            {
                if (authority.IndexOf(':') != colon || colon == 0 || colon == authority.Length - 1)
                {
                    throw Invalid("The proxy authority port is malformed.");
                }

                host = authority.Substring(0, colon);
                var portText = authority.Substring(colon + 1);
                int parsedPort;
                if (!int.TryParse(portText, NumberStyles.None, CultureInfo.InvariantCulture, out parsedPort) ||
                    parsedPort < 1 || parsedPort > 65535)
                {
                    throw Invalid("The proxy authority port is unsupported.");
                }

                port = parsedPort;
            }
            else
            {
                host = authority;
            }

            if (requirePort && port == null)
            {
                throw Invalid("CONNECT requires an explicit destination port.");
            }

            return new Authority(NormalizeDnsHost(host), port);
        }

        private static string NormalizeDnsHost(string host)
        {
            if (host.Length == 0 || host.Length > WebProxyProtocolLimits.MaximumHostCharacters + 1 ||
                IPAddress.TryParse(host, out _) || host.IndexOf("..", StringComparison.Ordinal) >= 0)
            {
                throw Invalid("The proxy host must be a DNS name, not an IP literal.");
            }

            var normalized = host.EndsWith(".", StringComparison.Ordinal)
                ? host.Substring(0, host.Length - 1)
                : host;
            if (normalized.Length == 0 ||
                normalized.Length > WebProxyProtocolLimits.MaximumHostCharacters ||
                normalized.EndsWith(".", StringComparison.Ordinal) ||
                IPAddress.TryParse(normalized, out _))
            {
                throw Invalid("The proxy DNS name is invalid.");
            }

            var labels = normalized.Split('.');
            foreach (var label in labels)
            {
                if (label.Length == 0 || label.Length > 63 || label[0] == '-' || label[label.Length - 1] == '-')
                {
                    throw Invalid("The proxy DNS label is invalid.");
                }

                for (var index = 0; index < label.Length; index++)
                {
                    var character = label[index];
                    if (!((character >= 'a' && character <= 'z') ||
                          (character >= 'A' && character <= 'Z') ||
                          (character >= '0' && character <= '9') || character == '-'))
                    {
                        throw Invalid("The proxy DNS name must be ASCII LDH notation.");
                    }
                }
            }

            return normalized.ToLowerInvariant();
        }

        private static string GetRequiredSingleHeader(Dictionary<string, List<string>> headers, string name)
        {
            var value = GetOptionalSingleHeader(headers, name);
            if (value == null)
            {
                throw Invalid("The required Host header is missing or duplicated.");
            }

            return value;
        }

        private static string? GetOptionalSingleHeader(Dictionary<string, List<string>> headers, string name)
        {
            List<string> values;
            if (!headers.TryGetValue(name, out values))
            {
                return null;
            }

            if (values.Count != 1)
            {
                throw Invalid("A singleton proxy header was duplicated.");
            }

            return values[0];
        }

        private static bool HeaderHasToken(Dictionary<string, List<string>> headers, string name, string expected)
        {
            var value = GetOptionalSingleHeader(headers, name);
            if (value == null)
            {
                return false;
            }

            var tokens = value.Split(',');
            foreach (var token in tokens)
            {
                var normalized = token.Trim(' ', '\t');
                if (normalized.Length == 0 ||
                    !string.Equals(normalized, expected, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                return true;
            }

            return false;
        }

        private static bool IsHeaderName(string value)
        {
            for (var index = 0; index < value.Length; index++)
            {
                var character = value[index];
                if (!((character >= 'A' && character <= 'Z') ||
                      (character >= 'a' && character <= 'z') ||
                      (character >= '0' && character <= '9') || character == '-'))
                {
                    return false;
                }
            }

            return true;
        }

        private static bool ContainsUnsafeWhitespace(string value)
        {
            for (var index = 0; index < value.Length; index++)
            {
                var character = value[index];
                if (character < 0x21 || character == 0x7f)
                {
                    return true;
                }
            }

            return false;
        }

        private static string NormalizeHeaderValue(string value)
        {
            if (value == null)
            {
                throw Invalid("The proxy header value is missing.");
            }

            var start = 0;
            while (start < value.Length &&
                   (value[start] == ' ' || value[start] == '\t'))
            {
                start++;
            }

            var end = value.Length;
            while (end > start &&
                   (value[end - 1] == ' ' || value[end - 1] == '\t'))
            {
                end--;
            }

            if (start == end)
            {
                throw Invalid("The proxy header value is empty.");
            }

            for (var index = start; index < end; index++)
            {
                var character = value[index];
                if ((character < 0x20 && character != '\t') ||
                    character == 0x7f)
                {
                    throw Invalid("The proxy header value contains a control character.");
                }
            }

            return value.Substring(start, end - start);
        }

        private static bool ContainsInvalidPercentEscape(string value)
        {
            for (var index = 0; index < value.Length; index++)
            {
                if (value[index] == '%' &&
                    (index + 2 >= value.Length || !IsHex(value[index + 1]) || !IsHex(value[index + 2])))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool IsHex(char character)
        {
            return (character >= '0' && character <= '9') ||
                   (character >= 'A' && character <= 'F') ||
                   (character >= 'a' && character <= 'f');
        }

        private static InvalidDataException Invalid(string message)
        {
            return new InvalidDataException(message);
        }

        private sealed class Authority
        {
            public Authority(string host, int? port)
            {
                Host = host;
                Port = port;
            }

            public string Host { get; }
            public int? Port { get; }
        }
    }

    public static class WebProxyProtocolLimits
    {
        public const int MaximumHeaderFrameBytes = 16384;
        public const int MaximumRequestLineCharacters = 4096;
        public const int MaximumHeaderLineCharacters = 4096;
        public const int MaximumHeaderCount = 64;
        public const int MaximumMethodCharacters = 16;
        public const int MaximumAuthorityCharacters = 320;
        public const int MaximumHostCharacters = 253;
    }

    public sealed class ObservedWebProxyRequest
    {
        internal ObservedWebProxyRequest(string method, string host, int port, bool isConnect, bool isWebSocketUpgrade)
        {
            Method = method;
            Host = host;
            Port = port;
            IsConnect = isConnect;
            IsWebSocketUpgrade = isWebSocketUpgrade;
        }

        public string Method { get; }
        public string Host { get; }
        public int Port { get; }
        public bool IsConnect { get; }
        public bool IsWebSocketUpgrade { get; }

        // Observations are untrusted input and must never be used as authorization by themselves.
        public bool IsAuthorizationEvidence => false;
    }
}
