using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Guard.Protocol.WebProxy;

namespace Guard.WebProxyProtocol.Tests
{
    internal static class Program
    {
        private static int Main()
        {
            var tests = new List<(string Name, Action Run)>
            {
                ("parses CONNECT as an observation", ParsesConnect),
                ("parses absolute HTTP target and normalized trailing dot", ParsesAbsoluteHttpTarget),
                ("accepts ordinary safe header whitespace", ParsesOrdinaryHeaders),
                ("records WebSocket upgrade metadata only", RecordsWebSocketUpgrade),
                ("rejects IP literals and zone identifiers", RejectsIpLiterals),
                ("rejects malformed authorities and percent escapes", RejectsMalformedAuthority),
                ("rejects host ambiguity and smuggling framing", RejectsHostAndSmuggling),
                ("rejects unsafe line endings and trailing bytes", RejectsUnsafeFrames),
                ("rejects non-ASCII header bytes", RejectsNonAsciiBytes),
                ("rejects oversized inputs", RejectsOversizedInputs),
                ("does not expose authorization evidence", DoesNotExposeAuthorizationEvidence)
            };

            var failures = 0;
            foreach (var test in tests)
            {
                try { test.Run(); Console.WriteLine("PASS " + test.Name); }
                catch (Exception exception) { failures++; Console.WriteLine("FAIL " + test.Name + ": " + exception.Message); }
            }

            Console.WriteLine(failures == 0 ? "All web proxy protocol checks passed." : failures + " web proxy protocol check(s) failed.");
            return failures == 0 ? 0 : 1;
        }

        private static void ParsesConnect()
        {
            var parsed = Parse("CONNECT Example.COM.:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n");
            AssertEqual("CONNECT", parsed.Method, "CONNECT method changed.");
            AssertEqual("example.com", parsed.Host, "CONNECT host was not normalized.");
            AssertEqual(443, parsed.Port, "CONNECT port changed.");
            Assert(parsed.IsConnect, "CONNECT was not marked.");
        }

        private static void ParsesAbsoluteHttpTarget()
        {
            var parsed = Parse("GET http://Example.COM./a%20b HTTP/1.1\r\nHost: example.com\r\n\r\n");
            AssertEqual("example.com", parsed.Host, "HTTP host was not normalized.");
            AssertEqual(80, parsed.Port, "Default HTTP port changed.");
            Assert(!parsed.IsConnect, "HTTP request became CONNECT.");
        }

        private static void RecordsWebSocketUpgrade()
        {
            var parsed = Parse("GET http://chat.example.test/socket HTTP/1.1\r\nHost: chat.example.test\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\n");
            Assert(parsed.IsWebSocketUpgrade, "WebSocket upgrade metadata was not observed.");
        }

        private static void ParsesOrdinaryHeaders()
        {
            var parsed = Parse(
                "GET http://example.test/ HTTP/1.1\r\n" +
                "Host:\texample.test\t\r\n" +
                "User-Agent: Guard Browser Test\r\n" +
                "Accept: text/html, application/xhtml+xml\r\n\r\n");
            AssertEqual("example.test", parsed.Host, "Safe ordinary browser headers changed the target.");
        }

        private static void RejectsIpLiterals()
        {
            Throws(() => Parse("CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n"));
            Throws(() => Parse("CONNECT [::1]:443 HTTP/1.1\r\nHost: [::1]:443\r\n\r\n"));
            Throws(() => Parse("CONNECT [fe80::1%25eth0]:443 HTTP/1.1\r\nHost: [fe80::1%25eth0]:443\r\n\r\n"));
        }

        private static void RejectsMalformedAuthority()
        {
            Throws(() => Parse("CONNECT user@example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n"));
            Throws(() => Parse("CONNECT example.test HTTP/1.1\r\nHost: example.test\r\n\r\n"));
            Throws(() => Parse("GET https://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n"));
            Throws(() => Parse("CONNECT example.test:8443 HTTP/1.1\r\nHost: example.test:8443\r\n\r\n"));
            Throws(() => Parse("GET http://example.test:8080/ HTTP/1.1\r\nHost: example.test:8080\r\n\r\n"));
            Throws(() => Parse("GET http://example.test/%ZZ HTTP/1.1\r\nHost: example.test\r\n\r\n"));
            Throws(() => Parse("GET http://example.test/#fragment HTTP/1.1\r\nHost: example.test\r\n\r\n"));
        }

        private static void RejectsHostAndSmuggling()
        {
            Throws(() => Parse("GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\nHost: other.test\r\n\r\n"));
            Throws(() => Parse("GET http://example.test/ HTTP/1.1\r\nHost: other.test\r\n\r\n"));
            Throws(() => Parse("GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n"));
            Throws(() => Parse("GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\nContent-Length: 1\r\n\r\nx"));
            Throws(() => Parse("GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n"));
        }

        private static void RejectsUnsafeFrames()
        {
            Throws(() => Parse("GET http://example.test/ HTTP/1.1\nHost: example.test\n\n"));
            Throws(() => Parse("GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n X-Folded: bad\r\n\r\n"));
            Throws(() => Parse("GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\nGET / HTTP/1.1"));
        }

        private static void RejectsNonAsciiBytes()
        {
            var frame = Encoding.ASCII.GetBytes("GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\nX-Test: x\r\n\r\n");
            frame[frame.Length - 7] = 0xff;
            Throws(() => WebProxyRequestParser.ParseHeaderFrame(frame));
        }

        private static void RejectsOversizedInputs()
        {
            var oversized = new byte[WebProxyProtocolLimits.MaximumHeaderFrameBytes + 1];
            Throws(() => WebProxyRequestParser.ParseHeaderFrame(oversized));
            var longHost = new string('a', WebProxyProtocolLimits.MaximumHostCharacters + 1);
            Throws(() => Parse("CONNECT " + longHost + ".test:443 HTTP/1.1\r\nHost: " + longHost + ".test:443\r\n\r\n"));
        }

        private static void DoesNotExposeAuthorizationEvidence()
        {
            var parsed = Parse("GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n");
            Assert(!parsed.IsAuthorizationEvidence, "A parsed proxy target became authorization evidence.");
        }

        private static ObservedWebProxyRequest Parse(string text)
        {
            return WebProxyRequestParser.ParseHeaderFrame(Encoding.ASCII.GetBytes(text));
        }

        private static void Throws(Action action)
        {
            try { action(); }
            catch (InvalidDataException) { return; }
            throw new InvalidOperationException("Malformed frame was accepted.");
        }

        private static void Assert(bool condition, string message)
        {
            if (!condition) { throw new InvalidOperationException(message); }
        }

        private static void AssertEqual<T>(T expected, T actual, string message)
        {
            if (!EqualityComparer<T>.Default.Equals(expected, actual)) { throw new InvalidOperationException(message); }
        }
    }
}
