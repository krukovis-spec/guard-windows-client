using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Guard.Windows.Cryptography;

namespace Guard.Windows.Crypto.Tests;

internal static class GoogleAttestationSourceChecks
{
    public static void Run() => CheckAsync().GetAwaiter().GetResult();
    private static async Task CheckAsync()
    {
        var roots = GoogleAndroidAttestationSource.LoadRoots();
        Check(roots.Length == 2, "root count");
        using (var root = X509CertificateLoader.LoadCertificate(roots[0]))
            Check(root.GetRSAPublicKey()?.KeySize == 4096, "Google RSA root");
        using (var root = X509CertificateLoader.LoadCertificate(roots[1]))
            Check(root.GetECDsaPublicKey()?.KeySize == 384, "Google rotated EC root");
        roots[0][0] ^= 1;
        Check(GoogleAndroidAttestationSource.LoadRoots()[0][0] != roots[0][0], "mutable trusted roots");
        var clock = new Clock(); var handler = new Handler(() => Response(clock));
        using (var source = new GoogleAndroidAttestationSource(handler, clock, TimeSpan.FromSeconds(2)))
        {
            var first = await source.GetCurrentStatusAsync(default);
            Check(first.Contains("000a") && !first.Contains("b"), "status parser binding");
            Check(ReferenceEquals(first, await source.GetCurrentStatusAsync(default)) && handler.Calls == 1, "fresh cache");
            clock.Advance(TimeSpan.FromSeconds(59));
            Check(ReferenceEquals(first, await source.GetCurrentStatusAsync(default)), "cache ended too early");
            clock.Advance(TimeSpan.FromSeconds(1));
            Check(!ReferenceEquals(first, await source.GetCurrentStatusAsync(default)) && handler.Calls == 2, "cache deadline");
            using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
            await Reject<OperationCanceledException>(() => source.GetCurrentStatusAsync(cancelled.Token));
            Check(handler.Calls == 2, "cancelled cache access sent HTTP");
            using var synthetic = new AndroidAttestationChecks.Fixture();
            var verifier = source.CreateVerifier(AndroidAttestationChecks.ApkSigner, 1);
            var challenge = SHA256.HashData("Google source test challenge"u8); var claimHash = SHA256.HashData("Google source test claim"u8);
            var chain = synthetic.Chain(AndroidAttestationChecks.Description(challenge: challenge)); var signature = synthetic.Sign(claimHash);
            var current = await source.GetCurrentStatusAsync(default);
            Check(synthetic.Verifier.Verify(synthetic.Anchor, chain, challenge, claimHash, signature, current, clock.Now), "synthetic control chain must be valid");
            Check(!verifier.Verify(synthetic.Anchor, chain, challenge, claimHash, signature, current, clock.Now), "factory trusted non-Google chain");
            clock.Advance(TimeSpan.FromSeconds(61));
            handler.Reply = () => throw new HttpRequestException("synthetic offline");
            await Reject<HttpRequestException>(() => source.GetCurrentStatusAsync(default));
            source.Dispose(); await Reject<ObjectDisposedException>(() => source.GetCurrentStatusAsync(default));
        }
        // HTTP Age, Date, transfer delay and monotonic residence all reduce the remaining lease.
        foreach (var mode in new[] { "age", "date", "transfer", "monotonic", "rollback" })
        {
            clock = new Clock(); handler = new Handler(() =>
            {
                var result = Response(clock);
                if (mode == "age") result.Headers.Age = TimeSpan.FromSeconds(50);
                if (mode == "date") result.Headers.Date = clock.Now.AddSeconds(-50);
                if (mode == "transfer") clock.Advance(TimeSpan.FromSeconds(50));
                return result;
            });
            using var source = new GoogleAndroidAttestationSource(handler, clock, TimeSpan.FromSeconds(2));
            await source.GetCurrentStatusAsync(default);
            if (mode == "monotonic") clock.Advance(TimeSpan.FromSeconds(61), wall: false);
            else if (mode == "rollback") clock.Now = clock.Now.AddSeconds(-1);
            else clock.Advance(TimeSpan.FromSeconds(10));
            handler.Reply = () => throw new HttpRequestException("synthetic offline");
            await Reject<HttpRequestException>(() => source.GetCurrentStatusAsync(default));
            Check(handler.Calls == 2, "stale cache reused: " + mode);
        }
        foreach (var mode in new[] { "redirect", "server-error", "content-type", "encoding", "declared-size", "actual-size", "lying-size", "invalid-json",
            "no-cache", "no-store", "no-maxage", "duplicate-maxage", "bad-maxage", "zero-maxage", "missing-date", "future-date",
            "duplicate-date", "bad-age", "duplicate-age", "stale-age", "stale-date", "clock-backwards" })
        {
            clock = new Clock(); handler = new Handler(() =>
            {
                var result = Response(clock);
                switch (mode)
                {
                    case "redirect": result.StatusCode = HttpStatusCode.Redirect; result.Headers.Location = new Uri("https://other.example.test"); break;
                    case "server-error": result.StatusCode = HttpStatusCode.ServiceUnavailable; break;
                    case "content-type": result.Content.Headers.ContentType = new MediaTypeHeaderValue("text/html"); break;
                    case "encoding": result.Content.Headers.ContentEncoding.Add("gzip"); break;
                    case "declared-size": result.Content.Headers.ContentLength = 1024 * 1024 + 1; break;
                    case "actual-size": case "lying-size":
                        result.Content = new StreamContent(new StreamingBytes(new byte[1024 * 1024 + 1]));
                        result.Content.Headers.ContentType = new("application/json");
                        if (mode == "lying-size") result.Content.Headers.ContentLength = 10;
                        break;
                    case "invalid-json": result.Content = new StringContent("{}"); result.Content.Headers.ContentType = new("application/json"); break;
                    case "no-cache": result.Headers.CacheControl!.NoCache = true; break;
                    case "no-store": result.Headers.CacheControl!.NoStore = true; break;
                    case "no-maxage": result.Headers.CacheControl!.MaxAge = null; break;
                    case "duplicate-maxage": result.Headers.TryAddWithoutValidation("Cache-Control", "max-age=600"); break;
                    case "bad-maxage": result.Headers.Remove("Cache-Control"); result.Headers.TryAddWithoutValidation("Cache-Control", "max-age=bad"); break;
                    case "zero-maxage": result.Headers.CacheControl!.MaxAge = TimeSpan.Zero; break;
                    case "missing-date": result.Headers.Date = null; break;
                    case "future-date": result.Headers.Date = clock.Now.AddMinutes(6); break;
                    case "duplicate-date": result.Headers.TryAddWithoutValidation("Date", clock.Now.ToString("r")); break;
                    case "bad-age": result.Headers.Remove("Age"); result.Headers.TryAddWithoutValidation("Age", "bad"); break;
                    case "duplicate-age": result.Headers.TryAddWithoutValidation("Age", "0"); break;
                    case "stale-age": result.Headers.Age = TimeSpan.FromSeconds(60); break;
                    case "stale-date": result.Headers.Date = clock.Now.AddSeconds(-60); break;
                    case "clock-backwards": clock.Now = clock.Now.AddSeconds(-1); break;
                }
                return result;
            });
            using var source = new GoogleAndroidAttestationSource(handler, clock, TimeSpan.FromSeconds(2));
            try { await Reject<Exception>(() => source.GetCurrentStatusAsync(default)); }
            catch (InvalidOperationException error) { throw new InvalidOperationException("Rejected-header case failed: " + mode, error); }
            Check(handler.Calls == 1, "unexpected retry: " + mode);
        }
        clock = new Clock(); handler = new Handler(() =>
        {
            var response = Response(clock); response.Content = new StreamContent(new StalledStream());
            response.Content.Headers.ContentType = new("application/json"); return response;
        });
        using (var source = new GoogleAndroidAttestationSource(handler, clock, TimeSpan.FromMilliseconds(100)))
            await Reject<OperationCanceledException>(() => source.GetCurrentStatusAsync(default));
        clock = new Clock(); handler = new Handler(() => Response(clock));
        using (var cancelled = new CancellationTokenSource())
        using (var source = new GoogleAndroidAttestationSource(handler, clock, TimeSpan.FromSeconds(2)))
        {
            var reads = 0; clock.OnRead = () => { if (++reads == 3) cancelled.Cancel(); };
            await Reject<OperationCanceledException>(() => source.GetCurrentStatusAsync(cancelled.Token));
            clock.OnRead = null;
            await source.GetCurrentStatusAsync(default);
            Check(handler.Calls == 2, "cancelled parse published a cache entry");
        }
        Console.WriteLine("PASS Google source: pinned roots, fixed HTTPS target, corrected cache age, monotonic expiry, hostile headers/body, no stale fallback and stream timeout");
    }

    private static HttpResponseMessage Response(Clock clock)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent("{\"entries\":{\"a\":{\"status\":\"REVOKED\"}}}"u8.ToArray()) };
        response.Content.Headers.ContentType = new("application/json");
        response.Headers.CacheControl = new CacheControlHeaderValue { Public = true, MaxAge = TimeSpan.FromSeconds(60) };
        response.Headers.Date = clock.Now; response.Headers.Age = TimeSpan.Zero;
        return response;
    }
    private sealed class Clock : TimeProvider
    {
        public DateTimeOffset Now = AndroidAttestationChecks.Now;
        private long _ticks;
        public Action? OnRead;
        public override DateTimeOffset GetUtcNow() { OnRead?.Invoke(); return Now; }
        public override long GetTimestamp() => _ticks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public void Advance(TimeSpan elapsed, bool wall = true) { _ticks += elapsed.Ticks; if (wall) Now += elapsed; }
    }
    private sealed class Handler(Func<HttpResponseMessage> reply) : HttpMessageHandler
    {
        public Func<HttpResponseMessage> Reply = reply;
        public int Calls;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); Calls++;
            Check(request.Method == HttpMethod.Get && request.RequestUri?.AbsoluteUri == "https://android.googleapis.com/attestation/status" &&
                request.Headers.Authorization == null && !request.Headers.Contains("Cookie") && request.Content == null, "unsafe request");
            return Task.FromResult(Reply());
        }
    }
    private sealed class StalledStream : MemoryStream
    {
        public override bool CanSeek => false;
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        { await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken); return 0; }
    }
    private sealed class StreamingBytes(byte[] bytes) : MemoryStream(bytes) { public override bool CanSeek => false; }
    private static void Check(bool value, string message) { if (!value) throw new InvalidOperationException(message); }
    private static async Task Reject<T>(Func<Task> action) where T : Exception
    { try { await action(); } catch (T) { return; } throw new InvalidOperationException("Expected rejection: " + typeof(T).Name); }
}
