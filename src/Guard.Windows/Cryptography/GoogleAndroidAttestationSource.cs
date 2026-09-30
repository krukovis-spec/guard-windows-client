using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace Guard.Windows.Cryptography;

/// <summary>Build-pinned Google roots and fixed-origin HTTPS revocation status. No relay inputs,
/// disk cache, credentials, root-store writes or background networking.</summary>
public sealed class GoogleAndroidAttestationSource : IDisposable
{
    private static readonly Uri StatusUri = new("https://android.googleapis.com/attestation/status");
    private const int MaximumBytes = 1024 * 1024;
    private readonly HttpClient _client;
    private readonly TimeProvider _clock;
    private readonly TimeSpan _timeout;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private AndroidAttestationRevocations? _cached;
    private long _cachedAt;
    private TimeSpan _remaining;
    private bool _disposed;

    public GoogleAndroidAttestationSource() : this(new SocketsHttpHandler
    {
        AllowAutoRedirect = false, UseCookies = false, UseProxy = false,
        AutomaticDecompression = DecompressionMethods.None,
        ConnectTimeout = TimeSpan.FromSeconds(5), MaxResponseHeadersLength = 8,
        MaxConnectionsPerServer = 1, PooledConnectionLifetime = TimeSpan.FromMinutes(5)
    }, TimeProvider.System, TimeSpan.FromSeconds(20)) { }

    internal GoogleAndroidAttestationSource(HttpMessageHandler handler, TimeProvider clock, TimeSpan timeout)
    {
        ArgumentNullException.ThrowIfNull(handler); ArgumentNullException.ThrowIfNull(clock);
        if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromSeconds(30)) throw new ArgumentOutOfRangeException(nameof(timeout));
        _client = new HttpClient(handler, disposeHandler: true) { Timeout = Timeout.InfiniteTimeSpan };
        _clock = clock; _timeout = timeout;
    }

    // APK signer/version come from trusted signed deployment, NEVER the enrollment claim.
    public AndroidApprovalAttestation CreateVerifier(byte[] trustedApkSignerSha256, long minimumAppVersion)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return new AndroidApprovalAttestation(LoadRoots(), trustedApkSignerSha256, minimumAppVersion);
    }

    internal static byte[][] LoadRoots()
    {
        // Official /attestation/root and Android documentation checked 2026-09-30.
        // Root rotation is a reviewed application update, not trust-on-first-use from a phone/relay.
        var hashes = new[] { "CEDB1CB6DC896AE5EC797348BCE9286753C2B38EE71CE0FBE34A9A1248800DFC",
            "6D9DB4CE6C5C0B293166D08986E05774A8776CEB525D9E4329520DE12BA4BCC0" };
        using var stream = typeof(GoogleAndroidAttestationSource).Assembly.GetManifestResourceStream("Guard.GoogleAttestationRoots")
            ?? throw new InvalidDataException("Missing Google attestation roots.");
        using var reader = new StreamReader(stream);
        var certificates = new X509Certificate2Collection();
        try
        {
            certificates.ImportFromPem(reader.ReadToEnd());
            if (certificates.Count != hashes.Length) throw new InvalidDataException("Invalid Google root bundle.");
            return certificates.Cast<X509Certificate2>().Select((cert, index) =>
                cert.GetCertHashString(HashAlgorithmName.SHA256) == hashes[index] ? cert.RawData
                    : throw new InvalidDataException("Google root fingerprint mismatch.")).ToArray();
        }
        finally { foreach (var certificate in certificates) certificate.Dispose(); }
    }

    public async Task<AndroidAttestationRevocations> GetCurrentStatusAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        cancellationToken.ThrowIfCancellationRequested();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(_timeout);
        await _gate.WaitAsync(deadline.Token).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var elapsed = _clock.GetElapsedTime(_cachedAt);
            if (_cached != null && _cached.IsCurrent(_clock.GetUtcNow()) && elapsed >= TimeSpan.Zero && elapsed < _remaining) return _cached;
            _cached = null; // An invalid/expired cache must never be served on network failure.
            var startedAt = _clock.GetTimestamp();
            var startedUtc = _clock.GetUtcNow();
            using var request = new HttpRequestMessage(HttpMethod.Get, StatusUri);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
            if (response.StatusCode != HttpStatusCode.OK) throw new HttpRequestException("Google attestation status unavailable.", null, response.StatusCode);
            if (response.Content.Headers.ContentType?.MediaType != "application/json" || response.Content.Headers.ContentEncoding.Count != 0 ||
                response.Content.Headers.ContentLength > MaximumBytes) throw new InvalidDataException("Invalid attestation status headers.");
            await using var body = await response.Content.ReadAsStreamAsync(deadline.Token).ConfigureAwait(false);
            using var buffer = new MemoryStream(); var bytes = new byte[8192];
            while (true)
            {
                var count = await body.ReadAsync(bytes.AsMemory(0, (int)Math.Min(bytes.Length, MaximumBytes + 1L - buffer.Length)), deadline.Token).ConfigureAwait(false);
                if (count == 0) break;
                buffer.Write(bytes, 0, count);
                if (buffer.Length > MaximumBytes) throw new InvalidDataException("Oversized attestation status.");
            }
            var receivedAt = _clock.GetTimestamp(); var receivedUtc = _clock.GetUtcNow();
            if (receivedUtc < startedUtc) throw new InvalidDataException("Clock moved backwards during attestation status request.");
            var remaining = Freshness(response.Headers, receivedUtc, _clock.GetElapsedTime(startedAt, receivedAt));
            var status = AndroidAttestationRevocations.FromTrustedResponse(buffer.ToArray(), receivedUtc, receivedUtc.Add(remaining));
            var parsedAt = _clock.GetElapsedTime(receivedAt);
            if (!status.IsCurrent(_clock.GetUtcNow()) || parsedAt < TimeSpan.Zero || parsedAt >= remaining)
                throw new InvalidDataException("Attestation status expired during parsing.");
            deadline.Token.ThrowIfCancellationRequested();
            ObjectDisposedException.ThrowIf(_disposed, this);
            _cachedAt = receivedAt; _remaining = remaining; _cached = status;
            return status;
        }
        finally { _gate.Release(); }
    }

    private static TimeSpan Freshness(HttpResponseHeaders headers, DateTimeOffset now, TimeSpan responseDelay)
    {
        // RFC 9111 corrected_initial_age. Date/Age include time in upstream caches; receipt
        // is NOT a fresh 24-hour lease. No heuristic, 304 or stale-if-error fallback.
        // Inspect raw multiplicity BEFORE .NET's typed parser coalesces repeated directives.
        if (!headers.NonValidated.TryGetValues("Cache-Control", out var cacheValues) ||
            cacheValues.SelectMany(v => v.Split(',')).Count(v => v.Trim().Split('=', 2)[0].Trim().Equals("max-age", StringComparison.OrdinalIgnoreCase)) != 1 ||
            !headers.NonValidated.TryGetValues("Date", out var dates) || dates.Count() != 1 ||
            (headers.NonValidated.TryGetValues("Age", out var ages) && ages.Count() != 1))
            throw new InvalidDataException("Ambiguous attestation status freshness.");
        var cache = headers.CacheControl;
        if (cache == null || cache.NoCache || cache.NoStore || cache.MaxAge is not { } lifetime || lifetime <= TimeSpan.Zero || headers.Date is not { } date ||
            date > now.AddMinutes(5) || responseDelay < TimeSpan.Zero)
            throw new InvalidDataException("Missing or unsafe attestation status freshness.");
        if (headers.Contains("Age") && (headers.Age == null || headers.Age < TimeSpan.Zero))
            throw new InvalidDataException("Invalid attestation status age.");
        lifetime = lifetime > TimeSpan.FromHours(24) ? TimeSpan.FromHours(24) : lifetime;
        var apparentAge = now > date ? now - date : TimeSpan.Zero;
        var correctedAge = (headers.Age ?? TimeSpan.Zero) + responseDelay;
        var remaining = lifetime - (apparentAge > correctedAge ? apparentAge : correctedAge);
        if (remaining <= TimeSpan.Zero) throw new InvalidDataException("Stale attestation status.");
        return remaining;
    }

    public void Dispose() { _disposed = true; _cached = null; _client.Dispose(); }
}
