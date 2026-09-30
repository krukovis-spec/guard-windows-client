using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Guard.Contracts;
using Guard.Protocol.Relay;

namespace Guard.Windows.Ipc;

public enum NativeSetupPhase
{
    RelayPending, ScanPhone, PhoneProof, ComparePhone, RestartRequired,
    ConfirmationUnknown, Confirmed, CancellationUnknown, Cancelled, Expired, RecoveryRequired
}

// Not a record: generated ToString() must never print a QR/session secret.
public sealed class NativeSetupSnapshot
{
    internal NativeSetupSnapshot(NativeSetupPhase phase, long stateVersion = -1, string? qrText = null,
        string? claimHash = null, bool relayPassCompleted = false, bool recoveryRequired = false)
    {
        Phase = phase; StateVersion = stateVersion; QrText = qrText; ClaimHash = claimHash;
        RelayPassCompleted = relayPassCompleted; RecoveryRequired = recoveryRequired;
    }
    public NativeSetupPhase Phase { get; }
    public long StateVersion { get; }
    // Render locally only; no browser, clipboard, settings, serialization or logging.
    public string? QrText { get; }
    public string? ClaimHash { get; }
    public bool RelayPassCompleted { get; }
    public bool RecoveryRequired { get; }
}

/// <summary>One originating setup window. Closing forgets its capability, not the durable owner.</summary>
public sealed class NativeSetupSession : IAsyncDisposable
{
    private readonly Func<GuardVerb, byte[], CancellationToken, Task<GuardIpcResponse>> _send;
    private readonly Func<DateTimeOffset> _clock;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly CancellationTokenSource _lifetime = new();
    private byte[]? _secret;
    private string? _qrCommitment;
    private DateTimeOffset _observedAt;
    private bool _mayHaveConfirmed;
    private int _closed;
    private NativeSetupSnapshot _snapshot = new(NativeSetupPhase.RelayPending);

    private NativeSetupSession(string enrollmentId, DateTimeOffset expiresAt, byte[] secret, DateTimeOffset now,
        Func<GuardVerb, byte[], CancellationToken, Task<GuardIpcResponse>> send, Func<DateTimeOffset> clock)
    { EnrollmentId = enrollmentId; ExpiresAt = expiresAt; _secret = secret; _observedAt = now; _send = send; _clock = clock; }

    public string EnrollmentId { get; }
    public DateTimeOffset ExpiresAt { get; }
    public NativeSetupSnapshot Snapshot => Volatile.Read(ref _snapshot);

    // A failed/lost Begin reply is NOT retried here: the service may have created a live ceremony.
    public static Task<NativeSetupSession> BeginAsync(CancellationToken token) =>
        BeginAsync(GuardSetupQueryClient.NativeSetupAsync, () => DateTimeOffset.UtcNow, token);

    internal static async Task<NativeSetupSession> BeginAsync(
        Func<GuardVerb, byte[], CancellationToken, Task<GuardIpcResponse>> send, Func<DateTimeOffset> clock,
        CancellationToken token)
    {
        var started = clock();
        var response = await send(GuardVerb.BeginNativeSetup, Array.Empty<byte>(), token).ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        using var doc = ReadJson(response, "version", "enrollmentId", "expiresAt", "confirmationSecret", "phase");
        var root = doc.RootElement;
        var id = Text(root, "enrollmentId");
        var expiry = Time(root, "expiresAt");
        var encoded = Text(root, "confirmationSecret");
        var now = clock();
        if (!GuardIdentifier.IsCanonicalToken(id) || Text(root, "phase") != "relay-pending" ||
            now < started || expiry <= now || expiry > started.AddMinutes(10) || encoded.Length != 44)
            throw InvalidResponse();
        byte[] secret;
        try { secret = Convert.FromBase64String(encoded); }
        catch (FormatException) { throw InvalidResponse(); }
        if (secret.Length != 32 || Convert.ToBase64String(secret) != encoded)
        { CryptographicOperations.ZeroMemory(secret); throw InvalidResponse(); }
        return new NativeSetupSession(id, expiry, secret, now, send, clock);
    }

    public Task<NativeSetupSnapshot> RefreshAsync(CancellationToken token) => RunAsync(async ct =>
    {
        if (_snapshot.Phase is NativeSetupPhase.Cancelled or NativeSetupPhase.CancellationUnknown or
            NativeSetupPhase.Expired or NativeSetupPhase.RecoveryRequired) return;
        if (_mayHaveConfirmed)
        {
            // No confirmation capability in this query. A successful poll is not a phone receipt.
            var result = await SendAsync(GuardVerb.GetNativeSetupResult,
                new { version = 1, enrollmentId = EnrollmentId, claimHash = _snapshot.ClaimHash }, ct).ConfigureAwait(false);
            if (result.Status == GuardIpcResponseStatus.Success)
            {
                using var doc = ReadJson(result, "version", "stateVersion", "enrollmentId", "claimHash", "phase",
                    "relayPassCompleted", "recoveryRequired");
                var root = doc.RootElement;
                var version = StateVersion(root);
                if (Text(root, "enrollmentId") != EnrollmentId || Hash(root, "claimHash") != _snapshot.ClaimHash ||
                    Text(root, "phase") != "confirmed") throw InvalidResponse();
                var pass = Boolean(root, "relayPassCompleted");
                var recovery = Boolean(root, "recoveryRequired");
                ForgetSecret();
                _snapshot = new(NativeSetupPhase.Confirmed, version, claimHash: _snapshot.ClaimHash,
                    relayPassCompleted: pass, recoveryRequired: recovery);
                return;
            }
            // Only an explicit negative read may return to the pending ceremony, and only
            // via the original secret. An offline/unknown result never starts another setup.
            if (result.Status != GuardIpcResponseStatus.Rejected) RequireSuccess(result);
            if (_snapshot.Phase == NativeSetupPhase.Confirmed) throw InvalidResponse();
        }
        if (!StillLive()) return;
        using var advance = ReadJson(await SendAsync(GuardVerb.AdvanceNativeSetup,
            new { version = 1, confirmationSecret = Secret() }, ct).ConfigureAwait(false),
            "version", "stateVersion", "enrollmentId", "expiresAt", "phase", "qr", "claimHash");
        if (!StillLive()) return;
        var value = advance.RootElement;
        var nextVersion = StateVersion(value);
        if (Text(value, "enrollmentId") != EnrollmentId || Time(value, "expiresAt") != ExpiresAt)
            throw InvalidResponse();
        var phase = Text(value, "phase") switch {
            "scan-phone" => NativeSetupPhase.ScanPhone, "phone-proof" => NativeSetupPhase.PhoneProof,
            "compare-phone" => NativeSetupPhase.ComparePhone, "restart-required" => NativeSetupPhase.RestartRequired,
            _ => throw InvalidResponse()
        };
        var qr = NullableText(value, "qr");
        var hash = NullableText(value, "claimHash");
        if ((phase == NativeSetupPhase.ScanPhone) != (qr != null) ||
            (phase == NativeSetupPhase.ComparePhone) != (hash != null)) throw InvalidResponse();
        if (hash != null) Hash(value, "claimHash");
        if (_snapshot.ClaimHash != null && hash != _snapshot.ClaimHash ||
            _snapshot.Phase == NativeSetupPhase.PhoneProof && phase is NativeSetupPhase.ScanPhone or NativeSetupPhase.RestartRequired)
            throw InvalidResponse();
        if (qr != null) ValidateQr(qr);
        _mayHaveConfirmed = false;
        _snapshot = new(phase, nextVersion, qr, hash);
    }, token);

    // Call ONLY from the user's explicit full-code comparison action, never from a poll callback.
    // Version+hash must come from the screen actually compared, not a newer background response.
    public Task<NativeSetupSnapshot> ConfirmComparedAsync(long displayedVersion, string displayedClaimHash,
        CancellationToken token) => RunAsync(async ct =>
    {
        if (_snapshot.Phase != NativeSetupPhase.ComparePhone || !StillLive() ||
            displayedVersion != _snapshot.StateVersion || displayedClaimHash != _snapshot.ClaimHash)
            throw new InvalidOperationException("The displayed phone comparison is no longer current.");
        _mayHaveConfirmed = true;
        _snapshot = new(NativeSetupPhase.ConfirmationUnknown, displayedVersion, claimHash: displayedClaimHash);
        var response = await SendAsync(GuardVerb.ConfirmNativeSetup, new { version = 1,
            confirmationSecret = Secret(), expectedVersion = displayedVersion, claimHash = displayedClaimHash }, ct).ConfigureAwait(false);
        RequireEmptySuccess(response);
        ForgetSecret();
        _snapshot = new(NativeSetupPhase.Confirmed, displayedVersion, claimHash: displayedClaimHash);
    }, token);

    public Task<NativeSetupSnapshot> CancelAsync(long displayedVersion, CancellationToken token) => RunAsync(async ct =>
    {
        if (_mayHaveConfirmed || _snapshot.Phase is not (NativeSetupPhase.ScanPhone or NativeSetupPhase.PhoneProof or
            NativeSetupPhase.ComparePhone or NativeSetupPhase.RestartRequired) || !StillLive() ||
            displayedVersion < 0 || displayedVersion != _snapshot.StateVersion)
            throw new InvalidOperationException("This ceremony cannot be cancelled from the displayed state.");
        _snapshot = new(NativeSetupPhase.CancellationUnknown, displayedVersion);
        RequireEmptySuccess(await SendAsync(GuardVerb.CancelNativeSetup, new { version = 1,
            confirmationSecret = Secret(), expectedVersion = displayedVersion }, ct).ConfigureAwait(false));
        ForgetSecret();
        _snapshot = new(NativeSetupPhase.Cancelled, displayedVersion);
    }, token);

    private async Task<NativeSetupSnapshot> RunAsync(Func<CancellationToken, Task> action, CancellationToken token)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _closed) != 0, this);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, _lifetime.Token);
        await _gate.WaitAsync(linked.Token).ConfigureAwait(false);
        try
        {
            linked.Token.ThrowIfCancellationRequested();
            ObserveTime();
            await action(linked.Token).ConfigureAwait(false);
            return Snapshot;
        }
        catch (InvalidDataException)
        { ForgetSecret(); _snapshot = new(NativeSetupPhase.RecoveryRequired); throw; }
        finally { _gate.Release(); }
    }

    private async Task<GuardIpcResponse> SendAsync(GuardVerb verb, object value, CancellationToken token)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(value);
        try
        {
            var response = await _send(verb, bytes, token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            ValidateEnvelope(response);
            ObserveTime();
            return response;
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private void ObserveTime()
    {
        var now = _clock();
        if (now < _observedAt) throw InvalidResponse();
        _observedAt = now;
    }

    private bool StillLive()
    {
        if (_observedAt < ExpiresAt) return true;
        ForgetSecret();
        _snapshot = new(_mayHaveConfirmed ? NativeSetupPhase.RecoveryRequired : NativeSetupPhase.Expired,
            _snapshot.StateVersion, claimHash: _snapshot.ClaimHash);
        return false;
    }

    private string Secret() => _secret == null ? throw new InvalidOperationException("The setup capability is no longer available.") :
        Convert.ToBase64String(_secret);

    private long StateVersion(JsonElement value)
    {
        var item = value.GetProperty("stateVersion");
        if (item.ValueKind != JsonValueKind.Number || !item.TryGetInt64(out var version) || version < 0 || version < _snapshot.StateVersion)
            throw InvalidResponse();
        return version;
    }

    private void ValidateQr(string qr)
    {
        const string prefix = "guard-enroll://v2?offer=";
        var split = qr.IndexOf("&secret=", StringComparison.Ordinal);
        if (qr.Length > 2200 || !qr.StartsWith(prefix, StringComparison.Ordinal) || split <= prefix.Length)
            throw InvalidResponse();
        byte[]? secret = null;
        try
        {
            static byte[] Decode(string s) => Convert.FromBase64String(s.Replace('-', '+').Replace('_', '/') +
                new string('=', (4 - s.Length % 4) % 4));
            var offer = RelayCanonicalEncoding.DecodeEnrollmentOffer(Decode(qr[prefix.Length..split]));
            secret = Decode(qr[(split + 8)..]);
            if (offer.EnrollmentId != EnrollmentId || offer.ExpiresAtUtc != ExpiresAt ||
                offer.CreatedAtUtc > _observedAt || _secret == null || CryptographicOperations.FixedTimeEquals(secret, _secret) ||
                RelayCanonicalEncoding.EncodeEnrollmentQr(offer, secret) != qr)
                throw InvalidResponse();
            // Pin the entire QR without retaining another plaintext secret string.
            var encoded = System.Text.Encoding.UTF8.GetBytes(qr);
            string hash;
            try { hash = Convert.ToHexString(SHA256.HashData(encoded)); }
            finally { CryptographicOperations.ZeroMemory(encoded); }
            if (_qrCommitment != null && _qrCommitment != hash) throw InvalidResponse();
            _qrCommitment = hash;
        }
        catch (Exception e) when (e is ArgumentException or FormatException or OverflowException or EndOfStreamException)
        { throw InvalidResponse(); }
        finally { if (secret != null) CryptographicOperations.ZeroMemory(secret); }
    }

    private static JsonDocument ReadJson(GuardIpcResponse response, params string[] fields)
    {
        RequireSuccess(response);
        if (response.PayloadLength == 0 || response.PayloadLength > 4096) throw InvalidResponse();
        var bytes = response.GetPayloadCopy();
        JsonDocument? doc = null;
        try
        {
            var reader = new Utf8JsonReader(bytes, new JsonReaderOptions { MaxDepth = 2 });
            doc = JsonDocument.ParseValue(ref reader);
            if (reader.Read()) throw InvalidResponse();
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) throw InvalidResponse();
            var expected = new HashSet<string>(fields, StringComparer.Ordinal);
            foreach (var property in root.EnumerateObject())
                if (!expected.Remove(property.Name)) throw InvalidResponse();
            if (expected.Count != 0 || !root.GetProperty("version").TryGetInt32(out var version) || version != 1)
                throw InvalidResponse();
            return doc;
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException or InvalidDataException)
        { doc?.Dispose(); throw InvalidResponse(); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private static string Text(JsonElement value, string name) => NullableText(value, name) ?? throw InvalidResponse();
    private static string? NullableText(JsonElement value, string name)
    {
        var item = value.GetProperty(name);
        return item.ValueKind == JsonValueKind.Null ? null : item.ValueKind == JsonValueKind.String ? item.GetString() : throw InvalidResponse();
    }
    private static string Hash(JsonElement value, string name)
    {
        var hash = Text(value, name);
        if (hash.Length != 64) throw InvalidResponse();
        foreach (var c in hash) if (!(c is >= '0' and <= '9' or >= 'a' and <= 'f')) throw InvalidResponse();
        return hash;
    }
    private static bool Boolean(JsonElement value, string name) => value.GetProperty(name).ValueKind switch {
        JsonValueKind.True => true, JsonValueKind.False => false, _ => throw InvalidResponse()
    };
    private static DateTimeOffset Time(JsonElement value, string name)
    {
        var item = value.GetProperty(name);
        if (item.ValueKind != JsonValueKind.Number || !item.TryGetInt64(out var millis)) throw InvalidResponse();
        try { return DateTimeOffset.FromUnixTimeMilliseconds(millis); }
        catch (ArgumentOutOfRangeException) { throw InvalidResponse(); }
    }
    private static void RequireSuccess(GuardIpcResponse response)
    {
        ValidateEnvelope(response);
        if (response.Status != GuardIpcResponseStatus.Success)
            throw new IOException("Native setup service response: " + response.Status + ".");
    }
    private static void ValidateEnvelope(GuardIpcResponse response)
    {
        if (response.ProtocolVersion != GuardProtocol.CurrentVersion || !Enum.IsDefined(response.Status) ||
            response.PayloadLength > 4096 || response.Status != GuardIpcResponseStatus.Success && response.PayloadLength != 0)
            throw InvalidResponse();
    }
    private static void RequireEmptySuccess(GuardIpcResponse response)
    { RequireSuccess(response); if (response.PayloadLength != 0) throw InvalidResponse(); }
    private static InvalidDataException InvalidResponse() => new("The native setup response is invalid or no longer current.");
    private void ForgetSecret()
    { if (_secret != null) CryptographicOperations.ZeroMemory(_secret); _secret = null; }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _closed, 1) != 0) return;
        _lifetime.Cancel();
        await _gate.WaitAsync().ConfigureAwait(false);
        try { ForgetSecret(); _snapshot = new(NativeSetupPhase.RecoveryRequired); }
        finally { _gate.Release(); _lifetime.Dispose(); }
        // No remote cancel/revoke on window close. Already-issued snapshots/managed strings
        // cannot be erased; the UI must drop its QR image/text on close or phase change.
    }
}
