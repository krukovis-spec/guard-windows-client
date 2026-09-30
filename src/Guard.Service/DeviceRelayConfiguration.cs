using System;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Guard.Contracts;
using Guard.Contracts.Relay;
using Guard.Domain;
using Guard.Protocol.Relay;
using Guard.Storage;
using Guard.Windows;
using Guard.Windows.Cryptography;
using Guard.Windows.Storage;

namespace Guard.Service;

// Trusted install input, NOT an enrollment message or an appsettings/environment override.
// The off-PC operator provisions a device-scoped credential; its admin credential never enters this format.
internal sealed class DeviceRelayConfiguration
{
    private readonly string _origin, _deviceId, _signingKeyId, _encryptionKeyId, _accessToken;
    internal string MailboxId { get; }
    internal long DeviceEpoch { get; }
    internal long AuthorityEpoch { get; }
    internal DateTimeOffset IssuedAt { get; }
    internal DateTimeOffset ExpiresAt { get; }
    private DeviceRelayConfiguration(JsonElement value)
    {
        HttpRelayTransport.RequireObject(value, "version", "role", "relayOrigin", "deviceId", "signingKeyId", "encryptionKeyId",
            "mailboxId", "deviceEpoch", "authorityEpoch", "accessToken", "issuedAt", "expiresAt");
        if (value.GetProperty("version").GetInt32() != 1 || value.GetProperty("role").GetString() != "device")
            throw new InvalidDataException("Only device connection profiles are supported.");
        _origin = value.GetProperty("relayOrigin").GetString() ?? throw new InvalidDataException("Missing relay origin.");
        RelayCanonicalEncoding.RequireEnrollmentRelay(_origin);
        _deviceId = Id("deviceId"); _signingKeyId = Id("signingKeyId"); _encryptionKeyId = Id("encryptionKeyId");
        MailboxId = Id("mailboxId");
        if (MailboxId == "guard:bff:auth:v1") throw new InvalidDataException("Reserved relay mailbox.");
        DeviceEpoch = value.GetProperty("deviceEpoch").GetInt64(); AuthorityEpoch = value.GetProperty("authorityEpoch").GetInt64();
        if (DeviceEpoch < 1 || DeviceEpoch > HttpRelayTransport.MaximumCursor ||
            AuthorityEpoch < 1 || AuthorityEpoch > HttpRelayTransport.MaximumCursor)
            throw new InvalidDataException("Connection epochs out of range.");
        _accessToken = value.GetProperty("accessToken").GetString() ?? throw new InvalidDataException("Missing device credential.");
        HttpRelayTransport.RequireCredential(_accessToken);
        IssuedAt = DateTimeOffset.FromUnixTimeMilliseconds(value.GetProperty("issuedAt").GetInt64());
        ExpiresAt = DateTimeOffset.FromUnixTimeMilliseconds(value.GetProperty("expiresAt").GetInt64());
        if (IssuedAt.ToUnixTimeMilliseconds() < 0 || ExpiresAt <= IssuedAt) throw new InvalidDataException("Connection lifetime.");
        string Id(string name)
        {
            var id = value.GetProperty(name).GetString();
            return id != null && GuardIdentifier.IsCanonicalToken(id) ? id : throw new InvalidDataException("Connection identifier.");
        }
    }

    internal static DeviceRelayConfiguration Decode(byte[] encoded)
    {
        if (encoded == null || encoded.Length == 0 || encoded.Length > DeviceRelayConfigurationStore.MaximumPlaintextBytes)
            throw new InvalidDataException("Connection profile size.");
        using var document = JsonDocument.Parse(encoded, new JsonDocumentOptions { MaxDepth = 3 });
        return new DeviceRelayConfiguration(document.RootElement);
    }

    internal void RequireMatches(EnrollmentDeploymentTrust trust, DeviceIdentity identity, DeviceSecurityState state, DateTimeOffset now)
    {
        identity.RequireMatches(state);
        if (_origin != trust.Origin.GetLeftPart(UriPartial.Authority) || _deviceId != identity.DeviceId ||
            _signingKeyId != identity.SigningKeyId || _encryptionKeyId != identity.EncryptionKeyId ||
            now < IssuedAt || now >= ExpiresAt)
            throw new InvalidDataException("Connection profile does not match this deployment/device/time.");
        var offer = state.Enrollment?.Offer;
        if (offer != null && (offer.RelayEndpoint != _origin || offer.MailboxId != MailboxId ||
            offer.DeviceEpoch != DeviceEpoch || offer.AuthorityEpoch != AuthorityEpoch))
            throw new InvalidDataException("Connection profile does not match enrolled authority.");
    }

    internal HttpRelayTransport CreateTransport(EnrollmentDeploymentTrust trust, DeviceIdentity identity,
        DeviceSecurityState state, DateTimeOffset now)
    {
        RequireMatches(trust, identity, state, now);
        return new HttpRelayTransport(trust.Origin, MailboxId, _encryptionKeyId, _accessToken);
    }

    internal EnrollmentOffer CreateOffer(EnrollmentDeploymentTrust trust, DeviceIdentity identity, DeviceSecurityState state,
        string label, DateTimeOffset now)
    {
        RequireMatches(trust, identity, state, now);
        var issued = DateTimeOffset.FromUnixTimeMilliseconds(now.ToUnixTimeMilliseconds());
        var expires = issued.AddMinutes(5);
        if (state.IsProvisioned || state.Enrollment?.Confirmed == true || expires.AddDays(1) > ExpiresAt)
            throw new InvalidOperationException("Enrollment requires an unprovisioned device and a usable credential retention window.");
        var offer = new EnrollmentOffer(_origin, "enrollment-" + Guid.NewGuid().ToString("N"), identity.DeviceId, label,
            DeviceEpoch, AuthorityEpoch, MailboxId, identity.SigningKeyId, identity.SigningPoint,
            identity.EncryptionKeyId, identity.EncryptionPoint, issued, expires, RandomNumberGenerator.GetBytes(32));
        _ = RelayCanonicalEncoding.EncodeEnrollmentOffer(offer);
        return offer;
    }
}

// Import is internal and restricted to the trusted installer before setup/IPC starts, under the writer lease.
// Neither the child nor a relay/phone message can invoke it. Credential rotation/recovery is a separate signed workflow.
internal sealed class DeviceRelayConfigurationStore(GuardDataPaths paths, IStateDataProtector protector, IServiceDataBoundaryGuard boundary)
{
    internal const string Purpose = "guard-v2-device-relay-configuration-v1";
    internal const int MaximumPlaintextBytes = 4096;
    private readonly ProtectedServiceRecord _record = new(paths.DeviceRelayConfigurationFile, paths.DeviceRelayConfigurationPendingFile,
        protector, boundary, MaximumPlaintextBytes, 8192);

    internal DeviceRelayConfiguration Load(EnrollmentDeploymentTrust trust, DeviceIdentity identity, DeviceSecurityState state, DateTimeOffset now)
    {
        var plaintext = _record.Read();
        try
        {
            var config = DeviceRelayConfiguration.Decode(plaintext);
            config.RequireMatches(trust, identity, state, now);
            return config;
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    internal async Task InstallNewAsync(byte[] trustedProfile, EnrollmentDeploymentTrust trust, DeviceIdentity identity,
        DeviceSecurityState pristineState, DateTimeOffset now, CancellationToken cancellationToken)
    {
        if (trustedProfile == null || trustedProfile.Length > MaximumPlaintextBytes) throw new InvalidDataException("Connection profile size.");
        var plaintext = (byte[])trustedProfile.Clone();
        try
        {
            var config = DeviceRelayConfiguration.Decode(plaintext);
            config.RequireMatches(trust, identity, pristineState, now);
            if (pristineState.Version != 0 || pristineState.IsProvisioned || pristineState.SetupChallenge != null ||
                pristineState.Enrollment != null || pristineState.ChildAccountSid != null || config.DeviceEpoch != 1 || config.AuthorityEpoch != 1)
                throw new InvalidOperationException("Connection installation requires pristine initial state.");
            await _record.PublishNewAsync(plaintext, cancellationToken).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }
}

// One owner for disposable enrollment components; keys/store remain owned by the service boundary.
internal sealed class ServiceNativeEnrollment : IDisposable
{
    private readonly GoogleAndroidAttestationSource _source;
    private readonly HttpRelayTransport _transport;
    internal NativeEnrollmentCoordinator Coordinator { get; }
    internal NativeEnrollmentRelay Relay { get; }
    private ServiceNativeEnrollment(GoogleAndroidAttestationSource source, HttpRelayTransport transport,
        NativeEnrollmentCoordinator coordinator, NativeEnrollmentRelay relay)
    { _source = source; _transport = transport; Coordinator = coordinator; Relay = relay; }

    internal static async Task<ServiceNativeEnrollment> OpenAsync(ServiceAuthoritativeStateBoundary boundary,
        DeviceRelayConfigurationStore configurations, CancellationToken cancellationToken)
    {
        var trust = EnrollmentDeploymentTrust.FromServiceAssembly();
        var state = await boundary.LoadAsync(cancellationToken).ConfigureAwait(false);
        var config = configurations.Load(trust, boundary.Identity, state, TimeProvider.System.GetUtcNow());
        cancellationToken.ThrowIfCancellationRequested();
        return Create(boundary.NativeEnrollmentStore, boundary.Identity, state, config, trust, TimeProvider.System);
    }

    internal static ServiceNativeEnrollment Create(FileAuthoritativeStateStore store, DeviceIdentity identity,
        DeviceSecurityState state, DeviceRelayConfiguration config, EnrollmentDeploymentTrust trust, TimeProvider clock)
    {
        var transport = config.CreateTransport(trust, identity, state, clock.GetUtcNow());
        GoogleAndroidAttestationSource? source = null;
        try
        {
            source = new GoogleAndroidAttestationSource();
            var coordinator = new NativeEnrollmentCoordinator(store, trust.CreateVerifier(source), source.GetCurrentStatusAsync, clock);
            var exchange = new NativeEnrollmentExchange(store, coordinator, identity.Encryption, identity.Signing, clock);
            return new ServiceNativeEnrollment(source, transport, coordinator, new NativeEnrollmentRelay(store, exchange, transport, clock));
        }
        catch { source?.Dispose(); transport.Dispose(); throw; }
    }
    public void Dispose() { Relay.Dispose(); _transport.Dispose(); _source.Dispose(); }
}
