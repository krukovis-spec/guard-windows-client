using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using Guard.Contracts;
using Guard.Contracts.Relay;
using Guard.Protocol;
using Guard.Protocol.Relay;
using Guard.Windows.Cryptography;
using Guard.Windows.Ipc;

namespace Guard.Setup;

// Deliberately contains no default/fallback service client, HTTP, disk storage or OS probes.
internal sealed class PreviewBackend : ISetupBackend
{
    internal const string Hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string Id = "preview-enrollment-0001";
    private readonly byte[] _secret = RandomNumberGenerator.GetBytes(32);
    private DateTimeOffset _created, _expiry;
    private string _qr = "";
    internal string Phase = "scan-phone";
    internal bool Fail, Committed;
    internal bool LoseConfirmation { get; set; }
    internal int AdvanceCalls, ConfirmCalls, CancelCalls, ActiveCalls, MaxActiveCalls;
    internal TaskCompletionSource? HoldNextAdvance { get; set; }
    internal TaskCompletionSource? AdvanceEntered { get; set; }
    internal long Version = 1;
    internal TimeSpan Lifetime { get; set; } = TimeSpan.FromMinutes(5);

    public Task<SetupInspection> InspectAsync(CancellationToken token) => SetupInspection.ReadAsync(async (verb, ct) =>
    {
        await Task.Delay(250, ct); // Visible, cancellable simulated latency; never a production delay.
        var unknown = GuardReadinessFactState.Unknown;
        var codes = new[] { GuardReadinessFindingCodes.WindowsEditionBlocking, GuardReadinessFindingCodes.ChildAccountBlocking,
            GuardReadinessFindingCodes.SeparateLocalAdministratorBlocking, GuardReadinessFindingCodes.SecureBootBlocking,
            GuardReadinessFindingCodes.BitLockerBlocking, GuardReadinessFindingCodes.ServiceBoundaryBlocking,
            GuardReadinessFindingCodes.ProgramDataAclBlocking, GuardReadinessFindingCodes.SupportedManagedBrowserBlocking };
        var readiness = new GuardReadinessPayload(Version, DateTimeOffset.UtcNow,
            unknown, unknown, unknown, unknown, unknown, unknown, unknown, unknown, 0, false,
            codes.Select(code => new GuardReadinessFindingPayload(code, GuardReadinessFindingSeverity.Blocking)).ToArray());
        return new GuardIpcResponse(1, "preview", GuardIpcResponseStatus.Success, verb switch {
            GuardVerb.GetStatus => GuardStatusPayloadCodec.Encode(new(Version, Committed, false)),
            GuardVerb.GetReadiness => GuardReadinessPayloadCodec.Encode(readiness),
            _ => throw new InvalidOperationException("Preview query not supported.")
        });
    }, token);

    public Task<NativeSetupSession> BeginAsync(CancellationToken token)
    {
        _created = DateTimeOffset.FromUnixTimeMilliseconds(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        _expiry = _created.Add(Lifetime);
        using var signing = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var encryption = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var offer = new EnrollmentOffer("https://preview.invalid", Id, "preview-device-0001", "DEMO - not a real computer",
            1, 1, "preview-mailbox-0001", "preview-signing-0001", signing.ExportSubjectPublicKeyInfo()[26..],
            "preview-encryption-0001", encryption.ExportSubjectPublicKeyInfo()[26..], _created, _expiry,
            RandomNumberGenerator.GetBytes(32));
        _qr = RelayCanonicalEncoding.EncodeEnrollmentQr(offer, RandomNumberGenerator.GetBytes(32));
        return NativeSetupSession.BeginAsync(SendAsync, () => DateTimeOffset.UtcNow, token);
    }

    private async Task<GuardIpcResponse> SendAsync(GuardVerb verb, byte[] payload, CancellationToken token)
    {
        ActiveCalls++; MaxActiveCalls = Math.Max(MaxActiveCalls, ActiveCalls);
        try
        {
            if (verb == GuardVerb.AdvanceNativeSetup)
            {
                AdvanceCalls++;
                if (HoldNextAdvance is { } held)
                {
                    HoldNextAdvance = null; AdvanceEntered?.TrySetResult();
                    await held.Task.WaitAsync(token);
                }
            }
            await Task.Delay(400, token);
            if (Fail) throw new IOException("Simulated offline peer.");
            switch (verb)
            {
                case GuardVerb.BeginNativeSetup:
                    return Json(new { version = 1, enrollmentId = Id, expiresAt = _expiry.ToUnixTimeMilliseconds(),
                        confirmationSecret = Convert.ToBase64String(_secret), phase = "relay-pending" });
                case GuardVerb.AdvanceNativeSetup:
                    return Json(new { version = 1, stateVersion = Version, enrollmentId = Id,
                        expiresAt = _expiry.ToUnixTimeMilliseconds(), phase = Phase,
                        qr = Phase == "scan-phone" ? _qr : null, claimHash = Phase == "compare-phone" ? Hash : null });
                case GuardVerb.ConfirmNativeSetup:
                    ConfirmCalls++; Committed = true;
                    if (LoseConfirmation) throw new IOException("Simulated lost confirmation reply.");
                    return Empty();
                case GuardVerb.CancelNativeSetup:
                    CancelCalls++; return Empty();
                case GuardVerb.GetNativeSetupResult:
                    return Json(new { version = 1, stateVersion = Version, enrollmentId = Id, claimHash = Hash,
                        phase = "confirmed", relayPassCompleted = true, recoveryRequired = false });
                default: throw new InvalidOperationException("Preview command not supported.");
            }
        }
        finally { ActiveCalls--; }
    }

    public Task<DeviceProvisioningDescriptor> DescriptorAsync(CancellationToken token) =>
        throw new NotSupportedException("Preview never exports provisioning data.");
    public Task<NativeActivationConfirmation> ActivationAsync(CancellationToken token) =>
        throw new NotSupportedException("Preview never exports activation data.");
    private static GuardIpcResponse Json(object value) => new(1, "preview", GuardIpcResponseStatus.Success, JsonSerializer.SerializeToUtf8Bytes(value));
    private static GuardIpcResponse Empty() => new(1, "preview", GuardIpcResponseStatus.Success, Array.Empty<byte>());
}
