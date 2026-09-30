using System;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Guard.Application;
using Guard.Contracts;
using Guard.Domain;
using Guard.Protocol.Relay;
using Guard.Windows;

namespace Guard.Service;

internal sealed partial class GuardServiceIpcOperationHandler
{
    private readonly DeviceRelayConfigurationStore? _configurations;
    // Internal test seam only. Production DI supplies no factory or authority override.
    private readonly Func<CancellationToken, Task<ServiceNativeEnrollment>>? _openNativeEnrollment;
    private readonly SemaphoreSlim _nativeSetupGate = new(1, 1);
    private ServiceNativeEnrollment? _nativeEnrollment;
    private NativeEnrollmentStart? _nativeStart;
    private string? _nativeStartId;

    private async Task<GuardIpcResponse> NativeSetupAsync(ClientRole role, GuardIpcRequest request, CancellationToken token)
    {
        if (role != ClientRole.AdminSetup) return Response(request, GuardIpcResponseStatus.Forbidden);
        if (_stateStore is not ServiceAuthoritativeStateBoundary boundary)
            return Response(request, GuardIpcResponseStatus.Unavailable);
        byte[]? secret = null;
        byte[]? claimHash = null;
        long expectedVersion = 0;
        var input = request.GetPayloadCopy();
        try
        {
            try
            {
                if (request.Verb == GuardVerb.BeginNativeSetup)
                {
                    if (input.Length != 0) throw new InvalidDataException();
                }
                else
                {
                    if (input.Length == 0 || input.Length > 512) throw new InvalidDataException();
                    using var document = JsonDocument.Parse(input, new JsonDocumentOptions { MaxDepth = 2 });
                    var value = document.RootElement;
                    HttpRelayTransport.RequireObject(value, request.Verb switch
                    {
                        GuardVerb.AdvanceNativeSetup => new[] { "version", "confirmationSecret" },
                        GuardVerb.CancelNativeSetup => new[] { "version", "confirmationSecret", "expectedVersion" },
                        _ => new[] { "version", "confirmationSecret", "expectedVersion", "claimHash" }
                    });
                    if (value.GetProperty("version").GetInt32() != 1) throw new InvalidDataException();
                    var encodedSecret = value.GetProperty("confirmationSecret").GetString();
                    if (encodedSecret?.Length != 44) throw new InvalidDataException();
                    secret = Convert.FromBase64String(encodedSecret);
                    if (secret.Length != 32 || Convert.ToBase64String(secret) != encodedSecret) throw new InvalidDataException();
                    if (request.Verb != GuardVerb.AdvanceNativeSetup &&
                        (expectedVersion = value.GetProperty("expectedVersion").GetInt64()) < 0) throw new InvalidDataException();
                    if (request.Verb == GuardVerb.ConfirmNativeSetup)
                    {
                        var hash = value.GetProperty("claimHash").GetString();
                        if (hash?.Length != 64) throw new InvalidDataException();
                        claimHash = Convert.FromHexString(hash);
                        if (Convert.ToHexStringLower(claimHash) != hash) throw new InvalidDataException();
                    }
                }
            }
            catch (Exception e) when (e is InvalidDataException or JsonException or InvalidOperationException or FormatException or OverflowException)
            { return Response(request, GuardIpcResponseStatus.InvalidRequest); }

            await _nativeSetupGate.WaitAsync(token).ConfigureAwait(false);
            try
            {
                var state = await boundary.LoadAsync(token).ConfigureAwait(false);
                if (request.Verb == GuardVerb.BeginNativeSetup)
                {
                    if (state.IsProvisioned || state.SetupChallenge?.IsActive(_clock.UtcNow) == true)
                        return Response(request, GuardIpcResponseStatus.Conflict);
                }
                else if (secret == null || !OwnsSession(state, secret))
                    return Response(request, GuardIpcResponseStatus.Forbidden);

                _nativeEnrollment ??= _openNativeEnrollment != null ?
                    await _openNativeEnrollment(token).ConfigureAwait(false) :
                    _configurations != null ? await ServiceNativeEnrollment.OpenAsync(boundary, _configurations, token).ConfigureAwait(false) :
                    throw new InvalidDataException("Native enrollment is not configured.");
                var runtime = _nativeEnrollment;
                if (request.Verb == GuardVerb.BeginNativeSetup)
                {
                    var offer = runtime.CreateOffer(state, _clock.UtcNow);
                    var (status, start) = await runtime.Coordinator.BeginAsync(role, offer, token).ConfigureAwait(false);
                    if (status != SetupOperationStatus.Succeeded || start == null)
                        return Response(request, MapSetupStatus(status));
                    _nativeStart?.Dispose(); _nativeStart = start; _nativeStartId = offer.EnrollmentId;
                    secret = start.GetConfirmationSecretCopy();
                    // Return only the local session capability now. No network or visible QR yet:
                    // the caller can retry provisioning with this capability after an HTTP failure.
                    return JsonResponse(request, new { version = 1, enrollmentId = offer.EnrollmentId,
                        expiresAt = offer.ExpiresAtUtc.ToUnixTimeMilliseconds(),
                        confirmationSecret = Convert.ToBase64String(secret), phase = "relay-pending" });
                }

                if (request.Verb == GuardVerb.AdvanceNativeSetup)
                {
                    if (!state.Enrollment!.Confirmed)
                        await runtime.Relay.ProvisionPendingAsync(token).ConfigureAwait(false);
                    await runtime.Relay.ProcessNextAsync(token).ConfigureAwait(false);
                    var after = await boundary.LoadAsync(token).ConfigureAwait(false);
                    if (!OwnsSession(after, secret!) || (!after.Enrollment!.Confirmed &&
                        (_clock.UtcNow < after.Enrollment.Offer.CreatedAtUtc || _clock.UtcNow >= after.Enrollment.Offer.ExpiresAtUtc)))
                        return Response(request, GuardIpcResponseStatus.Conflict);
                    var session = after.Enrollment!;
                    // A service restart loses the unshown QR, not the durable ceremony or keys.
                    // The originating caller may cancel explicitly or wait for expiry; never invent a new secret.
                    var qr = session.Candidate == null && _nativeStartId == session.Offer.EnrollmentId ? _nativeStart?.QrText : null;
                    return JsonResponse(request, new { version = 1, stateVersion = after.Version,
                        enrollmentId = session.Offer.EnrollmentId, expiresAt = session.Offer.ExpiresAtUtc.ToUnixTimeMilliseconds(),
                        phase = session.Confirmed ? "confirmed" : session.PhoneKeyConfirmed ? "compare-phone" :
                            session.Candidate != null ? "phone-proof" : qr != null ? "scan-phone" : "restart-required",
                        qr, claimHash = session.PhoneKeyConfirmed && session.Candidate != null ?
                            Convert.ToHexStringLower(RelayCanonicalEncoding.ComputeEnrollmentClaimHash(session.Candidate)) : null });
                }

                var result = request.Verb == GuardVerb.ConfirmNativeSetup ?
                    await runtime.Coordinator.ConfirmLocalAsync(role, expectedVersion, secret!, claimHash!, token).ConfigureAwait(false) :
                    await runtime.Coordinator.CancelAsync(role, expectedVersion, secret!, token).ConfigureAwait(false);
                if (result == SetupOperationStatus.Succeeded)
                { _nativeStart?.Dispose(); _nativeStart = null; _nativeStartId = null; }
                return Response(request, result == SetupOperationStatus.Succeeded ? GuardIpcResponseStatus.Success : MapSetupStatus(result));
            }
            catch (Exception e) when (e is InvalidDataException or IOException or HttpRequestException or CryptographicException)
            { return Response(request, GuardIpcResponseStatus.Unavailable); }
            finally { _nativeSetupGate.Release(); }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
            if (secret != null) CryptographicOperations.ZeroMemory(secret);
        }
    }

    private static bool OwnsSession(DeviceSecurityState state, byte[] secret) => state.Enrollment != null &&
        CryptographicOperations.FixedTimeEquals(SHA256.HashData(secret), state.Enrollment.GetConfirmationHashCopy());

    private static GuardIpcResponse JsonResponse(GuardIpcRequest request, object value)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(value);
        try
        {
            if (bytes.Length > 4096) throw new InvalidDataException("Native setup response is oversized.");
            return Response(request, GuardIpcResponseStatus.Success, bytes);
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    public void Dispose()
    { _nativeStart?.Dispose(); _nativeEnrollment?.Dispose(); _nativeSetupGate.Dispose(); }
}
