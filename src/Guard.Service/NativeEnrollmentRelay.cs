using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Guard.Domain;
using Guard.Protocol.Relay;
using Guard.Storage;
using Guard.Windows;

namespace Guard.Service;

/// <summary>One internal outbound pass; never supplies a local confirmation or claims protection readiness.</summary>
internal sealed class NativeEnrollmentRelay(FileAuthoritativeStateStore store, NativeEnrollmentExchange exchange,
    HttpRelayTransport transport, TimeProvider? clock = null) : IDisposable
{
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;
    // ponytail: one service-owned ceremony; serialize foreground/background passes, no additional queue.
    private readonly SemaphoreSlim _gate = new(1, 1);

    // UI retains NativeEnrollmentStart; show its QR only after this succeeds. HTTP failure never resets setup.
    public async Task ProvisionPendingAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var before = await store.LoadAsync(cancellationToken).ConfigureAwait(false);
            RequireCurrent(before, confirmedAllowed: false);
            var proofKey = before.SetupChallenge!.GetSecretHashCopy();
            try
            {
                var capability = RelayCanonicalEncoding.ComputeEnrollmentRelayCapability(proofKey, before.Enrollment!.Offer);
                try { await transport.ProvisionEnrollmentAsync(before.Enrollment.Offer, capability, cancellationToken).ConfigureAwait(false); }
                finally { CryptographicOperations.ZeroMemory(capability); }
            }
            finally { CryptographicOperations.ZeroMemory(proofKey); }
            RequireSameOffer(before, await store.LoadAsync(cancellationToken).ConfigureAwait(false), confirmedAllowed: false);
        }
        finally { _gate.Release(); }
    }

    /// <returns>True if one message was answered/rejected; false for an empty queue. Neither means owner/Applied.</returns>
    public async Task<bool> ProcessNextAsync(CancellationToken cancellationToken, bool confirmedOnly = false)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var before = await store.LoadAsync(cancellationToken).ConfigureAwait(false);
            RequireCurrent(before, confirmedAllowed: true, confirmedOnly);
            var offer = before.Enrollment!.Offer;
            var request = await transport.PollEnrollmentAsync(offer, cancellationToken).ConfigureAwait(false);
            RequireSameOffer(before, await store.LoadAsync(cancellationToken).ConfigureAwait(false), confirmedAllowed: true, confirmedOnly);
            if (request == null) return false;
            byte[] reply;
            try { reply = await exchange.HandleAsync(request, cancellationToken).ConfigureAwait(false); }
            catch (EnrollmentRequestRejectedException)
            {
                RequireSameOffer(before, await store.LoadAsync(cancellationToken).ConfigureAwait(false), confirmedAllowed: true, confirmedOnly);
                await transport.RejectEnrollmentRequestAsync(offer, request, cancellationToken).ConfigureAwait(false);
                return true;
            }
            RequireSameOffer(before, await store.LoadAsync(cancellationToken).ConfigureAwait(false), confirmedAllowed: true, confirmedOnly);
            await transport.PublishEnrollmentReplyAsync(offer, request, reply, cancellationToken).ConfigureAwait(false);
            // After a lost POST response/restart, POLL again: the relay excludes already answered requests.
            // No new ciphertext is blindly retried against an already committed nonce.
            return true;
        }
        finally { _gate.Release(); }
    }

    private void RequireCurrent(DeviceSecurityState state, bool confirmedAllowed, bool confirmedOnly = false)
    {
        var session = state.Enrollment ?? throw new InvalidDataException("No native enrollment.");
        var now = _clock.GetUtcNow();
        if ((confirmedOnly && !session.Confirmed) || now < session.Offer.CreatedAtUtc || now >= session.Offer.ExpiresAtUtc.AddDays(1) ||
            (session.Confirmed ? !confirmedAllowed || !state.IsProvisioned :
                state.IsProvisioned || state.SetupChallenge?.IsActive(now) != true || now >= session.Offer.ExpiresAtUtc))
            throw new InvalidDataException("Enrollment is unavailable for relay exchange.");
    }

    private void RequireSameOffer(DeviceSecurityState before, DeviceSecurityState after, bool confirmedAllowed, bool confirmedOnly = false)
    {
        RequireCurrent(after, confirmedAllowed, confirmedOnly);
        if (!RelayCanonicalEncoding.EncodeEnrollmentOffer(before.Enrollment!.Offer).AsSpan().SequenceEqual(
            RelayCanonicalEncoding.EncodeEnrollmentOffer(after.Enrollment!.Offer)) ||
            (!before.Enrollment.Confirmed && !after.Enrollment.Confirmed &&
                (!CryptographicOperations.FixedTimeEquals(before.Enrollment.GetConfirmationHashCopy(), after.Enrollment.GetConfirmationHashCopy()) ||
                 !CryptographicOperations.FixedTimeEquals(before.SetupChallenge!.GetSecretHashCopy(), after.SetupChallenge!.GetSecretHashCopy()))))
            throw new InvalidDataException("Enrollment changed during relay exchange.");
    }
    public void Dispose() => _gate.Dispose();
}
