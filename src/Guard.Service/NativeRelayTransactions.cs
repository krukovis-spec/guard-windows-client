using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Guard.Application;
using Guard.Contracts;
using Guard.Contracts.Relay;
using Guard.Domain;
using Guard.Domain.Relay;
using Guard.Protocol.Relay;
using Guard.Storage;
using Guard.Storage.Relay;
using Guard.Windows;

namespace Guard.Service;

// A pure incoming-message refusal, distinct from local storage/profile/ACL failure.
internal sealed class NativeApprovalRejectedException() : Exception("Incoming native approval was refused.");

// Service-local commit path. The caller owns both writer/key lifetimes and the
// ACL boundary for both stores; no IPC trust import, HTTP or policy effects here.
internal sealed class NativeRelayTransactions(FileAuthoritativeStateStore owners, FileRelayTransactionStore relay,
    DeviceIdentity identity, DeviceRelayConfiguration configuration, EnrollmentDeploymentTrust trust,
    IServiceDataBoundaryGuard boundary, TimeProvider clock)
{
    // Not wired to child IPC until its token-derived context and verified active-policy
    // observation source exist. Never substitute client assertions or arbitrary CI events.
    internal async Task<(RequestSnapshot Request, bool Created)?> CreateApplicationRequestAsync(
        long ownerVersion, AuthenticatedChildContext caller, CreateApplicationRequestPayload input,
        IBlockedApplicationObservationResolver observations, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(caller);
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(observations);
        token.ThrowIfCancellationRequested();
        boundary.DemandReady();
        var startedAt = clock.GetUtcNow();
        var observation = await observations.ResolveAsync(input.ObservationId, token).ConfigureAwait(false)
            ?? throw new InvalidDataException("The local blocked observation is unavailable.");
        (RequestSnapshot Request, bool Created)? result = null;
        var committed = await CommitAsync(ownerVersion, (owner, current, now) =>
        {
            if (now < startedAt) throw new InvalidDataException("Clock moved backwards while resolving the observation.");
            var prepared = NativeApprovalTransaction.PrepareApplicationRequest(owner, current, caller, input,
                observation, identity.Encryption, identity.Signing, now);
            result = (prepared.Request, prepared.Created);
            var deadline = prepared.Request.PendingExpiresAtUtc < observation.ExpiresAtUtc
                ? prepared.Request.PendingExpiresAtUtc : observation.ExpiresAtUtc;
            return (prepared.State, deadline);
        }, token).ConfigureAwait(false);
        return committed ? result : null;
    }

    internal Task<bool> PublishRequestAsync(long ownerVersion, RequestSnapshot localRequest, CancellationToken token)
    {
        var snapshot = RelayCanonicalEncoding.DecodeRequestSnapshot(RelayCanonicalEncoding.EncodeRequestSnapshot(localRequest));
        return CommitAsync(ownerVersion, (owner, current, now) =>
            (NativeApprovalTransaction.PrepareRequest(owner, current, snapshot, identity.Encryption, identity.Signing, now),
                snapshot.PendingExpiresAtUtc), token);
    }

    internal Task<bool> AcceptApprovalAsync(long ownerVersion, byte[] encodedFrame, CancellationToken token)
    {
        if (encodedFrame == null || encodedFrame.Length == 0 || encodedFrame.Length > RelayProtocol.MaximumFrameBytes)
            throw new ArgumentException("Bounded approval frame required.", nameof(encodedFrame));
        var frame = (byte[])encodedFrame.Clone();
        return CommitAsync(ownerVersion, (owner, current, now) =>
        {
            try
            {
                var next = NativeApprovalTransaction.Prepare(owner, current, frame, identity.Encryption, identity.Signing, now, out var deadline);
                return (next, deadline);
            }
            catch (Exception e) when (e is ArgumentException or InvalidDataException or InvalidOperationException or CryptographicException or OverflowException)
            { throw new NativeApprovalRejectedException(); }
        }, token);
    }

    internal Task<bool> AcknowledgePublishedAsync(long ownerVersion, RelayEncryptedOutboxItem published, CancellationToken token)
        => RemoveOutboxHeadAsync(ownerVersion, published, false, token);

    internal Task<bool> RetireExpiredAsync(long ownerVersion, RelayEncryptedOutboxItem expired, CancellationToken token)
        => RemoveOutboxHeadAsync(ownerVersion, expired, true, token);

    private Task<bool> RemoveOutboxHeadAsync(long ownerVersion, RelayEncryptedOutboxItem published, bool requireExpired, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(published);
        return CommitAsync(ownerVersion, (_, current, now) =>
        {
            if (current.Outbox.Count == 0) throw new InvalidOperationException("Published item is no longer queued.");
            var first = current.Outbox[0];
            if (first.OutboundCursor != published.OutboundCursor || first.FrameId != published.FrameId ||
                first.RecipientKeyId != published.RecipientKeyId || first.RecipientCursor != published.RecipientCursor ||
                first.Kind != published.Kind || !CryptographicOperations.FixedTimeEquals(first.GetEncryptedFrameCopy(), published.GetEncryptedFrameCopy()))
                throw new InvalidOperationException("Only the exact first published item can be acknowledged.");
            if (requireExpired && now < RelayCanonicalEncoding.DecodeRelayFrame(first.GetEncryptedFrameCopy()).ExpiresAtUtc)
                throw new InvalidDataException("Cannot retire a live outbox frame.");
            return (current.WithAcknowledgedOutboundCursor(first.OutboundCursor), configuration.ExpiresAt);
        }, token);
    }

    private Task<bool> CommitAsync(long ownerVersion,
        Func<DeviceSecurityState, RelayTransactionState, DateTimeOffset, (RelayTransactionState Next, DateTimeOffset Deadline)> prepare,
        CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        boundary.DemandReady();
        return owners.TryWithCurrentStateAsync(ownerVersion, async (owner, cancellation) =>
        {
            var current = await relay.LoadAsync(cancellation).ConfigureAwait(false);
            var preparedAt = clock.GetUtcNow();
            configuration.RequireMatches(trust, identity, owner, preparedAt);
            var (next, deadline) = prepare(owner, current, preparedAt);
            bool CanPublish()
            {
                boundary.DemandReady();
                var now = clock.GetUtcNow();
                configuration.RequireMatches(trust, identity, owner, now);
                return now >= preparedAt && now < deadline;
            }
            // All service relay mutations hold this same owner lock. A deduplicated read
            // must not consume a cursor/version or encrypt/sign a replacement request.
            if (ReferenceEquals(next, current))
            {
                var valid = CanPublish();
                cancellation.ThrowIfCancellationRequested();
                return valid;
            }
            return await relay.TryCommitGuardedAsync(current.Version, next, CanPublish, cancellation).ConfigureAwait(false);
        }, token);
    }
}
