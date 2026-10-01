using System;
using System.Threading;
using System.Threading.Tasks;
using Guard.Contracts.Relay;
using Guard.Domain;
using Guard.Domain.Relay;
using Guard.Protocol.Relay;
using Guard.Storage;
using Guard.Storage.Relay;
using Guard.Windows;

namespace Guard.Service;

// Service-local commit path. The caller owns both writer/key lifetimes and the
// ACL boundary for both stores; no IPC trust import, HTTP or policy effects here.
internal sealed class NativeRelayTransactions(FileAuthoritativeStateStore owners, FileRelayTransactionStore relay,
    DeviceIdentity identity, DeviceRelayConfiguration configuration, EnrollmentDeploymentTrust trust,
    IServiceDataBoundaryGuard boundary, TimeProvider clock)
{
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
            var next = NativeApprovalTransaction.Prepare(owner, current, frame, identity.Encryption, identity.Signing, now, out var deadline);
            return (next, deadline);
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
            return await relay.TryCommitGuardedAsync(current.Version, next, () =>
            {
                boundary.DemandReady();
                var now = clock.GetUtcNow();
                configuration.RequireMatches(trust, identity, owner, now);
                return now >= preparedAt && now < deadline;
            }, cancellation).ConfigureAwait(false);
        }, token);
    }
}
