using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Guard.Contracts.Relay;
using Guard.Domain;
using Guard.Domain.Relay;
using Guard.Protocol.Relay;
using Guard.Service;
using Guard.Storage;
using Guard.Storage.Relay;
using Guard.Windows.Cryptography;

namespace Guard.Windows.Crypto.Tests;

// Reuses the real synthetic-attestation owner fixture. Only temporary CurrentUser
// DPAPI files; no actual service, host policy, production credential or network.
internal static class NativeRelayCommitChecks
{
    internal static async Task RunAsync(FileAuthoritativeStateStore owners, DeviceIdentity identity,
        DeviceRelayConfiguration config, EnrollmentDeploymentTrust trust, Func<byte[], byte[]> signApproval, DateTimeOffset now)
    {
        var directory = Directory.CreateTempSubdirectory("Guard-native-relay-commit-");
        var owner = await owners.LoadAsync(default);
        var clock = new Clock { Value = now };
        var guard = new Boundary();
        var statePath = Path.Combine(directory.FullName, "relay.dat");
        var journal = new Journal(new ProtectedFileStateVersionJournal(Path.Combine(directory.FullName, "relay.journal"),
            new LocalSystemDpapiDataProtector(FileRelayTransactionStore.JournalDataProtectionPurpose, true)));
        FileRelayTransactionStore Open() => new(statePath,
            new LocalSystemDpapiDataProtector(FileRelayTransactionStore.StateDataProtectionPurpose, true), journal);
        try
        {
            using (var relay = Open())
            {
                await relay.InitializeAsync(new RelayTransactionState(owner.DeviceId, 0, 1, 1, 0, 0, 0, 0), default);
                var runtime = new NativeRelayTransactions(owners, relay, identity, config, trust, guard, clock);
                var snapshot = new RequestSnapshot(owner.DeviceId, 1, 1, "event-commit-0001", "request-commit-0001", 1,
                    RelayTargetKind.Application, "sha256:" + new string('a', 64), Array.Empty<RelayEvidenceField>(), "test", now,
                    now.AddMinutes(10), RandomNumberGenerator.GetBytes(32), 0);
                Check(!await runtime.PublishRequestAsync(owner.Version - 1, snapshot, default), "stale owner version");
                using (var cancelled = new CancellationTokenSource())
                {
                    cancelled.Cancel();
                    await ThrowsAsync(() => runtime.PublishRequestAsync(owner.Version, snapshot, cancelled.Token));
                }
                foreach (var deadline in new[] { snapshot.PendingExpiresAtUtc, now.AddTicks(-1), config.ExpiresAt })
                {
                    clock.Value = now; guard.Reset(() => clock.Value = deadline);
                    if (deadline == snapshot.PendingExpiresAtUtc)
                        Check(!await runtime.PublishRequestAsync(owner.Version, snapshot, default), "expired request published");
                    else await ThrowsAsync(() => runtime.PublishRequestAsync(owner.Version, snapshot, default));
                    Check(guard.Calls == 3 && (await relay.LoadAsync(default)).Version == 0, "late guard skipped or wrote state");
                }
                clock.Value = now;
                using (var cancellation = new CancellationTokenSource())
                {
                    guard.Reset(cancellation.Cancel);
                    await ThrowsAsync(() => runtime.PublishRequestAsync(owner.Version, snapshot, cancellation.Token));
                    Check((await relay.LoadAsync(default)).Version == 0, "cancellation inside final validation committed");
                }
                guard.Reset(() => throw new UnauthorizedAccessException("Synthetic lost ACL boundary."));
                await ThrowsAsync(() => runtime.PublishRequestAsync(owner.Version, snapshot, default));
                Check((await relay.LoadAsync(default)).Version == 0 && !Directory.EnumerateFiles(directory.FullName, "*.tmp").Any(),
                    "guard failure wrote state or left temp plaintext");
                guard.Reset();
                Check(await runtime.PublishRequestAsync(owner.Version, snapshot, default), "trusted request commit");
                var published = await relay.LoadAsync(default);
                Check(published.TrackedRequests.Single().GetEncodedSnapshotCopy().SequenceEqual(RelayCanonicalEncoding.EncodeRequestSnapshot(snapshot)),
                    "committed original mismatch");
                Check(await relay.TryCommitAsync(published.Version, published.WithAcknowledgedOutboundCursor(1), default), "test delivery ack");

                byte[] ApprovalFrame(DateTimeOffset frameDeadline)
                {
                    SignedApprovalEnvelope Approval(byte[] signature) => new(1, owner.Enrollment!.Candidate!.ApprovalKeyId, 1,
                        "command-commit-001", "nonce-commit-0001", now, now.AddMinutes(2), owner.DeviceId, 1, snapshot.RequestId, 1,
                        RelayCanonicalEncoding.ComputeRequestSnapshotHash(snapshot), snapshot.GetDecisionChallengeCopy(), snapshot.TargetKind,
                        snapshot.CanonicalTargetIdentity, 0, ParentDecisionKind.AllowTemporary, 10, signature);
                    var signed = Approval(signApproval(RelayCanonicalEncoding.ComputeApprovalHash(Approval(new byte[64]))));
                    RelayFrame Frame(byte[] enc, byte[] cipher) => new(RelayFrameKind.Approval, config.MailboxId, identity.EncryptionKeyId,
                        "frame-commit-0001", 1, 0, now, frameDeadline, enc, cipher);
                    var aad = RelayCanonicalEncoding.EncodeRelayFrameAssociatedData(Frame(Array.Empty<byte>(), Array.Empty<byte>()));
                    var cipher = RelayCryptography.Encrypt(identity.EncryptionPoint, RelayCanonicalEncoding.EncodeApprovalEnvelope(signed),
                        aad, "guard-relay-approval-hpke-v1"u8.ToArray().Concat(aad).ToArray(), out var encapsulated);
                    return RelayCanonicalEncoding.EncodeRelayFrame(Frame(encapsulated, cipher));
                }
                var frame = ApprovalFrame(now.AddHours(1));
                foreach (var scenario in new[] { (frame, now.AddMinutes(2)), (ApprovalFrame(now.AddMinutes(1)), now.AddMinutes(1)) })
                {
                    clock.Value = now; guard.Reset(() => clock.Value = scenario.Item2);
                    Check(!await runtime.AcceptApprovalAsync(owner.Version, scenario.Item1, default) && guard.Calls == 3 &&
                        (await relay.LoadAsync(default)).CommittedInboundCursor == 0, "inner/outer deadline crossed during commit");
                }
                clock.Value = now; guard.Reset();

                // The operation snapshots input before waiting on the owner lock.
                var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                var held = owners.TryWithCurrentStateAsync(owner.Version, async (_, token) =>
                { entered.SetResult(); await release.Task.WaitAsync(token); return true; }, default);
                await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
                Task<bool>? ownerWrite = null;
                var nextOwner = new DeviceSecurityState(owner.DeviceId, owner.Version + 1, owner.HighestAcceptedSequence,
                    owner.DesiredPolicyRevision, owner.RecentCommandIds, owner.SetupChallenge, owner.TrustedParentKeys,
                    owner.ChildAccountSid, owner.Enrollment);
                using var afterCommitCancellation = new CancellationTokenSource();
                try
                {
                    using var cancelledWait = new CancellationTokenSource();
                    var waiting = runtime.AcceptApprovalAsync(owner.Version, frame, cancelledWait.Token);
                    cancelledWait.Cancel(); await ThrowsAsync(() => waiting);
                    guard.Reset(() =>
                    {
                        ownerWrite = owners.TryCommitAsync(owner.Version, nextOwner, default);
                        Check(!ownerWrite.IsCompleted, "owner changed inside dependent relay commit");
                    });
                    // Cancellation after the durable publication point must finish the journal.
                    journal.BeforeAdvance = version => { if (version == 3) afterCommitCancellation.Cancel(); };
                    var exactFrame = (byte[])frame.Clone();
                    var accepting = runtime.AcceptApprovalAsync(owner.Version, frame, afterCommitCancellation.Token);
                    frame[0] ^= 1;
                    release.SetResult();
                    Check(await accepting.WaitAsync(TimeSpan.FromSeconds(10)), "valid approval not committed");
                    Check(await held && ownerWrite != null && await ownerWrite && afterCommitCancellation.IsCancellationRequested,
                        "owner lock release or post-publication cancellation semantics");
                    var committed = await relay.LoadAsync(default);
                    Check(committed.Version == 3 && committed.CommittedInboundCursor == 1 && committed.PolicyLedger.Count == 1 &&
                        committed.ReplayFloors.Single().HighestAcceptedSequence == 1 &&
                        committed.SignedReceipts.Single().Status == CommandReceiptStatus.AcceptedPendingReconciliation,
                        "complete pending transaction required");
                    guard.Reset();
                    Check(!await runtime.AcceptApprovalAsync(owner.Version, exactFrame, default), "stale owner callback ran");
                    await ThrowsAsync(() => runtime.AcceptApprovalAsync(nextOwner.Version, exactFrame, default));
                }
                finally { release.TrySetResult(); await held; }
            }
            using var reopened = Open();
            var restored = await reopened.LoadAsync(default);
            Check(restored.Version == 3 && restored.SignedReceipts.Count == 1 && restored.ReconcileIntents.Count == 1 &&
                restored.TrackedRequests.Single().Resolution == RelayRequestResolution.Allowed && restored.Outbox.Count == 1,
                "restart lost committed result");
        }
        finally { directory.Delete(recursive: true); }
    }

    private sealed class Clock : TimeProvider { internal DateTimeOffset Value; public override DateTimeOffset GetUtcNow() => Value; }
    private sealed class Boundary : IServiceDataBoundaryGuard
    {
        internal int Calls; private Action? _last;
        internal void Reset(Action? action = null) { Calls = 0; _last = action; }
        public void DemandReady() { if (++Calls == 3) _last?.Invoke(); }
    }
    private sealed class Journal(IStateVersionWatermark inner) : IStateVersionWatermark
    {
        internal Action<long>? BeforeAdvance;
        public Task<StateVersionWatermark?> GetCurrentAsync(CancellationToken token) => inner.GetCurrentAsync(token);
        public Task AdvanceToAsync(long version, byte[] commitment, CancellationToken token)
        { BeforeAdvance?.Invoke(version); return inner.AdvanceToAsync(version, commitment, token); }
    }
    private static void Check(bool condition, string message) { if (!condition) throw new Exception(message); }
    private static async Task ThrowsAsync(Func<Task> action)
    {
        try { await action(); }
        catch (Exception e) when (e is ArgumentException or InvalidDataException or InvalidOperationException or
            OperationCanceledException or UnauthorizedAccessException or CryptographicException) { return; }
        throw new Exception("Expected native relay commit rejection.");
    }
}
