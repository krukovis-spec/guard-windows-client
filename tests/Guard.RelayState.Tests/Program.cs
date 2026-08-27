using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Guard.Contracts.Relay;
using Guard.Domain.Relay;
using Guard.Storage;
using Guard.Storage.Relay;
using RelayParentDecisionKind = Guard.Contracts.Relay.ParentDecisionKind;

namespace Guard.RelayState.Tests
{
    internal static class Program
    {
        private static int Main()
        {
            var tests = new List<(string Name, Action Run)>
            {
                ("uses distinct bounded relay DPAPI purposes", UsesDistinctProtectionPurposes),
                ("commits the complete approval transaction atomically", CommitsApprovalAtomically),
                ("rejects receipt context mismatch", RejectsReceiptContextMismatch),
                ("rejects a partial inbound-cursor commit", RejectsPartialApprovalCommit),
                ("allows exactly one concurrent CAS winner", AllowsOneConcurrentCasWinner),
                ("rejects stale CAS without changing state", RejectsStaleCas),
                ("recovers a state commit after journal-advance crash", RecoversJournalAdvanceCrash),
                ("detects rollback to the atomic backup", DetectsBackupRollback),
                ("rejects state corruption and oversized files", RejectsCorruptAndOversizedState),
                ("holds an exclusive writer lease", HoldsExclusiveWriterLease),
                ("requires an empty explicit relay initialization", RequiresEmptyInitialization),
                ("fails closed before relay enrollment", FailsClosedBeforeEnrollment),
                ("enforces aggregate and outbox bounds", EnforcesAggregateBounds),
                ("does not ack an outbox frame before CAS", DoesNotAckBeforeCas),
                ("persists an idempotent AlreadyResolved receipt", PersistsAlreadyResolvedReceipt)
            };

            var failures = 0;
            foreach (var test in tests)
            {
                try
                {
                    test.Run();
                    Console.WriteLine("PASS " + test.Name);
                }
                catch (Exception exception)
                {
                    failures++;
                    Console.WriteLine(
                        "FAIL " + test.Name + ": " + exception.Message);
                }
            }

            Console.WriteLine(
                failures == 0
                    ? "All Guard relay-state checks passed."
                    : failures + " Guard relay-state check(s) failed.");
            return failures == 0 ? 0 : 1;
        }

        private static void UsesDistinctProtectionPurposes()
        {
            Assert(
                !string.Equals(
                    FileRelayTransactionStore.StateDataProtectionPurpose,
                    FileRelayTransactionStore.JournalDataProtectionPurpose,
                    StringComparison.Ordinal),
                "Relay state and journal share one DPAPI purpose.");
            Assert(
                FileRelayTransactionStore.StateDataProtectionPurpose.Length >= 16 &&
                FileRelayTransactionStore.JournalDataProtectionPurpose.Length >= 16,
                "A relay DPAPI purpose is not bounded/canonical.");
            Assert(
                FileRelayTransactionStore.StateDataProtectionPurpose
                    .IndexOf("relay", StringComparison.Ordinal) >= 0 &&
                FileRelayTransactionStore.JournalDataProtectionPurpose
                    .IndexOf("relay", StringComparison.Ordinal) >= 0,
                "A relay DPAPI purpose is not domain-separated.");
        }

        private static void CommitsApprovalAtomically()
        {
            using (var directory = new TemporaryDirectory())
            using (var bundle = CreateStore(directory.PathValue))
            {
                var initial = InitialState();
                bundle.Store.InitializeAsync(initial, CancellationToken.None)
                    .GetAwaiter().GetResult();
                var published = initial.WithPublishedRequest(
                    PendingRequest(),
                    Outbox(1, RelayFrameKind.Request, "frame-request-0001"));
                Assert(
                    bundle.Store.TryCommitAsync(
                        initial.Version,
                        published,
                        CancellationToken.None).GetAwaiter().GetResult(),
                    "Request publish CAS failed.");
                var acknowledged =
                    published.WithAcknowledgedOutboundCursor(1);
                Assert(
                    bundle.Store.TryCommitAsync(
                        published.Version,
                        acknowledged,
                        CancellationToken.None).GetAwaiter().GetResult(),
                    "Request ack CAS failed.");

                var committed =
                    acknowledged.WithCommittedApproval(
                        AllowedTransaction(acknowledged, sequence: 1));
                Assert(
                    bundle.Store.TryCommitAsync(
                        acknowledged.Version,
                        committed,
                        CancellationToken.None).GetAwaiter().GetResult(),
                    "Approval CAS failed.");

                var loaded = bundle.Store.LoadAsync(CancellationToken.None)
                    .GetAwaiter().GetResult();
                AssertEqual(1L, loaded.CommittedInboundCursor, "Inbound cursor was not committed.");
                AssertEqual(1L, loaded.PolicyRevision, "Policy revision was not committed.");
                AssertEqual(1, loaded.ReplayFloors.Count, "Replay floor was not committed.");
                AssertEqual(1, loaded.PolicyLedger.Count, "Policy ledger was not committed.");
                AssertEqual(1, loaded.ReconcileIntents.Count, "Reconcile intent was not committed.");
                AssertEqual(1, loaded.SignedReceipts.Count, "Signed receipt was not committed.");
                AssertEqual(1, loaded.Outbox.Count, "Encrypted receipt frame was not committed.");
                Assert(
                    loaded.TrackedRequests[0].Resolution ==
                        RelayRequestResolution.Allowed,
                    "The exact request was not resolved.");
                AssertEqual(
                    1L,
                    loaded.ReplayFloors[0].HighestAcceptedSequence,
                    "Per-key sequence was not advanced.");
            }
        }

        private static void RejectsPartialApprovalCommit()
        {
            using (var directory = new TemporaryDirectory())
            using (var bundle = CreateStore(directory.PathValue))
            {
                var initial = InitialState();
                bundle.Store.InitializeAsync(initial, CancellationToken.None)
                    .GetAwaiter().GetResult();
                var published = initial.WithPublishedRequest(
                    PendingRequest(),
                    Outbox(1, RelayFrameKind.Request, "frame-request-0001"));
                bundle.Store.TryCommitAsync(
                    initial.Version,
                    published,
                    CancellationToken.None).GetAwaiter().GetResult();

                var partial = new RelayTransactionState(
                    published.DeviceId,
                    published.Version + 1,
                    published.DeviceEpoch,
                    published.AuthorityEpoch,
                    committedInboundCursor: 1,
                    published.HighestOutboundCursor,
                    published.AcknowledgedOutboundCursor,
                    published.PolicyRevision,
                    published.ReplayFloors,
                    published.TrackedRequests,
                    published.PolicyLedger,
                    published.ReconcileIntents,
                    published.SignedReceipts,
                    published.Outbox);
                AssertThrows<ArgumentException>(
                    () => bundle.Store.TryCommitAsync(
                        published.Version,
                        partial,
                        CancellationToken.None).GetAwaiter().GetResult());
                AssertEqual(
                    published.Version,
                    bundle.Store.LoadAsync(CancellationToken.None)
                        .GetAwaiter().GetResult().Version,
                    "A partial approval changed authoritative relay state.");
            }
        }

        private static void RejectsReceiptContextMismatch()
        {
            var state = InitialState()
                .WithPublishedRequest(
                    PendingRequest(),
                    Outbox(1, RelayFrameKind.Request, "frame-request-0001"))
                .WithAcknowledgedOutboundCursor(1);
            var exact = AllowedTransaction(state, sequence: 1);
            var receipt = exact.SignedReceipt;
            var wrongReceipt = new RelaySignedReceiptRecord(
                "device-relay-wrong1",
                receipt.DeviceEpoch,
                receipt.CommandId,
                receipt.RequestId,
                receipt.RequestRevision,
                receipt.AuthorityEpoch,
                receipt.ApprovalKeyId,
                receipt.Sequence,
                receipt.Status,
                receipt.GetApprovalHashCopy(),
                receipt.GetSignedReceiptCopy());
            var wrong = new RelayApprovalTransaction(
                exact.InboundCursor,
                exact.RequestId,
                exact.RequestRevision,
                exact.GetSnapshotHashCopy(),
                exact.Disposition,
                exact.ReplayFloor,
                exact.PolicyLedgerEntry,
                exact.ReconcileIntent,
                wrongReceipt,
                exact.EncryptedReceiptOutboxItem);
            AssertThrows<InvalidOperationException>(
                () => state.WithCommittedApproval(wrong));

            var wrongSnapshot = new RelayApprovalTransaction(
                exact.InboundCursor,
                exact.RequestId,
                exact.RequestRevision,
                Bytes(32, 99),
                exact.Disposition,
                exact.ReplayFloor,
                exact.PolicyLedgerEntry,
                exact.ReconcileIntent,
                exact.SignedReceipt,
                exact.EncryptedReceiptOutboxItem);
            AssertThrows<InvalidOperationException>(
                () => state.WithCommittedApproval(wrongSnapshot));
        }

        private static void AllowsOneConcurrentCasWinner()
        {
            using (var directory = new TemporaryDirectory())
            using (var bundle = CreateStore(directory.PathValue))
            {
                var initial = InitialState();
                bundle.Store.InitializeAsync(initial, CancellationToken.None)
                    .GetAwaiter().GetResult();
                var first = initial.WithPublishedRequest(
                    PendingRequest(),
                    Outbox(1, RelayFrameKind.Request, "frame-request-0001"));
                var second = initial.WithPublishedRequest(
                    PendingRequest(
                        "request-relay-0002",
                        seed: 22),
                    Outbox(1, RelayFrameKind.Request, "frame-request-0002"));

                var results = Task.WhenAll(
                    bundle.Store.TryCommitAsync(
                        initial.Version,
                        first,
                        CancellationToken.None),
                    bundle.Store.TryCommitAsync(
                        initial.Version,
                        second,
                        CancellationToken.None)).GetAwaiter().GetResult();
                AssertEqual(
                    1,
                    results.Count(value => value),
                    "Concurrent CAS did not produce exactly one winner.");
                AssertEqual(
                    1L,
                    bundle.Store.LoadAsync(CancellationToken.None)
                        .GetAwaiter().GetResult().Version,
                    "The winning CAS was not durable.");
            }
        }

        private static void RejectsStaleCas()
        {
            using (var directory = new TemporaryDirectory())
            using (var bundle = CreateStore(directory.PathValue))
            {
                var initial = InitialState();
                bundle.Store.InitializeAsync(initial, CancellationToken.None)
                    .GetAwaiter().GetResult();
                var first = initial.WithPublishedRequest(
                    PendingRequest(),
                    Outbox(1, RelayFrameKind.Request, "frame-request-0001"));
                var stale = initial.WithPublishedRequest(
                    PendingRequest(
                        "request-relay-0002",
                        seed: 22),
                    Outbox(1, RelayFrameKind.Request, "frame-request-0002"));
                Assert(
                    bundle.Store.TryCommitAsync(
                        0,
                        first,
                        CancellationToken.None).GetAwaiter().GetResult(),
                    "Fresh CAS failed.");
                Assert(
                    !bundle.Store.TryCommitAsync(
                        0,
                        stale,
                        CancellationToken.None).GetAwaiter().GetResult(),
                    "A stale CAS unexpectedly succeeded.");
                AssertEqual(
                    "request-relay-0001",
                    bundle.Store.LoadAsync(CancellationToken.None)
                        .GetAwaiter().GetResult().TrackedRequests[0].RequestId,
                    "A stale CAS changed relay state.");
            }
        }

        private static void RecoversJournalAdvanceCrash()
        {
            using (var directory = new TemporaryDirectory())
            {
                var stateProtector = new AuthenticatedTestProtector(
                    Bytes(32, 31));
                var journalProtector = new AuthenticatedTestProtector(
                    Bytes(32, 32));
                var journal = new ProtectedFileStateVersionJournal(
                    Path.Combine(directory.PathValue, "relay.journal"),
                    journalProtector);
                var failOnce = new FailOnceWatermark(journal, failVersion: 1);
                using (var store = new FileRelayTransactionStore(
                    Path.Combine(directory.PathValue, "relay.dat"),
                    stateProtector,
                    failOnce))
                {
                    var initial = InitialState();
                    store.InitializeAsync(initial, CancellationToken.None)
                        .GetAwaiter().GetResult();
                    var published = initial.WithPublishedRequest(
                        PendingRequest(),
                        Outbox(
                            1,
                            RelayFrameKind.Request,
                            "frame-request-0001"));
                    AssertThrows<IOException>(
                        () => store.TryCommitAsync(
                            initial.Version,
                            published,
                            CancellationToken.None).GetAwaiter().GetResult());

                    var recovered = store.LoadAsync(CancellationToken.None)
                        .GetAwaiter().GetResult();
                    AssertEqual(
                        published.Version,
                        recovered.Version,
                        "The direct state successor was not recovered.");
                    AssertEqual(
                        published.Version,
                        journal.GetCurrentAsync(CancellationToken.None)
                            .GetAwaiter().GetResult()!.Version,
                        "Recovery did not advance the protected journal.");
                }
            }
        }

        private static void DetectsBackupRollback()
        {
            using (var directory = new TemporaryDirectory())
            using (var bundle = CreateStore(directory.PathValue))
            {
                var initial = InitialState();
                bundle.Store.InitializeAsync(initial, CancellationToken.None)
                    .GetAwaiter().GetResult();
                var published = initial.WithPublishedRequest(
                    PendingRequest(),
                    Outbox(1, RelayFrameKind.Request, "frame-request-0001"));
                bundle.Store.TryCommitAsync(
                    initial.Version,
                    published,
                    CancellationToken.None).GetAwaiter().GetResult();
                Assert(
                    File.Exists(bundle.Store.BackupFilePath),
                    "Atomic replace did not retain a backup.");
                File.Copy(
                    bundle.Store.BackupFilePath,
                    bundle.Store.StateFilePath,
                    overwrite: true);
                AssertThrows<StateRollbackDetectedException>(
                    () => bundle.Store.LoadAsync(CancellationToken.None)
                        .GetAwaiter().GetResult());
            }
        }

        private static void RejectsCorruptAndOversizedState()
        {
            using (var corruptDirectory = new TemporaryDirectory())
            using (var corruptBundle = CreateStore(corruptDirectory.PathValue))
            {
                corruptBundle.Store.InitializeAsync(
                    InitialState(),
                    CancellationToken.None).GetAwaiter().GetResult();
                var bytes = File.ReadAllBytes(corruptBundle.Store.StateFilePath);
                bytes[bytes.Length - 1] ^= 0x01;
                File.WriteAllBytes(corruptBundle.Store.StateFilePath, bytes);
                AssertThrows<StateStoreCorruptionException>(
                    () => corruptBundle.Store.LoadAsync(CancellationToken.None)
                        .GetAwaiter().GetResult());
            }

            using (var oversizedDirectory = new TemporaryDirectory())
            using (var oversizedBundle = CreateStore(oversizedDirectory.PathValue))
            {
                oversizedBundle.Store.InitializeAsync(
                    InitialState(),
                    CancellationToken.None).GetAwaiter().GetResult();
                File.WriteAllBytes(
                    oversizedBundle.Store.StateFilePath,
                    new byte[1024 * 1024]);
                AssertThrows<StateStoreCorruptionException>(
                    () => oversizedBundle.Store.LoadAsync(CancellationToken.None)
                        .GetAwaiter().GetResult());
            }
        }

        private static void HoldsExclusiveWriterLease()
        {
            using (var directory = new TemporaryDirectory())
            using (var first = CreateStore(directory.PathValue))
            {
                AssertThrows<IOException>(
                    () =>
                    {
                        using (var ignored = CreateStore(directory.PathValue))
                        {
                        }
                    });
            }
        }

        private static void RequiresEmptyInitialization()
        {
            using (var directory = new TemporaryDirectory())
            using (var bundle = CreateStore(directory.PathValue))
            {
                var seeded = new RelayTransactionState(
                    "device-relay-0001",
                    version: 0,
                    deviceEpoch: 2,
                    authorityEpoch: 4,
                    committedInboundCursor: 0,
                    highestOutboundCursor: 1,
                    acknowledgedOutboundCursor: 1,
                    policyRevision: 0);
                AssertThrows<ArgumentException>(
                    () => bundle.Store.InitializeAsync(
                        seeded,
                        CancellationToken.None).GetAwaiter().GetResult());
                Assert(
                    !File.Exists(bundle.Store.StateFilePath),
                    "Rejected initialization left authoritative relay state.");
            }
        }

        private static void FailsClosedBeforeEnrollment()
        {
            var unprovisioned = new RelayTransactionState(
                "device-relay-0001",
                version: 0,
                deviceEpoch: 0,
                authorityEpoch: 0,
                committedInboundCursor: 0,
                highestOutboundCursor: 0,
                acknowledgedOutboundCursor: 0,
                policyRevision: 0);
            AssertThrows<InvalidOperationException>(
                () => unprovisioned.WithPublishedRequest(
                    PendingRequest(),
                    Outbox(
                        1,
                        RelayFrameKind.Request,
                        "frame-request-0001")));
        }

        private static void EnforcesAggregateBounds()
        {
            AssertThrows<ArgumentException>(
                () => new RelayEncryptedOutboxItem(
                    "frame-oversized-0001",
                    1,
                    RelayFrameKind.Request,
                    new byte[RelayProtocol.MaximumFrameBytes + 1]));

            var floors = new List<RelayReplayFloor>();
            for (var index = 0;
                index <= RelayTransactionState.MaximumReplayFloors;
                index++)
            {
                floors.Add(new RelayReplayFloor(
                    4,
                    "approval-key-" + index.ToString("D4"),
                    1,
                    "command-floor-" + index.ToString("D4"),
                    Bytes(32, index + 1)));
            }

            AssertThrows<ArgumentException>(
                () => new RelayTransactionState(
                    "device-relay-0001",
                    0,
                    2,
                    4,
                    0,
                    0,
                    0,
                    0,
                    floors));

            var oversizedReceipts = new List<RelaySignedReceiptRecord>();
            for (var index = 0;
                index < RelayTransactionState.MaximumSignedReceipts;
                index++)
            {
                oversizedReceipts.Add(new RelaySignedReceiptRecord(
                    "device-relay-0001",
                    deviceEpoch: 2,
                    "command-bound-" + index.ToString("D4"),
                    "request-bound-" + index.ToString("D4"),
                    requestRevision: 1,
                    authorityEpoch: 4,
                    "approval-key-0001",
                    sequence: index + 1,
                    CommandReceiptStatus.Rejected,
                    Bytes(32, index + 10),
                    Bytes(
                        RelaySignedReceiptRecord.MaximumSignedReceiptBytes,
                        index + 20)));
            }

            var oversizedState = new RelayTransactionState(
                "device-relay-0001",
                version: 1,
                deviceEpoch: 2,
                authorityEpoch: 4,
                committedInboundCursor: 0,
                highestOutboundCursor: 0,
                acknowledgedOutboundCursor: 0,
                policyRevision: 0,
                signedReceipts: oversizedReceipts);
            var codec = typeof(FileRelayTransactionStore).Assembly.GetType(
                "Guard.Storage.Relay.RelayStateCodec",
                throwOnError: true)!;
            var encode = codec.GetMethod(
                "Encode",
                BindingFlags.Public | BindingFlags.Static)!;
            try
            {
                encode.Invoke(null, new object[] { oversizedState });
                throw new InvalidOperationException(
                    "The relay codec accepted an oversized aggregate.");
            }
            catch (TargetInvocationException exception)
                when (exception.InnerException is ArgumentException)
            {
            }

            var state = InitialState();
            for (var index = 1;
                index <= RelayTransactionState.MaximumOutboxItems;
                index++)
            {
                state = state.WithPublishedRequest(
                    PendingRequest(
                        "request-relay-" + index.ToString("D4"),
                        index + 40),
                    Outbox(
                        index,
                        RelayFrameKind.Request,
                        "frame-request-" + index.ToString("D4")));
            }

            AssertThrows<InvalidOperationException>(
                () => state.WithPublishedRequest(
                    PendingRequest("request-relay-9999", 99),
                    Outbox(
                        RelayTransactionState.MaximumOutboxItems + 1,
                        RelayFrameKind.Request,
                        "frame-request-9999")));
        }

        private static void DoesNotAckBeforeCas()
        {
            using (var directory = new TemporaryDirectory())
            using (var bundle = CreateStore(directory.PathValue))
            {
                var initial = InitialState();
                bundle.Store.InitializeAsync(initial, CancellationToken.None)
                    .GetAwaiter().GetResult();
                var published = initial.WithPublishedRequest(
                    PendingRequest(),
                    Outbox(1, RelayFrameKind.Request, "frame-request-0001"));
                bundle.Store.TryCommitAsync(
                    initial.Version,
                    published,
                    CancellationToken.None).GetAwaiter().GetResult();

                var notCommitted =
                    published.WithAcknowledgedOutboundCursor(1);
                AssertEqual(
                    1,
                    bundle.Store.LoadAsync(CancellationToken.None)
                        .GetAwaiter().GetResult().Outbox.Count,
                    "Constructing an ack removed a durable frame.");
                Assert(
                    bundle.Store.TryCommitAsync(
                        published.Version,
                        notCommitted,
                        CancellationToken.None).GetAwaiter().GetResult(),
                    "Ack CAS failed.");
                AssertEqual(
                    0,
                    bundle.Store.LoadAsync(CancellationToken.None)
                        .GetAwaiter().GetResult().Outbox.Count,
                    "A committed ack did not remove its frame.");
            }
        }

        private static void PersistsAlreadyResolvedReceipt()
        {
            using (var directory = new TemporaryDirectory())
            using (var bundle = CreateStore(directory.PathValue))
            {
                var initial = InitialState();
                bundle.Store.InitializeAsync(initial, CancellationToken.None)
                    .GetAwaiter().GetResult();
                var published = initial.WithPublishedRequest(
                    PendingRequest(),
                    Outbox(1, RelayFrameKind.Request, "frame-request-0001"));
                Commit(bundle.Store, initial, published);
                var requestAck = published.WithAcknowledgedOutboundCursor(1);
                Commit(bundle.Store, published, requestAck);
                var denied = requestAck.WithCommittedApproval(
                    DeniedTransaction(requestAck, sequence: 1));
                Commit(bundle.Store, requestAck, denied);
                var receiptAck = denied.WithAcknowledgedOutboundCursor(2);
                Commit(bundle.Store, denied, receiptAck);

                var approvalHash = Bytes(32, 73);
                var floor = new RelayReplayFloor(
                    receiptAck.AuthorityEpoch,
                    "approval-key-0001",
                    2,
                    "command-relay-0002",
                    approvalHash);
                var receipt = new RelaySignedReceiptRecord(
                    receiptAck.DeviceId,
                    receiptAck.DeviceEpoch,
                    floor.CommandId,
                    "request-relay-0001",
                    requestRevision: 3,
                    floor.AuthorityEpoch,
                    floor.ApprovalKeyId,
                    floor.HighestAcceptedSequence,
                    CommandReceiptStatus.AlreadyResolved,
                    approvalHash,
                    Bytes(96, 74));
                var replay = receiptAck.WithCommittedApproval(
                    new RelayApprovalTransaction(
                        inboundCursor: 2,
                        "request-relay-0001",
                        requestRevision: 3,
                        Bytes(32, 11),
                        RelayApprovalDisposition.AlreadyResolved,
                        floor,
                        policyLedgerEntry: null,
                        reconcileIntent: null,
                        receipt,
                        Outbox(
                            3,
                            RelayFrameKind.Receipt,
                            "frame-receipt-0003")));
                Commit(bundle.Store, receiptAck, replay);
                var loaded = bundle.Store.LoadAsync(CancellationToken.None)
                    .GetAwaiter().GetResult();
                AssertEqual(
                    RelayRequestResolution.Denied,
                    loaded.TrackedRequests[0].Resolution,
                    "AlreadyResolved rewrote the first decision.");
                AssertEqual(
                    2L,
                    loaded.ReplayFloors[0].HighestAcceptedSequence,
                    "AlreadyResolved did not advance the exact per-key floor.");
                AssertEqual(
                    CommandReceiptStatus.AlreadyResolved,
                    loaded.SignedReceipts[1].Status,
                    "AlreadyResolved receipt was not retained.");
            }
        }

        private static RelayTransactionState InitialState()
        {
            return new RelayTransactionState(
                "device-relay-0001",
                version: 0,
                deviceEpoch: 2,
                authorityEpoch: 4,
                committedInboundCursor: 0,
                highestOutboundCursor: 0,
                acknowledgedOutboundCursor: 0,
                policyRevision: 0);
        }

        private static RelayTrackedRequest PendingRequest(
            string requestId = "request-relay-0001",
            int seed = 11)
        {
            return new RelayTrackedRequest(
                requestId,
                requestRevision: 3,
                Bytes(32, seed),
                Bytes(32, seed + 1));
        }

        private static RelayApprovalTransaction AllowedTransaction(
            RelayTransactionState state,
            long sequence)
        {
            var approvalHash = Bytes(32, 61);
            var floor = new RelayReplayFloor(
                state.AuthorityEpoch,
                "approval-key-0001",
                sequence,
                "command-relay-0001",
                approvalHash);
            var policy = new RelayPolicyLedgerEntry(
                state.PolicyRevision + 1,
                "request-relay-0001",
                floor.CommandId,
                RelayTargetKind.Website,
                "https://example.test/",
                RelayParentDecisionKind.AllowTemporary,
                durationMinutes: 60,
                approvalHash);
            var intent = new RelayReconcileIntent(
                "reconcile-relay-0001",
                policy.PolicyRevision,
                floor.CommandId,
                policy.ComputeDigest());
            var receipt = new RelaySignedReceiptRecord(
                state.DeviceId,
                state.DeviceEpoch,
                floor.CommandId,
                "request-relay-0001",
                requestRevision: 3,
                floor.AuthorityEpoch,
                floor.ApprovalKeyId,
                floor.HighestAcceptedSequence,
                CommandReceiptStatus.AcceptedPendingReconciliation,
                approvalHash,
                Bytes(96, 62));
            return new RelayApprovalTransaction(
                state.CommittedInboundCursor + 1,
                "request-relay-0001",
                requestRevision: 3,
                Bytes(32, 11),
                RelayApprovalDisposition.Allowed,
                floor,
                policy,
                intent,
                receipt,
                Outbox(
                    state.HighestOutboundCursor + 1,
                    RelayFrameKind.Receipt,
                    "frame-receipt-0002"));
        }

        private static RelayApprovalTransaction DeniedTransaction(
            RelayTransactionState state,
            long sequence)
        {
            var approvalHash = Bytes(32, 71);
            var floor = new RelayReplayFloor(
                state.AuthorityEpoch,
                "approval-key-0001",
                sequence,
                "command-relay-0001",
                approvalHash);
            var receipt = new RelaySignedReceiptRecord(
                state.DeviceId,
                state.DeviceEpoch,
                floor.CommandId,
                "request-relay-0001",
                requestRevision: 3,
                floor.AuthorityEpoch,
                floor.ApprovalKeyId,
                floor.HighestAcceptedSequence,
                CommandReceiptStatus.Applied,
                approvalHash,
                Bytes(96, 72));
            return new RelayApprovalTransaction(
                state.CommittedInboundCursor + 1,
                "request-relay-0001",
                requestRevision: 3,
                Bytes(32, 11),
                RelayApprovalDisposition.Denied,
                floor,
                policyLedgerEntry: null,
                reconcileIntent: null,
                receipt,
                Outbox(
                    state.HighestOutboundCursor + 1,
                    RelayFrameKind.Receipt,
                    "frame-receipt-0002"));
        }

        private static RelayEncryptedOutboxItem Outbox(
            long cursor,
            RelayFrameKind kind,
            string frameId)
        {
            return new RelayEncryptedOutboxItem(
                frameId,
                cursor,
                kind,
                Bytes(160, checked((int)cursor + 80)));
        }

        private static StoreBundle CreateStore(string directory)
        {
            var stateProtector =
                new AuthenticatedTestProtector(Bytes(32, 1));
            var journalProtector =
                new AuthenticatedTestProtector(Bytes(32, 2));
            var journal = new ProtectedFileStateVersionJournal(
                Path.Combine(directory, "relay.journal"),
                journalProtector);
            var store = new FileRelayTransactionStore(
                Path.Combine(directory, "relay.dat"),
                stateProtector,
                journal);
            return new StoreBundle(store);
        }

        private static void Commit(
            FileRelayTransactionStore store,
            RelayTransactionState current,
            RelayTransactionState next)
        {
            Assert(
                store.TryCommitAsync(
                    current.Version,
                    next,
                    CancellationToken.None).GetAwaiter().GetResult(),
                "Expected relay CAS failed.");
        }

        private static byte[] Bytes(int count, int seed)
        {
            var result = new byte[count];
            for (var index = 0; index < result.Length; index++)
            {
                result[index] = (byte)((seed + index) & 0xFF);
            }

            return result;
        }

        private static void Assert(bool condition, string message)
        {
            if (!condition)
            {
                throw new InvalidOperationException(message);
            }
        }

        private static void AssertEqual<T>(
            T expected,
            T actual,
            string message)
        {
            if (!EqualityComparer<T>.Default.Equals(expected, actual))
            {
                throw new InvalidOperationException(message);
            }
        }

        private static void AssertThrows<TException>(Action action)
            where TException : Exception
        {
            try
            {
                action();
            }
            catch (TException)
            {
                return;
            }

            throw new InvalidOperationException(
                "Expected " + typeof(TException).Name + ".");
        }

        private sealed class StoreBundle : IDisposable
        {
            public StoreBundle(FileRelayTransactionStore store)
            {
                Store = store;
            }

            public FileRelayTransactionStore Store { get; }

            public void Dispose()
            {
                Store.Dispose();
            }
        }

        private sealed class TemporaryDirectory : IDisposable
        {
            public TemporaryDirectory()
            {
                PathValue = Path.Combine(
                    Path.GetTempPath(),
                    "guard-relay-state-tests-" +
                    Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(PathValue);
            }

            public string PathValue { get; }

            public void Dispose()
            {
                if (Directory.Exists(PathValue))
                {
                    Directory.Delete(PathValue, recursive: true);
                }
            }
        }

        private sealed class AuthenticatedTestProtector :
            IStateDataProtector
        {
            private readonly byte[] _key;

            public AuthenticatedTestProtector(byte[] key)
            {
                if (key == null || key.Length != 32)
                {
                    throw new ArgumentException(
                        "A 256-bit test key is required.",
                        nameof(key));
                }

                _key = (byte[])key.Clone();
            }

            public byte[] Protect(byte[] plaintext)
            {
                if (plaintext == null || plaintext.Length == 0)
                {
                    throw new ArgumentException(
                        "Plaintext is required.",
                        nameof(plaintext));
                }

                var nonce = RandomNumberGenerator.GetBytes(12);
                var ciphertext = new byte[plaintext.Length];
                var tag = new byte[16];
                using (var aes = new AesGcm(_key, tagSizeInBytes: tag.Length))
                {
                    aes.Encrypt(nonce, plaintext, ciphertext, tag);
                }

                var result = new byte[
                    nonce.Length + tag.Length + ciphertext.Length];
                Buffer.BlockCopy(nonce, 0, result, 0, nonce.Length);
                Buffer.BlockCopy(tag, 0, result, nonce.Length, tag.Length);
                Buffer.BlockCopy(
                    ciphertext,
                    0,
                    result,
                    nonce.Length + tag.Length,
                    ciphertext.Length);
                return result;
            }

            public byte[] Unprotect(byte[] protectedData)
            {
                if (protectedData == null || protectedData.Length <= 28)
                {
                    throw new CryptographicException(
                        "Protected test data is malformed.");
                }

                var nonce = new byte[12];
                var tag = new byte[16];
                var ciphertext = new byte[protectedData.Length - 28];
                Buffer.BlockCopy(protectedData, 0, nonce, 0, nonce.Length);
                Buffer.BlockCopy(
                    protectedData,
                    nonce.Length,
                    tag,
                    0,
                    tag.Length);
                Buffer.BlockCopy(
                    protectedData,
                    nonce.Length + tag.Length,
                    ciphertext,
                    0,
                    ciphertext.Length);
                var plaintext = new byte[ciphertext.Length];
                using (var aes = new AesGcm(_key, tagSizeInBytes: tag.Length))
                {
                    aes.Decrypt(nonce, ciphertext, tag, plaintext);
                }

                return plaintext;
            }
        }

        private sealed class FailOnceWatermark : IStateVersionWatermark
        {
            private readonly IStateVersionWatermark _inner;
            private readonly long _failVersion;
            private int _failed;

            public FailOnceWatermark(
                IStateVersionWatermark inner,
                long failVersion)
            {
                _inner = inner;
                _failVersion = failVersion;
            }

            public Task<StateVersionWatermark?> GetCurrentAsync(
                CancellationToken cancellationToken)
            {
                return _inner.GetCurrentAsync(cancellationToken);
            }

            public Task AdvanceToAsync(
                long version,
                byte[] stateCommitment,
                CancellationToken cancellationToken)
            {
                if (version == _failVersion &&
                    Interlocked.Exchange(ref _failed, 1) == 0)
                {
                    throw new IOException(
                        "Injected journal-advance crash.");
                }

                return _inner.AdvanceToAsync(
                    version,
                    stateCommitment,
                    cancellationToken);
            }
        }
    }
}
