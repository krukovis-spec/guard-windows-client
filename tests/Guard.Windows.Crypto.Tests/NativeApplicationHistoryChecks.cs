using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Guard.Application;
using Guard.Contracts;
using Guard.Contracts.Relay;
using Guard.Domain;
using Guard.Domain.Relay;
using Guard.Protocol.Relay;
using Guard.Service;

namespace Guard.Windows.Crypto.Tests;

internal static class NativeApplicationHistoryChecks
{
    internal static void Run(DeviceSecurityState owner, DeviceIdentity identity, WindowsAccountSid child, DateTimeOffset now)
    {
        now = DateTimeOffset.FromUnixTimeMilliseconds(now.ToUnixTimeMilliseconds());
        var session = owner.Enrollment!;
        var caller = new AuthenticatedChildContext(owner.DeviceId, child);
        RequestSnapshot Original(int index = 1, string? sid = null, long? epoch = null) => new(owner.DeviceId, session.Offer.DeviceEpoch,
            epoch ?? session.Offer.AuthorityEpoch, "event-history-000" + index, "request-history-" + index, 1, RelayTargetKind.Application,
            "sha256:" + new string('A', 64), new[] { new RelayEvidenceField("application-name", "Программа 😀"),
                new RelayEvidenceField("child-account", sid ?? child.Value) }, "", now, now.AddMinutes(10), new byte[32], 0);
        RelayTrackedRequest Track(RequestSnapshot original, RelayRequestResolution resolution = RelayRequestResolution.Pending) =>
            new(original.RequestId, 1, RelayCanonicalEncoding.ComputeRequestSnapshotHash(original), original.GetDecisionChallengeCopy(), resolution,
                resolution == RelayRequestResolution.Pending ? null : "command-history-1",
                resolution == RelayRequestResolution.Pending ? null : new byte[32], RelayCanonicalEncoding.EncodeRequestSnapshot(original));
        RelaySignedReceiptRecord Receipt(CommandReceiptStatus status, ReconciliationStatus reconciliation, string requestId = "request-history-1",
            bool corrupt = false, long? metadataEpoch = null, DateTimeOffset? processed = null)
        {
            var receipt = new CommandReceipt(owner.DeviceId, session.Offer.DeviceEpoch, session.Offer.AuthorityEpoch,
                session.Candidate!.ApprovalKeyId, 1, "command-history-1", requestId, 1, status, processed ?? now, new byte[32], 0,
                reconciliation, "history-test-0001");
            var envelope = new DeviceSignedCommandReceiptEnvelope(receipt, session.Offer.SigningKeyId, new byte[64]);
            var signature = identity.Signing.SignHash(RelayCanonicalEncoding.ComputeDeviceReceiptHash(envelope), DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            if (corrupt) signature[0] ^= 1;
            var bytes = RelayCanonicalEncoding.EncodeDeviceReceiptEnvelope(new DeviceSignedCommandReceiptEnvelope(receipt, session.Offer.SigningKeyId, signature));
            return new RelaySignedReceiptRecord(owner.DeviceId, session.Offer.DeviceEpoch, receipt.CommandId, receipt.RequestId, 1,
                metadataEpoch ?? session.Offer.AuthorityEpoch, receipt.KeyId, 1, status, new byte[32], bytes);
        }
        RelayTransactionState State(RelayTrackedRequest[] requests, params RelaySignedReceiptRecord[] receipts) =>
            new(owner.DeviceId, 0, session.Offer.DeviceEpoch, session.Offer.AuthorityEpoch, 0, 0, 0, 0, trackedRequests: requests, signedReceipts: receipts);
        ApplicationRequestHistoryPayload Read(RelayTransactionState state, DateTimeOffset? at = null, AuthenticatedChildContext? context = null) =>
            NativeApprovalTransaction.ReadApplicationHistory(owner, state, context ?? caller, identity.Encryption, identity.Signing, at ?? now);
        var pending = State(new[] { Track(Original()) });
        Check(Read(pending).Items.Single().Status == ApplicationRequestHistoryStatus.AwaitingResponse, "pending permission claim");
        Check(Read(pending, now.AddMinutes(10)).Items.Single().Status == ApplicationRequestHistoryStatus.Expired, "request expiry");
        Reject(() => Read(pending, now.AddTicks(-1)));
        Reject(() => Read(pending, context: new AuthenticatedChildContext(owner.DeviceId, new WindowsAccountSid("S-1-5-21-11-22-33-1002"))));
        Check(Read(State(new[] { Track(Original(sid: "S-1-5-21-11-22-33-1002")), Track(Original(2, epoch: session.Offer.AuthorityEpoch + 1)) })).Items.Count == 0,
            "foreign account/epoch history leaked");
        var denied = Track(Original(), RelayRequestResolution.Denied);
        var allowed = Track(Original(), RelayRequestResolution.Allowed);
        Check(Read(State(new[] { denied }, Receipt(CommandReceiptStatus.Applied, ReconciliationStatus.Reconciled))).Items.Single().Status ==
            ApplicationRequestHistoryStatus.Denied, "deny interpreted as allow");
        Check(Read(State(new[] { allowed }, Receipt(CommandReceiptStatus.AcceptedPendingReconciliation, ReconciliationStatus.Pending))).Items.Single().Status ==
            ApplicationRequestHistoryStatus.AwaitingApplication, "interim interpreted as effect");
        Check(Read(State(new[] { allowed }, Receipt(CommandReceiptStatus.Applied, ReconciliationStatus.Reconciled)), now.AddDays(1)).Items.Single().Status ==
            ApplicationRequestHistoryStatus.AppliedPreviously, "historical apply changed to current permission");
        Check(Read(State(new[] { Track(Original()) }, Receipt(CommandReceiptStatus.Rejected, ReconciliationStatus.NotRequired))).Items.Single().Status ==
            ApplicationRequestHistoryStatus.NotApplied, "rejection lost");
        Reject(() => Read(State(new[] { denied })));
        Reject(() => Read(State(new[] { denied }, Receipt(CommandReceiptStatus.Applied, ReconciliationStatus.Reconciled, corrupt: true))));
        Reject(() => Read(State(new[] { denied }, Receipt(CommandReceiptStatus.Applied, ReconciliationStatus.Reconciled, metadataEpoch: session.Offer.AuthorityEpoch + 1))));
        Reject(() => Read(State(new[] { denied }, Receipt(CommandReceiptStatus.Applied, ReconciliationStatus.Reconciled, requestId: "other-request-0001"))));
        Reject(() => Read(State(new[] { denied }, Receipt(CommandReceiptStatus.Applied, ReconciliationStatus.Pending))));
        Reject(() => Read(State(new[] { denied }, Receipt(CommandReceiptStatus.Applied, ReconciliationStatus.Reconciled, processed: now.AddSeconds(1)))));
        var many = Read(State(Enumerable.Range(1, 20).Select(i => Track(Original(i))).ToArray()));
        Check(many.Items.Count == 16 && many.Items.Select(i => i.RequestId).SequenceEqual(many.Items.Select(i => i.RequestId).Order(StringComparer.Ordinal)), "history bounds/order");
        Check(Read(pending).Items.Single().Status == ApplicationRequestHistoryStatus.AwaitingResponse && pending.Version == 0, "read mutated state");
        Console.WriteLine("PASS child history: signed outcomes, exact account/epochs/originals, offline expiry, corruption/rollback refusals and no live-access claim");
    }
    private static void Check(bool value, string message) { if (!value) throw new InvalidOperationException(message); }
    private static void Reject(Action action)
    {
        try { action(); } catch (Exception e) when (e is InvalidDataException or ArgumentException) { return; }
        throw new InvalidOperationException("Unsafe history accepted.");
    }
}
