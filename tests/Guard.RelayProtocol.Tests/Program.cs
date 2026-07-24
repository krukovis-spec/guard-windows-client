using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using Guard.Contracts.Relay;
using Guard.Protocol.Relay;

namespace Guard.RelayProtocol.Tests
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            try
            {
                var emitVectors =
                    args.Length == 1 &&
                    string.Equals(
                        args[0],
                        "--emit-vectors",
                        StringComparison.Ordinal);
                var golden = ReadGoldenVectors();
                var snapshot = Snapshot();
                var encodedSnapshot = RelayCanonicalEncoding.EncodeRequestSnapshot(snapshot);
                var hash = RelayCanonicalEncoding.ComputeRequestSnapshotHash(snapshot);
                Require(RelayCanonicalEncoding.DecodeRequestSnapshot(encodedSnapshot).DeviceEventId == "event-alpha-000001", "snapshot");
                Require(
                    RelayCanonicalEncoding.DecodeRequestSnapshot(
                        encodedSnapshot).AuthorityEpoch == 4,
                    "snapshot authority epoch");
                if (!emitVectors)
                {
                    Require(Hex(encodedSnapshot) == golden["REQUEST_HEX"], "request bytes golden");
                    Require(Hex(hash) == golden["REQUEST_SHA256"], "request hash golden");
                }
                var invalidUtf8 = (byte[])encodedSnapshot.Clone();
                invalidUtf8[12] = 0xc3;
                invalidUtf8[13] = 0x28;
                Expect(() => RelayCanonicalEncoding.DecodeRequestSnapshot(invalidUtf8), "invalid utf8");
                var unknownKind = (byte[])encodedSnapshot.Clone();
                unknownKind[99] = 3;
                Expect(() => RelayCanonicalEncoding.DecodeRequestSnapshot(unknownKind), "unknown target kind");

                var device = new DeviceSignedRequestEnvelope(snapshot, "device-key-alpha01", Bytes(64, 7));
                Require(RelayCanonicalEncoding.DecodeDeviceRequestEnvelope(RelayCanonicalEncoding.EncodeDeviceRequestEnvelope(device)).DeviceKeyId == device.DeviceKeyId, "device request");

                var approval = Approval(hash);
                var encodedApproval = RelayCanonicalEncoding.EncodeApprovalEnvelope(approval);
                Require(RelayCanonicalEncoding.DecodeApprovalEnvelope(encodedApproval).DurationMinutes == 60, "approval");
                if (!emitVectors)
                {
                    Require(Hex(encodedApproval) == golden["APPROVAL_HEX"], "approval bytes golden");
                    Require(Hex(RelayCanonicalEncoding.ComputeApprovalHash(approval)) == golden["APPROVAL_SIGNATURE_INPUT_SHA256"], "approval hash golden");
                }
                Expect(() => RelayCanonicalEncoding.EncodeDeviceRequestEnvelope(new DeviceSignedRequestEnvelope(snapshot, "device-key-alpha01", Bytes(63, 1))), "63 signature");
                Expect(() => RelayCanonicalEncoding.EncodeDeviceRequestEnvelope(new DeviceSignedRequestEnvelope(snapshot, "device-key-alpha01", Bytes(65, 1))), "65 signature");
                var receipt = new CommandReceipt("device-alpha-0001", 2, 4, "parent-key-alpha1", 7, "command-alpha-001", "request-alpha-001", 3, CommandReceiptStatus.AcceptedPendingReconciliation, At(4), RelayCanonicalEncoding.ComputeApprovalHash(approval), 10, ReconciliationStatus.Pending, "pending-reconcile");
                var receiptEnvelope = new DeviceSignedCommandReceiptEnvelope(receipt, "device-key-alpha01", Bytes(64, 11));
                var decodedReceiptEnvelope =
                    RelayCanonicalEncoding.DecodeDeviceReceiptEnvelope(
                        RelayCanonicalEncoding.EncodeDeviceReceiptEnvelope(
                            receiptEnvelope));
                Require(
                    decodedReceiptEnvelope.Receipt.Sequence == 7 &&
                    decodedReceiptEnvelope.Receipt.AuthorityEpoch == 4,
                    "receipt");
                VerifyRealP256Signatures(snapshot, approval, receipt);

                var frame = new RelayFrame(RelayFrameKind.Approval, "mailbox-alpha-0001", "recipient-key-0001", "frame-alpha-00001", 11, 10, At(3), At(4), Bytes(65, 1), Bytes(32, 101));
                var encodedFrame = RelayCanonicalEncoding.EncodeRelayFrame(frame);
                Require(RelayCanonicalEncoding.DecodeRelayFrame(encodedFrame).MailboxId == frame.MailboxId, "frame");
                if (!emitVectors)
                {
                    Require(Hex(encodedFrame) == golden["FRAME_HEX"], "frame bytes golden");
                }
                Require(Hex(RelayCanonicalEncoding.EncodeRelayFrameAssociatedData(frame)) != Hex(RelayCanonicalEncoding.EncodeRelayFrameAssociatedData(new RelayFrame(RelayFrameKind.Approval, "mailbox-alpha-0001", "recipient-key-0001", "frame-alpha-00001", 12, 10, At(3), At(4), Bytes(65, 1), Bytes(32, 101)))), "aad cursor binding");
                Expect(() => RelayCanonicalEncoding.EncodeRelayFrame(new RelayFrame(RelayFrameKind.Approval, "mailbox-alpha-0001", "recipient-key-0001", "frame-alpha-00001", 11, 10, At(3), At(4), Bytes(64, 1), Bytes(32, 101))), "enc length");
                Expect(() => RelayCanonicalEncoding.EncodeRelayFrame(new RelayFrame(RelayFrameKind.Approval, "mailbox-alpha-0001", "recipient-key-0001", "frame-alpha-00001", 11, 10, At(3), At(4), Bytes(65, 1), Bytes(15, 101))), "tag length");

                Expect(() => RelayCanonicalEncoding.DecodeRelayFrame(Append(encodedFrame, 0)), "trailing");
                Expect(() => RelayCanonicalEncoding.DecodeRelayFrame(Cut(encodedFrame)), "truncated");
                Expect(() => RelayCanonicalEncoding.EncodeRelayFrame(new RelayFrame(RelayFrameKind.Request, "mailbox-alpha-0001", "recipient-key-0001", "frame-alpha-00001", 1, 2, At(1), At(2), Bytes(1, 1), Bytes(1, 2))), "ack");
                Expect(() => RelayCanonicalEncoding.EncodeRelayFrame(new RelayFrame(RelayFrameKind.Request, "mailbox-alpha-0001", "recipient-key-0001", "frame-alpha-00001", 1, 0, At(2), At(1), Bytes(1, 1), Bytes(1, 2))), "expiry");
                Expect(() => RelayCanonicalEncoding.EncodeApprovalEnvelope(Approval(hash, ParentDecisionKind.AllowAlways, 1)), "duration");
                Expect(() => RelayCanonicalEncoding.EncodeApprovalEnvelope(Approval(hash, ParentDecisionKind.AllowTemporary, 0)), "duration zero");
                var changed = approval.GetDecisionChallengeCopy();
                changed[0] ^= 1;
                Require(Hex(RelayCanonicalEncoding.ComputeApprovalHash(new SignedApprovalEnvelope(4, "parent-key-alpha1", 7, "command-alpha-001", "nonce-alpha-00001", At(3), At(4), "device-alpha-0001", 2, "request-alpha-001", 3, hash, changed, RelayTargetKind.Website, "https://example.test/path", 9, ParentDecisionKind.AllowTemporary, 60, Bytes(64, 9)))) != Hex(RelayCanonicalEncoding.ComputeApprovalHash(approval)), "challenge binding");
                var otherHash = (byte[])hash.Clone();
                otherHash[0] ^= 1;
                Require(Hex(RelayCanonicalEncoding.ComputeApprovalHash(Approval(otherHash))) != Hex(RelayCanonicalEncoding.ComputeApprovalHash(approval)), "hash binding");
                var otherAuthoritySnapshot = new RequestSnapshot(
                    snapshot.DeviceId,
                    snapshot.DeviceEpoch,
                    snapshot.AuthorityEpoch + 1,
                    snapshot.DeviceEventId,
                    snapshot.RequestId,
                    snapshot.RequestRevision,
                    snapshot.TargetKind,
                    snapshot.CanonicalTargetIdentity,
                    snapshot.DisplayEvidence,
                    snapshot.ChildReason,
                    snapshot.CreatedAtUtc,
                    snapshot.PendingExpiresAtUtc,
                    snapshot.GetDecisionChallengeCopy(),
                    snapshot.PolicyRevision);
                Require(
                    Hex(
                        RelayCanonicalEncoding.ComputeRequestSnapshotHash(
                            otherAuthoritySnapshot)) != Hex(hash),
                    "authority epoch binding");
                Require(Hex(RelayCanonicalEncoding.ComputeApprovalHash(new SignedApprovalEnvelope(4, "parent-key-alpha1", 7, "command-alpha-001", "nonce-alpha-00001", At(3), At(4), "device-alpha-0001", 2, "request-alpha-001", 3, hash, Bytes(32, 1), RelayTargetKind.Application, "app.test", 9, ParentDecisionKind.AllowTemporary, 60, Bytes(64, 9)))) != Hex(RelayCanonicalEncoding.ComputeApprovalHash(approval)), "target binding");
                var copy = frame.GetCiphertextCopy();
                copy[0] = 0;
                Require(frame.GetCiphertextCopy()[0] == 101, "copy");

                Console.WriteLine("REQUEST_HEX=" + Hex(encodedSnapshot));
                Console.WriteLine("REQUEST_SHA256=" + Hex(hash));
                Console.WriteLine("APPROVAL_HEX=" + Hex(encodedApproval));
                Console.WriteLine("APPROVAL_SHA256=" + Hex(RelayCanonicalEncoding.ComputeApprovalHash(approval)));
                Console.WriteLine("FRAME_HEX=" + Hex(encodedFrame));
                Console.WriteLine("PASS Guard.RelayProtocol.Tests");
                return 0;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e);
                return 1;
            }
        }
        private static RequestSnapshot Snapshot()
        {
            return new RequestSnapshot("device-alpha-0001", 2, 4, "event-alpha-000001", "request-alpha-001", 3, RelayTargetKind.Website, "https://example.test/path", new List<RelayEvidenceField> { new RelayEvidenceField("host", "example.test") }, "homework", At(1), At(2), Bytes(32, 1), 9);
        }

        private static SignedApprovalEnvelope Approval(byte[] h, ParentDecisionKind d = ParentDecisionKind.AllowTemporary, int m = 60)
        {
            return new SignedApprovalEnvelope(4, "parent-key-alpha1", 7, "command-alpha-001", "nonce-alpha-00001", At(3), At(4), "device-alpha-0001", 2, "request-alpha-001", 3, h, Bytes(32, 1), RelayTargetKind.Website, "https://example.test/path", 9, d, m, Bytes(64, 9));
        }

        private static void VerifyRealP256Signatures(
            RequestSnapshot snapshot,
            SignedApprovalEnvelope approval,
            CommandReceipt receipt)
        {
            using (var signingKey = ECDsa.Create(
                ECCurve.NamedCurves.nistP256))
            {
                var unsignedRequest = new DeviceSignedRequestEnvelope(
                    snapshot,
                    "device-key-alpha01",
                    new byte[64]);
                var requestHash =
                    RelayCanonicalEncoding.ComputeDeviceRequestHash(
                        unsignedRequest);
                var requestSignature = signingKey.SignHash(
                    requestHash,
                    DSASignatureFormat
                        .IeeeP1363FixedFieldConcatenation);
                var signedRequest = new DeviceSignedRequestEnvelope(
                    snapshot,
                    "device-key-alpha01",
                    requestSignature);
                var decodedRequest =
                    RelayCanonicalEncoding.DecodeDeviceRequestEnvelope(
                        RelayCanonicalEncoding.EncodeDeviceRequestEnvelope(
                            signedRequest));
                Require(
                    signingKey.VerifyHash(
                        RelayCanonicalEncoding
                            .ComputeDeviceRequestHash(decodedRequest),
                        decodedRequest.GetSignatureP1363Copy(),
                        DSASignatureFormat
                            .IeeeP1363FixedFieldConcatenation),
                    "real device request signature");

                var approvalSignature = signingKey.SignHash(
                    RelayCanonicalEncoding.ComputeApprovalHash(approval),
                    DSASignatureFormat
                        .IeeeP1363FixedFieldConcatenation);
                var signedApproval = CopyApproval(
                    approval,
                    approvalSignature);
                var decodedApproval =
                    RelayCanonicalEncoding.DecodeApprovalEnvelope(
                        RelayCanonicalEncoding.EncodeApprovalEnvelope(
                            signedApproval));
                Require(
                    signingKey.VerifyHash(
                        RelayCanonicalEncoding.ComputeApprovalHash(
                            decodedApproval),
                        decodedApproval.GetSignatureP1363Copy(),
                        DSASignatureFormat
                            .IeeeP1363FixedFieldConcatenation),
                    "real approval signature");

                var unsignedReceipt =
                    new DeviceSignedCommandReceiptEnvelope(
                        receipt,
                        "device-key-alpha01",
                        new byte[64]);
                var receiptSignature = signingKey.SignHash(
                    RelayCanonicalEncoding.ComputeDeviceReceiptHash(
                        unsignedReceipt),
                    DSASignatureFormat
                        .IeeeP1363FixedFieldConcatenation);
                var signedReceipt =
                    new DeviceSignedCommandReceiptEnvelope(
                        receipt,
                        "device-key-alpha01",
                        receiptSignature);
                var decodedReceipt =
                    RelayCanonicalEncoding.DecodeDeviceReceiptEnvelope(
                        RelayCanonicalEncoding.EncodeDeviceReceiptEnvelope(
                            signedReceipt));
                Require(
                    signingKey.VerifyHash(
                        RelayCanonicalEncoding
                            .ComputeDeviceReceiptHash(decodedReceipt),
                        decodedReceipt.GetSignatureP1363Copy(),
                        DSASignatureFormat
                            .IeeeP1363FixedFieldConcatenation),
                    "real device receipt signature");

                var mutatedSignature =
                    decodedApproval.GetSignatureP1363Copy();
                mutatedSignature[0] ^= 1;
                Require(
                    !signingKey.VerifyHash(
                        RelayCanonicalEncoding.ComputeApprovalHash(
                            decodedApproval),
                        mutatedSignature,
                        DSASignatureFormat
                            .IeeeP1363FixedFieldConcatenation),
                    "mutated approval signature");
            }
        }

        private static SignedApprovalEnvelope CopyApproval(
            SignedApprovalEnvelope source,
            byte[] signature)
        {
            return new SignedApprovalEnvelope(
                source.AuthorityEpoch,
                source.KeyId,
                source.Sequence,
                source.CommandId,
                source.Nonce,
                source.IssuedAtUtc,
                source.ExpiresAtUtc,
                source.DeviceId,
                source.DeviceEpoch,
                source.RequestId,
                source.RequestRevision,
                source.GetRequestSnapshotHashCopy(),
                source.GetDecisionChallengeCopy(),
                source.TargetKind,
                source.CanonicalTargetIdentity,
                source.PolicyRevision,
                source.Decision,
                source.DurationMinutes,
                signature);
        }

        private static DateTimeOffset At(int n)
        {
            return new DateTimeOffset(2026, 7, 24, 12, 0, n, TimeSpan.Zero);
        }

        private static byte[] Bytes(int n, int s)
        {
            var x = new byte[n];
            for (var i = 0; i < n; i++)
            {
                x[i] = (byte)(s + i);
            }

            return x;
        }

        private static byte[] Append(byte[] x, byte b)
        {
            var r = new byte[x.Length + 1];
            Buffer.BlockCopy(x, 0, r, 0, x.Length);
            r[x.Length] = b;
            return r;
        }

        private static byte[] Cut(byte[] x)
        {
            var r = new byte[x.Length - 1];
            Buffer.BlockCopy(x, 0, r, 0, r.Length);
            return r;
        }

        private static string Hex(byte[] x)
        {
            return Convert.ToHexString(x).ToLowerInvariant();
        }

        private static IReadOnlyDictionary<string, string> ReadGoldenVectors()
        {
            var result = new Dictionary<string, string>(StringComparer.Ordinal);
            var path = Path.Combine(AppContext.BaseDirectory, "relay-v1.hex");
            foreach (var line in File.ReadAllLines(path))
            {
                var separator = line.IndexOf('=');
                if (separator <= 0 || separator == line.Length - 1)
                {
                    throw new InvalidDataException("The relay golden-vector file is malformed.");
                }

                result.Add(
                    line.Substring(0, separator),
                    line.Substring(separator + 1));
            }

            Require(result.Count == 5, "golden vector count");
            return result;
        }

        private static void Require(bool x, string n)
        {
            if (!x)
            {
                throw new InvalidOperationException(n);
            }
        }

        private static void Expect(Action x, string n)
        {
            try
            {
                x();
            }
            catch (ArgumentException)
            {
                return;
            }

            throw new InvalidOperationException(n);
        }
    }
}
