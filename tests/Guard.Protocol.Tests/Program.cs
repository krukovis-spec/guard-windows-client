using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Guard.Contracts;
using Guard.Protocol;

namespace Guard.Protocol.Tests
{
    internal static class Program
    {
        private static int Main()
        {
            var tests = new List<(string Name, Action Run)>
            {
                ("canonical command encoding is deterministic", IsDeterministic),
                ("all signed metadata is bound into the hash", BindsMetadata),
                ("signature bytes are excluded from signed content", ExcludesSignatureBytes),
                ("invalid and oversized envelopes fail closed", RejectsInvalidEnvelope),
                ("parent decisions use a closed request-bound payload", RoundTripsParentDecisionPayload),
                ("child account binding uses a strict SID-only payload", RoundTripsChildBindingPayload),
                ("service operation payloads are bounded and versioned", RoundTripsServiceOperationPayloads),
                ("malformed service operation payloads fail closed", RejectsMalformedServiceOperationPayloads),
                ("IPC frames round-trip without polymorphic payloads", RoundTripsIpcFrame),
                ("IPC responses are bounded and request-correlated", RoundTripsIpcResponse),
                ("truncated and oversized IPC frames fail closed", RejectsInvalidIpcFrame),
                ("partial IPC frames honor cancellation", CancelsPartialIpcFrame),
                ("partial IPC frames cannot outlive their read budget", TimesOutPartialIpcFrame)
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
                    Console.WriteLine("FAIL " + test.Name + ": " + exception.Message);
                }
            }

            Console.WriteLine(failures == 0
                ? "All Guard.Protocol checks passed."
                : failures + " Guard.Protocol check(s) failed.");
            return failures == 0 ? 0 : 1;
        }

        private static void IsDeterministic()
        {
            var envelope = CreateEnvelope();
            var first = Convert.ToBase64String(CanonicalCommandEncoding.EncodeForSignature(envelope));
            var second = Convert.ToBase64String(CanonicalCommandEncoding.EncodeForSignature(envelope));
            AssertEqual(first, second, "Canonical output changed between runs.");
            AssertEqual(
                Convert.ToBase64String(CanonicalCommandEncoding.ComputeSignatureHash(envelope)),
                Convert.ToBase64String(CanonicalCommandEncoding.ComputeSignatureHash(envelope)),
                "Signature hash changed between runs.");
        }

        private static void BindsMetadata()
        {
            var baseline = Hash(CreateEnvelope());
            AssertDifferent(baseline, Hash(CreateEnvelope(commandId: "cmd-000000000002")), "Command id was not bound.");
            AssertDifferent(baseline, Hash(CreateEnvelope(deviceId: "device-v2-000002")), "Device id was not bound.");
            AssertDifferent(baseline, Hash(CreateEnvelope(sequence: 2)), "Sequence was not bound.");
            AssertDifferent(baseline, Hash(CreateEnvelope(issuedOffsetMinutes: 1)), "Issue time was not bound.");
            AssertDifferent(baseline, Hash(CreateEnvelope(expiryOffsetMinutes: 3)), "Expiry was not bound.");
            AssertDifferent(baseline, Hash(CreateEnvelope(nonce: "nonce-000000000002")), "Nonce was not bound.");
            AssertDifferent(baseline, Hash(CreateEnvelope(keyId: "parent-key-000002")), "Parent key id was not bound.");
            AssertDifferent(baseline, Hash(CreateEnvelope(payload: new byte[] { 1, 2, 4 })), "Payload was not bound.");
        }

        private static void ExcludesSignatureBytes()
        {
            var first = Hash(CreateEnvelope(signature: new byte[] { 1 }));
            var second = Hash(CreateEnvelope(signature: new byte[] { 9, 8, 7 }));
            AssertEqual(first, second, "Signature recursively changed signed content.");
        }

        private static void RejectsInvalidEnvelope()
        {
            AssertThrows(() => CanonicalCommandEncoding.EncodeForSignature(CreateEnvelope(sequence: 0)), "Zero sequence was accepted.");
            AssertThrows(() => CanonicalCommandEncoding.EncodeForSignature(CreateEnvelope(commandId: "x")), "Short id was accepted.");
            AssertThrows(() => CanonicalCommandEncoding.EncodeForSignature(CreateEnvelope(commandId: "cmd-000000000001-é")), "A non-canonical identifier was accepted.");
            AssertThrows(() => CanonicalCommandEncoding.EncodeForSignature(CreateEnvelope(extraTimestampTicks: 1)), "A sub-millisecond timestamp was accepted.");
            AssertThrows(() => CanonicalCommandEncoding.EncodeForSignature(CreateEnvelope(expiryOffsetMinutes: 0)), "Non-positive lifetime was accepted.");
            AssertThrows(
                () => CanonicalCommandEncoding.EncodeForSignature(CreateEnvelope(payload: new byte[GuardProtocol.MaximumFrameBytes + 1])),
                "Oversized payload was accepted.");
        }

        private static void RoundTripsIpcFrame()
        {
            var request = new GuardIpcRequest(
                GuardProtocol.CurrentVersion,
                "8f31a964-65d1-4f8f-91f7-5cf2ea3f7da3",
                GuardVerb.CreateApplicationRequest,
                new byte[] { 1, 2, 3, 4 });
            var encoded = IpcFrameCodec.Encode(request);
            var decoded = IpcFrameCodec.DecodeAsync(
                new MemoryStream(encoded),
                TimeSpan.FromMilliseconds(GuardProtocol.DefaultIpcReadTimeoutMilliseconds),
                CancellationToken.None).GetAwaiter().GetResult();
            AssertEqual(request.ProtocolVersion, decoded.ProtocolVersion, "Protocol version changed.");
            AssertEqual(request.RequestId, decoded.RequestId, "Request id changed.");
            AssertEqual(request.Verb, decoded.Verb, "Verb changed.");
            AssertEqual(Convert.ToBase64String(request.GetPayloadCopy()), Convert.ToBase64String(decoded.GetPayloadCopy()), "Payload changed.");
        }

        private static void RejectsInvalidIpcFrame()
        {
            var valid = IpcFrameCodec.Encode(new GuardIpcRequest(
                GuardProtocol.CurrentVersion,
                "8f31a964-65d1-4f8f-91f7-5cf2ea3f7da3",
                GuardVerb.GetStatus,
                new byte[] { 1 }));

            var truncated = new byte[valid.Length - 1];
            Array.Copy(valid, truncated, truncated.Length);
            AssertThrowsInvalidData(
                () => IpcFrameCodec.DecodeAsync(
                    new MemoryStream(truncated),
                    TimeSpan.FromMilliseconds(GuardProtocol.DefaultIpcReadTimeoutMilliseconds),
                    CancellationToken.None).GetAwaiter().GetResult(),
                "Truncated frame was accepted.");

            var tamperedLength = (byte[])valid.Clone();
            var lengthOffset = 4 + 4 + 36 + 4;
            tamperedLength[lengthOffset] = 0x00;
            tamperedLength[lengthOffset + 1] = 0x01;
            tamperedLength[lengthOffset + 2] = 0x00;
            tamperedLength[lengthOffset + 3] = 0x01;
            AssertThrowsInvalidData(
                () => IpcFrameCodec.DecodeAsync(
                    new MemoryStream(tamperedLength),
                    TimeSpan.FromMilliseconds(GuardProtocol.DefaultIpcReadTimeoutMilliseconds),
                    CancellationToken.None).GetAwaiter().GetResult(),
                "Oversized frame length was accepted.");
        }

        private static void RoundTripsParentDecisionPayload()
        {
            var first = new ParentDecisionCommand(
                "8f31a964-65d1-4f8f-91f7-5cf2ea3f7da3",
                GuardTargetKind.Application,
                "sha256:0123456789ABCDEF",
                ParentDecisionKind.AllowDailyQuota,
                dailyQuotaMinutes: 45);
            var encoded = ParentDecisionPayloadCodec.Encode(first);
            var decoded = ParentDecisionPayloadCodec.Decode(encoded);
            AssertEqual(first.RequestId, decoded.RequestId, "Request id changed.");
            AssertEqual(first.TargetKind, decoded.TargetKind, "Target kind changed.");
            AssertEqual(first.TargetIdentity, decoded.TargetIdentity, "Target identity changed.");
            AssertEqual(first.Decision, decoded.Decision, "Decision changed.");
            AssertEqual(first.DailyQuotaMinutes, decoded.DailyQuotaMinutes, "Daily quota changed.");

            var otherRequest = ParentDecisionPayloadCodec.Encode(new ParentDecisionCommand(
                "8f31a964-65d1-4f8f-91f7-5cf2ea3f7da4",
                GuardTargetKind.Application,
                first.TargetIdentity,
                first.Decision,
                dailyQuotaMinutes: 45));
            AssertDifferent(
                Convert.ToBase64String(encoded),
                Convert.ToBase64String(otherRequest),
                "Different access requests shared one parent-decision payload.");

            var withTrailingByte = new byte[encoded.Length + 1];
            Array.Copy(encoded, withTrailingByte, encoded.Length);
            AssertThrowsInvalidData(
                () => ParentDecisionPayloadCodec.Decode(withTrailingByte),
                "Trailing payload bytes were accepted as another schema.");
        }

        private static void RoundTripsChildBindingPayload()
        {
            var request = new BindChildAccountRequest("S-1-5-21-1001-2002-3003-1004");
            var encoded = BindChildAccountPayloadCodec.Encode(request);
            var decoded = BindChildAccountPayloadCodec.Decode(encoded);
            AssertEqual(request.CandidateSid, decoded.CandidateSid, "Child SID payload did not round-trip.");

            var trailing = new byte[encoded.Length + 1];
            Array.Copy(encoded, trailing, encoded.Length);
            AssertThrowsInvalidData(
                () => BindChildAccountPayloadCodec.Decode(trailing),
                "Trailing child-binding payload bytes were accepted.");

            var nonAscii = new BindChildAccountRequest("S-1-5-21-1001");
            var malformed = BindChildAccountPayloadCodec.Encode(nonAscii);
            malformed[malformed.Length - 1] = 0xFF;
            AssertThrowsInvalidData(
                () => BindChildAccountPayloadCodec.Decode(malformed),
                "Non-ASCII child SID bytes were accepted.");
        }

        private static void RoundTripsServiceOperationPayloads()
        {
            var status = GuardStatusPayloadCodec.Decode(
                GuardStatusPayloadCodec.Encode(
                    new GuardStatusPayload(
                        stateVersion: 7,
                        isProvisioned: true,
                        isChildAccountBound: false)));
            AssertEqual(7L, status.StateVersion, "Guard status version changed.");
            AssertEqual(true, status.IsProvisioned, "Guard provisioning status changed.");
            AssertEqual(false, status.IsChildAccountBound, "Guard child-binding status changed.");

            var secret = new byte[GuardProtocol.SetupSecretBytes];
            for (var index = 0; index < secret.Length; index++)
            {
                secret[index] = (byte)(index + 1);
            }

            var expiry = new DateTimeOffset(
                2026,
                7,
                23,
                12,
                5,
                0,
                TimeSpan.Zero);
            var ticket = SetupTicketPayloadCodec.Decode(
                SetupTicketPayloadCodec.Encode(
                    new SetupTicketPayload(
                        "setup:challenge-000001",
                        secret,
                        expiry)));
            AssertEqual(
                "setup:challenge-000001",
                ticket.ChallengeId,
                "Setup challenge id changed.");
            AssertEqual(
                expiry,
                ticket.ExpiresAtUtc,
                "Setup ticket expiry changed.");
            var decodedSecret = ticket.GetSecretCopy();
            AssertEqual(
                GuardProtocol.SetupSecretBytes,
                decodedSecret.Length,
                "Setup secret length changed.");
            AssertEqual(secret[0], decodedSecret[0], "Setup secret changed.");
            Array.Clear(decodedSecret, 0, decodedSecret.Length);
            Array.Clear(secret, 0, secret.Length);

            var binding = ChildAccountBindingPayloadCodec.Decode(
                ChildAccountBindingPayloadCodec.Encode(
                    new ChildAccountBindingPayload(
                        serviceRestartRequired: true)));
            AssertEqual(
                true,
                binding.ServiceRestartRequired,
                "Child binding restart requirement changed.");
        }

        private static void RejectsMalformedServiceOperationPayloads()
        {
            var status = GuardStatusPayloadCodec.Encode(
                new GuardStatusPayload(0, false, false));
            status[status.Length - 1] = 0x80;
            AssertThrowsInvalidData(
                () => GuardStatusPayloadCodec.Decode(status),
                "Unknown Guard status flags were accepted.");

            var secret = new byte[GuardProtocol.SetupSecretBytes];
            var ticket = SetupTicketPayloadCodec.Encode(
                new SetupTicketPayload(
                    "setup:challenge-000002",
                    secret,
                    DateTimeOffset.UtcNow.AddMinutes(5)));
            var trailing = new byte[ticket.Length + 1];
            Array.Copy(ticket, trailing, ticket.Length);
            AssertThrowsInvalidData(
                () => SetupTicketPayloadCodec.Decode(trailing),
                "Trailing setup ticket data was accepted.");
            Array.Clear(secret, 0, secret.Length);

            var binding = ChildAccountBindingPayloadCodec.Encode(
                new ChildAccountBindingPayload(
                    serviceRestartRequired: false));
            binding[binding.Length - 1] = 0x02;
            AssertThrowsInvalidData(
                () => ChildAccountBindingPayloadCodec.Decode(binding),
                "Unknown child-binding result flags were accepted.");
        }

        private static void RoundTripsIpcResponse()
        {
            var requestId = Guid.NewGuid().ToString("D");
            var response = new GuardIpcResponse(
                GuardProtocol.CurrentVersion,
                requestId,
                GuardIpcResponseStatus.Forbidden,
                new byte[] { 1, 2, 3 });
            var decoded = IpcResponseFrameCodec.Decode(IpcResponseFrameCodec.Encode(response));
            AssertEqual(requestId, decoded.RequestId, "IPC response lost request correlation.");
            AssertEqual(GuardIpcResponseStatus.Forbidden, decoded.Status, "IPC response status changed.");
            AssertEqual(3, decoded.PayloadLength, "IPC response payload changed.");

            var frame = IpcResponseFrameCodec.Encode(response);
            var trailing = new byte[frame.Length + 1];
            Array.Copy(frame, trailing, frame.Length);
            AssertThrowsInvalidData(
                () => IpcResponseFrameCodec.Decode(trailing),
                "Trailing IPC response bytes were accepted.");
        }

        private static void CancelsPartialIpcFrame()
        {
            using (var cancellation = new CancellationTokenSource())
            using (var stream = new PartialThenWaitingStream(new byte[] { 0x47, 0x49 }))
            {
                var decode = IpcFrameCodec.DecodeAsync(
                    stream,
                    TimeSpan.FromMilliseconds(GuardProtocol.DefaultIpcReadTimeoutMilliseconds),
                    cancellation.Token);
                cancellation.Cancel();
                AssertThrowsCanceled(() => decode.GetAwaiter().GetResult(), "A partial IPC frame ignored cancellation.");
            }
        }

        private static void TimesOutPartialIpcFrame()
        {
            using (var stream = new PartialThenWaitingStream(new byte[] { 0x47, 0x49 }))
            {
                var decode = IpcFrameCodec.DecodeAsync(
                    stream,
                    TimeSpan.FromMilliseconds(100),
                    CancellationToken.None);
                AssertThrowsCanceled(() => decode.GetAwaiter().GetResult(), "A partial IPC frame outlived its read budget.");
            }
        }

        private static string Hash(SignedCommandEnvelope envelope)
        {
            return Convert.ToBase64String(CanonicalCommandEncoding.ComputeSignatureHash(envelope));
        }

        private static SignedCommandEnvelope CreateEnvelope(
            string commandId = "cmd-000000000001",
            string deviceId = "device-v2-000001",
            long sequence = 1,
            int issuedOffsetMinutes = 0,
            int expiryOffsetMinutes = 2,
            string nonce = "nonce-000000000001",
            string keyId = "parent-key-000001",
            byte[]? payload = null,
            byte[]? signature = null,
            long extraTimestampTicks = 0)
        {
            var epoch = new DateTimeOffset(2026, 7, 23, 0, 0, 0, TimeSpan.Zero);
            return new SignedCommandEnvelope(
                commandId,
                deviceId,
                sequence,
                epoch.AddMinutes(issuedOffsetMinutes).AddTicks(extraTimestampTicks),
                epoch.AddMinutes(expiryOffsetMinutes).AddTicks(extraTimestampTicks),
                nonce,
                keyId,
                payload ?? new byte[] { 1, 2, 3 },
                signature ?? new byte[] { 5, 6, 7 });
        }

        private static void AssertDifferent(string left, string right, string message)
        {
            if (string.Equals(left, right, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(message);
            }
        }

        private static void AssertEqual<T>(T expected, T actual, string message)
        {
            if (!EqualityComparer<T>.Default.Equals(expected, actual))
            {
                throw new InvalidOperationException(message);
            }
        }

        private static void AssertThrows(Action action, string message)
        {
            try
            {
                action();
            }
            catch (ArgumentException)
            {
                return;
            }

            throw new InvalidOperationException(message);
        }

        private static void AssertThrowsInvalidData(Action action, string message)
        {
            try
            {
                action();
            }
            catch (InvalidDataException)
            {
                return;
            }
            catch (EndOfStreamException)
            {
                return;
            }

            throw new InvalidOperationException(message);
        }

        private static void AssertThrowsCanceled(Action action, string message)
        {
            try
            {
                action();
            }
            catch (OperationCanceledException)
            {
                return;
            }

            throw new InvalidOperationException(message);
        }

        private sealed class PartialThenWaitingStream : Stream
        {
            private readonly byte[] _prefix;
            private bool _prefixReturned;

            public PartialThenWaitingStream(byte[] prefix)
            {
                _prefix = prefix;
            }

            public override bool CanRead => true;

            public override bool CanSeek => false;

            public override bool CanWrite => false;

            public override long Length => throw new NotSupportedException();

            public override long Position
            {
                get => throw new NotSupportedException();
                set => throw new NotSupportedException();
            }

            public override void Flush()
            {
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                throw new NotSupportedException();
            }

            public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            {
                if (!_prefixReturned)
                {
                    _prefixReturned = true;
                    Array.Copy(_prefix, 0, buffer, offset, _prefix.Length);
                    return Task.FromResult(_prefix.Length);
                }

                var completion = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
                cancellationToken.Register(() => completion.TrySetCanceled(cancellationToken));
                return completion.Task;
            }

            public override long Seek(long offset, SeekOrigin origin)
            {
                throw new NotSupportedException();
            }

            public override void SetLength(long value)
            {
                throw new NotSupportedException();
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                throw new NotSupportedException();
            }
        }
    }
}
