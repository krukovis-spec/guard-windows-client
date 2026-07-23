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
                ("IPC frames round-trip without polymorphic payloads", RoundTripsIpcFrame),
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
