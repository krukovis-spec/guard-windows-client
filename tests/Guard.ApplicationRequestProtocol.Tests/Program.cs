using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using Guard.Contracts;
using Guard.Protocol;

namespace Guard.ApplicationRequestProtocol.Tests
{
    internal static class Program
    {
        private const string ObservationId =
            "observation:blocked-000001";

        private static int Main()
        {
            var tests = new List<(string Name, Action Run)>
            {
                ("round-trips request without a reason", RoundTripsWithoutReason),
                ("round-trips strict UTF-8 reason", RoundTripsUtf8Reason),
                ("rejects malformed magic", RejectsMalformedMagic),
                ("rejects unsupported version", RejectsUnsupportedVersion),
                ("rejects malformed UTF-8", RejectsMalformedUtf8),
                ("rejects invalid lengths", RejectsInvalidLengths),
                ("rejects trailing bytes", RejectsTrailingBytes),
                ("rejects oversized payload", RejectsOversizedPayload),
                ("validates optional short reason", ValidatesShortReason),
                ("exposes no asserted application identity", ExposesNoAssertedIdentity),
                ("decodes from a defensive snapshot", DecodesFromDefensiveSnapshot)
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
                    ? "All application request protocol checks passed."
                    : failures +
                      " application request protocol check(s) failed.");
            return failures == 0 ? 0 : 1;
        }

        private static void RoundTripsWithoutReason()
        {
            var request =
                new CreateApplicationRequestPayload(
                    ObservationId,
                    null);
            var encoded =
                ApplicationRequestPayloadCodec.Encode(request);
            var decoded =
                ApplicationRequestPayloadCodec.Decode(encoded);

            AssertEqual(
                ObservationId,
                decoded.ObservationId,
                "Observation id changed.");
            AssertEqual<string?>(
                null,
                decoded.ShortReason,
                "An absent reason became present.");
            Assert(
                encoded.Length <=
                    ApplicationRequestPayloadLimits
                        .MaximumPayloadBytes,
                "Encoder exceeded its application payload budget.");
        }

        private static void RoundTripsUtf8Reason()
        {
            const string reason =
                "Приложение заблокировано политикой 🛡";
            var decoded = ApplicationRequestPayloadCodec.Decode(
                ApplicationRequestPayloadCodec.Encode(
                    new CreateApplicationRequestPayload(
                        ObservationId,
                        reason)));

            AssertEqual(
                reason,
                decoded.ShortReason,
                "The strict UTF-8 reason changed.");
        }

        private static void RejectsMalformedMagic()
        {
            var encoded = ValidPayload("Blocked");
            encoded[0] ^= 0x01;
            ThrowsInvalidData(
                () => ApplicationRequestPayloadCodec.Decode(encoded),
                "Malformed magic was accepted.");
        }

        private static void RejectsUnsupportedVersion()
        {
            var encoded = ValidPayload("Blocked");
            WriteInt32(encoded, 4, GuardProtocol.CurrentVersion + 1);
            ThrowsInvalidData(
                () => ApplicationRequestPayloadCodec.Decode(encoded),
                "An unsupported version was accepted.");
        }

        private static void RejectsMalformedUtf8()
        {
            var encoded = ValidPayload("x");
            var observationLength = ReadInt32(encoded, 8);
            var reasonOffset = 16 + observationLength;
            encoded[reasonOffset] = 0xFF;
            ThrowsInvalidData(
                () => ApplicationRequestPayloadCodec.Decode(encoded),
                "Malformed UTF-8 was accepted.");
        }

        private static void RejectsInvalidLengths()
        {
            var negativeObservation = ValidPayload("Blocked");
            WriteInt32(negativeObservation, 8, -1);
            ThrowsInvalidData(
                () =>
                    ApplicationRequestPayloadCodec.Decode(
                        negativeObservation),
                "A negative observation length was accepted.");

            var zeroObservation = ValidPayload("Blocked");
            WriteInt32(zeroObservation, 8, 0);
            ThrowsInvalidData(
                () =>
                    ApplicationRequestPayloadCodec.Decode(
                        zeroObservation),
                "An empty observation was accepted.");

            var excessiveObservation = ValidPayload("Blocked");
            WriteInt32(
                excessiveObservation,
                8,
                GuardIdentifier.MaximumCharacters + 1);
            ThrowsInvalidData(
                () =>
                    ApplicationRequestPayloadCodec.Decode(
                        excessiveObservation),
                "An excessive observation length was accepted.");

            var zeroReason = ValidPayload("Blocked");
            WriteInt32(zeroReason, 12, 0);
            ThrowsInvalidData(
                () =>
                    ApplicationRequestPayloadCodec.Decode(
                        zeroReason),
                "An empty present reason was accepted.");

            var invalidAbsentReason = ValidPayload("Blocked");
            WriteInt32(invalidAbsentReason, 12, -2);
            ThrowsInvalidData(
                () =>
                    ApplicationRequestPayloadCodec.Decode(
                        invalidAbsentReason),
                "An invalid absent-reason marker was accepted.");

            var excessiveReason = ValidPayload("Blocked");
            WriteInt32(
                excessiveReason,
                12,
                ApplicationRequestPayloadLimits
                    .MaximumShortReasonUtf8Bytes + 1);
            ThrowsInvalidData(
                () =>
                    ApplicationRequestPayloadCodec.Decode(
                        excessiveReason),
                "An excessive reason length was accepted.");

            var truncated = ValidPayload("Blocked");
            Array.Resize(ref truncated, truncated.Length - 1);
            ThrowsInvalidData(
                () => ApplicationRequestPayloadCodec.Decode(truncated),
                "A truncated payload was accepted.");
        }

        private static void RejectsTrailingBytes()
        {
            var encoded = ValidPayload(null);
            var trailing = new byte[encoded.Length + 1];
            Array.Copy(encoded, trailing, encoded.Length);
            ThrowsInvalidData(
                () => ApplicationRequestPayloadCodec.Decode(trailing),
                "A trailing byte was accepted.");
        }

        private static void RejectsOversizedPayload()
        {
            var oversized = new byte[
                ApplicationRequestPayloadLimits.MaximumPayloadBytes + 1];
            ThrowsInvalidData(
                () => ApplicationRequestPayloadCodec.Decode(oversized),
                "An oversized payload was accepted.");
        }

        private static void ValidatesShortReason()
        {
            ThrowsArgument(
                () =>
                    new CreateApplicationRequestPayload(
                        ObservationId,
                        string.Empty),
                "An empty reason was accepted.");
            ThrowsArgument(
                () =>
                    new CreateApplicationRequestPayload(
                        ObservationId,
                        "   "),
                "A whitespace-only reason was accepted.");
            ThrowsArgument(
                () =>
                    new CreateApplicationRequestPayload(
                        ObservationId,
                        " leading"),
                "A reason with leading whitespace was accepted.");
            ThrowsArgument(
                () =>
                    new CreateApplicationRequestPayload(
                        ObservationId,
                        "line\nbreak"),
                "A control character was accepted in the reason.");
            ThrowsArgument(
                () =>
                    new CreateApplicationRequestPayload(
                        ObservationId,
                        "safe\u202Etxt"),
                "A bidirectional formatting character was accepted.");
            ThrowsArgument(
                () =>
                    new CreateApplicationRequestPayload(
                        ObservationId,
                        new string(
                            'x',
                            ApplicationRequestPayloadLimits
                                .MaximumShortReasonCharacters + 1)),
                "An oversized reason was accepted.");
            ThrowsArgument(
                () =>
                    new CreateApplicationRequestPayload(
                        ObservationId,
                        "\uD800"),
                "An unpaired surrogate was accepted.");

            var maximum = new string(
                'я',
                ApplicationRequestPayloadLimits
                    .MaximumShortReasonCharacters);
            var decoded = ApplicationRequestPayloadCodec.Decode(
                ApplicationRequestPayloadCodec.Encode(
                    new CreateApplicationRequestPayload(
                        ObservationId,
                        maximum)));
            AssertEqual(
                maximum,
                decoded.ShortReason,
                "A valid maximum-length reason changed.");
        }

        private static void ExposesNoAssertedIdentity()
        {
            var publicProperties =
                typeof(CreateApplicationRequestPayload)
                    .GetProperties(
                        BindingFlags.Instance |
                        BindingFlags.Public)
                    .Select(property => property.Name)
                    .OrderBy(name => name, StringComparer.Ordinal)
                    .ToArray();
            var expected =
                new[] { "ObservationId", "ShortReason" };
            Array.Sort(expected, StringComparer.Ordinal);

            AssertEqual(
                string.Join(",", expected),
                string.Join(",", publicProperties),
                "The child payload exposes an asserted identity field.");

            var forbiddenFragments = new[]
            {
                "Path",
                "Hash",
                "Publisher",
                "Package",
                "Pfn",
                "Sid",
                "Device",
                "Child",
                "Identity"
            };
            foreach (var property in publicProperties)
            {
                foreach (var forbidden in forbiddenFragments)
                {
                    Assert(
                        property.IndexOf(
                            forbidden,
                            StringComparison.OrdinalIgnoreCase) < 0,
                        "Forbidden identity field exposed: " +
                        property);
                }
            }
        }

        private static void DecodesFromDefensiveSnapshot()
        {
            var encoded = ValidPayload("Blocked");
            var decoded =
                ApplicationRequestPayloadCodec.Decode(encoded);
            Array.Clear(encoded, 0, encoded.Length);

            AssertEqual(
                ObservationId,
                decoded.ObservationId,
                "Decoded data retained the caller's mutable buffer.");
            AssertEqual(
                "Blocked",
                decoded.ShortReason,
                "Decoded reason retained the caller's mutable buffer.");
        }

        private static byte[] ValidPayload(string? reason)
        {
            return ApplicationRequestPayloadCodec.Encode(
                new CreateApplicationRequestPayload(
                    ObservationId,
                    reason));
        }

        private static int ReadInt32(byte[] bytes, int offset)
        {
            return (bytes[offset] << 24) |
                   (bytes[offset + 1] << 16) |
                   (bytes[offset + 2] << 8) |
                   bytes[offset + 3];
        }

        private static void WriteInt32(
            byte[] bytes,
            int offset,
            int value)
        {
            bytes[offset] =
                (byte)((value >> 24) & 0xFF);
            bytes[offset + 1] =
                (byte)((value >> 16) & 0xFF);
            bytes[offset + 2] =
                (byte)((value >> 8) & 0xFF);
            bytes[offset + 3] =
                (byte)(value & 0xFF);
        }

        private static void ThrowsArgument(
            Action action,
            string message)
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

        private static void ThrowsInvalidData(
            Action action,
            string message)
        {
            try
            {
                action();
            }
            catch (InvalidDataException)
            {
                return;
            }

            throw new InvalidOperationException(message);
        }

        private static void Assert(
            bool condition,
            string message)
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
            if (!EqualityComparer<T>.Default.Equals(
                    expected,
                    actual))
            {
                throw new InvalidOperationException(message);
            }
        }
    }
}
