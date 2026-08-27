using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Guard.Windows.Cryptography;

namespace Guard.Windows.RelayCrypto.Tests
{
    internal static class Program
    {
        private static int Main()
        {
            var tests = new List<(string Name, Action Run)>
            {
                ("RFC 9180 P-256/AES-256-GCM vector decrypts exactly", DecryptsRfcVector),
                ("relay HPKE round-trips", RoundTrips),
                ("wrong recipient key fails closed", RejectsWrongRecipientKey),
                ("wrong associated data fails closed", RejectsWrongAssociatedData),
                ("wrong HPKE info fails closed", RejectsWrongInfo),
                ("modified ciphertext fails closed", RejectsModifiedCiphertext),
                ("malformed encapsulated keys fail closed", RejectsMalformedEncapsulatedKey),
                ("truncated input and bounds fail closed", RejectsTruncationAndBounds)
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
                    Console.WriteLine("FAIL " + test.Name + ": " + exception);
                }
            }

            Console.WriteLine(
                failures == 0
                    ? "All Guard.Windows relay cryptography checks passed."
                    : failures + " Guard.Windows relay cryptography check(s) failed.");
            return failures == 0 ? 0 : 1;
        }

        private static void DecryptsRfcVector()
        {
            // CFRG HPKE test-vector corpus, pinned at commit
            // 5f503c564da00b0687b3de75f1dfbdfc4079ad31, mode 0 /
            // KEM 0x0010 / KDF 0x0001 / AEAD 0x0002, encryption 0.
            var plaintext = RelayCryptography.Decrypt(
                Hex("317f915db7bc629c48fe765587897e01e282d3e8445f79f27f65d031a88082b2"),
                Hex("04abc7e49a4c6b3566d77d0304addc6ed0e98512ffccf505e6a8e3eb25c685136f853148544876de76c0f2ef99cdc3a05ccf5ded7860c7c021238f9e2073d2356c"),
                Hex("04c06b4f6bebc7bb495cb797ab753f911aff80aefb86fd8b6fcc35525f3ab5f03e0b21bd31a86c6048af3cb2d98e0d3bf01da5cc4c39ff5370d331a4f1f7d5a4e0"),
                Hex("58c61a45059d0c5704560e9d88b564a8b63f1364b8d1fcb3c4c6ddc1d291742465e902cd216f8908da49f8f96f"),
                Hex("436f756e742d30"),
                Hex("4f6465206f6e2061204772656369616e2055726e"));

            AssertSequenceEqual(
                Hex("4265617574792069732074727574682c20747275746820626561757479"),
                plaintext,
                "The pinned RFC 9180 vector did not decrypt exactly.");
        }

        private static void RoundTrips()
        {
            using (var recipient = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256))
            {
                var parameters = recipient.ExportParameters(includePrivateParameters: true);
                var recipientPublicKey = Serialize(parameters.Q);
                var plaintext = Hex("00010203040506070809");
                var associatedData = Hex("aabbccdd");
                var ciphertext = RelayCryptography.Encrypt(
                    recipientPublicKey,
                    plaintext,
                    associatedData,
                    out var encapsulatedKey);
                var recovered = RelayCryptography.Decrypt(
                    parameters.D!,
                    recipientPublicKey,
                    encapsulatedKey,
                    ciphertext,
                    associatedData);

                AssertSequenceEqual(plaintext, recovered, "HPKE changed the plaintext.");
                AssertEqual(
                    RelayCryptography.EncapsulatedKeyBytes,
                    encapsulatedKey.Length,
                    "HPKE did not emit a 65-byte encapsulated key.");
                AssertEqual(
                    plaintext.Length + RelayCryptography.TagBytes,
                    ciphertext.Length,
                    "HPKE did not append the GCM tag.");
                AssertSequenceEqual(
                    recipientPublicKey,
                    Serialize(recipient.ExportParameters(false).Q),
                    "The test recipient key was unstable.");
            }
        }

        private static void RejectsWrongRecipientKey()
        {
            using (var intended = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256))
            using (var different = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256))
            {
                var plaintext = new byte[] { 1, 2, 3 };
                var aad = new byte[] { 4, 5 };
                var ciphertext = RelayCryptography.Encrypt(
                    Serialize(intended.ExportParameters(false).Q),
                    plaintext,
                    aad,
                    out var encapsulatedKey);
                AssertThrows<CryptographicException>(
                    () => RelayCryptography.Decrypt(
                        different.ExportParameters(true).D!,
                        Serialize(different.ExportParameters(false).Q),
                        encapsulatedKey,
                        ciphertext,
                        aad),
                    "A different recipient key decrypted the ciphertext.");
            }
        }

        private static void RejectsWrongAssociatedData()
        {
            WithCiphertext((privateKey, publicKey, encapsulatedKey, ciphertext, _) =>
            {
                AssertThrows<CryptographicException>(
                    () => RelayCryptography.Decrypt(
                        privateKey,
                        publicKey,
                        encapsulatedKey,
                        ciphertext,
                        new byte[] { 0xff }),
                    "Different AAD decrypted the ciphertext.");
            });
        }

        private static void RejectsWrongInfo()
        {
            using (var recipient = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256))
            {
                var parameters = recipient.ExportParameters(includePrivateParameters: true);
                var publicKey = Serialize(parameters.Q);
                var ciphertext = RelayCryptography.Encrypt(
                    publicKey,
                    new byte[] { 1, 2, 3 },
                    new byte[] { 4, 5 },
                    new byte[] { 6 },
                    out var encapsulatedKey);
                AssertThrows<CryptographicException>(
                    () => RelayCryptography.Decrypt(
                        parameters.D!,
                        publicKey,
                        encapsulatedKey,
                        ciphertext,
                        new byte[] { 4, 5 },
                        new byte[] { 7 }),
                    "Different HPKE info decrypted the ciphertext.");
            }
        }

        private static void RejectsModifiedCiphertext()
        {
            WithCiphertext((privateKey, publicKey, encapsulatedKey, ciphertext, associatedData) =>
            {
                ciphertext[ciphertext.Length - 1] ^= 0x80;
                AssertThrows<CryptographicException>(
                    () => RelayCryptography.Decrypt(
                        privateKey,
                        publicKey,
                        encapsulatedKey,
                        ciphertext,
                        associatedData),
                    "Modified ciphertext decrypted.");
            });
        }

        private static void RejectsMalformedEncapsulatedKey()
        {
            WithCiphertext((privateKey, publicKey, encapsulatedKey, ciphertext, associatedData) =>
            {
                AssertThrows<ArgumentException>(
                    () => RelayCryptography.Decrypt(
                        privateKey,
                        publicKey,
                        new byte[64],
                        ciphertext,
                        associatedData),
                    "A short encapsulated key was accepted.");
                encapsulatedKey[0] = 0x02;
                AssertThrows<ArgumentException>(
                    () => RelayCryptography.Decrypt(
                        privateKey,
                        publicKey,
                        encapsulatedKey,
                        ciphertext,
                        associatedData),
                    "A compressed SEC1 encapsulated key was accepted.");
            });
        }

        private static void RejectsTruncationAndBounds()
        {
            WithCiphertext((privateKey, publicKey, encapsulatedKey, ciphertext, associatedData) =>
            {
                AssertThrows<ArgumentException>(
                    () => RelayCryptography.Decrypt(
                        privateKey,
                        publicKey,
                        encapsulatedKey,
                        new byte[RelayCryptography.TagBytes - 1],
                        associatedData),
                    "A truncated ciphertext was accepted.");
                AssertThrows<ArgumentException>(
                    () => RelayCryptography.Encrypt(
                        new byte[RelayCryptography.PublicKeyBytes - 1],
                        Array.Empty<byte>(),
                        Array.Empty<byte>(),
                        out _),
                    "A short recipient key was accepted.");
                using (var recipient = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256))
                {
                    AssertThrows<ArgumentException>(
                        () => RelayCryptography.Encrypt(
                            Serialize(recipient.ExportParameters(false).Q),
                            new byte[RelayCryptography.MaximumPlaintextBytes + 1],
                            Array.Empty<byte>(),
                            out _),
                        "An oversized plaintext was accepted.");
                }
            });
        }

        private static void WithCiphertext(
            Action<byte[], byte[], byte[], byte[], byte[]> action)
        {
            using (var recipient = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256))
            {
                var parameters = recipient.ExportParameters(includePrivateParameters: true);
                var associatedData = new byte[] { 6, 7 };
                var ciphertext = RelayCryptography.Encrypt(
                    Serialize(parameters.Q),
                    new byte[] { 8, 9, 10 },
                    associatedData,
                    out var encapsulatedKey);
                action(
                    parameters.D!,
                    Serialize(parameters.Q),
                    encapsulatedKey,
                    ciphertext,
                    associatedData);
            }
        }

        private static byte[] Serialize(ECPoint point)
        {
            var value = new byte[RelayCryptography.PublicKeyBytes];
            value[0] = 0x04;
            Buffer.BlockCopy(point.X!, 0, value, 1, RelayCryptography.PrivateKeyBytes);
            Buffer.BlockCopy(point.Y!, 0, value, 33, RelayCryptography.PrivateKeyBytes);
            return value;
        }

        private static byte[] Hex(string value)
        {
            return Convert.FromHexString(value);
        }

        private static void AssertSequenceEqual(
            byte[] expected,
            byte[] actual,
            string message)
        {
            if (expected.Length != actual.Length ||
                !CryptographicOperations.FixedTimeEquals(expected, actual))
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

        private static void AssertThrows<TException>(Action action, string message)
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

            throw new InvalidOperationException(message);
        }
    }
}
