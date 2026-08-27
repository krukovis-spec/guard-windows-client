using System;
using System.Collections.Generic;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Principal;
using Guard.Domain;
using Guard.Windows.Cryptography;

namespace Guard.Windows.Crypto.Tests
{
    internal static class Program
    {
        private const string AlternatePurpose =
            "guard-v2-authoritative-state-crypto-test";

        private static int Main()
        {
            var tests = new List<(string Name, Action Run)>
            {
                ("P-256 canonical SPKI and P1363 signature verify", VerifiesCanonicalP256Signature),
                ("non-P256 and noncanonical SPKI fail closed", RejectsInvalidPublicKeys),
                ("malformed and out-of-range signatures fail closed", RejectsInvalidSignatures),
                ("DPAPI CurrentUser round-trips without mutating input", RoundTripsDpapiCurrentUser),
                ("DPAPI purpose mismatch and tampering fail closed", RejectsWrongPurposeAndTampering),
                ("production protector requires LocalSystem", RequiresLocalSystemForProduction),
                ("DPAPI purposes and payloads are bounded", RejectsInvalidDpapiInputs)
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
                    ? "All Guard.Windows cryptography checks passed."
                    : failures + " Guard.Windows cryptography check(s) failed.");
            return failures == 0 ? 0 : 1;
        }

        private static void VerifiesCanonicalP256Signature()
        {
            using (var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                var subjectPublicKeyInfo = signer.ExportSubjectPublicKeyInfo();
                AssertEqual(
                    EcdsaP256SignatureVerifier.CanonicalSubjectPublicKeyInfoBytes,
                    subjectPublicKeyInfo.Length,
                    "The platform emitted an unexpected P-256 SPKI.");
                var anchor = new ParentTrustAnchor(
                    ParentKeyAlgorithm.EcdsaP256Sha256,
                    subjectPublicKeyInfo);
                var hash = SHA256.HashData(new byte[] { 1, 2, 3, 4 });
                var signature = signer.SignHash(
                    hash,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                var verifier = new EcdsaP256SignatureVerifier();

                Assert(verifier.IsValid(anchor), "A canonical P-256 key was rejected.");
                Assert(
                    verifier.Verify(anchor, hash, signature),
                    "A valid P-256/P1363 signature was rejected.");

                var differentHash = (byte[])hash.Clone();
                differentHash[0] ^= 0x80;
                Assert(
                    !verifier.Verify(anchor, differentHash, signature),
                    "A signature verified a different hash.");
            }
        }

        private static void RejectsInvalidPublicKeys()
        {
            var verifier = new EcdsaP256SignatureVerifier();
            using (var wrongCurve = ECDsa.Create(ECCurve.NamedCurves.nistP384))
            {
                var anchor = new ParentTrustAnchor(
                    ParentKeyAlgorithm.EcdsaP256Sha256,
                    wrongCurve.ExportSubjectPublicKeyInfo());
                Assert(!verifier.IsValid(anchor), "A P-384 key was accepted as P-256.");
            }

            using (var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                var canonical = signer.ExportSubjectPublicKeyInfo();
                var withTrailingData = new byte[canonical.Length + 1];
                Buffer.BlockCopy(canonical, 0, withTrailingData, 0, canonical.Length);
                var trailingDataAnchor = new ParentTrustAnchor(
                    ParentKeyAlgorithm.EcdsaP256Sha256,
                    withTrailingData);
                Assert(
                    !verifier.IsValid(trailingDataAnchor),
                    "A SPKI with trailing data was accepted.");
            }

            var malformed = new ParentTrustAnchor(
                ParentKeyAlgorithm.EcdsaP256Sha256,
                new byte[EcdsaP256SignatureVerifier.CanonicalSubjectPublicKeyInfoBytes]);
            Assert(!verifier.IsValid(malformed), "A malformed SPKI was accepted.");
        }

        private static void RejectsInvalidSignatures()
        {
            using (var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                var anchor = new ParentTrustAnchor(
                    ParentKeyAlgorithm.EcdsaP256Sha256,
                    signer.ExportSubjectPublicKeyInfo());
                var hash = SHA256.HashData(new byte[] { 9, 8, 7 });
                var verifier = new EcdsaP256SignatureVerifier();
                var signature = signer.SignHash(
                    hash,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                var derSignature = signer.SignHash(
                    hash,
                    DSASignatureFormat.Rfc3279DerSequence);

                Assert(
                    !verifier.Verify(anchor, new byte[31], signature),
                    "A non-SHA256 hash was accepted.");
                Assert(
                    !verifier.Verify(anchor, hash, derSignature),
                    "A DER signature was accepted as canonical P1363.");
                Assert(
                    !verifier.Verify(anchor, hash, new byte[64]),
                    "A signature with zero scalars was accepted.");
                var zeroS = new byte[64];
                zeroS[31] = 1;
                Assert(
                    !verifier.Verify(anchor, hash, zeroS),
                    "A signature with a zero S scalar was accepted.");

                var p256Order = Convert.FromHexString(
                    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
                var orderAsR = new byte[64];
                Buffer.BlockCopy(p256Order, 0, orderAsR, 0, p256Order.Length);
                orderAsR[63] = 1;
                Assert(
                    !verifier.Verify(anchor, hash, orderAsR),
                    "An R scalar equal to the curve order was accepted.");
                var orderAsS = new byte[64];
                orderAsS[31] = 1;
                Buffer.BlockCopy(
                    p256Order,
                    0,
                    orderAsS,
                    EcdsaP256SignatureVerifier.Sha256HashBytes,
                    p256Order.Length);
                Assert(
                    !verifier.Verify(anchor, hash, orderAsS),
                    "An S scalar equal to the curve order was accepted.");

                var changedSignature = (byte[])signature.Clone();
                changedSignature[changedSignature.Length - 1] ^= 0x01;
                Assert(
                    !verifier.Verify(anchor, hash, changedSignature),
                    "A modified signature was accepted.");
            }
        }

        private static void RoundTripsDpapiCurrentUser()
        {
            RequireWindows();
            var protector = CreateCurrentIdentityTestProtector(
                LocalSystemDpapiDataProtector.DefaultPurpose);
            var plaintext = new byte[] { 7, 0, 9, 4, 1, 2 };
            var original = (byte[])plaintext.Clone();
            byte[]? protectedData = null;
            byte[]? roundTrip = null;
            try
            {
                protectedData = protector.Protect(plaintext);
                roundTrip = protector.Unprotect(protectedData);

                AssertSequenceEqual(original, plaintext, "Protect mutated its input.");
                AssertSequenceEqual(original, roundTrip, "DPAPI changed the plaintext.");
                Assert(
                    !SequenceEqual(plaintext, protectedData),
                    "DPAPI returned plaintext as protected data.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
                CryptographicOperations.ZeroMemory(original);
                if (protectedData != null)
                {
                    CryptographicOperations.ZeroMemory(protectedData);
                }

                if (roundTrip != null)
                {
                    CryptographicOperations.ZeroMemory(roundTrip);
                }
            }
        }

        private static void RejectsWrongPurposeAndTampering()
        {
            RequireWindows();
            var primary = CreateCurrentIdentityTestProtector(
                LocalSystemDpapiDataProtector.DefaultPurpose);
            var alternate = CreateCurrentIdentityTestProtector(AlternatePurpose);
            var plaintext = new byte[] { 4, 5, 6, 7 };
            byte[]? protectedData = null;
            byte[]? tampered = null;
            try
            {
                var protectedPayload = primary.Protect(plaintext);
                protectedData = protectedPayload;
                AssertThrows<CryptographicException>(
                    () => alternate.Unprotect(protectedPayload),
                    "A different purpose decrypted protected state.");

                tampered = (byte[])protectedPayload.Clone();
                tampered[tampered.Length / 2] ^= 0x80;
                AssertThrows<CryptographicException>(
                    () => primary.Unprotect(tampered),
                    "Tampered protected state was accepted.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
                if (protectedData != null)
                {
                    CryptographicOperations.ZeroMemory(protectedData);
                }

                if (tampered != null)
                {
                    CryptographicOperations.ZeroMemory(tampered);
                }
            }
        }

        private static void RequiresLocalSystemForProduction()
        {
            RequireWindows();
            using (var identity = WindowsIdentity.GetCurrent(ifImpersonating: false))
            {
                if (identity == null)
                {
                    throw new InvalidOperationException(
                        "Windows did not expose the effective identity.");
                }

                var userSid = identity.User;
                if (userSid != null &&
                    userSid.IsWellKnown(WellKnownSidType.LocalSystemSid))
                {
                    return;
                }
            }

            var production = new LocalSystemDpapiDataProtector();
            AssertThrows<UnauthorizedAccessException>(
                () => production.Protect(new byte[] { 1 }),
                "Production DPAPI ran outside LocalSystem.");
        }

        private static void RejectsInvalidDpapiInputs()
        {
            RequireWindows();
            var protector = CreateCurrentIdentityTestProtector(
                LocalSystemDpapiDataProtector.DefaultPurpose);
            AssertThrows<ArgumentException>(
                () => protector.Protect(Array.Empty<byte>()),
                "An empty plaintext was accepted.");
            AssertThrows<ArgumentException>(
                () => protector.Protect(
                    new byte[LocalSystemDpapiDataProtector.MaximumPlaintextBytes + 1]),
                "An oversized plaintext was accepted.");
            AssertThrows<ArgumentException>(
                () => protector.Unprotect(Array.Empty<byte>()),
                "Empty protected data was accepted.");
            AssertThrows<ArgumentException>(
                () => protector.Unprotect(
                    new byte[LocalSystemDpapiDataProtector.MaximumProtectedBytes + 1]),
                "Oversized protected data was accepted.");
            AssertThrows<ArgumentException>(
                () => new LocalSystemDpapiDataProtector("purpose with spaces"),
                "A noncanonical purpose was accepted.");
        }

        private static LocalSystemDpapiDataProtector CreateCurrentIdentityTestProtector(
            string purpose)
        {
            var constructor = typeof(LocalSystemDpapiDataProtector).GetConstructor(
                BindingFlags.Instance | BindingFlags.NonPublic,
                binder: null,
                types: new[] { typeof(string), typeof(bool) },
                modifiers: null);
            if (constructor == null)
            {
                throw new InvalidOperationException(
                    "The DPAPI test constructor is unavailable.");
            }

            var instance = constructor.Invoke(new object[] { purpose, true })
                as LocalSystemDpapiDataProtector;
            return instance ?? throw new InvalidOperationException(
                "The DPAPI test constructor returned no protector.");
        }

        private static void RequireWindows()
        {
            if (!OperatingSystem.IsWindows())
            {
                throw new PlatformNotSupportedException(
                    "These DPAPI checks require Windows.");
            }
        }

        private static bool SequenceEqual(byte[] left, byte[] right)
        {
            return left.Length == right.Length &&
                   CryptographicOperations.FixedTimeEquals(left, right);
        }

        private static void AssertSequenceEqual(
            byte[] expected,
            byte[] actual,
            string message)
        {
            if (!SequenceEqual(expected, actual))
            {
                throw new InvalidOperationException(message);
            }
        }

        private static void AssertEqual<T>(T expected, T actual, string message)
        {
            if (!EqualityComparer<T>.Default.Equals(expected, actual))
            {
                throw new InvalidOperationException(
                    message + " Expected=" + expected + " Actual=" + actual);
            }
        }

        private static void Assert(bool condition, string message)
        {
            if (!condition)
            {
                throw new InvalidOperationException(message);
            }
        }

        private static void AssertThrows<TException>(
            Action action,
            string message)
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
