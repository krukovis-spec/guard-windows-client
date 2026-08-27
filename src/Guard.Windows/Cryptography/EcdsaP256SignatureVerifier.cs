using System;
using System.Security.Cryptography;
using Guard.Application;
using Guard.Domain;

namespace Guard.Windows.Cryptography
{
    /// <summary>
    /// Validates canonical P-256 SubjectPublicKeyInfo values and verifies
    /// SHA-256 hashes with fixed-width IEEE P1363 signatures.
    /// </summary>
    public sealed class EcdsaP256SignatureVerifier :
        ICommandSignatureVerifier,
        IParentTrustAnchorValidator
    {
        public const int Sha256HashBytes = 32;
        public const int P1363SignatureBytes = 64;
        public const int CanonicalSubjectPublicKeyInfoBytes = 91;

        private const string P256CurveOid = "1.2.840.10045.3.1.7";
        private static readonly byte[] P256Order = Convert.FromHexString(
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");

        public bool IsValid(ParentTrustAnchor trustAnchor)
        {
            if (trustAnchor == null ||
                trustAnchor.Algorithm != ParentKeyAlgorithm.EcdsaP256Sha256)
            {
                return false;
            }

            ECDsa? key = null;
            try
            {
                return TryImportCanonicalP256(
                    trustAnchor.GetSubjectPublicKeyInfoCopy(),
                    out key);
            }
            catch (ArgumentException)
            {
                return false;
            }
            catch (CryptographicException)
            {
                return false;
            }
            catch (PlatformNotSupportedException)
            {
                return false;
            }
            finally
            {
                key?.Dispose();
            }
        }

        public bool Verify(
            ParentTrustAnchor trustAnchor,
            byte[] canonicalHash,
            byte[] signature)
        {
            if (trustAnchor == null ||
                trustAnchor.Algorithm != ParentKeyAlgorithm.EcdsaP256Sha256 ||
                canonicalHash == null ||
                canonicalHash.Length != Sha256HashBytes ||
                signature == null ||
                signature.Length != P1363SignatureBytes ||
                !HasCanonicalSignatureScalars(signature))
            {
                return false;
            }

            ECDsa? key = null;
            try
            {
                if (!TryImportCanonicalP256(
                    trustAnchor.GetSubjectPublicKeyInfoCopy(),
                    out key) ||
                    key == null)
                {
                    return false;
                }

                return key.VerifyHash(
                    canonicalHash,
                    signature,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }
            catch (ArgumentException)
            {
                return false;
            }
            catch (CryptographicException)
            {
                return false;
            }
            catch (PlatformNotSupportedException)
            {
                return false;
            }
            finally
            {
                key?.Dispose();
            }
        }

        private static bool TryImportCanonicalP256(
            byte[] subjectPublicKeyInfo,
            out ECDsa? key)
        {
            key = null;
            if (subjectPublicKeyInfo.Length != CanonicalSubjectPublicKeyInfoBytes)
            {
                return false;
            }

            key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo, out var bytesRead);
            if (bytesRead != subjectPublicKeyInfo.Length || key.KeySize != 256)
            {
                return false;
            }

            var parameters = key.ExportParameters(includePrivateParameters: false);
            if (!string.Equals(
                    parameters.Curve.Oid.Value,
                    P256CurveOid,
                    StringComparison.Ordinal) ||
                parameters.Q.X == null ||
                parameters.Q.X.Length != Sha256HashBytes ||
                parameters.Q.Y == null ||
                parameters.Q.Y.Length != Sha256HashBytes)
            {
                return false;
            }

            var canonical = key.ExportSubjectPublicKeyInfo();
            return canonical.Length == subjectPublicKeyInfo.Length &&
                   CryptographicOperations.FixedTimeEquals(
                       canonical,
                       subjectPublicKeyInfo);
        }

        private static bool HasCanonicalSignatureScalars(byte[] signature)
        {
            return IsScalarInRange(signature, offset: 0) &&
                   IsScalarInRange(signature, offset: Sha256HashBytes);
        }

        private static bool IsScalarInRange(byte[] signature, int offset)
        {
            var nonZero = false;
            for (var index = 0; index < Sha256HashBytes; index++)
            {
                nonZero |= signature[offset + index] != 0;
            }

            if (!nonZero)
            {
                return false;
            }

            for (var index = 0; index < Sha256HashBytes; index++)
            {
                var value = signature[offset + index];
                var maximumExclusive = P256Order[index];
                if (value < maximumExclusive)
                {
                    return true;
                }

                if (value > maximumExclusive)
                {
                    return false;
                }
            }

            return false;
        }
    }
}
