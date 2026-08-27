using System;
using System.Security.Cryptography;
using Guard.Contracts;

namespace Guard.Domain
{
    public enum ParentKeyAlgorithm
    {
        EcdsaP256Sha256 = 1
    }

    public sealed class ParentTrustAnchor : IEquatable<ParentTrustAnchor>
    {
        private const int MinimumSubjectPublicKeyInfoBytes = 64;
        private readonly byte[] _subjectPublicKeyInfo;

        public ParentTrustAnchor(ParentKeyAlgorithm algorithm, byte[] subjectPublicKeyInfo)
        {
            if (!Enum.IsDefined(typeof(ParentKeyAlgorithm), algorithm))
            {
                throw new ArgumentOutOfRangeException(nameof(algorithm));
            }

            if (subjectPublicKeyInfo == null ||
                subjectPublicKeyInfo.Length < MinimumSubjectPublicKeyInfoBytes ||
                subjectPublicKeyInfo.Length > GuardProtocol.MaximumParentPublicKeyBytes)
            {
                throw new ArgumentException("A bounded public-key value is required.", nameof(subjectPublicKeyInfo));
            }

            Algorithm = algorithm;
            _subjectPublicKeyInfo = (byte[])subjectPublicKeyInfo.Clone();
            KeyId = CreateKeyId(algorithm, _subjectPublicKeyInfo);
        }

        public ParentKeyAlgorithm Algorithm { get; }

        public string KeyId { get; }

        public byte[] GetSubjectPublicKeyInfoCopy()
        {
            return (byte[])_subjectPublicKeyInfo.Clone();
        }

        public bool Equals(ParentTrustAnchor? other)
        {
            if (other == null || Algorithm != other.Algorithm ||
                !string.Equals(KeyId, other.KeyId, StringComparison.Ordinal) ||
                _subjectPublicKeyInfo.Length != other._subjectPublicKeyInfo.Length)
            {
                return false;
            }

            var difference = 0;
            for (var index = 0; index < _subjectPublicKeyInfo.Length; index++)
            {
                difference |= _subjectPublicKeyInfo[index] ^ other._subjectPublicKeyInfo[index];
            }

            return difference == 0;
        }

        public override bool Equals(object? obj)
        {
            return Equals(obj as ParentTrustAnchor);
        }

        public override int GetHashCode()
        {
            return StringComparer.Ordinal.GetHashCode(KeyId);
        }

        private static string CreateKeyId(ParentKeyAlgorithm algorithm, byte[] subjectPublicKeyInfo)
        {
            byte[] fingerprint;
            using (var sha256 = SHA256.Create())
            {
                fingerprint = sha256.ComputeHash(subjectPublicKeyInfo);
            }

            var prefix = algorithm == ParentKeyAlgorithm.EcdsaP256Sha256 ? "p256:" : "key:";
            var encoded = Convert.ToBase64String(fingerprint)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
            var keyId = prefix + encoded;
            if (!GuardIdentifier.IsCanonicalToken(keyId))
            {
                throw new InvalidOperationException("The derived parent key id is not canonical.");
            }

            return keyId;
        }
    }
}
