using System;
using System.Security.Cryptography;

namespace Guard.Windows.Cryptography
{
    /// <summary>
    /// RFC 9180 Base-mode HPKE for the fixed Guard relay ciphersuite:
    /// DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM.
    /// </summary>
    public static class RelayCryptography
    {
        public const ushort KemId = 0x0010;
        public const ushort KdfId = 0x0001;
        public const ushort AeadId = 0x0002;
        public const int PrivateKeyBytes = 32;
        public const int PublicKeyBytes = 65;
        public const int EncapsulatedKeyBytes = 65;
        public const int KeyBytes = 32;
        public const int NonceBytes = 12;
        public const int TagBytes = 16;
        public const int MaximumPlaintextBytes = 1024 * 1024;
        public const int MaximumAssociatedDataBytes = 64 * 1024;

        private static readonly ECCurve P256 = ECCurve.NamedCurves.nistP256;
        private static readonly byte[] KemSuiteId =
            { 0x4b, 0x45, 0x4d, 0x00, 0x10 };
        private static readonly byte[] HpkeSuiteId =
            { 0x48, 0x50, 0x4b, 0x45, 0x00, 0x10, 0x00, 0x01, 0x00, 0x02 };
        private static readonly byte[] HpkeVersion =
            { 0x48, 0x50, 0x4b, 0x45, 0x2d, 0x76, 0x31 };

        public static byte[] Encrypt(
            byte[] recipientPublicKey,
            byte[] plaintext,
            byte[] associatedData,
            out byte[] encapsulatedKey)
        {
            return Encrypt(
                recipientPublicKey,
                plaintext,
                associatedData,
                Array.Empty<byte>(),
                out encapsulatedKey);
        }

        public static byte[] Encrypt(
            byte[] recipientPublicKey,
            byte[] plaintext,
            byte[] associatedData,
            byte[] info,
            out byte[] encapsulatedKey)
        {
            ValidatePublicKey(recipientPublicKey, nameof(recipientPublicKey));
            ValidateMessageInput(plaintext, nameof(plaintext), MaximumPlaintextBytes);
            ValidateMessageInput(
                associatedData,
                nameof(associatedData),
                MaximumAssociatedDataBytes);
            ValidateMessageInput(info, nameof(info), MaximumAssociatedDataBytes);

            using (var recipient = ImportPublicKey(recipientPublicKey))
            using (var ephemeral = ECDiffieHellman.Create(P256))
            {
                var encapsulated = SerializePublicKey(ephemeral);
                byte[]? sharedSecret = null;
                byte[]? key = null;
                byte[]? nonce = null;
                try
                {
                    sharedSecret = Encap(
                        ephemeral,
                        recipient.PublicKey,
                        encapsulated,
                        recipientPublicKey);
                    DeriveContext(sharedSecret, info, out key, out nonce);
                    var ciphertext = new byte[plaintext.Length + TagBytes];
                    using (var aes = new AesGcm(key, TagBytes))
                    {
                        aes.Encrypt(
                            nonce,
                            plaintext,
                            ciphertext.AsSpan(0, plaintext.Length),
                            ciphertext.AsSpan(plaintext.Length, TagBytes),
                            associatedData);
                    }

                    encapsulatedKey = encapsulated;
                    return ciphertext;
                }
                finally
                {
                    Zero(sharedSecret);
                    Zero(key);
                    Zero(nonce);
                }
            }
        }

        public static byte[] Decrypt(
            byte[] recipientPrivateKey,
            byte[] recipientPublicKey,
            byte[] encapsulatedKey,
            byte[] ciphertext,
            byte[] associatedData)
        {
            return Decrypt(
                recipientPrivateKey,
                recipientPublicKey,
                encapsulatedKey,
                ciphertext,
                associatedData,
                Array.Empty<byte>());
        }

        public static byte[] Decrypt(
            byte[] recipientPrivateKey,
            byte[] recipientPublicKey,
            byte[] encapsulatedKey,
            byte[] ciphertext,
            byte[] associatedData,
            byte[] info)
        {
            ValidatePrivateKey(recipientPrivateKey, nameof(recipientPrivateKey));
            ValidatePublicKey(recipientPublicKey, nameof(recipientPublicKey));
            ValidatePublicKey(encapsulatedKey, nameof(encapsulatedKey));
            ValidateCiphertext(ciphertext);
            ValidateMessageInput(
                associatedData,
                nameof(associatedData),
                MaximumAssociatedDataBytes);
            ValidateMessageInput(info, nameof(info), MaximumAssociatedDataBytes);

            using (var recipient = ImportPrivateKey(recipientPrivateKey, recipientPublicKey))
            using (var ephemeral = ImportPublicKey(encapsulatedKey))
            {
                byte[]? sharedSecret = null;
                byte[]? key = null;
                byte[]? nonce = null;
                var plaintext = new byte[ciphertext.Length - TagBytes];
                try
                {
                    sharedSecret = Decap(
                        recipient,
                        ephemeral.PublicKey,
                        encapsulatedKey,
                        recipientPublicKey);
                    DeriveContext(sharedSecret, info, out key, out nonce);
                    using (var aes = new AesGcm(key, TagBytes))
                    {
                        aes.Decrypt(
                            nonce,
                            ciphertext.AsSpan(0, plaintext.Length),
                            ciphertext.AsSpan(plaintext.Length, TagBytes),
                            plaintext,
                            associatedData);
                    }

                    return plaintext;
                }
                catch
                {
                    Zero(plaintext);
                    throw;
                }
                finally
                {
                    Zero(sharedSecret);
                    Zero(key);
                    Zero(nonce);
                }
            }
        }

        private static byte[] Encap(
            ECDiffieHellman ephemeral,
            ECDiffieHellmanPublicKey recipient,
            byte[] encapsulatedKey,
            byte[] recipientPublicKey)
        {
            var dh = ephemeral.DeriveRawSecretAgreement(recipient);
            try
            {
                return ExtractAndExpand(dh, Concat(encapsulatedKey, recipientPublicKey));
            }
            finally
            {
                Zero(dh);
            }
        }

        private static byte[] Decap(
            ECDiffieHellman recipient,
            ECDiffieHellmanPublicKey ephemeral,
            byte[] encapsulatedKey,
            byte[] recipientPublicKey)
        {
            var dh = recipient.DeriveRawSecretAgreement(ephemeral);
            try
            {
                return ExtractAndExpand(dh, Concat(encapsulatedKey, recipientPublicKey));
            }
            finally
            {
                Zero(dh);
            }
        }

        private static byte[] ExtractAndExpand(byte[] dh, byte[] kemContext)
        {
            byte[]? eaePrk = null;
            try
            {
                eaePrk = LabeledExtract(KemSuiteId, Array.Empty<byte>(), "eae_prk", dh);
                return LabeledExpand(
                    KemSuiteId,
                    eaePrk,
                    "shared_secret",
                    kemContext,
                    KeyBytes);
            }
            finally
            {
                Zero(eaePrk);
                Zero(kemContext);
            }
        }

        private static void DeriveContext(
            byte[] sharedSecret,
            byte[] info,
            out byte[] key,
            out byte[] nonce)
        {
            byte[]? pskIdHash = null;
            byte[]? infoHash = null;
            byte[]? context = null;
            byte[]? secret = null;
            try
            {
                pskIdHash = LabeledExtract(
                    HpkeSuiteId,
                    Array.Empty<byte>(),
                    "psk_id_hash",
                    Array.Empty<byte>());
                infoHash = LabeledExtract(
                    HpkeSuiteId,
                    Array.Empty<byte>(),
                    "info_hash",
                    info);
                context = Concat(new byte[] { 0 }, pskIdHash, infoHash);
                secret = LabeledExtract(
                    HpkeSuiteId,
                    sharedSecret,
                    "secret",
                    Array.Empty<byte>());
                key = LabeledExpand(HpkeSuiteId, secret, "key", context, KeyBytes);
                nonce = LabeledExpand(
                    HpkeSuiteId,
                    secret,
                    "base_nonce",
                    context,
                    NonceBytes);
            }
            finally
            {
                Zero(pskIdHash);
                Zero(infoHash);
                Zero(context);
                Zero(secret);
            }
        }

        private static byte[] LabeledExtract(
            byte[] suiteId,
            byte[] salt,
            string label,
            byte[] inputKeyMaterial)
        {
            var labeledIkm = Concat(HpkeVersion, suiteId, Ascii(label), inputKeyMaterial);
            try
            {
                return HMACSHA256.HashData(salt, labeledIkm);
            }
            finally
            {
                Zero(labeledIkm);
            }
        }

        private static byte[] LabeledExpand(
            byte[] suiteId,
            byte[] pseudorandomKey,
            string label,
            byte[] info,
            int length)
        {
            var labeledInfo = Concat(
                LengthPrefix(length),
                HpkeVersion,
                suiteId,
                Ascii(label),
                info);
            try
            {
                return HkdfExpand(pseudorandomKey, labeledInfo, length);
            }
            finally
            {
                Zero(labeledInfo);
            }
        }

        private static byte[] HkdfExpand(byte[] pseudorandomKey, byte[] info, int length)
        {
            if (length < 0 || length > 255 * KeyBytes)
            {
                throw new ArgumentOutOfRangeException(nameof(length));
            }

            var output = new byte[length];
            var previous = Array.Empty<byte>();
            var offset = 0;
            try
            {
                for (var counter = 1; offset < length; counter++)
                {
                    var input = Concat(previous, info, new byte[] { (byte)counter });
                    try
                    {
                        previous = HMACSHA256.HashData(pseudorandomKey, input);
                    }
                    finally
                    {
                        Zero(input);
                    }

                    var count = Math.Min(previous.Length, length - offset);
                    Buffer.BlockCopy(previous, 0, output, offset, count);
                    offset += count;
                }

                return output;
            }
            finally
            {
                Zero(previous);
            }
        }

        private static ECDiffieHellman ImportPublicKey(byte[] serializedPublicKey)
        {
            var parameters = new ECParameters
            {
                Curve = P256,
                Q = new ECPoint
                {
                    X = CopyPart(serializedPublicKey, 1),
                    Y = CopyPart(serializedPublicKey, 33)
                }
            };
            return ECDiffieHellman.Create(parameters);
        }

        private static ECDiffieHellman ImportPrivateKey(
            byte[] privateKey,
            byte[] publicKey)
        {
            return ECDiffieHellman.Create(new ECParameters
            {
                Curve = P256,
                D = (byte[])privateKey.Clone(),
                Q = new ECPoint
                {
                    X = CopyPart(publicKey, 1),
                    Y = CopyPart(publicKey, 33)
                }
            });
        }

        private static byte[] SerializePublicKey(ECDiffieHellman key)
        {
            var parameters = key.ExportParameters(includePrivateParameters: false);
            if (parameters.Q.X == null || parameters.Q.X.Length != PrivateKeyBytes ||
                parameters.Q.Y == null || parameters.Q.Y.Length != PrivateKeyBytes)
            {
                throw new CryptographicException("P-256 public key is invalid.");
            }

            var serialized = new byte[PublicKeyBytes];
            serialized[0] = 0x04;
            Buffer.BlockCopy(parameters.Q.X, 0, serialized, 1, PrivateKeyBytes);
            Buffer.BlockCopy(parameters.Q.Y, 0, serialized, 33, PrivateKeyBytes);
            return serialized;
        }

        private static void ValidatePrivateKey(byte[] value, string name)
        {
            if (value == null || value.Length != PrivateKeyBytes)
            {
                throw new ArgumentException("A P-256 private key must be 32 bytes.", name);
            }
        }

        private static void ValidatePublicKey(byte[] value, string name)
        {
            if (value == null || value.Length != PublicKeyBytes || value[0] != 0x04)
            {
                throw new ArgumentException(
                    "A P-256 public key must be an uncompressed SEC1 point.",
                    name);
            }
        }

        private static void ValidateCiphertext(byte[] ciphertext)
        {
            if (ciphertext == null || ciphertext.Length < TagBytes ||
                ciphertext.Length > MaximumPlaintextBytes + TagBytes)
            {
                throw new ArgumentException("Ciphertext has an invalid length.", nameof(ciphertext));
            }
        }

        private static void ValidateMessageInput(byte[] value, string name, int maximumLength)
        {
            if (value == null || value.Length > maximumLength)
            {
                throw new ArgumentException("Input has an invalid length.", name);
            }
        }

        private static byte[] CopyPart(byte[] source, int offset)
        {
            var result = new byte[PrivateKeyBytes];
            Buffer.BlockCopy(source, offset, result, 0, result.Length);
            return result;
        }

        private static byte[] Ascii(string value)
        {
            var bytes = new byte[value.Length];
            for (var index = 0; index < value.Length; index++)
            {
                bytes[index] = (byte)value[index];
            }

            return bytes;
        }

        private static byte[] LengthPrefix(int length)
        {
            return new[] { (byte)(length >> 8), (byte)length };
        }

        private static byte[] Concat(params byte[][] parts)
        {
            var length = 0;
            foreach (var part in parts)
            {
                length += part.Length;
            }

            var result = new byte[length];
            var offset = 0;
            foreach (var part in parts)
            {
                Buffer.BlockCopy(part, 0, result, offset, part.Length);
                offset += part.Length;
            }

            return result;
        }

        private static void Zero(byte[]? value)
        {
            if (value != null)
            {
                CryptographicOperations.ZeroMemory(value);
            }
        }
    }
}
