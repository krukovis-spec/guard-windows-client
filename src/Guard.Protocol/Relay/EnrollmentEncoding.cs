using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Guard.Contracts.Relay;

namespace Guard.Protocol.Relay
{
    public static partial class RelayCanonicalEncoding
    {
        public const int MaximumEnrollmentOfferBytes = 1536;
        private static readonly byte[] EnrollmentMagic = Encoding.ASCII.GetBytes("GREO");
        private static readonly byte[] EnrollmentClaimMagic = Encoding.ASCII.GetBytes("GREC");
        private static readonly byte[] P256SpkiPrefix = {
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00 };

        public static byte[] EncodeEnrollmentOffer(EnrollmentOffer offer)
        {
            if (offer == null) throw new ArgumentNullException(nameof(offer));
            RequireEnrollmentRelay(offer.RelayEndpoint);
            RequireLifetime(offer.CreatedAtUtc, offer.ExpiresAtUtc, TimeSpan.FromMinutes(10), "enrollment");
            var signing = offer.GetSigningKeyCopy(); var encryption = offer.GetEncryptionKeyCopy();
            RequirePointEncoding(signing); RequirePointEncoding(encryption);
            if (offer.SigningKeyId == offer.EncryptionKeyId || signing.SequenceEqual(encryption))
                throw new ArgumentException("Separate device keys required.");
            var bytes = Encode(EnrollmentMagic, stream => {
                WriteVersion(stream);
                WriteText(stream, offer.RelayEndpoint, 256, false); WriteIdentifier(stream, offer.EnrollmentId);
                WriteIdentifier(stream, offer.DeviceId); WriteText(stream, offer.DeviceLabel, 96, false);
                WritePositiveInt64(stream, offer.DeviceEpoch); WritePositiveInt64(stream, offer.AuthorityEpoch);
                WriteIdentifier(stream, offer.MailboxId); WriteIdentifier(stream, offer.SigningKeyId);
                WriteFixedBytes(stream, signing, 65); WriteIdentifier(stream, offer.EncryptionKeyId);
                WriteFixedBytes(stream, encryption, 65); WriteTime(stream, offer.CreatedAtUtc);
                WriteTime(stream, offer.ExpiresAtUtc); WriteFixedBytes(stream, offer.GetChallengeCopy(), 32);
            });
            if (bytes.Length > MaximumEnrollmentOfferBytes) throw new ArgumentException("Enrollment offer too large.");
            return bytes;
        }

        public static EnrollmentOffer DecodeEnrollmentOffer(byte[] encoded)
        {
            if (encoded == null || encoded.Length > MaximumEnrollmentOfferBytes) throw new ArgumentException("Invalid offer size.");
            var reader = new Reader(encoded, EnrollmentMagic); RequireVersion(reader);
            var offer = new EnrollmentOffer(reader.ReadText(256, false), reader.ReadIdentifier(), reader.ReadIdentifier(),
                reader.ReadText(96, false), reader.ReadPositiveInt64(), reader.ReadPositiveInt64(), reader.ReadIdentifier(),
                reader.ReadIdentifier(), reader.ReadFixedBytes(65), reader.ReadIdentifier(), reader.ReadFixedBytes(65),
                reader.ReadTime(), reader.ReadTime(), reader.ReadFixedBytes(32));
            reader.RequireEnd(); EncodeEnrollmentOffer(offer); return offer;
        }

        public static byte[] ComputeEnrollmentOfferHash(EnrollmentOffer offer)
        {
            using (var hash = SHA256.Create()) return hash.ComputeHash(EncodeEnrollmentOffer(offer));
        }

        // Render only in the elevated native setup window. Never open as a browser URL or log it.
        public static string EncodeEnrollmentQr(EnrollmentOffer offer, byte[] setupSecret)
        {
            if (offer == null) throw new ArgumentNullException(nameof(offer));
            if (setupSecret == null || setupSecret.Length != 32) throw new ArgumentException("Setup secret required.");
            using (var sha = SHA256.Create())
                if (offer.GetChallengeCopy().SequenceEqual(setupSecret) || offer.GetChallengeCopy().SequenceEqual(sha.ComputeHash(setupSecret)))
                    throw new ArgumentException("Public challenge must be independent of the setup secret/proof key.");
            string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            return "guard-enroll://v2?offer=" + Base64Url(EncodeEnrollmentOffer(offer)) + "&secret=" + Base64Url(setupSecret);
        }

        public static byte[] EncodeEnrollmentClaimForSignature(EnrollmentKeyClaim claim)
        {
            if (claim == null) throw new ArgumentNullException(nameof(claim));
            var approval = claim.GetApprovalKeyCopy(); var encryption = claim.GetEncryptionKeyCopy();
            if (approval.Length != 91 || !approval.Take(26).SequenceEqual(P256SpkiPrefix))
                throw new ArgumentException("Canonical P-256 SPKI required.");
            RequirePointEncoding(approval.Skip(26).ToArray()); RequirePointEncoding(encryption);
            if (claim.ApprovalKeyId == claim.EncryptionKeyId || approval.Skip(26).SequenceEqual(encryption))
                throw new ArgumentException("Separate parent keys required.");
            return Encode(EnrollmentClaimMagic, stream => {
                WriteVersion(stream); WriteFixedBytes(stream, claim.GetOfferHashCopy(), 32);
                WriteIdentifier(stream, claim.ApprovalKeyId); WriteFixedBytes(stream, approval, 91);
                WriteIdentifier(stream, claim.EncryptionKeyId); WriteFixedBytes(stream, encryption, 65);
            });
        }

        public static EnrollmentKeyClaim DecodeEnrollmentClaimForSignature(byte[] encoded)
        {
            if (encoded == null || encoded.Length > 460) throw new ArgumentException("Invalid claim size.");
            var reader = new Reader(encoded, EnrollmentClaimMagic); RequireVersion(reader);
            var claim = new EnrollmentKeyClaim(reader.ReadFixedBytes(32), reader.ReadIdentifier(), reader.ReadFixedBytes(91),
                reader.ReadIdentifier(), reader.ReadFixedBytes(65));
            reader.RequireEnd(); EncodeEnrollmentClaimForSignature(claim); return claim;
        }

        public static byte[] ComputeEnrollmentClaimHash(EnrollmentKeyClaim claim)
        {
            using (var hash = SHA256.Create()) return hash.ComputeHash(EncodeEnrollmentClaimForSignature(claim));
        }

        // proofKey = SHA256(the native-scanned 32-byte setup secret), kept only by phone and SYSTEM.
        // Neither the secret nor proofKey goes in the public offer, attestation challenge, relay or logs.
        // A valid MAC proves QR possession, NOT parent identity; attestation + local confirmation + CAS are still required.
        public static byte[] ComputeEnrollmentClaimProof(byte[] proofKey, EnrollmentKeyClaim claim)
        {
            if (proofKey == null || proofKey.Length != 32) throw new ArgumentException("Setup proof key required.");
            using (var mac = new HMACSHA256(proofKey))
                return mac.ComputeHash(Encoding.ASCII.GetBytes("guard-enrollment-possession-v1").Concat(ComputeEnrollmentClaimHash(claim)).ToArray());
        }

        public static void RequireEnrollmentRelay(string endpoint)
        {
            if (endpoint == null || endpoint.Length > 256 || !Regex.IsMatch(endpoint,
                @"\Ahttps://(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?(?:/[a-z0-9_-]+)*\z",
                RegexOptions.CultureInvariant)) throw new ArgumentException("Canonical pinned HTTPS relay required.");
        }

        // Wire shape only. Native curve import/attestation must validate the actual points before trust is committed.
        private static void RequirePointEncoding(byte[] key)
        {
            if (key.Length != 65 || key[0] != 4) throw new ArgumentException("Uncompressed P-256 point required.");
        }
    }
}
