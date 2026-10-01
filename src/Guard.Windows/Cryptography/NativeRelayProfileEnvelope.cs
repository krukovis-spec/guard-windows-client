using System;
using System.Buffers.Binary;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Guard.Contracts.Relay;
using Guard.Protocol.Relay;

namespace Guard.Windows.Cryptography;

// Initial approval transport only. HPKE is confidential, NOT sender authentication.
// Android must already trust this exact confirmed enrollment and independently pin the file SHA-256.
public static class NativeRelayProfileEnvelope
{
    public const int FileBytes = 233;
    public static byte[] Seal(EnrollmentOffer offer, EnrollmentKeyClaim claim, string approvalCredential,
        DateTimeOffset prepared, DateTimeOffset expires)
    {
        var offerHash = RelayCanonicalEncoding.ComputeEnrollmentOfferHash(offer);
        var claimHash = RelayCanonicalEncoding.ComputeEnrollmentClaimHash(claim);
        if (offer.DeviceEpoch != 1 || offer.AuthorityEpoch != 1 || !offerHash.AsSpan().SequenceEqual(claim.GetOfferHashCopy()) ||
            prepared < offer.CreatedAtUtc || prepared >= offer.ExpiresAtUtc.AddDays(1) || expires <= prepared ||
            approvalCredential.Length != 64 || approvalCredential.Any(c => !(c is >= '0' and <= '9' or >= 'A' and <= 'F')))
            throw new InvalidDataException("Initial native transport profile.");
        var header = new byte[68]; "GNI1"u8.CopyTo(header); offerHash.CopyTo(header, 4); claimHash.CopyTo(header, 36);
        var plain = new byte[84]; "GNP1"u8.CopyTo(plain);
        BinaryPrimitives.WriteInt64BigEndian(plain.AsSpan(4), prepared.ToUnixTimeMilliseconds());
        BinaryPrimitives.WriteInt64BigEndian(plain.AsSpan(12), expires.ToUnixTimeMilliseconds());
        Encoding.ASCII.GetBytes(approvalCredential, plain.AsSpan(20));
        try
        {
            var info = "Guard.v2.native-relay.install.hpke.v1"u8.ToArray().Concat(header).ToArray();
            var cipher = RelayCryptography.Encrypt(claim.GetEncryptionKeyCopy(), plain, header, info, out var enc);
            return header.Concat(enc).Concat(cipher).ToArray();
        }
        finally { CryptographicOperations.ZeroMemory(plain); }
    }
}
