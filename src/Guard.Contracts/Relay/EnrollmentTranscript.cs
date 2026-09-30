using System;

namespace Guard.Contracts.Relay
{
    // Public offer only. The QR's 256-bit setup secret is deliberately NOT part of this object.
    public sealed class EnrollmentOffer
    {
        private readonly byte[] _signingKey, _encryptionKey, _challenge;
        public EnrollmentOffer(string relayEndpoint, string enrollmentId, string deviceId, string deviceLabel,
            long deviceEpoch, long authorityEpoch, string mailboxId, string signingKeyId, byte[] signingKeySec1,
            string encryptionKeyId, byte[] encryptionKeySec1, DateTimeOffset createdAtUtc,
            DateTimeOffset expiresAtUtc, byte[] challenge)
        {
            RelayEndpoint = relayEndpoint; EnrollmentId = enrollmentId; DeviceId = deviceId; DeviceLabel = deviceLabel;
            DeviceEpoch = deviceEpoch; AuthorityEpoch = authorityEpoch; MailboxId = mailboxId;
            SigningKeyId = signingKeyId; EncryptionKeyId = encryptionKeyId;
            CreatedAtUtc = createdAtUtc; ExpiresAtUtc = expiresAtUtc;
            _signingKey = (byte[])(signingKeySec1 ?? throw new ArgumentNullException(nameof(signingKeySec1))).Clone();
            _encryptionKey = (byte[])(encryptionKeySec1 ?? throw new ArgumentNullException(nameof(encryptionKeySec1))).Clone();
            _challenge = (byte[])(challenge ?? throw new ArgumentNullException(nameof(challenge))).Clone();
        }
        public string RelayEndpoint { get; }
        public string EnrollmentId { get; }
        public string DeviceId { get; }
        public string DeviceLabel { get; }
        public long DeviceEpoch { get; }
        public long AuthorityEpoch { get; }
        public string MailboxId { get; }
        public string SigningKeyId { get; }
        public string EncryptionKeyId { get; }
        public DateTimeOffset CreatedAtUtc { get; }
        public DateTimeOffset ExpiresAtUtc { get; }
        public byte[] GetSigningKeyCopy() => (byte[])_signingKey.Clone();
        public byte[] GetEncryptionKeyCopy() => (byte[])_encryptionKey.Clone();
        public byte[] GetChallengeCopy() => (byte[])_challenge.Clone();
    }

    // Exact signature input, not a verified claimant or permission to commit enrollment.
    public sealed class EnrollmentKeyClaim
    {
        private readonly byte[] _offerHash, _approvalKey, _encryptionKey;
        public EnrollmentKeyClaim(byte[] offerHash, string approvalKeyId, byte[] approvalKeySpki,
            string encryptionKeyId, byte[] encryptionKeySec1)
        {
            ApprovalKeyId = approvalKeyId; EncryptionKeyId = encryptionKeyId;
            _offerHash = (byte[])(offerHash ?? throw new ArgumentNullException(nameof(offerHash))).Clone();
            _approvalKey = (byte[])(approvalKeySpki ?? throw new ArgumentNullException(nameof(approvalKeySpki))).Clone();
            _encryptionKey = (byte[])(encryptionKeySec1 ?? throw new ArgumentNullException(nameof(encryptionKeySec1))).Clone();
        }
        public string ApprovalKeyId { get; }
        public string EncryptionKeyId { get; }
        public byte[] GetOfferHashCopy() => (byte[])_offerHash.Clone();
        public byte[] GetApprovalKeyCopy() => (byte[])_approvalKey.Clone();
        public byte[] GetEncryptionKeyCopy() => (byte[])_encryptionKey.Clone();
    }
}
