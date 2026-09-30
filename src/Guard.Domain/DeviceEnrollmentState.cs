using System;
using System.Collections.Generic;
using System.Linq;
using Guard.Contracts.Relay;

namespace Guard.Domain
{
    // One durable ceremony/binding in the same atomic record as its owner. Never expose this
    // object through status IPC: confirmation hashes and expected key proof are authenticators.
    public sealed class DeviceEnrollmentState
    {
        private readonly byte[] _confirmationHash, _signature, _mac, _enc, _cipher, _keyProof;
        private readonly byte[][] _chain;
        public DeviceEnrollmentState(EnrollmentOffer offer, byte[] confirmationHash, EnrollmentKeyClaim? candidate = null,
            IReadOnlyList<byte[]>? certificates = null, byte[]? signature = null, byte[]? mac = null,
            byte[]? encapsulatedKey = null, byte[]? encryptedChallenge = null, byte[]? expectedKeyProof = null,
            bool phoneKeyConfirmed = false, bool confirmed = false)
        {
            Offer = offer ?? throw new ArgumentNullException(nameof(offer));
            Candidate = candidate; PhoneKeyConfirmed = phoneKeyConfirmed; Confirmed = confirmed;
            _confirmationHash = Exact(confirmationHash, confirmed ? 0 : 32);
            if (candidate == null)
            {
                if (confirmed || phoneKeyConfirmed || certificates != null || signature != null || mac != null ||
                    encapsulatedKey != null || encryptedChallenge != null || expectedKeyProof != null)
                    throw new ArgumentException("A partial enrollment candidate is forbidden.");
                _chain = Array.Empty<byte[]>(); _signature = _mac = _enc = _cipher = _keyProof = Array.Empty<byte>();
                return;
            }
            if (certificates == null || certificates.Count < 2 || certificates.Count > 8)
                throw new ArgumentException("A bounded attestation chain is required.");
            var chain = new List<byte[]>(); var total = 0;
            foreach (var cert in certificates)
            {
                if (cert == null || cert.Length == 0 || cert.Length > 16384 || (total += cert.Length) > 65536)
                    throw new ArgumentException("Invalid certificate chain size.");
                chain.Add((byte[])cert.Clone());
            }
            _chain = chain.ToArray(); _signature = Exact(signature, 64); _mac = Exact(mac, 32);
            _enc = Exact(encapsulatedKey, 65); _cipher = Exact(encryptedChallenge, 48);
            _keyProof = Exact(expectedKeyProof, confirmed ? 0 : 32);
            if (confirmed && !phoneKeyConfirmed) throw new ArgumentException("Phone decryption key is unconfirmed.");
        }
        public EnrollmentOffer Offer { get; }
        public EnrollmentKeyClaim? Candidate { get; }
        public bool PhoneKeyConfirmed { get; }
        public bool Confirmed { get; }
        public byte[] GetConfirmationHashCopy() => (byte[])_confirmationHash.Clone();
        public byte[] GetSignatureCopy() => (byte[])_signature.Clone();
        public byte[] GetMacCopy() => (byte[])_mac.Clone();
        public byte[] GetEncapsulatedKeyCopy() => (byte[])_enc.Clone();
        public byte[] GetEncryptedChallengeCopy() => (byte[])_cipher.Clone();
        public byte[] GetExpectedKeyProofCopy() => (byte[])_keyProof.Clone();
        public IReadOnlyList<byte[]> GetCertificatesCopy() => Array.AsReadOnly(_chain.Select(c => (byte[])c.Clone()).ToArray());
        public DeviceEnrollmentState WithPhoneKeyConfirmed() => new DeviceEnrollmentState(Offer, _confirmationHash, Candidate,
            _chain, _signature, _mac, _enc, _cipher, _keyProof, phoneKeyConfirmed: true);
        public DeviceEnrollmentState WithConfirmedOwner() => new DeviceEnrollmentState(Offer, Array.Empty<byte>(), Candidate,
            _chain, _signature, _mac, _enc, _cipher, Array.Empty<byte>(), PhoneKeyConfirmed, confirmed: true);
        private static byte[] Exact(byte[]? value, int length)
        {
            if (value == null || value.Length != length) throw new ArgumentException("Invalid enrollment field length.");
            return (byte[])value.Clone();
        }
    }
}
