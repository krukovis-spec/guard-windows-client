using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Guard.Application;
using Guard.Contracts;
using Guard.Contracts.Relay;
using Guard.Domain;
using Guard.Protocol.Relay;
using Guard.Storage;
using Guard.Windows.Cryptography;

namespace Guard.Windows;

// This result goes only to the authenticated originating elevated setup session. Never serialize/log it.
public sealed class NativeEnrollmentStart
{
    private readonly byte[] _confirmationSecret;
    internal NativeEnrollmentStart(string qr, byte[] confirmationSecret) { QrText = qr; _confirmationSecret = (byte[])confirmationSecret.Clone(); }
    public string QrText { get; }
    public byte[] GetConfirmationSecretCopy() => (byte[])_confirmationSecret.Clone();
}

/// <summary>One protected file transaction owns the ceremony, phone-key confirmation and final owner.
/// Trusted provisioning supplies attestation verifier/status; no public ParentRelay pipe is added.</summary>
public sealed class NativeEnrollmentCoordinator
{
    private readonly FileAuthoritativeStateStore _store;
    private readonly AndroidApprovalAttestation _verifier;
    private readonly Func<CancellationToken, Task<AndroidAttestationRevocations>> _status;
    private readonly TimeProvider _clock;
    public NativeEnrollmentCoordinator(FileAuthoritativeStateStore store, AndroidApprovalAttestation verifier,
        Func<CancellationToken, Task<AndroidAttestationRevocations>> trustedStatus, TimeProvider? clock = null)
    { _store = store ?? throw new ArgumentNullException(nameof(store)); _verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
        _status = trustedStatus ?? throw new ArgumentNullException(nameof(trustedStatus)); _clock = clock ?? TimeProvider.System; }

    public async Task<(SetupOperationStatus Status, NativeEnrollmentStart? Start)> BeginAsync(ClientRole role,
        EnrollmentOffer locallyCreatedOffer, CancellationToken cancellationToken)
    {
        if (role != ClientRole.AdminSetup) return (SetupOperationStatus.Forbidden, null);
        var offer = RelayCanonicalEncoding.DecodeEnrollmentOffer(RelayCanonicalEncoding.EncodeEnrollmentOffer(locallyCreatedOffer));
        var current = await _store.LoadAsync(cancellationToken).ConfigureAwait(false);
        if (current.IsProvisioned) return (SetupOperationStatus.AlreadyProvisioned, null);
        if (current.SetupChallenge?.IsActive(_clock.GetUtcNow()) == true) return (SetupOperationStatus.ChallengeAlreadyActive, null);
        if (offer.DeviceId != current.DeviceId || !Active(offer)) return (SetupOperationStatus.Rejected, null);
        var secret = RandomNumberGenerator.GetBytes(32); var localSecret = RandomNumberGenerator.GetBytes(32);
        try
        {
            var challenge = new SetupChallengeState(offer.EnrollmentId, SHA256.HashData(secret), offer.ExpiresAtUtc, false);
            var pending = new DeviceEnrollmentState(offer, SHA256.HashData(localSecret));
            var next = current.WithEnrollment(challenge, pending);
            var qr = RelayCanonicalEncoding.EncodeEnrollmentQr(offer, secret);
            if (!await _store.TryCommitGuardedAsync(current.Version, next, () => Active(offer), cancellationToken).ConfigureAwait(false))
                return (SetupOperationStatus.StateConflict, null);
            return (SetupOperationStatus.Succeeded, new NativeEnrollmentStart(qr, localSecret));
        }
        finally { CryptographicOperations.ZeroMemory(secret); CryptographicOperations.ZeroMemory(localSecret); }
    }

    // A verified first candidate is pinned, NOT made owner. Other candidates cannot replace it.
    public async Task<SetupOperationStatus> StageAsync(ClientRole role, EnrollmentKeyClaim claim, byte[] mac,
        IReadOnlyList<byte[]> certificates, byte[] signature, CancellationToken cancellationToken)
    {
        if (role != ClientRole.ParentRelay) return SetupOperationStatus.Forbidden;
        var current = await _store.LoadAsync(cancellationToken).ConfigureAwait(false);
        if (!Pending(current)) return SetupOperationStatus.Rejected;
        var session = current.Enrollment!;
        DeviceEnrollmentState candidate;
        try
        {
            // Snapshot/bound all remote evidence before the first await or cryptographic operation.
            candidate = new DeviceEnrollmentState(session.Offer, session.GetConfirmationHashCopy(), claim, certificates, signature, mac,
                new byte[65], new byte[48], new byte[32]);
        }
        catch (ArgumentException) { return SetupOperationStatus.Rejected; }
        var status = await _status(cancellationToken).ConfigureAwait(false);
        if (!Verified(current, candidate, status)) return SetupOperationStatus.Rejected;
        if (session.Candidate != null)
            return SameClaim(session, claim) ? SetupOperationStatus.Succeeded : SetupOperationStatus.StateConflict;
        var hash = RelayCanonicalEncoding.ComputeEnrollmentClaimHash(claim);
        var witness = RandomNumberGenerator.GetBytes(32);
        try
        {
            var cipher = RelayCryptography.Encrypt(claim.GetEncryptionKeyCopy(), witness, hash, KeyConfirmationInfo(hash), out var enc);
            var expectedProof = ComputePhoneKeyProof(witness, hash);
            candidate = new DeviceEnrollmentState(session.Offer, session.GetConfirmationHashCopy(), claim, candidate.GetCertificatesCopy(),
                candidate.GetSignatureCopy(), candidate.GetMacCopy(), enc, cipher, expectedProof);
            var next = current.WithEnrollment(current.SetupChallenge, candidate);
            return await _store.TryCommitGuardedAsync(current.Version, next, () => Verified(current, candidate, status), cancellationToken).ConfigureAwait(false)
                ? SetupOperationStatus.Succeeded : SetupOperationStatus.StateConflict;
        }
        finally { CryptographicOperations.ZeroMemory(witness); }
    }

    // Send ONLY persisted enc/cipher + claimHash to the phone, never GetExpectedKeyProofCopy().
    public async Task<SetupOperationStatus> ConfirmPhoneKeyAsync(ClientRole role, byte[] claimHash, byte[] response,
        CancellationToken cancellationToken)
    {
        if (role != ClientRole.ParentRelay) return SetupOperationStatus.Forbidden;
        if (claimHash == null || claimHash.Length != 32 || response == null || response.Length != 32) return SetupOperationStatus.Rejected;
        var hash = (byte[])claimHash.Clone(); var proof = (byte[])response.Clone();
        var current = await _store.LoadAsync(cancellationToken).ConfigureAwait(false);
        if (!Pending(current) || current.Enrollment!.Candidate == null) return SetupOperationStatus.Rejected;
        var session = current.Enrollment;
        if (!CryptographicOperations.FixedTimeEquals(hash, RelayCanonicalEncoding.ComputeEnrollmentClaimHash(session.Candidate)) ||
            !CryptographicOperations.FixedTimeEquals(proof, session.GetExpectedKeyProofCopy())) return SetupOperationStatus.Rejected;
        if (session.PhoneKeyConfirmed) return SetupOperationStatus.Succeeded;
        return await _store.TryCommitGuardedAsync(current.Version, current.WithEnrollment(current.SetupChallenge, session.WithPhoneKeyConfirmed()),
            () => Pending(current), cancellationToken).ConfigureAwait(false) ? SetupOperationStatus.Succeeded : SetupOperationStatus.StateConflict;
    }

    public async Task<SetupOperationStatus> ConfirmLocalAsync(ClientRole role, long expectedVersion, byte[] confirmationSecret,
        byte[] confirmedClaimHash, CancellationToken cancellationToken)
    {
        if (role != ClientRole.AdminSetup) return SetupOperationStatus.Forbidden;
        if (confirmationSecret == null || confirmationSecret.Length != 32 || confirmedClaimHash == null || confirmedClaimHash.Length != 32)
            return SetupOperationStatus.Rejected;
        var secretHash = SHA256.HashData(confirmationSecret); var claimHash = (byte[])confirmedClaimHash.Clone();
        var current = await _store.LoadAsync(cancellationToken).ConfigureAwait(false);
        if (current.Version != expectedVersion) return SetupOperationStatus.StateConflict;
        if (!Pending(current) || current.Enrollment!.Candidate == null || !current.Enrollment.PhoneKeyConfirmed) return SetupOperationStatus.Rejected;
        var session = current.Enrollment;
        if (!CryptographicOperations.FixedTimeEquals(secretHash, session.GetConfirmationHashCopy()) ||
            !CryptographicOperations.FixedTimeEquals(claimHash, RelayCanonicalEncoding.ComputeEnrollmentClaimHash(session.Candidate))) return SetupOperationStatus.Rejected;
        var status = await _status(cancellationToken).ConfigureAwait(false);
        if (!Verified(current, session, status)) return SetupOperationStatus.Rejected;
        var next = current.WithEnrollment(null, session.WithConfirmedOwner());
        return await _store.TryCommitGuardedAsync(current.Version, next, () => Verified(current, session, status), cancellationToken).ConfigureAwait(false)
            ? SetupOperationStatus.Succeeded : SetupOperationStatus.StateConflict;
    }

    public async Task<SetupOperationStatus> CancelAsync(ClientRole role, long expectedVersion, byte[] confirmationSecret,
        CancellationToken cancellationToken)
    {
        if (role != ClientRole.AdminSetup) return SetupOperationStatus.Forbidden;
        if (confirmationSecret == null || confirmationSecret.Length != 32) return SetupOperationStatus.Rejected;
        var hash = SHA256.HashData(confirmationSecret);
        var current = await _store.LoadAsync(cancellationToken).ConfigureAwait(false);
        if (current.Version != expectedVersion) return SetupOperationStatus.StateConflict;
        if (current.IsProvisioned || current.Enrollment == null || current.Enrollment.Confirmed ||
            !CryptographicOperations.FixedTimeEquals(hash, current.Enrollment.GetConfirmationHashCopy())) return SetupOperationStatus.Rejected;
        return await _store.TryCommitAsync(current.Version, current.WithEnrollment(null, null), cancellationToken).ConfigureAwait(false)
            ? SetupOperationStatus.Succeeded : SetupOperationStatus.StateConflict;
    }

    private bool Pending(DeviceSecurityState state) => !state.IsProvisioned && state.Enrollment is { Confirmed: false } session &&
        state.SetupChallenge?.IsActive(_clock.GetUtcNow()) == true && Active(session.Offer);
    private bool Active(EnrollmentOffer offer) { var now = _clock.GetUtcNow(); return now >= offer.CreatedAtUtc && now < offer.ExpiresAtUtc; }
    private bool Verified(DeviceSecurityState current, DeviceEnrollmentState candidate, AndroidAttestationRevocations status) =>
        Pending(current) && candidate.Candidate != null && _verifier.VerifyEnrollmentCandidate(candidate.Offer, current.SetupChallenge!.GetSecretHashCopy(),
            candidate.Candidate, candidate.GetMacCopy(), candidate.GetCertificatesCopy(), candidate.GetSignatureCopy(), status, _clock.GetUtcNow());
    private static bool SameClaim(DeviceEnrollmentState state, EnrollmentKeyClaim claim) => state.Candidate != null &&
        RelayCanonicalEncoding.EncodeEnrollmentClaimForSignature(state.Candidate).AsSpan().SequenceEqual(RelayCanonicalEncoding.EncodeEnrollmentClaimForSignature(claim));
    public static byte[] KeyConfirmationInfo(byte[] claimHash) => Encoding.ASCII.GetBytes("guard-enrollment-decryption-hpke-v1").Concat(ExactHash(claimHash)).ToArray();
    public static byte[] ComputePhoneKeyProof(byte[] witness, byte[] claimHash)
    {
        using var mac = new HMACSHA256(ExactHash(witness));
        return mac.ComputeHash(Encoding.ASCII.GetBytes("guard-enrollment-decryption-proof-v1").Concat(ExactHash(claimHash)).ToArray());
    }
    private static byte[] ExactHash(byte[] value) => value != null && value.Length == 32 ? (byte[])value.Clone() : throw new ArgumentException("32-byte value required.");
}
