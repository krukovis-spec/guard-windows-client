using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Guard.Application;
using Guard.Contracts;
using Guard.Contracts.Relay;
using Guard.Protocol.Relay;
using Guard.Storage;
using Guard.Windows.Cryptography;

namespace Guard.Windows;

/// <summary>Definitive rejection of this remote message, not a storage/network/provider failure.</summary>
public sealed class EnrollmentRequestRejectedException : Exception
{
    internal EnrollmentRequestRejectedException() : base("Enrollment message rejected.") { }
}

/// <summary>Encrypted remote boundary into the durable native ceremony, never a local-confirm shortcut.
/// The owning service supplies and owns its protected device keys; no key is accepted from the relay.</summary>
public sealed class NativeEnrollmentExchange(FileAuthoritativeStateStore store, NativeEnrollmentCoordinator coordinator,
    ECDiffieHellman decryptionKey, ECDsa signingKey, TimeProvider? clock = null)
{
    public const int MaximumRequestBytes = EnrollmentExchange.MaximumBytes;
    public const int MaximumReplyBytes = 414;
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;

    // Routing checks only; callers must still use HandleAsync for cryptography and durable semantics.
    public static byte[] RequestNonce(byte[] raw, EnrollmentOffer offer) => RequestMessage(raw, offer).Nonce;

    private static EnrollmentExchange.Message RequestMessage(byte[] raw, EnrollmentOffer offer)
    {
        var message = EnrollmentExchange.Decode(raw);
        if (message.Kind == EnrollmentExchange.Reply ||
            !message.OfferHash.AsSpan().SequenceEqual(RelayCanonicalEncoding.ComputeEnrollmentOfferHash(offer)))
            throw new InvalidDataException("Enrollment request routing.");
        return message;
    }

    public static void RequireReplyBinding(byte[] raw, byte[] request, EnrollmentOffer offer)
    {
        var submitted = RequestMessage(request, offer); var reply = EnrollmentExchange.Decode(raw);
        if (reply.Kind != EnrollmentExchange.Reply || !reply.Header.AsSpan(12).SequenceEqual(submitted.Header.AsSpan(12)))
            throw new InvalidDataException("Enrollment reply routing.");
    }

    public async Task<byte[]> HandleAsync(byte[] encodedRequest, CancellationToken cancellationToken)
    {
        var message = EnrollmentExchange.Decode(encodedRequest);
        if (message.Kind == EnrollmentExchange.Reply) throw new InvalidDataException("Wrong enrollment direction.");
        var before = await store.LoadAsync(cancellationToken).ConfigureAwait(false);
        var offer = before.Enrollment?.Offer ?? throw new InvalidDataException("No enrollment.");
        if (!message.OfferHash.AsSpan().SequenceEqual(RelayCanonicalEncoding.ComputeEnrollmentOfferHash(offer)) ||
            !offer.GetEncryptionKeyCopy().AsSpan().SequenceEqual(EnrollmentExchange.Point(decryptionKey.ExportParameters(false).Q)) ||
            !offer.GetSigningKeyCopy().AsSpan().SequenceEqual(EnrollmentExchange.Point(signingKey.ExportParameters(false).Q)))
            throw new InvalidDataException("Enrollment device binding.");
        var candidate = before.Enrollment!.Candidate;
        if ((candidate == null && message.Kind != EnrollmentExchange.Claim) || (candidate != null &&
            !message.ClaimHash.AsSpan().SequenceEqual(RelayCanonicalEncoding.ComputeEnrollmentClaimHash(candidate))))
            throw new EnrollmentRequestRejectedException();
        // Reject an invalid remote curve point, separately from local key/provider or state failures.
        try
        {
            using var remotePoint = ECDiffieHellman.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = message.Enc[1..33], Y = message.Enc[33..65] } });
        }
        catch (CryptographicException) { throw new EnrollmentRequestRejectedException(); }
        // Windows CNG also wraps an invalid supplied EC point in this exception.
        catch (PlatformNotSupportedException error) when (error.InnerException is CryptographicException)
        { throw new EnrollmentRequestRejectedException(); }
        byte[] plaintext;
        try { plaintext = EnrollmentExchange.Open(message, decryptionKey); }
        catch (AuthenticationTagMismatchException) { throw new EnrollmentRequestRejectedException(); }
        try
        {
            if (message.Kind == EnrollmentExchange.Claim)
            {
                EnrollmentExchange.Submission submission;
                try { submission = EnrollmentExchange.DecodeSubmission(plaintext); }
                catch (ArgumentException) { throw new EnrollmentRequestRejectedException(); }
                if (!message.ClaimHash.AsSpan().SequenceEqual(RelayCanonicalEncoding.ComputeEnrollmentClaimHash(submission.Claim)))
                    throw new EnrollmentRequestRejectedException();
                if (!before.IsProvisioned)
                    RequireSuccess(await coordinator.StageAsync(ClientRole.ParentRelay, submission.Claim, submission.Mac,
                        submission.Chain, submission.Signature, cancellationToken).ConfigureAwait(false));
                else
                {
                    // A lost final response may retry after offer expiry, but it cannot replace committed evidence.
                    var saved = before.Enrollment!;
                    if (saved.Candidate == null || !plaintext.AsSpan().SequenceEqual(EnrollmentExchange.EncodeSubmission(
                        saved.Candidate, saved.GetCertificatesCopy(), saved.GetMacCopy(), saved.GetSignatureCopy())))
                        throw new EnrollmentRequestRejectedException();
                }
            }
            else if (message.Kind == EnrollmentExchange.KeyProof)
                RequireSuccess(await coordinator.ConfirmPhoneKeyAsync(ClientRole.ParentRelay, message.ClaimHash, plaintext, cancellationToken).ConfigureAwait(false));
            else if (plaintext.Length != 0) throw new EnrollmentRequestRejectedException();
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); }

        var current = await store.LoadAsync(cancellationToken).ConfigureAwait(false);
        var session = current.Enrollment;
        if (session?.Candidate == null || !message.OfferHash.AsSpan().SequenceEqual(RelayCanonicalEncoding.ComputeEnrollmentOfferHash(session.Offer)) ||
            !message.ClaimHash.AsSpan().SequenceEqual(RelayCanonicalEncoding.ComputeEnrollmentClaimHash(session.Candidate)))
            throw new InvalidDataException("Enrollment changed.");
        var issued = _clock.GetUtcNow(); var expires = issued.AddMinutes(1);
        if (issued < offer.CreatedAtUtc) throw new InvalidDataException("Enrollment clock rollback.");
        var outcome = session.Confirmed && current.IsProvisioned ? EnrollmentExchange.Confirmed :
            session.PhoneKeyConfirmed ? EnrollmentExchange.NeedsLocalConfirmation : EnrollmentExchange.NeedsPhoneProof;
        if (outcome != EnrollmentExchange.Confirmed)
        {
            if (issued < offer.CreatedAtUtc || issued >= offer.ExpiresAtUtc || current.SetupChallenge?.IsActive(issued) != true)
                throw new InvalidDataException("Expired enrollment.");
            if (expires > offer.ExpiresAtUtc) expires = offer.ExpiresAtUtc;
        }
        var header = EnrollmentExchange.Header(EnrollmentExchange.Reply, message.OfferHash, message.ClaimHash, message.Nonce);
        var result = EnrollmentExchange.Result(outcome, current.Version, issued, expires,
            outcome == EnrollmentExchange.NeedsPhoneProof ? session.GetEncapsulatedKeyCopy() : Array.Empty<byte>(),
            outcome == EnrollmentExchange.NeedsPhoneProof ? session.GetEncryptedChallengeCopy() : Array.Empty<byte>());
        byte[] signature;
        lock (signingKey) signature = signingKey.SignData(EnrollmentExchange.SignatureInput(header, result), HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        var reply = EnrollmentExchange.Seal(header, result.Concat(signature).ToArray(), session.Candidate.GetEncryptionKeyCopy());
        var after = await store.LoadAsync(cancellationToken).ConfigureAwait(false);
        var completedAt = _clock.GetUtcNow();
        if (after.Version != current.Version || completedAt < issued || completedAt >= expires)
            throw new InvalidDataException("Enrollment changed during reply.");
        return reply; // A signed enrollment confirmation is not a protection-readiness/permission receipt.
    }

    private static void RequireSuccess(SetupOperationStatus status)
    {
        if (status == SetupOperationStatus.Rejected) throw new EnrollmentRequestRejectedException();
        if (status != SetupOperationStatus.Succeeded) throw new InvalidDataException("Enrollment request rejected.");
    }
}
