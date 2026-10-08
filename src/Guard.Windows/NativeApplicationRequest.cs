using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Guard.Application;
using Guard.Contracts;
using Guard.Contracts.Relay;
using Guard.Domain;
using Guard.Domain.Relay;
using Guard.Protocol.Relay;

namespace Guard.Windows;

public static partial class NativeApprovalTransaction
{
    // Service-only evidence and authenticated context, never a client-supplied path/hash/XML.
    // Returning the same aggregate is a read-only retry, not another signed publication.
    public static (RelayTransactionState State, RequestSnapshot Request, bool Created) PrepareApplicationRequest(
        DeviceSecurityState owner, RelayTransactionState current, AuthenticatedChildContext caller,
        CreateApplicationRequestPayload input, VerifiedBlockedApplicationObservation observation,
        ECDiffieHellman decryptionKey, ECDsa signingKey, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(caller);
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(observation);
        var session = RequireOwner(owner, current, decryptionKey, signingKey);
        RequireClockFloor(current, now);
        if (owner.DeviceId != caller.DeviceId || owner.ChildAccountSid == null ||
            !owner.ChildAccountSid.Equals(caller.ChildAccountSid) ||
            observation.DeviceId != caller.DeviceId || !observation.ChildAccountSid.Equals(caller.ChildAccountSid) ||
            observation.ObservationId != input.ObservationId || !observation.IsActiveAt(now) ||
            observation.ObservedAtUtc < session.Offer.CreatedAtUtc)
            throw new InvalidDataException("An active exact observation for the bound authenticated account is required.");

        var target = observation.Identity.AuthorizationKey;
        foreach (var tracked in current.TrackedRequests)
        {
            var encoded = tracked.GetEncodedSnapshotCopy();
            if (!tracked.IsPending || encoded.Length == 0) continue;
            var saved = RelayCanonicalEncoding.DecodeRequestSnapshot(encoded);
            if (saved.RequestId != tracked.RequestId || saved.RequestRevision != tracked.RequestRevision ||
                !Equal(saved.GetDecisionChallengeCopy(), tracked.GetDecisionChallengeCopy()))
                throw new InvalidDataException("Stored request metadata does not match its original.");
            if (saved.DeviceId == current.DeviceId && saved.DeviceEpoch == current.DeviceEpoch &&
                saved.AuthorityEpoch == current.AuthorityEpoch && saved.PolicyRevision == current.PolicyRevision &&
                saved.TargetKind == RelayTargetKind.Application && saved.CanonicalTargetIdentity == target &&
                saved.DisplayEvidence.Any(e => e.Name == "child-account" && e.Value == caller.ChildAccountSid.Value) &&
                now < saved.PendingExpiresAtUtc)
            {
                if (now < saved.CreatedAtUtc) throw new InvalidDataException("Request clock rollback.");
                return (current, saved, false);
            }
        }

        var evidence = new List<RelayEvidenceField>
        {
            new("application-name", DisplayText(observation.DisplayName)),
            new("child-account", caller.ChildAccountSid.Value),
            new("observed-at", observation.ObservedAtUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture))
        };
        if (observation.ObservedExecutablePath != null)
            evidence.Add(new("path-hint", DisplayText(observation.ObservedExecutablePath)));
        if (observation.VerifiedSignatureSummary != null)
            evidence.Add(new("verified-signature", DisplayText(observation.VerifiedSignatureSummary)));
        // The event fixes the deadline; repeated clicks cannot renew it. The reason is
        // normalized but never shortened silently (the wire encoder enforces its byte limit).
        var snapshot = new RequestSnapshot(current.DeviceId, current.DeviceEpoch, current.AuthorityEpoch,
            observation.ObservationId, Guid.NewGuid().ToString("N"), 1, RelayTargetKind.Application, target,
            evidence, (input.ShortReason ?? string.Empty).Normalize(NormalizationForm.FormC), MillisecondTime(now),
            MillisecondTime(observation.ExpiresAtUtc), RandomNumberGenerator.GetBytes(RelayProtocol.ChallengeBytes), current.PolicyRevision);
        return (PrepareRequest(owner, current, snapshot, decryptionKey, signingKey, now), snapshot, true);
    }

    private static string DisplayText(string value)
    {
        value = value.Normalize(NormalizationForm.FormC);
        if (Encoding.UTF8.GetByteCount(value) <= RelayProtocol.MaximumEvidenceValueBytes) return value;
        // Only descriptive hints are shortened, visibly, at Unicode scalar boundaries.
        var text = new StringBuilder();
        var bytes = 0;
        foreach (var rune in value.EnumerateRunes())
        {
            if (bytes + rune.Utf8SequenceLength > RelayProtocol.MaximumEvidenceValueBytes - 3) break;
            text.Append(rune.ToString());
            bytes += rune.Utf8SequenceLength;
        }
        return text.Append("…").ToString();
    }
}
