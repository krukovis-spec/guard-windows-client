using System;
using System.Collections.Generic;
using Guard.Contracts;

namespace Guard.Domain
{
    public sealed class DeviceSecurityState
    {
        public const int MaximumRecentCommandIds = 128;
        public const int MaximumTrustedParentKeys = 8;

        private readonly string[] _recentCommandIds;
        private readonly ParentTrustAnchor[] _trustedParentKeys;

        public DeviceSecurityState(
            string deviceId,
            long version,
            long highestAcceptedSequence,
            long desiredPolicyRevision,
            IEnumerable<string>? recentCommandIds = null,
            SetupChallengeState? setupChallenge = null,
            IEnumerable<ParentTrustAnchor>? trustedParentKeys = null,
            WindowsAccountSid? childAccountSid = null)
        {
            if (!GuardIdentifier.IsCanonicalToken(deviceId))
            {
                throw new ArgumentException("A canonical device id is required.", nameof(deviceId));
            }

            if (version < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(version));
            }

            if (highestAcceptedSequence < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(highestAcceptedSequence));
            }

            if (desiredPolicyRevision < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(desiredPolicyRevision));
            }

            DeviceId = deviceId;
            Version = version;
            HighestAcceptedSequence = highestAcceptedSequence;
            DesiredPolicyRevision = desiredPolicyRevision;
            SetupChallenge = setupChallenge;
            ChildAccountSid = childAccountSid;
            _recentCommandIds = CopyRecentIds(recentCommandIds);
            _trustedParentKeys = CopyTrustAnchors(trustedParentKeys);
        }

        public string DeviceId { get; }

        public long Version { get; }

        public long HighestAcceptedSequence { get; }

        public long DesiredPolicyRevision { get; }

        public SetupChallengeState? SetupChallenge { get; }

        public WindowsAccountSid? ChildAccountSid { get; }

        public IReadOnlyList<string> RecentCommandIds => Array.AsReadOnly((string[])_recentCommandIds.Clone());

        public IReadOnlyList<ParentTrustAnchor> TrustedParentKeys => Array.AsReadOnly((ParentTrustAnchor[])_trustedParentKeys.Clone());

        public IReadOnlyList<string> TrustedParentKeyIds
        {
            get
            {
                var keyIds = new string[_trustedParentKeys.Length];
                for (var index = 0; index < _trustedParentKeys.Length; index++)
                {
                    keyIds[index] = _trustedParentKeys[index].KeyId;
                }

                return Array.AsReadOnly(keyIds);
            }
        }

        public bool IsProvisioned => _trustedParentKeys.Length > 0;

        public bool HasAcceptedCommand(string commandId)
        {
            for (var index = 0; index < _recentCommandIds.Length; index++)
            {
                if (string.Equals(_recentCommandIds[index], commandId, StringComparison.Ordinal))
                {
                    return true;
                }
            }

            return false;
        }

        public bool TrustsParentKey(string keyId)
        {
            ParentTrustAnchor ignored;
            return TryGetParentTrustAnchor(keyId, out ignored);
        }

        public bool TryGetParentTrustAnchor(string keyId, out ParentTrustAnchor trustAnchor)
        {
            for (var index = 0; index < _trustedParentKeys.Length; index++)
            {
                if (string.Equals(_trustedParentKeys[index].KeyId, keyId, StringComparison.Ordinal))
                {
                    trustAnchor = _trustedParentKeys[index];
                    return true;
                }
            }

            trustAnchor = null!;
            return false;
        }

        public DeviceSecurityState WithSetupChallenge(SetupChallengeState? challenge)
        {
            return new DeviceSecurityState(
                DeviceId,
                checked(Version + 1),
                HighestAcceptedSequence,
                DesiredPolicyRevision,
                _recentCommandIds,
                challenge,
                _trustedParentKeys,
                ChildAccountSid);
        }

        public DeviceSecurityState WithCompletedSetup(SetupChallengeState consumedChallenge, ParentTrustAnchor parentKey)
        {
            if (consumedChallenge == null)
            {
                throw new ArgumentNullException(nameof(consumedChallenge));
            }

            if (!consumedChallenge.Consumed || SetupChallenge == null ||
                !string.Equals(SetupChallenge.ChallengeId, consumedChallenge.ChallengeId, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Setup completion must consume the active challenge.");
            }

            if (parentKey == null)
            {
                throw new ArgumentNullException(nameof(parentKey));
            }

            if (_trustedParentKeys.Length >= MaximumTrustedParentKeys)
            {
                throw new InvalidOperationException("The trusted parent key limit has been reached.");
            }

            var nextKeys = new ParentTrustAnchor[_trustedParentKeys.Length + 1];
            Array.Copy(_trustedParentKeys, nextKeys, _trustedParentKeys.Length);
            nextKeys[nextKeys.Length - 1] = parentKey;

            return new DeviceSecurityState(
                DeviceId,
                checked(Version + 1),
                HighestAcceptedSequence,
                DesiredPolicyRevision,
                _recentCommandIds,
                setupChallenge: null,
                trustedParentKeys: nextKeys,
                childAccountSid: ChildAccountSid);
        }

        public DeviceSecurityState WithBoundChildAccount(
            WindowsAccountSid childAccountSid,
            DateTimeOffset nowUtc)
        {
            if (!IsProvisioned &&
                (SetupChallenge == null ||
                 !SetupChallenge.IsActive(nowUtc)))
            {
                throw new InvalidOperationException(
                    "Child binding requires an active setup ceremony or a parent trust anchor.");
            }

            if (childAccountSid == null)
            {
                throw new ArgumentNullException(nameof(childAccountSid));
            }

            if (ChildAccountSid != null)
            {
                throw new InvalidOperationException("The child account is already bound.");
            }

            return new DeviceSecurityState(
                DeviceId,
                checked(Version + 1),
                HighestAcceptedSequence,
                DesiredPolicyRevision,
                _recentCommandIds,
                SetupChallenge,
                _trustedParentKeys,
                childAccountSid);
        }

        public DeviceSecurityState WithAcceptedCommand(string commandId, long sequence)
        {
            if (string.IsNullOrWhiteSpace(commandId))
            {
                throw new ArgumentException("A command id is required.", nameof(commandId));
            }

            if (sequence <= HighestAcceptedSequence)
            {
                throw new InvalidOperationException("The accepted sequence must advance monotonically.");
            }

            var keepCount = Math.Min(_recentCommandIds.Length, MaximumRecentCommandIds - 1);
            var nextIds = new string[keepCount + 1];
            var sourceOffset = _recentCommandIds.Length - keepCount;
            for (var index = 0; index < keepCount; index++)
            {
                nextIds[index] = _recentCommandIds[sourceOffset + index];
            }

            nextIds[nextIds.Length - 1] = commandId;
            return new DeviceSecurityState(
                DeviceId,
                checked(Version + 1),
                sequence,
                checked(DesiredPolicyRevision + 1),
                nextIds,
                SetupChallenge,
                _trustedParentKeys,
                ChildAccountSid);
        }

        private static string[] CopyRecentIds(IEnumerable<string>? values)
        {
            if (values == null)
            {
                return Array.Empty<string>();
            }

            var result = new List<string>();
            foreach (var value in values)
            {
                if (!GuardIdentifier.IsCanonicalToken(value))
                {
                    throw new ArgumentException("Recent command ids must be canonical tokens.", nameof(values));
                }

                result.Add(value);
            }

            if (result.Count > MaximumRecentCommandIds)
            {
                result.RemoveRange(0, result.Count - MaximumRecentCommandIds);
            }

            return result.ToArray();
        }

        private static ParentTrustAnchor[] CopyTrustAnchors(IEnumerable<ParentTrustAnchor>? values)
        {
            if (values == null)
            {
                return Array.Empty<ParentTrustAnchor>();
            }

            var result = new List<ParentTrustAnchor>();
            foreach (var value in values)
            {
                if (value == null)
                {
                    throw new ArgumentException("Trusted parent keys cannot contain null values.", nameof(values));
                }

                for (var index = 0; index < result.Count; index++)
                {
                    if (string.Equals(result[index].KeyId, value.KeyId, StringComparison.Ordinal))
                    {
                        throw new ArgumentException("Trusted parent key ids must be unique.", nameof(values));
                    }
                }

                result.Add(value);
                if (result.Count > MaximumTrustedParentKeys)
                {
                    throw new ArgumentException("Too many trusted parent keys were supplied.", nameof(values));
                }
            }

            return result.ToArray();
        }
    }
}
