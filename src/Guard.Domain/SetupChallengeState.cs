using System;
using Guard.Contracts;

namespace Guard.Domain
{
    public sealed class SetupChallengeState
    {
        public const int SecretHashBytes = 32;
        private readonly byte[] _secretHash;

        public SetupChallengeState(
            string challengeId,
            byte[] secretHash,
            DateTimeOffset expiresAtUtc,
            bool consumed)
        {
            if (!GuardIdentifier.IsCanonicalToken(challengeId))
            {
                throw new ArgumentException("A canonical setup challenge id is required.", nameof(challengeId));
            }

            if (secretHash == null || secretHash.Length != SecretHashBytes)
            {
                throw new ArgumentException("A SHA-256 setup secret hash is required.", nameof(secretHash));
            }

            ChallengeId = challengeId;
            _secretHash = (byte[])secretHash.Clone();
            ExpiresAtUtc = expiresAtUtc;
            Consumed = consumed;
        }

        public string ChallengeId { get; }

        public DateTimeOffset ExpiresAtUtc { get; }

        public bool Consumed { get; }

        public bool IsActive(DateTimeOffset nowUtc)
        {
            return !Consumed && nowUtc < ExpiresAtUtc;
        }

        public bool TryConsume(byte[] candidateHash, DateTimeOffset nowUtc, out SetupChallengeState next)
        {
            next = this;
            if (!IsActive(nowUtc) || candidateHash == null || candidateHash.Length != _secretHash.Length)
            {
                return false;
            }

            var difference = 0;
            for (var index = 0; index < _secretHash.Length; index++)
            {
                difference |= _secretHash[index] ^ candidateHash[index];
            }

            if (difference != 0)
            {
                return false;
            }

            next = new SetupChallengeState(ChallengeId, _secretHash, ExpiresAtUtc, consumed: true);
            return true;
        }
    }
}
