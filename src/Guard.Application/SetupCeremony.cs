using System;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Guard.Contracts;
using Guard.Domain;

namespace Guard.Application
{
    public interface ISetupSecretGenerator
    {
        string CreateChallengeId();

        byte[] CreateSecret(int byteCount);
    }

    public interface ISetupSecretHasher
    {
        byte[] ComputeHash(byte[] secret);
    }

    public interface IParentTrustAnchorValidator
    {
        bool IsValid(ParentTrustAnchor trustAnchor);
    }

    public sealed class SetupTicket
    {
        private readonly byte[] _secret;

        public SetupTicket(string challengeId, byte[] secret, DateTimeOffset expiresAtUtc)
        {
            if (!GuardIdentifier.IsCanonicalToken(challengeId))
            {
                throw new ArgumentException("A canonical challenge id is required.", nameof(challengeId));
            }

            if (secret == null || secret.Length != SetupCeremony.SetupSecretBytes)
            {
                throw new ArgumentException("A setup secret is required.", nameof(secret));
            }

            ChallengeId = challengeId;
            _secret = (byte[])secret.Clone();
            ExpiresAtUtc = expiresAtUtc;
        }

        public string ChallengeId { get; }

        public DateTimeOffset ExpiresAtUtc { get; }

        public byte[] GetSecretCopy()
        {
            return (byte[])_secret.Clone();
        }
    }

    public enum SetupOperationStatus
    {
        Succeeded = 0,
        Forbidden = 1,
        AlreadyProvisioned = 2,
        ChallengeAlreadyActive = 3,
        Rejected = 4,
        StateConflict = 5
    }

    public sealed class SetupBeginResult
    {
        private SetupBeginResult(SetupOperationStatus status, DeviceSecurityState state, SetupTicket? ticket)
        {
            Status = status;
            State = state;
            Ticket = ticket;
        }

        public SetupOperationStatus Status { get; }

        public DeviceSecurityState State { get; }

        public SetupTicket? Ticket { get; }

        public static SetupBeginResult Success(DeviceSecurityState state, SetupTicket ticket)
        {
            return new SetupBeginResult(SetupOperationStatus.Succeeded, state, ticket);
        }

        public static SetupBeginResult Fail(SetupOperationStatus status, DeviceSecurityState state)
        {
            return new SetupBeginResult(status, state, null);
        }
    }

    public sealed class SetupCompleteResult
    {
        private SetupCompleteResult(SetupOperationStatus status, DeviceSecurityState state)
        {
            Status = status;
            State = state;
        }

        public SetupOperationStatus Status { get; }

        public DeviceSecurityState State { get; }

        public static SetupCompleteResult Success(DeviceSecurityState state)
        {
            return new SetupCompleteResult(SetupOperationStatus.Succeeded, state);
        }

        public static SetupCompleteResult Fail(SetupOperationStatus status, DeviceSecurityState state)
        {
            return new SetupCompleteResult(status, state);
        }
    }

    public sealed class SetupCeremony
    {
        public const int SetupSecretBytes = GuardProtocol.SetupSecretBytes;

        private static readonly TimeSpan MinimumLifetime = TimeSpan.FromMinutes(1);
        private static readonly TimeSpan MaximumLifetime = TimeSpan.FromMinutes(10);

        private readonly ISetupSecretGenerator _generator;
        private readonly ISetupSecretHasher _hasher;
        private readonly IParentTrustAnchorValidator _trustAnchorValidator;

        public SetupCeremony(
            ISetupSecretGenerator generator,
            ISetupSecretHasher hasher,
            IParentTrustAnchorValidator trustAnchorValidator)
        {
            _generator = generator ?? throw new ArgumentNullException(nameof(generator));
            _hasher = hasher ?? throw new ArgumentNullException(nameof(hasher));
            _trustAnchorValidator = trustAnchorValidator ?? throw new ArgumentNullException(nameof(trustAnchorValidator));
        }

        internal SetupBeginResult Begin(
            ClientRole role,
            DeviceSecurityState state,
            DateTimeOffset nowUtc,
            TimeSpan lifetime)
        {
            if (state == null)
            {
                throw new ArgumentNullException(nameof(state));
            }

            if (role != ClientRole.AdminSetup)
            {
                return SetupBeginResult.Fail(SetupOperationStatus.Forbidden, state);
            }

            if (state.IsProvisioned)
            {
                return SetupBeginResult.Fail(SetupOperationStatus.AlreadyProvisioned, state);
            }

            if (lifetime < MinimumLifetime || lifetime > MaximumLifetime)
            {
                return SetupBeginResult.Fail(SetupOperationStatus.Rejected, state);
            }

            if (state.SetupChallenge != null && state.SetupChallenge.IsActive(nowUtc))
            {
                return SetupBeginResult.Fail(SetupOperationStatus.ChallengeAlreadyActive, state);
            }

            var challengeId = _generator.CreateChallengeId();
            var secret = _generator.CreateSecret(SetupSecretBytes);
            if (!GuardIdentifier.IsCanonicalToken(challengeId) ||
                secret == null || secret.Length != SetupSecretBytes)
            {
                return SetupBeginResult.Fail(SetupOperationStatus.Rejected, state);
            }

            var expiresAtUtc = nowUtc.Add(lifetime);
            var secretHash = _hasher.ComputeHash(secret);
            if (secretHash == null || secretHash.Length != SetupChallengeState.SecretHashBytes)
            {
                return SetupBeginResult.Fail(SetupOperationStatus.Rejected, state);
            }

            var challenge = new SetupChallengeState(challengeId, secretHash, expiresAtUtc, consumed: false);
            var nextState = state.WithSetupChallenge(challenge);
            return SetupBeginResult.Success(nextState, new SetupTicket(challengeId, secret, expiresAtUtc));
        }

        internal SetupCompleteResult Complete(
            ClientRole role,
            DeviceSecurityState state,
            string challengeId,
            byte[] presentedSecret,
            ParentTrustAnchor parentKey,
            DateTimeOffset nowUtc)
        {
            if (state == null)
            {
                throw new ArgumentNullException(nameof(state));
            }

            if (role != ClientRole.ParentRelay || state.IsProvisioned)
            {
                return SetupCompleteResult.Fail(SetupOperationStatus.Forbidden, state);
            }

            var challenge = state.SetupChallenge;
            if (challenge == null ||
                !string.Equals(challenge.ChallengeId, challengeId, StringComparison.Ordinal) ||
                parentKey == null || !IsValidTrustAnchor(parentKey) ||
                presentedSecret == null || presentedSecret.Length != SetupSecretBytes)
            {
                return SetupCompleteResult.Fail(SetupOperationStatus.Rejected, state);
            }

            var candidateHash = _hasher.ComputeHash(presentedSecret);
            if (candidateHash == null || candidateHash.Length != SetupChallengeState.SecretHashBytes)
            {
                return SetupCompleteResult.Fail(SetupOperationStatus.Rejected, state);
            }

            SetupChallengeState consumed;
            if (!challenge.TryConsume(candidateHash, nowUtc, out consumed))
            {
                return SetupCompleteResult.Fail(SetupOperationStatus.Rejected, state);
            }

            return SetupCompleteResult.Success(state.WithCompletedSetup(consumed, parentKey));
        }

        private bool IsValidTrustAnchor(ParentTrustAnchor trustAnchor)
        {
            try
            {
                return _trustAnchorValidator.IsValid(trustAnchor);
            }
            catch (ArgumentException)
            {
                return false;
            }
            catch (InvalidOperationException)
            {
                return false;
            }
            catch (CryptographicException)
            {
                return false;
            }
        }
    }

    public sealed class SetupCoordinator
    {
        private readonly IAuthoritativeStateStore _store;
        private readonly SetupCeremony _ceremony;

        public SetupCoordinator(IAuthoritativeStateStore store, SetupCeremony ceremony)
        {
            _store = store ?? throw new ArgumentNullException(nameof(store));
            _ceremony = ceremony ?? throw new ArgumentNullException(nameof(ceremony));
        }

        public async Task<SetupBeginResult> BeginAsync(
            ClientRole role,
            DateTimeOffset nowUtc,
            TimeSpan lifetime,
            CancellationToken cancellationToken)
        {
            var current = await _store.LoadAsync(cancellationToken).ConfigureAwait(false);
            var result = _ceremony.Begin(role, current, nowUtc, lifetime);
            if (result.Status != SetupOperationStatus.Succeeded)
            {
                return result;
            }

            var committed = await _store.TryCommitAsync(current.Version, result.State, cancellationToken).ConfigureAwait(false);
            return committed
                ? result
                : SetupBeginResult.Fail(SetupOperationStatus.StateConflict, current);
        }

        public async Task<SetupCompleteResult> CompleteAsync(
            ClientRole role,
            string challengeId,
            byte[] presentedSecret,
            ParentTrustAnchor parentKey,
            DateTimeOffset nowUtc,
            CancellationToken cancellationToken)
        {
            var current = await _store.LoadAsync(cancellationToken).ConfigureAwait(false);
            var result = _ceremony.Complete(role, current, challengeId, presentedSecret, parentKey, nowUtc);
            if (result.Status != SetupOperationStatus.Succeeded)
            {
                return result;
            }

            var committed = await _store.TryCommitAsync(current.Version, result.State, cancellationToken).ConfigureAwait(false);
            return committed
                ? result
                : SetupCompleteResult.Fail(SetupOperationStatus.StateConflict, current);
        }
    }
}
