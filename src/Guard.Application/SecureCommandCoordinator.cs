using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Guard.Contracts;
using Guard.Domain;
using Guard.Protocol;

namespace Guard.Application
{
    public interface IAuthoritativeStateStore
    {
        Task<DeviceSecurityState> LoadAsync(CancellationToken cancellationToken);

        Task<bool> TryCommitAsync(
            long expectedVersion,
            DeviceSecurityState nextState,
            CancellationToken cancellationToken);
    }

    public interface ICommandSignatureVerifier
    {
        bool Verify(ParentTrustAnchor trustAnchor, byte[] canonicalHash, byte[] signature);
    }

    public interface IParentCommandReducer
    {
        DeviceSecurityState ApplyDesiredMutation(
            DeviceSecurityState acceptedState,
            ParentDecisionCommand command);
    }

    public interface IPendingAccessRequestValidator
    {
        bool IsExactPendingMatch(DeviceSecurityState currentState, ParentDecisionCommand command);
    }

    public interface IPolicyReconciler
    {
        Task ReconcileAsync(DeviceSecurityState desiredState, CancellationToken cancellationToken);
    }

    public enum CommandProcessingStatus
    {
        Applied = 0,
        Rejected = 1,
        InvalidSignature = 2,
        StateConflict = 3,
        AcceptedPendingReconciliation = 4
    }

    public sealed class CommandProcessingResult
    {
        public CommandProcessingResult(
            CommandProcessingStatus status,
            CommandAcceptanceStatus? acceptanceStatus = null)
        {
            Status = status;
            AcceptanceStatus = acceptanceStatus;
        }

        public CommandProcessingStatus Status { get; }

        public CommandAcceptanceStatus? AcceptanceStatus { get; }
    }

    public sealed class SecureCommandCoordinator
    {
        private readonly IAuthoritativeStateStore _store;
        private readonly ICommandSignatureVerifier _signatureVerifier;
        private readonly IPendingAccessRequestValidator _pendingRequestValidator;
        private readonly IParentCommandReducer _reducer;
        private readonly IPolicyReconciler _reconciler;
        private readonly CommandAcceptancePolicy _acceptancePolicy;

        public SecureCommandCoordinator(
            IAuthoritativeStateStore store,
            ICommandSignatureVerifier signatureVerifier,
            IPendingAccessRequestValidator pendingRequestValidator,
            IParentCommandReducer reducer,
            IPolicyReconciler reconciler,
            CommandAcceptancePolicy acceptancePolicy)
        {
            _store = store ?? throw new ArgumentNullException(nameof(store));
            _signatureVerifier = signatureVerifier ?? throw new ArgumentNullException(nameof(signatureVerifier));
            _pendingRequestValidator = pendingRequestValidator ?? throw new ArgumentNullException(nameof(pendingRequestValidator));
            _reducer = reducer ?? throw new ArgumentNullException(nameof(reducer));
            _reconciler = reconciler ?? throw new ArgumentNullException(nameof(reconciler));
            _acceptancePolicy = acceptancePolicy ?? throw new ArgumentNullException(nameof(acceptancePolicy));
        }

        public async Task<CommandProcessingResult> ProcessAsync(
            SignedCommandEnvelope envelope,
            DateTimeOffset nowUtc,
            CancellationToken cancellationToken)
        {
            if (envelope == null)
            {
                throw new ArgumentNullException(nameof(envelope));
            }

            if (envelope.PayloadLength <= 0 || envelope.PayloadLength > GuardProtocol.MaximumFrameBytes ||
                envelope.SignatureLength <= 0 || envelope.SignatureLength > 2048 ||
                string.IsNullOrWhiteSpace(envelope.KeyId) || envelope.KeyId.Length > 128)
            {
                return new CommandProcessingResult(CommandProcessingStatus.Rejected);
            }

            var current = await _store.LoadAsync(cancellationToken).ConfigureAwait(false);
            ParentTrustAnchor trustAnchor;
            if (!current.IsProvisioned || !current.TryGetParentTrustAnchor(envelope.KeyId, out trustAnchor))
            {
                return new CommandProcessingResult(CommandProcessingStatus.Rejected);
            }

            byte[] canonicalHash;
            try
            {
                canonicalHash = CanonicalCommandEncoding.ComputeSignatureHash(envelope);
            }
            catch (ArgumentException)
            {
                return new CommandProcessingResult(CommandProcessingStatus.Rejected);
            }
            catch (InvalidOperationException)
            {
                return new CommandProcessingResult(CommandProcessingStatus.Rejected);
            }
            catch (CryptographicException)
            {
                return new CommandProcessingResult(CommandProcessingStatus.Rejected);
            }

            var metadata = new CommandMetadata(
                envelope.CommandId,
                envelope.DeviceId,
                envelope.Sequence,
                envelope.IssuedAtUtc,
                envelope.ExpiresAtUtc,
                envelope.Nonce);

            var acceptance = CommandAcceptanceEvaluator.Evaluate(current, metadata, nowUtc, _acceptancePolicy);
            if (acceptance != CommandAcceptanceStatus.Accepted)
            {
                return new CommandProcessingResult(CommandProcessingStatus.Rejected, acceptance);
            }

            bool signatureValid;
            try
            {
                signatureValid = _signatureVerifier.Verify(
                    trustAnchor,
                    canonicalHash,
                    envelope.GetSignatureCopy());
            }
            catch (ArgumentException)
            {
                signatureValid = false;
            }
            catch (InvalidOperationException)
            {
                signatureValid = false;
            }
            catch (CryptographicException)
            {
                signatureValid = false;
            }

            if (!signatureValid)
            {
                return new CommandProcessingResult(CommandProcessingStatus.InvalidSignature);
            }

            ParentDecisionCommand command;
            try
            {
                command = ParentDecisionPayloadCodec.Decode(envelope.GetCanonicalPayloadCopy());
            }
            catch (IOException)
            {
                return new CommandProcessingResult(CommandProcessingStatus.Rejected);
            }
            catch (ArgumentException)
            {
                return new CommandProcessingResult(CommandProcessingStatus.Rejected);
            }

            bool exactPendingMatch;
            try
            {
                exactPendingMatch = _pendingRequestValidator.IsExactPendingMatch(current, command);
            }
            catch (ArgumentException)
            {
                exactPendingMatch = false;
            }
            catch (InvalidOperationException)
            {
                exactPendingMatch = false;
            }

            if (!exactPendingMatch)
            {
                return new CommandProcessingResult(CommandProcessingStatus.Rejected);
            }

            var accepted = current.WithAcceptedCommand(envelope.CommandId, envelope.Sequence);
            DeviceSecurityState desired;
            try
            {
                desired = _reducer.ApplyDesiredMutation(accepted, command);
            }
            catch (ArgumentException)
            {
                return new CommandProcessingResult(CommandProcessingStatus.Rejected);
            }
            catch (InvalidOperationException)
            {
                return new CommandProcessingResult(CommandProcessingStatus.Rejected);
            }

            if (desired == null ||
                !string.Equals(desired.DeviceId, current.DeviceId, StringComparison.Ordinal) ||
                desired.Version != accepted.Version ||
                desired.HighestAcceptedSequence != envelope.Sequence ||
                desired.DesiredPolicyRevision != accepted.DesiredPolicyRevision ||
                !desired.HasAcceptedCommand(envelope.CommandId) ||
                !HasSameTrustBoundary(accepted, desired))
            {
                return new CommandProcessingResult(CommandProcessingStatus.Rejected);
            }

            var committed = await _store.TryCommitAsync(current.Version, desired, cancellationToken).ConfigureAwait(false);
            if (!committed)
            {
                return new CommandProcessingResult(CommandProcessingStatus.StateConflict);
            }

            try
            {
                await _reconciler.ReconcileAsync(desired, cancellationToken).ConfigureAwait(false);
                return new CommandProcessingResult(CommandProcessingStatus.Applied, CommandAcceptanceStatus.Accepted);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                return new CommandProcessingResult(
                    CommandProcessingStatus.AcceptedPendingReconciliation,
                    CommandAcceptanceStatus.Accepted);
            }
        }

        private static bool HasSameTrustBoundary(DeviceSecurityState accepted, DeviceSecurityState desired)
        {
            if (!ReferenceEquals(accepted.SetupChallenge, desired.SetupChallenge) ||
                !Equals(accepted.ChildAccountSid, desired.ChildAccountSid) ||
                accepted.TrustedParentKeys.Count != desired.TrustedParentKeys.Count ||
                accepted.RecentCommandIds.Count != desired.RecentCommandIds.Count)
            {
                return false;
            }

            for (var index = 0; index < accepted.TrustedParentKeys.Count; index++)
            {
                if (!accepted.TrustedParentKeys[index].Equals(desired.TrustedParentKeys[index]))
                {
                    return false;
                }
            }

            for (var index = 0; index < accepted.RecentCommandIds.Count; index++)
            {
                if (!string.Equals(
                    accepted.RecentCommandIds[index],
                    desired.RecentCommandIds[index],
                    StringComparison.Ordinal))
                {
                    return false;
                }
            }

            return true;
        }
    }
}
