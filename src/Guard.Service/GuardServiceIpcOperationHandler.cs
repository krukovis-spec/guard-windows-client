using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Guard.Application;
using Guard.Application.Readiness;
using Guard.Contracts;
using Guard.Domain.Readiness;
using Guard.Protocol;

namespace Guard.Service
{
    internal interface IServiceUtcClock
    {
        DateTimeOffset UtcNow { get; }
    }

    internal sealed class SystemServiceUtcClock : IServiceUtcClock
    {
        public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
    }

    internal sealed class CryptographicSetupSecretGenerator :
        ISetupSecretGenerator
    {
        public string CreateChallengeId()
        {
            return "setup:" + Guid.NewGuid().ToString("N");
        }

        public byte[] CreateSecret(int byteCount)
        {
            if (byteCount <= 0 || byteCount > 64)
            {
                throw new ArgumentOutOfRangeException(nameof(byteCount));
            }

            return RandomNumberGenerator.GetBytes(byteCount);
        }
    }

    internal sealed class Sha256SetupSecretHasher : ISetupSecretHasher
    {
        public byte[] ComputeHash(byte[] secret)
        {
            if (secret == null ||
                secret.Length != GuardProtocol.SetupSecretBytes)
            {
                throw new ArgumentException(
                    "A complete setup secret is required.",
                    nameof(secret));
            }

            return SHA256.HashData(secret);
        }
    }

    internal sealed class GuardServiceIpcOperationHandler :
        IGuardIpcOperationHandler
    {
        private static readonly TimeSpan SetupTicketLifetime =
            TimeSpan.FromMinutes(5);

        private readonly IAuthoritativeStateStore _stateStore;
        private readonly SetupCoordinator _setupCoordinator;
        private readonly ChildAccountBindingCoordinator _bindingCoordinator;
        private readonly GuardReadinessCoordinator _readinessCoordinator;
        private readonly IServiceUtcClock _clock;

        public GuardServiceIpcOperationHandler(
            IAuthoritativeStateStore stateStore,
            SetupCoordinator setupCoordinator,
            ChildAccountBindingCoordinator bindingCoordinator,
            GuardReadinessCoordinator readinessCoordinator,
            IServiceUtcClock clock)
        {
            _stateStore = stateStore ??
                throw new ArgumentNullException(nameof(stateStore));
            _setupCoordinator = setupCoordinator ??
                throw new ArgumentNullException(nameof(setupCoordinator));
            _bindingCoordinator = bindingCoordinator ??
                throw new ArgumentNullException(nameof(bindingCoordinator));
            _readinessCoordinator = readinessCoordinator ??
                throw new ArgumentNullException(nameof(readinessCoordinator));
            _clock = clock ?? throw new ArgumentNullException(nameof(clock));
        }

        public async Task<GuardIpcResponse> HandleAsync(
            ClientRole authenticatedRole,
            GuardIpcRequest request,
            CancellationToken cancellationToken)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            switch (request.Verb)
            {
                case GuardVerb.GetStatus:
                    return await GetStatusAsync(
                        request,
                        cancellationToken).ConfigureAwait(false);

                case GuardVerb.GetReadiness:
                    return await GetReadinessAsync(
                        authenticatedRole,
                        request,
                        cancellationToken).ConfigureAwait(false);

                case GuardVerb.BeginSetup:
                    return await BeginSetupAsync(
                        authenticatedRole,
                        request,
                        cancellationToken).ConfigureAwait(false);

                case GuardVerb.BindChildAccount:
                    return await BindChildAccountAsync(
                        authenticatedRole,
                        request,
                        cancellationToken).ConfigureAwait(false);

                default:
                    return Response(
                        request,
                        GuardIpcResponseStatus.Unavailable);
            }
        }

        private async Task<GuardIpcResponse> GetReadinessAsync(
            ClientRole authenticatedRole,
            GuardIpcRequest request,
            CancellationToken cancellationToken)
        {
            if (authenticatedRole != ClientRole.AdminSetup &&
                authenticatedRole != ClientRole.ServiceInternal)
            {
                return Response(
                    request,
                    GuardIpcResponseStatus.Forbidden);
            }

            if (request.PayloadLength != 0)
            {
                return Response(
                    request,
                    GuardIpcResponseStatus.InvalidRequest);
            }

            var snapshot = await _readinessCoordinator
                .ObserveAsync(_clock.UtcNow, cancellationToken)
                .ConfigureAwait(false);
            var findings = snapshot.Evaluation.Findings;
            var wireFindings =
                new GuardReadinessFindingPayload[findings.Count];
            for (var index = 0; index < findings.Count; index++)
            {
                wireFindings[index] =
                    new GuardReadinessFindingPayload(
                        findings[index].Code,
                        MapSeverity(findings[index].Severity));
            }

            var facts = snapshot.Facts;
            var payload = GuardReadinessPayloadCodec.Encode(
                new GuardReadinessPayload(
                    snapshot.StateVersion,
                    snapshot.ObservedAtUtc,
                    MapFactState(facts.WindowsEdition.State),
                    MapFactState(facts.ChildAccount.State),
                    MapFactState(
                        facts.SeparateLocalAdministrator.State),
                    MapFactState(facts.SecureBoot.State),
                    MapFactState(facts.BitLocker.State),
                    MapFactState(facts.ServiceBoundary.State),
                    MapFactState(facts.ProgramDataAcl.State),
                    MapFactState(
                        facts.SupportedManagedBrowser.State),
                    facts.SupportedManagedBrowser.ManagedBrowserCount,
                    snapshot.Evaluation.CanEnableProtection,
                    wireFindings));
            return Response(
                request,
                GuardIpcResponseStatus.Success,
                payload);
        }

        private async Task<GuardIpcResponse> GetStatusAsync(
            GuardIpcRequest request,
            CancellationToken cancellationToken)
        {
            if (request.PayloadLength != 0)
            {
                return Response(
                    request,
                    GuardIpcResponseStatus.InvalidRequest);
            }

            var state = await _stateStore
                .LoadAsync(cancellationToken)
                .ConfigureAwait(false);
            var payload = GuardStatusPayloadCodec.Encode(
                new GuardStatusPayload(
                    state.Version,
                    state.IsProvisioned,
                    state.ChildAccountSid != null));
            return Response(
                request,
                GuardIpcResponseStatus.Success,
                payload);
        }

        private async Task<GuardIpcResponse> BeginSetupAsync(
            ClientRole authenticatedRole,
            GuardIpcRequest request,
            CancellationToken cancellationToken)
        {
            if (authenticatedRole != ClientRole.AdminSetup)
            {
                return Response(
                    request,
                    GuardIpcResponseStatus.Forbidden);
            }

            if (request.PayloadLength != 0)
            {
                return Response(
                    request,
                    GuardIpcResponseStatus.InvalidRequest);
            }

            var result = await _setupCoordinator
                .BeginAsync(
                    authenticatedRole,
                    _clock.UtcNow,
                    SetupTicketLifetime,
                    cancellationToken)
                .ConfigureAwait(false);
            if (result.Status != SetupOperationStatus.Succeeded)
            {
                return Response(
                    request,
                    MapSetupStatus(result.Status));
            }

            if (result.Ticket == null)
            {
                return Response(
                    request,
                    GuardIpcResponseStatus.InternalError);
            }

            var secret = result.Ticket.GetSecretCopy();
            try
            {
                var payload = SetupTicketPayloadCodec.Encode(
                    new SetupTicketPayload(
                        result.Ticket.ChallengeId,
                        secret,
                        result.Ticket.ExpiresAtUtc));
                return Response(
                    request,
                    GuardIpcResponseStatus.Success,
                    payload);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(secret);
            }
        }

        private async Task<GuardIpcResponse> BindChildAccountAsync(
            ClientRole authenticatedRole,
            GuardIpcRequest request,
            CancellationToken cancellationToken)
        {
            if (authenticatedRole != ClientRole.AdminSetup)
            {
                return Response(
                    request,
                    GuardIpcResponseStatus.Forbidden);
            }

            BindChildAccountRequest bindRequest;
            try
            {
                bindRequest = BindChildAccountPayloadCodec.Decode(
                    request.GetPayloadCopy());
            }
            catch (InvalidDataException)
            {
                return Response(
                    request,
                    GuardIpcResponseStatus.InvalidRequest);
            }
            catch (ArgumentException)
            {
                return Response(
                    request,
                    GuardIpcResponseStatus.InvalidRequest);
            }

            var result = await _bindingCoordinator
                .BindAsync(
                    authenticatedRole,
                    bindRequest.CandidateSid,
                    _clock.UtcNow,
                    cancellationToken)
                .ConfigureAwait(false);
            if (result.Status != ChildAccountBindingStatus.Succeeded)
            {
                return Response(
                    request,
                    MapBindingStatus(result.Status));
            }

            // The endpoint catalog is fixed at service startup. The new exact
            // child SID therefore becomes active only after a normal,
            // administrator-controlled service restart.
            var payload = ChildAccountBindingPayloadCodec.Encode(
                new ChildAccountBindingPayload(
                    serviceRestartRequired: true));
            return Response(
                request,
                GuardIpcResponseStatus.Success,
                payload);
        }

        private static GuardIpcResponseStatus MapSetupStatus(
            SetupOperationStatus status)
        {
            switch (status)
            {
                case SetupOperationStatus.Forbidden:
                    return GuardIpcResponseStatus.Forbidden;

                case SetupOperationStatus.AlreadyProvisioned:
                case SetupOperationStatus.ChallengeAlreadyActive:
                case SetupOperationStatus.StateConflict:
                    return GuardIpcResponseStatus.Conflict;

                case SetupOperationStatus.Rejected:
                    return GuardIpcResponseStatus.Rejected;

                default:
                    return GuardIpcResponseStatus.InternalError;
            }
        }

        private static GuardIpcResponseStatus MapBindingStatus(
            ChildAccountBindingStatus status)
        {
            switch (status)
            {
                case ChildAccountBindingStatus.Forbidden:
                    return GuardIpcResponseStatus.Forbidden;

                case ChildAccountBindingStatus.AlreadyBound:
                case ChildAccountBindingStatus.StateConflict:
                    return GuardIpcResponseStatus.Conflict;

                case ChildAccountBindingStatus.ParentNotProvisioned:
                case ChildAccountBindingStatus.InvalidCandidate:
                    return GuardIpcResponseStatus.Rejected;

                default:
                    return GuardIpcResponseStatus.InternalError;
            }
        }

        private static GuardReadinessFactState MapFactState(
            ReadinessFactState state)
        {
            switch (state)
            {
                case ReadinessFactState.Satisfied:
                    return GuardReadinessFactState.Satisfied;

                case ReadinessFactState.Unsatisfied:
                    return GuardReadinessFactState.Unsatisfied;

                case ReadinessFactState.Unknown:
                    return GuardReadinessFactState.Unknown;

                case ReadinessFactState.Error:
                    return GuardReadinessFactState.Error;

                default:
                    throw new InvalidOperationException(
                        "The readiness fact state is invalid.");
            }
        }

        private static GuardReadinessFindingSeverity MapSeverity(
            ReadinessFindingSeverity severity)
        {
            switch (severity)
            {
                case ReadinessFindingSeverity.Blocking:
                    return GuardReadinessFindingSeverity.Blocking;

                case ReadinessFindingSeverity.Warning:
                    return GuardReadinessFindingSeverity.Warning;

                case ReadinessFindingSeverity.Ready:
                    return GuardReadinessFindingSeverity.Ready;

                default:
                    throw new InvalidOperationException(
                        "The readiness finding severity is invalid.");
            }
        }

        private static GuardIpcResponse Response(
            GuardIpcRequest request,
            GuardIpcResponseStatus status,
            byte[]? payload = null)
        {
            return new GuardIpcResponse(
                GuardProtocol.CurrentVersion,
                request.RequestId,
                status,
                payload ?? Array.Empty<byte>());
        }
    }
}
