using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Guard.Application;
using Guard.Application.Readiness;
using Guard.Contracts;
using Guard.Domain;
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

    internal sealed partial class GuardServiceIpcOperationHandler :
        IGuardIpcOperationHandler, IDisposable
    {
        private readonly IAuthoritativeStateStore _stateStore;
        private readonly ChildAccountBindingCoordinator _bindingCoordinator;
        private readonly GuardReadinessCoordinator _readinessCoordinator;
        private readonly IServiceUtcClock _clock;
        private readonly EnrollmentDeploymentTrust? _deploymentTrust;

        public GuardServiceIpcOperationHandler(
            IAuthoritativeStateStore stateStore,
            ChildAccountBindingCoordinator bindingCoordinator,
            GuardReadinessCoordinator readinessCoordinator,
            IServiceUtcClock clock,
            EnrollmentDeploymentTrust? deploymentTrust = null,
            DeviceRelayConfigurationStore? configurations = null,
            Func<CancellationToken, Task<ServiceNativeEnrollment>>? openNativeEnrollment = null,
            IBlockedApplicationObservationSource? blockedApplications = null,
            IServiceDataBoundaryGuard? dataBoundaryGuard = null)
        {
            _stateStore = stateStore ??
                throw new ArgumentNullException(nameof(stateStore));
            _bindingCoordinator = bindingCoordinator ??
                throw new ArgumentNullException(nameof(bindingCoordinator));
            _readinessCoordinator = readinessCoordinator ??
                throw new ArgumentNullException(nameof(readinessCoordinator));
            _clock = clock ?? throw new ArgumentNullException(nameof(clock));
            // Production DI supplies no override: release pins come only from this service assembly.
            _deploymentTrust = deploymentTrust;
            _configurations = configurations;
            _openNativeEnrollment = openNativeEnrollment;
            _blockedApplications = blockedApplications;
            _childDataBoundary = dataBoundaryGuard;
        }

        public async Task<GuardIpcResponse> HandleAsync(
            ClientRole authenticatedRole,
            GuardIpcRequest request,
            CancellationToken cancellationToken,
            WindowsAccountSid? authenticatedAccount = null)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            switch (request.Verb)
            {
                case GuardVerb.GetBlockedApplications:
                case GuardVerb.CreateApplicationRequest:
                    return await ChildApplicationAsync(authenticatedRole, authenticatedAccount, request, cancellationToken).ConfigureAwait(false);

                case GuardVerb.GetDeviceProvisioning:
                    return await GetDeviceProvisioningAsync(authenticatedRole, request, cancellationToken).ConfigureAwait(false);

                case GuardVerb.GetNativeActivationConfirmation:
                    return await GetNativeActivationConfirmationAsync(authenticatedRole, request, cancellationToken).ConfigureAwait(false);

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
                    // Quarantined raw-ticket ceremony cannot complete the native attested enrollment.
                    return Response(request, authenticatedRole == ClientRole.AdminSetup ?
                        GuardIpcResponseStatus.Unavailable : GuardIpcResponseStatus.Forbidden);

                case GuardVerb.BeginNativeSetup:
                case GuardVerb.AdvanceNativeSetup:
                case GuardVerb.ConfirmNativeSetup:
                case GuardVerb.CancelNativeSetup:
                case GuardVerb.GetNativeSetupResult:
                    return await NativeSetupAsync(authenticatedRole, request, cancellationToken).ConfigureAwait(false);

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

        private async Task<GuardIpcResponse> GetNativeActivationConfirmationAsync(ClientRole role, GuardIpcRequest request,
            CancellationToken token)
        {
            if (role != ClientRole.AdminSetup) return Response(request, GuardIpcResponseStatus.Forbidden);
            if (request.PayloadLength != 0) return Response(request, GuardIpcResponseStatus.InvalidRequest);
            if (_stateStore is not ServiceAuthoritativeStateBoundary boundary) return Response(request, GuardIpcResponseStatus.Unavailable);
            try
            {
                var state = await boundary.LoadAsync(token).ConfigureAwait(false);
                var proof = Guard.Windows.Cryptography.NativeActivationConfirmation.Create(state, boundary.Identity.Signing, _clock.UtcNow);
                var after = await boundary.LoadAsync(token).ConfigureAwait(false);
                if (after.Version != state.Version) return Response(request, GuardIpcResponseStatus.Conflict);
                token.ThrowIfCancellationRequested();
                proof.RequireCurrent(_clock.UtcNow);
                return Response(request, GuardIpcResponseStatus.Success, proof.GetBytesCopy());
            }
            catch (InvalidOperationException) { return Response(request, GuardIpcResponseStatus.Conflict); }
            catch (Exception error) when (error is InvalidDataException or System.Security.Cryptography.CryptographicException)
            { return Response(request, GuardIpcResponseStatus.Unavailable); }
        }

        private async Task<GuardIpcResponse> GetDeviceProvisioningAsync(ClientRole role, GuardIpcRequest request,
            CancellationToken cancellationToken)
        {
            if (role != ClientRole.AdminSetup) return Response(request, GuardIpcResponseStatus.Forbidden);
            if (request.PayloadLength != 0) return Response(request, GuardIpcResponseStatus.InvalidRequest);
            if (_stateStore is not ServiceAuthoritativeStateBoundary service)
                return Response(request, GuardIpcResponseStatus.Unavailable);
            try
            {
                var trust = _deploymentTrust ?? EnrollmentDeploymentTrust.FromServiceAssembly();
                return Response(request, GuardIpcResponseStatus.Success,
                    await service.ExportDeviceProvisioningAsync(trust, cancellationToken).ConfigureAwait(false));
            }
            catch (InvalidDataException) { return Response(request, GuardIpcResponseStatus.Unavailable); }
            catch (InvalidOperationException) { return Response(request, GuardIpcResponseStatus.Conflict); }
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
