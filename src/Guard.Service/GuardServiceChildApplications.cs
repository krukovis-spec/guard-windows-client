using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Guard.Application;
using Guard.Contracts;
using Guard.Domain;
using Guard.Protocol;

namespace Guard.Service;

internal sealed partial class GuardServiceIpcOperationHandler
{
    private readonly IBlockedApplicationObservationSource? _blockedApplications;
    private readonly IServiceDataBoundaryGuard? _childDataBoundary;

    private async Task<GuardIpcResponse> ChildApplicationAsync(ClientRole role, WindowsAccountSid? account,
        GuardIpcRequest request, CancellationToken cancellationToken)
    {
        if (role != ClientRole.Child || account == null) return Response(request, GuardIpcResponseStatus.Forbidden);
        CreateApplicationRequestPayload? input = null;
        if (request.Verb == GuardVerb.GetBlockedApplications)
        {
            if (request.PayloadLength != 0) return Response(request, GuardIpcResponseStatus.InvalidRequest);
        }
        else
        {
            try { input = ApplicationRequestPayloadCodec.Decode(request.GetPayloadCopy()); }
            catch (InvalidDataException) { return Response(request, GuardIpcResponseStatus.InvalidRequest); }
        }
        // No production source is installed until M1 supplies a verified active policy.
        if (_blockedApplications == null || _childDataBoundary == null || _configurations == null ||
            _stateStore is not ServiceAuthoritativeStateBoundary boundary)
            return Response(request, GuardIpcResponseStatus.Unavailable);

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(25));
        var token = deadline.Token;
        try
        {
            token.ThrowIfCancellationRequested();
            _childDataBoundary.DemandReady();
            var started = _clock.UtcNow;
            var owner = await boundary.LoadAsync(token).ConfigureAwait(false);
            if (owner.ChildAccountSid == null || !owner.ChildAccountSid.Equals(account))
                return Response(request, GuardIpcResponseStatus.Forbidden);
            if (owner.Enrollment?.Confirmed != true) return Response(request, GuardIpcResponseStatus.Unavailable);
            var trust = _deploymentTrust ?? EnrollmentDeploymentTrust.FromServiceAssembly();
            var config = _configurations.Load(trust, boundary.Identity, owner, started);
            if (input == null)
            {
                var observed = await _blockedApplications.ReadRecentAsync(account, token).ConfigureAwait(false);
                var after = await boundary.LoadAsync(token).ConfigureAwait(false);
                if (after.Version != owner.Version) return Response(request, GuardIpcResponseStatus.Conflict);
                _childDataBoundary.DemandReady();
                var now = _clock.UtcNow;
                config.RequireMatches(trust, boundary.Identity, after, now);
                if (now < started || observed == null || observed.Count > BlockedApplicationsPayload.MaximumItems ||
                    observed.Any(item => item == null || item.DeviceId != owner.DeviceId || !item.ChildAccountSid.Equals(account) ||
                        item.ObservedAtUtc < owner.Enrollment.Offer.CreatedAtUtc || !item.IsActiveAt(now)))
                    return Response(request, GuardIpcResponseStatus.Unavailable);
                var payload = new BlockedApplicationsPayload(now, observed.Select(item => new BlockedApplicationItem(
                    item.ObservationId, item.DisplayName, item.ObservedAtUtc, item.ExpiresAtUtc)).ToArray());
                token.ThrowIfCancellationRequested();
                return Response(request, GuardIpcResponseStatus.Success, BlockedApplicationsPayloadCodec.Encode(payload));
            }
            var transactions = new NativeRelayTransactions(boundary.NativeEnrollmentStore, boundary.RelayTransactions,
                boundary.Identity, config, trust, _childDataBoundary, new ChildRequestClock(_clock));
            var result = await transactions.CreateApplicationRequestAsync(owner.Version,
                new AuthenticatedChildContext(owner.DeviceId, account), input, _blockedApplications, token).ConfigureAwait(false);
            if (result == null) return Response(request, GuardIpcResponseStatus.Conflict);
            return Response(request, GuardIpcResponseStatus.Success, BlockedApplicationsPayloadCodec.EncodeQueued(
                new ApplicationRequestQueuedPayload(result.Value.Request.RequestId, result.Value.Created, result.Value.Request.PendingExpiresAtUtc)));
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        { return Response(request, GuardIpcResponseStatus.Unavailable); }
        catch (Exception error) when (error is IOException or InvalidOperationException or ArgumentException or
            UnauthorizedAccessException or CryptographicException or OverflowException or System.Diagnostics.Eventing.Reader.EventLogException)
        { return Response(request, GuardIpcResponseStatus.Unavailable); }
    }

    private sealed class ChildRequestClock(IServiceUtcClock clock) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => clock.UtcNow;
    }
}
