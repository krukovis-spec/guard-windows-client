using System;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Guard.Domain;
using Guard.Domain.Relay;

namespace Guard.Service;

// One service-owned pass; HTTP never runs while holding the authoritative owner/relay write locks.
internal sealed class NativeRelayDelivery(ServiceAuthoritativeStateBoundary service, DeviceRelayConfiguration config,
    EnrollmentDeploymentTrust trust, IServiceDataBoundaryGuard boundary, TimeProvider clock, HttpRelayTransport transport)
{
    private readonly NativeRelayTransactions _transactions = new(service.NativeEnrollmentStore, service.RelayTransactions,
        service.Identity, config, trust, boundary, clock);

    internal static async Task<bool> DeliverConfirmedAsync(ServiceAuthoritativeStateBoundary service,
        DeviceRelayConfigurationStore configurations, IServiceDataBoundaryGuard boundary, CancellationToken token)
    {
        var owner = await service.LoadAsync(token).ConfigureAwait(false);
        if (!IsConfirmed(owner)) return false; // No release pins/profile/network required before native enrollment.
        var trust = EnrollmentDeploymentTrust.FromServiceAssembly();
        var clock = TimeProvider.System;
        var config = configurations.Load(trust, service.Identity, owner, clock.GetUtcNow());
        // ponytail: one client per low-frequency pass; retain a client if measured connection overhead warrants it.
        using var transport = config.CreateTransport(trust, service.Identity, owner, clock.GetUtcNow());
        return await new NativeRelayDelivery(service, config, trust, boundary, clock, transport).RunAsync(token).ConfigureAwait(false);
    }

    internal async Task<bool> RunAsync(CancellationToken token)
    {
        var delivered = await DeliverOutboxAsync(token).ConfigureAwait(false);
        if (!delivered.Drained) return delivered.Processed;
        await AcknowledgeInboxAsync(token).ConfigureAwait(false); // Retries an ack lost after an earlier durable commit.
        var owner = await RequireReadyAsync(token).ConfigureAwait(false);
        var current = await service.RelayTransactions.LoadAsync(token).ConfigureAwait(false);
        var page = await transport.PollAsync(current.CommittedInboundCursor, token).ConfigureAwait(false);
        if (page.Count == 0) return delivered.Processed;
        // ponytail: one approval per pass bounds receipt capacity and latency; batch only if throughput requires it.
        try
        {
            if (!await _transactions.AcceptApprovalAsync(owner.Version, page[0], token).ConfigureAwait(false)) return delivered.Processed;
        }
        catch (NativeApprovalRejectedException)
        { throw new HttpRequestException("Relay approval was refused; inbox cursor is unchanged."); }
        await DeliverOutboxAsync(token).ConfigureAwait(false);
        await AcknowledgeInboxAsync(token).ConfigureAwait(false);
        return true;
    }

    private async Task<(bool Drained, bool Processed)> DeliverOutboxAsync(CancellationToken token)
    {
        var processed = false;
        for (var index = 0; index < RelayTransactionState.MaximumOutboxItems; index++)
        {
            var owner = await RequireReadyAsync(token).ConfigureAwait(false);
            var current = await service.RelayTransactions.LoadAsync(token).ConfigureAwait(false);
            if (current.Outbox.Count == 0) return (true, processed);
            var item = current.Outbox[0];
            await transport.PublishAsync(item, token).ConfigureAwait(false);
            if (!await _transactions.AcknowledgePublishedAsync(owner.Version, item, token).ConfigureAwait(false)) return (false, processed);
            processed = true;
        }
        return ((await service.RelayTransactions.LoadAsync(token).ConfigureAwait(false)).Outbox.Count == 0, processed);
    }

    private async Task AcknowledgeInboxAsync(CancellationToken token)
    {
        await RequireReadyAsync(token).ConfigureAwait(false);
        await transport.AcknowledgeCommittedInboxAsync(service.RelayTransactions, token).ConfigureAwait(false);
    }

    private async Task<DeviceSecurityState> RequireReadyAsync(CancellationToken token)
    {
        boundary.DemandReady();
        var owner = await service.LoadAsync(token).ConfigureAwait(false);
        if (!IsConfirmed(owner)) throw new InvalidDataException("Native relay requires the current confirmed owner.");
        config.RequireMatches(trust, service.Identity, owner, clock.GetUtcNow());
        token.ThrowIfCancellationRequested();
        return owner;
    }

    private static bool IsConfirmed(DeviceSecurityState owner) => owner.IsProvisioned &&
        owner.Enrollment is { Confirmed: true, PhoneKeyConfirmed: true };
}
