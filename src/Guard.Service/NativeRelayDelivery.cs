using System;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Guard.Domain;
using Guard.Domain.Relay;
using Guard.Protocol.Relay;

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
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(25), clock);
        using var pass = CancellationTokenSource.CreateLinkedTokenSource(token, deadline.Token);
        token = pass.Token;
        var delivered = await DeliverOutboxAsync(token).ConfigureAwait(false);
        if (!delivered.Drained) return delivered.Processed;
        await AcknowledgeInboxAsync(token).ConfigureAwait(false); // Retries an ack lost after an earlier durable commit.
        var owner = await RequireReadyAsync(token).ConfigureAwait(false);
        var current = await service.RelayTransactions.LoadAsync(token).ConfigureAwait(false);
        var scanAfter = current.CommittedInboundCursor;
        // ponytail: scan at most 64 pages (covers the Worker's 1000-frame quota), within this pass's
        // pass deadline. This is only a read bookmark, never a durable cursor or acknowledgment.
        for (var pageIndex = 0; pageIndex < 64; pageIndex++)
        {
            await RequireReadyAsync(token).ConfigureAwait(false);
            var page = await transport.PollAsync(scanAfter, token).ConfigureAwait(false);
            if (page.Count == 0 && pageIndex == 0) return delivered.Processed;
            // At most one verified outcome per pass. Bad ciphertext never advances local state;
            // later commands still require exact signed sequence/request/history checks.
            foreach (var frame in page)
            {
                try
                {
                    if (!await _transactions.AcceptApprovalAsync(owner.Version, frame, token).ConfigureAwait(false)) return delivered.Processed;
                }
                catch (NativeApprovalRejectedException) { continue; }
                await DeliverOutboxAsync(token).ConfigureAwait(false);
                await AcknowledgeInboxAsync(token).ConfigureAwait(false);
                return true;
            }
            if (page.Count < HttpRelayTransport.PageSize) break;
            // Poll already checked the entire page's bounded, strictly increasing GRF1 cursors.
            scanAfter = RelayCanonicalEncoding.DecodeRelayFrame(page[^1]).Cursor;
        }
        throw new HttpRequestException("Relay approval page was refused; inbox cursor is unchanged.");
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
            var now = clock.GetUtcNow();
            var expired = now >= RelayCanonicalEncoding.DecodeRelayFrame(item.GetEncryptedFrameCopy()).ExpiresAtUtc;
            if (expired) await transport.RetireExpiredAsync(item, now, token).ConfigureAwait(false);
            else await transport.PublishAsync(item, token).ConfigureAwait(false);
            var committed = expired
                ? await _transactions.RetireExpiredAsync(owner.Version, item, token).ConfigureAwait(false)
                : await _transactions.AcknowledgePublishedAsync(owner.Version, item, token).ConfigureAwait(false);
            if (!committed) return (false, processed);
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
