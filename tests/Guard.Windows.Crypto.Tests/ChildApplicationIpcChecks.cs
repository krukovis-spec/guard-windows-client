using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Guard.Application;
using Guard.Application.Readiness;
using Guard.Contracts;
using Guard.Domain;
using Guard.Domain.Policy;
using Guard.Domain.Readiness;
using Guard.Protocol;
using Guard.Service;

namespace Guard.Windows.Crypto.Tests;

// Reuse the real synthetic attested owner, installed test profile and temporary DPAPI stores.
internal static class ChildApplicationIpcChecks
{
    internal static async Task RunAsync(ServiceAuthoritativeStateBoundary boundary, DeviceRelayConfigurationStore configurations,
        EnrollmentDeploymentTrust trust, DateTimeOffset now)
    {
        var account = new WindowsAccountSid("S-1-5-21-11-22-33-1001");
        var other = new WindowsAccountSid("S-1-5-21-11-22-33-1002");
        var before = await boundary.LoadAsync(default);
        if (before.ChildAccountSid == null)
            Check(await boundary.NativeEnrollmentStore.TryCommitAsync(before.Version, before.WithBoundChildAccount(account, now), default), "bind fixture account");
        var owner = await boundary.LoadAsync(default);
        var dependency = new Dependencies { UtcNow = now };
        var source = new Source();
        var observation = new VerifiedBlockedApplicationObservation("child-ipc-event-0001", owner.DeviceId, account,
            new ApplicationIdentity(null, null, null, new string('B', 64)), "Учебная программа", now, now.AddMinutes(10));
        source.Items = new[] { observation };
        GuardServiceIpcOperationHandler Open(IBlockedApplicationObservationSource? observations) => new(boundary,
            new ChildAccountBindingCoordinator(boundary, dependency), new GuardReadinessCoordinator(boundary, dependency), dependency,
            trust, configurations, blockedApplications: observations, dataBoundaryGuard: dependency);
        using var handler = Open(source);
        var dispatcher = new SecureIpcRequestDispatcher(handler);
        var create = ApplicationRequestPayloadCodec.Encode(new CreateApplicationRequestPayload(observation.ObservationId, "Нужно для урока"));
        Task<GuardIpcResponse> Call(GuardVerb verb, WindowsAccountSid? sid, byte[]? data = null, ClientRole role = ClientRole.Child,
            CancellationToken token = default) => dispatcher.DispatchAsync(role,
                new GuardIpcRequest(1, Guid.NewGuid().ToString("D"), verb, data ?? Array.Empty<byte>()), token, sid);

        var initial = await boundary.RelayTransactions.LoadAsync(default);
        foreach (var verb in new[] { GuardVerb.GetBlockedApplications, GuardVerb.CreateApplicationRequest, GuardVerb.GetApplicationRequestHistory })
        {
            var data = verb == GuardVerb.CreateApplicationRequest ? create : Array.Empty<byte>();
            foreach (var sid in new[] { null, other }) Check((await Call(verb, sid, data)).Status == GuardIpcResponseStatus.Forbidden, "SID boundary");
            Check((await Call(verb, account, data, ClientRole.AdminSetup)).Status == GuardIpcResponseStatus.Forbidden, "admin verb boundary");
        }
        Check(source.Calls == 0, "unauthorized request reached source");
        Check((await Call(GuardVerb.GetApplicationRequestHistory, account, new byte[] { 1 })).Status == GuardIpcResponseStatus.InvalidRequest, "history payload accepted");
        Check((await Call(GuardVerb.GetBlockedApplications, account, new byte[] { 1 })).Status == GuardIpcResponseStatus.InvalidRequest, "list payload");
        Check((await Call(GuardVerb.CreateApplicationRequest, account, create.Concat(new byte[] { 1 }).ToArray())).Status == GuardIpcResponseStatus.InvalidRequest, "injected fields");
        using (var absent = Open(null))
            Check((await absent.HandleAsync(ClientRole.Child, new GuardIpcRequest(1, Guid.NewGuid().ToString("D"),
                GuardVerb.GetBlockedApplications, Array.Empty<byte>()), default, account)).Status == GuardIpcResponseStatus.Unavailable, "absent source looked healthy");
        var list = await Call(GuardVerb.GetBlockedApplications, account);
        Check(list.Status == GuardIpcResponseStatus.Success && BlockedApplicationsPayloadCodec.Decode(list.GetPayloadCopy()).Items.Single().DisplayName == observation.DisplayName,
            "trusted list roundtrip");
        source.Items = new[] { new VerifiedBlockedApplicationObservation(observation.ObservationId, owner.DeviceId, other,
            observation.Identity, observation.DisplayName, now, now.AddMinutes(10)) };
        Check((await Call(GuardVerb.GetBlockedApplications, account)).Status == GuardIpcResponseStatus.Unavailable, "foreign list leaked");
        Check((await Call(GuardVerb.CreateApplicationRequest, account, create)).Status != GuardIpcResponseStatus.Success, "foreign event submitted");
        source.Items = new[] { observation, observation };
        Check((await Call(GuardVerb.GetBlockedApplications, account)).Status == GuardIpcResponseStatus.Unavailable, "duplicate list accepted");
        source.Items = new[] { observation };
        source.Before = () => { dependency.UtcNow = now.AddMinutes(10); return Task.CompletedTask; };
        Check((await Call(GuardVerb.GetBlockedApplications, account)).Status == GuardIpcResponseStatus.Unavailable, "expired list accepted");
        dependency.UtcNow = now;
        source.Before = () => { dependency.UtcNow = now.AddTicks(-1); return Task.CompletedTask; };
        Check((await Call(GuardVerb.GetBlockedApplications, account)).Status == GuardIpcResponseStatus.Unavailable, "clock rollback accepted");
        dependency.UtcNow = now;
        source.Before = () => throw new IOException("synthetic unavailable source");
        Check((await Call(GuardVerb.GetBlockedApplications, account)).Status == GuardIpcResponseStatus.Unavailable, "source failure looked empty");
        source.Before = null;
        dependency.Ready = false;
        Check((await Call(GuardVerb.GetApplicationRequestHistory, account)).Status == GuardIpcResponseStatus.Unavailable, "history ignored ACL");
        Check((await Call(GuardVerb.CreateApplicationRequest, account, create)).Status == GuardIpcResponseStatus.Unavailable, "ACL loss accepted");
        dependency.Ready = true;
        Check((await boundary.RelayTransactions.LoadAsync(default)).Version == initial.Version, "refusals changed relay");

        var responses = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Call(GuardVerb.CreateApplicationRequest, account, create)));
        Check(responses.All(x => x.Status == GuardIpcResponseStatus.Success), "concurrent child submission");
        var results = responses.Select(x => BlockedApplicationsPayloadCodec.DecodeQueued(x.GetPayloadCopy())).ToArray();
        Check(results.Count(x => x.Created) == 1 && results.Select(x => x.RequestId).Distinct().Count() == 1, "child dedup");
        using (var reopened = Open(source))
        {
            var repeated = await reopened.HandleAsync(ClientRole.Child, new GuardIpcRequest(1, Guid.NewGuid().ToString("D"),
                GuardVerb.CreateApplicationRequest, create), default, account);
            var queued = BlockedApplicationsPayloadCodec.DecodeQueued(repeated.GetPayloadCopy());
            Check(!queued.Created && queued.RequestId == results[0].RequestId && queued.ExpiresAtUtc == results[0].ExpiresAtUtc, "lost response retry renewed request");
        }
        var saved = await boundary.RelayTransactions.LoadAsync(default);
        Check(saved.Outbox.Count == initial.Outbox.Count + 1 && saved.PolicyRevision == initial.PolicyRevision &&
            saved.SignedReceipts.Count == initial.SignedReceipts.Count && saved.ReconcileIntents.Count == initial.ReconcileIntents.Count, "submission changed policy");
        using (var reopened = Open(null))
        {
            var read = await reopened.HandleAsync(ClientRole.Child, new GuardIpcRequest(1, Guid.NewGuid().ToString("D"),
                GuardVerb.GetApplicationRequestHistory, Array.Empty<byte>()), default, account);
            Check(read.Status == GuardIpcResponseStatus.Success, "history depends on active observation source");
            var own = BlockedApplicationsPayloadCodec.DecodeHistory(read.GetPayloadCopy()).Items.Single(x => x.RequestId == results[0].RequestId);
            Check(own.Status == ApplicationRequestHistoryStatus.AwaitingResponse && own.DisplayName == observation.DisplayName, "history lost original queue");
        }
        dependency.UtcNow = now.AddMinutes(11);
        var expiredHistory = await Call(GuardVerb.GetApplicationRequestHistory, account);
        Check(BlockedApplicationsPayloadCodec.DecodeHistory(expiredHistory.GetPayloadCopy()).Items.Single(x => x.RequestId == results[0].RequestId).Status ==
            ApplicationRequestHistoryStatus.Expired, "expired request appeared live");
        dependency.UtcNow = now;
        Check((await boundary.RelayTransactions.LoadAsync(default)).Version == saved.Version, "history changed durable state");
        NativeApplicationHistoryChecks.Run(owner, boundary.Identity, account, now);

        async Task ChangeOwner()
        {
            var current = await boundary.NativeEnrollmentStore.LoadAsync(default);
            Check(await boundary.NativeEnrollmentStore.TryCommitAsync(current.Version, new DeviceSecurityState(current.DeviceId,
                current.Version + 1, current.HighestAcceptedSequence, current.DesiredPolicyRevision, current.RecentCommandIds,
                current.SetupChallenge, current.TrustedParentKeys, current.ChildAccountSid, current.Enrollment), default), "owner race fixture");
        }
        source.Before = ChangeOwner;
        Check((await Call(GuardVerb.GetBlockedApplications, account)).Status == GuardIpcResponseStatus.Conflict, "stale owner list");
        Check((await Call(GuardVerb.CreateApplicationRequest, account, create)).Status == GuardIpcResponseStatus.Conflict, "stale owner submission");
        using var cancellation = new CancellationTokenSource();
        source.Before = () => { cancellation.Cancel(); return Task.CompletedTask; };
        try { await Call(GuardVerb.CreateApplicationRequest, account, create, token: cancellation.Token); throw new Exception("cancel ignored"); }
        catch (OperationCanceledException) { }
        Check((await boundary.RelayTransactions.LoadAsync(default)).Version == saved.Version, "race/cancel changed relay");
        Console.WriteLine("PASS child IPC: token SID, trusted bounded list, fail-closed dependencies, real durable queue, concurrent/lost reply dedup, owner race/cancel");
    }
    private static void Check(bool value, string message) { if (!value) throw new InvalidOperationException(message); }
    private sealed class Source : IBlockedApplicationObservationSource
    {
        internal IReadOnlyList<VerifiedBlockedApplicationObservation> Items = Array.Empty<VerifiedBlockedApplicationObservation>();
        internal Func<Task>? Before;
        internal int Calls;
        public async Task<IReadOnlyList<VerifiedBlockedApplicationObservation>> ReadRecentAsync(WindowsAccountSid account, CancellationToken token)
        { Calls++; if (Before != null) await Before(); token.ThrowIfCancellationRequested(); return Items; }
        public async Task<VerifiedBlockedApplicationObservation?> ResolveAsync(string id, CancellationToken token)
        { Calls++; if (Before != null) await Before(); token.ThrowIfCancellationRequested(); return Items.SingleOrDefault(x => x.ObservationId == id); }
    }
    private sealed class Dependencies : IServiceUtcClock, IServiceDataBoundaryGuard, IManagedChildAccountValidator, IDeviceReadinessFactsProvider
    {
        public DateTimeOffset UtcNow { get; set; }
        internal bool Ready = true;
        public void DemandReady() { if (!Ready) throw new UnauthorizedAccessException("synthetic boundary loss"); }
        public bool TryValidate(string sid, out WindowsAccountSid binding) => throw new InvalidOperationException("No host account queries.");
        public ReadinessProbeFacts Probe(DeviceSecurityState state, CancellationToken token) => throw new InvalidOperationException("No host probes.");
    }
}
