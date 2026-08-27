using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Guard.Application;
using Guard.Contracts;
using Guard.Domain;
using Guard.Protocol;

namespace Guard.V2.Tests
{
    internal static class Program
    {
        private static int Main()
        {
            var tests = new List<(string Name, Action Run)>
            {
                ("restricts IPC verbs by authenticated client role", RestrictsIpcVerbs),
                ("dispatches IPC only through the server-authenticated role", DispatchesOnlyAuthorizedIpc),
                ("rejects malformed and oversized IPC frames", RejectsInvalidFrames),
                ("limits concurrent IPC handlers", LimitsConcurrentIpcHandlers),
                ("keeps contract byte arrays defensive", KeepsContractArraysDefensive),
                ("allows setup only from an admin session", AllowsSetupOnlyFromAdmin),
                ("fails setup closed when the secret hash contract is broken", RejectsInvalidSetupHash),
                ("consumes setup secrets once and registers a parent key", ConsumesSetupOnce),
                ("commits setup consumption and parent key atomically", CommitsSetupAtomically),
                ("rejects expired setup completion", RejectsExpiredSetup),
                ("accepts only canonical Windows account SIDs", AcceptsOnlyCanonicalWindowsAccountSids),
                ("binds the child SID once through admin setup", BindsChildSidOnce),
                ("rejects replayed and stale parent commands", RejectsReplayedCommands),
                ("persists command acceptance before policy reconciliation", PersistsBeforeReconcile),
                ("keeps committed desired state when reconciliation fails", KeepsCommitOnReconcileFailure),
                ("does not commit commands with an invalid signature", RejectsInvalidSignature),
                ("handles malformed command signatures without throwing", RejectsMalformedSignatureInput),
                ("rejects malformed typed parent decision payloads", RejectsMalformedParentDecision),
                ("rejects a decision for a different pending request", RejectsCrossRequestDecision),
                ("does not let a reducer mutate the trust boundary", RejectsReducerTrustMutation),
                ("does not let a reducer rebind the child account", RejectsReducerChildBindingMutation),
                ("does not let a reducer mutate replay markers", RejectsReducerMarkerMutation)
            };

            var failures = 0;
            foreach (var test in tests)
            {
                try
                {
                    test.Run();
                    Console.WriteLine("PASS " + test.Name);
                }
                catch (Exception exception)
                {
                    failures++;
                    Console.WriteLine("FAIL " + test.Name + ": " + exception.Message);
                }
            }

            Console.WriteLine(failures == 0
                ? "All Guard.V2 contract checks passed."
                : failures + " Guard.V2 contract check(s) failed.");
            return failures == 0 ? 0 : 1;
        }

        private static void RestrictsIpcVerbs()
        {
            Assert(IpcSecurityPolicy.CanInvoke(ClientRole.Child, GuardVerb.GetStatus), "Child status must be allowed.");
            Assert(IpcSecurityPolicy.CanInvoke(ClientRole.Child, GuardVerb.CreateApplicationRequest), "Child app request must be allowed.");
            Assert(!IpcSecurityPolicy.CanInvoke(ClientRole.Child, GuardVerb.BeginSetup), "Child setup must be denied.");
            Assert(!IpcSecurityPolicy.CanInvoke(ClientRole.Child, GuardVerb.BindChildAccount), "Child account binding must be denied.");
            Assert(!IpcSecurityPolicy.CanInvoke(ClientRole.Child, GuardVerb.ApplyParentDecision), "Child parent decision must be denied.");
            Assert(!IpcSecurityPolicy.CanInvoke(ClientRole.Child, GuardVerb.ReconcilePolicy), "Child reconciliation must be denied.");
            Assert(IpcSecurityPolicy.CanInvoke(ClientRole.AdminSetup, GuardVerb.BeginSetup), "Admin setup must be allowed.");
            Assert(IpcSecurityPolicy.CanInvoke(ClientRole.AdminSetup, GuardVerb.BindChildAccount), "Admin child binding must be allowed.");
            Assert(!IpcSecurityPolicy.CanInvoke(ClientRole.AdminSetup, GuardVerb.ApplyParentDecision), "Admin IPC is not a parent-decision channel.");
            Assert(IpcSecurityPolicy.CanInvoke(ClientRole.Proxy, GuardVerb.EvaluateDomain), "Proxy domain evaluation must be allowed.");
            Assert(!IpcSecurityPolicy.CanInvoke(ClientRole.Proxy, GuardVerb.GetStatus), "Proxy status must be denied.");
            Assert(!IpcSecurityPolicy.CanInvoke(ClientRole.Unknown, GuardVerb.GetStatus), "Unknown role must be denied.");
        }

        private static void DispatchesOnlyAuthorizedIpc()
        {
            var handler = new RecordingIpcHandler();
            var dispatcher = new SecureIpcRequestDispatcher(handler);
            var requestId = Guid.NewGuid().ToString("D");
            var setup = new GuardIpcRequest(
                GuardProtocol.CurrentVersion,
                requestId,
                GuardVerb.BeginSetup,
                Array.Empty<byte>());
            var childResult = dispatcher
                .DispatchAsync(ClientRole.Child, setup, CancellationToken.None)
                .GetAwaiter()
                .GetResult();
            AssertEqual(GuardIpcResponseStatus.Forbidden, childResult.Status, "Child reached an admin setup verb.");
            AssertEqual(0, handler.CallCount, "Forbidden IPC reached the operation handler.");

            var adminResult = dispatcher
                .DispatchAsync(ClientRole.AdminSetup, setup, CancellationToken.None)
                .GetAwaiter()
                .GetResult();
            AssertEqual(GuardIpcResponseStatus.Success, adminResult.Status, "Admin setup verb was rejected.");
            AssertEqual(ClientRole.AdminSetup, handler.LastRole, "Handler role did not come from the authenticated endpoint.");
            AssertEqual(requestId, adminResult.RequestId, "Response was not correlated to the request.");

            handler.ThrowOnCall = true;
            var sanitized = dispatcher
                .DispatchAsync(ClientRole.AdminSetup, setup, CancellationToken.None)
                .GetAwaiter()
                .GetResult();
            AssertEqual(GuardIpcResponseStatus.InternalError, sanitized.Status, "Handler failure was exposed to the IPC client.");
            AssertEqual(0, sanitized.PayloadLength, "Internal failure leaked a response payload.");
        }

        private static void RejectsInvalidFrames()
        {
            var valid = new GuardIpcRequest(
                GuardProtocol.CurrentVersion,
                Guid.NewGuid().ToString("D"),
                GuardVerb.GetStatus,
                Array.Empty<byte>());
            AssertEqual(IpcValidationStatus.Valid, IpcSecurityPolicy.Validate(valid), "Valid frame was rejected.");

            var oldProtocol = new GuardIpcRequest(0, Guid.NewGuid().ToString("D"), GuardVerb.GetStatus, Array.Empty<byte>());
            AssertEqual(IpcValidationStatus.UnsupportedProtocol, IpcSecurityPolicy.Validate(oldProtocol), "Old protocol was accepted.");

            var malformedId = new GuardIpcRequest(GuardProtocol.CurrentVersion, "not-a-guid", GuardVerb.GetStatus, Array.Empty<byte>());
            AssertEqual(IpcValidationStatus.InvalidRequestId, IpcSecurityPolicy.Validate(malformedId), "Malformed request id was accepted.");

            var unknownVerb = new GuardIpcRequest(GuardProtocol.CurrentVersion, Guid.NewGuid().ToString("D"), (GuardVerb)999, Array.Empty<byte>());
            AssertEqual(IpcValidationStatus.UnknownVerb, IpcSecurityPolicy.Validate(unknownVerb), "Unknown verb was accepted.");

            var oversized = new GuardIpcRequest(
                GuardProtocol.CurrentVersion,
                Guid.NewGuid().ToString("D"),
                GuardVerb.GetStatus,
                new byte[GuardProtocol.MaximumFrameBytes + 1]);
            AssertEqual(IpcValidationStatus.PayloadTooLarge, IpcSecurityPolicy.Validate(oversized), "Oversized payload was accepted.");
        }

        private static void LimitsConcurrentIpcHandlers()
        {
            var limiter = new IpcConnectionLimiter(maximumConnections: 2);
            IDisposable? first;
            IDisposable? second;
            IDisposable? rejected;
            Assert(limiter.TryAcquire(out first) && first != null, "First IPC handler was rejected.");
            Assert(limiter.TryAcquire(out second) && second != null, "Second IPC handler was rejected.");
            Assert(!limiter.TryAcquire(out rejected) && rejected == null, "Connection quota was bypassed.");
            AssertEqual(2, limiter.ActiveConnections, "Connection count was inaccurate.");

            first!.Dispose();
            first.Dispose();
            AssertEqual(1, limiter.ActiveConnections, "Idempotent lease disposal corrupted the connection count.");
            Assert(limiter.TryAcquire(out rejected) && rejected != null, "Released capacity was not restored.");
            second!.Dispose();
            rejected!.Dispose();
            AssertEqual(0, limiter.ActiveConnections, "Connection leases were not released.");
        }

        private static void KeepsContractArraysDefensive()
        {
            var source = new byte[] { 1, 2, 3 };
            var request = new GuardIpcRequest(GuardProtocol.CurrentVersion, Guid.NewGuid().ToString("D"), GuardVerb.GetStatus, source);
            source[0] = 99;
            var firstCopy = request.GetPayloadCopy();
            AssertEqual((byte)1, firstCopy[0], "Request retained the caller array.");
            firstCopy[1] = 88;
            AssertEqual((byte)2, request.GetPayloadCopy()[1], "Request exposed its internal payload.");

            var signature = new byte[] { 4, 5 };
            var envelope = CreateEnvelope(signature: signature);
            signature[0] = 77;
            AssertEqual((byte)4, envelope.GetSignatureCopy()[0], "Envelope retained the caller signature array.");
        }

        private static void AllowsSetupOnlyFromAdmin()
        {
            var now = DateTimeOffset.UtcNow;
            var state = CreateUnprovisionedState();
            var ceremony = CreateCeremony();

            var childAttempt = ceremony.Begin(ClientRole.Child, state, now, TimeSpan.FromMinutes(5));
            AssertEqual(SetupOperationStatus.Forbidden, childAttempt.Status, "Child started setup.");
            AssertEqual(state.Version, childAttempt.State.Version, "Forbidden setup changed state.");

            var adminAttempt = ceremony.Begin(ClientRole.AdminSetup, state, now, TimeSpan.FromMinutes(5));
            AssertEqual(SetupOperationStatus.Succeeded, adminAttempt.Status, "Admin setup was rejected.");
            Assert(adminAttempt.Ticket != null, "Setup ticket was not returned once.");
            Assert(adminAttempt.State.SetupChallenge != null, "Setup hash was not persisted in state.");
            Assert(!adminAttempt.State.IsProvisioned, "Beginning setup provisioned the device prematurely.");

            var repeated = ceremony.Begin(ClientRole.AdminSetup, adminAttempt.State, now.AddSeconds(1), TimeSpan.FromMinutes(5));
            AssertEqual(SetupOperationStatus.ChallengeAlreadyActive, repeated.Status, "Active setup was silently rotated.");
        }

        private static void ConsumesSetupOnce()
        {
            var now = DateTimeOffset.UtcNow;
            var ceremony = CreateCeremony();
            var begin = ceremony.Begin(ClientRole.AdminSetup, CreateUnprovisionedState(), now, TimeSpan.FromMinutes(5));
            var ticket = RequireTicket(begin);
            var secret = ticket.GetSecretCopy();
            var firstParentKey = CreateParentKey(1);
            var secondParentKey = CreateParentKey(2);

            var wrong = (byte[])secret.Clone();
            wrong[0] ^= 0x5A;
            var wrongAttempt = ceremony.Complete(
                ClientRole.ParentRelay,
                begin.State,
                ticket.ChallengeId,
                wrong,
                firstParentKey,
                now.AddMinutes(1));
            AssertEqual(SetupOperationStatus.Rejected, wrongAttempt.Status, "Wrong setup secret was accepted.");

            var completed = ceremony.Complete(
                ClientRole.ParentRelay,
                begin.State,
                ticket.ChallengeId,
                secret,
                firstParentKey,
                now.AddMinutes(1));
            AssertEqual(SetupOperationStatus.Succeeded, completed.Status, "Valid setup was rejected.");
            Assert(completed.State.IsProvisioned, "Parent key was not registered.");
            Assert(GuardIdentifier.IsCanonicalToken(firstParentKey.KeyId), "Derived parent key id is not canonical.");
            Assert(completed.State.TrustsParentKey(firstParentKey.KeyId), "Registered key is not trusted.");
            Assert(completed.State.TrustedParentKeys[0].Equals(firstParentKey), "Registered public key material changed.");
            Assert(completed.State.SetupChallenge == null, "Consumed setup challenge remained active.");

            var replay = ceremony.Complete(
                ClientRole.ParentRelay,
                completed.State,
                ticket.ChallengeId,
                secret,
                secondParentKey,
                now.AddMinutes(2));
            AssertEqual(SetupOperationStatus.Forbidden, replay.Status, "Setup ticket was reusable.");
        }

        private static void CommitsSetupAtomically()
        {
            var now = DateTimeOffset.UtcNow;
            var ceremony = CreateCeremony();
            var begin = ceremony.Begin(ClientRole.AdminSetup, CreateUnprovisionedState(), now, TimeSpan.FromMinutes(5));
            var ticket = RequireTicket(begin);
            var store = new CoordinatedStateStore(begin.State);
            var coordinator = new SetupCoordinator(store, ceremony);

            var first = coordinator.CompleteAsync(
                ClientRole.ParentRelay,
                ticket.ChallengeId,
                ticket.GetSecretCopy(),
                CreateParentKey(1),
                now.AddMinutes(1),
                CancellationToken.None);
            var second = coordinator.CompleteAsync(
                ClientRole.ParentRelay,
                ticket.ChallengeId,
                ticket.GetSecretCopy(),
                CreateParentKey(2),
                now.AddMinutes(1),
                CancellationToken.None);
            var results = Task.WhenAll(first, second).GetAwaiter().GetResult();

            var succeeded = 0;
            var conflicted = 0;
            foreach (var result in results)
            {
                if (result.Status == SetupOperationStatus.Succeeded)
                {
                    succeeded++;
                }
                else if (result.Status == SetupOperationStatus.StateConflict)
                {
                    conflicted++;
                }
            }

            AssertEqual(1, succeeded, "Concurrent setup completed more or less than once.");
            AssertEqual(1, conflicted, "The losing setup did not report a state conflict.");
            AssertEqual(1, store.State.TrustedParentKeys.Count, "More than one parent key was committed.");
            Assert(store.State.SetupChallenge == null, "Committed setup left its challenge active.");
        }

        private static void RejectsInvalidSetupHash()
        {
            var ceremony = new SetupCeremony(
                new DeterministicSecretGenerator(),
                new InvalidLengthSecretHasher(),
                new AcceptingTrustAnchorValidator());
            var result = ceremony.Begin(
                ClientRole.AdminSetup,
                CreateUnprovisionedState(),
                DateTimeOffset.UtcNow,
                TimeSpan.FromMinutes(5));

            AssertEqual(SetupOperationStatus.Rejected, result.Status, "An invalid secret hash provisioned setup state.");
            Assert(result.State.SetupChallenge == null, "An invalid secret hash was persisted.");
        }

        private static void RejectsExpiredSetup()
        {
            var now = DateTimeOffset.UtcNow;
            var ceremony = CreateCeremony();
            var begin = ceremony.Begin(ClientRole.AdminSetup, CreateUnprovisionedState(), now, TimeSpan.FromMinutes(1));
            var ticket = RequireTicket(begin);
            var completed = ceremony.Complete(
                ClientRole.ParentRelay,
                begin.State,
                ticket.ChallengeId,
                ticket.GetSecretCopy(),
                CreateParentKey(1),
                now.AddMinutes(1));
            AssertEqual(SetupOperationStatus.Rejected, completed.Status, "Expired setup ticket was accepted.");
        }

        private static void AcceptsOnlyCanonicalWindowsAccountSids()
        {
            Assert(WindowsAccountSid.IsCanonical("S-1-5-21-1001-2002-3003-1004"), "Canonical child SID was rejected.");
            Assert(!WindowsAccountSid.IsCanonical("s-1-5-21-1001"), "Lowercase SID prefix was accepted.");
            Assert(!WindowsAccountSid.IsCanonical("S-01-5-21-1001"), "Non-canonical revision was accepted.");
            Assert(!WindowsAccountSid.IsCanonical("S-1-5-21-4294967296"), "Oversized sub-authority was accepted.");
            Assert(!WindowsAccountSid.IsCanonical("S-1-281474976710656-21-1001"), "Oversized identifier authority was accepted.");
        }

        private static void BindsChildSidOnce()
        {
            var now = DateTimeOffset.UtcNow;
            var childSid = new WindowsAccountSid("S-1-5-21-1001-2002-3003-1004");
            var unprovisionedStore = new FakeStateStore(CreateUnprovisionedState());
            var unprovisioned = new ChildAccountBindingCoordinator(unprovisionedStore, new FixedChildAccountValidator(childSid))
                .BindAsync(ClientRole.AdminSetup, childSid.Value, now, CancellationToken.None)
                .GetAwaiter()
                .GetResult();
            AssertEqual(ChildAccountBindingStatus.ParentNotProvisioned, unprovisioned.Status, "Child was bound before parent provisioning.");

            var setup = CreateCeremony().Begin(
                ClientRole.AdminSetup,
                CreateUnprovisionedState(),
                now,
                TimeSpan.FromMinutes(5));
            var expiredSetupStore = new FakeStateStore(setup.State);
            var expiredSetupBinding = new ChildAccountBindingCoordinator(
                    expiredSetupStore,
                    new FixedChildAccountValidator(childSid))
                .BindAsync(
                    ClientRole.AdminSetup,
                    childSid.Value,
                    now.AddMinutes(5),
                    CancellationToken.None)
                .GetAwaiter()
                .GetResult();
            AssertEqual(
                ChildAccountBindingStatus.ParentNotProvisioned,
                expiredSetupBinding.Status,
                "An expired setup ceremony authorized child binding.");

            var setupStore = new FakeStateStore(setup.State);
            var setupBound = new ChildAccountBindingCoordinator(
                    setupStore,
                    new FixedChildAccountValidator(childSid))
                .BindAsync(
                    ClientRole.AdminSetup,
                    childSid.Value,
                    now,
                    CancellationToken.None)
                .GetAwaiter()
                .GetResult();
            AssertEqual(
                ChildAccountBindingStatus.Succeeded,
                setupBound.Status,
                "An authenticated admin could not bind the child during the active setup ceremony.");

            var store = new FakeStateStore(CreateProvisionedState());
            var coordinator = new ChildAccountBindingCoordinator(store, new FixedChildAccountValidator(childSid));
            var childAttempt = coordinator
                .BindAsync(ClientRole.Child, childSid.Value, now, CancellationToken.None)
                .GetAwaiter()
                .GetResult();
            AssertEqual(ChildAccountBindingStatus.Forbidden, childAttempt.Status, "Child bound its own account.");

            var bound = coordinator
                .BindAsync(ClientRole.AdminSetup, childSid.Value, now, CancellationToken.None)
                .GetAwaiter()
                .GetResult();
            AssertEqual(ChildAccountBindingStatus.Succeeded, bound.Status, "Admin setup did not bind the child account.");
            AssertEqual(childSid, store.State.ChildAccountSid, "Bound child SID was not committed.");

            var repeated = coordinator
                .BindAsync(
                    ClientRole.AdminSetup,
                    "S-1-5-21-1001-2002-3003-1005",
                    now,
                    CancellationToken.None)
                .GetAwaiter()
                .GetResult();
            AssertEqual(ChildAccountBindingStatus.AlreadyBound, repeated.Status, "Child account binding was replaceable.");
        }

        private static void RejectsReplayedCommands()
        {
            var now = DateTimeOffset.UtcNow;
            var state = CreateProvisionedState(highestSequence: 4, recentCommandIds: new[] { "cmd-000000000004" });
            var policy = new CommandAcceptancePolicy(TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(5));

            AssertEqual(
                CommandAcceptanceStatus.Accepted,
                CommandAcceptanceEvaluator.Evaluate(state, Metadata("cmd-000000000005", "device-v2-000001", 5, now, now.AddMinutes(2)), now, policy),
                "Fresh command was rejected.");
            AssertEqual(
                CommandAcceptanceStatus.WrongDevice,
                CommandAcceptanceEvaluator.Evaluate(state, Metadata("cmd-000000000005", "device-v2-999999", 5, now, now.AddMinutes(2)), now, policy),
                "Wrong-device command was accepted.");
            AssertEqual(
                CommandAcceptanceStatus.InvalidSequence,
                CommandAcceptanceEvaluator.Evaluate(state, Metadata("cmd-000000000003", "device-v2-000001", 3, now, now.AddMinutes(2)), now, policy),
                "Stale sequence was accepted.");
            AssertEqual(
                CommandAcceptanceStatus.InvalidSequence,
                CommandAcceptanceEvaluator.Evaluate(state, Metadata("cmd-000000000004", "device-v2-000001", 4, now, now.AddMinutes(2)), now, policy),
                "Replayed command was accepted.");
            AssertEqual(
                CommandAcceptanceStatus.Expired,
                CommandAcceptanceEvaluator.Evaluate(state, Metadata("cmd-000000000005", "device-v2-000001", 5, now.AddMinutes(-2), now), now, policy),
                "Expired command was accepted.");
            AssertEqual(
                CommandAcceptanceStatus.IssuedInFuture,
                CommandAcceptanceEvaluator.Evaluate(state, Metadata("cmd-000000000005", "device-v2-000001", 5, now.AddMinutes(2), now.AddMinutes(3)), now, policy),
                "Future-issued command was accepted.");
            AssertEqual(
                CommandAcceptanceStatus.InvalidLifetime,
                CommandAcceptanceEvaluator.Evaluate(state, Metadata("cmd-000000000005", "device-v2-000001", 5, now, now.AddMinutes(6)), now, policy),
                "Overlong command lifetime was accepted.");
        }

        private static void PersistsBeforeReconcile()
        {
            var store = new FakeStateStore(CreateProvisionedState());
            var reconciler = new RecordingReconciler(store, shouldThrow: false);
            var coordinator = CreateCoordinator(store, reconciler, signatureValid: true);
            var result = coordinator.ProcessAsync(CreateEnvelope(), DateTimeOffset.UtcNow, CancellationToken.None).GetAwaiter().GetResult();

            AssertEqual(CommandProcessingStatus.Applied, result.Status, "Valid command was not applied.");
            Assert(reconciler.SawCommittedState, "Reconciliation ran before the state commit.");
            AssertEqual(1L, store.State.HighestAcceptedSequence, "Accepted sequence was not persisted.");
            Assert(store.State.HasAcceptedCommand("cmd-000000000001"), "Command id was not persisted.");
        }

        private static void KeepsCommitOnReconcileFailure()
        {
            var store = new FakeStateStore(CreateProvisionedState());
            var reconciler = new RecordingReconciler(store, shouldThrow: true);
            var coordinator = CreateCoordinator(store, reconciler, signatureValid: true);
            var result = coordinator.ProcessAsync(CreateEnvelope(), DateTimeOffset.UtcNow, CancellationToken.None).GetAwaiter().GetResult();

            AssertEqual(CommandProcessingStatus.AcceptedPendingReconciliation, result.Status, "Reconcile failure reported false rollback.");
            AssertEqual(1L, store.State.HighestAcceptedSequence, "Accepted command marker was rolled back.");
        }

        private static void RejectsInvalidSignature()
        {
            var store = new FakeStateStore(CreateProvisionedState());
            var coordinator = CreateCoordinator(store, new RecordingReconciler(store, shouldThrow: false), signatureValid: false);
            var result = coordinator.ProcessAsync(CreateEnvelope(), DateTimeOffset.UtcNow, CancellationToken.None).GetAwaiter().GetResult();

            AssertEqual(CommandProcessingStatus.InvalidSignature, result.Status, "Invalid signature was not rejected.");
            AssertEqual(0L, store.State.HighestAcceptedSequence, "Invalid signature changed state.");
            AssertEqual(0, store.CommitCount, "Invalid signature reached the commit boundary.");
        }

        private static void RejectsMalformedSignatureInput()
        {
            var store = new FakeStateStore(CreateProvisionedState());
            var throwing = CreateCoordinator(
                store,
                new RecordingReconciler(store, shouldThrow: false),
                signatureValid: true,
                verifier: new ThrowingSignatureVerifier());
            var verifierFailure = throwing.ProcessAsync(CreateEnvelope(), DateTimeOffset.UtcNow, CancellationToken.None).GetAwaiter().GetResult();
            AssertEqual(CommandProcessingStatus.InvalidSignature, verifierFailure.Status, "Verifier exception escaped the command boundary.");

            var malformed = CreateCoordinator(
                store,
                new RecordingReconciler(store, shouldThrow: false),
                signatureValid: true);
            var invalidEnvelope = CreateEnvelope(nonce: "nonce with spaces 01");
            var malformedResult = malformed.ProcessAsync(invalidEnvelope, DateTimeOffset.UtcNow, CancellationToken.None).GetAwaiter().GetResult();
            AssertEqual(CommandProcessingStatus.Rejected, malformedResult.Status, "Non-canonical signed metadata reached the verifier.");
            AssertEqual(0, store.CommitCount, "Malformed signature input changed state.");
        }

        private static void RejectsMalformedParentDecision()
        {
            var store = new FakeStateStore(CreateProvisionedState());
            var coordinator = CreateCoordinator(store, new RecordingReconciler(store, shouldThrow: false), signatureValid: true);
            var result = coordinator.ProcessAsync(
                CreateEnvelope(payload: new byte[] { 1, 2, 3 }),
                DateTimeOffset.UtcNow,
                CancellationToken.None).GetAwaiter().GetResult();

            AssertEqual(CommandProcessingStatus.Rejected, result.Status, "Opaque malformed parent payload was accepted.");
            AssertEqual(0, store.CommitCount, "Malformed parent payload changed state.");
        }

        private static void RejectsCrossRequestDecision()
        {
            var store = new FakeStateStore(CreateProvisionedState());
            var coordinator = CreateCoordinator(store, new RecordingReconciler(store, shouldThrow: false), signatureValid: true);
            var result = coordinator.ProcessAsync(
                CreateEnvelope(payload: CreateParentDecisionPayload("8f31a964-65d1-4f8f-91f7-5cf2ea3f7da4")),
                DateTimeOffset.UtcNow,
                CancellationToken.None).GetAwaiter().GetResult();

            AssertEqual(CommandProcessingStatus.Rejected, result.Status, "A decision crossed access-request boundaries.");
            AssertEqual(0, store.CommitCount, "A cross-request decision changed state.");
        }

        private static void RejectsReducerTrustMutation()
        {
            var store = new FakeStateStore(CreateProvisionedState());
            var reconciler = new RecordingReconciler(store, shouldThrow: false);
            var coordinator = CreateCoordinator(
                store,
                reconciler,
                signatureValid: true,
                reducer: new TrustDroppingReducer());
            var result = coordinator.ProcessAsync(CreateEnvelope(), DateTimeOffset.UtcNow, CancellationToken.None).GetAwaiter().GetResult();

            AssertEqual(CommandProcessingStatus.Rejected, result.Status, "A reducer changed the trusted-key boundary.");
            AssertEqual(0, store.CommitCount, "Trust-boundary mutation reached the commit boundary.");
        }

        private static void RejectsReducerChildBindingMutation()
        {
            var store = new FakeStateStore(CreateProvisionedState(
                childAccountSid: new WindowsAccountSid("S-1-5-21-1001-2002-3003-1004")));
            var reconciler = new RecordingReconciler(store, shouldThrow: false);
            var coordinator = CreateCoordinator(
                store,
                reconciler,
                signatureValid: true,
                reducer: new ChildRebindingReducer());
            var result = coordinator.ProcessAsync(CreateEnvelope(), DateTimeOffset.UtcNow, CancellationToken.None).GetAwaiter().GetResult();

            AssertEqual(CommandProcessingStatus.Rejected, result.Status, "A reducer changed the child-account boundary.");
            AssertEqual(0, store.CommitCount, "Child-account mutation reached the commit boundary.");
        }

        private static void RejectsReducerMarkerMutation()
        {
            var store = new FakeStateStore(CreateProvisionedState(recentCommandIds: new[] { "cmd-000000000000" }));
            var reconciler = new RecordingReconciler(store, shouldThrow: false);
            var coordinator = CreateCoordinator(
                store,
                reconciler,
                signatureValid: true,
                reducer: new MarkerDroppingReducer());
            var result = coordinator.ProcessAsync(CreateEnvelope(), DateTimeOffset.UtcNow, CancellationToken.None).GetAwaiter().GetResult();

            AssertEqual(CommandProcessingStatus.Rejected, result.Status, "A reducer changed replay markers.");
            AssertEqual(0, store.CommitCount, "Replay-marker mutation reached the commit boundary.");
        }

        private static SetupCeremony CreateCeremony()
        {
            return new SetupCeremony(
                new DeterministicSecretGenerator(),
                new Sha256SecretHasher(),
                new AcceptingTrustAnchorValidator());
        }

        private static SetupTicket RequireTicket(SetupBeginResult result)
        {
            if (result.Ticket == null)
            {
                throw new InvalidOperationException("Expected a setup ticket.");
            }

            return result.Ticket;
        }

        private static DeviceSecurityState CreateUnprovisionedState()
        {
            return new DeviceSecurityState("device-v2-000001", 0, 0, 0);
        }

        private static DeviceSecurityState CreateProvisionedState(
            long highestSequence = 0,
            IEnumerable<string>? recentCommandIds = null,
            WindowsAccountSid? childAccountSid = null)
        {
            return new DeviceSecurityState(
                "device-v2-000001",
                version: 0,
                highestAcceptedSequence: highestSequence,
                desiredPolicyRevision: 0,
                recentCommandIds: recentCommandIds,
                trustedParentKeys: new[] { CreateParentKey(1) },
                childAccountSid: childAccountSid);
        }

        private static CommandMetadata Metadata(
            string commandId,
            string deviceId,
            long sequence,
            DateTimeOffset issuedAt,
            DateTimeOffset expiresAt)
        {
            return new CommandMetadata(commandId, deviceId, sequence, issuedAt, expiresAt, "nonce-000000000001");
        }

        private static SignedCommandEnvelope CreateEnvelope(
            byte[]? signature = null,
            string nonce = "nonce-000000000001",
            byte[]? payload = null)
        {
            var now = DateTimeOffset.FromUnixTimeMilliseconds(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
            return new SignedCommandEnvelope(
                "cmd-000000000001",
                "device-v2-000001",
                1,
                now,
                now.AddMinutes(2),
                nonce,
                CreateParentKey(1).KeyId,
                payload ?? CreateParentDecisionPayload(),
                signature ?? new byte[] { 9, 8, 7 });
        }

        private static byte[] CreateParentDecisionPayload(string requestId = "8f31a964-65d1-4f8f-91f7-5cf2ea3f7da3")
        {
            return ParentDecisionPayloadCodec.Encode(new ParentDecisionCommand(
                requestId,
                GuardTargetKind.Site,
                "example.com",
                ParentDecisionKind.AllowAlways));
        }

        private static ParentTrustAnchor CreateParentKey(byte seed)
        {
            var publicKey = new byte[91];
            for (var index = 0; index < publicKey.Length; index++)
            {
                publicKey[index] = unchecked((byte)(seed + index));
            }

            return new ParentTrustAnchor(ParentKeyAlgorithm.EcdsaP256Sha256, publicKey);
        }

        private static SecureCommandCoordinator CreateCoordinator(
            FakeStateStore store,
            RecordingReconciler reconciler,
            bool signatureValid,
            IParentCommandReducer? reducer = null,
            ICommandSignatureVerifier? verifier = null,
            IPendingAccessRequestValidator? pendingRequestValidator = null)
        {
            return new SecureCommandCoordinator(
                store,
                verifier ?? new FixedSignatureVerifier(signatureValid),
                pendingRequestValidator ?? new ExactPendingRequestValidator(),
                reducer ?? new IdentityReducer(),
                reconciler,
                new CommandAcceptancePolicy(TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(5)));
        }

        private static void Assert(bool condition, string message)
        {
            if (!condition)
            {
                throw new InvalidOperationException(message);
            }
        }

        private static void AssertEqual<T>(T expected, T actual, string message)
        {
            if (!EqualityComparer<T>.Default.Equals(expected, actual))
            {
                throw new InvalidOperationException(message + " Expected=" + expected + " Actual=" + actual);
            }
        }

        private sealed class DeterministicSecretGenerator : ISetupSecretGenerator
        {
            public string CreateChallengeId()
            {
                return "setup-000000000001";
            }

            public byte[] CreateSecret(int byteCount)
            {
                var result = new byte[byteCount];
                for (var index = 0; index < result.Length; index++)
                {
                    result[index] = (byte)(index + 1);
                }

                return result;
            }
        }

        private sealed class Sha256SecretHasher : ISetupSecretHasher
        {
            public byte[] ComputeHash(byte[] secret)
            {
                return SHA256.HashData(secret);
            }
        }

        private sealed class AcceptingTrustAnchorValidator : IParentTrustAnchorValidator
        {
            public bool IsValid(ParentTrustAnchor trustAnchor)
            {
                return trustAnchor != null &&
                       trustAnchor.Algorithm == ParentKeyAlgorithm.EcdsaP256Sha256 &&
                       GuardIdentifier.IsCanonicalToken(trustAnchor.KeyId) &&
                       trustAnchor.GetSubjectPublicKeyInfoCopy().Length == 91;
            }
        }

        private sealed class InvalidLengthSecretHasher : ISetupSecretHasher
        {
            public byte[] ComputeHash(byte[] secret)
            {
                return new byte[SetupChallengeState.SecretHashBytes + 1];
            }
        }

        private sealed class FakeStateStore : IAuthoritativeStateStore
        {
            public FakeStateStore(DeviceSecurityState state)
            {
                State = state;
            }

            public DeviceSecurityState State { get; private set; }

            public int CommitCount { get; private set; }

            public Task<DeviceSecurityState> LoadAsync(CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                return Task.FromResult(State);
            }

            public Task<bool> TryCommitAsync(long expectedVersion, DeviceSecurityState nextState, CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (State.Version != expectedVersion)
                {
                    return Task.FromResult(false);
                }

                State = nextState;
                CommitCount++;
                return Task.FromResult(true);
            }
        }

        private sealed class CoordinatedStateStore : IAuthoritativeStateStore
        {
            private readonly object _gate = new object();
            private readonly TaskCompletionSource<bool> _releaseLoads =
                new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            private DeviceSecurityState _state;
            private int _loadCount;

            public CoordinatedStateStore(DeviceSecurityState state)
            {
                _state = state;
            }

            public DeviceSecurityState State
            {
                get
                {
                    lock (_gate)
                    {
                        return _state;
                    }
                }
            }

            public async Task<DeviceSecurityState> LoadAsync(CancellationToken cancellationToken)
            {
                DeviceSecurityState snapshot;
                lock (_gate)
                {
                    snapshot = _state;
                }

                if (Interlocked.Increment(ref _loadCount) == 2)
                {
                    _releaseLoads.TrySetResult(true);
                }

                await _releaseLoads.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
                return snapshot;
            }

            public Task<bool> TryCommitAsync(long expectedVersion, DeviceSecurityState nextState, CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                lock (_gate)
                {
                    if (_state.Version != expectedVersion)
                    {
                        return Task.FromResult(false);
                    }

                    _state = nextState;
                    return Task.FromResult(true);
                }
            }
        }

        private sealed class FixedSignatureVerifier : ICommandSignatureVerifier
        {
            private readonly bool _result;

            public FixedSignatureVerifier(bool result)
            {
                _result = result;
            }

            public bool Verify(ParentTrustAnchor trustAnchor, byte[] canonicalHash, byte[] signature)
            {
                return _result;
            }
        }

        private sealed class ThrowingSignatureVerifier : ICommandSignatureVerifier
        {
            public bool Verify(ParentTrustAnchor trustAnchor, byte[] canonicalHash, byte[] signature)
            {
                throw new CryptographicException("Synthetic malformed signature.");
            }
        }

        private sealed class ExactPendingRequestValidator : IPendingAccessRequestValidator
        {
            public bool IsExactPendingMatch(DeviceSecurityState currentState, ParentDecisionCommand command)
            {
                return string.Equals(command.RequestId, "8f31a964-65d1-4f8f-91f7-5cf2ea3f7da3", StringComparison.Ordinal) &&
                       command.TargetKind == GuardTargetKind.Site &&
                       string.Equals(command.TargetIdentity, "example.com", StringComparison.Ordinal);
            }
        }

        private sealed class IdentityReducer : IParentCommandReducer
        {
            public DeviceSecurityState ApplyDesiredMutation(DeviceSecurityState acceptedState, ParentDecisionCommand command)
            {
                return acceptedState;
            }
        }

        private sealed class TrustDroppingReducer : IParentCommandReducer
        {
            public DeviceSecurityState ApplyDesiredMutation(DeviceSecurityState acceptedState, ParentDecisionCommand command)
            {
                return new DeviceSecurityState(
                    acceptedState.DeviceId,
                    acceptedState.Version,
                    acceptedState.HighestAcceptedSequence,
                    acceptedState.DesiredPolicyRevision,
                    acceptedState.RecentCommandIds,
                    acceptedState.SetupChallenge,
                    trustedParentKeys: Array.Empty<ParentTrustAnchor>());
            }
        }

        private sealed class MarkerDroppingReducer : IParentCommandReducer
        {
            public DeviceSecurityState ApplyDesiredMutation(DeviceSecurityState acceptedState, ParentDecisionCommand command)
            {
                return new DeviceSecurityState(
                    acceptedState.DeviceId,
                    acceptedState.Version,
                    acceptedState.HighestAcceptedSequence,
                    acceptedState.DesiredPolicyRevision,
                    recentCommandIds: new[] { "cmd-000000000001" },
                    setupChallenge: acceptedState.SetupChallenge,
                    trustedParentKeys: acceptedState.TrustedParentKeys);
            }
        }

        private sealed class ChildRebindingReducer : IParentCommandReducer
        {
            public DeviceSecurityState ApplyDesiredMutation(DeviceSecurityState acceptedState, ParentDecisionCommand command)
            {
                return new DeviceSecurityState(
                    acceptedState.DeviceId,
                    acceptedState.Version,
                    acceptedState.HighestAcceptedSequence,
                    acceptedState.DesiredPolicyRevision,
                    acceptedState.RecentCommandIds,
                    acceptedState.SetupChallenge,
                    acceptedState.TrustedParentKeys,
                    new WindowsAccountSid("S-1-5-21-1001-2002-3003-1005"));
            }
        }

        private sealed class RecordingReconciler : IPolicyReconciler
        {
            private readonly FakeStateStore _store;
            private readonly bool _shouldThrow;

            public RecordingReconciler(FakeStateStore store, bool shouldThrow)
            {
                _store = store;
                _shouldThrow = shouldThrow;
            }

            public bool SawCommittedState { get; private set; }

            public Task ReconcileAsync(DeviceSecurityState desiredState, CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                SawCommittedState = ReferenceEquals(_store.State, desiredState) &&
                                    _store.State.HighestAcceptedSequence == desiredState.HighestAcceptedSequence;
                if (_shouldThrow)
                {
                    throw new InvalidOperationException("Synthetic reconciliation failure.");
                }

                return Task.CompletedTask;
            }
        }

        private sealed class FixedChildAccountValidator : IManagedChildAccountValidator
        {
            private readonly WindowsAccountSid _binding;

            public FixedChildAccountValidator(WindowsAccountSid binding)
            {
                _binding = binding;
            }

            public bool TryValidate(string candidateSid, out WindowsAccountSid binding)
            {
                binding = _binding;
                return string.Equals(candidateSid, _binding.Value, StringComparison.Ordinal);
            }
        }

        private sealed class RecordingIpcHandler : IGuardIpcOperationHandler
        {
            public int CallCount { get; private set; }

            public ClientRole LastRole { get; private set; }

            public bool ThrowOnCall { get; set; }

            public Task<GuardIpcResponse> HandleAsync(
                ClientRole authenticatedRole,
                GuardIpcRequest request,
                CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                CallCount++;
                LastRole = authenticatedRole;
                if (ThrowOnCall)
                {
                    throw new InvalidOperationException("Synthetic handler failure.");
                }

                return Task.FromResult(new GuardIpcResponse(
                    GuardProtocol.CurrentVersion,
                    request.RequestId,
                    GuardIpcResponseStatus.Success,
                    Array.Empty<byte>()));
            }
        }
    }
}
