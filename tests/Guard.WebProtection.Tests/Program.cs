using System;
using System.Collections.Generic;
using Guard.Windows.WebProtection;

namespace Guard.WebProtection.Tests
{
    internal static class Program
    {
        private static readonly DateTimeOffset NowUtc =
            new DateTimeOffset(2026, 7, 24, 12, 0, 0, TimeSpan.Zero);

        private static int Main()
        {
            var tests = new List<(string Name, Action Run)>
            {
                ("accepts only a complete exact enforcement and website-request snapshot", AcceptsCompleteSnapshot),
                ("requires exclusive IPv4 and IPv6 loopback listeners", RequiresBothExclusiveListeners),
                ("rejects listener restart and rebind races", RejectsListenerRebindRace),
                ("rejects PID reuse between listeners and WFP", RejectsPidReuse),
                ("requires an exact dedicated low-privilege proxy identity", RequiresLowPrivilegeProxyIdentity),
                ("binds proxy evidence to exact update version and digest", BindsProxyUpdateIdentity),
                ("rejects untrusted stale future and mismatched bindings", RejectsInvalidEnvelopes),
                ("rejects browser policy drift missing and duplicate evidence", RejectsBrowserPolicyDrift),
                ("requires every deny-first WFP closure", RequiresAllWfpClosures),
                ("binds WFP to exact policy browser and bypass catalogs", BindsExactWfpState),
                ("binds WFP to the exact canonical child SID", BindsExactChildSid),
                ("requires proxy process confinement controls", RequiresProxyProcessConfinement),
                ("requires signed current catalogs and rollback floors", RequiresTrustedCurrentCatalogs),
                ("caps desired and attestation evidence age at one minute", CapsEvidenceAge),
                ("separates fail-closed enforcement from website-request UX readiness", SeparatesEnforcementFromWebsiteRequestReadiness),
                ("does not let extension evidence enable protection alone", ExtensionCannotEnableProtectionAlone),
                ("rejects duplicate and contradictory evidence", RejectsDuplicateEvidence),
                ("exposes immutable evidence collections", CollectionsAreImmutable),
                ("rejects malformed desired-state identities", RejectsMalformedDesiredState)
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

            Console.WriteLine(
                failures == 0
                    ? "All Guard web-protection readiness checks passed."
                    : failures + " web-protection readiness check(s) failed.");
            return failures == 0 ? 0 : 1;
        }

        private static void AcceptsCompleteSnapshot()
        {
            var fixture = CreateFixture();
            var result = Evaluate(fixture, fixture.CreateSnapshot());
            Assert(result.CanEnableEnforcement, "Complete exact evidence did not enable enforcement.");
            Assert(result.IsWebsiteRequestReady, "Healthy extension UX did not enable website requests.");
            Assert(result.Issues.Count == 0, "Complete exact evidence produced readiness issues.");
            Assert(result.ExtensionUxState == ExtensionUxEvidenceState.Healthy, "Healthy UX evidence was degraded.");
        }

        private static void RequiresBothExclusiveListeners()
        {
            var fixture = CreateFixture();
            var missingIpv6 = Evaluate(
                fixture,
                fixture.CreateSnapshot(listeners: new[] { fixture.IPv4 }));
            AssertIssue(missingIpv6, WebProtectionReadinessIssue.MissingListenerEvidence);

            var nonExclusiveIpv4 = fixture.CreateListener(
                LoopbackAddressFamily.IPv4,
                "127.0.0.1",
                fixture.Proxy,
                usesExclusiveAddress: false);
            var nonExclusive = Evaluate(
                fixture,
                fixture.CreateSnapshot(listeners: new[] { nonExclusiveIpv4, fixture.IPv6 }));
            AssertIssue(nonExclusive, WebProtectionReadinessIssue.ListenerNotExclusive);

            var wrongAddress = fixture.CreateListener(
                LoopbackAddressFamily.IPv6,
                "0:0:0:0:0:0:0:1",
                fixture.Proxy);
            var nonCanonical = Evaluate(
                fixture,
                fixture.CreateSnapshot(listeners: new[] { fixture.IPv4, wrongAddress }));
            AssertIssue(nonCanonical, WebProtectionReadinessIssue.ListenerEndpointMismatch);
        }

        private static void RejectsListenerRebindRace()
        {
            var fixture = CreateFixture();
            var restarted = fixture.CreateProxy(processStartToken: Guid.Parse("99999999-9999-9999-9999-999999999999"));
            var reboundIpv6 = fixture.CreateListener(LoopbackAddressFamily.IPv6, "::1", restarted);
            var result = Evaluate(
                fixture,
                fixture.CreateSnapshot(listeners: new[] { fixture.IPv4, reboundIpv6 }));
            AssertIssue(result, WebProtectionReadinessIssue.ProxyProcessGenerationMismatch);
            AssertIssue(result, WebProtectionReadinessIssue.ContradictoryEvidence);
        }

        private static void RejectsPidReuse()
        {
            var fixture = CreateFixture();
            var wfp = fixture.CreateWfp(
                boundProxyProcessStartToken: Guid.Parse("88888888-8888-8888-8888-888888888888"));
            var result = Evaluate(
                fixture,
                fixture.CreateSnapshot(wfpPolicies: new[] { wfp }));
            AssertIssue(result, WebProtectionReadinessIssue.ProxyProcessGenerationMismatch);
        }

        private static void RequiresLowPrivilegeProxyIdentity()
        {
            var fixture = CreateFixture();
            var privileged = fixture.CreateProxy(
                isDedicatedAccount: false,
                isRestrictedToken: false,
                isElevated: true,
                hasAdministrativeSids: true);
            var result = Evaluate(
                fixture,
                fixture.CreateSnapshot(
                    listeners: new[]
                    {
                        fixture.CreateListener(LoopbackAddressFamily.IPv4, "127.0.0.1", privileged),
                        fixture.CreateListener(LoopbackAddressFamily.IPv6, "::1", privileged)
                    }));
            AssertIssue(result, WebProtectionReadinessIssue.ProxyPrivilegeMismatch);
        }

        private static void BindsProxyUpdateIdentity()
        {
            var fixture = CreateFixture();
            var oldProxy = fixture.CreateProxy(
                executableVersion: "5.0.6",
                executableDigestSha256: Hash('0'));
            var result = Evaluate(
                fixture,
                fixture.CreateSnapshot(
                    listeners: new[]
                    {
                        fixture.CreateListener(LoopbackAddressFamily.IPv4, "127.0.0.1", oldProxy),
                        fixture.CreateListener(LoopbackAddressFamily.IPv6, "::1", oldProxy)
                    }));
            AssertIssue(result, WebProtectionReadinessIssue.ProxyIdentityMismatch);
        }

        private static void RejectsInvalidEnvelopes()
        {
            var fixture = CreateFixture();
            var untrusted = fixture.CreateListener(
                LoopbackAddressFamily.IPv4,
                "127.0.0.1",
                fixture.Proxy,
                envelope: fixture.CreateEnvelope(isServiceAuthenticated: false));
            AssertIssue(
                Evaluate(fixture, fixture.CreateSnapshot(listeners: new[] { untrusted, fixture.IPv6 })),
                WebProtectionReadinessIssue.UntrustedEvidence);

            var stale = fixture.CreateListener(
                LoopbackAddressFamily.IPv4,
                "127.0.0.1",
                fixture.Proxy,
                envelope: fixture.CreateEnvelope(
                    capturedAtUtc: NowUtc.AddSeconds(-40),
                    validUntilUtc: NowUtc.AddSeconds(10)));
            AssertIssue(
                Evaluate(fixture, fixture.CreateSnapshot(listeners: new[] { stale, fixture.IPv6 })),
                WebProtectionReadinessIssue.EvidenceStale);

            var future = fixture.CreateListener(
                LoopbackAddressFamily.IPv4,
                "127.0.0.1",
                fixture.Proxy,
                envelope: fixture.CreateEnvelope(
                    capturedAtUtc: NowUtc.AddSeconds(1),
                    validUntilUtc: NowUtc.AddMinutes(1)));
            AssertIssue(
                Evaluate(fixture, fixture.CreateSnapshot(listeners: new[] { future, fixture.IPv6 })),
                WebProtectionReadinessIssue.EvidenceFromFuture);

            var otherBinding = new WebProtectionEvidenceBinding(
                fixture.Desired.Binding.ServiceBootNonce,
                fixture.Desired.Binding.ProtectionInstanceId,
                fixture.Desired.Binding.ProxyLaunchId,
                fixture.Desired.Binding.ConfigurationVersion + 1,
                Hash('f'));
            var mismatched = fixture.CreateListener(
                LoopbackAddressFamily.IPv4,
                "127.0.0.1",
                fixture.Proxy,
                envelope: fixture.CreateEnvelope(binding: otherBinding));
            AssertIssue(
                Evaluate(fixture, fixture.CreateSnapshot(listeners: new[] { mismatched, fixture.IPv6 })),
                WebProtectionReadinessIssue.EvidenceBindingMismatch);

            var expiredAtBoundary = fixture.CreateListener(
                LoopbackAddressFamily.IPv4,
                "127.0.0.1",
                fixture.Proxy,
                envelope: fixture.CreateEnvelope(validUntilUtc: NowUtc));
            AssertIssue(
                Evaluate(fixture, fixture.CreateSnapshot(listeners: new[] { expiredAtBoundary, fixture.IPv6 })),
                WebProtectionReadinessIssue.EvidenceStale);
        }

        private static void RejectsBrowserPolicyDrift()
        {
            var fixture = CreateFixture();
            var missing = Evaluate(
                fixture,
                fixture.CreateSnapshot(browserPolicies: new[] { fixture.EdgePolicy }));
            AssertIssue(missing, WebProtectionReadinessIssue.MissingBrowserPolicyEvidence);

            var changedEdge = fixture.CreateBrowserPolicy(
                fixture.Edge,
                executableVersion: "145.0.0.0");
            var changed = Evaluate(
                fixture,
                fixture.CreateSnapshot(browserPolicies: new[] { changedEdge, fixture.ChromePolicy }));
            AssertIssue(changed, WebProtectionReadinessIssue.BrowserPolicyMismatch);

            var overrideEdge = fixture.CreateBrowserPolicy(
                fixture.Edge,
                hasNoEffectiveProxyOverrideRules: false);
            var overridden = Evaluate(
                fixture,
                fixture.CreateSnapshot(browserPolicies: new[] { overrideEdge, fixture.ChromePolicy }));
            AssertIssue(overridden, WebProtectionReadinessIssue.BrowserPolicyMismatch);

            var duplicate = Evaluate(
                fixture,
                fixture.CreateSnapshot(
                    browserPolicies: new[] { fixture.EdgePolicy, fixture.EdgePolicy, fixture.ChromePolicy }));
            AssertIssue(duplicate, WebProtectionReadinessIssue.DuplicateEvidence);
        }

        private static void RequiresAllWfpClosures()
        {
            var fixture = CreateFixture();
            var missing = Evaluate(
                fixture,
                fixture.CreateSnapshot(wfpPolicies: Array.Empty<WfpEnforcementEvidence>()));
            AssertIssue(missing, WebProtectionReadinessIssue.MissingWfpEvidence);

            var requiredFlags = new[]
            {
                WfpCoverageFlags.AtomicFilterTransactionCommitted,
                WfpCoverageFlags.BoundToCurrentBoot,
                WfpCoverageFlags.IPv4Covered,
                WfpCoverageFlags.IPv6Covered,
                WfpCoverageFlags.BrowserTcpRestrictedToExactLoopbackProxy,
                WfpCoverageFlags.BrowserDirectTcpBlocked,
                WfpCoverageFlags.BrowserUdpBlocked,
                WfpCoverageFlags.BrowserQuicBlocked,
                WfpCoverageFlags.BrowserDirectDnsBlocked,
                WfpCoverageFlags.BrowserTcpAndWebSocketCovered,
                WfpCoverageFlags.DirectIpLiteralEgressBlocked,
                WfpCoverageFlags.ExternalProxyAndTunnelEgressBlocked,
                WfpCoverageFlags.UnsupportedBrowserEgressBlocked,
                WfpCoverageFlags.BypassToolEgressBlocked,
                WfpCoverageFlags.VpnEgressBlocked,
                WfpCoverageFlags.TorEgressBlocked,
                WfpCoverageFlags.ProxyEgressSeparatelyScoped,
                WfpCoverageFlags.NoBroadChildEgressAllow,
                WfpCoverageFlags.DenyFirstBaselineActive,
                WfpCoverageFlags.NoPolicyDriftDetected,
                WfpCoverageFlags.ProxyHeartbeatCurrent,
                WfpCoverageFlags.TunnelClosureVerified,
                WfpCoverageFlags.PersistentDenyRulesActive,
                WfpCoverageFlags.LoopbackReceiveAcceptBoundToExactProxyOwner,
                WfpCoverageFlags.OtherLoopbackAddressesBlocked,
                WfpCoverageFlags.LanAndLinkLocalEgressBlocked
            };

            for (var index = 0; index < requiredFlags.Length; index++)
            {
                var incomplete = fixture.CreateWfp(
                    coverage: WfpCoverageFlags.AllRequired & ~requiredFlags[index]);
                var result = Evaluate(
                    fixture,
                    fixture.CreateSnapshot(wfpPolicies: new[] { incomplete }));
                AssertIssue(result, WebProtectionReadinessIssue.WfpCoverageIncomplete);
            }
        }

        private static void BindsExactWfpState()
        {
            var fixture = CreateFixture();
            var oldPolicy = fixture.CreateWfp(policyVersion: "11", policyDigestSha256: Hash('0'));
            AssertIssue(
                Evaluate(fixture, fixture.CreateSnapshot(wfpPolicies: new[] { oldPolicy })),
                WebProtectionReadinessIssue.WfpPolicyMismatch);

            var oldBypassCatalog = fixture.CreateWfp(
                bypassIdentityCatalogVersion: "2026.07.23",
                bypassIdentityCatalogDigestSha256: Hash('1'));
            AssertIssue(
                Evaluate(fixture, fixture.CreateSnapshot(wfpPolicies: new[] { oldBypassCatalog })),
                WebProtectionReadinessIssue.WfpPolicyMismatch);

            var oldEdge = new WfpBrowserBindingEvidence(
                ManagedBrowserFamily.MicrosoftEdge,
                fixture.Edge.ExecutablePath,
                "143.0.0.0",
                fixture.Edge.ExecutableDigestSha256);
            var wrongBrowserSet = fixture.CreateWfp(
                browserBindings: new[]
                {
                    oldEdge,
                    fixture.CreateWfpBrowserBinding(fixture.Chrome)
                });
            AssertIssue(
                Evaluate(fixture, fixture.CreateSnapshot(wfpPolicies: new[] { wrongBrowserSet })),
                WebProtectionReadinessIssue.WfpBrowserBindingMismatch);
        }

        private static void BindsExactChildSid()
        {
            var fixture = CreateFixture();
            var wrongChild = fixture.CreateWfp(
                boundChildAccountSid: "S-1-5-21-1000-1001-1002-1300");
            var result = Evaluate(
                fixture,
                fixture.CreateSnapshot(wfpPolicies: new[] { wrongChild }));
            AssertIssue(result, WebProtectionReadinessIssue.ChildAccountMismatch);
        }

        private static void RequiresProxyProcessConfinement()
        {
            var fixture = CreateFixture();
            var weakened = new[]
            {
                fixture.CreateProxy(isInKillOnCloseJob: false),
                fixture.CreateProxy(isChildProcessCreationBlocked: false),
                fixture.CreateProxy(hasRestrictiveProcessDacl: false),
                fixture.CreateProxy(hasNoNetworkCredentials: false)
            };

            for (var index = 0; index < weakened.Length; index++)
            {
                var result = Evaluate(
                    fixture,
                    fixture.CreateSnapshot(
                        listeners: new[]
                        {
                            fixture.CreateListener(LoopbackAddressFamily.IPv4, "127.0.0.1", weakened[index]),
                            fixture.CreateListener(LoopbackAddressFamily.IPv6, "::1", weakened[index])
                        }));
                AssertIssue(result, WebProtectionReadinessIssue.ProxyProcessHardeningMismatch);
            }
        }

        private static void RequiresTrustedCurrentCatalogs()
        {
            var fixture = CreateFixture();
            var missing = Evaluate(
                fixture,
                fixture.CreateSnapshot(trustedCatalogs: new[] { fixture.PslCatalog }));
            AssertIssue(missing, WebProtectionReadinessIssue.MissingCatalogEvidence);

            var unsignedPsl = fixture.CreateCatalog(
                fixture.Psl,
                isSignatureVerified: false);
            AssertIssue(
                Evaluate(
                    fixture,
                    fixture.CreateSnapshot(trustedCatalogs: new[] { unsignedPsl, fixture.ServiceCatalog })),
                WebProtectionReadinessIssue.CatalogUntrusted);

            var rolledBackPsl = fixture.CreateCatalog(
                fixture.Psl,
                revision: fixture.Psl.CurrentRevision - 1,
                rollbackFloorRevision: fixture.Psl.RollbackFloorRevision - 1);
            AssertIssue(
                Evaluate(
                    fixture,
                    fixture.CreateSnapshot(trustedCatalogs: new[] { rolledBackPsl, fixture.ServiceCatalog })),
                WebProtectionReadinessIssue.CatalogMismatch);

            var inactiveRollbackFloor = fixture.CreateCatalog(
                fixture.Psl,
                isRollbackProtectionActive: false);
            AssertIssue(
                Evaluate(
                    fixture,
                    fixture.CreateSnapshot(trustedCatalogs: new[] { inactiveRollbackFloor, fixture.ServiceCatalog })),
                WebProtectionReadinessIssue.CatalogUntrusted);
        }

        private static void CapsEvidenceAge()
        {
            var fixture = CreateFixture();
            Throws<ArgumentException>(
                () => new ServiceAttestationEnvelope(
                    fixture.Desired.Binding,
                    NowUtc.AddSeconds(-31),
                    NowUtc.AddSeconds(30),
                    true),
                "An attestation lifetime over one minute was accepted.");
            Throws<ArgumentOutOfRangeException>(
                () => new WebProtectionDesiredState(
                    fixture.Desired.Binding,
                    fixture.Desired.ChildAccountSid,
                    fixture.Desired.ProxyPort,
                    TimeSpan.FromSeconds(61),
                    fixture.Desired.ProxyProcess,
                    fixture.Desired.Browsers,
                    fixture.Desired.WfpPolicy,
                    fixture.Desired.TrustedCatalogs),
                "A desired evidence age over one minute was accepted.");
        }

        private static void SeparatesEnforcementFromWebsiteRequestReadiness()
        {
            var fixture = CreateFixture();
            var missing = Evaluate(
                fixture,
                fixture.CreateSnapshot(extensionUx: Array.Empty<ExtensionUxEvidence>()));
            Assert(missing.CanEnableEnforcement, "Missing UX extension disabled otherwise complete fail-closed enforcement.");
            Assert(!missing.IsWebsiteRequestReady, "Missing UX extension enabled website requests.");
            Assert(missing.ExtensionUxState == ExtensionUxEvidenceState.Missing, "Missing UX extension was not reported.");

            var unhealthyEdge = fixture.CreateExtension(fixture.Edge, isConnected: false);
            var unhealthy = Evaluate(
                fixture,
                fixture.CreateSnapshot(extensionUx: new[] { unhealthyEdge, fixture.ChromeExtension }));
            Assert(unhealthy.CanEnableEnforcement, "Unhealthy UX extension disabled otherwise complete fail-closed enforcement.");
            Assert(!unhealthy.IsWebsiteRequestReady, "Unhealthy UX extension enabled website requests.");
            Assert(unhealthy.ExtensionUxState == ExtensionUxEvidenceState.Unhealthy, "Unhealthy UX state was not reported.");

            var otherSessionEdge = fixture.CreateExtension(
                fixture.Edge,
                boundChildAccountSid:
                    "S-1-5-21-1000-1001-1002-1300");
            var otherSession = Evaluate(
                fixture,
                fixture.CreateSnapshot(
                    extensionUx: new[]
                    {
                        otherSessionEdge,
                        fixture.ChromeExtension
                    }));
            Assert(
                otherSession.CanEnableEnforcement,
                "Wrong-session UX evidence disabled otherwise complete fail-closed enforcement.");
            Assert(
                !otherSession.IsWebsiteRequestReady &&
                otherSession.ExtensionUxState ==
                    ExtensionUxEvidenceState.BindingMismatch,
                "An extension from another Windows session enabled child website requests.");

            var futureEdge = fixture.CreateExtension(
                fixture.Edge,
                envelope: fixture.CreateEnvelope(
                    capturedAtUtc: NowUtc.AddSeconds(1),
                    validUntilUtc: NowUtc.AddSeconds(30)));
            var future = Evaluate(
                fixture,
                fixture.CreateSnapshot(
                    extensionUx: new[]
                    {
                        futureEdge,
                        fixture.ChromeExtension
                    }));
            Assert(
                future.CanEnableEnforcement &&
                !future.IsWebsiteRequestReady &&
                future.ExtensionUxState ==
                    ExtensionUxEvidenceState.Future,
                "Future-dated extension evidence enabled child website requests.");
        }

        private static void ExtensionCannotEnableProtectionAlone()
        {
            var fixture = CreateFixture();
            var extensionOnly = new WebProtectionEvidenceSnapshot(
                null,
                null,
                null,
                null,
                new[] { fixture.EdgeExtension, fixture.ChromeExtension });
            var result = Evaluate(fixture, extensionOnly);
            Assert(!result.CanEnableEnforcement, "UX-only extension evidence enabled enforcement.");
            Assert(!result.IsWebsiteRequestReady, "UX-only extension evidence enabled website requests.");
            AssertIssue(result, WebProtectionReadinessIssue.MissingListenerEvidence);
            AssertIssue(result, WebProtectionReadinessIssue.MissingBrowserPolicyEvidence);
            AssertIssue(result, WebProtectionReadinessIssue.MissingWfpEvidence);
            AssertIssue(result, WebProtectionReadinessIssue.MissingCatalogEvidence);
        }

        private static void RejectsDuplicateEvidence()
        {
            var fixture = CreateFixture();
            var duplicateListener = Evaluate(
                fixture,
                fixture.CreateSnapshot(
                    listeners: new[] { fixture.IPv4, fixture.IPv4, fixture.IPv6 }));
            AssertIssue(duplicateListener, WebProtectionReadinessIssue.DuplicateEvidence);

            var duplicateWfp = Evaluate(
                fixture,
                fixture.CreateSnapshot(wfpPolicies: new[] { fixture.Wfp, fixture.Wfp }));
            AssertIssue(duplicateWfp, WebProtectionReadinessIssue.DuplicateEvidence);

            var duplicateCatalog = Evaluate(
                fixture,
                fixture.CreateSnapshot(
                    trustedCatalogs: new[]
                    {
                        fixture.PslCatalog,
                        fixture.PslCatalog,
                        fixture.ServiceCatalog
                    }));
            AssertIssue(duplicateCatalog, WebProtectionReadinessIssue.DuplicateEvidence);
        }

        private static void CollectionsAreImmutable()
        {
            var fixture = CreateFixture();
            var browserList = fixture.Desired.Browsers as IList<BrowserEnforcementExpectation>;
            Assert(browserList != null, "Browser collection did not expose a read-only list contract.");
            Throws<NotSupportedException>(
                () => browserList!.Add(fixture.Edge),
                "Desired browser collection was mutable.");

            var snapshot = fixture.CreateSnapshot();
            var listenerList = snapshot.Listeners as IList<ProxyListenerEvidence>;
            Assert(listenerList != null, "Listener collection did not expose a read-only list contract.");
            Throws<NotSupportedException>(
                () => listenerList!.Clear(),
                "Listener evidence collection was mutable.");
        }

        private static void RejectsMalformedDesiredState()
        {
            Throws<ArgumentException>(
                () => new ProxyProcessExpectation(
                    "S-1-5-18",
                    @"C:\Guard\Guard.Proxy.exe",
                    "1",
                    Hash('a'),
                    Hash('b')),
                "LocalSystem was accepted as the proxy identity.");
            Throws<ArgumentException>(
                () => new WebProtectionEvidenceBinding(
                    Guid.NewGuid(),
                    Guid.NewGuid(),
                    Guid.NewGuid(),
                    1,
                    new string('A', 64)),
                "Uppercase digest was accepted.");

            var fixture = CreateFixture();
            Throws<ArgumentException>(
                () => new WebProtectionDesiredState(
                    fixture.Desired.Binding,
                    fixture.Desired.ChildAccountSid,
                    fixture.Desired.ProxyPort,
                    fixture.Desired.MaximumEvidenceAge,
                    fixture.Desired.ProxyProcess,
                    new[] { fixture.Edge, fixture.Edge },
                    fixture.Desired.WfpPolicy,
                    fixture.Desired.TrustedCatalogs),
                "Duplicate browser expectations were accepted.");
            Throws<ArgumentException>(
                () => new WebProtectionDesiredState(
                    fixture.Desired.Binding,
                    fixture.Desired.ProxyProcess.DedicatedAccountSid,
                    fixture.Desired.ProxyPort,
                    fixture.Desired.MaximumEvidenceAge,
                    fixture.Desired.ProxyProcess,
                    fixture.Desired.Browsers,
                    fixture.Desired.WfpPolicy,
                    fixture.Desired.TrustedCatalogs),
                "The dedicated proxy account was allowed to match the child account.");
        }

        private static WebProtectionReadinessResult Evaluate(Fixture fixture, WebProtectionEvidenceSnapshot snapshot)
        {
            return WebProtectionReadinessEvaluator.Evaluate(fixture.Desired, snapshot, NowUtc);
        }

        private static Fixture CreateFixture()
        {
            return new Fixture();
        }

        private static string Hash(char character)
        {
            return new string(character, 64);
        }

        private static void AssertIssue(
            WebProtectionReadinessResult result,
            WebProtectionReadinessIssue expected)
        {
            for (var index = 0; index < result.Issues.Count; index++)
            {
                if (result.Issues[index] == expected)
                {
                    Assert(!result.CanEnableEnforcement, "A failed readiness result was marked enforcement-ready.");
                    Assert(!result.IsWebsiteRequestReady, "A failed readiness result was marked website-request ready.");
                    return;
                }
            }

            throw new InvalidOperationException("Expected readiness issue was absent: " + expected);
        }

        private static void Throws<T>(Action action, string message)
            where T : Exception
        {
            try
            {
                action();
            }
            catch (T)
            {
                return;
            }

            throw new InvalidOperationException(message);
        }

        private static void Assert(bool condition, string message)
        {
            if (!condition)
            {
                throw new InvalidOperationException(message);
            }
        }

        private sealed class Fixture
        {
            public Fixture()
            {
                var binding = new WebProtectionEvidenceBinding(
                    Guid.Parse("11111111-1111-1111-1111-111111111111"),
                    Guid.Parse("22222222-2222-2222-2222-222222222222"),
                    Guid.Parse("33333333-3333-3333-3333-333333333333"),
                    7,
                    Hash('a'));
                var proxyExpectation = new ProxyProcessExpectation(
                    "S-1-5-21-1000-1001-1002-1201",
                    @"C:\Program Files\Guard\Guard.Proxy.exe",
                    "5.0.7",
                    Hash('b'),
                    Hash('c'));
                Edge = new BrowserEnforcementExpectation(
                    ManagedBrowserFamily.MicrosoftEdge,
                    @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                    "144.0.0.0",
                    Hash('d'),
                    Hash('e'),
                    "5.0.7",
                    Hash('f'));
                Chrome = new BrowserEnforcementExpectation(
                    ManagedBrowserFamily.GoogleChrome,
                    @"C:\Program Files\Google\Chrome\Application\chrome.exe",
                    "144.0.1.0",
                    Hash('1'),
                    Hash('2'),
                    "5.0.7",
                    Hash('3'));
                var wfpExpectation = new WfpPolicyExpectation(
                    "12",
                    Hash('4'),
                    "2026.07.24",
                    Hash('5'));
                Psl = new TrustedWebCatalogExpectation(
                    TrustedWebCatalogKind.PublicSuffixList,
                    2026072401,
                    2026072301,
                    "2026-07-24",
                    Hash('6'));
                SiteCatalog = new TrustedWebCatalogExpectation(
                    TrustedWebCatalogKind.SiteServiceCatalog,
                    44,
                    40,
                    "44",
                    Hash('7'));
                Desired = new WebProtectionDesiredState(
                    binding,
                    "S-1-5-21-1000-1001-1002-1100",
                    48123,
                    TimeSpan.FromSeconds(30),
                    proxyExpectation,
                    new[] { Edge, Chrome },
                    wfpExpectation,
                    new[] { Psl, SiteCatalog });

                Proxy = CreateProxy();
                IPv4 = CreateListener(LoopbackAddressFamily.IPv4, "127.0.0.1", Proxy);
                IPv6 = CreateListener(LoopbackAddressFamily.IPv6, "::1", Proxy);
                EdgePolicy = CreateBrowserPolicy(Edge);
                ChromePolicy = CreateBrowserPolicy(Chrome);
                Wfp = CreateWfp();
                PslCatalog = CreateCatalog(Psl);
                ServiceCatalog = CreateCatalog(SiteCatalog);
                EdgeExtension = CreateExtension(Edge);
                ChromeExtension = CreateExtension(Chrome);
            }

            public WebProtectionDesiredState Desired { get; }

            public BrowserEnforcementExpectation Edge { get; }

            public BrowserEnforcementExpectation Chrome { get; }

            public TrustedWebCatalogExpectation Psl { get; }

            public TrustedWebCatalogExpectation SiteCatalog { get; }

            public ProxyProcessObservation Proxy { get; }

            public ProxyListenerEvidence IPv4 { get; }

            public ProxyListenerEvidence IPv6 { get; }

            public BrowserPolicyEvidence EdgePolicy { get; }

            public BrowserPolicyEvidence ChromePolicy { get; }

            public WfpEnforcementEvidence Wfp { get; }

            public TrustedWebCatalogEvidence PslCatalog { get; }

            public TrustedWebCatalogEvidence ServiceCatalog { get; }

            public ExtensionUxEvidence EdgeExtension { get; }

            public ExtensionUxEvidence ChromeExtension { get; }

            public ServiceAttestationEnvelope CreateEnvelope(
                WebProtectionEvidenceBinding? binding = null,
                DateTimeOffset? capturedAtUtc = null,
                DateTimeOffset? validUntilUtc = null,
                bool isServiceAuthenticated = true)
            {
                return new ServiceAttestationEnvelope(
                    binding ?? Desired.Binding,
                    capturedAtUtc ?? NowUtc.AddSeconds(-10),
                    validUntilUtc ?? NowUtc.AddSeconds(20),
                    isServiceAuthenticated);
            }

            public ProxyProcessObservation CreateProxy(
                int processId = 4242,
                Guid? processStartToken = null,
                string? executableVersion = null,
                string? executableDigestSha256 = null,
                bool isDedicatedAccount = true,
                bool isRestrictedToken = true,
                bool isElevated = false,
                bool hasAdministrativeSids = false,
                bool isInKillOnCloseJob = true,
                bool isChildProcessCreationBlocked = true,
                bool hasRestrictiveProcessDacl = true,
                bool hasNoNetworkCredentials = true)
            {
                return new ProxyProcessObservation(
                    processId,
                    processStartToken ?? Guid.Parse("44444444-4444-4444-4444-444444444444"),
                    Desired.ProxyProcess.DedicatedAccountSid,
                    Desired.ProxyProcess.ExecutablePath,
                    executableVersion ?? Desired.ProxyProcess.ExecutableVersion,
                    executableDigestSha256 ?? Desired.ProxyProcess.ExecutableDigestSha256,
                    Desired.ProxyProcess.RestrictedTokenProfileDigestSha256,
                    isDedicatedAccount,
                    isRestrictedToken,
                    isElevated,
                    false,
                    hasAdministrativeSids,
                    false,
                    isInKillOnCloseJob,
                    isChildProcessCreationBlocked,
                    hasRestrictiveProcessDacl,
                    hasNoNetworkCredentials);
            }

            public ProxyListenerEvidence CreateListener(
                LoopbackAddressFamily family,
                string address,
                ProxyProcessObservation owner,
                bool usesExclusiveAddress = true,
                ServiceAttestationEnvelope? envelope = null)
            {
                return new ProxyListenerEvidence(
                    envelope ?? CreateEnvelope(),
                    family,
                    address,
                    Desired.ProxyPort,
                    usesExclusiveAddress,
                    true,
                    true,
                    owner);
            }

            public BrowserPolicyEvidence CreateBrowserPolicy(
                BrowserEnforcementExpectation expected,
                string? executableVersion = null,
                bool hasNoEffectiveProxyOverrideRules = true)
            {
                return new BrowserPolicyEvidence(
                    CreateEnvelope(),
                    expected.Browser,
                    expected.ExecutablePath,
                    executableVersion ?? expected.ExecutableVersion,
                    expected.ExecutableDigestSha256,
                    expected.PolicyDigestSha256,
                    true,
                    true,
                    false,
                    true,
                    hasNoEffectiveProxyOverrideRules);
            }

            public WfpBrowserBindingEvidence CreateWfpBrowserBinding(
                BrowserEnforcementExpectation expected)
            {
                return new WfpBrowserBindingEvidence(
                    expected.Browser,
                    expected.ExecutablePath,
                    expected.ExecutableVersion,
                    expected.ExecutableDigestSha256);
            }

            public WfpEnforcementEvidence CreateWfp(
                string? policyVersion = null,
                string? policyDigestSha256 = null,
                string? bypassIdentityCatalogVersion = null,
                string? bypassIdentityCatalogDigestSha256 = null,
                Guid? boundProxyProcessStartToken = null,
                string? boundChildAccountSid = null,
                WfpCoverageFlags coverage = WfpCoverageFlags.AllRequired,
                IEnumerable<WfpBrowserBindingEvidence>? browserBindings = null)
            {
                return new WfpEnforcementEvidence(
                    CreateEnvelope(),
                    policyVersion ?? Desired.WfpPolicy.PolicyVersion,
                    policyDigestSha256 ?? Desired.WfpPolicy.PolicyDigestSha256,
                    bypassIdentityCatalogVersion ?? Desired.WfpPolicy.BypassIdentityCatalogVersion,
                    bypassIdentityCatalogDigestSha256 ?? Desired.WfpPolicy.BypassIdentityCatalogDigestSha256,
                    Desired.ProxyPort,
                    Proxy.ProcessId,
                    boundProxyProcessStartToken ?? Proxy.ProcessStartToken,
                    boundChildAccountSid ?? Desired.ChildAccountSid,
                    Desired.ProxyProcess.DedicatedAccountSid,
                    Desired.ProxyProcess.ExecutableDigestSha256,
                    coverage,
                    browserBindings ??
                    new[]
                    {
                        CreateWfpBrowserBinding(Edge),
                        CreateWfpBrowserBinding(Chrome)
                    });
            }

            public TrustedWebCatalogEvidence CreateCatalog(
                TrustedWebCatalogExpectation expected,
                long? revision = null,
                long? rollbackFloorRevision = null,
                bool isSignatureVerified = true,
                bool isRollbackProtectionActive = true)
            {
                return new TrustedWebCatalogEvidence(
                    CreateEnvelope(),
                    expected.Kind,
                    revision ?? expected.CurrentRevision,
                    rollbackFloorRevision ?? expected.RollbackFloorRevision,
                    expected.Version,
                    expected.DigestSha256,
                    isSignatureVerified,
                    true,
                    true,
                    true,
                    isRollbackProtectionActive);
            }

            public ExtensionUxEvidence CreateExtension(
                BrowserEnforcementExpectation expected,
                bool isConnected = true,
                string? boundChildAccountSid = null,
                bool isAuthenticatedChildSession = true,
                ServiceAttestationEnvelope? envelope = null)
            {
                return new ExtensionUxEvidence(
                    envelope ?? CreateEnvelope(),
                    expected.Browser,
                    boundChildAccountSid ?? Desired.ChildAccountSid,
                    expected.ExecutableDigestSha256,
                    expected.ExtensionVersion,
                    expected.ExtensionDigestSha256,
                    isAuthenticatedChildSession,
                    isConnected,
                    true);
            }

            public WebProtectionEvidenceSnapshot CreateSnapshot(
                IEnumerable<ProxyListenerEvidence>? listeners = null,
                IEnumerable<BrowserPolicyEvidence>? browserPolicies = null,
                IEnumerable<WfpEnforcementEvidence>? wfpPolicies = null,
                IEnumerable<TrustedWebCatalogEvidence>? trustedCatalogs = null,
                IEnumerable<ExtensionUxEvidence>? extensionUx = null)
            {
                return new WebProtectionEvidenceSnapshot(
                    listeners ?? new[] { IPv4, IPv6 },
                    browserPolicies ?? new[] { EdgePolicy, ChromePolicy },
                    wfpPolicies ?? new[] { Wfp },
                    trustedCatalogs ?? new[] { PslCatalog, ServiceCatalog },
                    extensionUx ?? new[] { EdgeExtension, ChromeExtension });
            }
        }
    }
}
