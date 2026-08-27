using System;
using System.Collections.Generic;

namespace Guard.Windows.WebProtection
{
    public static class WebProtectionReadinessEvaluator
    {
        public static WebProtectionReadinessResult Evaluate(
            WebProtectionDesiredState desired,
            WebProtectionEvidenceSnapshot snapshot,
            DateTimeOffset nowUtc)
        {
            if (desired == null)
            {
                throw new ArgumentNullException(nameof(desired));
            }

            if (snapshot == null)
            {
                throw new ArgumentNullException(nameof(snapshot));
            }

            WebProtectionValueValidator.RequireUtc(nowUtc, nameof(nowUtc));
            var issues = new IssueAccumulator();
            var selectedListeners = EvaluateListeners(desired, snapshot.Listeners, nowUtc, issues);
            EvaluateBrowserPolicies(desired, snapshot.BrowserPolicies, nowUtc, issues);
            EvaluateWfp(desired, snapshot.WfpPolicies, selectedListeners, nowUtc, issues);
            EvaluateCatalogs(desired, snapshot.TrustedCatalogs, nowUtc, issues);
            var extensionState = EvaluateExtensionUx(desired, snapshot.ExtensionUx, nowUtc);
            return new WebProtectionReadinessResult(issues.ToSortedList(), extensionState);
        }

        private static ListenerSelection EvaluateListeners(
            WebProtectionDesiredState desired,
            IReadOnlyList<ProxyListenerEvidence> listeners,
            DateTimeOffset nowUtc,
            IssueAccumulator issues)
        {
            ProxyListenerEvidence? ipv4 = null;
            ProxyListenerEvidence? ipv6 = null;
            var ipv4Count = 0;
            var ipv6Count = 0;
            for (var index = 0; index < listeners.Count; index++)
            {
                var listener = listeners[index];
                EvaluateEnvelope(desired, listener.Envelope, nowUtc, issues);
                if (listener.AddressFamily == LoopbackAddressFamily.IPv4)
                {
                    ipv4Count++;
                    ipv4 = listener;
                }
                else
                {
                    ipv6Count++;
                    ipv6 = listener;
                }
            }

            if (ipv4Count == 0 || ipv6Count == 0)
            {
                issues.Add(WebProtectionReadinessIssue.MissingListenerEvidence);
            }

            if (ipv4Count > 1 || ipv6Count > 1)
            {
                issues.Add(WebProtectionReadinessIssue.DuplicateEvidence);
            }

            if (ipv4Count != 1 || ipv6Count != 1 || ipv4 == null || ipv6 == null)
            {
                return new ListenerSelection(null, null);
            }

            EvaluateListener(desired, ipv4, "127.0.0.1", issues);
            EvaluateListener(desired, ipv6, "::1", issues);
            if (ipv4.Owner.ProcessId != ipv6.Owner.ProcessId ||
                ipv4.Owner.ProcessStartToken != ipv6.Owner.ProcessStartToken)
            {
                issues.Add(WebProtectionReadinessIssue.ProxyProcessGenerationMismatch);
                issues.Add(WebProtectionReadinessIssue.ContradictoryEvidence);
            }

            return new ListenerSelection(ipv4, ipv6);
        }

        private static void EvaluateListener(
            WebProtectionDesiredState desired,
            ProxyListenerEvidence listener,
            string requiredAddress,
            IssueAccumulator issues)
        {
            if (!string.Equals(listener.LocalAddress, requiredAddress, StringComparison.Ordinal) ||
                listener.Port != desired.ProxyPort)
            {
                issues.Add(WebProtectionReadinessIssue.ListenerEndpointMismatch);
            }

            if (!listener.UsesExclusiveAddress ||
                !listener.OwnsExactEndpoint ||
                !listener.NoCompetingListenerDetected)
            {
                issues.Add(WebProtectionReadinessIssue.ListenerNotExclusive);
            }

            EvaluateProxyIdentity(desired.ProxyProcess, listener.Owner, issues);
        }

        private static void EvaluateProxyIdentity(
            ProxyProcessExpectation expected,
            ProxyProcessObservation observed,
            IssueAccumulator issues)
        {
            if (!string.Equals(expected.DedicatedAccountSid, observed.AccountSid, StringComparison.Ordinal) ||
                !string.Equals(expected.ExecutablePath, observed.ExecutablePath, StringComparison.Ordinal) ||
                !string.Equals(expected.ExecutableVersion, observed.ExecutableVersion, StringComparison.Ordinal) ||
                !string.Equals(expected.ExecutableDigestSha256, observed.ExecutableDigestSha256, StringComparison.Ordinal) ||
                !string.Equals(
                    expected.RestrictedTokenProfileDigestSha256,
                    observed.TokenProfileDigestSha256,
                    StringComparison.Ordinal))
            {
                issues.Add(WebProtectionReadinessIssue.ProxyIdentityMismatch);
            }

            if (!observed.IsDedicatedAccount ||
                !observed.IsRestrictedToken ||
                observed.IsElevated ||
                observed.IsLocalSystem ||
                observed.HasAdministrativeSids ||
                observed.IsInteractiveLogonToken ||
                WebProtectionValueValidator.IsPrivilegedServiceSid(observed.AccountSid))
            {
                issues.Add(WebProtectionReadinessIssue.ProxyPrivilegeMismatch);
            }

            if (!observed.IsInKillOnCloseJob ||
                !observed.IsChildProcessCreationBlocked ||
                !observed.HasRestrictiveProcessDacl ||
                !observed.HasNoNetworkCredentials)
            {
                issues.Add(WebProtectionReadinessIssue.ProxyProcessHardeningMismatch);
            }
        }

        private static void EvaluateBrowserPolicies(
            WebProtectionDesiredState desired,
            IReadOnlyList<BrowserPolicyEvidence> policies,
            DateTimeOffset nowUtc,
            IssueAccumulator issues)
        {
            for (var index = 0; index < policies.Count; index++)
            {
                EvaluateEnvelope(desired, policies[index].Envelope, nowUtc, issues);
                if (FindBrowser(desired.Browsers, policies[index].Browser) == null)
                {
                    issues.Add(WebProtectionReadinessIssue.UnexpectedEvidence);
                }
            }

            for (var expectedIndex = 0; expectedIndex < desired.Browsers.Count; expectedIndex++)
            {
                var expected = desired.Browsers[expectedIndex];
                BrowserPolicyEvidence? selected = null;
                var count = 0;
                for (var evidenceIndex = 0; evidenceIndex < policies.Count; evidenceIndex++)
                {
                    if (policies[evidenceIndex].Browser == expected.Browser)
                    {
                        count++;
                        selected = policies[evidenceIndex];
                    }
                }

                if (count == 0)
                {
                    issues.Add(WebProtectionReadinessIssue.MissingBrowserPolicyEvidence);
                    continue;
                }

                if (count > 1)
                {
                    issues.Add(WebProtectionReadinessIssue.DuplicateEvidence);
                    continue;
                }

                if (selected == null ||
                    !string.Equals(expected.ExecutablePath, selected.ExecutablePath, StringComparison.Ordinal) ||
                    !string.Equals(expected.ExecutableVersion, selected.ExecutableVersion, StringComparison.Ordinal) ||
                    !string.Equals(expected.ExecutableDigestSha256, selected.ExecutableDigestSha256, StringComparison.Ordinal) ||
                    !string.Equals(expected.PolicyDigestSha256, selected.PolicyDigestSha256, StringComparison.Ordinal) ||
                    !selected.IsMachinePolicy ||
                    !selected.IsEffective ||
                    selected.UserCanChangeProxy ||
                    !selected.WasLoadedWithoutFallback ||
                    !selected.HasNoEffectiveProxyOverrideRules)
                {
                    issues.Add(WebProtectionReadinessIssue.BrowserPolicyMismatch);
                }
            }
        }

        private static void EvaluateWfp(
            WebProtectionDesiredState desired,
            IReadOnlyList<WfpEnforcementEvidence> policies,
            ListenerSelection listeners,
            DateTimeOffset nowUtc,
            IssueAccumulator issues)
        {
            if (policies.Count == 0)
            {
                issues.Add(WebProtectionReadinessIssue.MissingWfpEvidence);
                return;
            }

            if (policies.Count > 1)
            {
                issues.Add(WebProtectionReadinessIssue.DuplicateEvidence);
                for (var index = 0; index < policies.Count; index++)
                {
                    EvaluateEnvelope(desired, policies[index].Envelope, nowUtc, issues);
                }

                return;
            }

            var evidence = policies[0];
            EvaluateEnvelope(desired, evidence.Envelope, nowUtc, issues);
            if (!string.Equals(desired.WfpPolicy.PolicyVersion, evidence.PolicyVersion, StringComparison.Ordinal) ||
                !string.Equals(desired.WfpPolicy.PolicyDigestSha256, evidence.PolicyDigestSha256, StringComparison.Ordinal) ||
                !string.Equals(
                    desired.WfpPolicy.BypassIdentityCatalogVersion,
                    evidence.BypassIdentityCatalogVersion,
                    StringComparison.Ordinal) ||
                !string.Equals(
                    desired.WfpPolicy.BypassIdentityCatalogDigestSha256,
                    evidence.BypassIdentityCatalogDigestSha256,
                    StringComparison.Ordinal) ||
                evidence.AllowedProxyPort != desired.ProxyPort)
            {
                issues.Add(WebProtectionReadinessIssue.WfpPolicyMismatch);
            }

            var unknownCoverage = evidence.Coverage & ~WfpCoverageFlags.AllRequired;
            if ((evidence.Coverage & WfpCoverageFlags.AllRequired) != WfpCoverageFlags.AllRequired ||
                unknownCoverage != WfpCoverageFlags.None)
            {
                issues.Add(WebProtectionReadinessIssue.WfpCoverageIncomplete);
            }

            if (listeners.IPv4 == null ||
                listeners.IPv6 == null ||
                evidence.BoundProxyProcessId != listeners.IPv4.Owner.ProcessId ||
                evidence.BoundProxyProcessStartToken != listeners.IPv4.Owner.ProcessStartToken ||
                evidence.BoundProxyProcessId != listeners.IPv6.Owner.ProcessId ||
                evidence.BoundProxyProcessStartToken != listeners.IPv6.Owner.ProcessStartToken)
            {
                issues.Add(WebProtectionReadinessIssue.ProxyProcessGenerationMismatch);
            }

            if (!string.Equals(
                    desired.ProxyProcess.DedicatedAccountSid,
                    evidence.BoundProxyAccountSid,
                    StringComparison.Ordinal) ||
                !string.Equals(
                    desired.ProxyProcess.ExecutableDigestSha256,
                    evidence.BoundProxyExecutableDigestSha256,
                    StringComparison.Ordinal))
            {
                issues.Add(WebProtectionReadinessIssue.ProxyIdentityMismatch);
            }

            if (!string.Equals(
                    desired.ChildAccountSid,
                    evidence.BoundChildAccountSid,
                    StringComparison.Ordinal))
            {
                issues.Add(WebProtectionReadinessIssue.ChildAccountMismatch);
            }

            EvaluateWfpBrowserBindings(desired.Browsers, evidence.BrowserBindings, issues);
        }

        private static void EvaluateWfpBrowserBindings(
            IReadOnlyList<BrowserEnforcementExpectation> expectedBrowsers,
            IReadOnlyList<WfpBrowserBindingEvidence> observedBrowsers,
            IssueAccumulator issues)
        {
            var seen = new HashSet<ManagedBrowserFamily>();
            for (var index = 0; index < observedBrowsers.Count; index++)
            {
                var observed = observedBrowsers[index];
                if (!seen.Add(observed.Browser))
                {
                    issues.Add(WebProtectionReadinessIssue.DuplicateEvidence);
                    continue;
                }

                var expected = FindBrowser(expectedBrowsers, observed.Browser);
                if (expected == null)
                {
                    issues.Add(WebProtectionReadinessIssue.UnexpectedEvidence);
                    continue;
                }

                if (!string.Equals(expected.ExecutablePath, observed.ExecutablePath, StringComparison.Ordinal) ||
                    !string.Equals(expected.ExecutableVersion, observed.ExecutableVersion, StringComparison.Ordinal) ||
                    !string.Equals(expected.ExecutableDigestSha256, observed.ExecutableDigestSha256, StringComparison.Ordinal))
                {
                    issues.Add(WebProtectionReadinessIssue.WfpBrowserBindingMismatch);
                }
            }

            if (seen.Count != expectedBrowsers.Count)
            {
                issues.Add(WebProtectionReadinessIssue.WfpBrowserBindingMismatch);
            }

            for (var index = 0; index < expectedBrowsers.Count; index++)
            {
                if (!seen.Contains(expectedBrowsers[index].Browser))
                {
                    issues.Add(WebProtectionReadinessIssue.WfpBrowserBindingMismatch);
                }
            }
        }

        private static void EvaluateCatalogs(
            WebProtectionDesiredState desired,
            IReadOnlyList<TrustedWebCatalogEvidence> catalogs,
            DateTimeOffset nowUtc,
            IssueAccumulator issues)
        {
            for (var index = 0; index < catalogs.Count; index++)
            {
                EvaluateEnvelope(desired, catalogs[index].Envelope, nowUtc, issues);
                if (FindCatalog(desired.TrustedCatalogs, catalogs[index].Kind) == null)
                {
                    issues.Add(WebProtectionReadinessIssue.UnexpectedEvidence);
                }
            }

            for (var expectedIndex = 0; expectedIndex < desired.TrustedCatalogs.Count; expectedIndex++)
            {
                var expected = desired.TrustedCatalogs[expectedIndex];
                TrustedWebCatalogEvidence? selected = null;
                var count = 0;
                for (var evidenceIndex = 0; evidenceIndex < catalogs.Count; evidenceIndex++)
                {
                    if (catalogs[evidenceIndex].Kind == expected.Kind)
                    {
                        count++;
                        selected = catalogs[evidenceIndex];
                    }
                }

                if (count == 0)
                {
                    issues.Add(WebProtectionReadinessIssue.MissingCatalogEvidence);
                    continue;
                }

                if (count > 1)
                {
                    issues.Add(WebProtectionReadinessIssue.DuplicateEvidence);
                    continue;
                }

                if (selected == null ||
                    expected.CurrentRevision != selected.Revision ||
                    expected.RollbackFloorRevision != selected.RollbackFloorRevision ||
                    !string.Equals(expected.Version, selected.Version, StringComparison.Ordinal) ||
                    !string.Equals(expected.DigestSha256, selected.DigestSha256, StringComparison.Ordinal))
                {
                    issues.Add(WebProtectionReadinessIssue.CatalogMismatch);
                    continue;
                }

                if (!selected.IsSignatureVerified ||
                    !selected.IsTrustedSource ||
                    !selected.IsComplete ||
                    !selected.WasLoadedWithoutFallback ||
                    !selected.IsRollbackProtectionActive ||
                    selected.Revision < selected.RollbackFloorRevision)
                {
                    issues.Add(WebProtectionReadinessIssue.CatalogUntrusted);
                }
            }
        }

        private static ExtensionUxEvidenceState EvaluateExtensionUx(
            WebProtectionDesiredState desired,
            IReadOnlyList<ExtensionUxEvidence> extensions,
            DateTimeOffset nowUtc)
        {
            if (extensions.Count == 0)
            {
                return ExtensionUxEvidenceState.Missing;
            }

            var seen = new HashSet<ManagedBrowserFamily>();
            var state = ExtensionUxEvidenceState.Healthy;
            for (var index = 0; index < extensions.Count; index++)
            {
                var evidence = extensions[index];
                if (!seen.Add(evidence.Browser))
                {
                    state = MoreSevere(state, ExtensionUxEvidenceState.DuplicateOrContradictory);
                    continue;
                }

                var expected = FindBrowser(desired.Browsers, evidence.Browser);
                if (expected == null)
                {
                    state = MoreSevere(state, ExtensionUxEvidenceState.DuplicateOrContradictory);
                    continue;
                }

                if (!evidence.Envelope.Binding.Equals(desired.Binding))
                {
                    state = MoreSevere(state, ExtensionUxEvidenceState.BindingMismatch);
                }

                if (!string.Equals(
                        evidence.BoundChildAccountSid,
                        desired.ChildAccountSid,
                        StringComparison.Ordinal))
                {
                    state = MoreSevere(state, ExtensionUxEvidenceState.BindingMismatch);
                }

                if (!evidence.Envelope.IsServiceAuthenticated ||
                    !evidence.IsAuthenticatedChildSession)
                {
                    state = MoreSevere(state, ExtensionUxEvidenceState.Untrusted);
                }

                if (evidence.Envelope.CapturedAtUtc > nowUtc)
                {
                    state = MoreSevere(state, ExtensionUxEvidenceState.Future);
                }
                else if (IsNotCurrent(desired, evidence.Envelope, nowUtc))
                {
                    state = MoreSevere(state, ExtensionUxEvidenceState.Stale);
                }

                if (!string.Equals(expected.ExtensionVersion, evidence.ExtensionVersion, StringComparison.Ordinal) ||
                    !string.Equals(expected.ExtensionDigestSha256, evidence.ExtensionDigestSha256, StringComparison.Ordinal) ||
                    !string.Equals(
                        expected.ExecutableDigestSha256,
                        evidence.BrowserExecutableDigestSha256,
                        StringComparison.Ordinal))
                {
                    state = MoreSevere(state, ExtensionUxEvidenceState.VersionOrDigestMismatch);
                }

                if (!evidence.IsConnected || !evidence.IsRequestPageReady)
                {
                    state = MoreSevere(state, ExtensionUxEvidenceState.Unhealthy);
                }
            }

            if (seen.Count != desired.Browsers.Count)
            {
                state = MoreSevere(state, ExtensionUxEvidenceState.Missing);
            }

            return state;
        }

        private static ExtensionUxEvidenceState MoreSevere(
            ExtensionUxEvidenceState current,
            ExtensionUxEvidenceState candidate)
        {
            return (int)candidate > (int)current ? candidate : current;
        }

        private static void EvaluateEnvelope(
            WebProtectionDesiredState desired,
            ServiceAttestationEnvelope envelope,
            DateTimeOffset nowUtc,
            IssueAccumulator issues)
        {
            if (!envelope.IsServiceAuthenticated)
            {
                issues.Add(WebProtectionReadinessIssue.UntrustedEvidence);
            }

            if (!envelope.Binding.Equals(desired.Binding))
            {
                issues.Add(WebProtectionReadinessIssue.EvidenceBindingMismatch);
            }

            if (envelope.CapturedAtUtc > nowUtc)
            {
                issues.Add(WebProtectionReadinessIssue.EvidenceFromFuture);
            }

            if (IsNotCurrent(desired, envelope, nowUtc))
            {
                issues.Add(WebProtectionReadinessIssue.EvidenceStale);
            }
        }

        private static bool IsNotCurrent(
            WebProtectionDesiredState desired,
            ServiceAttestationEnvelope envelope,
            DateTimeOffset nowUtc)
        {
            if (envelope.CapturedAtUtc > nowUtc)
            {
                return false;
            }

            return nowUtc >= envelope.ValidUntilUtc ||
                nowUtc - envelope.CapturedAtUtc > desired.MaximumEvidenceAge;
        }

        private static BrowserEnforcementExpectation? FindBrowser(
            IReadOnlyList<BrowserEnforcementExpectation> browsers,
            ManagedBrowserFamily browser)
        {
            for (var index = 0; index < browsers.Count; index++)
            {
                if (browsers[index].Browser == browser)
                {
                    return browsers[index];
                }
            }

            return null;
        }

        private static TrustedWebCatalogExpectation? FindCatalog(
            IReadOnlyList<TrustedWebCatalogExpectation> catalogs,
            TrustedWebCatalogKind kind)
        {
            for (var index = 0; index < catalogs.Count; index++)
            {
                if (catalogs[index].Kind == kind)
                {
                    return catalogs[index];
                }
            }

            return null;
        }

        private sealed class ListenerSelection
        {
            public ListenerSelection(ProxyListenerEvidence? ipv4, ProxyListenerEvidence? ipv6)
            {
                IPv4 = ipv4;
                IPv6 = ipv6;
            }

            public ProxyListenerEvidence? IPv4 { get; }

            public ProxyListenerEvidence? IPv6 { get; }
        }

        private sealed class IssueAccumulator
        {
            private readonly HashSet<WebProtectionReadinessIssue> _issues =
                new HashSet<WebProtectionReadinessIssue>();

            public void Add(WebProtectionReadinessIssue issue)
            {
                _issues.Add(issue);
            }

            public IReadOnlyList<WebProtectionReadinessIssue> ToSortedList()
            {
                var sorted = new List<WebProtectionReadinessIssue>(_issues);
                sorted.Sort();
                return sorted;
            }
        }
    }
}
