using System;
using System.Collections.Generic;
using Guard.Windows.BrowserPolicy;

namespace Guard.BrowserPolicy.Tests
{
    internal static class Program
    {
        private const string ExtensionId = "abcdefghijklmnopabcdefghijklmnop";

        private static int Main()
        {
            var tests = new List<(string Name, Action Run)>
            {
                ("creates strict Edge desired state", CreatesStrictEdgePlan),
                ("creates equivalent strict Chrome adapter state", CreatesStrictChromePlan),
                ("rejects non-loopback proxies and broad extension origins", RejectsUnsafeInputs),
                ("binds coverage evidence to browser version and exact digest", AttestsExactCoverage),
                ("fails closed for missing or contradictory attestation", FailsClosedForContradictions),
                ("fails closed when Edge reports an effective proxy override", RejectsEdgeProxyOverride),
                ("fails closed when Chrome reports an effective proxy override", RejectsChromeProxyOverride)
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

            Console.WriteLine(failures == 0 ? "All Guard browser policy checks passed." : failures + " browser policy check(s) failed.");
            return failures == 0 ? 0 : 1;
        }

        private static void CreatesStrictEdgePlan()
        {
            var plan = CreateEdgePlan();
            Assert(plan.Browser == ManagedBrowserKind.MicrosoftEdge, "Plan was not Edge-first.");
            Assert(plan.ProxyEndpoint.Endpoint == "http://127.0.0.1:48123", "Proxy endpoint changed.");
            Assert(
                plan.IsMachineManagedProxyOnly &&
                plan.IsProxyAutoDetectDisabled &&
                plan.IsProxyPacDisabled &&
                plan.HasNoProxyBypassRules &&
                plan.HasNoProxyOverrideRules,
                "Proxy policy was not strict.");
            Assert(plan.IsQuicDisabled && plan.IsDnsOverHttpsDisabled, "Network bypass policies were not disabled.");
            Assert(
                plan.IsIncognitoDisabled &&
                plan.IsGuestModeDisabled &&
                plan.IsProfileAdditionDisabled &&
                plan.IsBrowserSigninDisabled &&
                plan.AreDeveloperToolsRestricted &&
                plan.IsExtensionDeveloperModeDisabled,
                "Browser escape policies were not restricted.");
            Assert(
                plan.ForceInstalledExtension.UpdateUrl ==
                    "https://edge.microsoft.com/extensionwebstorebase/v1/crx",
                "The exact extension update URL changed.");
            Assert(plan.MachinePolicies.Count == 10, "The exact Edge machine-policy set changed.");
            AssertPolicy(
                plan,
                "ProxySettings",
                ManagedBrowserPolicyValueKind.String,
                "{\"ProxyBypassList\":\"\",\"ProxyMode\":\"fixed_servers\",\"ProxyServer\":\"http://127.0.0.1:48123\"}");
            AssertPolicy(plan, "QuicAllowed", ManagedBrowserPolicyValueKind.Boolean, "false");
            AssertPolicy(plan, "DnsOverHttpsMode", ManagedBrowserPolicyValueKind.String, "off");
            AssertPolicy(plan, "InPrivateModeAvailability", ManagedBrowserPolicyValueKind.Integer, "1");
            AssertPolicy(plan, "BrowserAddProfileEnabled", ManagedBrowserPolicyValueKind.Boolean, "false");
            AssertPolicy(plan, "BrowserSignin", ManagedBrowserPolicyValueKind.Integer, "0");
            AssertPolicy(plan, "DeveloperToolsAvailability", ManagedBrowserPolicyValueKind.Integer, "2");
            AssertPolicy(plan, "ExtensionDeveloperModeSettings", ManagedBrowserPolicyValueKind.Integer, "1");
            AssertPolicy(
                plan,
                "ExtensionSettings",
                ManagedBrowserPolicyValueKind.String,
                "{\"*\":{\"installation_mode\":\"blocked\"},\"abcdefghijklmnopabcdefghijklmnop\":{\"installation_mode\":\"force_installed\",\"update_url\":\"https://edge.microsoft.com/extensionwebstorebase/v1/crx\"}}");
            Assert(plan.PolicyDigestSha256.Length == 64, "Plan digest was not SHA-256 shaped.");
        }

        private static void CreatesStrictChromePlan()
        {
            var proxy = new TrustedLoopbackProxyEndpoint("http://[::1]:48123");
            var extension = new ForceInstalledExtension(
                ExtensionId,
                "https://clients2.google.com/service/update2/crx");
            var chrome = ManagedBrowserPolicyPlan.CreateChrome(proxy, extension);
            var edge = CreateEdgePlan();
            Assert(chrome.Browser == ManagedBrowserKind.GoogleChrome, "Chrome adapter was not created.");
            Assert(chrome.IsQuicDisabled && chrome.IsDnsOverHttpsDisabled && chrome.HasNoProxyBypassRules, "Chrome adapter weakened strict state.");
            Assert(chrome.MachinePolicies.Count == 9, "The exact Chrome machine-policy set changed.");
            AssertPolicy(chrome, "IncognitoModeAvailability", ManagedBrowserPolicyValueKind.Integer, "1");
            AssertPolicy(chrome, "BrowserAddPersonEnabled", ManagedBrowserPolicyValueKind.Boolean, "false");
            AssertPolicy(
                chrome,
                "ProxySettings",
                ManagedBrowserPolicyValueKind.String,
                "{\"ProxyBypassList\":\"\",\"ProxyMode\":\"fixed_servers\",\"ProxyServer\":\"http://[::1]:48123\"}");
            Assert(!string.Equals(chrome.PolicyDigestSha256, edge.PolicyDigestSha256, StringComparison.Ordinal), "Browser family was omitted from the digest.");
        }

        private static void RejectsUnsafeInputs()
        {
            Throws(() => new TrustedLoopbackProxyEndpoint("http://localhost:48123"), "Resolvable hostname was accepted as loopback.");
            Throws(() => new TrustedLoopbackProxyEndpoint("https://127.0.0.1:48123"), "HTTPS proxy endpoint was accepted.");
            Throws(() => new TrustedLoopbackProxyEndpoint("http://192.168.1.10:48123"), "Non-loopback proxy was accepted.");
            Throws(() => new BrowserCoverageEvidence(ManagedBrowserKind.Unknown, "144.0.0.0", new string('a', 64), EffectiveProxyOverrideRulesState.None), "An unknown browser kind was accepted.");
            Throws(() => new BrowserCoverageEvidence(ManagedBrowserKind.MicrosoftEdge, "144.0\nspoof", new string('a', 64), EffectiveProxyOverrideRulesState.None), "An unsafe browser version was accepted.");
            Throws(() => new BrowserCoverageEvidence(ManagedBrowserKind.MicrosoftEdge, "144.0.0.0", new string('a', 64), (EffectiveProxyOverrideRulesState)99), "An unknown proxy override state was accepted.");
            Throws(() => new ForceInstalledExtension(ExtensionId, "https://updates.guard.example"), "A non-exact extension update origin was accepted.");
            Throws(() => new ForceInstalledExtension(ExtensionId, "https://updates.guard.example/manifest.xml?channel=stable"), "A mutable extension update query was accepted.");
            Throws(() => new ForceInstalledExtension("ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP", "https://updates.guard.example"), "Non-canonical extension id was accepted.");
        }

        private static void AttestsExactCoverage()
        {
            var plan = CreateEdgePlan();
            var evidence = new BrowserCoverageEvidence(ManagedBrowserKind.MicrosoftEdge, "144.0.0.0", plan.PolicyDigestSha256, EffectiveProxyOverrideRulesState.None);
            var observation = new BrowserPolicyObservation(ManagedBrowserKind.MicrosoftEdge, "144.0.0.0", plan.PolicyDigestSha256, EffectiveProxyOverrideRulesState.None);
            var result = BrowserPolicyAttestationEvaluator.Evaluate(plan, evidence, observation);
            Assert(result.IsAttested && result.Status == BrowserPolicyAttestationStatus.Attested, "Matching evidence was not attested.");
        }

        private static void FailsClosedForContradictions()
        {
            var plan = CreateEdgePlan();
            var matchingEvidence = new BrowserCoverageEvidence(ManagedBrowserKind.MicrosoftEdge, "144.0.0.0", plan.PolicyDigestSha256, EffectiveProxyOverrideRulesState.None);
            var wrongVersion = new BrowserPolicyObservation(ManagedBrowserKind.MicrosoftEdge, "145.0.0.0", plan.PolicyDigestSha256, EffectiveProxyOverrideRulesState.None);
            var wrongBrowser = new BrowserPolicyObservation(ManagedBrowserKind.GoogleChrome, "144.0.0.0", plan.PolicyDigestSha256, EffectiveProxyOverrideRulesState.None);
            var wrongDigest = new BrowserPolicyObservation(ManagedBrowserKind.MicrosoftEdge, "144.0.0.0", new string('a', 64), EffectiveProxyOverrideRulesState.None);
            Assert(BrowserPolicyAttestationEvaluator.Evaluate(plan, null, null).Status == BrowserPolicyAttestationStatus.MissingEvidence, "Missing evidence did not fail closed.");
            Assert(BrowserPolicyAttestationEvaluator.Evaluate(plan, matchingEvidence, wrongVersion).Status == BrowserPolicyAttestationStatus.VersionMismatch, "Version mismatch was attested.");
            Assert(BrowserPolicyAttestationEvaluator.Evaluate(plan, matchingEvidence, wrongBrowser).Status == BrowserPolicyAttestationStatus.BrowserMismatch, "Browser mismatch was attested.");
            Assert(BrowserPolicyAttestationEvaluator.Evaluate(plan, matchingEvidence, wrongDigest).Status == BrowserPolicyAttestationStatus.DigestMismatch, "Digest mismatch was attested.");
        }

        private static void RejectsEdgeProxyOverride()
        {
            var plan = CreateEdgePlan();
            var evidence = new BrowserCoverageEvidence(ManagedBrowserKind.MicrosoftEdge, "144.0.0.0", plan.PolicyDigestSha256, EffectiveProxyOverrideRulesState.Direct);
            var observation = new BrowserPolicyObservation(ManagedBrowserKind.MicrosoftEdge, "144.0.0.0", plan.PolicyDigestSha256, EffectiveProxyOverrideRulesState.None);
            Assert(
                BrowserPolicyAttestationEvaluator.Evaluate(plan, evidence, observation).Status ==
                    BrowserPolicyAttestationStatus.ProxyOverrideRulesDetected,
                "Edge DIRECT proxy override was attested.");
        }

        private static void RejectsChromeProxyOverride()
        {
            var plan = ManagedBrowserPolicyPlan.CreateChrome(
                new TrustedLoopbackProxyEndpoint("http://127.0.0.1:48123"),
                new ForceInstalledExtension(ExtensionId, "https://clients2.google.com/service/update2/crx"));
            var evidence = new BrowserCoverageEvidence(ManagedBrowserKind.GoogleChrome, "144.0.0.0", plan.PolicyDigestSha256, EffectiveProxyOverrideRulesState.None);
            var observation = new BrowserPolicyObservation(ManagedBrowserKind.GoogleChrome, "144.0.0.0", plan.PolicyDigestSha256, EffectiveProxyOverrideRulesState.External);
            Assert(
                BrowserPolicyAttestationEvaluator.Evaluate(plan, evidence, observation).Status ==
                    BrowserPolicyAttestationStatus.ProxyOverrideRulesDetected,
                "Chrome external proxy override was attested.");
        }

        private static ManagedBrowserPolicyPlan CreateEdgePlan()
        {
            return ManagedBrowserPolicyPlan.CreateEdge(
                new TrustedLoopbackProxyEndpoint("http://127.0.0.1:48123"),
                new ForceInstalledExtension(
                    ExtensionId,
                    "https://edge.microsoft.com/extensionwebstorebase/v1/crx"));
        }

        private static void Throws(Action action, string message)
        {
            try
            {
                action();
            }
            catch (ArgumentException)
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

        private static void AssertPolicy(
            ManagedBrowserPolicyPlan plan,
            string name,
            ManagedBrowserPolicyValueKind kind,
            string value)
        {
            ManagedBrowserPolicySetting? found = null;
            for (var index = 0; index < plan.MachinePolicies.Count; index++)
            {
                if (string.Equals(
                        plan.MachinePolicies[index].Name,
                        name,
                        StringComparison.Ordinal))
                {
                    found = plan.MachinePolicies[index];
                    break;
                }
            }

            Assert(found != null, "Required machine policy is missing: " + name);
            Assert(
                found!.ValueKind == kind &&
                string.Equals(
                    found.CanonicalValue,
                    value,
                    StringComparison.Ordinal),
                "Machine policy changed: " + name);
        }
    }
}
