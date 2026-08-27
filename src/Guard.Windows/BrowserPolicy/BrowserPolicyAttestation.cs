using System;

namespace Guard.Windows.BrowserPolicy
{
    public enum EffectiveProxyOverrideRulesState
    {
        None = 0,
        Direct = 1,
        External = 2,
        Present = 3
    }

    public sealed class BrowserCoverageEvidence
    {
        public BrowserCoverageEvidence(
            ManagedBrowserKind browser,
            string browserVersion,
            string policyDigestSha256,
            EffectiveProxyOverrideRulesState effectiveProxyOverrideRulesState)
        {
            if (browser != ManagedBrowserKind.MicrosoftEdge &&
                browser != ManagedBrowserKind.GoogleChrome)
            {
                throw new ArgumentOutOfRangeException(nameof(browser));
            }

            if (!IsBrowserVersion(browserVersion))
            {
                throw new ArgumentException("A bounded browser version is required.", nameof(browserVersion));
            }

            if (!IsSha256(policyDigestSha256))
            {
                throw new ArgumentException("A lowercase SHA-256 digest is required.", nameof(policyDigestSha256));
            }

            if (!Enum.IsDefined(typeof(EffectiveProxyOverrideRulesState), effectiveProxyOverrideRulesState))
            {
                throw new ArgumentOutOfRangeException(nameof(effectiveProxyOverrideRulesState));
            }

            Browser = browser;
            BrowserVersion = browserVersion;
            PolicyDigestSha256 = policyDigestSha256;
            EffectiveProxyOverrideRulesState = effectiveProxyOverrideRulesState;
        }

        public ManagedBrowserKind Browser { get; }

        public string BrowserVersion { get; }

        public string PolicyDigestSha256 { get; }

        // This is attestation input only: a local policy cannot override a higher-priority policy source.
        public EffectiveProxyOverrideRulesState EffectiveProxyOverrideRulesState { get; }

        public bool HasNoEffectiveProxyOverrideRules =>
            EffectiveProxyOverrideRulesState == EffectiveProxyOverrideRulesState.None;

        internal static bool IsSha256(string value)
        {
            if (value == null || value.Length != 64)
            {
                return false;
            }

            for (var index = 0; index < value.Length; index++)
            {
                var character = value[index];
                if (!((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')))
                {
                    return false;
                }
            }

            return true;
        }

        internal static bool IsBrowserVersion(string value)
        {
            if (string.IsNullOrEmpty(value) ||
                value.Length > 64 ||
                value[0] == '.' ||
                value[value.Length - 1] == '.')
            {
                return false;
            }

            var previousWasDot = false;
            for (var index = 0; index < value.Length; index++)
            {
                var character = value[index];
                if (character == '.')
                {
                    if (previousWasDot)
                    {
                        return false;
                    }

                    previousWasDot = true;
                    continue;
                }

                if (character < '0' || character > '9')
                {
                    return false;
                }

                previousWasDot = false;
            }

            return true;
        }
    }

    public sealed class BrowserPolicyObservation
    {
        public BrowserPolicyObservation(
            ManagedBrowserKind browser,
            string browserVersion,
            string policyDigestSha256,
            EffectiveProxyOverrideRulesState effectiveProxyOverrideRulesState)
        {
            if (browser != ManagedBrowserKind.MicrosoftEdge &&
                browser != ManagedBrowserKind.GoogleChrome)
            {
                throw new ArgumentOutOfRangeException(nameof(browser));
            }

            if (!BrowserCoverageEvidence.IsBrowserVersion(browserVersion))
            {
                throw new ArgumentException("A bounded browser version is required.", nameof(browserVersion));
            }

            if (!BrowserCoverageEvidence.IsSha256(policyDigestSha256))
            {
                throw new ArgumentException("A lowercase SHA-256 digest is required.", nameof(policyDigestSha256));
            }

            if (!Enum.IsDefined(typeof(EffectiveProxyOverrideRulesState), effectiveProxyOverrideRulesState))
            {
                throw new ArgumentOutOfRangeException(nameof(effectiveProxyOverrideRulesState));
            }

            Browser = browser;
            BrowserVersion = browserVersion;
            PolicyDigestSha256 = policyDigestSha256;
            EffectiveProxyOverrideRulesState = effectiveProxyOverrideRulesState;
        }

        public ManagedBrowserKind Browser { get; }

        public string BrowserVersion { get; }

        public string PolicyDigestSha256 { get; }

        // This records the browser's effective state; it does not attempt to change policy precedence.
        public EffectiveProxyOverrideRulesState EffectiveProxyOverrideRulesState { get; }

        public bool HasNoEffectiveProxyOverrideRules =>
            EffectiveProxyOverrideRulesState == EffectiveProxyOverrideRulesState.None;
    }

    public enum BrowserPolicyAttestationStatus
    {
        Attested = 0,
        MissingEvidence = 1,
        BrowserMismatch = 2,
        VersionMismatch = 3,
        DigestMismatch = 4,
        ProxyOverrideRulesDetected = 5
    }

    public sealed class BrowserPolicyAttestation
    {
        internal BrowserPolicyAttestation(BrowserPolicyAttestationStatus status)
        {
            if (!Enum.IsDefined(typeof(BrowserPolicyAttestationStatus), status))
            {
                throw new ArgumentOutOfRangeException(nameof(status));
            }

            Status = status;
        }

        public BrowserPolicyAttestationStatus Status { get; }

        public bool IsAttested => Status == BrowserPolicyAttestationStatus.Attested;
    }

    public static class BrowserPolicyAttestationEvaluator
    {
        public static BrowserPolicyAttestation Evaluate(
            ManagedBrowserPolicyPlan plan,
            BrowserCoverageEvidence? evidence,
            BrowserPolicyObservation? observation)
        {
            if (plan == null)
            {
                throw new ArgumentNullException(nameof(plan));
            }

            if (evidence == null || observation == null)
            {
                return new BrowserPolicyAttestation(BrowserPolicyAttestationStatus.MissingEvidence);
            }

            if (evidence.Browser != plan.Browser || observation.Browser != plan.Browser)
            {
                return new BrowserPolicyAttestation(BrowserPolicyAttestationStatus.BrowserMismatch);
            }

            if (!string.Equals(evidence.BrowserVersion, observation.BrowserVersion, StringComparison.Ordinal))
            {
                return new BrowserPolicyAttestation(BrowserPolicyAttestationStatus.VersionMismatch);
            }

            if (!string.Equals(plan.PolicyDigestSha256, evidence.PolicyDigestSha256, StringComparison.Ordinal) ||
                !string.Equals(plan.PolicyDigestSha256, observation.PolicyDigestSha256, StringComparison.Ordinal))
            {
                return new BrowserPolicyAttestation(BrowserPolicyAttestationStatus.DigestMismatch);
            }

            if (!evidence.HasNoEffectiveProxyOverrideRules ||
                !observation.HasNoEffectiveProxyOverrideRules)
            {
                return new BrowserPolicyAttestation(BrowserPolicyAttestationStatus.ProxyOverrideRulesDetected);
            }

            return new BrowserPolicyAttestation(BrowserPolicyAttestationStatus.Attested);
        }
    }
}
