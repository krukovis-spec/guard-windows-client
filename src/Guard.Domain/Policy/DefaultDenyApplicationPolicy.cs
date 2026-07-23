using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Guard.Contracts;
using Guard.Domain;

namespace Guard.Domain.Policy
{
    public enum AppControlCollection
    {
        Executable = 1,
        WindowsInstaller = 2,
        Script = 3,
        PackagedApp = 4,
        DynamicLibrary = 5
    }

    public sealed class RuleCatalogReference : IEquatable<RuleCatalogReference>
    {
        public RuleCatalogReference(string catalogId, string revision, string digestSha256, string windowsBuild, string guardVersion)
        {
            CatalogId = RequireIdentifier(catalogId, nameof(catalogId), 128);
            Revision = RequireIdentifier(revision, nameof(revision), 64);
            DigestSha256 = RequireSha256(digestSha256, nameof(digestSha256));
            WindowsBuild = RequireIdentifier(windowsBuild, nameof(windowsBuild), 64);
            GuardVersion = RequireIdentifier(guardVersion, nameof(guardVersion), 64);
        }

        public string CatalogId { get; }

        public string Revision { get; }

        public string DigestSha256 { get; }

        public string WindowsBuild { get; }

        public string GuardVersion { get; }

        public bool Equals(RuleCatalogReference? other)
        {
            return other != null &&
                   string.Equals(CatalogId, other.CatalogId, StringComparison.Ordinal) &&
                   string.Equals(Revision, other.Revision, StringComparison.Ordinal) &&
                   string.Equals(DigestSha256, other.DigestSha256, StringComparison.Ordinal) &&
                   string.Equals(WindowsBuild, other.WindowsBuild, StringComparison.Ordinal) &&
                   string.Equals(GuardVersion, other.GuardVersion, StringComparison.Ordinal);
        }

        public override bool Equals(object? obj) => Equals(obj as RuleCatalogReference);

        public override int GetHashCode()
        {
            var hash = StringComparer.Ordinal.GetHashCode(CatalogId);
            hash = (hash * 397) ^ StringComparer.Ordinal.GetHashCode(Revision);
            hash = (hash * 397) ^ StringComparer.Ordinal.GetHashCode(DigestSha256);
            hash = (hash * 397) ^ StringComparer.Ordinal.GetHashCode(WindowsBuild);
            return (hash * 397) ^ StringComparer.Ordinal.GetHashCode(GuardVersion);
        }

        private static string RequireIdentifier(string value, string parameterName, int maximumLength)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new ArgumentException("A rule-catalog identifier is required.", parameterName);
            }

            var normalized = value.Trim();
            if (normalized.Length > maximumLength || ContainsControlCharacter(normalized))
            {
                throw new ArgumentException("The rule-catalog identifier is invalid.", parameterName);
            }

            return normalized;
        }

        private static string RequireSha256(string value, string parameterName)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new ArgumentException("A rule-catalog digest is required.", parameterName);
            }

            var normalized = value.Trim();
            if (normalized.Length != 64)
            {
                throw new ArgumentException("A rule-catalog digest must be SHA-256.", parameterName);
            }

            for (var index = 0; index < normalized.Length; index++)
            {
                var character = normalized[index];
                if (!((character >= '0' && character <= '9') ||
                      (character >= 'a' && character <= 'f') ||
                      (character >= 'A' && character <= 'F')))
                {
                    throw new ArgumentException("A rule-catalog digest must be hexadecimal.", parameterName);
                }
            }

            return normalized.ToUpperInvariant();
        }

        private static bool ContainsControlCharacter(string value)
        {
            for (var index = 0; index < value.Length; index++)
            {
                if (char.IsControl(value[index]))
                {
                    return true;
                }
            }

            return false;
        }
    }

    public sealed class DisposableVmRuleCatalogAttestation
    {
        private static readonly AppControlCollection[] RequiredCollections =
        {
            AppControlCollection.Executable,
            AppControlCollection.WindowsInstaller,
            AppControlCollection.Script,
            AppControlCollection.PackagedApp,
            AppControlCollection.DynamicLibrary
        };

        private readonly AppControlCollection[] _verifiedCollections;

        internal DisposableVmRuleCatalogAttestation(
            RuleCatalogReference catalog,
            IEnumerable<AppControlCollection> verifiedCollections,
            bool guardSelfProtectionVerified,
            bool criticalSystemToolsVerified,
            bool arbitraryLaunchMatrixVerified,
            DateTimeOffset validatedAt)
        {
            Catalog = catalog ?? throw new ArgumentNullException(nameof(catalog));
            if (verifiedCollections == null)
            {
                throw new ArgumentNullException(nameof(verifiedCollections));
            }

            var seen = new HashSet<AppControlCollection>();
            foreach (var collection in verifiedCollections)
            {
                if (!Enum.IsDefined(typeof(AppControlCollection), collection) || !seen.Add(collection))
                {
                    throw new ArgumentException("Verified rule collections must be valid and unique.", nameof(verifiedCollections));
                }
            }

            _verifiedCollections = new AppControlCollection[seen.Count];
            seen.CopyTo(_verifiedCollections);
            Array.Sort(_verifiedCollections);
            GuardSelfProtectionVerified = guardSelfProtectionVerified;
            CriticalSystemToolsVerified = criticalSystemToolsVerified;
            ArbitraryLaunchMatrixVerified = arbitraryLaunchMatrixVerified;
            ValidatedAt = validatedAt;
        }

        public RuleCatalogReference Catalog { get; }

        public IReadOnlyList<AppControlCollection> VerifiedCollections =>
            Array.AsReadOnly((AppControlCollection[])_verifiedCollections.Clone());

        public bool GuardSelfProtectionVerified { get; }

        public bool CriticalSystemToolsVerified { get; }

        public bool ArbitraryLaunchMatrixVerified { get; }

        public DateTimeOffset ValidatedAt { get; }

        public bool IsValidFor(RuleCatalogReference requiredCatalog, DateTimeOffset now)
        {
            if (requiredCatalog == null || !Catalog.Equals(requiredCatalog) ||
                now < ValidatedAt ||
                !GuardSelfProtectionVerified ||
                !CriticalSystemToolsVerified ||
                !ArbitraryLaunchMatrixVerified)
            {
                return false;
            }

            if (_verifiedCollections.Length != RequiredCollections.Length)
            {
                return false;
            }

            for (var index = 0; index < RequiredCollections.Length; index++)
            {
                if (_verifiedCollections[index] != RequiredCollections[index])
                {
                    return false;
                }
            }

            return true;
        }
    }

    public sealed class ExactApplicationGrant
    {
        public ExactApplicationGrant(
            string grantId,
            string deviceId,
            string childSid,
            AppControlCollection collection,
            ApplicationIdentity identity,
            ParentDecision decision)
        {
            GrantId = RequireIdentifier(grantId, nameof(grantId), 128);
            DeviceId = RequireCanonicalToken(deviceId, nameof(deviceId));
            ChildSid = new WindowsAccountSid(childSid).Value;
            if (!Enum.IsDefined(typeof(AppControlCollection), collection))
            {
                throw new ArgumentOutOfRangeException(nameof(collection));
            }

            Identity = identity ?? throw new ArgumentNullException(nameof(identity));
            Decision = decision ?? throw new ArgumentNullException(nameof(decision));

            if (collection == AppControlCollection.PackagedApp)
            {
                if (!identity.HasPackageFamilyIdentity)
                {
                    throw new ArgumentException("Packaged-app grants require an exact package family identity.", nameof(identity));
                }
            }
            else if (!identity.HasFileHashFallback)
            {
                throw new ArgumentException("Unpackaged grants require an exact SHA-256 artifact identity.", nameof(identity));
            }

            Collection = collection;
        }

        public string GrantId { get; }

        public string DeviceId { get; }

        public string ChildSid { get; }

        public AppControlCollection Collection { get; }

        public ApplicationIdentity Identity { get; }

        public ParentDecision Decision { get; }

        public bool IsAllowedAt(DateTimeOffset now, int? trustedConsumedDailyMinutes)
        {
            switch (Decision.Kind)
            {
                case ParentDecisionKind.AlwaysAllow:
                    return true;
                case ParentDecisionKind.TemporaryAllow:
                    return Decision.ExpiresAt.HasValue && now < Decision.ExpiresAt.Value;
                case ParentDecisionKind.DailyQuota:
                    return trustedConsumedDailyMinutes.HasValue &&
                           trustedConsumedDailyMinutes.Value >= 0 &&
                           trustedConsumedDailyMinutes.Value < Decision.DailyQuotaMinutes!.Value;
                case ParentDecisionKind.Deny:
                default:
                    return false;
            }
        }

        public string TargetKey =>
            ((int)Collection).ToString(CultureInfo.InvariantCulture) + ":" + Identity.AuthorizationKey;

        private static string RequireIdentifier(string value, string parameterName, int maximumLength)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new ArgumentException("A bounded identifier is required.", parameterName);
            }

            var normalized = value.Trim();
            if (normalized.Length > maximumLength)
            {
                throw new ArgumentException("A bounded identifier is required.", parameterName);
            }

            for (var index = 0; index < normalized.Length; index++)
            {
                if (char.IsControl(normalized[index]))
                {
                    throw new ArgumentException("Control characters are not allowed in identifiers.", parameterName);
                }
            }

            return normalized;
        }

        private static string RequireCanonicalToken(string value, string parameterName)
        {
            if (!GuardIdentifier.IsCanonicalToken(value))
            {
                throw new ArgumentException("A canonical device token is required.", parameterName);
            }

            return value;
        }
    }

    public sealed class ApplicationGrantRuntimeState
    {
        public ApplicationGrantRuntimeState(
            string grantId,
            int consumedDailyMinutes,
            DateTimeOffset observedAt,
            DateTimeOffset validUntil)
        {
            if (string.IsNullOrWhiteSpace(grantId) || grantId.Trim().Length > 128)
            {
                throw new ArgumentException("A bounded grant id is required.", nameof(grantId));
            }

            if (consumedDailyMinutes < 0 || consumedDailyMinutes > 1440)
            {
                throw new ArgumentOutOfRangeException(nameof(consumedDailyMinutes));
            }

            if (validUntil <= observedAt || validUntil - observedAt > TimeSpan.FromMinutes(1))
            {
                throw new ArgumentOutOfRangeException(
                    nameof(validUntil),
                    "Daily-quota runtime state must expire within one minute.");
            }

            GrantId = grantId.Trim();
            ConsumedDailyMinutes = consumedDailyMinutes;
            ObservedAt = observedAt;
            ValidUntil = validUntil;
        }

        public string GrantId { get; }

        public int ConsumedDailyMinutes { get; }

        public DateTimeOffset ObservedAt { get; }

        public DateTimeOffset ValidUntil { get; }

        public bool IsCurrentAt(DateTimeOffset now)
        {
            return now >= ObservedAt && now < ValidUntil;
        }
    }

    public sealed class DesiredApplicationPolicy
    {
        private readonly ExactApplicationGrant[] _grants;

        public DesiredApplicationPolicy(
            string deviceId,
            string childSid,
            long revision,
            RuleCatalogReference requiredRuleCatalog,
            IEnumerable<ExactApplicationGrant> grants)
        {
            DeviceId = RequireCanonicalToken(deviceId, nameof(deviceId));
            ChildSid = new WindowsAccountSid(childSid).Value;
            if (revision < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(revision));
            }

            RequiredRuleCatalog = requiredRuleCatalog ?? throw new ArgumentNullException(nameof(requiredRuleCatalog));
            if (grants == null)
            {
                throw new ArgumentNullException(nameof(grants));
            }

            var copied = new List<ExactApplicationGrant>();
            var grantIds = new HashSet<string>(StringComparer.Ordinal);
            var targetKeys = new HashSet<string>(StringComparer.Ordinal);
            foreach (var grant in grants)
            {
                if (grant == null)
                {
                    throw new ArgumentException("Application grants cannot contain null.", nameof(grants));
                }

                if (!string.Equals(DeviceId, grant.DeviceId, StringComparison.Ordinal) ||
                    !string.Equals(ChildSid, grant.ChildSid, StringComparison.Ordinal))
                {
                    throw new ArgumentException("Application grants cannot cross device or child bindings.", nameof(grants));
                }

                if (!grantIds.Add(grant.GrantId) || !targetKeys.Add(grant.TargetKey))
                {
                    throw new ArgumentException("Application grants must have unique ids and exact targets.", nameof(grants));
                }

                copied.Add(grant);
            }

            _grants = copied.ToArray();
            Revision = revision;
        }

        public string DeviceId { get; }

        public string ChildSid { get; }

        public long Revision { get; }

        public RuleCatalogReference RequiredRuleCatalog { get; }

        public IReadOnlyList<ExactApplicationGrant> Grants =>
            Array.AsReadOnly((ExactApplicationGrant[])_grants.Clone());

        private static string RequireIdentifier(string value, string parameterName, int maximumLength)
        {
            if (string.IsNullOrWhiteSpace(value) || value.Trim().Length > maximumLength)
            {
                throw new ArgumentException("A bounded identifier is required.", parameterName);
            }

            return value.Trim();
        }

        private static string RequireCanonicalToken(string value, string parameterName)
        {
            if (!GuardIdentifier.IsCanonicalToken(value))
            {
                throw new ArgumentException("A canonical device token is required.", parameterName);
            }

            return value;
        }
    }

    public sealed class ExactApplicationRule
    {
        internal ExactApplicationRule(string ruleId, AppControlCollection collection, ApplicationIdentity identity)
        {
            RuleId = ruleId;
            Collection = collection;
            Identity = identity;
        }

        public string RuleId { get; }

        public AppControlCollection Collection { get; }

        public ApplicationIdentity Identity { get; }
    }

    public sealed class AppControlCollectionPlan
    {
        private readonly ExactApplicationRule[] _allowRules;

        internal AppControlCollectionPlan(AppControlCollection collection, IEnumerable<ExactApplicationRule> allowRules)
        {
            Collection = collection;
            _allowRules = new List<ExactApplicationRule>(allowRules).ToArray();
        }

        public AppControlCollection Collection { get; }

        public bool IsEnforced => true;

        public bool IsDefaultDeny => true;

        public IReadOnlyList<ExactApplicationRule> AllowRules =>
            Array.AsReadOnly((ExactApplicationRule[])_allowRules.Clone());
    }

    public sealed class DefaultDenyApplicationPolicyPlan
    {
        private readonly AppControlCollectionPlan[] _collections;
        private readonly string[] _diagnostics;

        internal DefaultDenyApplicationPolicyPlan(
            DesiredApplicationPolicy desired,
            IEnumerable<AppControlCollectionPlan> collections,
            IEnumerable<string> diagnostics,
            bool hasVerifiedRuleCatalog,
            DateTimeOffset? nextReconcileAt)
        {
            Desired = desired;
            _collections = new List<AppControlCollectionPlan>(collections).ToArray();
            _diagnostics = new List<string>(diagnostics).ToArray();
            HasVerifiedRuleCatalog = hasVerifiedRuleCatalog;
            NextReconcileAt = nextReconcileAt;
        }

        public DesiredApplicationPolicy Desired { get; }

        public IReadOnlyList<AppControlCollectionPlan> Collections =>
            Array.AsReadOnly((AppControlCollectionPlan[])_collections.Clone());

        public IReadOnlyList<string> Diagnostics =>
            Array.AsReadOnly((string[])_diagnostics.Clone());

        public bool HasVerifiedRuleCatalog { get; }

        public DateTimeOffset? NextReconcileAt { get; }

        public bool CanApply => HasVerifiedRuleCatalog && _collections.Length == 5;
    }

    public static class DefaultDenyApplicationPolicyCompiler
    {
        private static readonly AppControlCollection[] RequiredCollections =
        {
            AppControlCollection.Executable,
            AppControlCollection.WindowsInstaller,
            AppControlCollection.Script,
            AppControlCollection.PackagedApp,
            AppControlCollection.DynamicLibrary
        };

        public static DefaultDenyApplicationPolicyPlan Compile(
            DesiredApplicationPolicy desired,
            DisposableVmRuleCatalogAttestation? attestation,
            IEnumerable<ApplicationGrantRuntimeState>? runtimeStates,
            DateTimeOffset now)
        {
            if (desired == null)
            {
                throw new ArgumentNullException(nameof(desired));
            }

            var runtimeByGrant = CopyRuntimeStates(runtimeStates);
            var rulesByCollection = new Dictionary<AppControlCollection, List<ExactApplicationRule>>();
            for (var index = 0; index < RequiredCollections.Length; index++)
            {
                rulesByCollection.Add(RequiredCollections[index], new List<ExactApplicationRule>());
            }

            var diagnostics = new List<string>();
            DateTimeOffset? nextReconcileAt = null;
            foreach (var grant in desired.Grants)
            {
                int? consumed = null;
                ApplicationGrantRuntimeState runtime;
                ApplicationGrantRuntimeState? currentRuntime = null;
                if (runtimeByGrant.TryGetValue(grant.GrantId, out runtime) &&
                    runtime.IsCurrentAt(now))
                {
                    currentRuntime = runtime;
                    consumed = runtime.ConsumedDailyMinutes;
                }

                if (!grant.IsAllowedAt(now, consumed))
                {
                    if (grant.Decision.Kind == ParentDecisionKind.DailyQuota && !consumed.HasValue)
                    {
                        diagnostics.Add("Daily quota state is unavailable for grant " + grant.GrantId + "; denied.");
                    }

                    continue;
                }

                rulesByCollection[grant.Collection].Add(new ExactApplicationRule(
                    CreateStableRuleId(desired, grant),
                    grant.Collection,
                    grant.Identity));

                if (grant.Decision.Kind == ParentDecisionKind.TemporaryAllow)
                {
                    nextReconcileAt = Earlier(nextReconcileAt, grant.Decision.ExpiresAt);
                }
                else if (grant.Decision.Kind == ParentDecisionKind.DailyQuota &&
                         currentRuntime != null)
                {
                    nextReconcileAt = Earlier(nextReconcileAt, currentRuntime.ValidUntil);
                }
            }

            var plans = new List<AppControlCollectionPlan>(RequiredCollections.Length);
            for (var index = 0; index < RequiredCollections.Length; index++)
            {
                var collection = RequiredCollections[index];
                rulesByCollection[collection].Sort((left, right) => string.CompareOrdinal(left.RuleId, right.RuleId));
                plans.Add(new AppControlCollectionPlan(collection, rulesByCollection[collection]));
            }

            var catalogVerified = attestation != null &&
                                  attestation.IsValidFor(desired.RequiredRuleCatalog, now);
            if (!catalogVerified)
            {
                diagnostics.Add("The exact Guard and critical-system rule catalog is not attested by a current disposable-VM validation.");
            }

            return new DefaultDenyApplicationPolicyPlan(
                desired,
                plans,
                diagnostics,
                catalogVerified,
                nextReconcileAt);
        }

        private static DateTimeOffset? Earlier(DateTimeOffset? current, DateTimeOffset? candidate)
        {
            if (!candidate.HasValue)
            {
                return current;
            }

            return !current.HasValue || candidate.Value < current.Value
                ? candidate
                : current;
        }

        private static Dictionary<string, ApplicationGrantRuntimeState> CopyRuntimeStates(
            IEnumerable<ApplicationGrantRuntimeState>? runtimeStates)
        {
            var copied = new Dictionary<string, ApplicationGrantRuntimeState>(StringComparer.Ordinal);
            if (runtimeStates == null)
            {
                return copied;
            }

            foreach (var state in runtimeStates)
            {
                if (state == null || copied.ContainsKey(state.GrantId))
                {
                    throw new ArgumentException("Runtime grant states must be non-null and unique.", nameof(runtimeStates));
                }

                copied.Add(state.GrantId, state);
            }

            return copied;
        }

        private static string CreateStableRuleId(DesiredApplicationPolicy desired, ExactApplicationGrant grant)
        {
            var source = desired.DeviceId + "\n" + desired.ChildSid + "\n" +
                         ((int)grant.Collection).ToString(CultureInfo.InvariantCulture) + "\n" +
                         grant.Identity.AuthorizationKey;
            using (var sha256 = SHA256.Create())
            {
                var digest = sha256.ComputeHash(Encoding.UTF8.GetBytes(source));
                var builder = new StringBuilder(32);
                for (var index = 0; index < 16; index++)
                {
                    builder.Append(digest[index].ToString("x2", CultureInfo.InvariantCulture));
                }

                return "guard-v2-" + builder;
            }
        }
    }
}
