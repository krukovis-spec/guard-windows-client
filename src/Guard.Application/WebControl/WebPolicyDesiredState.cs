using System;
using System.Collections.Generic;
using Guard.Contracts;
using Guard.Domain;
using Guard.Domain.Web;

namespace Guard.Application.WebControl
{
    public sealed class WebCatalogReference : IEquatable<WebCatalogReference>
    {
        public WebCatalogReference(
            string catalogId,
            long revision,
            string digestSha256,
            long rollbackFloor)
        {
            CatalogId = RequireIdentifier(catalogId, nameof(catalogId));
            if (revision < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(revision));
            }

            if (rollbackFloor < 1 || rollbackFloor > revision)
            {
                throw new ArgumentOutOfRangeException(nameof(rollbackFloor));
            }

            Revision = revision;
            DigestSha256 = RequireSha256(digestSha256, nameof(digestSha256));
            RollbackFloor = rollbackFloor;
        }

        public string CatalogId { get; }

        public long Revision { get; }

        public string DigestSha256 { get; }

        public long RollbackFloor { get; }

        public bool Equals(WebCatalogReference? other)
        {
            return other != null &&
                   string.Equals(CatalogId, other.CatalogId, StringComparison.Ordinal) &&
                   Revision == other.Revision &&
                   string.Equals(DigestSha256, other.DigestSha256, StringComparison.Ordinal) &&
                   RollbackFloor == other.RollbackFloor;
        }

        public override bool Equals(object? obj) => Equals(obj as WebCatalogReference);

        public override int GetHashCode()
        {
            var hash = StringComparer.Ordinal.GetHashCode(CatalogId);
            hash = (hash * 397) ^ Revision.GetHashCode();
            hash = (hash * 397) ^ StringComparer.Ordinal.GetHashCode(DigestSha256);
            return (hash * 397) ^ RollbackFloor.GetHashCode();
        }

        private static string RequireIdentifier(string value, string parameterName)
        {
            if (string.IsNullOrWhiteSpace(value) ||
                value.Length > 128 ||
                !string.Equals(value, value.Trim(), StringComparison.Ordinal))
            {
                throw new ArgumentException(
                    "A bounded canonical catalog identifier is required.",
                    parameterName);
            }

            for (var index = 0; index < value.Length; index++)
            {
                var character = value[index];
                if (!((character >= 'a' && character <= 'z') ||
                      (character >= 'A' && character <= 'Z') ||
                      (character >= '0' && character <= '9') ||
                      character == '-' || character == '_' ||
                      character == '.' || character == ':'))
                {
                    throw new ArgumentException(
                        "The catalog identifier contains unsafe characters.",
                        parameterName);
                }
            }

            return value;
        }

        private static string RequireSha256(string value, string parameterName)
        {
            if (string.IsNullOrWhiteSpace(value) ||
                value.Length != 64 ||
                !string.Equals(value, value.Trim(), StringComparison.Ordinal))
            {
                throw new ArgumentException("A SHA-256 catalog digest is required.", parameterName);
            }

            for (var index = 0; index < value.Length; index++)
            {
                if (!Uri.IsHexDigit(value[index]))
                {
                    throw new ArgumentException(
                        "The catalog digest must be hexadecimal.",
                        parameterName);
                }
            }

            return value.ToUpperInvariant();
        }
    }

    public sealed class DesiredWebPolicy
    {
        private readonly WebAccessGrant[] _grants;

        public DesiredWebPolicy(
            string deviceId,
            string childSid,
            long revision,
            WebCatalogReference requiredPublicSuffixCatalog,
            WebCatalogReference requiredServiceCatalog,
            IEnumerable<WebAccessGrant> grants)
        {
            if (!GuardIdentifier.IsCanonicalToken(deviceId))
            {
                throw new ArgumentException(
                    "A canonical device identifier is required.",
                    nameof(deviceId));
            }

            DeviceId = deviceId;
            ChildSid = new WindowsAccountSid(childSid).Value;
            if (revision < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(revision));
            }

            Revision = revision;
            RequiredPublicSuffixCatalog = requiredPublicSuffixCatalog ??
                                          throw new ArgumentNullException(
                                              nameof(requiredPublicSuffixCatalog));
            RequiredServiceCatalog = requiredServiceCatalog ??
                                     throw new ArgumentNullException(
                                         nameof(requiredServiceCatalog));
            if (grants == null)
            {
                throw new ArgumentNullException(nameof(grants));
            }

            var copied = new List<WebAccessGrant>();
            var grantIds = new HashSet<string>(StringComparer.Ordinal);
            var bundleIds = new HashSet<string>(StringComparer.Ordinal);
            foreach (var grant in grants)
            {
                if (grant == null)
                {
                    throw new ArgumentException(
                        "Web grants cannot contain null.",
                        nameof(grants));
                }

                var signature = grant.Bundle.Signature;
                if (!string.Equals(
                        signature.CatalogId,
                        RequiredServiceCatalog.CatalogId,
                        StringComparison.Ordinal) ||
                    signature.CatalogSequence != RequiredServiceCatalog.Revision)
                {
                    throw new ArgumentException(
                        "Every web grant must belong to the exact required service catalog.",
                        nameof(grants));
                }

                if (!grantIds.Add(grant.GrantId) ||
                    !bundleIds.Add(grant.Bundle.Bundle.BundleId))
                {
                    throw new ArgumentException(
                        "Web grants must have unique ids and service-bundle targets.",
                        nameof(grants));
                }

                copied.Add(grant);
            }

            copied.Sort((left, right) =>
                string.CompareOrdinal(left.GrantId, right.GrantId));
            _grants = copied.ToArray();
        }

        public string DeviceId { get; }

        public string ChildSid { get; }

        public long Revision { get; }

        public WebCatalogReference RequiredPublicSuffixCatalog { get; }

        public WebCatalogReference RequiredServiceCatalog { get; }

        public IReadOnlyList<WebAccessGrant> Grants =>
            Array.AsReadOnly((WebAccessGrant[])_grants.Clone());
    }

    public sealed class VerifiedWebCatalogSet
    {
        public static readonly TimeSpan MaximumValidity = TimeSpan.FromDays(180);

        public VerifiedWebCatalogSet(
            WebCatalogReference publicSuffixCatalog,
            WebCatalogReference serviceCatalog,
            bool publicSuffixRulesVerified,
            bool serviceBundlesVerified,
            bool rollbackFloorsEnforced,
            DateTimeOffset validatedAt,
            DateTimeOffset validUntil)
        {
            PublicSuffixCatalog = publicSuffixCatalog ??
                                  throw new ArgumentNullException(
                                      nameof(publicSuffixCatalog));
            ServiceCatalog = serviceCatalog ??
                             throw new ArgumentNullException(nameof(serviceCatalog));
            if (validUntil <= validatedAt ||
                validUntil - validatedAt > MaximumValidity)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(validUntil),
                    "Verified web catalogs must have a bounded positive validity period.");
            }

            PublicSuffixRulesVerified = publicSuffixRulesVerified;
            ServiceBundlesVerified = serviceBundlesVerified;
            RollbackFloorsEnforced = rollbackFloorsEnforced;
            ValidatedAt = validatedAt;
            ValidUntil = validUntil;
        }

        public WebCatalogReference PublicSuffixCatalog { get; }

        public WebCatalogReference ServiceCatalog { get; }

        public bool PublicSuffixRulesVerified { get; }

        public bool ServiceBundlesVerified { get; }

        public bool RollbackFloorsEnforced { get; }

        public DateTimeOffset ValidatedAt { get; }

        public DateTimeOffset ValidUntil { get; }

        public bool IsValidFor(
            WebCatalogReference requiredPublicSuffixCatalog,
            WebCatalogReference requiredServiceCatalog,
            DateTimeOffset now)
        {
            return requiredPublicSuffixCatalog != null &&
                   requiredServiceCatalog != null &&
                   PublicSuffixCatalog.Equals(requiredPublicSuffixCatalog) &&
                   ServiceCatalog.Equals(requiredServiceCatalog) &&
                   PublicSuffixCatalog.Revision >= PublicSuffixCatalog.RollbackFloor &&
                   ServiceCatalog.Revision >= ServiceCatalog.RollbackFloor &&
                   PublicSuffixRulesVerified &&
                   ServiceBundlesVerified &&
                   RollbackFloorsEnforced &&
                   now >= ValidatedAt &&
                   now < ValidUntil;
        }
    }

    public sealed class WebPolicyApplyPlan
    {
        internal WebPolicyApplyPlan(
            DesiredWebPolicy desired,
            VerifiedWebCatalogSet catalogs,
            DefaultDenyWebPolicyPlan enforcement)
        {
            Desired = desired;
            Catalogs = catalogs;
            Enforcement = enforcement;
            NextReconcileAt = Earlier(
                enforcement.NextReconcileAt,
                catalogs.ValidUntil);
        }

        public DesiredWebPolicy Desired { get; }

        public VerifiedWebCatalogSet Catalogs { get; }

        public DefaultDenyWebPolicyPlan Enforcement { get; }

        public bool IsDefaultDeny => Enforcement.IsDefaultDeny;

        public DateTimeOffset? NextReconcileAt { get; }

        private static DateTimeOffset? Earlier(
            DateTimeOffset? current,
            DateTimeOffset candidate)
        {
            return !current.HasValue || candidate < current.Value
                ? candidate
                : current;
        }
    }
}
