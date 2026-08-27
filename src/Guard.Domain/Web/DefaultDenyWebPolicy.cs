using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Guard.Domain.Policy;

namespace Guard.Domain.Web
{
    /// <summary>Canonical ASCII DNS host; deliberately does not accept URLs, IP literals, wildcards, or user-info.</summary>
    public sealed class CanonicalDnsHost : IEquatable<CanonicalDnsHost>
    {
        private CanonicalDnsHost(string value) { Value = value; }
        public string Value { get; }

        public static CanonicalDnsHost Parse(string value) => ParseCore(value, requireMultipleLabels: true);
        internal static CanonicalDnsHost ParsePublicSuffix(string value) => ParseCore(value, requireMultipleLabels: false);
        private static CanonicalDnsHost ParseCore(string value, bool requireMultipleLabels)
        {
            if (string.IsNullOrWhiteSpace(value) ||
                !string.Equals(value, value.Trim(), StringComparison.Ordinal) ||
                value.Length > 1024)
                throw new ArgumentException("A canonical DNS host is required.", nameof(value));

            var input = value;
            if (input.EndsWith(".", StringComparison.Ordinal))
            {
                input = input.Substring(0, input.Length - 1);
                if (input.EndsWith(".", StringComparison.Ordinal))
                    throw new ArgumentException("A DNS host can contain at most one trailing root label.", nameof(value));
            }

            if (input.Length == 0 || input.IndexOfAny(new[] { '/', ':', '@', '*', '?', '#', '\\' }) >= 0 ||
                IPAddress.TryParse(input, out _))
                throw new ArgumentException("Only a DNS host name is allowed.", nameof(value));

            var labels = input.Split('.');
            if (requireMultipleLabels && labels.Length < 2) throw new ArgumentException("A DNS host must have at least two labels.", nameof(value));
            var idn = new IdnMapping();
            var canonical = new StringBuilder(input.Length);
            for (var index = 0; index < labels.Length; index++)
            {
                string label;
                try { label = idn.GetAscii(labels[index]); }
                catch (ArgumentException) { throw new ArgumentException("The DNS host contains an invalid internationalized label.", nameof(value)); }
                if (label.Length == 0 || label.Length > 63 || label[0] == '-' || label[label.Length - 1] == '-')
                    throw new ArgumentException("The DNS host contains an invalid label.", nameof(value));
                for (var character = 0; character < label.Length; character++)
                {
                    var current = label[character];
                    if (!((current >= 'a' && current <= 'z') || (current >= 'A' && current <= 'Z') ||
                          (current >= '0' && current <= '9') || current == '-'))
                        throw new ArgumentException("The DNS host contains an invalid label.", nameof(value));
                }
                if (index > 0) canonical.Append('.');
                canonical.Append(label.ToLowerInvariant());
            }

            var canonicalValue = canonical.ToString();
            if (canonicalValue.Length > 253 || IPAddress.TryParse(canonicalValue, out _))
                throw new ArgumentException("The canonical DNS host is invalid or oversized.", nameof(value));

            return new CanonicalDnsHost(canonicalValue);
        }

        public bool Equals(CanonicalDnsHost? other) => other != null && string.Equals(Value, other.Value, StringComparison.Ordinal);
        public override bool Equals(object? obj) => Equals(obj as CanonicalDnsHost);
        public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(Value);
        public override string ToString() => Value;
    }

    /// <summary>
    /// An explicit result from a trusted public-suffix/registrable-domain resolver. The domain is never inferred from the last labels.
    /// </summary>
    public sealed class RegistrableDomainEvidence
    {
        private RegistrableDomainEvidence(CanonicalDnsHost observedHost, string registrableDomain, string publicSuffix, string resolverRevision)
        {
            ObservedHost = observedHost;
            RegistrableDomain = CanonicalDnsHost.Parse(registrableDomain);
            PublicSuffix = CanonicalDnsHost.ParsePublicSuffix(publicSuffix);
            if (!IsSameOrChild(ObservedHost, RegistrableDomain) || !IsSameOrChild(RegistrableDomain, PublicSuffix) ||
                string.Equals(RegistrableDomain.Value, PublicSuffix.Value, StringComparison.Ordinal) ||
                !HasOneOrMoreLabelsBefore(RegistrableDomain, PublicSuffix))
                throw new ArgumentException("The supplied registrable-domain evidence is structurally inconsistent.");
            ResolverRevision = WebPolicyIdentifier.Require(
                resolverRevision,
                128,
                nameof(resolverRevision));
        }

        public static RegistrableDomainEvidence Resolve(string observedHost, ITrustedRegistrableDomainResolver resolver)
        {
            if (resolver == null) throw new ArgumentNullException(nameof(resolver));
            var host = CanonicalDnsHost.Parse(observedHost);
            if (!resolver.TryResolve(host, out var registrableDomain, out var publicSuffix, out var resolverRevision))
                throw new InvalidOperationException("No trusted registrable-domain evidence is available for this host.");
            return new RegistrableDomainEvidence(host, registrableDomain, publicSuffix, resolverRevision);
        }

        public CanonicalDnsHost ObservedHost { get; }
        public CanonicalDnsHost RegistrableDomain { get; }
        public CanonicalDnsHost PublicSuffix { get; }
        public string ResolverRevision { get; }

        internal static bool IsSameOrChild(CanonicalDnsHost host, CanonicalDnsHost parent) =>
            string.Equals(host.Value, parent.Value, StringComparison.Ordinal) ||
            host.Value.EndsWith("." + parent.Value, StringComparison.Ordinal);

        private static bool HasOneOrMoreLabelsBefore(CanonicalDnsHost value, CanonicalDnsHost suffix) =>
            value.Value.Length > suffix.Value.Length + 1 && value.Value.EndsWith("." + suffix.Value, StringComparison.Ordinal);
    }

    public interface ITrustedRegistrableDomainResolver
    {
        bool TryResolve(CanonicalDnsHost observedHost, out string registrableDomain, out string publicSuffix, out string resolverRevision);
    }

    public enum WebScopeKind { ExactHost = 1, RegistrableDomainSubtree = 2 }

    /// <summary>Network endpoints are constrained to HTTP or HTTPS on their default ports; schemes and ports are not wildcard policy inputs.</summary>
    public sealed class WebEndpoint
    {
        public WebEndpoint(string scheme, string host, int port)
        {
            var isHttp = string.Equals(scheme, "http", StringComparison.OrdinalIgnoreCase);
            var isHttps = string.Equals(scheme, "https", StringComparison.OrdinalIgnoreCase);
            if ((!isHttp || port != 80) && (!isHttps || port != 443))
                throw new ArgumentException("Only HTTP or HTTPS on its default port is eligible for the web policy.");
            Scheme = isHttps ? "https" : "http"; Host = CanonicalDnsHost.Parse(host); Port = port;
        }
        public string Scheme { get; } public CanonicalDnsHost Host { get; } public int Port { get; }
    }

    public sealed class WebScope : IEquatable<WebScope>
    {
        private WebScope(WebScopeKind kind, CanonicalDnsHost host) { Kind = kind; Host = host; }
        public WebScopeKind Kind { get; }
        public CanonicalDnsHost Host { get; }
        public static WebScope ExactHost(string host) => new WebScope(WebScopeKind.ExactHost, CanonicalDnsHost.Parse(host));
        public static WebScope RegistrableDomainSubtree(RegistrableDomainEvidence evidence) =>
            evidence == null ? throw new ArgumentNullException(nameof(evidence)) : new WebScope(WebScopeKind.RegistrableDomainSubtree, evidence.RegistrableDomain);
        public bool Matches(string host)
        {
            var candidate = CanonicalDnsHost.Parse(host);
            return Kind == WebScopeKind.ExactHost ? Host.Equals(candidate) : RegistrableDomainEvidence.IsSameOrChild(candidate, Host);
        }
        public bool Equals(WebScope? other) => other != null && Kind == other.Kind && Host.Equals(other.Host);
        public override bool Equals(object? obj) => Equals(obj as WebScope);
        public override int GetHashCode() => ((int)Kind * 397) ^ Host.GetHashCode();
    }

    public sealed class WebServiceBundle
    {
        private readonly WebScope[] _scopes;
        public WebServiceBundle(string bundleId, IEnumerable<WebScope> scopes)
        {
            BundleId = WebPolicyIdentifier.Require(bundleId, 128, nameof(bundleId));
            if (scopes == null) throw new ArgumentNullException(nameof(scopes));
            var unique = new HashSet<WebScope>();
            foreach (var scope in scopes)
            {
                if (scope == null) throw new ArgumentException("A bundle cannot contain a null scope.", nameof(scopes));
                if (!unique.Add(scope)) throw new ArgumentException("A bundle cannot contain duplicate scopes.", nameof(scopes));
            }
            if (unique.Count == 0 || unique.Count > 32) throw new ArgumentException("A bundle must contain 1 to 32 explicit scopes.", nameof(scopes));
            _scopes = new WebScope[unique.Count]; unique.CopyTo(_scopes);
            Array.Sort(_scopes, CompareScopes);
        }
        public string BundleId { get; }
        public IReadOnlyList<WebScope> Scopes => Array.AsReadOnly((WebScope[])_scopes.Clone());
        internal byte[] CanonicalBytes()
        {
            var builder = new StringBuilder(BundleId.Length + 128);
            builder.Append(BundleId).Append('\n');
            for (var index = 0; index < _scopes.Length; index++) builder.Append((int)_scopes[index].Kind).Append(':').Append(_scopes[index].Host.Value).Append('\n');
            return Encoding.UTF8.GetBytes(builder.ToString());
        }
        public string CanonicalDigestSha256()
        {
            using (var sha = SHA256.Create())
            {
                return BitConverter.ToString(sha.ComputeHash(CanonicalBytes())).Replace("-", string.Empty);
            }
        }
        private static int CompareScopes(WebScope left, WebScope right) => string.CompareOrdinal(((int)left.Kind).ToString(CultureInfo.InvariantCulture) + left.Host.Value, ((int)right.Kind).ToString(CultureInfo.InvariantCulture) + right.Host.Value);
    }

    public sealed class WebBundleSignature
    {
        public static readonly TimeSpan MaximumValidity =
            TimeSpan.FromDays(180);

        public WebBundleSignature(
            string catalogId,
            long catalogSequence,
            long bundleVersion,
            DateTimeOffset issuedAtUtc,
            DateTimeOffset expiresAtUtc,
            string minimumGuardVersion,
            string digestSha256,
            string signingKeyId,
            byte[] signature)
        {
            if (catalogSequence < 1) throw new ArgumentOutOfRangeException(nameof(catalogSequence));
            if (bundleVersion < 1) throw new ArgumentOutOfRangeException(nameof(bundleVersion));
            if (expiresAtUtc <= issuedAtUtc ||
                expiresAtUtc - issuedAtUtc > MaximumValidity)
                throw new ArgumentOutOfRangeException(
                    nameof(expiresAtUtc),
                    "A signed web bundle must have a bounded positive validity period.");
            if (!Version.TryParse(minimumGuardVersion, out var parsedMinimumVersion) ||
                !string.Equals(
                    parsedMinimumVersion.ToString(),
                    minimumGuardVersion,
                    StringComparison.Ordinal))
                throw new ArgumentException(
                    "A canonical minimum Guard version is required.",
                    nameof(minimumGuardVersion));
            if (!IsSha256(digestSha256)) throw new ArgumentException("A SHA-256 digest is required.", nameof(digestSha256));
            if (signature == null || signature.Length == 0 || signature.Length > 4096) throw new ArgumentException("A bounded signature is required.", nameof(signature));
            CatalogId = WebPolicyIdentifier.Require(catalogId, 128, nameof(catalogId));
            CatalogSequence = catalogSequence;
            BundleVersion = bundleVersion;
            IssuedAtUtc = issuedAtUtc.ToUniversalTime();
            ExpiresAtUtc = expiresAtUtc.ToUniversalTime();
            MinimumGuardVersion = minimumGuardVersion;
            DigestSha256 = digestSha256.ToUpperInvariant();
            SigningKeyId = WebPolicyIdentifier.Require(signingKeyId, 128, nameof(signingKeyId));
            _signature = (byte[])signature.Clone();
        }
        private readonly byte[] _signature;
        public string CatalogId { get; }
        public long CatalogSequence { get; }
        public long BundleVersion { get; }
        public DateTimeOffset IssuedAtUtc { get; }
        public DateTimeOffset ExpiresAtUtc { get; }
        public string MinimumGuardVersion { get; }
        public string DigestSha256 { get; }
        public string SigningKeyId { get; }
        public byte[] Signature => (byte[])_signature.Clone();

        public bool IsActiveAt(DateTimeOffset nowUtc)
        {
            return nowUtc >= IssuedAtUtc && nowUtc < ExpiresAtUtc;
        }

        internal static bool IsSha256(string value)
        {
            if (string.IsNullOrWhiteSpace(value) || value.Length != 64) return false;
            for (var index = 0; index < value.Length; index++) if (!Uri.IsHexDigit(value[index])) return false;
            return true;
        }
    }

    public interface IWebBundleSignatureVerifier { bool Verify(string signingKeyId, byte[] canonicalBundleBytes, byte[] signature); }

    /// <summary>
    /// Durable monotonic acceptance floor for one exact bundle. Callers persist
    /// a separate floor for every (catalog, bundle) pair after verification.
    /// The digest binding prevents a catalog sequence from reusing the same
    /// bundle version with different scopes.
    /// </summary>
    public sealed class WebBundleAcceptanceFloor
    {
        public WebBundleAcceptanceFloor(
            string catalogId,
            string bundleId,
            long minimumCatalogSequence,
            long minimumBundleVersion,
            string acceptedDigestAtMinimumVersionSha256)
        {
            if (minimumCatalogSequence < 1)
                throw new ArgumentOutOfRangeException(nameof(minimumCatalogSequence));
            if (minimumBundleVersion < 1)
                throw new ArgumentOutOfRangeException(nameof(minimumBundleVersion));
            if (!WebBundleSignature.IsSha256(acceptedDigestAtMinimumVersionSha256))
                throw new ArgumentException(
                    "A SHA-256 digest is required for the accepted bundle-version floor.",
                    nameof(acceptedDigestAtMinimumVersionSha256));

            CatalogId = WebPolicyIdentifier.Require(catalogId, 128, nameof(catalogId));
            BundleId = WebPolicyIdentifier.Require(bundleId, 128, nameof(bundleId));
            MinimumCatalogSequence = minimumCatalogSequence;
            MinimumBundleVersion = minimumBundleVersion;
            AcceptedDigestAtMinimumVersionSha256 =
                acceptedDigestAtMinimumVersionSha256.ToUpperInvariant();
        }

        public string CatalogId { get; }
        public string BundleId { get; }
        public long MinimumCatalogSequence { get; }
        public long MinimumBundleVersion { get; }
        public string AcceptedDigestAtMinimumVersionSha256 { get; }
    }

    public sealed class VerifiedWebServiceBundle
    {
        private VerifiedWebServiceBundle(WebServiceBundle bundle, WebBundleSignature signature) { Bundle = bundle; Signature = signature; }
        public WebServiceBundle Bundle { get; } public WebBundleSignature Signature { get; }
        public bool IsActiveAt(DateTimeOffset nowUtc) => Signature.IsActiveAt(nowUtc);
        public static VerifiedWebServiceBundle Verify(
            WebServiceBundle bundle,
            WebBundleSignature signature,
            IWebBundleSignatureVerifier verifier,
            WebBundleAcceptanceFloor acceptanceFloor,
            Version currentGuardVersion,
            DateTimeOffset nowUtc)
        {
            if (bundle == null) throw new ArgumentNullException(nameof(bundle));
            if (signature == null) throw new ArgumentNullException(nameof(signature));
            if (verifier == null) throw new ArgumentNullException(nameof(verifier));
            if (acceptanceFloor == null) throw new ArgumentNullException(nameof(acceptanceFloor));
            if (currentGuardVersion == null) throw new ArgumentNullException(nameof(currentGuardVersion));
            var bytes = bundle.CanonicalBytes();
            var digest = bundle.CanonicalDigestSha256();
            var signedBytes = CreateSignedBytes(signature, bytes);
            if (!string.Equals(digest, signature.DigestSha256, StringComparison.Ordinal) ||
                !string.Equals(
                    signature.CatalogId,
                    acceptanceFloor.CatalogId,
                    StringComparison.Ordinal) ||
                !string.Equals(
                    bundle.BundleId,
                    acceptanceFloor.BundleId,
                    StringComparison.Ordinal) ||
                signature.CatalogSequence <
                    acceptanceFloor.MinimumCatalogSequence ||
                signature.BundleVersion <
                    acceptanceFloor.MinimumBundleVersion ||
                signature.BundleVersion ==
                    acceptanceFloor.MinimumBundleVersion &&
                !string.Equals(
                    signature.DigestSha256,
                    acceptanceFloor.AcceptedDigestAtMinimumVersionSha256,
                    StringComparison.Ordinal) ||
                !signature.IsActiveAt(nowUtc) ||
                currentGuardVersion.CompareTo(
                    new Version(signature.MinimumGuardVersion)) < 0 ||
                !verifier.Verify(signature.SigningKeyId, signedBytes, signature.Signature))
                throw new InvalidOperationException("The service bundle signature or digest is not trusted.");
            return new VerifiedWebServiceBundle(bundle, signature);
        }

        private static byte[] CreateSignedBytes(
            WebBundleSignature signature,
            byte[] canonicalBundleBytes)
        {
            var prefix = Encoding.UTF8.GetBytes(
                "guard.web-bundle.v2\n" +
                "catalog=" + signature.CatalogId + "\n" +
                "catalogSequence=" +
                    signature.CatalogSequence.ToString(CultureInfo.InvariantCulture) + "\n" +
                "bundleVersion=" +
                    signature.BundleVersion.ToString(CultureInfo.InvariantCulture) + "\n" +
                "issuedUtcTicks=" +
                    signature.IssuedAtUtc.UtcDateTime.Ticks.ToString(CultureInfo.InvariantCulture) + "\n" +
                "expiresUtcTicks=" +
                    signature.ExpiresAtUtc.UtcDateTime.Ticks.ToString(CultureInfo.InvariantCulture) + "\n" +
                "minimumGuardVersion=" + signature.MinimumGuardVersion + "\n" +
                "signingKeyId=" + signature.SigningKeyId + "\n" +
                "digest=" + signature.DigestSha256 + "\n");
            var result = new byte[prefix.Length + canonicalBundleBytes.Length];
            Buffer.BlockCopy(prefix, 0, result, 0, prefix.Length);
            Buffer.BlockCopy(
                canonicalBundleBytes,
                0,
                result,
                prefix.Length,
                canonicalBundleBytes.Length);
            return result;
        }
    }

    public sealed class WebAccessGrant
    {
        public WebAccessGrant(string grantId, VerifiedWebServiceBundle bundle, ParentDecision decision)
        {
            GrantId = WebPolicyIdentifier.Require(grantId, 128, nameof(grantId));
            Bundle = bundle ?? throw new ArgumentNullException(nameof(bundle)); Decision = decision ?? throw new ArgumentNullException(nameof(decision));
        }
        public string GrantId { get; } public VerifiedWebServiceBundle Bundle { get; } public ParentDecision Decision { get; }
    }

    public sealed class TrustedDailyWebUsage
    {
        public TrustedDailyWebUsage(string grantId, int consumedMinutes, DateTimeOffset observedAt, DateTimeOffset validUntil)
        {
            if (consumedMinutes < 0 || validUntil <= observedAt || validUntil - observedAt > TimeSpan.FromMinutes(1))
                throw new ArgumentException("Daily web usage must be bounded and fresh.");
            GrantId = WebPolicyIdentifier.Require(grantId, 128, nameof(grantId));
            ConsumedMinutes = consumedMinutes; ObservedAt = observedAt; ValidUntil = validUntil;
        }
        public string GrantId { get; } public int ConsumedMinutes { get; } public DateTimeOffset ObservedAt { get; } public DateTimeOffset ValidUntil { get; }
        public bool IsCurrentAt(DateTimeOffset now) => now >= ObservedAt && now < ValidUntil;
    }

    public sealed class DefaultDenyWebPolicyPlan
    {
        internal DefaultDenyWebPolicyPlan(IReadOnlyList<WebAccessGrant> allowed, DateTimeOffset? nextReconcileAt) { AllowedGrants = allowed; NextReconcileAt = nextReconcileAt; }
        public bool IsDefaultDeny => true; public IReadOnlyList<WebAccessGrant> AllowedGrants { get; } public DateTimeOffset? NextReconcileAt { get; }
        public bool Allows(string host)
        {
            for (var grant = 0; grant < AllowedGrants.Count; grant++)
                for (var scope = 0; scope < AllowedGrants[grant].Bundle.Bundle.Scopes.Count; scope++)
                    if (AllowedGrants[grant].Bundle.Bundle.Scopes[scope].Matches(host)) return true;
            return false;
        }
    }

    public static class DefaultDenyWebPolicyCompiler
    {
        public static DefaultDenyWebPolicyPlan Compile(IEnumerable<WebAccessGrant> grants, IEnumerable<TrustedDailyWebUsage>? usage, DateTimeOffset now)
        {
            if (grants == null) throw new ArgumentNullException(nameof(grants));
            var usageByGrant = new Dictionary<string, TrustedDailyWebUsage>(StringComparer.Ordinal);
            var grantIds = new HashSet<string>(StringComparer.Ordinal);
            if (usage != null) foreach (var item in usage) { if (item == null || usageByGrant.ContainsKey(item.GrantId)) throw new ArgumentException("Usage states must be non-null and unique.", nameof(usage)); usageByGrant.Add(item.GrantId, item); }
            var allowed = new List<WebAccessGrant>(); DateTimeOffset? next = null;
            foreach (var grant in grants)
            {
                if (grant == null) throw new ArgumentException("Grants must be non-null.", nameof(grants));
                if (!grantIds.Add(grant.GrantId)) throw new ArgumentException("Grant identifiers must be unique.", nameof(grants));
                if (grant.Decision.Kind == ParentDecisionKind.Deny) continue;
                if (!grant.Bundle.IsActiveAt(now)) continue;
                next = Earlier(next, grant.Bundle.Signature.ExpiresAtUtc);
                if (grant.Decision.Kind == ParentDecisionKind.TemporaryAllow)
                {
                    if (!grant.Decision.IsEffectiveAt(now)) continue; next = Earlier(next, grant.Decision.ExpiresAt);
                }
                else if (grant.Decision.Kind == ParentDecisionKind.DailyQuota)
                {
                    if (!usageByGrant.TryGetValue(grant.GrantId, out var state) || !state.IsCurrentAt(now) || state.ConsumedMinutes >= grant.Decision.DailyQuotaMinutes!.Value) continue;
                    next = Earlier(next, state.ValidUntil);
                }
                allowed.Add(grant);
            }
            return new DefaultDenyWebPolicyPlan(allowed.AsReadOnly(), next);
        }
        private static DateTimeOffset? Earlier(DateTimeOffset? current, DateTimeOffset? candidate) => !candidate.HasValue || current.HasValue && current.Value <= candidate.Value ? current : candidate;
    }

    public sealed class UntrustedBrowserWebObservation { public UntrustedBrowserWebObservation(string host) { Host = host ?? throw new ArgumentNullException(nameof(host)); } public string Host { get; } }
    public interface IWebConnectionEvidenceVerifier { bool Verify(CanonicalDnsHost host, string connectionBinding); }
    public sealed class VerifiedWebConnection
    {
        private VerifiedWebConnection(CanonicalDnsHost host) { Host = host; }
        public CanonicalDnsHost Host { get; }
        public static VerifiedWebConnection Verify(UntrustedBrowserWebObservation observation, string connectionBinding, IWebConnectionEvidenceVerifier verifier)
        {
            if (observation == null) throw new ArgumentNullException(nameof(observation));
            if (verifier == null) throw new ArgumentNullException(nameof(verifier));
            connectionBinding = WebPolicyIdentifier.Require(
                connectionBinding,
                128,
                nameof(connectionBinding));
            var host = CanonicalDnsHost.Parse(observation.Host);
            if (!verifier.Verify(host, connectionBinding)) throw new InvalidOperationException("Browser-supplied host identity was not independently verified.");
            return new VerifiedWebConnection(host);
        }
    }
    public sealed class WebAccessCandidate { internal WebAccessCandidate(CanonicalDnsHost host) { Host = host; } public CanonicalDnsHost Host { get; } public bool RequiresParentApproval => true; }
    public static class WebAccessCandidateDiscovery
    {
        public static WebAccessCandidate Discover(VerifiedWebConnection verifiedConnection)
        {
            if (verifiedConnection == null) throw new ArgumentNullException(nameof(verifiedConnection));
            return new WebAccessCandidate(verifiedConnection.Host);
        }
    }

    internal static class WebPolicyIdentifier
    {
        public static string Require(
            string value,
            int maximumCharacters,
            string parameterName)
        {
            if (string.IsNullOrWhiteSpace(value) ||
                value.Length > maximumCharacters ||
                !string.Equals(value, value.Trim(), StringComparison.Ordinal))
                throw new ArgumentException(
                    "A bounded canonical identifier is required.",
                    parameterName);

            for (var index = 0; index < value.Length; index++)
            {
                var character = value[index];
                if (!((character >= 'a' && character <= 'z') ||
                      (character >= 'A' && character <= 'Z') ||
                      (character >= '0' && character <= '9') ||
                      character == '-' || character == '_' ||
                      character == '.' || character == ':'))
                    throw new ArgumentException(
                        "The identifier contains unsafe characters.",
                        parameterName);
            }

            return value;
        }
    }
}
