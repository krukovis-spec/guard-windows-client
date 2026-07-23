using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Text;

namespace Guard.Domain.Policy
{
    public enum SecureInstallRoot
    {
        ProgramFiles64 = 1,
        ProgramFiles32 = 2,
        WindowsApps = 3,
        WindowsSystem = 4
    }

    public sealed class ApplicationIdentity : IEquatable<ApplicationIdentity>
    {
        private const int MaximumTextLength = 256;
        private readonly string? _publisher;
        private readonly string? _product;
        private readonly SecureInstallRoot? _secureInstallRoot;
        private readonly string? _fileSha256;

        public ApplicationIdentity(string? publisher, string? product, SecureInstallRoot? secureInstallRoot, string? fileSha256)
        {
            _publisher = NormalizeOptionalText(publisher, nameof(publisher));
            _product = NormalizeOptionalText(product, nameof(product));
            _secureInstallRoot = secureInstallRoot;
            _fileSha256 = NormalizeOptionalSha256(fileSha256, nameof(fileSha256));

            var signedParts = (_publisher != null ? 1 : 0) + (_product != null ? 1 : 0) + (_secureInstallRoot.HasValue ? 1 : 0);
            if (signedParts != 0 && signedParts != 3)
            {
                throw new ArgumentException("Publisher authorization requires publisher, product, and secure root together.");
            }

            if (_secureInstallRoot.HasValue && !Enum.IsDefined(typeof(SecureInstallRoot), _secureInstallRoot.Value))
            {
                throw new ArgumentOutOfRangeException(nameof(secureInstallRoot));
            }

            if (signedParts == 3 && _fileSha256 != null)
            {
                throw new ArgumentException("Publisher identity and SHA-256 fallback are separate authorization modes.");
            }

            if (signedParts == 0 && _fileSha256 == null)
            {
                throw new ArgumentException("A signed identity or a SHA-256 fallback is required.");
            }
        }

        public string? Publisher => _publisher;

        public string? Product => _product;

        public SecureInstallRoot? SecureInstallRoot => _secureInstallRoot;

        public string? FileSha256 => _fileSha256;

        public bool HasSignedPublisherIdentity => _publisher != null;

        public bool HasFileHashFallback => _fileSha256 != null;

        public string AuthorizationKey
        {
            get
            {
                if (HasSignedPublisherIdentity)
                {
                    return "signed:" + EncodeAuthorizationPart(_publisher!) + EncodeAuthorizationPart(_product!) + EncodeAuthorizationPart(((int)_secureInstallRoot!.Value).ToString(CultureInfo.InvariantCulture));
                }

                return "sha256:" + _fileSha256;
            }
        }

        public bool Authorizes(ApplicationIdentity candidate)
        {
            if (candidate == null)
            {
                return false;
            }

            return (HasSignedPublisherIdentity && candidate.HasSignedPublisherIdentity &&
                    string.Equals(_publisher, candidate._publisher, StringComparison.Ordinal) &&
                    string.Equals(_product, candidate._product, StringComparison.Ordinal) &&
                    _secureInstallRoot == candidate._secureInstallRoot) ||
                   (HasFileHashFallback && candidate.HasFileHashFallback &&
                    string.Equals(_fileSha256, candidate._fileSha256, StringComparison.Ordinal));
        }

        public bool Equals(ApplicationIdentity? other)
        {
            return other != null && string.Equals(AuthorizationKey, other.AuthorizationKey, StringComparison.Ordinal);
        }

        public override bool Equals(object? obj) => Equals(obj as ApplicationIdentity);

        public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(AuthorizationKey);

        private static string EncodeAuthorizationPart(string value)
        {
            return value.Length.ToString(CultureInfo.InvariantCulture) + ":" + value;
        }

        private static string? NormalizeOptionalText(string? value, string parameterName)
        {
            if (value == null)
            {
                return null;
            }

            value = value.Trim();
            if (value.Length == 0 || value.Length > MaximumTextLength)
            {
                throw new ArgumentException("Identity text must be non-blank and bounded.", parameterName);
            }

            return value;
        }

        private static string? NormalizeOptionalSha256(string? value, string parameterName)
        {
            if (value == null)
            {
                return null;
            }

            value = value.Trim();
            if (value.Length != 64)
            {
                throw new ArgumentException("A SHA-256 value must contain exactly 64 hexadecimal characters.", parameterName);
            }

            for (var index = 0; index < value.Length; index++)
            {
                var character = value[index];
                if (!((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') || (character >= 'A' && character <= 'F')))
                {
                    throw new ArgumentException("A SHA-256 value must be hexadecimal.", parameterName);
                }
            }

            return value.ToUpperInvariant();
        }
    }

    public sealed class DomainRule
    {
        public DomainRule(string domain, bool includeSubdomains)
        {
            Domain = DomainName.Normalize(domain);
            IncludeSubdomains = includeSubdomains;
        }

        public string Domain { get; }

        public bool IncludeSubdomains { get; }

        public bool Matches(string host)
        {
            var normalizedHost = DomainName.Normalize(host);
            return string.Equals(Domain, normalizedHost, StringComparison.Ordinal) ||
                   IncludeSubdomains && normalizedHost.Length > Domain.Length &&
                   normalizedHost.EndsWith("." + Domain, StringComparison.Ordinal);
        }
    }

    public sealed class ServiceBundle
    {
        private readonly DomainRule[] _rules;

        public ServiceBundle(string bundleId, IEnumerable<DomainRule> rules)
        {
            if (string.IsNullOrWhiteSpace(bundleId) || bundleId.Trim().Length > 128)
            {
                throw new ArgumentException("A bounded bundle id is required.", nameof(bundleId));
            }

            if (rules == null)
            {
                throw new ArgumentNullException(nameof(rules));
            }

            BundleId = bundleId.Trim();
            var copied = new List<DomainRule>();
            foreach (var rule in rules)
            {
                if (rule == null)
                {
                    throw new ArgumentException("Service bundles cannot contain null rules.", nameof(rules));
                }

                copied.Add(rule);
            }

            if (copied.Count == 0)
            {
                throw new ArgumentException("A service bundle needs at least one domain rule.", nameof(rules));
            }

            _rules = copied.ToArray();
        }

        public string BundleId { get; }

        public IReadOnlyList<DomainRule> Rules => Array.AsReadOnly((DomainRule[])_rules.Clone());

        public bool Matches(string host)
        {
            for (var index = 0; index < _rules.Length; index++)
            {
                if (_rules[index].Matches(host))
                {
                    return true;
                }
            }

            return false;
        }
    }

    public static class DomainName
    {
        public static string Normalize(string host)
        {
            if (string.IsNullOrWhiteSpace(host))
            {
                throw new ArgumentException("A domain name is required.", nameof(host));
            }

            host = host.Trim().TrimEnd('.');
            if (host.Length == 0 || host.Length > 253 || host.IndexOf("//", StringComparison.Ordinal) >= 0 || host.IndexOf('/') >= 0 || host.IndexOf(':') >= 0 || host.IndexOf('@') >= 0)
            {
                throw new ArgumentException("Only a DNS host name is allowed.", nameof(host));
            }

            IPAddress parsedAddress;
            if (IPAddress.TryParse(host, out parsedAddress))
            {
                throw new ArgumentException("IP literals require a separate explicit policy.", nameof(host));
            }

            var labels = host.Split('.');
            if (labels.Length < 2)
            {
                throw new ArgumentException("A domain name must contain at least two labels; public-suffix interpretation is intentionally not performed.", nameof(host));
            }

            var idn = new IdnMapping();
            var normalized = new StringBuilder(host.Length);
            for (var index = 0; index < labels.Length; index++)
            {
                var label = idn.GetAscii(labels[index]);
                if (label.Length == 0 || label.Length > 63)
                {
                    throw new ArgumentException("Domain labels must be non-empty and at most 63 characters.", nameof(host));
                }

                for (var characterIndex = 0; characterIndex < label.Length; characterIndex++)
                {
                    var character = label[characterIndex];
                    if (!((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-'))
                    {
                        throw new ArgumentException("Domain labels may contain only DNS label characters.", nameof(host));
                    }
                }

                if (label[0] == '-' || label[label.Length - 1] == '-')
                {
                    throw new ArgumentException("Domain labels cannot start or end with a hyphen.", nameof(host));
                }

                if (index > 0)
                {
                    normalized.Append('.');
                }

                normalized.Append(label.ToLowerInvariant());
            }

            return normalized.ToString();
        }
    }

    public enum AccessTargetKind
    {
        Application = 1,
        Site = 2
    }

    public sealed class AccessRequestKey : IEquatable<AccessRequestKey>
    {
        private AccessRequestKey(string deviceId, AccessTargetKind targetKind, string targetIdentity)
        {
            DeviceId = RequireIdentifier(deviceId, nameof(deviceId));
            TargetKind = targetKind;
            TargetIdentity = RequireIdentifier(targetIdentity, nameof(targetIdentity));
        }

        public string DeviceId { get; }

        public AccessTargetKind TargetKind { get; }

        public string TargetIdentity { get; }

        public static AccessRequestKey ForApplication(string deviceId, ApplicationIdentity application)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            return new AccessRequestKey(deviceId, AccessTargetKind.Application, application.AuthorizationKey);
        }

        public static AccessRequestKey ForSite(string deviceId, string domain)
        {
            return new AccessRequestKey(deviceId, AccessTargetKind.Site, DomainName.Normalize(domain));
        }

        public bool Equals(AccessRequestKey? other)
        {
            return other != null && TargetKind == other.TargetKind &&
                   string.Equals(DeviceId, other.DeviceId, StringComparison.Ordinal) &&
                   string.Equals(TargetIdentity, other.TargetIdentity, StringComparison.Ordinal);
        }

        public override bool Equals(object? obj) => Equals(obj as AccessRequestKey);

        public override int GetHashCode()
        {
            var hash = StringComparer.Ordinal.GetHashCode(DeviceId);
            hash = (hash * 397) ^ (int)TargetKind;
            return (hash * 397) ^ StringComparer.Ordinal.GetHashCode(TargetIdentity);
        }

        private static string RequireIdentifier(string value, string parameterName)
        {
            if (string.IsNullOrWhiteSpace(value) || value.Trim().Length > 1024)
            {
                throw new ArgumentException("A bounded identifier is required.", parameterName);
            }

            return value.Trim();
        }
    }

    public enum ParentDecisionKind
    {
        AlwaysAllow = 1,
        TemporaryAllow = 2,
        DailyQuota = 3,
        Deny = 4
    }

    public sealed class ParentDecision
    {
        public ParentDecision(ParentDecisionKind kind, DateTimeOffset? expiresAt = null, int? dailyQuotaMinutes = null)
        {
            if (!Enum.IsDefined(typeof(ParentDecisionKind), kind))
            {
                throw new ArgumentOutOfRangeException(nameof(kind));
            }

            if (kind == ParentDecisionKind.TemporaryAllow)
            {
                if (!expiresAt.HasValue || dailyQuotaMinutes.HasValue)
                {
                    throw new ArgumentException("A temporary decision requires only an expiry.");
                }
            }
            else if (kind == ParentDecisionKind.DailyQuota)
            {
                if (expiresAt.HasValue || !dailyQuotaMinutes.HasValue || dailyQuotaMinutes.Value < 1 || dailyQuotaMinutes.Value > 1440)
                {
                    throw new ArgumentException("A daily quota decision requires 1 to 1440 minutes and no expiry.");
                }
            }
            else if (expiresAt.HasValue || dailyQuotaMinutes.HasValue)
            {
                throw new ArgumentException("Always-allow and deny decisions cannot carry duration or quota.");
            }

            Kind = kind;
            ExpiresAt = expiresAt;
            DailyQuotaMinutes = dailyQuotaMinutes;
        }

        public ParentDecisionKind Kind { get; }

        public DateTimeOffset? ExpiresAt { get; }

        public int? DailyQuotaMinutes { get; }

        public bool IsEffectiveAt(DateTimeOffset now)
        {
            return Kind != ParentDecisionKind.Deny && (!ExpiresAt.HasValue || now < ExpiresAt.Value);
        }
    }

    [Flags]
    public enum MaintenanceCapability
    {
        None = 0,
        ApplicationPolicy = 1,
        WebPolicy = 2,
        NetworkProxy = 4,
        UpdateInstallation = 8
    }

    public sealed class MaintenanceLease
    {
        public MaintenanceLease(
            string deviceId,
            string leaseId,
            MaintenanceCapability capabilities,
            DateTimeOffset issuedAt,
            DateTimeOffset expiresAt)
        {
            DeviceId = RequireLeaseIdentifier(deviceId, nameof(deviceId));
            LeaseId = RequireLeaseIdentifier(leaseId, nameof(leaseId));
            if (capabilities == MaintenanceCapability.None || ((int)capabilities & ~(int)(MaintenanceCapability.ApplicationPolicy | MaintenanceCapability.WebPolicy | MaintenanceCapability.NetworkProxy | MaintenanceCapability.UpdateInstallation)) != 0)
            {
                throw new ArgumentOutOfRangeException(nameof(capabilities));
            }

            var lifetime = expiresAt - issuedAt;
            if (lifetime != TimeSpan.FromMinutes(15) &&
                lifetime != TimeSpan.FromMinutes(30) &&
                lifetime != TimeSpan.FromMinutes(60))
            {
                throw new ArgumentOutOfRangeException(nameof(expiresAt), "Maintenance must be limited to 15, 30, or 60 minutes.");
            }

            Capabilities = capabilities;
            IssuedAt = issuedAt;
            ExpiresAt = expiresAt;
        }

        public string DeviceId { get; }

        public string LeaseId { get; }

        public MaintenanceCapability Capabilities { get; }

        public DateTimeOffset IssuedAt { get; }

        public DateTimeOffset ExpiresAt { get; }

        public bool Allows(string deviceId, MaintenanceCapability capability, DateTimeOffset now)
        {
            return now >= IssuedAt && now < ExpiresAt && string.Equals(DeviceId, deviceId, StringComparison.Ordinal) &&
                   capability != MaintenanceCapability.None && (Capabilities & capability) == capability;
        }

        private static string RequireLeaseIdentifier(string value, string parameterName)
        {
            if (string.IsNullOrWhiteSpace(value) || value.Trim().Length > 128)
            {
                throw new ArgumentException("A bounded lease identifier is required.", parameterName);
            }

            return value.Trim();
        }
    }
}
