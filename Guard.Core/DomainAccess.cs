using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace Guard
{
    public class DomainAccessGrant
    {
        public string Domain { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public bool IsPermanent { get; set; }
        public DateTime? AllowedUntilUtc { get; set; }
        public DateTime AddedAtUtc { get; set; } = DateTime.UtcNow;
        public string SourceRequestId { get; set; } = "";
    }

    public static class DomainAccessGrantApplier
    {
        private static readonly string[] FriendlyPrefixes = { "www.", "m." };

        public static ParentCommandResult GrantWebsite(
            GuardState state,
            string domainInput,
            string displayName,
            int? minutes,
            string sourceRequestId,
            DateTime utcNow)
        {
            if (state == null) throw new ArgumentNullException(nameof(state));
            EnsureGrants(state);

            var domain = NormalizeDomainInput(domainInput);
            if (!IsValidWebsiteDomain(domain))
            {
                return new ParentCommandResult { Error = "Invalid domain." };
            }

            if (minutes.HasValue && (minutes.Value < 1 || minutes.Value > 1440))
            {
                return new ParentCommandResult { Error = "Website access time must be from 1 to 1440 minutes." };
            }

            var grant = state.DomainAccessGrants.FirstOrDefault(item =>
                string.Equals(item.Domain, domain, StringComparison.OrdinalIgnoreCase));
            var until = minutes.HasValue ? utcNow.AddMinutes(minutes.Value) : (DateTime?)null;
            var name = InputSanitizer.SanitizeString(displayName, 80);
            if (string.IsNullOrWhiteSpace(name))
            {
                name = domain;
            }

            if (grant == null)
            {
                state.DomainAccessGrants.Add(new DomainAccessGrant
                {
                    Domain = domain,
                    DisplayName = name,
                    IsPermanent = !minutes.HasValue,
                    AllowedUntilUtc = until,
                    AddedAtUtc = utcNow,
                    SourceRequestId = InputSanitizer.SanitizeString(sourceRequestId, 120)
                });
                MarkDomainPolicyChanged(state);
                return new ParentCommandResult { Changed = true };
            }

            var changed =
                !string.Equals(grant.DisplayName, name, StringComparison.Ordinal) ||
                grant.IsPermanent == minutes.HasValue ||
                grant.AllowedUntilUtc != until ||
                !string.Equals(grant.SourceRequestId, sourceRequestId ?? "", StringComparison.Ordinal);

            grant.DisplayName = name;
            grant.IsPermanent = !minutes.HasValue;
            grant.AllowedUntilUtc = until;
            grant.AddedAtUtc = utcNow;
            grant.SourceRequestId = InputSanitizer.SanitizeString(sourceRequestId, 120);

            if (changed)
            {
                MarkDomainPolicyChanged(state);
            }

            return new ParentCommandResult { Changed = changed };
        }

        public static ParentCommandResult RemoveWebsiteGrant(GuardState state, string domainInput)
        {
            if (state == null) throw new ArgumentNullException(nameof(state));
            EnsureGrants(state);

            var domain = NormalizeDomainInput(domainInput);
            if (!IsValidWebsiteDomain(domain))
            {
                return new ParentCommandResult { Error = "Invalid domain." };
            }

            var removed = state.DomainAccessGrants.RemoveAll(item =>
                string.Equals(item.Domain, domain, StringComparison.OrdinalIgnoreCase));
            if (removed == 0)
            {
                return new ParentCommandResult { Changed = false };
            }

            MarkDomainPolicyChanged(state);
            return new ParentCommandResult { Changed = true };
        }

        public static ParentCommandResult RemoveExpiredTemporaryGrants(GuardState state, DateTime utcNow)
        {
            if (state == null) throw new ArgumentNullException(nameof(state));
            EnsureGrants(state);

            var removed = state.DomainAccessGrants.RemoveAll(item =>
                !item.IsPermanent &&
                item.AllowedUntilUtc.HasValue &&
                item.AllowedUntilUtc.Value <= utcNow);
            if (removed == 0)
            {
                return new ParentCommandResult { Changed = false };
            }

            MarkDomainPolicyChanged(state);
            return new ParentCommandResult { Changed = true };
        }

        public static IReadOnlyList<DomainAccessGrant> GetActiveGrants(GuardState state, DateTime utcNow)
        {
            if (state == null || state.DomainAccessGrants == null)
            {
                return Array.Empty<DomainAccessGrant>();
            }

            return state.DomainAccessGrants
                .Where(grant => IsActive(grant, utcNow))
                .OrderBy(grant => grant.Domain)
                .ToList();
        }

        public static List<string> FilterBlockedDomains(IEnumerable<string> domains, GuardState state, DateTime utcNow)
        {
            var activeGrants = GetActiveGrants(state, utcNow);
            return (domains ?? Enumerable.Empty<string>())
                .Where(domain => !string.IsNullOrWhiteSpace(domain))
                .Select(NormalizeDomainInput)
                .Where(IsValidWebsiteDomain)
                .Where(domain => !activeGrants.Any(grant =>
                    DomainMatchesGrant(domain, grant.Domain) &&
                    TimeLimitEngine.IsWebsiteAllowedByTimeLimits(state, grant.Domain, utcNow)))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        public static bool IsDomainAllowed(GuardState state, string domainInput, DateTime utcNow)
        {
            var domain = NormalizeDomainInput(domainInput);
            if (!IsValidWebsiteDomain(domain))
            {
                return false;
            }

            return GetActiveGrants(state, utcNow).Any(grant =>
                DomainMatchesGrant(domain, grant.Domain) &&
                TimeLimitEngine.IsWebsiteAllowedByTimeLimits(state, grant.Domain, utcNow));
        }

        public static bool IsValidWebsiteDomain(string domainInput)
        {
            var domain = NormalizeDomainInput(domainInput);
            return InputSanitizer.IsValidDomainName(domain) &&
                domain.Contains(".") &&
                !IPAddress.TryParse(domain, out _);
        }

        public static string NormalizeDomainInput(string? input)
        {
            var value = (input ?? "").Trim().ToLowerInvariant();
            if (value.Length == 0)
            {
                return "";
            }

            if (Uri.TryCreate(value, UriKind.Absolute, out var uri) &&
                (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps))
            {
                value = uri.Host;
            }
            else
            {
                var slash = value.IndexOf('/');
                if (slash >= 0) value = value.Substring(0, slash);
                var query = value.IndexOf('?');
                if (query >= 0) value = value.Substring(0, query);
                var hash = value.IndexOf('#');
                if (hash >= 0) value = value.Substring(0, hash);
            }

            value = value.Trim().TrimEnd('.');
            if (value.StartsWith("*."))
            {
                value = value.Substring(2);
            }

            var colon = value.LastIndexOf(':');
            if (colon > -1 && value.IndexOf(':') == colon)
            {
                value = value.Substring(0, colon);
            }

            foreach (var prefix in FriendlyPrefixes)
            {
                if (value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) && value.Length > prefix.Length)
                {
                    value = value.Substring(prefix.Length);
                    break;
                }
            }

            return value;
        }

        private static bool IsActive(DomainAccessGrant grant, DateTime utcNow)
        {
            return grant != null &&
                !string.IsNullOrWhiteSpace(grant.Domain) &&
                (grant.IsPermanent || !grant.AllowedUntilUtc.HasValue || grant.AllowedUntilUtc.Value > utcNow);
        }

        private static bool DomainMatchesGrant(string domain, string grantDomain)
        {
            return string.Equals(domain, grantDomain, StringComparison.OrdinalIgnoreCase) ||
                domain.EndsWith("." + grantDomain, StringComparison.OrdinalIgnoreCase);
        }

        private static void EnsureGrants(GuardState state)
        {
            if (state.DomainAccessGrants == null)
            {
                state.DomainAccessGrants = new List<DomainAccessGrant>();
            }
        }

        private static void MarkDomainPolicyChanged(GuardState state)
        {
            state.UpdateInfo.Rules = true;
            state.UpdateInfo.Cats = true;
            state.UpdateInfo.UpdateApplied = false;
        }
    }
}
