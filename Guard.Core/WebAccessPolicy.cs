using System;
using System.Collections.Generic;
using System.Linq;

namespace Guard
{
    public sealed class WebAccessSettings
    {
        public bool DefaultDenyEnabled { get; set; } = true;
    }

    public static class WebsiteAccessPolicy
    {
        public const string DefaultDenyRulePrefix = "default-deny-site:";

        public static bool IsDefaultDenyActive(GuardState state, DateTime utcNow)
        {
            if (state == null)
            {
                return false;
            }

            EnsureSettings(state);
            return state.SyncStatus &&
                state.WebAccess.DefaultDenyEnabled &&
                (state.MaintenanceMode == null ||
                 !state.MaintenanceMode.IsActive ||
                 (state.MaintenanceMode.UntilUtc.HasValue && state.MaintenanceMode.UntilUtc.Value <= utcNow));
        }

        public static bool IsWebsiteAllowed(GuardState state, string domainInput, DateTime utcNow)
        {
            return DomainAccessGrantApplier.IsDomainAllowed(state, domainInput, utcNow);
        }

        public static bool ShouldBlockWebsite(GuardState state, string domainInput, DateTime utcNow)
        {
            var domain = DomainAccessGrantApplier.NormalizeDomainInput(domainInput);
            return IsDefaultDenyActive(state, utcNow) &&
                DomainAccessGrantApplier.IsValidWebsiteDomain(domain) &&
                !IsWebsiteAllowed(state, domain, utcNow);
        }

        public static ParentCommandResult EnsureDefaultDeniedDomainRule(GuardState state, string domainInput)
        {
            if (state == null) throw new ArgumentNullException(nameof(state));
            EnsureSettings(state);

            var domain = DomainAccessGrantApplier.NormalizeDomainInput(domainInput);
            if (!DomainAccessGrantApplier.IsValidWebsiteDomain(domain))
            {
                return new ParentCommandResult { Error = "Invalid domain." };
            }

            var ruleId = BuildDefaultDenyRuleId(domain);
            if (state.Rules.Any(rule => string.Equals(rule.Id, ruleId, StringComparison.OrdinalIgnoreCase)))
            {
                return new ParentCommandResult { Changed = false };
            }

            state.Rules.Add(new InstructionRule
            {
                Id = ruleId,
                Type = "custom_url",
                Value = domain,
                Schedule = ParentCommandApplier.AlwaysOnSchedule
            });

            state.UpdateInfo.Rules = true;
            state.UpdateInfo.UpdateApplied = false;
            return new ParentCommandResult { Changed = true };
        }

        public static string BuildDefaultDenyRuleId(string domainInput)
        {
            return DefaultDenyRulePrefix + DomainAccessGrantApplier.NormalizeDomainInput(domainInput);
        }

        private static void EnsureSettings(GuardState state)
        {
            if (state.WebAccess == null)
            {
                state.WebAccess = new WebAccessSettings();
            }

            if (state.Rules == null)
            {
                state.Rules = new List<InstructionRule>();
            }

            if (state.UpdateInfo == null)
            {
                state.UpdateInfo = new UpdateFor();
            }
        }
    }
}
