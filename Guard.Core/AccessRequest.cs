using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Guard
{
    public enum AccessRequestType
    {
        Application = 0,
        Website = 1
    }

    public enum AccessRequestStatus
    {
        Pending = 0,
        Approved = 1,
        Denied = 2
    }

    public class AccessRequest
    {
        public string Id { get; set; } = "";
        public AccessRequestType Type { get; set; } = AccessRequestType.Application;
        public AccessRequestStatus Status { get; set; } = AccessRequestStatus.Pending;
        public string DisplayName { get; set; } = "";
        public string Target { get; set; } = "";
        public string Source { get; set; } = "";
        public string RequestedBy { get; set; } = "";
        public DateTime RequestedAtUtc { get; set; } = DateTime.UtcNow;
        public DateTime LastSeenUtc { get; set; } = DateTime.UtcNow;
        public int AttemptCount { get; set; } = 1;
        public DateTime? DecidedAtUtc { get; set; }
        public string Decision { get; set; } = "";
        public int? DecisionMinutes { get; set; }
    }

    public static class AccessRequestApplier
    {
        public static ParentCommandResult RequestApplication(
            GuardState state,
            string filePath,
            string displayName,
            string source,
            string requestedBy,
            DateTime utcNow)
        {
            if (state == null) throw new ArgumentNullException(nameof(state));
            EnsureRequests(state);

            var normalized = ApplicationControlApplier.NormalizeExecutablePath(filePath);
            if (normalized == null)
            {
                return new ParentCommandResult { Error = "Invalid application path." };
            }

            var id = BuildApplicationRequestId(normalized);
            var name = InputSanitizer.SanitizeString(displayName, 80);
            if (string.IsNullOrWhiteSpace(name))
            {
                name = Path.GetFileNameWithoutExtension(normalized);
            }

            var existing = state.AccessRequests.FirstOrDefault(request => request.Id == id);
            if (existing == null)
            {
                state.AccessRequests.Add(new AccessRequest
                {
                    Id = id,
                    Type = AccessRequestType.Application,
                    Status = AccessRequestStatus.Pending,
                    DisplayName = name,
                    Target = normalized,
                    Source = InputSanitizer.SanitizeString(source, 80),
                    RequestedBy = InputSanitizer.SanitizeString(requestedBy, 80),
                    RequestedAtUtc = utcNow,
                    LastSeenUtc = utcNow,
                    AttemptCount = 1
                });
                return new ParentCommandResult { Changed = true };
            }

            existing.DisplayName = name;
            existing.Target = normalized;
            existing.Source = InputSanitizer.SanitizeString(source, 80);
            existing.RequestedBy = InputSanitizer.SanitizeString(requestedBy, 80);
            existing.LastSeenUtc = utcNow;
            existing.AttemptCount = Math.Max(1, existing.AttemptCount + 1);
            if (existing.Status != AccessRequestStatus.Pending)
            {
                existing.Status = AccessRequestStatus.Pending;
                existing.DecidedAtUtc = null;
                existing.Decision = "";
                existing.DecisionMinutes = null;
            }

            return new ParentCommandResult { Changed = true };
        }

        public static ParentCommandResult RequestWebsite(
            GuardState state,
            string domainInput,
            string source,
            string requestedBy,
            DateTime utcNow)
        {
            if (state == null) throw new ArgumentNullException(nameof(state));
            EnsureRequests(state);

            var domain = DomainAccessGrantApplier.NormalizeDomainInput(domainInput);
            if (!DomainAccessGrantApplier.IsValidWebsiteDomain(domain))
            {
                return new ParentCommandResult { Error = "Invalid domain." };
            }

            if (WebsiteAccessPolicy.IsDefaultDenyActive(state, utcNow))
            {
                var blockResult = WebsiteAccessPolicy.EnsureDefaultDeniedDomainRule(state, domain);
                if (!string.IsNullOrEmpty(blockResult.Error))
                {
                    return blockResult;
                }
            }

            var id = BuildWebsiteRequestId(domain);
            var existing = state.AccessRequests.FirstOrDefault(request => request.Id == id);
            if (existing == null)
            {
                state.AccessRequests.Add(new AccessRequest
                {
                    Id = id,
                    Type = AccessRequestType.Website,
                    Status = AccessRequestStatus.Pending,
                    DisplayName = domain,
                    Target = domain,
                    Source = InputSanitizer.SanitizeString(source, 80),
                    RequestedBy = InputSanitizer.SanitizeString(requestedBy, 80),
                    RequestedAtUtc = utcNow,
                    LastSeenUtc = utcNow,
                    AttemptCount = 1
                });
                return new ParentCommandResult { Changed = true };
            }

            existing.Type = AccessRequestType.Website;
            existing.DisplayName = domain;
            existing.Target = domain;
            existing.Source = InputSanitizer.SanitizeString(source, 80);
            existing.RequestedBy = InputSanitizer.SanitizeString(requestedBy, 80);
            existing.LastSeenUtc = utcNow;
            existing.AttemptCount = Math.Max(1, existing.AttemptCount + 1);
            if (existing.Status != AccessRequestStatus.Pending)
            {
                existing.Status = AccessRequestStatus.Pending;
                existing.DecidedAtUtc = null;
                existing.Decision = "";
                existing.DecisionMinutes = null;
            }

            return new ParentCommandResult { Changed = true };
        }

        public static ParentCommandResult ApproveRequest(
            GuardState state,
            string requestId,
            int? minutes,
            DateTime utcNow)
        {
            if (state == null) throw new ArgumentNullException(nameof(state));
            EnsureRequests(state);

            var request = state.AccessRequests.FirstOrDefault(item =>
                item.Id == (requestId ?? "") &&
                item.Status == AccessRequestStatus.Pending);
            if (request == null)
            {
                return new ParentCommandResult { Error = "Pending access request was not found." };
            }

            if (request.Type == AccessRequestType.Application)
            {
                return ApproveApplication(state, requestId, minutes, utcNow);
            }

            var siteResult = DomainAccessGrantApplier.GrantWebsite(
                state,
                request.Target,
                request.DisplayName,
                minutes,
                request.Id,
                utcNow);
            if (!string.IsNullOrEmpty(siteResult.Error))
            {
                return siteResult;
            }

            request.Status = AccessRequestStatus.Approved;
            request.DecidedAtUtc = utcNow;
            request.Decision = minutes.HasValue ? "temporary" : "always";
            request.DecisionMinutes = minutes;
            return new ParentCommandResult { Changed = true };
        }

        public static ParentCommandResult ApproveApplication(
            GuardState state,
            string requestId,
            int? minutes,
            DateTime utcNow)
        {
            if (state == null) throw new ArgumentNullException(nameof(state));
            EnsureRequests(state);

            var request = FindPendingApplicationRequest(state, requestId);
            if (request == null)
            {
                return new ParentCommandResult { Error = "Pending application request was not found." };
            }

            ParentCommandResult appResult;
            if (minutes.HasValue)
            {
                appResult = ApplicationControlApplier.GrantTemporaryApplication(
                    state,
                    request.Target,
                    request.DisplayName,
                    minutes.Value,
                    utcNow);
            }
            else
            {
                appResult = ApplicationControlApplier.AddPermanentApplication(
                    state,
                    request.Target,
                    request.DisplayName,
                    utcNow);
            }

            if (!string.IsNullOrEmpty(appResult.Error))
            {
                return appResult;
            }

            request.Status = AccessRequestStatus.Approved;
            request.DecidedAtUtc = utcNow;
            request.Decision = minutes.HasValue ? "temporary" : "always";
            request.DecisionMinutes = minutes;
            return new ParentCommandResult { Changed = true };
        }

        public static ParentCommandResult DenyRequest(GuardState state, string requestId, DateTime utcNow)
        {
            if (state == null) throw new ArgumentNullException(nameof(state));
            EnsureRequests(state);

            var request = state.AccessRequests.FirstOrDefault(item => item.Id == (requestId ?? ""));
            if (request == null || request.Status != AccessRequestStatus.Pending)
            {
                return new ParentCommandResult { Error = "Pending access request was not found." };
            }

            request.Status = AccessRequestStatus.Denied;
            request.DecidedAtUtc = utcNow;
            request.Decision = "denied";
            request.DecisionMinutes = null;
            return new ParentCommandResult { Changed = true };
        }

        public static IReadOnlyList<AccessRequest> GetPendingRequests(GuardState state)
        {
            if (state == null || state.AccessRequests == null)
            {
                return Array.Empty<AccessRequest>();
            }

            return state.AccessRequests
                .Where(request => request.Status == AccessRequestStatus.Pending)
                .OrderByDescending(request => request.LastSeenUtc)
                .ToList();
        }

        public static string BuildApplicationRequestId(string filePath)
        {
            return "request:" + ApplicationControlApplier.BuildApplicationId(filePath);
        }

        public static string BuildWebsiteRequestId(string domainInput)
        {
            return "request:site:" + DomainAccessGrantApplier.NormalizeDomainInput(domainInput);
        }

        private static AccessRequest? FindPendingApplicationRequest(GuardState state, string requestId)
        {
            return state.AccessRequests.FirstOrDefault(request =>
                request.Id == (requestId ?? "") &&
                request.Type == AccessRequestType.Application &&
                request.Status == AccessRequestStatus.Pending);
        }

        private static void EnsureRequests(GuardState state)
        {
            if (state.AccessRequests == null)
            {
                state.AccessRequests = new List<AccessRequest>();
            }
        }
    }
}
