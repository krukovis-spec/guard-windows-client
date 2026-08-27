using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Guard
{
    public enum ActivityCategory
    {
        Uncategorized = 0,
        Study = 1,
        Video = 2,
        Game = 3,
        UsefulTraining = 4,
        Communication = 5,
        System = 6
    }

    public class ActivitySettings
    {
        public int IdleThresholdSeconds { get; set; } = 60;
        public int MaxCountedGapSeconds { get; set; } = 300;
        public int DailyScreenTimeLimitMinutes { get; set; } = 0;
        public List<ApplicationActivityRule> ApplicationRules { get; set; } = new List<ApplicationActivityRule>();
        public List<SiteActivityRule> SiteRules { get; set; } = new List<SiteActivityRule>();
        public List<CategoryTimeLimit> CategoryLimits { get; set; } = new List<CategoryTimeLimit>();
    }

    public class CategoryTimeLimit
    {
        public ActivityCategory Category { get; set; } = ActivityCategory.Uncategorized;
        public int DailyLimitMinutes { get; set; } = 0;
        public int SessionLimitMinutes { get; set; } = 0;
    }

    public class ApplicationActivityRule
    {
        public string FilePath { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public ActivityCategory Category { get; set; } = ActivityCategory.Uncategorized;
        public bool CountsAsScreenTime { get; set; } = true;
    }

    public class SiteActivityRule
    {
        public string Domain { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public ActivityCategory Category { get; set; } = ActivityCategory.Uncategorized;
        public bool CountsAsScreenTime { get; set; } = true;
    }

    public class ActivityRuntimeState
    {
        public DateTime? LastSnapshotUtc { get; set; }
        public string LastForegroundFilePath { get; set; } = "";
        public string LastForegroundTitle { get; set; } = "";
        public string LastForegroundDisplayName { get; set; } = "";
        public ActivityCategory LastCategory { get; set; } = ActivityCategory.Uncategorized;
        public bool LastWasActive { get; set; }
        public bool LastCountsAsScreenTime { get; set; } = true;
        public string CurrentSessionFilePath { get; set; } = "";
        public ActivityCategory CurrentSessionCategory { get; set; } = ActivityCategory.Uncategorized;
        public DateTime? CurrentSessionStartedUtc { get; set; }
        public int CurrentSessionActiveSeconds { get; set; }
    }

    public class ActivityUsageEntry
    {
        public string Date { get; set; } = "";
        public string FilePath { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public ActivityCategory Category { get; set; } = ActivityCategory.Uncategorized;
        public bool CountsAsScreenTime { get; set; } = true;
        public int ActiveSeconds { get; set; }
        public DateTime LastSeenUtc { get; set; }
    }

    public class ActivitySnapshot
    {
        public DateTime TimestampUtc { get; set; }
        public int ForegroundProcessId { get; set; }
        public string ForegroundFilePath { get; set; } = "";
        public string ForegroundTitle { get; set; } = "";
        public string ForegroundDomain { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public int IdleSeconds { get; set; }
    }

    public sealed class ActivityAccountingResult
    {
        public bool Changed { get; set; }
        public int CountedSeconds { get; set; }
        public ActivityCategory Category { get; set; } = ActivityCategory.Uncategorized;
        public bool WasActive { get; set; }
    }

    public static class ActivityAccountingEngine
    {
        public static ActivityAccountingResult RecordSnapshot(GuardState state, ActivitySnapshot snapshot)
        {
            if (state == null) throw new ArgumentNullException(nameof(state));
            if (snapshot == null) throw new ArgumentNullException(nameof(snapshot));
            EnsureActivityState(state);

            var result = new ActivityAccountingResult();
            var runtime = state.ActivityRuntime;
            var settings = state.ActivitySettings;

            if (runtime.LastSnapshotUtc.HasValue &&
                runtime.LastWasActive &&
                !string.IsNullOrWhiteSpace(runtime.LastForegroundFilePath))
            {
                var deltaSeconds = (int)Math.Floor((snapshot.TimestampUtc - runtime.LastSnapshotUtc.Value).TotalSeconds);
                var maxGap = settings.MaxCountedGapSeconds <= 0 ? 300 : settings.MaxCountedGapSeconds;
                if (deltaSeconds > 0 && deltaSeconds <= maxGap)
                {
                    AddUsage(
                        state,
                        runtime.LastSnapshotUtc.Value,
                        runtime.LastForegroundFilePath,
                        runtime.LastForegroundDisplayName,
                        runtime.LastCategory,
                        runtime.LastCountsAsScreenTime,
                        deltaSeconds);
                    AddSessionTime(runtime, runtime.LastSnapshotUtc.Value, deltaSeconds);
                    result.Changed = true;
                    result.CountedSeconds = deltaSeconds;
                    result.Category = runtime.LastCategory;
                }
            }

            var normalizedDomain = DomainAccessGrantApplier.NormalizeDomainInput(snapshot.ForegroundDomain);
            var isSiteActivity = DomainAccessGrantApplier.IsValidWebsiteDomain(normalizedDomain);
            var normalizedPath = isSiteActivity
                ? BuildSiteActivityKey(normalizedDomain)
                : ApplicationControlApplier.NormalizeExecutablePath(snapshot.ForegroundFilePath) ?? "";
            var appRule = isSiteActivity ? null : FindRule(settings, normalizedPath);
            var siteRule = isSiteActivity ? FindSiteRule(settings, normalizedDomain) : null;
            var displayName = InputSanitizer.SanitizeString(snapshot.DisplayName, 80);
            if (isSiteActivity)
            {
                displayName = siteRule != null && !string.IsNullOrWhiteSpace(siteRule.DisplayName)
                    ? siteRule.DisplayName
                    : normalizedDomain;
            }
            else if (string.IsNullOrWhiteSpace(displayName) && !string.IsNullOrWhiteSpace(normalizedPath))
            {
                displayName = Path.GetFileNameWithoutExtension(normalizedPath);
            }

            var idleThreshold = settings.IdleThresholdSeconds <= 0 ? 60 : settings.IdleThresholdSeconds;
            var isActive = !string.IsNullOrWhiteSpace(normalizedPath) && snapshot.IdleSeconds <= idleThreshold;

            runtime.LastSnapshotUtc = snapshot.TimestampUtc;
            runtime.LastForegroundFilePath = normalizedPath;
            runtime.LastForegroundTitle = InputSanitizer.SanitizeString(snapshot.ForegroundTitle, 160);
            runtime.LastForegroundDisplayName = appRule != null && !string.IsNullOrWhiteSpace(appRule.DisplayName)
                ? appRule.DisplayName
                : displayName;
            runtime.LastCategory = siteRule?.Category ?? appRule?.Category ?? GuessCategory(normalizedPath);
            runtime.LastWasActive = isActive;
            runtime.LastCountsAsScreenTime = siteRule?.CountsAsScreenTime ?? appRule?.CountsAsScreenTime ?? (runtime.LastCategory != ActivityCategory.System);
            if (!isActive)
            {
                ResetSession(runtime);
            }

            result.WasActive = isActive;
            return result;
        }

        public static IReadOnlyList<ActivityUsageEntry> GetTodayUsage(GuardState state, DateTime utcNow)
        {
            if (state?.ActivityUsage == null)
            {
                return Array.Empty<ActivityUsageEntry>();
            }

            var today = DayKey(utcNow);
            return state.ActivityUsage
                .Where(item => item.Date == today)
                .OrderByDescending(item => item.ActiveSeconds)
                .ToList();
        }

        public static ParentCommandResult SetApplicationCategory(
            GuardState state,
            string filePath,
            string displayName,
            ActivityCategory category,
            bool countsAsScreenTime)
        {
            if (state == null) throw new ArgumentNullException(nameof(state));
            EnsureActivityState(state);

            var normalizedPath = ApplicationControlApplier.NormalizeExecutablePath(filePath);
            if (normalizedPath == null)
            {
                return new ParentCommandResult { Error = "Invalid application path." };
            }

            var existing = state.ActivitySettings.ApplicationRules.FirstOrDefault(rule =>
                string.Equals(
                    ApplicationControlApplier.NormalizeExecutablePath(rule.FilePath),
                    normalizedPath,
                    StringComparison.OrdinalIgnoreCase));
            var name = InputSanitizer.SanitizeString(displayName, 80);
            if (string.IsNullOrWhiteSpace(name))
            {
                name = Path.GetFileNameWithoutExtension(normalizedPath);
            }

            if (existing == null)
            {
                state.ActivitySettings.ApplicationRules.Add(new ApplicationActivityRule
                {
                    FilePath = normalizedPath,
                    DisplayName = name,
                    Category = category,
                    CountsAsScreenTime = countsAsScreenTime
                });
                return new ParentCommandResult { Changed = true };
            }

            if (existing.DisplayName == name &&
                existing.Category == category &&
                existing.CountsAsScreenTime == countsAsScreenTime)
            {
                return new ParentCommandResult { Changed = false };
            }

            existing.FilePath = normalizedPath;
            existing.DisplayName = name;
            existing.Category = category;
            existing.CountsAsScreenTime = countsAsScreenTime;
            return new ParentCommandResult { Changed = true };
        }

        public static ParentCommandResult SetSiteCategory(
            GuardState state,
            string domainInput,
            string displayName,
            ActivityCategory category,
            bool countsAsScreenTime)
        {
            if (state == null) throw new ArgumentNullException(nameof(state));
            EnsureActivityState(state);

            var domain = DomainAccessGrantApplier.NormalizeDomainInput(domainInput);
            if (!DomainAccessGrantApplier.IsValidWebsiteDomain(domain))
            {
                return new ParentCommandResult { Error = "Invalid domain." };
            }

            var existing = state.ActivitySettings.SiteRules.FirstOrDefault(rule =>
                string.Equals(rule.Domain, domain, StringComparison.OrdinalIgnoreCase));
            var name = InputSanitizer.SanitizeString(displayName, 80);
            if (string.IsNullOrWhiteSpace(name))
            {
                name = domain;
            }

            if (existing == null)
            {
                state.ActivitySettings.SiteRules.Add(new SiteActivityRule
                {
                    Domain = domain,
                    DisplayName = name,
                    Category = category,
                    CountsAsScreenTime = countsAsScreenTime
                });
                return new ParentCommandResult { Changed = true };
            }

            if (existing.DisplayName == name &&
                existing.Category == category &&
                existing.CountsAsScreenTime == countsAsScreenTime)
            {
                return new ParentCommandResult { Changed = false };
            }

            existing.Domain = domain;
            existing.DisplayName = name;
            existing.Category = category;
            existing.CountsAsScreenTime = countsAsScreenTime;
            return new ParentCommandResult { Changed = true };
        }

        public static string BuildSiteActivityKey(string domainInput)
        {
            return "site:" + DomainAccessGrantApplier.NormalizeDomainInput(domainInput);
        }

        public static bool IsSiteActivityKey(string key)
        {
            return (key ?? "").StartsWith("site:", StringComparison.OrdinalIgnoreCase);
        }

        public static string GetDomainFromSiteActivityKey(string key)
        {
            return IsSiteActivityKey(key) ? key.Substring("site:".Length) : "";
        }

        private static void AddUsage(
            GuardState state,
            DateTime sampleUtc,
            string filePath,
            string displayName,
            ActivityCategory category,
            bool countsAsScreenTime,
            int seconds)
        {
            var day = DayKey(sampleUtc);
            var entry = state.ActivityUsage.FirstOrDefault(item =>
                item.Date == day &&
                string.Equals(item.FilePath, filePath, StringComparison.OrdinalIgnoreCase));
            if (entry == null)
            {
                state.ActivityUsage.Add(new ActivityUsageEntry
                {
                    Date = day,
                    FilePath = filePath,
                    DisplayName = displayName,
                    Category = category,
                    CountsAsScreenTime = countsAsScreenTime,
                    ActiveSeconds = seconds,
                    LastSeenUtc = sampleUtc
                });
                return;
            }

            entry.DisplayName = displayName;
            entry.Category = category;
            entry.CountsAsScreenTime = countsAsScreenTime;
            entry.ActiveSeconds += seconds;
            entry.LastSeenUtc = sampleUtc;
        }

        private static void AddSessionTime(ActivityRuntimeState runtime, DateTime sampleUtc, int seconds)
        {
            if (!string.Equals(runtime.CurrentSessionFilePath, runtime.LastForegroundFilePath, StringComparison.OrdinalIgnoreCase) ||
                runtime.CurrentSessionCategory != runtime.LastCategory)
            {
                runtime.CurrentSessionFilePath = runtime.LastForegroundFilePath;
                runtime.CurrentSessionCategory = runtime.LastCategory;
                runtime.CurrentSessionStartedUtc = sampleUtc;
                runtime.CurrentSessionActiveSeconds = 0;
            }

            runtime.CurrentSessionActiveSeconds += seconds;
        }

        private static void ResetSession(ActivityRuntimeState runtime)
        {
            runtime.CurrentSessionFilePath = "";
            runtime.CurrentSessionCategory = ActivityCategory.Uncategorized;
            runtime.CurrentSessionStartedUtc = null;
            runtime.CurrentSessionActiveSeconds = 0;
        }

        private static ApplicationActivityRule? FindRule(ActivitySettings settings, string normalizedPath)
        {
            if (settings?.ApplicationRules == null || string.IsNullOrWhiteSpace(normalizedPath))
            {
                return null;
            }

            return settings.ApplicationRules.FirstOrDefault(rule =>
                string.Equals(
                    ApplicationControlApplier.NormalizeExecutablePath(rule.FilePath),
                    normalizedPath,
                    StringComparison.OrdinalIgnoreCase));
        }

        private static SiteActivityRule? FindSiteRule(ActivitySettings settings, string normalizedDomain)
        {
            if (settings?.SiteRules == null || string.IsNullOrWhiteSpace(normalizedDomain))
            {
                return null;
            }

            return settings.SiteRules.FirstOrDefault(rule =>
                string.Equals(
                    DomainAccessGrantApplier.NormalizeDomainInput(rule.Domain),
                    normalizedDomain,
                    StringComparison.OrdinalIgnoreCase));
        }

        private static ActivityCategory GuessCategory(string normalizedPath)
        {
            if (IsSiteActivityKey(normalizedPath))
            {
                return ActivityCategory.Uncategorized;
            }

            var fileName = Path.GetFileName(normalizedPath);
            if (ApplicationControlApplier.IsBlockedManagementToolFileName(fileName) ||
                string.Equals(fileName, "guard.exe", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(fileName, "StartHelperG.exe", StringComparison.OrdinalIgnoreCase))
            {
                return ActivityCategory.System;
            }

            return ActivityCategory.Uncategorized;
        }

        private static void EnsureActivityState(GuardState state)
        {
            if (state.ActivitySettings == null)
            {
                state.ActivitySettings = new ActivitySettings();
            }

            if (state.ActivitySettings.ApplicationRules == null)
            {
                state.ActivitySettings.ApplicationRules = new List<ApplicationActivityRule>();
            }

            if (state.ActivitySettings.SiteRules == null)
            {
                state.ActivitySettings.SiteRules = new List<SiteActivityRule>();
            }

            if (state.ActivitySettings.CategoryLimits == null)
            {
                state.ActivitySettings.CategoryLimits = new List<CategoryTimeLimit>();
            }

            if (state.ActivityRuntime == null)
            {
                state.ActivityRuntime = new ActivityRuntimeState();
            }

            if (state.ActivityUsage == null)
            {
                state.ActivityUsage = new List<ActivityUsageEntry>();
            }
        }

        private static string DayKey(DateTime utc)
        {
            return utc.ToString("yyyy-MM-dd");
        }
    }

    public sealed class TimeLimitStatus
    {
        public int DailyScreenTimeUsedSeconds { get; set; }
        public int DailyScreenTimeLimitSeconds { get; set; }
        public List<CategoryLimitStatus> Categories { get; } = new List<CategoryLimitStatus>();
    }

    public sealed class CategoryLimitStatus
    {
        public ActivityCategory Category { get; set; } = ActivityCategory.Uncategorized;
        public int UsedSeconds { get; set; }
        public int DailyLimitSeconds { get; set; }
        public int BonusSeconds { get; set; }
        public bool IsExceeded => DailyLimitSeconds > 0 && UsedSeconds >= DailyLimitSeconds;
    }

    public static class TimeLimitEngine
    {
        public static ParentCommandResult SetDailyScreenTimeLimit(GuardState state, int minutes)
        {
            if (state == null) throw new ArgumentNullException(nameof(state));
            EnsureSettings(state);
            if (minutes < 0 || minutes > 24 * 60)
            {
                return new ParentCommandResult { Error = "Daily screen time limit must be from 0 to 1440 minutes." };
            }

            if (state.ActivitySettings.DailyScreenTimeLimitMinutes == minutes)
            {
                return new ParentCommandResult { Changed = false };
            }

            state.ActivitySettings.DailyScreenTimeLimitMinutes = minutes;
            state.AppControl.PolicyUpdatePending = true;
            return new ParentCommandResult { Changed = true };
        }

        public static ParentCommandResult SetCategoryLimit(GuardState state, ActivityCategory category, int dailyMinutes, int sessionMinutes)
        {
            if (state == null) throw new ArgumentNullException(nameof(state));
            EnsureSettings(state);
            if (dailyMinutes < 0 || dailyMinutes > 24 * 60)
            {
                return new ParentCommandResult { Error = "Daily category limit must be from 0 to 1440 minutes." };
            }

            if (sessionMinutes < 0 || sessionMinutes > 24 * 60)
            {
                return new ParentCommandResult { Error = "Session category limit must be from 0 to 1440 minutes." };
            }

            var existing = state.ActivitySettings.CategoryLimits.FirstOrDefault(limit => limit.Category == category);
            if (existing == null)
            {
                state.ActivitySettings.CategoryLimits.Add(new CategoryTimeLimit
                {
                    Category = category,
                    DailyLimitMinutes = dailyMinutes,
                    SessionLimitMinutes = sessionMinutes
                });
                state.AppControl.PolicyUpdatePending = true;
                return new ParentCommandResult { Changed = true };
            }

            if (existing.DailyLimitMinutes == dailyMinutes && existing.SessionLimitMinutes == sessionMinutes)
            {
                return new ParentCommandResult { Changed = false };
            }

            existing.DailyLimitMinutes = dailyMinutes;
            existing.SessionLimitMinutes = sessionMinutes;
            state.AppControl.PolicyUpdatePending = true;
            return new ParentCommandResult { Changed = true };
        }

        public static TimeLimitStatus GetStatus(GuardState state, DateTime utcNow)
        {
            EnsureSettings(state);
            var today = utcNow.ToString("yyyy-MM-dd");
            var usage = state.ActivityUsage ?? new List<ActivityUsageEntry>();
            var todayUsage = usage.Where(item => item.Date == today).ToList();
            var status = new TimeLimitStatus
            {
                DailyScreenTimeUsedSeconds = todayUsage
                    .Where(item => item.CountsAsScreenTime)
                    .Sum(item => item.ActiveSeconds),
                DailyScreenTimeLimitSeconds = Math.Max(0, state.ActivitySettings.DailyScreenTimeLimitMinutes) * 60
            };

            foreach (var limit in state.ActivitySettings.CategoryLimits ?? new List<CategoryTimeLimit>())
            {
                if (limit.DailyLimitMinutes <= 0)
                {
                    continue;
                }

                status.Categories.Add(new CategoryLimitStatus
                {
                    Category = limit.Category,
                    UsedSeconds = todayUsage
                        .Where(item => item.Category == limit.Category && item.CountsAsScreenTime)
                        .Sum(item => item.ActiveSeconds),
                    DailyLimitSeconds = (limit.DailyLimitMinutes + DailyTaskEngine.GetBonusMinutes(state, limit.Category, utcNow)) * 60,
                    BonusSeconds = DailyTaskEngine.GetBonusMinutes(state, limit.Category, utcNow) * 60
                });
            }

            return status;
        }

        public static bool IsApplicationAllowedByTimeLimits(GuardState state, string filePath, DateTime utcNow)
        {
            if (state == null)
            {
                return true;
            }

            EnsureSettings(state);
            var normalized = ApplicationControlApplier.NormalizeExecutablePath(filePath);
            if (normalized == null)
            {
                return true;
            }

            var category = GetApplicationCategory(state, normalized);
            var countsAsScreenTime = CountsAsScreenTime(state, normalized, category);
            var status = GetStatus(state, utcNow);
            if (countsAsScreenTime &&
                status.DailyScreenTimeLimitSeconds > 0 &&
                status.DailyScreenTimeUsedSeconds >= status.DailyScreenTimeLimitSeconds)
            {
                return false;
            }

            var categoryStatus = status.Categories.FirstOrDefault(item => item.Category == category);
            if (categoryStatus != null && categoryStatus.IsExceeded)
            {
                return false;
            }

            var categoryLimit = state.ActivitySettings.CategoryLimits.FirstOrDefault(item => item.Category == category);
            if (categoryLimit != null &&
                categoryLimit.SessionLimitMinutes > 0 &&
                state.ActivityRuntime != null &&
                string.Equals(state.ActivityRuntime.CurrentSessionFilePath, normalized, StringComparison.OrdinalIgnoreCase) &&
                state.ActivityRuntime.CurrentSessionActiveSeconds >= categoryLimit.SessionLimitMinutes * 60)
            {
                return false;
            }

            return true;
        }

        public static bool IsWebsiteAllowedByTimeLimits(GuardState state, string domainInput, DateTime utcNow)
        {
            if (state == null)
            {
                return true;
            }

            EnsureSettings(state);
            var domain = DomainAccessGrantApplier.NormalizeDomainInput(domainInput);
            if (!DomainAccessGrantApplier.IsValidWebsiteDomain(domain))
            {
                return true;
            }

            var key = ActivityAccountingEngine.BuildSiteActivityKey(domain);
            var category = GetSiteCategory(state, domain);
            var countsAsScreenTime = SiteCountsAsScreenTime(state, domain, category);
            var status = GetStatus(state, utcNow);
            if (countsAsScreenTime &&
                status.DailyScreenTimeLimitSeconds > 0 &&
                status.DailyScreenTimeUsedSeconds >= status.DailyScreenTimeLimitSeconds)
            {
                return false;
            }

            var categoryStatus = status.Categories.FirstOrDefault(item => item.Category == category);
            if (categoryStatus != null && categoryStatus.IsExceeded)
            {
                return false;
            }

            var categoryLimit = state.ActivitySettings.CategoryLimits.FirstOrDefault(item => item.Category == category);
            if (categoryLimit != null &&
                categoryLimit.SessionLimitMinutes > 0 &&
                state.ActivityRuntime != null &&
                string.Equals(state.ActivityRuntime.CurrentSessionFilePath, key, StringComparison.OrdinalIgnoreCase) &&
                state.ActivityRuntime.CurrentSessionActiveSeconds >= categoryLimit.SessionLimitMinutes * 60)
            {
                return false;
            }

            return true;
        }

        public static IReadOnlyList<DomainAccessGrant> GetOverLimitWebsiteGrants(GuardState state, DateTime utcNow)
        {
            return DomainAccessGrantApplier.GetActiveGrants(state, utcNow)
                .Where(grant => !IsWebsiteAllowedByTimeLimits(state, grant.Domain, utcNow))
                .ToList();
        }

        public static IReadOnlyList<RunningApplication> GetOverLimitRunningApplications(
            GuardState state,
            IEnumerable<RunningApplication> runningApplications,
            DateTime utcNow)
        {
            return (runningApplications ?? Enumerable.Empty<RunningApplication>())
                .Where(app => app != null && !IsApplicationAllowedByTimeLimits(state, app.FilePath, utcNow))
                .ToList();
        }

        private static ActivityCategory GetApplicationCategory(GuardState state, string normalizedPath)
        {
            var rule = state.ActivitySettings.ApplicationRules.FirstOrDefault(item =>
                string.Equals(
                    ApplicationControlApplier.NormalizeExecutablePath(item.FilePath),
                    normalizedPath,
                    StringComparison.OrdinalIgnoreCase));
            if (rule != null)
            {
                return rule.Category;
            }

            var latestUsage = (state.ActivityUsage ?? new List<ActivityUsageEntry>())
                .Where(item => string.Equals(item.FilePath, normalizedPath, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(item => item.LastSeenUtc)
                .FirstOrDefault();
            return latestUsage?.Category ?? ActivityCategory.Uncategorized;
        }

        private static ActivityCategory GetSiteCategory(GuardState state, string normalizedDomain)
        {
            var rule = state.ActivitySettings.SiteRules.FirstOrDefault(item =>
                string.Equals(
                    DomainAccessGrantApplier.NormalizeDomainInput(item.Domain),
                    normalizedDomain,
                    StringComparison.OrdinalIgnoreCase));
            if (rule != null)
            {
                return rule.Category;
            }

            var key = ActivityAccountingEngine.BuildSiteActivityKey(normalizedDomain);
            var latestUsage = (state.ActivityUsage ?? new List<ActivityUsageEntry>())
                .Where(item => string.Equals(item.FilePath, key, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(item => item.LastSeenUtc)
                .FirstOrDefault();
            return latestUsage?.Category ?? ActivityCategory.Uncategorized;
        }

        private static bool CountsAsScreenTime(GuardState state, string normalizedPath, ActivityCategory category)
        {
            var rule = state.ActivitySettings.ApplicationRules.FirstOrDefault(item =>
                string.Equals(
                    ApplicationControlApplier.NormalizeExecutablePath(item.FilePath),
                    normalizedPath,
                    StringComparison.OrdinalIgnoreCase));
            if (rule != null)
            {
                return rule.CountsAsScreenTime;
            }

            return category != ActivityCategory.System;
        }

        private static bool SiteCountsAsScreenTime(GuardState state, string normalizedDomain, ActivityCategory category)
        {
            var rule = state.ActivitySettings.SiteRules.FirstOrDefault(item =>
                string.Equals(
                    DomainAccessGrantApplier.NormalizeDomainInput(item.Domain),
                    normalizedDomain,
                    StringComparison.OrdinalIgnoreCase));
            if (rule != null)
            {
                return rule.CountsAsScreenTime;
            }

            return category != ActivityCategory.System;
        }

        private static void EnsureSettings(GuardState state)
        {
            if (state.ActivitySettings == null)
            {
                state.ActivitySettings = new ActivitySettings();
            }

            if (state.ActivitySettings.ApplicationRules == null)
            {
                state.ActivitySettings.ApplicationRules = new List<ApplicationActivityRule>();
            }

            if (state.ActivitySettings.SiteRules == null)
            {
                state.ActivitySettings.SiteRules = new List<SiteActivityRule>();
            }

            if (state.ActivitySettings.CategoryLimits == null)
            {
                state.ActivitySettings.CategoryLimits = new List<CategoryTimeLimit>();
            }

            if (state.ActivityUsage == null)
            {
                state.ActivityUsage = new List<ActivityUsageEntry>();
            }

            if (state.AppControl == null)
            {
                state.AppControl = new ApplicationControlSettings();
            }
        }
    }
}
