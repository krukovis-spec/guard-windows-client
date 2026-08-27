using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Guard
{
    public enum DailyTaskType
    {
        SelfReport = 0,
        VerifiedApplicationTime = 1
    }

    public class DailyTask
    {
        public string Id { get; set; } = "";
        public string Title { get; set; } = "";
        public DailyTaskType Type { get; set; } = DailyTaskType.SelfReport;
        public string ApplicationPath { get; set; } = "";
        public ActivityCategory Category { get; set; } = ActivityCategory.Uncategorized;
        public int RequiredActiveMinutes { get; set; } = 0;
        public int RewardMinutes { get; set; } = 0;
        public ActivityCategory RewardCategory { get; set; } = ActivityCategory.Game;
        public int MaxCompletionsPerDay { get; set; } = 1;
        public bool Active { get; set; } = true;
    }

    public class DailyTaskCompletion
    {
        public string TaskId { get; set; } = "";
        public string Date { get; set; } = "";
        public DateTime CompletedAtUtc { get; set; }
        public string Source { get; set; } = "";
        public int VerifiedActiveSeconds { get; set; }
    }

    public class BonusTimeGrant
    {
        public string Id { get; set; } = "";
        public string Date { get; set; } = "";
        public ActivityCategory Category { get; set; } = ActivityCategory.Game;
        public int Minutes { get; set; }
        public string Reason { get; set; } = "";
        public DateTime CreatedAtUtc { get; set; }
    }

    public static class DailyTaskEngine
    {
        public static ParentCommandResult AddOrUpdateTask(GuardState state, DailyTask task)
        {
            if (state == null) throw new ArgumentNullException(nameof(state));
            if (task == null) throw new ArgumentNullException(nameof(task));
            EnsureTaskState(state);

            var title = InputSanitizer.SanitizeString(task.Title, 120);
            if (string.IsNullOrWhiteSpace(title))
            {
                return new ParentCommandResult { Error = "Task title is required." };
            }

            var id = string.IsNullOrWhiteSpace(task.Id) ? BuildTaskId(title) : task.Id;
            var existing = state.DailyTasks.FirstOrDefault(item => item.Id == id);
            var normalizedPath = string.IsNullOrWhiteSpace(task.ApplicationPath)
                ? ""
                : ApplicationControlApplier.NormalizeExecutablePath(task.ApplicationPath) ?? "";
            if (task.Type == DailyTaskType.VerifiedApplicationTime && string.IsNullOrWhiteSpace(normalizedPath))
            {
                return new ParentCommandResult { Error = "Verified task requires an application path." };
            }

            var saved = new DailyTask
            {
                Id = id,
                Title = title,
                Type = task.Type,
                ApplicationPath = normalizedPath,
                Category = task.Category,
                RequiredActiveMinutes = Math.Max(0, task.RequiredActiveMinutes),
                RewardMinutes = Math.Max(0, task.RewardMinutes),
                RewardCategory = task.RewardCategory,
                MaxCompletionsPerDay = Math.Max(1, task.MaxCompletionsPerDay),
                Active = task.Active
            };

            if (existing == null)
            {
                state.DailyTasks.Add(saved);
                return new ParentCommandResult { Changed = true };
            }

            existing.Title = saved.Title;
            existing.Type = saved.Type;
            existing.ApplicationPath = saved.ApplicationPath;
            existing.Category = saved.Category;
            existing.RequiredActiveMinutes = saved.RequiredActiveMinutes;
            existing.RewardMinutes = saved.RewardMinutes;
            existing.RewardCategory = saved.RewardCategory;
            existing.MaxCompletionsPerDay = saved.MaxCompletionsPerDay;
            existing.Active = saved.Active;
            return new ParentCommandResult { Changed = true };
        }

        public static ParentCommandResult CompleteTask(GuardState state, string taskId, string source, DateTime utcNow)
        {
            if (state == null) throw new ArgumentNullException(nameof(state));
            EnsureTaskState(state);

            var task = state.DailyTasks.FirstOrDefault(item => item.Id == (taskId ?? "") && item.Active);
            if (task == null)
            {
                return new ParentCommandResult { Error = "Active task was not found." };
            }

            var day = DayKey(utcNow);
            var completionsToday = state.DailyTaskCompletions.Count(item => item.TaskId == task.Id && item.Date == day);
            if (completionsToday >= task.MaxCompletionsPerDay)
            {
                return new ParentCommandResult { Error = "Task is already completed for today." };
            }

            var verifiedSeconds = GetVerifiedSeconds(state, task, day);
            if (task.Type == DailyTaskType.VerifiedApplicationTime &&
                verifiedSeconds < task.RequiredActiveMinutes * 60)
            {
                return new ParentCommandResult { Error = "Task does not have enough verified active time yet." };
            }

            state.DailyTaskCompletions.Add(new DailyTaskCompletion
            {
                TaskId = task.Id,
                Date = day,
                CompletedAtUtc = utcNow,
                Source = InputSanitizer.SanitizeString(source, 40),
                VerifiedActiveSeconds = verifiedSeconds
            });

            if (task.RewardMinutes > 0)
            {
                state.BonusTimeGrants.Add(new BonusTimeGrant
                {
                    Id = task.Id + ":" + day + ":" + (completionsToday + 1),
                    Date = day,
                    Category = task.RewardCategory,
                    Minutes = task.RewardMinutes,
                    Reason = task.Title,
                    CreatedAtUtc = utcNow
                });
            }

            state.AppControl.PolicyUpdatePending = true;
            return new ParentCommandResult { Changed = true };
        }

        public static IReadOnlyList<DailyTask> GetActiveTasks(GuardState state)
        {
            if (state?.DailyTasks == null)
            {
                return Array.Empty<DailyTask>();
            }

            return state.DailyTasks
                .Where(task => task.Active)
                .OrderBy(task => task.Title)
                .ToList();
        }

        public static int GetBonusMinutes(GuardState state, ActivityCategory category, DateTime utcNow)
        {
            if (state?.BonusTimeGrants == null)
            {
                return 0;
            }

            var day = DayKey(utcNow);
            return state.BonusTimeGrants
                .Where(grant => grant.Date == day && grant.Category == category)
                .Sum(grant => grant.Minutes);
        }

        private static int GetVerifiedSeconds(GuardState state, DailyTask task, string day)
        {
            var usage = state.ActivityUsage ?? new List<ActivityUsageEntry>();
            if (!string.IsNullOrWhiteSpace(task.ApplicationPath))
            {
                return usage
                    .Where(item => item.Date == day &&
                                   string.Equals(item.FilePath, task.ApplicationPath, StringComparison.OrdinalIgnoreCase))
                    .Sum(item => item.ActiveSeconds);
            }

            return usage
                .Where(item => item.Date == day && item.Category == task.Category)
                .Sum(item => item.ActiveSeconds);
        }

        private static string BuildTaskId(string title)
        {
            return "task:" + title.Trim().ToLowerInvariant().Replace(" ", "-");
        }

        private static void EnsureTaskState(GuardState state)
        {
            if (state.DailyTasks == null)
            {
                state.DailyTasks = new List<DailyTask>();
            }

            if (state.DailyTaskCompletions == null)
            {
                state.DailyTaskCompletions = new List<DailyTaskCompletion>();
            }

            if (state.BonusTimeGrants == null)
            {
                state.BonusTimeGrants = new List<BonusTimeGrant>();
            }

            if (state.AppControl == null)
            {
                state.AppControl = new ApplicationControlSettings();
            }
        }

        private static string DayKey(DateTime utc)
        {
            return utc.ToString("yyyy-MM-dd");
        }
    }
}
