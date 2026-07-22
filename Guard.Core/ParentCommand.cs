using System;
using System.Linq;

namespace Guard
{
    public enum ParentCommandType
    {
        AddBlockedDomain = 0,
        RemoveBlockedDomain = 1,
        SetSyncStatus = 2,
        SetEmergencyPin = 3,
        SetApplicationControlMode = 4,
        AddAllowedApplication = 5,
        RemoveAllowedApplication = 6,
        GrantTemporaryApplication = 7,
        GrantTaskManagerAccess = 8,
        BlockTaskManagerNow = 9,
        RequestApplicationAccess = 10,
        ApproveAccessRequest = 11,
        DenyAccessRequest = 12,
        SetApplicationCategory = 13,
        SetDailyScreenTimeLimit = 14,
        SetCategoryTimeLimit = 15,
        AddDailyTask = 16,
        CompleteDailyTask = 17,
        RequestWebsiteAccess = 18,
        RemoveWebsiteGrant = 19,
        SetChildWindowsUser = 20,
        DemoteChildWindowsUser = 21,
        SetSiteCategory = 22,
        StartMaintenanceMode = 23,
        EndMaintenanceMode = 24,
        SetUiLanguage = 25
    }

    public class ParentCommand
    {
        public ParentCommandType Type { get; set; }
        public string Value { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public bool? BoolValue { get; set; }
        public int? IntValue { get; set; }
        public ActivityCategory? ActivityCategory { get; set; }
        public ActivityCategory? RewardCategory { get; set; }
        public DailyTaskType? DailyTaskType { get; set; }
        public string Schedule { get; set; } = ParentCommandApplier.AlwaysOnSchedule;
    }

    public sealed class ParentCommandResult
    {
        public bool Changed { get; set; }
        public string Error { get; set; } = "";
    }

    public static class ParentCommandApplier
    {
        public const string AlwaysOnSchedule = "1";
        private const string ParentRulePrefix = "parent-block-domain:";

        public static ParentCommandResult Apply(GuardState state, ParentCommand command)
        {
            if (state == null) throw new ArgumentNullException(nameof(state));
            if (command == null) throw new ArgumentNullException(nameof(command));

            switch (command.Type)
            {
                case ParentCommandType.AddBlockedDomain:
                    return AddBlockedDomain(state, command);
                case ParentCommandType.RemoveBlockedDomain:
                    return RemoveBlockedDomain(state, command.Value);
                case ParentCommandType.SetSyncStatus:
                    return SetSyncStatus(state, command.BoolValue);
                case ParentCommandType.SetEmergencyPin:
                    return SetEmergencyPin(state, command.Value);
                case ParentCommandType.SetApplicationControlMode:
                    return SetApplicationControlMode(state, command.Value);
                case ParentCommandType.AddAllowedApplication:
                    return ApplicationControlApplier.AddPermanentApplication(state, command.Value, command.DisplayName, DateTime.UtcNow);
                case ParentCommandType.RemoveAllowedApplication:
                    return ApplicationControlApplier.RemoveApplication(state, command.Value);
                case ParentCommandType.GrantTemporaryApplication:
                    return ApplicationControlApplier.GrantTemporaryApplication(state, command.Value, command.DisplayName, command.IntValue ?? 0, DateTime.UtcNow);
                case ParentCommandType.GrantTaskManagerAccess:
                    return ApplicationControlApplier.GrantTaskManagerAccess(state, command.IntValue ?? 0, DateTime.UtcNow);
                case ParentCommandType.BlockTaskManagerNow:
                    return ApplicationControlApplier.BlockTaskManagerNow(state);
                case ParentCommandType.RequestApplicationAccess:
                    return AccessRequestApplier.RequestApplication(
                        state,
                        command.Value,
                        command.DisplayName,
                        "manual",
                        Environment.UserName,
                        DateTime.UtcNow);
                case ParentCommandType.ApproveAccessRequest:
                    return AccessRequestApplier.ApproveRequest(
                        state,
                        command.Value,
                        command.IntValue.HasValue && command.IntValue.Value > 0 ? command.IntValue : null,
                        DateTime.UtcNow);
                case ParentCommandType.DenyAccessRequest:
                    return AccessRequestApplier.DenyRequest(state, command.Value, DateTime.UtcNow);
                case ParentCommandType.RequestWebsiteAccess:
                    return AccessRequestApplier.RequestWebsite(
                        state,
                        command.Value,
                        "manual",
                        Environment.UserName,
                        DateTime.UtcNow);
                case ParentCommandType.RemoveWebsiteGrant:
                    return DomainAccessGrantApplier.RemoveWebsiteGrant(state, command.Value);
                case ParentCommandType.SetChildWindowsUser:
                    return SetChildWindowsUser(state, command.Value);
                case ParentCommandType.DemoteChildWindowsUser:
                    return DemoteChildWindowsUser(state, command.Value);
                case ParentCommandType.SetApplicationCategory:
                    if (!command.ActivityCategory.HasValue)
                    {
                        return new ParentCommandResult { Error = "Activity category is missing." };
                    }

                    return ActivityAccountingEngine.SetApplicationCategory(
                        state,
                        command.Value,
                        command.DisplayName,
                        command.ActivityCategory.Value,
                        command.BoolValue ?? true);
                case ParentCommandType.SetSiteCategory:
                    if (!command.ActivityCategory.HasValue)
                    {
                        return new ParentCommandResult { Error = "Activity category is missing." };
                    }

                    return ActivityAccountingEngine.SetSiteCategory(
                        state,
                        command.Value,
                        command.DisplayName,
                        command.ActivityCategory.Value,
                        command.BoolValue ?? true);
                case ParentCommandType.StartMaintenanceMode:
                    return MaintenanceModeApplier.Start(state, command.IntValue ?? 0, DateTime.UtcNow);
                case ParentCommandType.EndMaintenanceMode:
                    return MaintenanceModeApplier.End(state, DateTime.UtcNow);
                case ParentCommandType.SetUiLanguage:
                    return SetUiLanguage(state, command.Value);
                case ParentCommandType.SetDailyScreenTimeLimit:
                    return TimeLimitEngine.SetDailyScreenTimeLimit(state, command.IntValue ?? 0);
                case ParentCommandType.SetCategoryTimeLimit:
                    if (!command.ActivityCategory.HasValue)
                    {
                        return new ParentCommandResult { Error = "Activity category is missing." };
                    }

                    return TimeLimitEngine.SetCategoryLimit(
                        state,
                        command.ActivityCategory.Value,
                        command.IntValue ?? 0,
                        ParseSessionLimit(command.Schedule));
                case ParentCommandType.AddDailyTask:
                    if (!command.DailyTaskType.HasValue)
                    {
                        return new ParentCommandResult { Error = "Task type is missing." };
                    }

                    return DailyTaskEngine.AddOrUpdateTask(state, new DailyTask
                    {
                        Title = command.DisplayName,
                        Type = command.DailyTaskType.Value,
                        ApplicationPath = command.Value,
                        Category = command.ActivityCategory ?? ActivityCategory.Uncategorized,
                        RequiredActiveMinutes = Math.Max(0, command.IntValue ?? 0),
                        RewardMinutes = ParseSessionLimit(command.Schedule),
                        RewardCategory = command.RewardCategory ?? ActivityCategory.Game,
                        MaxCompletionsPerDay = 1,
                        Active = true
                    });
                case ParentCommandType.CompleteDailyTask:
                    return DailyTaskEngine.CompleteTask(state, command.Value, command.DisplayName, DateTime.UtcNow);
                default:
                    return new ParentCommandResult { Error = "Unsupported parent command." };
            }
        }

        public static string BuildDomainRuleId(string domain)
        {
            return ParentRulePrefix + NormalizeDomain(domain);
        }

        private static ParentCommandResult AddBlockedDomain(GuardState state, ParentCommand command)
        {
            var domain = NormalizeDomain(command.Value);
            if (!InputSanitizer.IsValidDomainName(domain))
            {
                return new ParentCommandResult { Error = "Invalid domain." };
            }

            var ruleId = BuildDomainRuleId(domain);
            if (state.Rules.Any(r => r.Id == ruleId))
            {
                return new ParentCommandResult { Changed = false };
            }

            state.Rules.Add(new InstructionRule
            {
                Id = ruleId,
                Type = "custom_url",
                Value = domain,
                Schedule = string.IsNullOrWhiteSpace(command.Schedule) ? AlwaysOnSchedule : command.Schedule
            });

            MarkRulesChanged(state);
            return new ParentCommandResult { Changed = true };
        }

        private static ParentCommandResult RemoveBlockedDomain(GuardState state, string domainValue)
        {
            var domain = NormalizeDomain(domainValue);
            if (!InputSanitizer.IsValidDomainName(domain))
            {
                return new ParentCommandResult { Error = "Invalid domain." };
            }

            var ruleId = BuildDomainRuleId(domain);
            int removed = state.Rules.RemoveAll(r => r.Id == ruleId);
            if (removed == 0)
            {
                return new ParentCommandResult { Changed = false };
            }

            MarkRulesChanged(state);
            return new ParentCommandResult { Changed = true };
        }

        private static ParentCommandResult SetSyncStatus(GuardState state, bool? enabled)
        {
            if (!enabled.HasValue)
            {
                return new ParentCommandResult { Error = "Sync status is missing." };
            }

            if (state.SyncStatus == enabled.Value)
            {
                return new ParentCommandResult { Changed = false };
            }

            state.SyncStatus = enabled.Value;
            state.UpdateInfo.SyncStatUpdate = true;
            state.UpdateInfo.UpdateApplied = false;
            return new ParentCommandResult { Changed = true };
        }

        private static ParentCommandResult SetEmergencyPin(GuardState state, string pin)
        {
            if (!InputSanitizer.IsValidPin(pin))
            {
                return new ParentCommandResult { Error = "Invalid PIN." };
            }

            if (!EmergencyPinPolicy.IsAllowedCustomPin(pin))
            {
                return new ParentCommandResult { Error = "Choose a custom PIN, not the temporary default." };
            }

            if (state.PinCode == pin)
            {
                return new ParentCommandResult { Changed = false };
            }

            state.PinCode = pin;
            return new ParentCommandResult { Changed = true };
        }

        private static ParentCommandResult SetApplicationControlMode(GuardState state, string modeValue)
        {
            var mode = (modeValue ?? "").Trim().ToLowerInvariant();
            if (mode == "off")
            {
                return ApplicationControlApplier.SetMode(state, ApplicationControlMode.Off);
            }

            if (mode == "audit")
            {
                return ApplicationControlApplier.SetMode(state, ApplicationControlMode.AuditOnly);
            }

            if (mode == "enforce")
            {
                return ApplicationControlApplier.SetMode(state, ApplicationControlMode.Enforced);
            }

            return new ParentCommandResult { Error = "Invalid application control mode." };
        }

        private static ParentCommandResult SetChildWindowsUser(GuardState state, string userName)
        {
            var value = InputSanitizer.SanitizeString(userName, 80);
            if (string.IsNullOrWhiteSpace(value))
            {
                return new ParentCommandResult { Error = "Child Windows user is missing." };
            }

            if (state.ChildWindowsUserName == value)
            {
                return new ParentCommandResult { Changed = false };
            }

            state.ChildWindowsUserName = value;
            return new ParentCommandResult { Changed = true };
        }

        private static ParentCommandResult DemoteChildWindowsUser(GuardState state, string userName)
        {
            var selectedUser = InputSanitizer.SanitizeString(
                string.IsNullOrWhiteSpace(userName) ? state.ChildWindowsUserName : userName,
                80);
            if (string.IsNullOrWhiteSpace(selectedUser))
            {
                return new ParentCommandResult { Error = "Child Windows user is missing." };
            }

            var status = AccountHardeningEngine.BuildLocalStatus(selectedUser);
            var result = AccountHardeningEngine.DemoteChildFromAdministrators(status);
            if (result.Changed)
            {
                state.ChildWindowsUserName = selectedUser;
            }

            return result;
        }

        private static ParentCommandResult SetUiLanguage(GuardState state, string language)
        {
            var normalized = UiLanguage.Normalize(language);
            if (state.UiLanguage == normalized)
            {
                return new ParentCommandResult { Changed = false };
            }

            state.UiLanguage = normalized;
            return new ParentCommandResult { Changed = true };
        }

        private static void MarkRulesChanged(GuardState state)
        {
            state.UpdateInfo.Rules = true;
            state.UpdateInfo.UpdateApplied = false;
        }

        private static string NormalizeDomain(string? domain)
        {
            return (domain ?? "").Trim().ToLowerInvariant();
        }

        private static int ParseSessionLimit(string? value)
        {
            return int.TryParse(value, out var result) ? result : 0;
        }
    }
}
