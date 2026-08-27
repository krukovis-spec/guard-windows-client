using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;

namespace Guard
{
    public sealed class AccountHardeningStatus
    {
        public string ChildUserName { get; set; } = "";
        public bool CouldReadAdministrators { get; set; } = true;
        public bool ChildIsAdministrator { get; set; }
        public List<string> AdministratorUsers { get; set; } = new List<string>();
        public bool HasSeparateAdministrator { get; set; }
        public bool CanDemoteChild => CouldReadAdministrators && ChildIsAdministrator && HasSeparateAdministrator;
        public string Reason { get; set; } = "";
    }

    public sealed class AccountLockdownSettings
    {
        public bool Enabled { get; set; }
        public bool AutoDisableUnknownUsers { get; set; }
        public DateTime? BaselineCapturedAtUtc { get; set; }
        public DateTime? LastCheckedAtUtc { get; set; }
        public List<string> AllowedLocalUsers { get; set; } = new List<string>();
        public List<string> LastSuspiciousUsers { get; set; } = new List<string>();
        public List<string> LastRemediatedUsers { get; set; } = new List<string>();
    }

    public sealed class AccountLockdownUserStatus
    {
        public string UserName { get; set; } = "";
        public bool IsAdministrator { get; set; }
        public bool IsAllowed { get; set; }
        public bool IsBuiltIn { get; set; }
        public bool IsSuspicious { get; set; }
        public bool CanDisable { get; set; }
        public bool CanRemoveFromAdministrators { get; set; }
    }

    public sealed class AccountLockdownStatus
    {
        public bool Enabled { get; set; }
        public bool AutoDisableUnknownUsers { get; set; }
        public bool CouldReadUsers { get; set; } = true;
        public bool CouldReadAdministrators { get; set; } = true;
        public bool HasSeparateAllowedAdministrator { get; set; }
        public List<string> AllowedLocalUsers { get; set; } = new List<string>();
        public List<AccountLockdownUserStatus> Users { get; set; } = new List<AccountLockdownUserStatus>();
        public List<AccountLockdownUserStatus> SuspiciousUsers { get; set; } = new List<AccountLockdownUserStatus>();
        public string Reason { get; set; } = "";
    }

    public static class AccountHardeningEngine
    {
        private static readonly HashSet<string> BuiltInLocalUsers = new HashSet<string>(
            new[]
            {
                "administrator",
                "администратор",
                "guest",
                "гость",
                "defaultaccount",
                "wdagutilityaccount"
            },
            StringComparer.OrdinalIgnoreCase);

        public static AccountHardeningStatus BuildStatus(
            string childUserName,
            bool childIsAdministrator,
            IEnumerable<string> administratorUsers)
        {
            var child = NormalizeUserName(childUserName);
            var admins = (administratorUsers ?? Enumerable.Empty<string>())
                .Select(NormalizeUserName)
                .Where(item => item.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            var hasSeparateAdmin = admins.Any(admin =>
                !UserMatches(admin, child));

            var status = new AccountHardeningStatus
            {
                ChildUserName = child,
                ChildIsAdministrator = childIsAdministrator,
                AdministratorUsers = admins,
                HasSeparateAdministrator = hasSeparateAdmin
            };

            if (child.Length == 0)
            {
                status.Reason = "Child Windows user is not selected.";
            }
            else if (!childIsAdministrator)
            {
                status.Reason = "Child account is already standard user.";
            }
            else if (!hasSeparateAdmin)
            {
                status.Reason = "Cannot demote child account because no separate administrator account was found.";
            }
            else
            {
                status.Reason = "Child account can be converted to standard user.";
            }

            return status;
        }

        public static AccountHardeningStatus BuildLocalStatus(string childUserName)
        {
            var child = NormalizeUserName(childUserName);
            var groupName = GetBuiltinAdministratorsGroupName();
            var result = SystemCommandRunnerProvider.Current.Run(
                "net.exe",
                "localgroup " + Quote(groupName),
                captureOutput: true);

            if (!result.Started || result.ExitCode != 0)
            {
                return new AccountHardeningStatus
                {
                    ChildUserName = child,
                    CouldReadAdministrators = false,
                    Reason = "Could not read local Administrators group."
                };
            }

            var admins = ParseLocalGroupUsers(result.Output);
            var childIsAdmin = admins.Any(admin => UserMatches(admin, child));
            return BuildStatus(child, childIsAdmin, admins);
        }

        public static ParentCommandResult DemoteChildFromAdministrators(AccountHardeningStatus status)
        {
            if (status == null) throw new ArgumentNullException(nameof(status));
            if (!status.CanDemoteChild)
            {
                return new ParentCommandResult { Error = status.Reason };
            }

            if (!IsSafeLocalUserName(status.ChildUserName))
            {
                return new ParentCommandResult { Error = "Child user name is not safe for account command." };
            }

            var groupName = GetBuiltinAdministratorsGroupName();
            var result = SystemCommandRunnerProvider.Current.Run(
                "net.exe",
                "localgroup " + Quote(groupName) + " " + Quote(status.ChildUserName) + " /delete",
                captureOutput: true);
            if (!result.Started || result.ExitCode != 0)
            {
                return new ParentCommandResult { Error = "Could not convert child account to standard user." };
            }

            return new ParentCommandResult { Changed = true };
        }

        public static AccountLockdownStatus BuildLocalLockdownStatus(GuardState state)
        {
            if (state == null) throw new ArgumentNullException(nameof(state));
            EnsureLockdownSettings(state);

            var usersResult = SystemCommandRunnerProvider.Current.Run("net.exe", "user", captureOutput: true);
            if (!usersResult.Started || usersResult.ExitCode != 0)
            {
                return new AccountLockdownStatus
                {
                    Enabled = state.AccountLockdown.Enabled,
                    AutoDisableUnknownUsers = state.AccountLockdown.AutoDisableUnknownUsers,
                    CouldReadUsers = false,
                    AllowedLocalUsers = NormalizeUsers(state.AccountLockdown.AllowedLocalUsers).ToList(),
                    Reason = "Could not read local Windows users."
                };
            }

            var groupName = GetBuiltinAdministratorsGroupName();
            var adminsResult = SystemCommandRunnerProvider.Current.Run(
                "net.exe",
                "localgroup " + Quote(groupName),
                captureOutput: true);
            if (!adminsResult.Started || adminsResult.ExitCode != 0)
            {
                return new AccountLockdownStatus
                {
                    Enabled = state.AccountLockdown.Enabled,
                    AutoDisableUnknownUsers = state.AccountLockdown.AutoDisableUnknownUsers,
                    CouldReadAdministrators = false,
                    AllowedLocalUsers = NormalizeUsers(state.AccountLockdown.AllowedLocalUsers).ToList(),
                    Reason = "Could not read local Administrators group."
                };
            }

            return BuildLockdownStatus(
                state.AccountLockdown,
                ParseLocalUsers(usersResult.Output),
                ParseLocalGroupUsers(adminsResult.Output));
        }

        public static AccountLockdownStatus BuildLockdownStatus(
            AccountLockdownSettings settings,
            IEnumerable<string> localUsers,
            IEnumerable<string> administratorUsers)
        {
            settings = settings ?? new AccountLockdownSettings();
            var allowed = NormalizeUsers(settings.AllowedLocalUsers).ToList();
            var localUserList = NormalizeUsers(localUsers).ToList();
            var admins = NormalizeUsers(administratorUsers).ToList();
            var hasSeparateAllowedAdmin = admins.Any(admin => UserInList(admin, allowed));
            var users = new List<AccountLockdownUserStatus>();

            foreach (var user in localUserList)
            {
                var isBuiltIn = IsBuiltInLocalUser(user);
                var isAllowed = isBuiltIn || UserInList(user, allowed);
                var isAdmin = admins.Any(admin => UserMatches(admin, user));
                var isSuspicious = settings.Enabled && !isAllowed;
                users.Add(new AccountLockdownUserStatus
                {
                    UserName = user,
                    IsAdministrator = isAdmin,
                    IsAllowed = isAllowed,
                    IsBuiltIn = isBuiltIn,
                    IsSuspicious = isSuspicious,
                    CanDisable = isSuspicious && hasSeparateAllowedAdmin && IsSafeLocalUserName(user),
                    CanRemoveFromAdministrators = isSuspicious && isAdmin && hasSeparateAllowedAdmin && IsSafeLocalUserName(user)
                });
            }

            var suspicious = users.Where(user => user.IsSuspicious).ToList();
            var status = new AccountLockdownStatus
            {
                Enabled = settings.Enabled,
                AutoDisableUnknownUsers = settings.AutoDisableUnknownUsers,
                HasSeparateAllowedAdministrator = hasSeparateAllowedAdmin,
                AllowedLocalUsers = allowed,
                Users = users,
                SuspiciousUsers = suspicious
            };

            if (!settings.Enabled)
            {
                status.Reason = "Windows account lockdown is not armed.";
            }
            else if (!hasSeparateAllowedAdmin)
            {
                status.Reason = "Lockdown needs at least one trusted administrator account.";
            }
            else if (suspicious.Count == 0)
            {
                status.Reason = "No unknown Windows users detected.";
            }
            else
            {
                status.Reason = "Unknown Windows users detected: " + string.Join(", ", suspicious.Select(user => user.UserName));
            }

            return status;
        }

        public static ParentCommandResult CaptureLocalUsersBaseline(GuardState state, DateTime utcNow)
        {
            if (state == null) throw new ArgumentNullException(nameof(state));
            EnsureLockdownSettings(state);

            var usersResult = SystemCommandRunnerProvider.Current.Run("net.exe", "user", captureOutput: true);
            if (!usersResult.Started || usersResult.ExitCode != 0)
            {
                return new ParentCommandResult { Error = "Could not read local Windows users." };
            }

            var users = ParseLocalUsers(usersResult.Output)
                .Where(user => !IsBuiltInLocalUser(user))
                .ToList();
            if (users.Count == 0)
            {
                return new ParentCommandResult { Error = "No local Windows users were found." };
            }

            state.AccountLockdown.Enabled = true;
            state.AccountLockdown.AutoDisableUnknownUsers = true;
            state.AccountLockdown.BaselineCapturedAtUtc = utcNow;
            state.AccountLockdown.AllowedLocalUsers = users;
            state.AccountLockdown.LastSuspiciousUsers = new List<string>();
            state.AccountLockdown.LastRemediatedUsers = new List<string>();
            return new ParentCommandResult { Changed = true };
        }

        public static ParentCommandResult TrustLocalUser(GuardState state, string userName)
        {
            if (state == null) throw new ArgumentNullException(nameof(state));
            EnsureLockdownSettings(state);

            var user = NormalizeUserName(userName);
            if (!IsSafeLocalUserName(user))
            {
                return new ParentCommandResult { Error = "Windows user name is not safe." };
            }

            if (UserInList(user, state.AccountLockdown.AllowedLocalUsers))
            {
                return new ParentCommandResult { Changed = false };
            }

            state.AccountLockdown.AllowedLocalUsers.Add(user);
            state.AccountLockdown.Enabled = true;
            return new ParentCommandResult { Changed = true };
        }

        public static ParentCommandResult DisableLocalUser(GuardState state, string userName)
        {
            var status = BuildLocalLockdownStatus(state);
            var target = FindUserStatus(status, userName);
            if (target == null)
            {
                return new ParentCommandResult { Error = "Windows user was not found." };
            }

            if (!target.CanDisable)
            {
                return new ParentCommandResult { Error = "Windows user cannot be disabled safely." };
            }

            return DisableLocalUser(target.UserName);
        }

        public static ParentCommandResult RemoveLocalUserFromAdministrators(GuardState state, string userName)
        {
            var status = BuildLocalLockdownStatus(state);
            var target = FindUserStatus(status, userName);
            if (target == null)
            {
                return new ParentCommandResult { Error = "Windows user was not found." };
            }

            if (!target.CanRemoveFromAdministrators)
            {
                return new ParentCommandResult { Error = "Windows user cannot be removed from administrators safely." };
            }

            return RemoveUserFromAdministrators(target.UserName);
        }

        public static ParentCommandResult EnforceLocalAccountLockdown(GuardState state, DateTime utcNow, Action<string>? log = null)
        {
            if (state == null) throw new ArgumentNullException(nameof(state));
            EnsureLockdownSettings(state);

            if (!state.AccountLockdown.Enabled || !state.AccountLockdown.AutoDisableUnknownUsers)
            {
                return new ParentCommandResult { Changed = false };
            }

            var status = BuildLocalLockdownStatus(state);
            state.AccountLockdown.LastCheckedAtUtc = utcNow;
            state.AccountLockdown.LastSuspiciousUsers = status.SuspiciousUsers.Select(user => user.UserName).ToList();

            if (!status.HasSeparateAllowedAdministrator)
            {
                log?.Invoke("[AccountLockdown] Skipped auto-disable: no trusted administrator found.");
                return new ParentCommandResult { Error = status.Reason };
            }

            bool changed = false;
            var remediated = new List<string>();
            foreach (var user in status.SuspiciousUsers)
            {
                if (user.CanRemoveFromAdministrators)
                {
                    var removeAdmin = RemoveUserFromAdministrators(user.UserName);
                    if (!string.IsNullOrWhiteSpace(removeAdmin.Error))
                    {
                        log?.Invoke("[AccountLockdown] Could not remove unknown user from Administrators: " + user.UserName);
                    }
                    changed |= removeAdmin.Changed;
                }

                if (user.CanDisable)
                {
                    var disable = DisableLocalUser(user.UserName);
                    if (disable.Changed)
                    {
                        remediated.Add(user.UserName);
                        log?.Invoke("[AccountLockdown] Disabled unknown Windows user: " + user.UserName);
                    }
                    else if (!string.IsNullOrWhiteSpace(disable.Error))
                    {
                        log?.Invoke("[AccountLockdown] Could not disable unknown Windows user: " + user.UserName);
                    }

                    changed |= disable.Changed;
                }
            }

            state.AccountLockdown.LastRemediatedUsers = remediated;
            return new ParentCommandResult { Changed = changed };
        }

        public static IReadOnlyList<string> ParseLocalUsers(string output)
        {
            var users = new List<string>();
            bool inUsers = false;
            foreach (var rawLine in (output ?? "").Split(new[] { "\r\n", "\n" }, StringSplitOptions.None))
            {
                var line = rawLine.Trim();
                if (line.Length == 0)
                {
                    continue;
                }

                if (line.StartsWith("---", StringComparison.Ordinal))
                {
                    inUsers = true;
                    continue;
                }

                if (!inUsers)
                {
                    continue;
                }

                if (line.StartsWith("The command completed", StringComparison.OrdinalIgnoreCase) ||
                    line.StartsWith("Команда выполнена", StringComparison.OrdinalIgnoreCase))
                {
                    break;
                }

                users.AddRange(line
                    .Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(NormalizeUserName)
                    .Where(user => user.Length > 0));
            }

            return users.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }

        public static IReadOnlyList<string> ParseLocalGroupUsers(string output)
        {
            var users = new List<string>();
            bool inMembers = false;
            foreach (var rawLine in (output ?? "").Split(new[] { "\r\n", "\n" }, StringSplitOptions.None))
            {
                var line = rawLine.Trim();
                if (line.Length == 0)
                {
                    continue;
                }

                if (line.StartsWith("---", StringComparison.Ordinal))
                {
                    inMembers = true;
                    continue;
                }

                if (!inMembers)
                {
                    continue;
                }

                if (line.StartsWith("The command completed", StringComparison.OrdinalIgnoreCase) ||
                    line.StartsWith("Команда выполнена", StringComparison.OrdinalIgnoreCase))
                {
                    break;
                }

                users.Add(NormalizeUserName(line));
            }

            return users.Where(item => item.Length > 0).ToList();
        }

        private static ParentCommandResult DisableLocalUser(string userName)
        {
            if (!IsSafeLocalUserName(userName))
            {
                return new ParentCommandResult { Error = "Windows user name is not safe." };
            }

            var result = SystemCommandRunnerProvider.Current.Run(
                "net.exe",
                "user " + Quote(userName) + " /active:no",
                captureOutput: true);
            if (!result.Started || result.ExitCode != 0)
            {
                return new ParentCommandResult { Error = "Could not disable Windows user." };
            }

            return new ParentCommandResult { Changed = true };
        }

        private static ParentCommandResult RemoveUserFromAdministrators(string userName)
        {
            if (!IsSafeLocalUserName(userName))
            {
                return new ParentCommandResult { Error = "Windows user name is not safe." };
            }

            var groupName = GetBuiltinAdministratorsGroupName();
            var result = SystemCommandRunnerProvider.Current.Run(
                "net.exe",
                "localgroup " + Quote(groupName) + " " + Quote(userName) + " /delete",
                captureOutput: true);
            if (!result.Started || result.ExitCode != 0)
            {
                return new ParentCommandResult { Error = "Could not remove Windows user from Administrators." };
            }

            return new ParentCommandResult { Changed = true };
        }

        private static AccountLockdownUserStatus? FindUserStatus(AccountLockdownStatus status, string userName)
        {
            var user = NormalizeUserName(userName);
            return status.Users.FirstOrDefault(item => UserMatches(item.UserName, user));
        }

        private static IEnumerable<string> NormalizeUsers(IEnumerable<string> users)
        {
            return (users ?? Enumerable.Empty<string>())
                .Select(NormalizeUserName)
                .Where(item => item.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase);
        }

        private static bool UserInList(string userName, IEnumerable<string> users)
        {
            return (users ?? Enumerable.Empty<string>()).Any(item => UserMatches(item, userName));
        }

        private static bool IsBuiltInLocalUser(string userName)
        {
            return BuiltInLocalUsers.Contains(GetLeafUserName(userName));
        }

        private static void EnsureLockdownSettings(GuardState state)
        {
            if (state.AccountLockdown == null)
            {
                state.AccountLockdown = new AccountLockdownSettings();
            }

            if (state.AccountLockdown.AllowedLocalUsers == null)
            {
                state.AccountLockdown.AllowedLocalUsers = new List<string>();
            }

            if (state.AccountLockdown.LastSuspiciousUsers == null)
            {
                state.AccountLockdown.LastSuspiciousUsers = new List<string>();
            }

            if (state.AccountLockdown.LastRemediatedUsers == null)
            {
                state.AccountLockdown.LastRemediatedUsers = new List<string>();
            }
        }

        private static bool IsSafeLocalUserName(string userName)
        {
            var value = NormalizeUserName(userName);
            return value.Length > 0 &&
                   value.Length <= 80 &&
                   value.IndexOfAny(new[] { '\0', '\r', '\n', '&', '|', '<', '>', '^' }) < 0;
        }

        private static string NormalizeUserName(string? userName)
        {
            return (userName ?? "").Trim();
        }

        private static bool UserMatches(string adminName, string childName)
        {
            if (string.Equals(adminName, childName, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return string.Equals(GetLeafUserName(adminName), GetLeafUserName(childName), StringComparison.OrdinalIgnoreCase);
        }

        private static string GetLeafUserName(string userName)
        {
            var value = NormalizeUserName(userName);
            var slash = value.LastIndexOf('\\');
            return slash >= 0 && slash + 1 < value.Length ? value.Substring(slash + 1) : value;
        }

        private static string Quote(string value)
        {
            return "\"" + value.Replace("\"", "\\\"") + "\"";
        }

        private static string GetBuiltinAdministratorsGroupName()
        {
            try
            {
                var sid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                var account = (NTAccount)sid.Translate(typeof(NTAccount));
                var value = account.Value ?? "Administrators";
                var slash = value.LastIndexOf('\\');
                return slash >= 0 && slash + 1 < value.Length ? value.Substring(slash + 1) : value;
            }
            catch
            {
                return "Administrators";
            }
        }
    }
}
