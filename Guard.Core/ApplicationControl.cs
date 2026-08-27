using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Guard
{
    public enum ApplicationControlMode
    {
        Off = 0,
        AuditOnly = 1,
        Enforced = 2
    }

    public class ApplicationControlSettings
    {
        public ApplicationControlMode Mode { get; set; } = ApplicationControlMode.Off;
        public int WarningMinutes { get; set; } = 5;
        public string TargetUserOrGroupSid { get; set; } = "S-1-5-32-545";
        public bool BlockTaskManager { get; set; } = true;
        public DateTime? TaskManagerAllowedUntilUtc { get; set; }
        public bool PolicyUpdatePending { get; set; } = false;
        public int PolicySchemaVersion { get; set; } = 0;
        public List<AllowedApplication> AllowedApplications { get; set; } = new List<AllowedApplication>();
    }

    public class AllowedApplication
    {
        public string Id { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public string FilePath { get; set; } = "";
        public DateTime AddedAtUtc { get; set; } = DateTime.UtcNow;
        public DateTime? AllowedUntilUtc { get; set; }
        public DateTime? LastWarningUtc { get; set; }
        public List<int> WarningMinuteMarksShown { get; set; } = new List<int>();
        public bool IsTemporary { get; set; }
        public bool ExpirationApplied { get; set; }
    }

    public sealed class ApplicationControlWarning
    {
        public AllowedApplication Application { get; set; } = new AllowedApplication();
        public int MinutesLeft { get; set; }
    }

    public sealed class RunningApplication
    {
        public int ProcessId { get; set; }
        public string FilePath { get; set; } = "";
    }

    public sealed class ApplicationControlTickResult
    {
        public bool Changed { get; set; }
        public List<ApplicationControlWarning> WarningApplications { get; } = new List<ApplicationControlWarning>();
        public List<RunningApplication> ExpiredRunningApplications { get; } = new List<RunningApplication>();
        public List<RunningApplication> BlockedManagementTools { get; } = new List<RunningApplication>();
    }

    public static class ApplicationControlApplier
    {
        private static readonly HashSet<string> BlockedManagementToolFileNames = new HashSet<string>(
            new[]
            {
                "taskmgr.exe",
                "taskkill.exe",
                "tskill.exe",
                "cmd.exe",
                "powershell.exe",
                "powershell_ise.exe",
                "pwsh.exe",
                "reg.exe",
                "regedit.exe",
                "wmic.exe",
                "mmc.exe",
                "control.exe",
                "systemsettings.exe",
                "netplwiz.exe",
                "runas.exe",
                "compmgmtlauncher.exe",
                "useraccountcontrolsettings.exe",
                "schtasks.exe",
                "sc.exe",
                "net.exe",
                "net1.exe",
                "wscript.exe",
                "cscript.exe"
            },
            StringComparer.OrdinalIgnoreCase);

        public static ParentCommandResult SetMode(GuardState state, ApplicationControlMode mode)
        {
            if (state == null) throw new ArgumentNullException(nameof(state));
            EnsureSettings(state);

            if (state.AppControl.Mode == mode)
            {
                return new ParentCommandResult { Changed = false };
            }

            state.AppControl.Mode = mode;
            state.AppControl.PolicyUpdatePending = true;
            return new ParentCommandResult { Changed = true };
        }

        public static ParentCommandResult AddPermanentApplication(GuardState state, string filePath, string displayName, DateTime utcNow)
        {
            return AddOrUpdateApplication(state, filePath, displayName, null, isTemporary: false, utcNow: utcNow);
        }

        public static ParentCommandResult GrantTemporaryApplication(GuardState state, string filePath, string displayName, int minutes, DateTime utcNow)
        {
            if (minutes < 1 || minutes > 24 * 60)
            {
                return new ParentCommandResult { Error = "Time grant must be from 1 to 1440 minutes." };
            }

            return AddOrUpdateApplication(state, filePath, displayName, utcNow.AddMinutes(minutes), isTemporary: true, utcNow: utcNow);
        }

        public static ParentCommandResult RemoveApplication(GuardState state, string filePath)
        {
            if (state == null) throw new ArgumentNullException(nameof(state));
            EnsureSettings(state);

            var normalized = NormalizeExecutablePath(filePath);
            if (normalized == null)
            {
                return new ParentCommandResult { Error = "Invalid application path." };
            }

            var id = BuildApplicationId(normalized);
            int removed = state.AppControl.AllowedApplications.RemoveAll(app => app.Id == id);
            if (removed == 0)
            {
                return new ParentCommandResult { Changed = false };
            }

            state.AppControl.PolicyUpdatePending = true;
            return new ParentCommandResult { Changed = true };
        }

        public static ParentCommandResult GrantTaskManagerAccess(GuardState state, int minutes, DateTime utcNow)
        {
            if (state == null) throw new ArgumentNullException(nameof(state));
            EnsureSettings(state);

            if (minutes < 1 || minutes > 120)
            {
                return new ParentCommandResult { Error = "Maintenance access must be from 1 to 120 minutes." };
            }

            state.AppControl.BlockTaskManager = true;
            state.AppControl.TaskManagerAllowedUntilUtc = utcNow.AddMinutes(minutes);
            state.AppControl.PolicyUpdatePending = true;
            return new ParentCommandResult { Changed = true };
        }

        public static ParentCommandResult BlockTaskManagerNow(GuardState state)
        {
            if (state == null) throw new ArgumentNullException(nameof(state));
            EnsureSettings(state);

            if (state.AppControl.BlockTaskManager && !state.AppControl.TaskManagerAllowedUntilUtc.HasValue)
            {
                return new ParentCommandResult { Changed = false };
            }

            state.AppControl.BlockTaskManager = true;
            state.AppControl.TaskManagerAllowedUntilUtc = null;
            state.AppControl.PolicyUpdatePending = true;
            return new ParentCommandResult { Changed = true };
        }

        public static bool IsTaskManagerBlocked(ApplicationControlSettings settings, DateTime utcNow)
        {
            return settings != null &&
                   settings.BlockTaskManager &&
                   (!settings.TaskManagerAllowedUntilUtc.HasValue || settings.TaskManagerAllowedUntilUtc.Value <= utcNow);
        }

        public static bool IsBlockedManagementToolFileName(string? fileName)
        {
            var safeFileName = (fileName ?? "").Trim();
            if (safeFileName.Length == 0)
            {
                return false;
            }

            return BlockedManagementToolFileNames.Contains(safeFileName);
        }

        public static string DescribeTaskManagerStatus(ApplicationControlSettings settings, DateTime utcNow)
        {
            if (settings == null)
            {
                return "Диспетчер задач и системные инструменты разрешены";
            }

            if (IsTaskManagerBlocked(settings, utcNow))
            {
                return "Диспетчер задач и системные инструменты заблокированы";
            }

            if (settings.BlockTaskManager &&
                settings.TaskManagerAllowedUntilUtc.HasValue &&
                settings.TaskManagerAllowedUntilUtc.Value > utcNow)
            {
                return "Диспетчер задач и системные инструменты разрешены до " +
                       settings.TaskManagerAllowedUntilUtc.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm");
            }

            return "Диспетчер задач и системные инструменты разрешены";
        }

        public static IReadOnlyList<AllowedApplication> GetActiveAllowedApplications(ApplicationControlSettings settings, DateTime utcNow)
        {
            if (settings == null)
            {
                return Array.Empty<AllowedApplication>();
            }

            return settings.AllowedApplications
                .Where(app => IsApplicationActive(app, utcNow))
                .OrderBy(app => app.DisplayName)
                .ToList();
        }

        public static bool IsApplicationActive(AllowedApplication app, DateTime utcNow)
        {
            return app != null && (!app.AllowedUntilUtc.HasValue || app.AllowedUntilUtc.Value > utcNow);
        }

        public static string BuildApplicationId(string filePath)
        {
            var normalized = (NormalizeExecutablePath(filePath) ?? filePath).ToLowerInvariant();
            using (var sha = SHA256.Create())
            {
                var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(normalized));
                return "app:" + BitConverter.ToString(bytes, 0, 8).Replace("-", "").ToLowerInvariant();
            }
        }

        public static string? NormalizeExecutablePath(string? filePath)
        {
            var value = (filePath ?? "").Trim().Trim('"');
            if (value.Length == 0 ||
                value.IndexOfAny(new[] { '\0', '\r', '\n' }) >= 0)
            {
                return null;
            }

            string fullPath;
            try
            {
                fullPath = Path.GetFullPath(Environment.ExpandEnvironmentVariables(value));
            }
            catch
            {
                return null;
            }

            if (!Path.IsPathRooted(fullPath))
            {
                return null;
            }

            var extension = Path.GetExtension(fullPath);
            if (!string.Equals(extension, ".exe", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(extension, ".com", StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            return fullPath;
        }

        private static ParentCommandResult AddOrUpdateApplication(
            GuardState state,
            string filePath,
            string displayName,
            DateTime? allowedUntilUtc,
            bool isTemporary,
            DateTime utcNow)
        {
            if (state == null) throw new ArgumentNullException(nameof(state));
            EnsureSettings(state);

            var normalized = NormalizeExecutablePath(filePath);
            if (normalized == null)
            {
                return new ParentCommandResult { Error = "Invalid application path." };
            }

            var id = BuildApplicationId(normalized);
            var name = InputSanitizer.SanitizeString(displayName, 80);
            if (string.IsNullOrWhiteSpace(name))
            {
                name = Path.GetFileNameWithoutExtension(normalized);
            }

            var existing = state.AppControl.AllowedApplications.FirstOrDefault(app => app.Id == id);
            if (existing == null)
            {
                state.AppControl.AllowedApplications.Add(new AllowedApplication
                {
                    Id = id,
                    DisplayName = name,
                    FilePath = normalized,
                    AddedAtUtc = utcNow,
                    AllowedUntilUtc = allowedUntilUtc,
                    IsTemporary = isTemporary,
                    ExpirationApplied = false
                });
            }
            else
            {
                bool changed = existing.DisplayName != name ||
                               existing.FilePath != normalized ||
                               existing.AllowedUntilUtc != allowedUntilUtc ||
                               existing.IsTemporary != isTemporary ||
                               existing.ExpirationApplied;
                if (!changed)
                {
                    return new ParentCommandResult { Changed = false };
                }

                existing.DisplayName = name;
                existing.FilePath = normalized;
                existing.AllowedUntilUtc = allowedUntilUtc;
                existing.IsTemporary = isTemporary;
                existing.ExpirationApplied = false;
                existing.LastWarningUtc = null;
                existing.WarningMinuteMarksShown = new List<int>();
            }

            state.AppControl.PolicyUpdatePending = true;
            return new ParentCommandResult { Changed = true };
        }

        private static void EnsureSettings(GuardState state)
        {
            if (state.AppControl == null)
            {
                state.AppControl = new ApplicationControlSettings();
            }

            if (state.AppControl.AllowedApplications == null)
            {
                state.AppControl.AllowedApplications = new List<AllowedApplication>();
            }

            if (state.AppControl.WarningMinutes <= 0)
            {
                state.AppControl.WarningMinutes = 5;
            }

            if (string.IsNullOrWhiteSpace(state.AppControl.TargetUserOrGroupSid))
            {
                state.AppControl.TargetUserOrGroupSid = "S-1-5-32-545";
            }

            foreach (var app in state.AppControl.AllowedApplications)
            {
                if (app.WarningMinuteMarksShown == null)
                {
                    app.WarningMinuteMarksShown = new List<int>();
                }
            }
        }
    }

    public static class ApplicationControlRuntime
    {
        public static ApplicationControlTickResult Evaluate(
            ApplicationControlSettings settings,
            IEnumerable<RunningApplication> runningApplications,
            DateTime utcNow)
        {
            var result = new ApplicationControlTickResult();
            if (settings == null || settings.Mode == ApplicationControlMode.Off)
            {
                return result;
            }

            var runningList = (runningApplications ?? Enumerable.Empty<RunningApplication>())
                .Where(app => app != null)
                .ToList();

            var runningByPath = runningList
                .Where(app => !string.IsNullOrWhiteSpace(app.FilePath))
                .GroupBy(app => app.FilePath, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(group => group.Key, group => group.ToList(), StringComparer.OrdinalIgnoreCase);

            if (settings.BlockTaskManager && settings.TaskManagerAllowedUntilUtc.HasValue && settings.TaskManagerAllowedUntilUtc.Value <= utcNow)
            {
                settings.TaskManagerAllowedUntilUtc = null;
                settings.PolicyUpdatePending = true;
                result.Changed = true;
            }

            if (ApplicationControlApplier.IsTaskManagerBlocked(settings, utcNow))
            {
                result.BlockedManagementTools.AddRange(runningList.Where(IsBlockedManagementToolProcess));
            }

            int warningMinutes = settings.WarningMinutes <= 0 ? 5 : settings.WarningMinutes;
            foreach (var app in settings.AllowedApplications ?? new List<AllowedApplication>())
            {
                if (!app.AllowedUntilUtc.HasValue)
                {
                    continue;
                }

                var remaining = app.AllowedUntilUtc.Value - utcNow;
                if (remaining <= TimeSpan.Zero)
                {
                    if (!app.ExpirationApplied)
                    {
                        app.ExpirationApplied = true;
                        app.LastWarningUtc = null;
                        app.WarningMinuteMarksShown = new List<int>();
                        settings.PolicyUpdatePending = true;
                        result.Changed = true;
                    }

                    if (runningByPath.TryGetValue(app.FilePath, out var expiredRunning))
                    {
                        result.ExpiredRunningApplications.AddRange(expiredRunning);
                    }

                    continue;
                }

                if (remaining <= TimeSpan.FromMinutes(warningMinutes) &&
                    runningByPath.ContainsKey(app.FilePath))
                {
                    int minuteMark = Math.Max(1, (int)Math.Ceiling(remaining.TotalMinutes));
                    if (app.WarningMinuteMarksShown == null)
                    {
                        app.WarningMinuteMarksShown = new List<int>();
                    }
                    if (app.WarningMinuteMarksShown.Contains(minuteMark))
                    {
                        continue;
                    }

                    app.LastWarningUtc = utcNow;
                    app.WarningMinuteMarksShown.Add(minuteMark);
                    result.WarningApplications.Add(new ApplicationControlWarning
                    {
                        Application = app,
                        MinutesLeft = minuteMark
                    });
                    result.Changed = true;
                }
            }

            return result;
        }

        private static bool IsBlockedManagementToolProcess(RunningApplication app)
        {
            return app != null &&
                   ApplicationControlApplier.IsBlockedManagementToolFileName(Path.GetFileName(app.FilePath));
        }
    }

    public static class ApplicationControlPolicyManager
    {
        public const int CurrentPolicySchemaVersion = 3;

        private static readonly string[] BlockedManagementToolRelativePaths =
        {
            @"System32\Taskmgr.exe",
            @"SysWOW64\Taskmgr.exe",
            @"System32\taskkill.exe",
            @"SysWOW64\taskkill.exe",
            @"System32\tskill.exe",
            @"SysWOW64\tskill.exe",
            @"System32\cmd.exe",
            @"SysWOW64\cmd.exe",
            @"System32\WindowsPowerShell\v1.0\powershell.exe",
            @"SysWOW64\WindowsPowerShell\v1.0\powershell.exe",
            @"System32\WindowsPowerShell\v1.0\powershell_ise.exe",
            @"SysWOW64\WindowsPowerShell\v1.0\powershell_ise.exe",
            @"System32\reg.exe",
            @"SysWOW64\reg.exe",
            @"regedit.exe",
            @"System32\wbem\WMIC.exe",
            @"SysWOW64\wbem\WMIC.exe",
            @"System32\mmc.exe",
            @"SysWOW64\mmc.exe",
            @"System32\control.exe",
            @"SysWOW64\control.exe",
            @"ImmersiveControlPanel\SystemSettings.exe",
            @"System32\netplwiz.exe",
            @"SysWOW64\netplwiz.exe",
            @"System32\runas.exe",
            @"SysWOW64\runas.exe",
            @"System32\CompMgmtLauncher.exe",
            @"SysWOW64\CompMgmtLauncher.exe",
            @"System32\UserAccountControlSettings.exe",
            @"SysWOW64\UserAccountControlSettings.exe",
            @"System32\schtasks.exe",
            @"SysWOW64\schtasks.exe",
            @"System32\sc.exe",
            @"SysWOW64\sc.exe",
            @"System32\net.exe",
            @"SysWOW64\net.exe",
            @"System32\net1.exe",
            @"SysWOW64\net1.exe",
            @"System32\wscript.exe",
            @"SysWOW64\wscript.exe",
            @"System32\cscript.exe",
            @"SysWOW64\cscript.exe"
        };

        private static readonly string[] BlockedManagementToolProgramFilesRelativePaths =
        {
            @"PowerShell\7\pwsh.exe",
            @"PowerShell\7-preview\pwsh.exe"
        };

        public static IReadOnlyList<string> BuildAllowedPaths(GuardState state, string guardExecutablePath, DateTime utcNow)
        {
            var paths = new List<string>();
            AddIfValid(paths, guardExecutablePath);

            var baseDirectory = Path.GetDirectoryName(guardExecutablePath);
            if (!string.IsNullOrWhiteSpace(baseDirectory))
            {
                AddIfValid(paths, Path.Combine(baseDirectory, "guard.exe"));
                AddIfValid(paths, Path.Combine(baseDirectory, "StartHelperG.exe"));
                AddIfValid(paths, Path.Combine(baseDirectory, "Guard.Cleaner.exe"));
            }

            foreach (var app in ApplicationControlApplier.GetActiveAllowedApplications(state.AppControl, utcNow))
            {
                if (TimeLimitEngine.IsApplicationAllowedByTimeLimits(state, app.FilePath, utcNow))
                {
                    AddIfValid(paths, app.FilePath);
                }
            }

            return paths
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        public static IReadOnlyList<string> BuildBlockedManagementToolPaths()
        {
            var paths = new List<string>();
            var windowsDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (string.IsNullOrWhiteSpace(windowsDirectory))
            {
                windowsDirectory = Environment.ExpandEnvironmentVariables("%WINDIR%");
            }

            if (string.IsNullOrWhiteSpace(windowsDirectory) || windowsDirectory.Contains("%"))
            {
                windowsDirectory = @"C:\Windows";
            }

            foreach (var relativePath in BlockedManagementToolRelativePaths)
            {
                AddIfValid(paths, Path.Combine(windowsDirectory, relativePath));
            }

            AddProgramFilesBlockedToolPaths(paths, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
            AddProgramFilesBlockedToolPaths(paths, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));

            return paths
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        public static async Task<bool> ApplyIfNeededAsync(GuardState state, string guardExecutablePath, Action<string>? log = null)
        {
            if (state?.AppControl == null || !NeedsApply(state.AppControl))
            {
                return true;
            }

            if (state.AppControl.Mode != ApplicationControlMode.Off &&
                state.AppControl.PolicySchemaVersion < CurrentPolicySchemaVersion)
            {
                state.AppControl.PolicyUpdatePending = true;
            }

            return await ApplyAsync(state, guardExecutablePath, log);
        }

        public static bool NeedsApply(ApplicationControlSettings settings)
        {
            if (settings == null)
            {
                return false;
            }

            return settings.PolicyUpdatePending ||
                   (settings.Mode != ApplicationControlMode.Off &&
                    settings.PolicySchemaVersion < CurrentPolicySchemaVersion);
        }

        public static string BuildPolicyScriptForDiagnostics()
        {
            return BuildScript();
        }

        public static async Task<bool> ApplyAsync(GuardState state, string guardExecutablePath, Action<string>? log = null)
        {
            return await Task.Run(() =>
            {
                try
                {
                    Directory.CreateDirectory(WorkDirectory);
                    var scriptPath = Path.Combine(WorkDirectory, "apply-applocker-policy.ps1");
                    var allowedPath = Path.Combine(WorkDirectory, "allowed-apps.txt");
                    var blockedToolsPath = Path.Combine(WorkDirectory, "blocked-management-tools.txt");
                    var policyPath = Path.Combine(WorkDirectory, "guard-applocker-policy.xml");
                    var backupPath = Path.Combine(WorkDirectory, "applocker-backup-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + ".xml");

                    File.WriteAllText(scriptPath, BuildScript(), Encoding.UTF8);
                    File.WriteAllLines(allowedPath, BuildAllowedPaths(state, guardExecutablePath, DateTime.UtcNow), Encoding.UTF8);
                    File.WriteAllLines(blockedToolsPath, BuildBlockedManagementToolPaths(), Encoding.UTF8);

                    var mode = state.AppControl.Mode == ApplicationControlMode.Enforced ? "Enabled" :
                        state.AppControl.Mode == ApplicationControlMode.AuditOnly ? "AuditOnly" : "Off";
                    var targetSid = string.IsNullOrWhiteSpace(state.AppControl.TargetUserOrGroupSid)
                        ? "S-1-5-32-545"
                        : state.AppControl.TargetUserOrGroupSid;
                    var guardDirectory = Path.GetDirectoryName(guardExecutablePath) ?? AppDomain.CurrentDomain.BaseDirectory;

                    var blockTaskManager = ApplicationControlApplier.IsTaskManagerBlocked(state.AppControl, DateTime.UtcNow) ? "1" : "0";

                    var args =
                        "-NoProfile -ExecutionPolicy Bypass -File " + Quote(scriptPath) +
                        " -AllowedList " + Quote(allowedPath) +
                        " -BlockedToolsList " + Quote(blockedToolsPath) +
                        " -Mode " + Quote(mode) +
                        " -PolicyXml " + Quote(policyPath) +
                        " -BackupXml " + Quote(backupPath) +
                        " -GuardDirectory " + Quote(guardDirectory) +
                        " -TargetSid " + Quote(targetSid) +
                        " -BlockTaskManager " + Quote(blockTaskManager);

                    var result = SystemCommandRunnerProvider.Current.Run("powershell.exe", args, captureOutput: true);
                    if (!result.Started || result.ExitCode != 0)
                    {
                        log?.Invoke("[AppControl] AppLocker policy apply failed. " + result.Error + " " + result.Output);
                        return false;
                    }

                    state.AppControl.PolicyUpdatePending = false;
                    state.AppControl.PolicySchemaVersion = CurrentPolicySchemaVersion;
                    GuardStateStorage.Save(state);
                    log?.Invoke("[AppControl] AppLocker policy applied in mode: " + mode + ".");
                    return true;
                }
                catch (Exception ex)
                {
                    log?.Invoke("[AppControl] Error applying AppLocker policy: " + ex.Message);
                    return false;
                }
            });
        }

        private static string WorkDirectory
        {
            get
            {
                var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Guard", "applocker");
                Directory.CreateDirectory(root);
                return root;
            }
        }

        private static void AddIfValid(List<string> paths, string? path)
        {
            var normalized = ApplicationControlApplier.NormalizeExecutablePath(path);
            if (!string.IsNullOrWhiteSpace(normalized))
            {
                paths.Add(normalized!);
            }
        }

        private static void AddProgramFilesBlockedToolPaths(List<string> paths, string programFilesDirectory)
        {
            if (string.IsNullOrWhiteSpace(programFilesDirectory))
            {
                return;
            }

            foreach (var relativePath in BlockedManagementToolProgramFilesRelativePaths)
            {
                AddIfValid(paths, Path.Combine(programFilesDirectory, relativePath));
            }
        }

        private static string Quote(string value)
        {
            return "\"" + value.Replace("\"", "\\\"") + "\"";
        }

        private static string BuildScript()
        {
            return @"param(
    [string]$AllowedList,
    [string]$BlockedToolsList,
    [string]$Mode,
    [string]$PolicyXml,
    [string]$BackupXml,
    [string]$GuardDirectory,
    [string]$TargetSid,
    [string]$BlockTaskManager
)

$ErrorActionPreference = 'Stop'

function Ensure-Collection([xml]$Policy, [string]$Type, [string]$EnforcementMode) {
    $collection = $Policy.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -eq $Type } | Select-Object -First 1
    if ($null -eq $collection) {
        $collection = $Policy.CreateElement('RuleCollection')
        $collection.SetAttribute('Type', $Type)
        [void]$Policy.AppLockerPolicy.AppendChild($collection)
    }
    $collection.SetAttribute('EnforcementMode', $EnforcementMode)
    return $collection
}

function Add-PathRule([xml]$Policy, $Collection, [string]$Sid, [string]$Name, [string]$Path, [string]$Action = 'Allow') {
    $rule = $Policy.CreateElement('FilePathRule')
    $rule.SetAttribute('Id', [guid]::NewGuid().ToString())
    $rule.SetAttribute('Name', $Name)
    $rule.SetAttribute('Description', '')
    $rule.SetAttribute('UserOrGroupSid', $Sid)
    $rule.SetAttribute('Action', $Action)

    $conditions = $Policy.CreateElement('Conditions')
    $condition = $Policy.CreateElement('FilePathCondition')
    $condition.SetAttribute('Path', $Path)
    [void]$conditions.AppendChild($condition)
    [void]$rule.AppendChild($conditions)
    [void]$Collection.AppendChild($rule)
}

function Remove-BroadProgramFilesAllows([xml]$Policy) {
    $programRoots = @(
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        ${env:ProgramW6432},
        '%PROGRAMFILES%',
        '%PROGRAMFILES(X86)%'
    ) | Where-Object { $_ }

    foreach ($collection in @($Policy.AppLockerPolicy.RuleCollection)) {
        foreach ($rule in @($collection.FilePathRule)) {
            if ($null -eq $rule -or $rule.Action -ne 'Allow') {
                continue
            }

            $path = $rule.Conditions.FilePathCondition.Path
            if ([string]::IsNullOrWhiteSpace($path)) {
                continue
            }

            $isProgramFilesRule = $false
            foreach ($root in $programRoots) {
                $normalizedRoot = $root.TrimEnd('\')
                if ($path -ieq ($normalizedRoot + '\*') -or $path -ilike ($normalizedRoot + '\*')) {
                    $isProgramFilesRule = $true
                    break
                }
            }

            if ($isProgramFilesRule) {
                [void]$collection.RemoveChild($rule)
            }
        }
    }
}

try {
    Get-AppLockerPolicy -Local -Xml | Out-File -LiteralPath $BackupXml -Encoding UTF8
} catch {
}

if ($Mode -eq 'Off') {
    $clear = '<AppLockerPolicy Version=""1""><RuleCollection Type=""Exe"" EnforcementMode=""NotConfigured"" /><RuleCollection Type=""Msi"" EnforcementMode=""NotConfigured"" /><RuleCollection Type=""Script"" EnforcementMode=""NotConfigured"" /></AppLockerPolicy>'
    $clear | Out-File -LiteralPath $PolicyXml -Encoding UTF8
    Set-AppLockerPolicy -XmlPolicy $PolicyXml
    exit 0
}

Set-Service -Name AppIDSvc -StartupType Automatic
Start-Service -Name AppIDSvc -ErrorAction SilentlyContinue

$paths = @()
if (Test-Path -LiteralPath $AllowedList) {
    $paths = Get-Content -LiteralPath $AllowedList -Encoding UTF8 | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
}

$fileInfo = @()
foreach ($path in $paths) {
    try {
        $itemInfo = Get-AppLockerFileInformation -Path $path
        if ($null -ne $itemInfo) {
            $fileInfo += $itemInfo
        }
    } catch {
    }
}

if ($fileInfo.Count -gt 0) {
    $xmlText = $fileInfo | New-AppLockerPolicy -AllowWindows -RuleType Publisher,Hash -User $TargetSid -Optimize -Xml
} else {
    $xmlText = New-AppLockerPolicy -AllowWindows -RuleType Path -User $TargetSid -Optimize -Xml
}

[xml]$policy = [string]::Join([Environment]::NewLine, @($xmlText))
$exe = Ensure-Collection $policy 'Exe' $Mode
$msi = Ensure-Collection $policy 'Msi' $Mode
$script = Ensure-Collection $policy 'Script' $Mode
Remove-BroadProgramFilesAllows $policy

Add-PathRule $policy $exe 'S-1-5-32-544' 'Guard: allow administrators all executables' '*'
Add-PathRule $policy $msi 'S-1-5-32-544' 'Guard: allow administrators all installers' '*'
Add-PathRule $policy $script 'S-1-5-32-544' 'Guard: allow administrators all scripts' '*'

if ($GuardDirectory -and (Test-Path -LiteralPath $GuardDirectory)) {
    Add-PathRule $policy $exe $TargetSid 'Guard: allow Guard application directory' ($GuardDirectory.TrimEnd('\') + '\*')
}

if ($BlockTaskManager -eq '1') {
    $blockedToolPaths = @()
    if (Test-Path -LiteralPath $BlockedToolsList) {
        $blockedToolPaths = Get-Content -LiteralPath $BlockedToolsList -Encoding UTF8 | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
    }

    foreach ($toolPath in $blockedToolPaths) {
        Add-PathRule $policy $exe $TargetSid ('Guard: deny management tool ' + [System.IO.Path]::GetFileName($toolPath)) $toolPath 'Deny'
    }
}

$policy.Save($PolicyXml)
Set-AppLockerPolicy -XmlPolicy $PolicyXml
";
        }
    }
}
