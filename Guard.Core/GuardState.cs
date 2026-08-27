using System;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text;
using System.Collections.Generic;
using System.Linq;

namespace Guard
{
    public class GuardState
    {
        public string AssignCode { get; set; } = string.Empty;
        public string PinCode { get; set; } = string.Empty;
        public string DeviceId { get; set; } = string.Empty;
        public int Version { get; set; } = 0;
        public bool DevUpdate { get; set; } = false;
        public bool SyncStatus { get; set; }
        public int PinStatus { get; set; }
        public bool Assigned { get; set; } = false; 
        public bool LocalParentMode { get; set; } = false;
        public bool AllowLegacyRemoteServer { get; set; } = false;
        public string UiLanguage { get; set; } = Guard.UiLanguage.Russian;
        public DateTime AdRecheck { get; set; } //?
        public string LastUpdate { get; set; } = string.Empty; 
        public DateTime IpsRecheck { get; set; } 
        public List<string> ErrorLog { get; set; } = new List<string>();
        public string? DeviceTimeZoneId { get; set; } // e.g. "Europe/Berlin" or "Pacific Standard Time"
        public int? DeviceUtcOffsetMinutes { get; set; }
        public List<int> RestrictedCategoryIds { get; set; } = new List<int>();
        public List<InstructionRule> Rules { get; set; } = new List<InstructionRule>();
        public List<Preset> Presets { get; set; } = new List<Preset>();
        public List<RestrictedCategory> RestrictedCategories { get; set; } = new List<RestrictedCategory>();
        public UpdateFor UpdateInfo { get; set; } = new UpdateFor();
        public List<string> RulePresets { get; set; } = new List<string>();
        public List<string> RuleUrls { get; set; } = new List<string>();
        public List<string> PermanentDomains { get; set; } = new List<string>();
        public List<string> ResolvedPermanentIps { get; set; } = new List<string>();
        public List<string> PermanentPresetIps { get; set; } = new List<string>();
        public List<string> ActiveRuleIds { get; set; } = new List<string>();
        public List<ParsedRule> ParsedRules { get; set; } = new List<ParsedRule>();
        public int LastAppliedSnapshotMinute { get; set; } = 0;
        public DateTime? HostsFileLastWriteTimeUtc { get; set; }
        public bool IsHostsFileActive { get; set; } = false;
        public bool IsStartUp { get; set; } = true;
        public string LastTurnOnTime { get; set; } = "";
        public string LastTurnOffTime { get; set; } = "";
        public long? HostsFileSize { get; set; } = 0;
        public List<ScheduleSnapshot> WeeklyTimeline { get; set; } = new List<ScheduleSnapshot>();
        public bool ResetConnection { get; set; }
        public int Sound { get; set; }
        public DevicePairing Pairing { get; set; } = new DevicePairing();
        public string ParentAdminPasswordHash { get; set; } = "";
        public string ParentAdminPasswordSalt { get; set; } = "";
        public int ParentAdminPasswordIterations { get; set; } = 0;
        public int ParentAdminPort { get; set; } = 8765;
        public string ChildWindowsUserName { get; set; } = "";
        public AccountLockdownSettings AccountLockdown { get; set; } = new AccountLockdownSettings();
        public ApplicationControlSettings AppControl { get; set; } = new ApplicationControlSettings();
        public List<AccessRequest> AccessRequests { get; set; } = new List<AccessRequest>();
        public List<DomainAccessGrant> DomainAccessGrants { get; set; } = new List<DomainAccessGrant>();
        public WebAccessSettings WebAccess { get; set; } = new WebAccessSettings();
        public long LastAppLockerExeEventRecordId { get; set; } = 0;
        public ActivitySettings ActivitySettings { get; set; } = new ActivitySettings();
        public ActivityRuntimeState ActivityRuntime { get; set; } = new ActivityRuntimeState();
        public List<ActivityUsageEntry> ActivityUsage { get; set; } = new List<ActivityUsageEntry>();
        public List<DailyTask> DailyTasks { get; set; } = new List<DailyTask>();
        public List<DailyTaskCompletion> DailyTaskCompletions { get; set; } = new List<DailyTaskCompletion>();
        public List<BonusTimeGrant> BonusTimeGrants { get; set; } = new List<BonusTimeGrant>();
        public MaintenanceModeState MaintenanceMode { get; set; } = new MaintenanceModeState();

    }
    public class ScheduleSnapshot
    {
        // The exact minute of the week this snapshot begins (0 to 10079).
        public int StartMinuteOfWeek { get; set; }
        // The complete list of rule IDs that are active during this snapshot.
        public List<string> ActiveRuleIds { get; set; } = new List<string>();
    }

    public static class GuardStateStorage
    {
        // SaveFile in AppData
        public static string StateFilePath
        {
            get
            {
                string userAppData = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Guard");
                Directory.CreateDirectory(userAppData);
                return Path.Combine(userAppData, "state.dat");
            }
        }
        public static string DocumentsBackupPath
        {
            get
            {
                // Create a 'Guard' folder inside the user's personal Documents folder.
                string documents = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "Guard");
                Directory.CreateDirectory(documents);
                return Path.Combine(documents, "state.dat");
            }
        }
        public static void Save(GuardState? state)
        {
            if (state == null) return;

            var json = JsonSerializer.Serialize(state);
            var data = Encoding.UTF8.GetBytes(json);
            var protectedData = ProtectedData.Protect(data, null, DataProtectionScope.CurrentUser);

            // Location 1: Main AppData file
            try
            {
                File.WriteAllBytes(StateFilePath, protectedData);
            }
            catch { }

            // Location 2: System backup folder (using your existing logic)
            try
            {
                string etcSavedBU = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\savedBU");
                Directory.CreateDirectory(etcSavedBU);
                string backupFile = Path.Combine(etcSavedBU, "state.dat");
                File.WriteAllBytes(backupFile, protectedData);
            }
            catch { }

            // Location 3: New Documents folder backup
            try
            {
                File.WriteAllBytes(DocumentsBackupPath, protectedData);
            }
            catch { }
        }

        public static GuardState? Load()
        {

            string sourceFile = StateFilePath;

                if (!File.Exists(sourceFile))
                {
                    string etcSavedBU = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\savedBU");
                    string backupFile = Path.Combine(etcSavedBU, "state.dat");

                    if (!File.Exists(backupFile))
                        return null;

                    sourceFile = backupFile;
                }              
            var protectedData = File.ReadAllBytes(sourceFile);
            var data = ProtectedData.Unprotect(protectedData, null, DataProtectionScope.CurrentUser);
            var json = Encoding.UTF8.GetString(data);
            return JsonSerializer.Deserialize<GuardState>(json);
        }

        public static void VerifyAndRestoreStateFiles(Action<string>? log = null)
        {
            try
            {
                // Create a list of all three state file locations
                var locations = new[]
                {
            StateFilePath,
            DocumentsBackupPath,
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\savedBU", "state.dat")
        };

                var existingFiles = locations.Where(File.Exists).ToList();
                var missingFiles = locations.Except(existingFiles).ToList();

                // If at least one file exists and at least one is missing, perform a restore.
                if (existingFiles.Any() && missingFiles.Any())
                {
                    log?.Invoke($"[State Heal] Detected missing state files. Restoring from first available backup.");

                    // The first valid file in our priority list will be the source
                    string sourceFile = existingFiles.First();

                    foreach (var destinationFile in missingFiles)
                    {
                        try
                        {
                            // Ensure the destination directory exists before copying
                            Directory.CreateDirectory(Path.GetDirectoryName(destinationFile));
                            File.Copy(sourceFile, destinationFile, true);
                            log?.Invoke($"[State Heal] Restored {Path.GetFileName(destinationFile)} to {Path.GetDirectoryName(destinationFile)}");
                        }
                        catch (Exception ex)
                        {
                            log?.Invoke($"[State Heal] FAILED to restore {destinationFile}. Error: {ex.Message}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                log?.Invoke($"[State Heal] A critical error occurred during the state file verification process: {ex.Message}");
            }
        }
    }
}
