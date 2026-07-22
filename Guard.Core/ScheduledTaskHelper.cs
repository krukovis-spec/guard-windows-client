using System;
using System.Diagnostics;
using System.Windows.Forms;
using Microsoft.Win32;

namespace Guard
{
    public enum ScheduledTaskPresence
    {
        Present,
        ConfirmedAbsent,
        Error
    }

    public static class ScheduledTaskHelper
    {
        public static string TaskName = "Helper Start Up Task for guard"; // A more descriptive name
        public static string HelperPath => System.IO.Path.Combine(
    AppDomain.CurrentDomain.BaseDirectory, "StartHelperG.exe");

        public static void RegisterStartupTask(Action<string>? log = null, GuardState? state = null)
        {
            string cmd = $@"/Create /F /RL HIGHEST /SC ONLOGON /TN ""{TaskName}"" /TR ""\""{HelperPath}\"" /startup"" /IT";
            try
            {
                var result = RunSchtasks(cmd, captureOutput: true);
                SetRegistryRunKey();
                log?.Invoke("Scheduled Task and registry auto-start registered successfully.");
                if (state != null)
                {
                    state.IsStartUp = true;
                    GuardStateStorage.Save(state);
                }
            }
            catch (Exception ex)
            {
                log?.Invoke($"ERROR creating startup task or registry: {ex.Message}");
            }
        }

        public static bool RemoveStartupTask(Action<string>? log = null, GuardState? state = null)
        {
            bool succeeded = true;

            try
            {
                string query = $@"/Query /TN ""{TaskName}""";
                var queryResult = SystemCommandRunnerProvider.Current.Run("schtasks.exe", query, captureOutput: true);
                var presence = ClassifyQueryResult(queryResult);
                if (presence == ScheduledTaskPresence.Error)
                {
                    succeeded = false;
                }
                else if (presence == ScheduledTaskPresence.Present)
                {
                    string delete = $@"/Delete /F /TN ""{TaskName}""";
                    var deleteResult = SystemCommandRunnerProvider.Current.Run("schtasks.exe", delete, captureOutput: true);
                    succeeded = deleteResult.Started && deleteResult.ExitCode == 0;
                    if (succeeded)
                    {
                        var verificationResult = SystemCommandRunnerProvider.Current.Run(
                            "schtasks.exe",
                            query,
                            captureOutput: true);
                        succeeded = ClassifyQueryResult(verificationResult) == ScheduledTaskPresence.ConfirmedAbsent;
                    }
                }
            }
            catch
            {
                succeeded = false;
            }

            try
            {
                RemoveRegistryRunKey();
                if (IsRegistryRunKeyPresent())
                {
                    succeeded = false;
                }
            }
            catch
            {
                succeeded = false;
            }

            if (!succeeded)
            {
                log?.Invoke("ERROR removing Guard startup entries.");
                return false;
            }

            log?.Invoke("Scheduled Task and registry auto-start removed successfully.");
            if (state != null)
            {
                state.IsStartUp = false;
                GuardStateStorage.Save(state);
            }

            return true;
        }

        public static ScheduledTaskPresence ClassifyQueryResult(SystemCommandResult? result)
        {
            if (result == null || !result.Started)
            {
                return ScheduledTaskPresence.Error;
            }

            if (result.ExitCode == 0)
            {
                return ScheduledTaskPresence.Present;
            }

            string message = (result.Output ?? string.Empty) + "\n" + (result.Error ?? string.Empty);
            string[] confirmedMissingMarkers =
            {
                "the system cannot find the file specified",
                "the system cannot find the path specified",
                "cannot find the specified task",
                "не удается найти указанный файл",
                "не удается найти указанный путь",
                "0x80070002",
                "error_file_not_found",
                "error_path_not_found"
            };

            foreach (var marker in confirmedMissingMarkers)
            {
                if (message.IndexOf(marker, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return ScheduledTaskPresence.ConfirmedAbsent;
                }
            }

            return ScheduledTaskPresence.Error;
        }

        public static bool IsStartupTaskInstalled()
        {
            bool task = false, reg = false;
            try
            {
                string cmd = $@"/Query /TN ""{TaskName}""";
                var output = RunSchtasks(cmd, captureOutput: true);
                task = output.Contains(TaskName);
            }
            catch { }

            try
            {
                reg = IsRegistryRunKeyPresent();
            }
            catch { }

            return task && reg;
        }

        private static string RunSchtasks(string arguments, bool captureOutput = false)
        {
            var result = SystemCommandRunnerProvider.Current.Run("schtasks.exe", arguments, captureOutput: true);
            if (!result.Started)
            {
                throw new Exception("Failed to start the schtasks.exe process.");
            }

            if (result.ExitCode != 0)
                throw new Exception($"schtasks.exe error: {result.Error}");

            return captureOutput ? result.Output : "";
        }

        private static void SetRegistryRunKey()
        {
            string runKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(runKey, true))
            {
                key.SetValue("GuardHelper", $"\"{HelperPath}\" /startup");
            }
        }

        private static void RemoveRegistryRunKey()
        {
            string runKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(runKey, true))
            {
                if (key != null && key.GetValue("GuardHelper") != null)
                    key.DeleteValue("GuardHelper");
            }
        }

        private static bool IsRegistryRunKeyPresent()
        {
            string runKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(runKey, false))
            {
                var value = key?.GetValue("GuardHelper") as string;
                return value?.Contains("StartHelperG.exe") == true;
            }
        }

    }
}
