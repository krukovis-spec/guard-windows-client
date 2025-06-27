using System;
using System.Diagnostics;
using System.Windows.Forms;
using Microsoft.Win32;

namespace Guard
{
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

        public static void RemoveStartupTask(Action<string>? log = null, GuardState? state = null)
        {
            string cmd = $@"/Delete /F /TN ""{TaskName}""";
            try
            {
                RunSchtasks(cmd);
                RemoveRegistryRunKey();
                log?.Invoke("Scheduled Task and registry auto-start removed successfully.");
                if (state != null)
                {
                    state.IsStartUp = false;
                    GuardStateStorage.Save(state);
                }
            }
            catch (Exception ex)
            {
                log?.Invoke($"ERROR removing startup task or registry: {ex.Message}");
            }
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
            var psi = new ProcessStartInfo("schtasks.exe", arguments)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };

            var proc = Process.Start(psi);
            if (proc == null)
            {
                throw new Exception("Failed to start the schtasks.exe process.");
            }

            string output = proc.StandardOutput.ReadToEnd();
            string error = proc.StandardError.ReadToEnd();
            proc.WaitForExit();

            if (proc.ExitCode != 0)
                throw new Exception($"schtasks.exe error: {error}");

            return output;
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
                if (key.GetValue("GuardHelper") != null)
                    key.DeleteValue("GuardHelper");
            }
        }

        private static bool IsRegistryRunKeyPresent()
        {
            string runKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(runKey, false))
            {
                var value = key?.GetValue("GuardHelper") as string;
                if (string.IsNullOrEmpty(value)) return false;
                return value.Contains("StartHelperG.exe");
            }
        }

    }
}