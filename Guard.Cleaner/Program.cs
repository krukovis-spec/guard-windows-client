using System;
using System.Diagnostics;
using System.IO;
using System.Windows.Forms;

namespace Guard.Cleaner
{
    static class Program
    {
        [STAThread]

        private static bool CanWriteToHostsFile()
        {
            try
            {
                string hostsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts");
                // Try to open the file with write access. If it succeeds, we have permission.
                using (FileStream fs = new FileStream(hostsPath, FileMode.Open, FileAccess.ReadWrite))
                {
                    return true;
                }
            }
            catch (UnauthorizedAccessException)
            {
                // This specific exception means we were denied access.
                return false;
            }
            catch
            {
                // Any other exception also means we can't reliably write to it.
                return false;
            }
        }



        static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            var launchMode = CleanerLaunchPolicy.Parse(args);
            if (launchMode == CleanerLaunchMode.StartupFailureNotification)
            {
                MessageBox.Show(
                    "Guard failed to start repeatedly. P0 containment will not remove or weaken protection automatically. A parent administrator must diagnose the failure.",
                    "Guard Startup Failure",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
                Environment.Exit(1);
                return;
            }

            if (launchMode != CleanerLaunchMode.AuthorizedCleanup)
            {
                MessageBox.Show(
                    "Direct and legacy cleaner modes are disabled. Start removal from Windows Installed apps.",
                    "Guard Removal Blocked",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                Environment.Exit(1);
                return;
            }

            if (!SystemCleaner.IsAdministrator())
            {
                MessageBox.Show("This utility requires administrator privileges to run.", "Permission Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Environment.Exit(1);
                return;
            }
            else if (!CanWriteToHostsFile())
            {
                MessageBox.Show(
                    "Guard does not have the necessary permissions to access the hosts file, likely due to an antivirus or security policy. The application cannot continue.",
                    "Guard Permission Error",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                Environment.Exit(1);
                return;
            }

            var state = GuardStateStorage.Load();
            bool isAuthorized;
            using (var pinDialog = new PinForm("Enter the existing custom parent PIN to uninstall Guard", null))
            {
                if (pinDialog.ShowDialog() != DialogResult.OK)
                {
                    Environment.Exit(1);
                    return;
                }

                isAuthorized = GuardV2ContainmentPolicy.CanAuthorizeCleaner(state?.PinCode, pinDialog.EnteredPin);
            }

            if (!isAuthorized)
            {
                MessageBox.Show(
                    "The parent PIN is unavailable, known to be compromised, incorrect, or the operation was cancelled. Guard was not removed.",
                    "Parent Authorization Required",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                Environment.Exit(1);
                return;
            }

            MessageBox.Show("Guard will now be completely removed from your system.", "Uninstalling Guard", MessageBoxButtons.OK, MessageBoxIcon.Information);

            bool guardKilled = false, helperKilled = false;
            if (!SystemCleaner.TryWriteDisableFlag())
            {
                AbortCleanupAndRestoreProtection("Guard could not enter the guarded cleanup state.");
                return;
            }

            for (int attempt = 1; attempt <= 3; attempt++)
            {
                guardKilled = true;
                helperKilled = true;
                var guards = Process.GetProcessesByName("guard");
                if (guards.Length > 0)
                {
                    guardKilled = false;
                    foreach (var proc in guards)
                    {
                        try { proc.CloseMainWindow(); if (!proc.WaitForExit(1000)) proc.Kill(); }
                        catch { }
                        finally { proc.Dispose(); }
                    }
                }
                var helpers = Process.GetProcessesByName("StartHelperG");
                if (helpers.Length > 0)
                {
                    helperKilled = false;
                    foreach (var proc in helpers)
                    {
                        try { proc.Kill(); }
                        catch { }
                        finally { proc.Dispose(); }
                    }
                }
                if (guardKilled && helperKilled) break;
                System.Threading.Thread.Sleep(500);
            }

            guardKilled = NoProcessesNamed("guard");
            helperKilled = NoProcessesNamed("StartHelperG");
            if (!guardKilled || !helperKilled)
            {
                AbortCleanupAndRestoreProtection("Guard processes could not be stopped safely.");
                return;
            }

            System.Threading.Thread.Sleep(500);

            GuardCleanupResult cleanupResult;
            try
            {
                cleanupResult = SystemCleaner.PerformFullCleanupAsync().GetAwaiter().GetResult();
            }
            catch
            {
                AbortCleanupAndRestoreProtection("Guard cleanup failed unexpectedly.");
                return;
            }

            if (!cleanupResult.Succeeded)
            {
                AbortCleanupAndRestoreProtection(
                    "Guard cleanup did not complete the " + cleanupResult.FailedStep + " stage.");
                return;
            }

            Environment.Exit(CleanerExitCodePolicy.FromCleanupResult(cleanupResult));
        }

        private static void AbortCleanupAndRestoreProtection(string reason)
        {
            SystemCleaner.TryRemoveDisableFlag();
            TryRestartProtection();

            MessageBox.Show(
                reason + " Uninstall was aborted and Guard recovery was requested.",
                "Guard Cleanup Failed",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
            Environment.Exit(CleanerExitCodePolicy.CleanupFailed);
        }

        private static bool NoProcessesNamed(string processName)
        {
            var processes = Process.GetProcessesByName(processName);
            try
            {
                return processes.Length == 0;
            }
            finally
            {
                foreach (var process in processes)
                {
                    process.Dispose();
                }
            }
        }

        private static void TryRestartProtection()
        {
            try
            {
                string helperPath = ScheduledTaskHelper.HelperPath;
                if (!File.Exists(helperPath))
                {
                    return;
                }

                Process.Start(new ProcessStartInfo
                {
                    FileName = helperPath,
                    Arguments = "/startup",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                });
            }
            catch
            {
                // Recovery is best-effort. The nonzero exit code still blocks file removal.
            }
        }
    }
}
