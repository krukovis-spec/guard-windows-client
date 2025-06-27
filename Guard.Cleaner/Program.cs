using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
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

            if (args.Contains("/checkpin"))
            {
                var state2 = GuardStateStorage.Load();
                if (state2 == null || string.IsNullOrEmpty(state2.PinCode))
                    Environment.Exit(0); // No PIN needed, allow uninstall

                using (var pinDialog = new PinForm("Enter PIN to Uninstall Guard", null))
                {
                    if (pinDialog.ShowDialog() == DialogResult.OK && pinDialog.EnteredPin == state2.PinCode)
                    {
                        File.WriteAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "uninstall.ok"), "ok");
                        Environment.Exit(0);
                    } // Correct PIN, allow uninstall 
                    else
                        Environment.Exit(1); // Wrong PIN or canceled, block uninstall
                }
                return; // Do not proceed to the rest of the program
            }

            // 1. Ensure we are running as Admin
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

            // 2. Check for the special notification argument from the service
            if (args.Contains("/notifyfailure"))
            {
                var result = MessageBox.Show(
                    "Guard has been failing to start. Would you like to run the uninstaller to cleanly remove the application?",
                    "Guard Startup Failure",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Warning);

                if (result == DialogResult.No)
                {
                    Environment.Exit(1);
                    return;
                }
            }

            // 3. Load state and check PIN
            var state = GuardStateStorage.Load();
            bool isAuthorized = false;

            string uninstallFlagPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "uninstall.ok");
            if (File.Exists(uninstallFlagPath))
            {
                try { File.Delete(uninstallFlagPath); } catch { }
                // Already authorized: skip PIN
                isAuthorized = true;
            }


                if (state == null || string.IsNullOrEmpty(state.PinCode) || isAuthorized == true)
            {
                isAuthorized = true;
            }
            else
            {
                using (var pinDialog = new PinForm("Enter PIN to Uninstall Guard", null))
                {
                    if (pinDialog.ShowDialog() == DialogResult.OK && pinDialog.EnteredPin == state.PinCode)
                    {
                        isAuthorized = true;
                    }
                    else
                    {
                        MessageBox.Show("The PIN code is incorrect or the operation was cancelled. Uninstall will not proceed.", "PIN Required", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        isAuthorized = false;
                    }
                }
            }

            // 4. Final check: Only run cleanup IF authorized. Otherwise, exit with an error.
            if (isAuthorized)
            {
                MessageBox.Show("Guard will now be completely removed from your system.", "Uninstalling Guard", MessageBoxButtons.OK, MessageBoxIcon.Information);

                bool guardKilled = false, helperKilled = false;
                try { File.WriteAllText(AppSettings.DisableFlagPath, DateTime.Now.ToString()); } catch { }
                for (int attempt = 1; attempt <= 3; attempt++)
                {
                    guardKilled = true; helperKilled = true;
                    var guards = Process.GetProcessesByName("guard");
                    if (guards.Length > 0)
                    {
                        guardKilled = false;
                        foreach (var proc in guards) { try { proc.CloseMainWindow(); if (!proc.WaitForExit(1000)) proc.Kill(); } catch { } }
                    }
                    var helpers = Process.GetProcessesByName("StartHelperG");
                    if (helpers.Length > 0)
                    {
                        helperKilled = false;
                        foreach (var proc in helpers) { try { proc.Kill(); } catch { } }
                    }
                    if (guardKilled && helperKilled) break;
                    System.Threading.Thread.Sleep(500);
                }
                if (guardKilled && helperKilled) { try { File.Delete(AppSettings.DisableFlagPath); } catch { } }
                System.Threading.Thread.Sleep(500);

                SystemCleaner.PerformFullCleanupAsync().Wait();

                if (args.Contains("/notifyfailure"))
                {
                    string uninstallPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "unins000.exe");
                    if (File.Exists(uninstallPath))
                    {
                        Process.Start(new ProcessStartInfo(uninstallPath) { UseShellExecute = true });
                    }
                    else
                    {
                        Process.Start("appwiz.cpl");
                    }
                }
                Environment.Exit(0);
            }
            else
            {
                Environment.Exit(1);
            }
        }
    }
}