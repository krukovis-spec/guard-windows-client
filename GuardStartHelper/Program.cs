using System;
using System.Diagnostics;
using System.IO;
using System.Threading;

namespace Guard
{
    class Program
    {
        // Mutex to prevent multiple instances
        private const string MutexName = "GuardStartHelperMutex";

        // Maximum restart attempts before failure notification
        private const int MaxRestartAttempts = 5;
        // Wait time after hitting max failures (in milliseconds)
        private const int FailureCooldownMs = 10 * 60 * 1000; // 10 minutes

        static void Main(string[] args)
        {
            using (var mutex = new Mutex(true, MutexName, out bool isNewInstance))
            {
                if (!isNewInstance)
                    return; // Only allow one instance

                // If /startup is passed, delete the flag file first
                if (args.Length > 0 && args[0].Equals("/startup", StringComparison.OrdinalIgnoreCase))
                {
                    try { File.Delete(AppSettings.DisableFlagPath); } catch { }
                }


                int restartAttempts = 0;

                while (true)
                {
                    // If session.lock (disable flag) exists, exit cleanly
                    if (File.Exists(AppSettings.DisableFlagPath))
                        break;

                    // Check if guard.exe is running
                    var guardProcesses = Process.GetProcessesByName("guard"); // must be lowercase!
                    if (guardProcesses.Length == 0)
                    {
                        restartAttempts++;

                        if (restartAttempts > MaxRestartAttempts)
                        {
                            // P0 containment never starts Cleaner after failures.
                            // Preserve the protection state and retry after a cooldown.
                            Thread.Sleep(FailureCooldownMs);
                            restartAttempts = 0; // Reset attempts for next cycle
                        }
                        else
                        {
                            // Try to start guard.exe as admin
                            StartGuardApp();
                            Thread.Sleep(2000); // Wait a bit before next check
                        }
                    }
                    else
                    {
                        // Reset attempts if main app is running
                        restartAttempts = 0;
                        Thread.Sleep(2000);
                    }
                }
            }
        }

        static void StartGuardApp()
        {
            try
            {
                var exePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "guard.exe");
                if (File.Exists(exePath))
                {
                    var psi = new ProcessStartInfo(exePath)
                    {
                        UseShellExecute = true
                    };
                    Process.Start(psi);
                }
            }
            catch
            {
                // Swallow exceptions silently; incrementing attempts is handled in Main loop
            }
        }

    }
}
