using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace Guard
{
    public static class SystemCleaner
    {
        public static async Task PerformFullCleanupAsync(Action<string>? log = null)
        {
            try
            {
                // Clear Hosts and Firewall Rules first
                await ResetHostsFileAsync(log);
                await RemoveFirewallRulesAsync(log);
                log?.Invoke("[Cleanup] Hosts and firewall rules cleared.");

                // Remove the scheduled task
                if (ScheduledTaskHelper.IsStartupTaskInstalled())
                {
                    ScheduledTaskHelper.RemoveStartupTask(log);
                }

                // Delete all three state files
                DeleteStateFiles(log);
            }
            catch (Exception ex)
            {
                log?.Invoke($"[Cleanup] Error during full clean: {ex.Message}");
            }
            finally
            {
                // This section will run even if there was an error during cleanup.
                try
                {
                    // Create the flag file to stop the watchdog
                    File.WriteAllText(AppSettings.DisableFlagPath, DateTime.Now.ToString());
                }
                catch { }
            }
        }

        public static bool IsAdministrator()
        {
            try
            {
                var wi = System.Security.Principal.WindowsIdentity.GetCurrent();
                var wp = new System.Security.Principal.WindowsPrincipal(wi);
                return wp.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }

        private static void DeleteStateFiles(Action<string>? log)
        {
            try { File.Delete(GuardStateStorage.StateFilePath); log?.Invoke("Primary state file deleted."); } catch { }
            try { File.Delete(GuardStateStorage.DocumentsBackupPath); log?.Invoke("Documents backup state file deleted."); } catch { }
            try
            {
                string systemBackupPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\savedBU", "state.dat");
                if (File.Exists(systemBackupPath)) File.Delete(systemBackupPath);
                log?.Invoke("System backup state file deleted.");
            }
            catch { }
        }
        private static string HostsPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts");

        public static void RunCmd(string cmd)
        {
            try
            {
                var psi = new ProcessStartInfo("cmd.exe", "/c " + cmd)
                {
                    WindowStyle = ProcessWindowStyle.Hidden,
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                var proc = Process.Start(psi);
                proc?.WaitForExit();
            }
            catch { }
        }

        public static async Task FlushDnsAsync()
        {
            await Task.Run(() => RunCmd("ipconfig /flushdns"));
        }

        public static async Task DisableAndRestoreNetworkAsync(Action<string>? log = null)
        {
            log?.Invoke("Resetting network connection...");
            RunCmd(@"netsh interface set interface name=""Ethernet"" admin=disabled");
            RunCmd(@"netsh interface set interface name=""Wi-Fi"" admin=disabled");
            await Task.Delay(500);
            RunCmd(@"netsh interface set interface name=""Ethernet"" admin=enabled");
            RunCmd(@"netsh interface set interface name=""Wi-Fi"" admin=enabled");
        }

        public static async Task RemoveFirewallRulesAsync(Action<string>? log = null, string? tag = null)
        {
            await Task.Run(() =>
            {
                List<string> tagsToRemove = new List<string>();
                if (string.IsNullOrEmpty(tag))
                {
                    tagsToRemove.AddRange(new[] { "GuardBlock-Cat", "GuardBlock-Ads", "GuardBlock-Ads-Batch-", "GuardBlock-Rules" });
                }
                else
                {
                    if (tag != null) tagsToRemove.Add(tag);
                }

                foreach (var prefix in tagsToRemove)
                {
                    var psi = new ProcessStartInfo("netsh", "advfirewall firewall show rule name=all")
                    {
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };

                    using (var process = Process.Start(psi))
                    {
                        if (process == null) continue;
                        string output = process.StandardOutput.ReadToEnd();
                        process.WaitForExit();

                        var ruleNames = output
                            .Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries)
                            .Where(line => line.StartsWith("Rule Name:", StringComparison.OrdinalIgnoreCase))
                            .Select(line => line.Substring("Rule Name:".Length).Trim())
                            .Where(name => name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                            .Distinct();

                        foreach (var ruleName in ruleNames)
                        {
                            RunCmd($"netsh advfirewall firewall delete rule name=\"{ruleName}\"");
                        }
                    }
                }
            });
            log?.Invoke($"[Firewall] Removed firewall rule(s) for tag: {(tag ?? "ALL")}.");
        }

        public static async Task ResetHostsFileAsync(Action<string>? log = null, string? tag = null)
        {
            try
            {
                var origLines = await Task.Run(() => File.ReadAllLines(HostsPath));
                List<string> cleanLines;
                if (string.IsNullOrEmpty(tag))
                {
                    string[] allTags = { "# GuardBlock", "# GuardBlock-Ads", "# GuardBlock-Rules" };
                    cleanLines = origLines
                        .Where(line => !allTags.Any(t => line.TrimEnd().EndsWith(t)))
                        .ToList();
                }
                else
                {
                    cleanLines = origLines
                        .Where(line => !line.TrimEnd().EndsWith(tag))
                        .ToList();
                }
                await Task.Run(() => File.WriteAllLines(HostsPath, cleanLines));
                log?.Invoke($"[Hosts] Hosts file cleaned (tag={tag ?? "ALL"}).");
            }
            catch (Exception ex)
            {
                log?.Invoke($"[Hosts] Failed to reset hosts file: " + ex.Message);
            }
        }
    }
}