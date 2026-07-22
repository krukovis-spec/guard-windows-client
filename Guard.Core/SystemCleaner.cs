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
        public static Task<GuardCleanupResult> PerformFullCleanupAsync(Action<string>? log = null)
        {
            return GuardCleanupCoordinator.RunAsync(new SystemGuardCleanupOperations(log), log);
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

        public static bool TryWriteDisableFlag(Action<string>? log = null)
        {
            try
            {
                File.WriteAllText(AppSettings.DisableFlagPath, DateTime.UtcNow.ToString("O"));
                return File.Exists(AppSettings.DisableFlagPath);
            }
            catch
            {
                log?.Invoke("[Cleanup] Could not create the watchdog disable flag.");
                return false;
            }
        }

        public static bool TryRemoveDisableFlag(Action<string>? log = null)
        {
            try
            {
                if (File.Exists(AppSettings.DisableFlagPath))
                {
                    File.Delete(AppSettings.DisableFlagPath);
                }

                return !File.Exists(AppSettings.DisableFlagPath);
            }
            catch
            {
                log?.Invoke("[Cleanup] Could not remove the watchdog disable flag.");
                return false;
            }
        }

        private static bool DeleteStateFiles(Action<string>? log)
        {
            var files = new[]
            {
                GuardStateStorage.StateFilePath,
                GuardStateStorage.DocumentsBackupPath,
                Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.System),
                    @"drivers\etc\savedBU",
                    "state.dat")
            };

            foreach (var file in files)
            {
                try
                {
                    if (File.Exists(file))
                    {
                        File.Delete(file);
                    }

                    if (File.Exists(file))
                    {
                        log?.Invoke("[Cleanup] A Guard state file could not be deleted.");
                        return false;
                    }
                }
                catch
                {
                    log?.Invoke("[Cleanup] A Guard state file could not be deleted.");
                    return false;
                }
            }

            log?.Invoke("[Cleanup] Guard state files deleted.");
            return true;
        }
        private static string HostsPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts");

        public static void RunCmd(string cmd)
        {
            try
            {
                SystemCommandRunnerProvider.Current.Run("cmd.exe", "/c " + cmd, captureOutput: true);
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

        public static async Task<bool> RemoveFirewallRulesAsync(Action<string>? log = null, string? tag = null)
        {
            try
            {
                bool succeeded = await Task.Run(() =>
                {
                    List<string> tagsToRemove = new List<string>();
                    if (string.IsNullOrEmpty(tag))
                    {
                        tagsToRemove.AddRange(new[] { "GuardBlock-Cat", "GuardBlock-Ads", "GuardBlock-Ads-Batch-", "GuardBlock-Rules" });
                    }
                    else
                    {
                        tagsToRemove.Add(tag!);
                    }

                    foreach (var prefix in tagsToRemove)
                    {
                        var result = SystemCommandRunnerProvider.Current.Run(
                            "netsh",
                            "advfirewall firewall show rule name=all",
                            captureOutput: true);
                        if (!result.Started || result.ExitCode != 0)
                        {
                            return false;
                        }

                        var ruleNames = ExtractFirewallRuleNames(result.Output, prefix);

                        foreach (var ruleName in ruleNames)
                        {
                            if (ruleName.IndexOfAny(new[] { '\"', '\r', '\n' }) >= 0)
                            {
                                return false;
                            }

                            var deleteResult = SystemCommandRunnerProvider.Current.Run(
                                "netsh",
                                $"advfirewall firewall delete rule name=\"{ruleName}\"",
                                captureOutput: true);
                            if (!deleteResult.Started || deleteResult.ExitCode != 0)
                            {
                                return false;
                            }
                        }

                        var verificationResult = SystemCommandRunnerProvider.Current.Run(
                            "netsh",
                            "advfirewall firewall show rule name=all",
                            captureOutput: true);
                        if (!verificationResult.Started ||
                            verificationResult.ExitCode != 0 ||
                            ExtractFirewallRuleNames(verificationResult.Output, prefix).Count > 0)
                        {
                            return false;
                        }
                    }

                    return true;
                });

                if (succeeded)
                {
                    log?.Invoke($"[Firewall] Removed firewall rule(s) for tag: {(tag ?? "ALL")}.");
                }
                else
                {
                    log?.Invoke("[Firewall] Failed to remove all Guard firewall rules.");
                }

                return succeeded;
            }
            catch
            {
                log?.Invoke("[Firewall] Failed to remove all Guard firewall rules.");
                return false;
            }
        }

        private static List<string> ExtractFirewallRuleNames(string output, string prefix)
        {
            return (output ?? string.Empty)
                .Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries)
                .Select(line =>
                {
                    int separatorIndex = line.IndexOf(':');
                    return separatorIndex >= 0 ? line.Substring(separatorIndex + 1).Trim() : string.Empty;
                })
                .Where(name => name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        public static async Task<bool> ResetHostsFileAsync(Action<string>? log = null, string? tag = null)
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
                return true;
            }
            catch
            {
                log?.Invoke("[Hosts] Failed to reset the hosts file.");
                return false;
            }
        }

        private sealed class SystemGuardCleanupOperations : IGuardCleanupOperations
        {
            private readonly Action<string>? _log;

            public SystemGuardCleanupOperations(Action<string>? log)
            {
                _log = log;
            }

            public bool WriteDisableFlag()
            {
                return TryWriteDisableFlag(_log);
            }

            public Task<bool> ResetHostsFileAsync()
            {
                return SystemCleaner.ResetHostsFileAsync(_log);
            }

            public Task<bool> RemoveFirewallRulesAsync()
            {
                return SystemCleaner.RemoveFirewallRulesAsync(_log);
            }

            public bool RemoveStartupEntries()
            {
                return ScheduledTaskHelper.RemoveStartupTask(_log);
            }

            public bool DeleteStateFiles()
            {
                return SystemCleaner.DeleteStateFiles(_log);
            }
        }
    }
}
