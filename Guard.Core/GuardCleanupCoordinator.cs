using System;
using System.Threading.Tasks;

namespace Guard
{
    public enum GuardCleanupStep
    {
        DisableWatchdog,
        HostsFile,
        FirewallRules,
        StartupEntries,
        StateFiles
    }

    public sealed class GuardCleanupResult
    {
        private GuardCleanupResult(bool succeeded, GuardCleanupStep? failedStep)
        {
            Succeeded = succeeded;
            FailedStep = failedStep;
        }

        public bool Succeeded { get; }
        public GuardCleanupStep? FailedStep { get; }

        public static GuardCleanupResult Completed()
        {
            return new GuardCleanupResult(true, null);
        }

        public static GuardCleanupResult Failed(GuardCleanupStep step)
        {
            return new GuardCleanupResult(false, step);
        }
    }

    public interface IGuardCleanupOperations
    {
        bool WriteDisableFlag();
        Task<bool> ResetHostsFileAsync();
        Task<bool> RemoveFirewallRulesAsync();
        bool RemoveStartupEntries();
        bool DeleteStateFiles();
    }

    public static class GuardCleanupCoordinator
    {
        public static async Task<GuardCleanupResult> RunAsync(
            IGuardCleanupOperations operations,
            Action<string>? log = null)
        {
            if (operations == null)
            {
                throw new ArgumentNullException(nameof(operations));
            }

            if (!RunStep(GuardCleanupStep.DisableWatchdog, operations.WriteDisableFlag, log))
            {
                return GuardCleanupResult.Failed(GuardCleanupStep.DisableWatchdog);
            }

            if (!await RunStepAsync(GuardCleanupStep.HostsFile, operations.ResetHostsFileAsync, log))
            {
                return GuardCleanupResult.Failed(GuardCleanupStep.HostsFile);
            }

            if (!await RunStepAsync(GuardCleanupStep.FirewallRules, operations.RemoveFirewallRulesAsync, log))
            {
                return GuardCleanupResult.Failed(GuardCleanupStep.FirewallRules);
            }

            if (!RunStep(GuardCleanupStep.StartupEntries, operations.RemoveStartupEntries, log))
            {
                return GuardCleanupResult.Failed(GuardCleanupStep.StartupEntries);
            }

            if (!RunStep(GuardCleanupStep.StateFiles, operations.DeleteStateFiles, log))
            {
                return GuardCleanupResult.Failed(GuardCleanupStep.StateFiles);
            }

            log?.Invoke("[Cleanup] Guard cleanup completed.");
            return GuardCleanupResult.Completed();
        }

        private static bool RunStep(GuardCleanupStep step, Func<bool> action, Action<string>? log)
        {
            try
            {
                if (action())
                {
                    return true;
                }
            }
            catch
            {
                // The caller receives a structured failed step, never a false success.
            }

            log?.Invoke($"[Cleanup] {step} failed.");
            return false;
        }

        private static async Task<bool> RunStepAsync(
            GuardCleanupStep step,
            Func<Task<bool>> action,
            Action<string>? log)
        {
            try
            {
                if (await action())
                {
                    return true;
                }
            }
            catch
            {
                // The caller receives a structured failed step, never a false success.
            }

            log?.Invoke($"[Cleanup] {step} failed.");
            return false;
        }
    }
}
