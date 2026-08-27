using System;
using System.Collections.Generic;

namespace Guard
{
    public enum CleanerLaunchMode
    {
        Rejected,
        StartupFailureNotification,
        AuthorizedCleanup
    }

    public static class CleanerLaunchPolicy
    {
        public const string AuthorizedCleanupArgument = "/authorize-and-clean";
        public const string StartupFailureNotificationArgument = "/notifyfailure";

        public static CleanerLaunchMode Parse(IReadOnlyList<string>? arguments)
        {
            if (arguments == null || arguments.Count != 1)
            {
                return CleanerLaunchMode.Rejected;
            }

            if (string.Equals(arguments[0], AuthorizedCleanupArgument, StringComparison.Ordinal))
            {
                return CleanerLaunchMode.AuthorizedCleanup;
            }

            if (string.Equals(arguments[0], StartupFailureNotificationArgument, StringComparison.Ordinal))
            {
                return CleanerLaunchMode.StartupFailureNotification;
            }

            return CleanerLaunchMode.Rejected;
        }
    }

    public static class CleanerExitCodePolicy
    {
        public const int Success = 0;
        public const int Rejected = 1;
        public const int CleanupFailed = 2;

        public static int FromCleanupResult(GuardCleanupResult? result)
        {
            return result != null && result.Succeeded ? Success : CleanupFailed;
        }
    }
}
