using System;

namespace Guard
{
    public sealed class MaintenanceModeState
    {
        public bool IsActive { get; set; }
        public DateTime? UntilUtc { get; set; }
        public bool PreviousSyncStatus { get; set; }
        public ApplicationControlMode PreviousAppControlMode { get; set; } = ApplicationControlMode.Off;
        public bool PreviousBlockTaskManager { get; set; } = true;
        public DateTime? PreviousTaskManagerAllowedUntilUtc { get; set; }
    }

    public static class MaintenanceModeApplier
    {
        public const int MaxMinutes = 8 * 60;

        public static ParentCommandResult Start(GuardState state, int minutes, DateTime utcNow)
        {
            if (state == null) throw new ArgumentNullException(nameof(state));
            EnsureState(state);

            if (minutes < 1 || minutes > MaxMinutes)
            {
                return new ParentCommandResult { Error = "Maintenance mode must be from 1 to 480 minutes." };
            }

            if (!state.MaintenanceMode.IsActive)
            {
                state.MaintenanceMode.PreviousSyncStatus = state.SyncStatus;
                state.MaintenanceMode.PreviousAppControlMode = state.AppControl.Mode;
                state.MaintenanceMode.PreviousBlockTaskManager = state.AppControl.BlockTaskManager;
                state.MaintenanceMode.PreviousTaskManagerAllowedUntilUtc = state.AppControl.TaskManagerAllowedUntilUtc;
            }

            state.MaintenanceMode.IsActive = true;
            state.MaintenanceMode.UntilUtc = utcNow.AddMinutes(minutes);

            ApplyPausedProtectionState(state, utcNow);
            return new ParentCommandResult { Changed = true };
        }

        public static ParentCommandResult End(GuardState state, DateTime utcNow)
        {
            if (state == null) throw new ArgumentNullException(nameof(state));
            EnsureState(state);

            if (!state.MaintenanceMode.IsActive)
            {
                return new ParentCommandResult { Changed = false };
            }

            var previousSyncStatus = state.MaintenanceMode.PreviousSyncStatus;
            var previousAppControlMode = state.MaintenanceMode.PreviousAppControlMode;
            var previousBlockTaskManager = state.MaintenanceMode.PreviousBlockTaskManager;
            var previousTaskManagerAllowedUntilUtc = state.MaintenanceMode.PreviousTaskManagerAllowedUntilUtc;

            state.SyncStatus = previousSyncStatus;
            state.AppControl.Mode = previousAppControlMode;
            state.AppControl.BlockTaskManager = previousBlockTaskManager;
            state.AppControl.TaskManagerAllowedUntilUtc = previousTaskManagerAllowedUntilUtc;
            state.AppControl.PolicyUpdatePending = true;
            state.MaintenanceMode = new MaintenanceModeState();

            state.UpdateInfo.SyncStatUpdate = true;
            state.UpdateInfo.Rules = true;
            state.UpdateInfo.Cats = true;
            state.UpdateInfo.UpdateApplied = false;

            return new ParentCommandResult { Changed = true };
        }

        public static ParentCommandResult ExpireIfNeeded(GuardState state, DateTime utcNow)
        {
            if (state == null) throw new ArgumentNullException(nameof(state));
            EnsureState(state);

            if (!state.MaintenanceMode.IsActive ||
                !state.MaintenanceMode.UntilUtc.HasValue ||
                state.MaintenanceMode.UntilUtc.Value > utcNow)
            {
                return new ParentCommandResult { Changed = false };
            }

            return End(state, utcNow);
        }

        public static ParentCommandResult RefreshActiveState(GuardState state, DateTime utcNow)
        {
            if (state == null) throw new ArgumentNullException(nameof(state));
            EnsureState(state);

            if (!state.MaintenanceMode.IsActive)
            {
                return new ParentCommandResult { Changed = false };
            }

            if (state.MaintenanceMode.UntilUtc.HasValue &&
                state.MaintenanceMode.UntilUtc.Value <= utcNow)
            {
                return End(state, utcNow);
            }

            bool changed = false;
            if (state.SyncStatus)
            {
                state.SyncStatus = false;
                state.UpdateInfo.SyncStatUpdate = true;
                state.UpdateInfo.UpdateApplied = false;
                changed = true;
            }

            if (state.AppControl.Mode != ApplicationControlMode.Off)
            {
                state.AppControl.Mode = ApplicationControlMode.Off;
                state.AppControl.PolicyUpdatePending = true;
                changed = true;
            }

            if (state.AppControl.BlockTaskManager)
            {
                state.AppControl.BlockTaskManager = false;
                state.AppControl.PolicyUpdatePending = true;
                changed = true;
            }

            if (state.AppControl.TaskManagerAllowedUntilUtc != state.MaintenanceMode.UntilUtc)
            {
                state.AppControl.TaskManagerAllowedUntilUtc = state.MaintenanceMode.UntilUtc;
                state.AppControl.PolicyUpdatePending = true;
                changed = true;
            }

            return new ParentCommandResult { Changed = changed };
        }

        public static string Describe(MaintenanceModeState state, DateTime utcNow)
        {
            if (state == null || !state.IsActive)
            {
                return "protection mode";
            }

            if (!state.UntilUtc.HasValue)
            {
                return "maintenance mode active";
            }

            var remaining = state.UntilUtc.Value - utcNow;
            if (remaining <= TimeSpan.Zero)
            {
                return "maintenance mode expiring";
            }

            var minutesLeft = Math.Max(1, (int)Math.Ceiling(remaining.TotalMinutes));
            return "maintenance mode, " + minutesLeft + " min left";
        }

        private static void ApplyPausedProtectionState(GuardState state, DateTime utcNow)
        {
            state.SyncStatus = false;
            state.UpdateInfo.SyncStatUpdate = true;
            state.UpdateInfo.UpdateApplied = false;

            state.AppControl.Mode = ApplicationControlMode.Off;
            state.AppControl.BlockTaskManager = false;
            state.AppControl.TaskManagerAllowedUntilUtc = state.MaintenanceMode.UntilUtc;
            state.AppControl.PolicyUpdatePending = true;
        }

        private static void EnsureState(GuardState state)
        {
            if (state.AppControl == null)
            {
                state.AppControl = new ApplicationControlSettings();
            }

            if (state.MaintenanceMode == null)
            {
                state.MaintenanceMode = new MaintenanceModeState();
            }
        }
    }
}
