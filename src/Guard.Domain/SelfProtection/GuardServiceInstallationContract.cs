using System;
using System.Collections.Generic;

namespace Guard.Domain.SelfProtection
{
    public enum ServiceInstallationObservationState
    {
        Observed = 0,
        NotInstalled = 1,
        Unknown = 2,
        Error = 3
    }

    public enum GuardServiceStartPolicy
    {
        Unspecified = 0,
        Automatic = 1,
        AutomaticDelayed = 2,
        Manual = 3,
        Disabled = 4
    }

    public enum GuardServiceSidPolicy
    {
        None = 0,
        Unrestricted = 1,
        Restricted = 2
    }

    public sealed class ObservedGuardServiceInstallation
    {
        public ObservedGuardServiceInstallation(
            ServiceInstallationObservationState observationState,
            string serviceName,
            string accountSid,
            bool isOwnProcess,
            bool isInteractive,
            GuardServiceStartPolicy startPolicy,
            GuardServiceSidPolicy serviceSidPolicy,
            bool recoveryActionsConfigured,
            bool standardUsersCanStop,
            bool standardUsersCanChangeConfiguration,
            bool standardUsersCanDelete,
            bool binaryPathMatchesExpected,
            bool installRootProtected,
            bool installRootIsReparsePoint,
            bool legacyAuthorityDisabled)
        {
            if (!Enum.IsDefined(
                    typeof(ServiceInstallationObservationState),
                    observationState))
            {
                throw new ArgumentOutOfRangeException(
                    nameof(observationState));
            }

            ObservationState = observationState;
            ServiceName = serviceName ?? string.Empty;
            AccountSid = accountSid ?? string.Empty;
            IsOwnProcess = isOwnProcess;
            IsInteractive = isInteractive;
            StartPolicy = startPolicy;
            ServiceSidPolicy = serviceSidPolicy;
            RecoveryActionsConfigured = recoveryActionsConfigured;
            StandardUsersCanStop = standardUsersCanStop;
            StandardUsersCanChangeConfiguration =
                standardUsersCanChangeConfiguration;
            StandardUsersCanDelete = standardUsersCanDelete;
            BinaryPathMatchesExpected = binaryPathMatchesExpected;
            InstallRootProtected = installRootProtected;
            InstallRootIsReparsePoint = installRootIsReparsePoint;
            LegacyAuthorityDisabled = legacyAuthorityDisabled;
        }

        public ServiceInstallationObservationState ObservationState { get; }

        public string ServiceName { get; }

        public string AccountSid { get; }

        public bool IsOwnProcess { get; }

        public bool IsInteractive { get; }

        public GuardServiceStartPolicy StartPolicy { get; }

        public GuardServiceSidPolicy ServiceSidPolicy { get; }

        public bool RecoveryActionsConfigured { get; }

        public bool StandardUsersCanStop { get; }

        public bool StandardUsersCanChangeConfiguration { get; }

        public bool StandardUsersCanDelete { get; }

        public bool BinaryPathMatchesExpected { get; }

        public bool InstallRootProtected { get; }

        public bool InstallRootIsReparsePoint { get; }

        public bool LegacyAuthorityDisabled { get; }
    }

    public enum GuardServiceInstallationFailure
    {
        NotInstalled = 1,
        ObservationUnavailable = 2,
        ObservationError = 3,
        ServiceNameMismatch = 4,
        AccountNotLocalSystem = 5,
        NotOwnProcess = 6,
        InteractiveService = 7,
        StartPolicyNotAutomatic = 8,
        ServiceSidMissing = 9,
        RecoveryActionsMissing = 10,
        StandardUserServiceControl = 11,
        BinaryPathMismatch = 12,
        InstallRootUnprotected = 13,
        InstallRootReparsePoint = 14,
        LegacyAuthorityActive = 15
    }

    public sealed class GuardServiceInstallationEvaluation
    {
        private readonly GuardServiceInstallationFailure[] _failures;

        public GuardServiceInstallationEvaluation(
            IEnumerable<GuardServiceInstallationFailure> failures)
        {
            if (failures == null)
            {
                throw new ArgumentNullException(nameof(failures));
            }

            var copy = new List<GuardServiceInstallationFailure>();
            foreach (var failure in failures)
            {
                if (!Enum.IsDefined(
                        typeof(GuardServiceInstallationFailure),
                        failure))
                {
                    throw new ArgumentOutOfRangeException(
                        nameof(failures));
                }

                copy.Add(failure);
            }

            _failures = copy.ToArray();
        }

        public IReadOnlyList<GuardServiceInstallationFailure> Failures =>
            Array.AsReadOnly(
                (GuardServiceInstallationFailure[])_failures.Clone());

        public bool IsSatisfied => _failures.Length == 0;
    }

    public static class GuardServiceInstallationContract
    {
        public const string ServiceName = "Guard";
        public const string LocalSystemSid = "S-1-5-18";

        public static GuardServiceInstallationEvaluation Evaluate(
            ObservedGuardServiceInstallation observation)
        {
            if (observation == null)
            {
                throw new ArgumentNullException(nameof(observation));
            }

            if (observation.ObservationState !=
                ServiceInstallationObservationState.Observed)
            {
                return new GuardServiceInstallationEvaluation(
                    new[]
                    {
                        MapUnavailableObservation(
                            observation.ObservationState)
                    });
            }

            var failures =
                new List<GuardServiceInstallationFailure>();
            AddIf(
                failures,
                !string.Equals(
                    observation.ServiceName,
                    ServiceName,
                    StringComparison.Ordinal),
                GuardServiceInstallationFailure.ServiceNameMismatch);
            AddIf(
                failures,
                !string.Equals(
                    observation.AccountSid,
                    LocalSystemSid,
                    StringComparison.Ordinal),
                GuardServiceInstallationFailure.AccountNotLocalSystem);
            AddIf(
                failures,
                !observation.IsOwnProcess,
                GuardServiceInstallationFailure.NotOwnProcess);
            AddIf(
                failures,
                observation.IsInteractive,
                GuardServiceInstallationFailure.InteractiveService);
            AddIf(
                failures,
                observation.StartPolicy !=
                    GuardServiceStartPolicy.Automatic,
                GuardServiceInstallationFailure.StartPolicyNotAutomatic);
            AddIf(
                failures,
                observation.ServiceSidPolicy ==
                    GuardServiceSidPolicy.None ||
                !Enum.IsDefined(
                    typeof(GuardServiceSidPolicy),
                    observation.ServiceSidPolicy),
                GuardServiceInstallationFailure.ServiceSidMissing);
            AddIf(
                failures,
                !observation.RecoveryActionsConfigured,
                GuardServiceInstallationFailure.RecoveryActionsMissing);
            AddIf(
                failures,
                observation.StandardUsersCanStop ||
                observation.StandardUsersCanChangeConfiguration ||
                observation.StandardUsersCanDelete,
                GuardServiceInstallationFailure.StandardUserServiceControl);
            AddIf(
                failures,
                !observation.BinaryPathMatchesExpected,
                GuardServiceInstallationFailure.BinaryPathMismatch);
            AddIf(
                failures,
                !observation.InstallRootProtected,
                GuardServiceInstallationFailure.InstallRootUnprotected);
            AddIf(
                failures,
                observation.InstallRootIsReparsePoint,
                GuardServiceInstallationFailure.InstallRootReparsePoint);
            AddIf(
                failures,
                !observation.LegacyAuthorityDisabled,
                GuardServiceInstallationFailure.LegacyAuthorityActive);
            return new GuardServiceInstallationEvaluation(failures);
        }

        private static GuardServiceInstallationFailure
            MapUnavailableObservation(
                ServiceInstallationObservationState state)
        {
            switch (state)
            {
                case ServiceInstallationObservationState.NotInstalled:
                    return GuardServiceInstallationFailure.NotInstalled;

                case ServiceInstallationObservationState.Error:
                    return GuardServiceInstallationFailure.ObservationError;

                default:
                    return GuardServiceInstallationFailure
                        .ObservationUnavailable;
            }
        }

        private static void AddIf(
            ICollection<GuardServiceInstallationFailure> failures,
            bool condition,
            GuardServiceInstallationFailure failure)
        {
            if (condition)
            {
                failures.Add(failure);
            }
        }
    }
}
