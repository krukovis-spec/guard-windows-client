using System;
using System.Collections.Generic;

namespace Guard.Domain.Readiness
{
    public enum ReadinessFindingSeverity
    {
        Blocking = 0,
        Warning = 1,
        Ready = 2
    }

    public static class ReadinessFindingCodes
    {
        public const string WindowsEditionReady = "READINESS_WINDOWS_11_PRO_OR_SUPPORTED";
        public const string WindowsEditionBlocking = "READINESS_WINDOWS_11_PRO_OR_SUPPORTED_REQUIRED";
        public const string ChildAccountReady = "READINESS_CHILD_STANDARD_ACCOUNT";
        public const string ChildAccountBlocking = "READINESS_CHILD_STANDARD_ACCOUNT_REQUIRED";
        public const string SeparateLocalAdministratorReady = "READINESS_SEPARATE_LOCAL_ADMINISTRATOR";
        public const string SeparateLocalAdministratorBlocking = "READINESS_SEPARATE_LOCAL_ADMINISTRATOR_REQUIRED";
        public const string SecureBootReady = "READINESS_SECURE_BOOT_ENABLED";
        public const string SecureBootBlocking = "READINESS_SECURE_BOOT_REQUIRED";
        public const string BitLockerReady = "READINESS_BITLOCKER_ENABLED";
        public const string BitLockerBlocking = "READINESS_BITLOCKER_REQUIRED";
        public const string ServiceBoundaryReady = "READINESS_SERVICE_BOUNDARY_HEALTHY";
        public const string ServiceBoundaryBlocking = "READINESS_SERVICE_BOUNDARY_HEALTHY_REQUIRED";
        public const string ProgramDataAclReady = "READINESS_PROGRAMDATA_ACL_HEALTHY";
        public const string ProgramDataAclBlocking = "READINESS_PROGRAMDATA_ACL_HEALTHY_REQUIRED";
        public const string SupportedManagedBrowserReady = "READINESS_SUPPORTED_MANAGED_BROWSER";
        public const string SupportedManagedBrowserBlocking = "READINESS_SUPPORTED_MANAGED_BROWSER_REQUIRED";
        public const string LimitedBrowserCoverageWarning = "READINESS_LIMITED_MANAGED_BROWSER_COVERAGE";
    }

    public sealed class ReadinessFinding
    {
        public ReadinessFinding(string code, ReadinessFindingSeverity severity)
        {
            if (string.IsNullOrWhiteSpace(code))
            {
                throw new ArgumentException("A stable finding code is required.", nameof(code));
            }

            if (!Enum.IsDefined(typeof(ReadinessFindingSeverity), severity))
            {
                throw new ArgumentOutOfRangeException(nameof(severity));
            }

            Code = code;
            Severity = severity;
        }

        public string Code { get; }

        public ReadinessFindingSeverity Severity { get; }

    }

    public sealed class ReadinessEvaluation
    {
        private sealed class RequiredOutcome
        {
            public RequiredOutcome(string readyCode, string blockingCode)
            {
                ReadyCode = readyCode;
                BlockingCode = blockingCode;
            }

            public string ReadyCode { get; }

            public string BlockingCode { get; }
        }

        private static readonly RequiredOutcome[] RequiredOutcomes =
        {
            new RequiredOutcome(ReadinessFindingCodes.WindowsEditionReady, ReadinessFindingCodes.WindowsEditionBlocking),
            new RequiredOutcome(ReadinessFindingCodes.ChildAccountReady, ReadinessFindingCodes.ChildAccountBlocking),
            new RequiredOutcome(ReadinessFindingCodes.SeparateLocalAdministratorReady, ReadinessFindingCodes.SeparateLocalAdministratorBlocking),
            new RequiredOutcome(ReadinessFindingCodes.SecureBootReady, ReadinessFindingCodes.SecureBootBlocking),
            new RequiredOutcome(ReadinessFindingCodes.BitLockerReady, ReadinessFindingCodes.BitLockerBlocking),
            new RequiredOutcome(ReadinessFindingCodes.ServiceBoundaryReady, ReadinessFindingCodes.ServiceBoundaryBlocking),
            new RequiredOutcome(ReadinessFindingCodes.ProgramDataAclReady, ReadinessFindingCodes.ProgramDataAclBlocking),
            new RequiredOutcome(ReadinessFindingCodes.SupportedManagedBrowserReady, ReadinessFindingCodes.SupportedManagedBrowserBlocking)
        };

        private readonly ReadinessFinding[] _findings;

        public ReadinessEvaluation(IEnumerable<ReadinessFinding> findings)
        {
            if (findings == null)
            {
                throw new ArgumentNullException(nameof(findings));
            }

            var copied = new List<ReadinessFinding>();
            foreach (var finding in findings)
            {
                if (finding == null)
                {
                    throw new ArgumentException("Findings cannot contain null values.", nameof(findings));
                }

                copied.Add(finding);
            }

            _findings = copied.ToArray();
        }

        public IReadOnlyList<ReadinessFinding> Findings => Array.AsReadOnly((ReadinessFinding[])_findings.Clone());

        public bool CanEnableProtection
        {
            get
            {
                if (!HasExactlyOneReadyOutcomeForEachRequiredCheck())
                {
                    return false;
                }

                return true;
            }
        }

        private bool HasExactlyOneReadyOutcomeForEachRequiredCheck()
        {
            var recognizedFindingCount = 0;
            var limitedBrowserWarningCount = 0;

            for (var outcomeIndex = 0; outcomeIndex < RequiredOutcomes.Length; outcomeIndex++)
            {
                var outcome = RequiredOutcomes[outcomeIndex];
                var readyCount = 0;
                var blockingCount = 0;

                for (var findingIndex = 0; findingIndex < _findings.Length; findingIndex++)
                {
                    var finding = _findings[findingIndex];
                    if (string.Equals(finding.Code, outcome.ReadyCode, StringComparison.Ordinal))
                    {
                        if (finding.Severity != ReadinessFindingSeverity.Ready)
                        {
                            return false;
                        }

                        readyCount++;
                        recognizedFindingCount++;
                    }
                    else if (string.Equals(finding.Code, outcome.BlockingCode, StringComparison.Ordinal))
                    {
                        if (finding.Severity != ReadinessFindingSeverity.Blocking)
                        {
                            return false;
                        }

                        blockingCount++;
                        recognizedFindingCount++;
                    }
                }

                if (readyCount != 1 || blockingCount != 0)
                {
                    return false;
                }
            }

            for (var findingIndex = 0; findingIndex < _findings.Length; findingIndex++)
            {
                var finding = _findings[findingIndex];
                if (string.Equals(finding.Code, ReadinessFindingCodes.LimitedBrowserCoverageWarning, StringComparison.Ordinal) &&
                    finding.Severity == ReadinessFindingSeverity.Warning)
                {
                    recognizedFindingCount++;
                    limitedBrowserWarningCount++;
                }
            }

            return limitedBrowserWarningCount <= 1 && recognizedFindingCount == _findings.Length;
        }
    }
}
