using System;

namespace Guard.Contracts
{
    public static class GuardProtocol
    {
        public const int CurrentVersion = 1;
        public const int MaximumFrameBytes = 64 * 1024;
        public const int MaximumReasonCharacters = 280;
        public const int MaximumTargetCharacters = 2048;
        public const int MaximumParentPublicKeyBytes = 1024;
        public const int MaximumWindowsSidCharacters = 184;
        public const int SetupSecretBytes = 32;
        public const int MaximumConcurrentPipeConnections = 8;
        public const int DefaultIpcReadTimeoutMilliseconds = 5000;
        public const int MaximumIpcReadTimeoutMilliseconds = 30000;
        public const int MaximumManagedBrowserCount = 16;
        public const int MaximumReadinessFindings = 9;
        public const int MaximumReadinessCodeCharacters = 96;
    }

    public static class GuardIdentifier
    {
        public const int MinimumCharacters = 16;
        public const int MaximumCharacters = 128;

        public static bool IsCanonicalToken(string value)
        {
            if (string.IsNullOrWhiteSpace(value) ||
                value.Length < MinimumCharacters ||
                value.Length > MaximumCharacters)
            {
                return false;
            }

            for (var index = 0; index < value.Length; index++)
            {
                var character = value[index];
                if (!((character >= 'a' && character <= 'z') ||
                      (character >= 'A' && character <= 'Z') ||
                      (character >= '0' && character <= '9') ||
                      character == '-' || character == '_' || character == '.' || character == ':'))
                {
                    return false;
                }
            }

            return true;
        }
    }

    public enum ClientRole
    {
        Unknown = 0,
        Child = 1,
        AdminSetup = 2,
        Proxy = 3,
        ParentRelay = 4,
        ServiceInternal = 5
    }

    public enum GuardVerb
    {
        Unknown = 0,
        GetStatus = 1,
        GetReadiness = 2,
        CreateApplicationRequest = 10,
        CreateWebsiteRequest = 11,
        EvaluateDomain = 20,
        BeginSetup = 30,
        CompleteSetup = 31,
        BindChildAccount = 32,
        ApplyParentDecision = 40,
        ReconcilePolicy = 50
    }

    public sealed class GuardIpcRequest
    {
        private readonly byte[] _payloadUtf8;

        public GuardIpcRequest(
            int protocolVersion,
            string requestId,
            GuardVerb verb,
            byte[] payloadUtf8)
        {
            ProtocolVersion = protocolVersion;
            RequestId = requestId ?? string.Empty;
            Verb = verb;
            _payloadUtf8 = payloadUtf8 == null ? Array.Empty<byte>() : (byte[])payloadUtf8.Clone();
        }

        public int ProtocolVersion { get; }

        public string RequestId { get; }

        public GuardVerb Verb { get; }

        public int PayloadLength => _payloadUtf8.Length;

        public byte[] GetPayloadCopy()
        {
            return (byte[])_payloadUtf8.Clone();
        }
    }

    public enum GuardIpcResponseStatus
    {
        Success = 0,
        Rejected = 1,
        Forbidden = 2,
        Conflict = 3,
        Unavailable = 4,
        InvalidRequest = 5,
        InternalError = 6
    }

    public sealed class GuardIpcResponse
    {
        private readonly byte[] _payloadUtf8;

        public GuardIpcResponse(
            int protocolVersion,
            string requestId,
            GuardIpcResponseStatus status,
            byte[] payloadUtf8)
        {
            ProtocolVersion = protocolVersion;
            RequestId = requestId ?? string.Empty;
            Status = status;
            _payloadUtf8 = payloadUtf8 == null ? Array.Empty<byte>() : (byte[])payloadUtf8.Clone();
        }

        public int ProtocolVersion { get; }

        public string RequestId { get; }

        public GuardIpcResponseStatus Status { get; }

        public int PayloadLength => _payloadUtf8.Length;

        public byte[] GetPayloadCopy()
        {
            return (byte[])_payloadUtf8.Clone();
        }
    }

    public sealed class BindChildAccountRequest
    {
        public BindChildAccountRequest(string candidateSid)
        {
            if (string.IsNullOrWhiteSpace(candidateSid) ||
                candidateSid.Length > GuardProtocol.MaximumWindowsSidCharacters)
            {
                throw new ArgumentException("A bounded candidate SID is required.", nameof(candidateSid));
            }

            for (var index = 0; index < candidateSid.Length; index++)
            {
                var character = candidateSid[index];
                if (character > 0x7F || char.IsControl(character))
                {
                    throw new ArgumentException("The candidate SID must contain printable ASCII.", nameof(candidateSid));
                }
            }

            CandidateSid = candidateSid;
        }

        public string CandidateSid { get; }
    }

    public sealed class GuardStatusPayload
    {
        public GuardStatusPayload(
            long stateVersion,
            bool isProvisioned,
            bool isChildAccountBound)
        {
            if (stateVersion < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(stateVersion));
            }

            StateVersion = stateVersion;
            IsProvisioned = isProvisioned;
            IsChildAccountBound = isChildAccountBound;
        }

        public long StateVersion { get; }

        public bool IsProvisioned { get; }

        public bool IsChildAccountBound { get; }
    }

    public enum GuardReadinessFactState
    {
        Satisfied = 0,
        Unsatisfied = 1,
        Unknown = 2,
        Error = 3
    }

    public enum GuardReadinessFindingSeverity
    {
        Blocking = 0,
        Warning = 1,
        Ready = 2
    }

    public static class GuardReadinessFindingCodes
    {
        public const string WindowsEditionReady =
            "READINESS_WINDOWS_11_PRO";
        public const string WindowsEditionBlocking =
            "READINESS_WINDOWS_11_PRO_REQUIRED";
        public const string ChildAccountReady =
            "READINESS_CHILD_STANDARD_ACCOUNT";
        public const string ChildAccountBlocking =
            "READINESS_CHILD_STANDARD_ACCOUNT_REQUIRED";
        public const string SeparateLocalAdministratorReady =
            "READINESS_SEPARATE_LOCAL_ADMINISTRATOR";
        public const string SeparateLocalAdministratorBlocking =
            "READINESS_SEPARATE_LOCAL_ADMINISTRATOR_REQUIRED";
        public const string SecureBootReady =
            "READINESS_SECURE_BOOT_ENABLED";
        public const string SecureBootBlocking =
            "READINESS_SECURE_BOOT_REQUIRED";
        public const string BitLockerReady =
            "READINESS_BITLOCKER_ENABLED";
        public const string BitLockerBlocking =
            "READINESS_BITLOCKER_REQUIRED";
        public const string ServiceBoundaryReady =
            "READINESS_SERVICE_BOUNDARY_HEALTHY";
        public const string ServiceBoundaryBlocking =
            "READINESS_SERVICE_BOUNDARY_HEALTHY_REQUIRED";
        public const string ProgramDataAclReady =
            "READINESS_PROGRAMDATA_ACL_HEALTHY";
        public const string ProgramDataAclBlocking =
            "READINESS_PROGRAMDATA_ACL_HEALTHY_REQUIRED";
        public const string SupportedManagedBrowserReady =
            "READINESS_SUPPORTED_MANAGED_BROWSER";
        public const string SupportedManagedBrowserBlocking =
            "READINESS_SUPPORTED_MANAGED_BROWSER_REQUIRED";
        public const string LimitedBrowserCoverageWarning =
            "READINESS_LIMITED_MANAGED_BROWSER_COVERAGE";
    }

    public sealed class GuardReadinessFindingPayload
    {
        public GuardReadinessFindingPayload(
            string code,
            GuardReadinessFindingSeverity severity)
        {
            if (string.IsNullOrWhiteSpace(code) ||
                code.Length > GuardProtocol.MaximumReadinessCodeCharacters)
            {
                throw new ArgumentException(
                    "A bounded readiness finding code is required.",
                    nameof(code));
            }

            for (var index = 0; index < code.Length; index++)
            {
                if (code[index] > 0x7F || char.IsControl(code[index]))
                {
                    throw new ArgumentException(
                        "Readiness finding codes must contain printable ASCII.",
                        nameof(code));
                }
            }

            if (!Enum.IsDefined(
                    typeof(GuardReadinessFindingSeverity),
                    severity))
            {
                throw new ArgumentOutOfRangeException(nameof(severity));
            }

            Code = code;
            Severity = severity;
        }

        public string Code { get; }

        public GuardReadinessFindingSeverity Severity { get; }
    }

    public sealed class GuardReadinessPayload
    {
        private readonly GuardReadinessFindingPayload[] _findings;

        public GuardReadinessPayload(
            long stateVersion,
            DateTimeOffset observedAtUtc,
            GuardReadinessFactState windowsEdition,
            GuardReadinessFactState childAccount,
            GuardReadinessFactState separateLocalAdministrator,
            GuardReadinessFactState secureBoot,
            GuardReadinessFactState bitLocker,
            GuardReadinessFactState serviceBoundary,
            GuardReadinessFactState programDataAcl,
            GuardReadinessFactState supportedManagedBrowser,
            int managedBrowserCount,
            bool canEnableProtection,
            GuardReadinessFindingPayload[] findings)
        {
            if (stateVersion < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(stateVersion));
            }

            RequireFactState(windowsEdition, nameof(windowsEdition));
            RequireFactState(childAccount, nameof(childAccount));
            RequireFactState(
                separateLocalAdministrator,
                nameof(separateLocalAdministrator));
            RequireFactState(secureBoot, nameof(secureBoot));
            RequireFactState(bitLocker, nameof(bitLocker));
            RequireFactState(serviceBoundary, nameof(serviceBoundary));
            RequireFactState(programDataAcl, nameof(programDataAcl));
            RequireFactState(
                supportedManagedBrowser,
                nameof(supportedManagedBrowser));

            if (managedBrowserCount < 0 ||
                managedBrowserCount > GuardProtocol.MaximumManagedBrowserCount)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(managedBrowserCount));
            }

            if ((supportedManagedBrowser ==
                 GuardReadinessFactState.Satisfied) !=
                (managedBrowserCount > 0))
            {
                throw new ArgumentException(
                    "Only a satisfied browser fact may carry a browser count.",
                    nameof(managedBrowserCount));
            }

            var allFactsSatisfied =
                windowsEdition == GuardReadinessFactState.Satisfied &&
                childAccount == GuardReadinessFactState.Satisfied &&
                separateLocalAdministrator ==
                    GuardReadinessFactState.Satisfied &&
                secureBoot == GuardReadinessFactState.Satisfied &&
                bitLocker == GuardReadinessFactState.Satisfied &&
                serviceBoundary == GuardReadinessFactState.Satisfied &&
                programDataAcl == GuardReadinessFactState.Satisfied &&
                supportedManagedBrowser ==
                    GuardReadinessFactState.Satisfied;
            if (canEnableProtection != allFactsSatisfied)
            {
                throw new ArgumentException(
                    "The protection flag does not match the readiness facts.",
                    nameof(canEnableProtection));
            }

            if (findings == null ||
                findings.Length < 8 ||
                findings.Length > GuardProtocol.MaximumReadinessFindings)
            {
                throw new ArgumentException(
                    "A complete bounded readiness finding set is required.",
                    nameof(findings));
            }

            _findings =
                new GuardReadinessFindingPayload[findings.Length];
            for (var index = 0; index < findings.Length; index++)
            {
                var finding = findings[index] ??
                    throw new ArgumentException(
                        "Readiness findings cannot contain null.",
                        nameof(findings));
                for (var earlier = 0; earlier < index; earlier++)
                {
                    if (string.Equals(
                        findings[earlier].Code,
                        finding.Code,
                        StringComparison.Ordinal))
                    {
                        throw new ArgumentException(
                            "Readiness finding codes must be unique.",
                            nameof(findings));
                    }
                }

                _findings[index] = finding;
            }

            ValidateFindingSet(
                _findings,
                windowsEdition,
                childAccount,
                separateLocalAdministrator,
                secureBoot,
                bitLocker,
                serviceBoundary,
                programDataAcl,
                supportedManagedBrowser,
                managedBrowserCount);

            StateVersion = stateVersion;
            ObservedAtUtc = observedAtUtc.ToUniversalTime();
            WindowsEdition = windowsEdition;
            ChildAccount = childAccount;
            SeparateLocalAdministrator = separateLocalAdministrator;
            SecureBoot = secureBoot;
            BitLocker = bitLocker;
            ServiceBoundary = serviceBoundary;
            ProgramDataAcl = programDataAcl;
            SupportedManagedBrowser = supportedManagedBrowser;
            ManagedBrowserCount = managedBrowserCount;
            CanEnableProtection = canEnableProtection;
        }

        public long StateVersion { get; }

        public DateTimeOffset ObservedAtUtc { get; }

        public GuardReadinessFactState WindowsEdition { get; }

        public GuardReadinessFactState ChildAccount { get; }

        public GuardReadinessFactState SeparateLocalAdministrator { get; }

        public GuardReadinessFactState SecureBoot { get; }

        public GuardReadinessFactState BitLocker { get; }

        public GuardReadinessFactState ServiceBoundary { get; }

        public GuardReadinessFactState ProgramDataAcl { get; }

        public GuardReadinessFactState SupportedManagedBrowser { get; }

        public int ManagedBrowserCount { get; }

        public bool CanEnableProtection { get; }

        public GuardReadinessFindingPayload[] GetFindingsCopy()
        {
            return (GuardReadinessFindingPayload[])_findings.Clone();
        }

        private static void RequireFactState(
            GuardReadinessFactState state,
            string parameterName)
        {
            if (!Enum.IsDefined(typeof(GuardReadinessFactState), state))
            {
                throw new ArgumentOutOfRangeException(parameterName);
            }
        }

        private static void ValidateFindingSet(
            GuardReadinessFindingPayload[] findings,
            GuardReadinessFactState windowsEdition,
            GuardReadinessFactState childAccount,
            GuardReadinessFactState separateLocalAdministrator,
            GuardReadinessFactState secureBoot,
            GuardReadinessFactState bitLocker,
            GuardReadinessFactState serviceBoundary,
            GuardReadinessFactState programDataAcl,
            GuardReadinessFactState supportedManagedBrowser,
            int managedBrowserCount)
        {
            RequireOutcome(
                findings,
                windowsEdition,
                GuardReadinessFindingCodes.WindowsEditionReady,
                GuardReadinessFindingCodes.WindowsEditionBlocking);
            RequireOutcome(
                findings,
                childAccount,
                GuardReadinessFindingCodes.ChildAccountReady,
                GuardReadinessFindingCodes.ChildAccountBlocking);
            RequireOutcome(
                findings,
                separateLocalAdministrator,
                GuardReadinessFindingCodes
                    .SeparateLocalAdministratorReady,
                GuardReadinessFindingCodes
                    .SeparateLocalAdministratorBlocking);
            RequireOutcome(
                findings,
                secureBoot,
                GuardReadinessFindingCodes.SecureBootReady,
                GuardReadinessFindingCodes.SecureBootBlocking);
            RequireOutcome(
                findings,
                bitLocker,
                GuardReadinessFindingCodes.BitLockerReady,
                GuardReadinessFindingCodes.BitLockerBlocking);
            RequireOutcome(
                findings,
                serviceBoundary,
                GuardReadinessFindingCodes.ServiceBoundaryReady,
                GuardReadinessFindingCodes.ServiceBoundaryBlocking);
            RequireOutcome(
                findings,
                programDataAcl,
                GuardReadinessFindingCodes.ProgramDataAclReady,
                GuardReadinessFindingCodes.ProgramDataAclBlocking);
            RequireOutcome(
                findings,
                supportedManagedBrowser,
                GuardReadinessFindingCodes.SupportedManagedBrowserReady,
                GuardReadinessFindingCodes
                    .SupportedManagedBrowserBlocking);

            var needsBrowserWarning =
                supportedManagedBrowser ==
                    GuardReadinessFactState.Satisfied &&
                managedBrowserCount == 1;
            var warningCount = CountFinding(
                findings,
                GuardReadinessFindingCodes
                    .LimitedBrowserCoverageWarning,
                GuardReadinessFindingSeverity.Warning);
            if ((needsBrowserWarning && warningCount != 1) ||
                (!needsBrowserWarning && warningCount != 0) ||
                findings.Length != 8 + (needsBrowserWarning ? 1 : 0))
            {
                throw new ArgumentException(
                    "The readiness finding set is inconsistent.",
                    nameof(findings));
            }
        }

        private static void RequireOutcome(
            GuardReadinessFindingPayload[] findings,
            GuardReadinessFactState state,
            string readyCode,
            string blockingCode)
        {
            var expectsReady =
                state == GuardReadinessFactState.Satisfied;
            var expectedCount = CountFinding(
                findings,
                expectsReady ? readyCode : blockingCode,
                expectsReady
                    ? GuardReadinessFindingSeverity.Ready
                    : GuardReadinessFindingSeverity.Blocking);
            var oppositeCount = CountCode(
                findings,
                expectsReady ? blockingCode : readyCode);
            if (expectedCount != 1 || oppositeCount != 0)
            {
                throw new ArgumentException(
                    "A readiness outcome does not match its fact.",
                    nameof(findings));
            }
        }

        private static int CountFinding(
            GuardReadinessFindingPayload[] findings,
            string code,
            GuardReadinessFindingSeverity severity)
        {
            var count = 0;
            for (var index = 0; index < findings.Length; index++)
            {
                if (string.Equals(
                        findings[index].Code,
                        code,
                        StringComparison.Ordinal) &&
                    findings[index].Severity == severity)
                {
                    count++;
                }
            }

            return count;
        }

        private static int CountCode(
            GuardReadinessFindingPayload[] findings,
            string code)
        {
            var count = 0;
            for (var index = 0; index < findings.Length; index++)
            {
                if (string.Equals(
                    findings[index].Code,
                    code,
                    StringComparison.Ordinal))
                {
                    count++;
                }
            }

            return count;
        }
    }

    public sealed class SetupTicketPayload
    {
        private readonly byte[] _secret;

        public SetupTicketPayload(
            string challengeId,
            byte[] secret,
            DateTimeOffset expiresAtUtc)
        {
            if (!GuardIdentifier.IsCanonicalToken(challengeId))
            {
                throw new ArgumentException(
                    "A canonical setup challenge id is required.",
                    nameof(challengeId));
            }

            if (secret == null || secret.Length != GuardProtocol.SetupSecretBytes)
            {
                throw new ArgumentException(
                    "A complete setup secret is required.",
                    nameof(secret));
            }

            ChallengeId = challengeId;
            _secret = (byte[])secret.Clone();
            ExpiresAtUtc = expiresAtUtc.ToUniversalTime();
        }

        public string ChallengeId { get; }

        public DateTimeOffset ExpiresAtUtc { get; }

        public byte[] GetSecretCopy()
        {
            return (byte[])_secret.Clone();
        }
    }

    public sealed class ChildAccountBindingPayload
    {
        public ChildAccountBindingPayload(bool serviceRestartRequired)
        {
            ServiceRestartRequired = serviceRestartRequired;
        }

        public bool ServiceRestartRequired { get; }
    }

    public enum ParentDecisionKind
    {
        Unknown = 0,
        AllowAlways = 1,
        AllowTemporary = 2,
        AllowDailyQuota = 3,
        Deny = 4
    }

    public enum GuardTargetKind
    {
        Unknown = 0,
        Application = 1,
        Site = 2
    }

    public sealed class ParentDecisionCommand
    {
        public ParentDecisionCommand(
            string requestId,
            GuardTargetKind targetKind,
            string targetIdentity,
            ParentDecisionKind decision,
            int? temporaryMinutes = null,
            int? dailyQuotaMinutes = null)
        {
            Guid parsedRequestId;
            if (!Guid.TryParseExact(requestId, "D", out parsedRequestId))
            {
                throw new ArgumentException("A canonical request id is required.", nameof(requestId));
            }

            if (!Enum.IsDefined(typeof(GuardTargetKind), targetKind) || targetKind == GuardTargetKind.Unknown)
            {
                throw new ArgumentOutOfRangeException(nameof(targetKind));
            }

            if (string.IsNullOrWhiteSpace(targetIdentity) || targetIdentity.Length > GuardProtocol.MaximumTargetCharacters)
            {
                throw new ArgumentException("A bounded target identity is required.", nameof(targetIdentity));
            }

            for (var index = 0; index < targetIdentity.Length; index++)
            {
                if (char.IsControl(targetIdentity[index]))
                {
                    throw new ArgumentException("Target identities cannot contain control characters.", nameof(targetIdentity));
                }
            }

            if (!Enum.IsDefined(typeof(ParentDecisionKind), decision) || decision == ParentDecisionKind.Unknown)
            {
                throw new ArgumentOutOfRangeException(nameof(decision));
            }

            if (decision == ParentDecisionKind.AllowTemporary)
            {
                if (!temporaryMinutes.HasValue || temporaryMinutes.Value < 1 || temporaryMinutes.Value > 1440 || dailyQuotaMinutes.HasValue)
                {
                    throw new ArgumentException("A temporary decision requires 1 to 1440 minutes and no quota.");
                }
            }
            else if (decision == ParentDecisionKind.AllowDailyQuota)
            {
                if (!dailyQuotaMinutes.HasValue || dailyQuotaMinutes.Value < 1 || dailyQuotaMinutes.Value > 1440 || temporaryMinutes.HasValue)
                {
                    throw new ArgumentException("A daily-quota decision requires 1 to 1440 minutes and no temporary duration.");
                }
            }
            else if (temporaryMinutes.HasValue || dailyQuotaMinutes.HasValue)
            {
                throw new ArgumentException("Always-allow and deny decisions cannot carry time values.");
            }

            RequestId = requestId;
            TargetKind = targetKind;
            TargetIdentity = targetIdentity;
            Decision = decision;
            TemporaryMinutes = temporaryMinutes;
            DailyQuotaMinutes = dailyQuotaMinutes;
        }

        public string RequestId { get; }

        public GuardTargetKind TargetKind { get; }

        public string TargetIdentity { get; }

        public ParentDecisionKind Decision { get; }

        public int? TemporaryMinutes { get; }

        public int? DailyQuotaMinutes { get; }
    }

    public sealed class SignedCommandEnvelope
    {
        private readonly byte[] _canonicalPayload;
        private readonly byte[] _signature;

        public SignedCommandEnvelope(
            string commandId,
            string deviceId,
            long sequence,
            DateTimeOffset issuedAtUtc,
            DateTimeOffset expiresAtUtc,
            string nonce,
            string keyId,
            byte[] canonicalPayload,
            byte[] signature)
        {
            CommandId = commandId ?? string.Empty;
            DeviceId = deviceId ?? string.Empty;
            Sequence = sequence;
            IssuedAtUtc = issuedAtUtc;
            ExpiresAtUtc = expiresAtUtc;
            Nonce = nonce ?? string.Empty;
            KeyId = keyId ?? string.Empty;
            _canonicalPayload = canonicalPayload == null ? Array.Empty<byte>() : (byte[])canonicalPayload.Clone();
            _signature = signature == null ? Array.Empty<byte>() : (byte[])signature.Clone();
        }

        public string CommandId { get; }

        public string DeviceId { get; }

        public long Sequence { get; }

        public DateTimeOffset IssuedAtUtc { get; }

        public DateTimeOffset ExpiresAtUtc { get; }

        public string Nonce { get; }

        public string KeyId { get; }

        public int PayloadLength => _canonicalPayload.Length;

        public int SignatureLength => _signature.Length;

        public byte[] GetCanonicalPayloadCopy()
        {
            return (byte[])_canonicalPayload.Clone();
        }

        public byte[] GetSignatureCopy()
        {
            return (byte[])_signature.Clone();
        }
    }
}
