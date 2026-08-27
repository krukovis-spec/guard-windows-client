using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Security.Principal;

namespace Guard.Windows.WebProtection
{
    public enum ManagedBrowserFamily
    {
        MicrosoftEdge = 0,
        GoogleChrome = 1
    }

    public enum LoopbackAddressFamily
    {
        IPv4 = 0,
        IPv6 = 1
    }

    public enum TrustedWebCatalogKind
    {
        PublicSuffixList = 0,
        SiteServiceCatalog = 1
    }

    public enum ExtensionUxEvidenceState
    {
        Healthy = 0,
        Missing = 1,
        DuplicateOrContradictory = 2,
        BindingMismatch = 3,
        Untrusted = 4,
        Future = 5,
        Stale = 6,
        VersionOrDigestMismatch = 7,
        Unhealthy = 8
    }

    public enum WebProtectionReadinessIssue
    {
        MissingListenerEvidence = 0,
        MissingBrowserPolicyEvidence = 1,
        MissingWfpEvidence = 2,
        MissingCatalogEvidence = 3,
        DuplicateEvidence = 4,
        UnexpectedEvidence = 5,
        ContradictoryEvidence = 6,
        UntrustedEvidence = 7,
        EvidenceBindingMismatch = 8,
        EvidenceFromFuture = 9,
        EvidenceStale = 10,
        ListenerEndpointMismatch = 11,
        ListenerNotExclusive = 12,
        ProxyIdentityMismatch = 13,
        ProxyPrivilegeMismatch = 14,
        ProxyProcessGenerationMismatch = 15,
        BrowserPolicyMismatch = 16,
        WfpPolicyMismatch = 17,
        WfpCoverageIncomplete = 18,
        WfpBrowserBindingMismatch = 19,
        CatalogMismatch = 20,
        CatalogUntrusted = 21,
        ChildAccountMismatch = 22,
        ProxyProcessHardeningMismatch = 23
    }

    [Flags]
    public enum WfpCoverageFlags : long
    {
        None = 0,
        AtomicFilterTransactionCommitted = 1L << 0,
        BoundToCurrentBoot = 1L << 1,
        IPv4Covered = 1L << 2,
        IPv6Covered = 1L << 3,
        BrowserTcpRestrictedToExactLoopbackProxy = 1L << 4,
        BrowserDirectTcpBlocked = 1L << 5,
        BrowserUdpBlocked = 1L << 6,
        BrowserQuicBlocked = 1L << 7,
        BrowserDirectDnsBlocked = 1L << 8,
        BrowserTcpAndWebSocketCovered = 1L << 9,
        DirectIpLiteralEgressBlocked = 1L << 10,
        ExternalProxyAndTunnelEgressBlocked = 1L << 11,
        UnsupportedBrowserEgressBlocked = 1L << 12,
        BypassToolEgressBlocked = 1L << 13,
        VpnEgressBlocked = 1L << 14,
        TorEgressBlocked = 1L << 15,
        ProxyEgressSeparatelyScoped = 1L << 16,
        NoBroadChildEgressAllow = 1L << 17,
        DenyFirstBaselineActive = 1L << 18,
        NoPolicyDriftDetected = 1L << 19,
        ProxyHeartbeatCurrent = 1L << 20,
        TunnelClosureVerified = 1L << 21,
        PersistentDenyRulesActive = 1L << 22,
        LoopbackReceiveAcceptBoundToExactProxyOwner = 1L << 23,
        OtherLoopbackAddressesBlocked = 1L << 24,
        LanAndLinkLocalEgressBlocked = 1L << 25,
        AllRequired =
            AtomicFilterTransactionCommitted |
            BoundToCurrentBoot |
            IPv4Covered |
            IPv6Covered |
            BrowserTcpRestrictedToExactLoopbackProxy |
            BrowserDirectTcpBlocked |
            BrowserUdpBlocked |
            BrowserQuicBlocked |
            BrowserDirectDnsBlocked |
            BrowserTcpAndWebSocketCovered |
            DirectIpLiteralEgressBlocked |
            ExternalProxyAndTunnelEgressBlocked |
            UnsupportedBrowserEgressBlocked |
            BypassToolEgressBlocked |
            VpnEgressBlocked |
            TorEgressBlocked |
            ProxyEgressSeparatelyScoped |
            NoBroadChildEgressAllow |
            DenyFirstBaselineActive |
            NoPolicyDriftDetected |
            ProxyHeartbeatCurrent |
            TunnelClosureVerified |
            PersistentDenyRulesActive |
            LoopbackReceiveAcceptBoundToExactProxyOwner |
            OtherLoopbackAddressesBlocked |
            LanAndLinkLocalEgressBlocked
    }

    public sealed class WebProtectionEvidenceBinding : IEquatable<WebProtectionEvidenceBinding>
    {
        public WebProtectionEvidenceBinding(
            Guid serviceBootNonce,
            Guid protectionInstanceId,
            Guid proxyLaunchId,
            long configurationVersion,
            string configurationDigestSha256)
        {
            if (serviceBootNonce == Guid.Empty)
            {
                throw new ArgumentException("A non-empty service-issued boot nonce is required.", nameof(serviceBootNonce));
            }

            if (protectionInstanceId == Guid.Empty)
            {
                throw new ArgumentException("A non-empty protection instance id is required.", nameof(protectionInstanceId));
            }

            if (proxyLaunchId == Guid.Empty)
            {
                throw new ArgumentException("A non-empty proxy launch id is required.", nameof(proxyLaunchId));
            }

            if (configurationVersion < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(configurationVersion));
            }

            WebProtectionValueValidator.RequireSha256(configurationDigestSha256, nameof(configurationDigestSha256));
            ServiceBootNonce = serviceBootNonce;
            ProtectionInstanceId = protectionInstanceId;
            ProxyLaunchId = proxyLaunchId;
            ConfigurationVersion = configurationVersion;
            ConfigurationDigestSha256 = configurationDigestSha256;
        }

        public Guid ServiceBootNonce { get; }

        public Guid ProtectionInstanceId { get; }

        public Guid ProxyLaunchId { get; }

        public long ConfigurationVersion { get; }

        public string ConfigurationDigestSha256 { get; }

        public bool Equals(WebProtectionEvidenceBinding? other)
        {
            return other != null &&
                ServiceBootNonce == other.ServiceBootNonce &&
                ProtectionInstanceId == other.ProtectionInstanceId &&
                ProxyLaunchId == other.ProxyLaunchId &&
                ConfigurationVersion == other.ConfigurationVersion &&
                string.Equals(ConfigurationDigestSha256, other.ConfigurationDigestSha256, StringComparison.Ordinal);
        }

        public override bool Equals(object? obj)
        {
            return Equals(obj as WebProtectionEvidenceBinding);
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(
                ServiceBootNonce,
                ProtectionInstanceId,
                ProxyLaunchId,
                ConfigurationVersion,
                StringComparer.Ordinal.GetHashCode(ConfigurationDigestSha256));
        }
    }

    public sealed class ServiceAttestationEnvelope
    {
        public ServiceAttestationEnvelope(
            WebProtectionEvidenceBinding binding,
            DateTimeOffset capturedAtUtc,
            DateTimeOffset validUntilUtc,
            bool isServiceAuthenticated)
        {
            Binding = binding ?? throw new ArgumentNullException(nameof(binding));
            WebProtectionValueValidator.RequireUtc(capturedAtUtc, nameof(capturedAtUtc));
            WebProtectionValueValidator.RequireUtc(validUntilUtc, nameof(validUntilUtc));
            if (validUntilUtc <= capturedAtUtc)
            {
                throw new ArgumentException("Attestation expiry must be later than capture time.", nameof(validUntilUtc));
            }

            if (validUntilUtc - capturedAtUtc > TimeSpan.FromMinutes(1))
            {
                throw new ArgumentException("Attestation lifetime must not exceed one minute.", nameof(validUntilUtc));
            }

            CapturedAtUtc = capturedAtUtc;
            ValidUntilUtc = validUntilUtc;
            IsServiceAuthenticated = isServiceAuthenticated;
        }

        public WebProtectionEvidenceBinding Binding { get; }

        public DateTimeOffset CapturedAtUtc { get; }

        public DateTimeOffset ValidUntilUtc { get; }

        public bool IsServiceAuthenticated { get; }
    }

    public sealed class ProxyProcessExpectation
    {
        public ProxyProcessExpectation(
            string dedicatedAccountSid,
            string executablePath,
            string executableVersion,
            string executableDigestSha256,
            string restrictedTokenProfileDigestSha256)
        {
            WebProtectionValueValidator.RequireCanonicalSid(dedicatedAccountSid, nameof(dedicatedAccountSid));
            if (WebProtectionValueValidator.IsPrivilegedServiceSid(dedicatedAccountSid))
            {
                throw new ArgumentException("The proxy must not use a privileged built-in service identity.", nameof(dedicatedAccountSid));
            }

            DedicatedAccountSid = dedicatedAccountSid;
            ExecutablePath = WebProtectionValueValidator.RequireToken(executablePath, 1024, nameof(executablePath));
            ExecutableVersion = WebProtectionValueValidator.RequireToken(executableVersion, 128, nameof(executableVersion));
            WebProtectionValueValidator.RequireSha256(executableDigestSha256, nameof(executableDigestSha256));
            WebProtectionValueValidator.RequireSha256(restrictedTokenProfileDigestSha256, nameof(restrictedTokenProfileDigestSha256));
            ExecutableDigestSha256 = executableDigestSha256;
            RestrictedTokenProfileDigestSha256 = restrictedTokenProfileDigestSha256;
        }

        public string DedicatedAccountSid { get; }

        public string ExecutablePath { get; }

        public string ExecutableVersion { get; }

        public string ExecutableDigestSha256 { get; }

        public string RestrictedTokenProfileDigestSha256 { get; }
    }

    public sealed class ProxyProcessObservation
    {
        public ProxyProcessObservation(
            int processId,
            Guid processStartToken,
            string accountSid,
            string executablePath,
            string executableVersion,
            string executableDigestSha256,
            string tokenProfileDigestSha256,
            bool isDedicatedAccount,
            bool isRestrictedToken,
            bool isElevated,
            bool isLocalSystem,
            bool hasAdministrativeSids,
            bool isInteractiveLogonToken,
            bool isInKillOnCloseJob,
            bool isChildProcessCreationBlocked,
            bool hasRestrictiveProcessDacl,
            bool hasNoNetworkCredentials)
        {
            if (processId < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(processId));
            }

            if (processStartToken == Guid.Empty)
            {
                throw new ArgumentException("A non-empty process start token is required.", nameof(processStartToken));
            }

            WebProtectionValueValidator.RequireCanonicalSid(accountSid, nameof(accountSid));
            ProcessId = processId;
            ProcessStartToken = processStartToken;
            AccountSid = accountSid;
            ExecutablePath = WebProtectionValueValidator.RequireToken(executablePath, 1024, nameof(executablePath));
            ExecutableVersion = WebProtectionValueValidator.RequireToken(executableVersion, 128, nameof(executableVersion));
            WebProtectionValueValidator.RequireSha256(executableDigestSha256, nameof(executableDigestSha256));
            WebProtectionValueValidator.RequireSha256(tokenProfileDigestSha256, nameof(tokenProfileDigestSha256));
            ExecutableDigestSha256 = executableDigestSha256;
            TokenProfileDigestSha256 = tokenProfileDigestSha256;
            IsDedicatedAccount = isDedicatedAccount;
            IsRestrictedToken = isRestrictedToken;
            IsElevated = isElevated;
            IsLocalSystem = isLocalSystem;
            HasAdministrativeSids = hasAdministrativeSids;
            IsInteractiveLogonToken = isInteractiveLogonToken;
            IsInKillOnCloseJob = isInKillOnCloseJob;
            IsChildProcessCreationBlocked = isChildProcessCreationBlocked;
            HasRestrictiveProcessDacl = hasRestrictiveProcessDacl;
            HasNoNetworkCredentials = hasNoNetworkCredentials;
        }

        public int ProcessId { get; }

        public Guid ProcessStartToken { get; }

        public string AccountSid { get; }

        public string ExecutablePath { get; }

        public string ExecutableVersion { get; }

        public string ExecutableDigestSha256 { get; }

        public string TokenProfileDigestSha256 { get; }

        public bool IsDedicatedAccount { get; }

        public bool IsRestrictedToken { get; }

        public bool IsElevated { get; }

        public bool IsLocalSystem { get; }

        public bool HasAdministrativeSids { get; }

        public bool IsInteractiveLogonToken { get; }

        public bool IsInKillOnCloseJob { get; }

        public bool IsChildProcessCreationBlocked { get; }

        public bool HasRestrictiveProcessDacl { get; }

        public bool HasNoNetworkCredentials { get; }
    }

    public sealed class ProxyListenerEvidence
    {
        public ProxyListenerEvidence(
            ServiceAttestationEnvelope envelope,
            LoopbackAddressFamily addressFamily,
            string localAddress,
            int port,
            bool usesExclusiveAddress,
            bool ownsExactEndpoint,
            bool noCompetingListenerDetected,
            ProxyProcessObservation owner)
        {
            if (!Enum.IsDefined(typeof(LoopbackAddressFamily), addressFamily))
            {
                throw new ArgumentOutOfRangeException(nameof(addressFamily));
            }

            if (port < 1 || port > 65535)
            {
                throw new ArgumentOutOfRangeException(nameof(port));
            }

            Envelope = envelope ?? throw new ArgumentNullException(nameof(envelope));
            AddressFamily = addressFamily;
            LocalAddress = WebProtectionValueValidator.RequireToken(localAddress, 64, nameof(localAddress));
            Port = port;
            UsesExclusiveAddress = usesExclusiveAddress;
            OwnsExactEndpoint = ownsExactEndpoint;
            NoCompetingListenerDetected = noCompetingListenerDetected;
            Owner = owner ?? throw new ArgumentNullException(nameof(owner));
        }

        public ServiceAttestationEnvelope Envelope { get; }

        public LoopbackAddressFamily AddressFamily { get; }

        public string LocalAddress { get; }

        public int Port { get; }

        public bool UsesExclusiveAddress { get; }

        public bool OwnsExactEndpoint { get; }

        public bool NoCompetingListenerDetected { get; }

        public ProxyProcessObservation Owner { get; }
    }

    public sealed class BrowserEnforcementExpectation
    {
        public BrowserEnforcementExpectation(
            ManagedBrowserFamily browser,
            string executablePath,
            string executableVersion,
            string executableDigestSha256,
            string policyDigestSha256,
            string extensionVersion,
            string extensionDigestSha256)
        {
            if (!Enum.IsDefined(typeof(ManagedBrowserFamily), browser))
            {
                throw new ArgumentOutOfRangeException(nameof(browser));
            }

            Browser = browser;
            ExecutablePath = WebProtectionValueValidator.RequireToken(executablePath, 1024, nameof(executablePath));
            ExecutableVersion = WebProtectionValueValidator.RequireToken(executableVersion, 128, nameof(executableVersion));
            WebProtectionValueValidator.RequireSha256(executableDigestSha256, nameof(executableDigestSha256));
            WebProtectionValueValidator.RequireSha256(policyDigestSha256, nameof(policyDigestSha256));
            ExtensionVersion = WebProtectionValueValidator.RequireToken(extensionVersion, 128, nameof(extensionVersion));
            WebProtectionValueValidator.RequireSha256(extensionDigestSha256, nameof(extensionDigestSha256));
            ExecutableDigestSha256 = executableDigestSha256;
            PolicyDigestSha256 = policyDigestSha256;
            ExtensionDigestSha256 = extensionDigestSha256;
        }

        public ManagedBrowserFamily Browser { get; }

        public string ExecutablePath { get; }

        public string ExecutableVersion { get; }

        public string ExecutableDigestSha256 { get; }

        public string PolicyDigestSha256 { get; }

        public string ExtensionVersion { get; }

        public string ExtensionDigestSha256 { get; }
    }

    public sealed class BrowserPolicyEvidence
    {
        public BrowserPolicyEvidence(
            ServiceAttestationEnvelope envelope,
            ManagedBrowserFamily browser,
            string executablePath,
            string executableVersion,
            string executableDigestSha256,
            string policyDigestSha256,
            bool isMachinePolicy,
            bool isEffective,
            bool userCanChangeProxy,
            bool wasLoadedWithoutFallback,
            bool hasNoEffectiveProxyOverrideRules)
        {
            if (!Enum.IsDefined(typeof(ManagedBrowserFamily), browser))
            {
                throw new ArgumentOutOfRangeException(nameof(browser));
            }

            Envelope = envelope ?? throw new ArgumentNullException(nameof(envelope));
            Browser = browser;
            ExecutablePath = WebProtectionValueValidator.RequireToken(executablePath, 1024, nameof(executablePath));
            ExecutableVersion = WebProtectionValueValidator.RequireToken(executableVersion, 128, nameof(executableVersion));
            WebProtectionValueValidator.RequireSha256(executableDigestSha256, nameof(executableDigestSha256));
            WebProtectionValueValidator.RequireSha256(policyDigestSha256, nameof(policyDigestSha256));
            ExecutableDigestSha256 = executableDigestSha256;
            PolicyDigestSha256 = policyDigestSha256;
            IsMachinePolicy = isMachinePolicy;
            IsEffective = isEffective;
            UserCanChangeProxy = userCanChangeProxy;
            WasLoadedWithoutFallback = wasLoadedWithoutFallback;
            HasNoEffectiveProxyOverrideRules =
                hasNoEffectiveProxyOverrideRules;
        }

        public ServiceAttestationEnvelope Envelope { get; }

        public ManagedBrowserFamily Browser { get; }

        public string ExecutablePath { get; }

        public string ExecutableVersion { get; }

        public string ExecutableDigestSha256 { get; }

        public string PolicyDigestSha256 { get; }

        public bool IsMachinePolicy { get; }

        public bool IsEffective { get; }

        public bool UserCanChangeProxy { get; }

        public bool WasLoadedWithoutFallback { get; }

        /// <summary>
        /// Service-observed effective state. This cannot be inferred from the
        /// desired local registry policy because higher-priority cloud policy
        /// can install ProxyOverrideRules.
        /// </summary>
        public bool HasNoEffectiveProxyOverrideRules { get; }
    }

    public sealed class WfpPolicyExpectation
    {
        public WfpPolicyExpectation(
            string policyVersion,
            string policyDigestSha256,
            string bypassIdentityCatalogVersion,
            string bypassIdentityCatalogDigestSha256)
        {
            PolicyVersion = WebProtectionValueValidator.RequireToken(policyVersion, 128, nameof(policyVersion));
            WebProtectionValueValidator.RequireSha256(policyDigestSha256, nameof(policyDigestSha256));
            BypassIdentityCatalogVersion = WebProtectionValueValidator.RequireToken(
                bypassIdentityCatalogVersion,
                128,
                nameof(bypassIdentityCatalogVersion));
            WebProtectionValueValidator.RequireSha256(
                bypassIdentityCatalogDigestSha256,
                nameof(bypassIdentityCatalogDigestSha256));
            PolicyDigestSha256 = policyDigestSha256;
            BypassIdentityCatalogDigestSha256 = bypassIdentityCatalogDigestSha256;
        }

        public string PolicyVersion { get; }

        public string PolicyDigestSha256 { get; }

        public string BypassIdentityCatalogVersion { get; }

        public string BypassIdentityCatalogDigestSha256 { get; }
    }

    public sealed class WfpBrowserBindingEvidence
    {
        public WfpBrowserBindingEvidence(
            ManagedBrowserFamily browser,
            string executablePath,
            string executableVersion,
            string executableDigestSha256)
        {
            if (!Enum.IsDefined(typeof(ManagedBrowserFamily), browser))
            {
                throw new ArgumentOutOfRangeException(nameof(browser));
            }

            Browser = browser;
            ExecutablePath = WebProtectionValueValidator.RequireToken(executablePath, 1024, nameof(executablePath));
            ExecutableVersion = WebProtectionValueValidator.RequireToken(executableVersion, 128, nameof(executableVersion));
            WebProtectionValueValidator.RequireSha256(executableDigestSha256, nameof(executableDigestSha256));
            ExecutableDigestSha256 = executableDigestSha256;
        }

        public ManagedBrowserFamily Browser { get; }

        public string ExecutablePath { get; }

        public string ExecutableVersion { get; }

        public string ExecutableDigestSha256 { get; }
    }

    public sealed class WfpEnforcementEvidence
    {
        public WfpEnforcementEvidence(
            ServiceAttestationEnvelope envelope,
            string policyVersion,
            string policyDigestSha256,
            string bypassIdentityCatalogVersion,
            string bypassIdentityCatalogDigestSha256,
            int allowedProxyPort,
            int boundProxyProcessId,
            Guid boundProxyProcessStartToken,
            string boundChildAccountSid,
            string boundProxyAccountSid,
            string boundProxyExecutableDigestSha256,
            WfpCoverageFlags coverage,
            IEnumerable<WfpBrowserBindingEvidence> browserBindings)
        {
            if (allowedProxyPort < 1 || allowedProxyPort > 65535)
            {
                throw new ArgumentOutOfRangeException(nameof(allowedProxyPort));
            }

            if (boundProxyProcessId < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(boundProxyProcessId));
            }

            if (boundProxyProcessStartToken == Guid.Empty)
            {
                throw new ArgumentException("A non-empty bound proxy process start token is required.", nameof(boundProxyProcessStartToken));
            }

            Envelope = envelope ?? throw new ArgumentNullException(nameof(envelope));
            PolicyVersion = WebProtectionValueValidator.RequireToken(policyVersion, 128, nameof(policyVersion));
            WebProtectionValueValidator.RequireSha256(policyDigestSha256, nameof(policyDigestSha256));
            BypassIdentityCatalogVersion = WebProtectionValueValidator.RequireToken(
                bypassIdentityCatalogVersion,
                128,
                nameof(bypassIdentityCatalogVersion));
            WebProtectionValueValidator.RequireSha256(
                bypassIdentityCatalogDigestSha256,
                nameof(bypassIdentityCatalogDigestSha256));
            WebProtectionValueValidator.RequireCanonicalSid(boundProxyAccountSid, nameof(boundProxyAccountSid));
            WebProtectionValueValidator.RequireCanonicalSid(boundChildAccountSid, nameof(boundChildAccountSid));
            WebProtectionValueValidator.RequireSha256(
                boundProxyExecutableDigestSha256,
                nameof(boundProxyExecutableDigestSha256));
            AllowedProxyPort = allowedProxyPort;
            BoundProxyProcessId = boundProxyProcessId;
            BoundProxyProcessStartToken = boundProxyProcessStartToken;
            BoundChildAccountSid = boundChildAccountSid;
            BoundProxyAccountSid = boundProxyAccountSid;
            BoundProxyExecutableDigestSha256 = boundProxyExecutableDigestSha256;
            PolicyDigestSha256 = policyDigestSha256;
            BypassIdentityCatalogDigestSha256 = bypassIdentityCatalogDigestSha256;
            Coverage = coverage;
            BrowserBindings = WebProtectionValueValidator.Copy(browserBindings, nameof(browserBindings));
        }

        public ServiceAttestationEnvelope Envelope { get; }

        public string PolicyVersion { get; }

        public string PolicyDigestSha256 { get; }

        public string BypassIdentityCatalogVersion { get; }

        public string BypassIdentityCatalogDigestSha256 { get; }

        public int AllowedProxyPort { get; }

        public int BoundProxyProcessId { get; }

        public Guid BoundProxyProcessStartToken { get; }

        public string BoundChildAccountSid { get; }

        public string BoundProxyAccountSid { get; }

        public string BoundProxyExecutableDigestSha256 { get; }

        public WfpCoverageFlags Coverage { get; }

        public IReadOnlyList<WfpBrowserBindingEvidence> BrowserBindings { get; }
    }

    public sealed class TrustedWebCatalogExpectation
    {
        public TrustedWebCatalogExpectation(
            TrustedWebCatalogKind kind,
            long currentRevision,
            long rollbackFloorRevision,
            string version,
            string digestSha256)
        {
            if (!Enum.IsDefined(typeof(TrustedWebCatalogKind), kind))
            {
                throw new ArgumentOutOfRangeException(nameof(kind));
            }

            if (currentRevision < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(currentRevision));
            }

            if (rollbackFloorRevision < 1 || rollbackFloorRevision > currentRevision)
            {
                throw new ArgumentOutOfRangeException(nameof(rollbackFloorRevision));
            }

            Kind = kind;
            CurrentRevision = currentRevision;
            RollbackFloorRevision = rollbackFloorRevision;
            Version = WebProtectionValueValidator.RequireToken(version, 128, nameof(version));
            WebProtectionValueValidator.RequireSha256(digestSha256, nameof(digestSha256));
            DigestSha256 = digestSha256;
        }

        public TrustedWebCatalogKind Kind { get; }

        public long CurrentRevision { get; }

        public long RollbackFloorRevision { get; }

        public string Version { get; }

        public string DigestSha256 { get; }
    }

    public sealed class TrustedWebCatalogEvidence
    {
        public TrustedWebCatalogEvidence(
            ServiceAttestationEnvelope envelope,
            TrustedWebCatalogKind kind,
            long revision,
            long rollbackFloorRevision,
            string version,
            string digestSha256,
            bool isSignatureVerified,
            bool isTrustedSource,
            bool isComplete,
            bool wasLoadedWithoutFallback,
            bool isRollbackProtectionActive)
        {
            if (!Enum.IsDefined(typeof(TrustedWebCatalogKind), kind))
            {
                throw new ArgumentOutOfRangeException(nameof(kind));
            }

            if (revision < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(revision));
            }

            if (rollbackFloorRevision < 1 || rollbackFloorRevision > revision)
            {
                throw new ArgumentOutOfRangeException(nameof(rollbackFloorRevision));
            }

            Envelope = envelope ?? throw new ArgumentNullException(nameof(envelope));
            Kind = kind;
            Revision = revision;
            RollbackFloorRevision = rollbackFloorRevision;
            Version = WebProtectionValueValidator.RequireToken(version, 128, nameof(version));
            WebProtectionValueValidator.RequireSha256(digestSha256, nameof(digestSha256));
            DigestSha256 = digestSha256;
            IsSignatureVerified = isSignatureVerified;
            IsTrustedSource = isTrustedSource;
            IsComplete = isComplete;
            WasLoadedWithoutFallback = wasLoadedWithoutFallback;
            IsRollbackProtectionActive = isRollbackProtectionActive;
        }

        public ServiceAttestationEnvelope Envelope { get; }

        public TrustedWebCatalogKind Kind { get; }

        public long Revision { get; }

        public long RollbackFloorRevision { get; }

        public string Version { get; }

        public string DigestSha256 { get; }

        public bool IsSignatureVerified { get; }

        public bool IsTrustedSource { get; }

        public bool IsComplete { get; }

        public bool WasLoadedWithoutFallback { get; }

        public bool IsRollbackProtectionActive { get; }
    }

    public sealed class ExtensionUxEvidence
    {
        public ExtensionUxEvidence(
            ServiceAttestationEnvelope envelope,
            ManagedBrowserFamily browser,
            string boundChildAccountSid,
            string browserExecutableDigestSha256,
            string extensionVersion,
            string extensionDigestSha256,
            bool isAuthenticatedChildSession,
            bool isConnected,
            bool isRequestPageReady)
        {
            if (!Enum.IsDefined(typeof(ManagedBrowserFamily), browser))
            {
                throw new ArgumentOutOfRangeException(nameof(browser));
            }

            Envelope = envelope ?? throw new ArgumentNullException(nameof(envelope));
            Browser = browser;
            WebProtectionValueValidator.RequireCanonicalSid(
                boundChildAccountSid,
                nameof(boundChildAccountSid));
            WebProtectionValueValidator.RequireSha256(
                browserExecutableDigestSha256,
                nameof(browserExecutableDigestSha256));
            ExtensionVersion = WebProtectionValueValidator.RequireToken(extensionVersion, 128, nameof(extensionVersion));
            WebProtectionValueValidator.RequireSha256(extensionDigestSha256, nameof(extensionDigestSha256));
            BoundChildAccountSid = boundChildAccountSid;
            BrowserExecutableDigestSha256 =
                browserExecutableDigestSha256;
            ExtensionDigestSha256 = extensionDigestSha256;
            IsAuthenticatedChildSession = isAuthenticatedChildSession;
            IsConnected = isConnected;
            IsRequestPageReady = isRequestPageReady;
        }

        public ServiceAttestationEnvelope Envelope { get; }

        public ManagedBrowserFamily Browser { get; }

        /// <summary>
        /// Exact service-observed Windows SID of the browser/extension IPC
        /// peer. A payload-declared SID is never sufficient.
        /// </summary>
        public string BoundChildAccountSid { get; }

        public string BrowserExecutableDigestSha256 { get; }

        public string ExtensionVersion { get; }

        public string ExtensionDigestSha256 { get; }

        public bool IsAuthenticatedChildSession { get; }

        public bool IsConnected { get; }

        public bool IsRequestPageReady { get; }
    }

    public sealed class WebProtectionDesiredState
    {
        public WebProtectionDesiredState(
            WebProtectionEvidenceBinding binding,
            string childAccountSid,
            int proxyPort,
            TimeSpan maximumEvidenceAge,
            ProxyProcessExpectation proxyProcess,
            IEnumerable<BrowserEnforcementExpectation> browsers,
            WfpPolicyExpectation wfpPolicy,
            IEnumerable<TrustedWebCatalogExpectation> trustedCatalogs)
        {
            if (proxyPort < 1 || proxyPort > 65535)
            {
                throw new ArgumentOutOfRangeException(nameof(proxyPort));
            }

            if (maximumEvidenceAge <= TimeSpan.Zero || maximumEvidenceAge > TimeSpan.FromMinutes(1))
            {
                throw new ArgumentOutOfRangeException(nameof(maximumEvidenceAge));
            }

            Binding = binding ?? throw new ArgumentNullException(nameof(binding));
            WebProtectionValueValidator.RequireCanonicalSid(childAccountSid, nameof(childAccountSid));
            var requiredProxyProcess = proxyProcess ?? throw new ArgumentNullException(nameof(proxyProcess));
            if (string.Equals(requiredProxyProcess.DedicatedAccountSid, childAccountSid, StringComparison.Ordinal))
            {
                throw new ArgumentException("The proxy account must be distinct from the child account.", nameof(proxyProcess));
            }

            ChildAccountSid = childAccountSid;
            ProxyPort = proxyPort;
            MaximumEvidenceAge = maximumEvidenceAge;
            ProxyProcess = requiredProxyProcess;
            Browsers = WebProtectionValueValidator.Copy(browsers, nameof(browsers));
            if (Browsers.Count < 1 || Browsers.Count > 2)
            {
                throw new ArgumentException("One or two managed browsers are required.", nameof(browsers));
            }

            WebProtectionValueValidator.RequireUniqueBrowsers(Browsers, nameof(browsers));
            WfpPolicy = wfpPolicy ?? throw new ArgumentNullException(nameof(wfpPolicy));
            TrustedCatalogs = WebProtectionValueValidator.Copy(trustedCatalogs, nameof(trustedCatalogs));
            WebProtectionValueValidator.RequireCompleteCatalogSet(TrustedCatalogs, nameof(trustedCatalogs));
        }

        public WebProtectionEvidenceBinding Binding { get; }

        public string ChildAccountSid { get; }

        public int ProxyPort { get; }

        public TimeSpan MaximumEvidenceAge { get; }

        public ProxyProcessExpectation ProxyProcess { get; }

        public IReadOnlyList<BrowserEnforcementExpectation> Browsers { get; }

        public WfpPolicyExpectation WfpPolicy { get; }

        public IReadOnlyList<TrustedWebCatalogExpectation> TrustedCatalogs { get; }
    }

    public sealed class WebProtectionEvidenceSnapshot
    {
        public WebProtectionEvidenceSnapshot(
            IEnumerable<ProxyListenerEvidence>? listeners,
            IEnumerable<BrowserPolicyEvidence>? browserPolicies,
            IEnumerable<WfpEnforcementEvidence>? wfpPolicies,
            IEnumerable<TrustedWebCatalogEvidence>? trustedCatalogs,
            IEnumerable<ExtensionUxEvidence>? extensionUx)
        {
            Listeners = WebProtectionValueValidator.CopyOrEmpty(listeners, nameof(listeners));
            BrowserPolicies = WebProtectionValueValidator.CopyOrEmpty(browserPolicies, nameof(browserPolicies));
            WfpPolicies = WebProtectionValueValidator.CopyOrEmpty(wfpPolicies, nameof(wfpPolicies));
            TrustedCatalogs = WebProtectionValueValidator.CopyOrEmpty(trustedCatalogs, nameof(trustedCatalogs));
            ExtensionUx = WebProtectionValueValidator.CopyOrEmpty(extensionUx, nameof(extensionUx));
        }

        public IReadOnlyList<ProxyListenerEvidence> Listeners { get; }

        public IReadOnlyList<BrowserPolicyEvidence> BrowserPolicies { get; }

        public IReadOnlyList<WfpEnforcementEvidence> WfpPolicies { get; }

        public IReadOnlyList<TrustedWebCatalogEvidence> TrustedCatalogs { get; }

        public IReadOnlyList<ExtensionUxEvidence> ExtensionUx { get; }
    }

    public sealed class WebProtectionReadinessResult
    {
        internal WebProtectionReadinessResult(
            IEnumerable<WebProtectionReadinessIssue> issues,
            ExtensionUxEvidenceState extensionUxState)
        {
            Issues = WebProtectionValueValidator.Copy(issues, nameof(issues));
            ExtensionUxState = extensionUxState;
        }

        public bool CanEnableEnforcement => Issues.Count == 0;

        public bool IsWebsiteRequestReady =>
            CanEnableEnforcement && ExtensionUxState == ExtensionUxEvidenceState.Healthy;

        public IReadOnlyList<WebProtectionReadinessIssue> Issues { get; }

        public ExtensionUxEvidenceState ExtensionUxState { get; }
    }

    internal static class WebProtectionValueValidator
    {
        public static string RequireToken(string value, int maximumLength, string parameterName)
        {
            if (string.IsNullOrWhiteSpace(value) ||
                value.Length > maximumLength ||
                !string.Equals(value, value.Trim(), StringComparison.Ordinal))
            {
                throw new ArgumentException("A non-empty bounded canonical value is required.", parameterName);
            }

            for (var index = 0; index < value.Length; index++)
            {
                if (char.IsControl(value[index]))
                {
                    throw new ArgumentException("Control characters are not allowed.", parameterName);
                }
            }

            return value;
        }

        public static void RequireSha256(string value, string parameterName)
        {
            if (value == null || value.Length != 64)
            {
                throw new ArgumentException("A lowercase SHA-256 digest is required.", parameterName);
            }

            for (var index = 0; index < value.Length; index++)
            {
                var character = value[index];
                if (!((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')))
                {
                    throw new ArgumentException("A lowercase SHA-256 digest is required.", parameterName);
                }
            }
        }

        public static void RequireUtc(DateTimeOffset value, string parameterName)
        {
            if (value.Offset != TimeSpan.Zero)
            {
                throw new ArgumentException("A UTC timestamp is required.", parameterName);
            }
        }

        public static void RequireCanonicalSid(string value, string parameterName)
        {
            RequireToken(value, 184, parameterName);
            try
            {
                var parsed = new SecurityIdentifier(value);
                if (!string.Equals(parsed.Value, value, StringComparison.Ordinal))
                {
                    throw new ArgumentException("A canonical Windows SID is required.", parameterName);
                }
            }
            catch (ArgumentException exception)
            {
                throw new ArgumentException("A canonical Windows SID is required.", parameterName, exception);
            }
        }

        public static bool IsPrivilegedServiceSid(string value)
        {
            return string.Equals(value, "S-1-5-18", StringComparison.Ordinal) ||
                string.Equals(value, "S-1-5-19", StringComparison.Ordinal) ||
                string.Equals(value, "S-1-5-20", StringComparison.Ordinal) ||
                string.Equals(value, "S-1-5-32-544", StringComparison.Ordinal);
        }

        public static IReadOnlyList<T> Copy<T>(IEnumerable<T> values, string parameterName)
            where T : class
        {
            if (values == null)
            {
                throw new ArgumentNullException(parameterName);
            }

            var copy = new List<T>();
            foreach (var value in values)
            {
                if (value == null)
                {
                    throw new ArgumentException("Null evidence entries are not allowed.", parameterName);
                }

                copy.Add(value);
            }

            return new ReadOnlyCollection<T>(copy);
        }

        public static IReadOnlyList<T> CopyOrEmpty<T>(IEnumerable<T>? values, string parameterName)
            where T : class
        {
            return values == null ? new ReadOnlyCollection<T>(Array.Empty<T>()) : Copy(values, parameterName);
        }

        public static IReadOnlyList<WebProtectionReadinessIssue> Copy(
            IEnumerable<WebProtectionReadinessIssue> values,
            string parameterName)
        {
            if (values == null)
            {
                throw new ArgumentNullException(parameterName);
            }

            return new ReadOnlyCollection<WebProtectionReadinessIssue>(
                new List<WebProtectionReadinessIssue>(values));
        }

        public static void RequireUniqueBrowsers(
            IReadOnlyList<BrowserEnforcementExpectation> browsers,
            string parameterName)
        {
            var seen = new HashSet<ManagedBrowserFamily>();
            for (var index = 0; index < browsers.Count; index++)
            {
                if (!seen.Add(browsers[index].Browser))
                {
                    throw new ArgumentException("Managed browser expectations must be unique.", parameterName);
                }
            }
        }

        public static void RequireCompleteCatalogSet(
            IReadOnlyList<TrustedWebCatalogExpectation> catalogs,
            string parameterName)
        {
            if (catalogs.Count != 2)
            {
                throw new ArgumentException("Exactly the PSL and site-service catalogs are required.", parameterName);
            }

            var seen = new HashSet<TrustedWebCatalogKind>();
            for (var index = 0; index < catalogs.Count; index++)
            {
                if (!seen.Add(catalogs[index].Kind))
                {
                    throw new ArgumentException("Trusted catalog expectations must be unique.", parameterName);
                }
            }

            if (!seen.Contains(TrustedWebCatalogKind.PublicSuffixList) ||
                !seen.Contains(TrustedWebCatalogKind.SiteServiceCatalog))
            {
                throw new ArgumentException("Exactly the PSL and site-service catalogs are required.", parameterName);
            }
        }
    }
}
