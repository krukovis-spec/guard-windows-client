using System;
using System.Collections.Generic;
using Guard.Contracts;

namespace Guard.Domain.Policy
{
    public enum ApplicationBundleComponentRole
    {
        Main = 1,
        Updater = 2,
        Helper = 3
    }

    public sealed class ApplicationBundleComponent
    {
        public ApplicationBundleComponent(
            ApplicationBundleComponentRole role,
            ApplicationIdentity executableIdentity)
        {
            if (!Enum.IsDefined(typeof(ApplicationBundleComponentRole), role))
            {
                throw new ArgumentOutOfRangeException(nameof(role));
            }

            ExecutableIdentity = executableIdentity ?? throw new ArgumentNullException(nameof(executableIdentity));
            if (!executableIdentity.IsExecutableGrantIdentity)
            {
                throw new ArgumentException(
                    "A bundle component requires an exact SHA-256 or package-family executable identity.",
                    nameof(executableIdentity));
            }

            Role = role;
        }

        public ApplicationBundleComponentRole Role { get; }

        public ApplicationIdentity ExecutableIdentity { get; }

        internal string ComponentKey =>
            ((int)Role).ToString(System.Globalization.CultureInfo.InvariantCulture) +
            ":" +
            ExecutableIdentity.AuthorizationKey;
    }

    public sealed class ApplicationBundle
    {
        public const int MaximumComponentCount = 32;

        private readonly ApplicationBundleComponent[] _components;

        public ApplicationBundle(string bundleId, IEnumerable<ApplicationBundleComponent> components)
        {
            BundleId = RequireIdentifier(bundleId, nameof(bundleId), 128);
            if (components == null)
            {
                throw new ArgumentNullException(nameof(components));
            }

            var copied = new List<ApplicationBundleComponent>();
            var componentKeys = new HashSet<string>(StringComparer.Ordinal);
            var hasMain = false;
            foreach (var component in components)
            {
                if (component == null)
                {
                    throw new ArgumentException("Application bundles cannot contain null components.", nameof(components));
                }

                if (copied.Count == MaximumComponentCount)
                {
                    throw new ArgumentException("An application bundle contains too many components.", nameof(components));
                }

                if (!componentKeys.Add(component.ComponentKey))
                {
                    throw new ArgumentException("Application bundle roles and identities must be unique.", nameof(components));
                }

                hasMain |= component.Role == ApplicationBundleComponentRole.Main;
                copied.Add(component);
            }

            if (!hasMain)
            {
                throw new ArgumentException("An application bundle requires at least one main component.", nameof(components));
            }

            _components = copied.ToArray();
        }

        public string BundleId { get; }

        public IReadOnlyList<ApplicationBundleComponent> Components =>
            Array.AsReadOnly((ApplicationBundleComponent[])_components.Clone());

        public bool ContainsExactComponent(
            ApplicationBundleComponentRole role,
            ApplicationIdentity executableIdentity)
        {
            if (!Enum.IsDefined(typeof(ApplicationBundleComponentRole), role) ||
                executableIdentity == null ||
                !executableIdentity.IsExecutableGrantIdentity)
            {
                return false;
            }

            for (var index = 0; index < _components.Length; index++)
            {
                var component = _components[index];
                if (component.Role == role &&
                    component.ExecutableIdentity.MatchesExactIdentity(executableIdentity))
                {
                    return true;
                }
            }

            return false;
        }

        public bool ContainsExactArtifact(ApplicationIdentity executableIdentity)
        {
            if (executableIdentity == null || !executableIdentity.IsExecutableGrantIdentity)
            {
                return false;
            }

            for (var index = 0; index < _components.Length; index++)
            {
                if (_components[index].ExecutableIdentity.MatchesExactIdentity(executableIdentity))
                {
                    return true;
                }
            }

            return false;
        }

        private static string RequireIdentifier(string value, string parameterName, int maximumLength)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new ArgumentException("A bounded identifier is required.", parameterName);
            }

            var normalized = value.Trim();
            if (normalized.Length > maximumLength)
            {
                throw new ArgumentException("A bounded identifier is required.", parameterName);
            }

            for (var index = 0; index < normalized.Length; index++)
            {
                if (char.IsControl(normalized[index]))
                {
                    throw new ArgumentException("Control characters are not allowed in identifiers.", parameterName);
                }
            }

            return normalized;
        }
    }

    public enum ApplicationVerificationKind
    {
        Authenticode = 1,
        FileHash = 2,
        PackageIdentity = 3
    }

    public sealed class VerifiedApplicationObservation
    {
        public VerifiedApplicationObservation(
            string artifactId,
            ApplicationIdentity provenanceIdentity,
            ApplicationIdentity executableIdentity,
            ApplicationVerificationKind verificationKind,
            string artifactDigestSha256)
        {
            if (!GuardIdentifier.IsCanonicalToken(artifactId))
            {
                throw new ArgumentException(
                    "A service-attested stable artifact id is required.",
                    nameof(artifactId));
            }

            ArtifactId = artifactId;
            ProvenanceIdentity = provenanceIdentity ?? throw new ArgumentNullException(nameof(provenanceIdentity));
            ExecutableIdentity = executableIdentity ?? throw new ArgumentNullException(nameof(executableIdentity));
            if (!Enum.IsDefined(typeof(ApplicationVerificationKind), verificationKind))
            {
                throw new ArgumentOutOfRangeException(nameof(verificationKind));
            }

            ArtifactDigestSha256 = ApplicationIdentity.NormalizeSha256(
                artifactDigestSha256,
                nameof(artifactDigestSha256));

            switch (verificationKind)
            {
                case ApplicationVerificationKind.Authenticode:
                    if (!provenanceIdentity.HasSignedPublisherIdentity ||
                        !executableIdentity.HasFileHashFallback ||
                        !string.Equals(
                            ArtifactDigestSha256,
                            executableIdentity.FileSha256,
                            StringComparison.Ordinal))
                    {
                        throw new ArgumentException(
                            "Authenticode observations require signed provenance and the exact verified file hash.");
                    }

                    break;
                case ApplicationVerificationKind.FileHash:
                    if (!provenanceIdentity.HasFileHashFallback ||
                        !executableIdentity.HasFileHashFallback ||
                        !provenanceIdentity.MatchesExactIdentity(executableIdentity) ||
                        !string.Equals(
                            ArtifactDigestSha256,
                            executableIdentity.FileSha256,
                            StringComparison.Ordinal))
                    {
                        throw new ArgumentException(
                            "Hash observations require matching exact hash provenance, executable identity, and digest.");
                    }

                    break;
                case ApplicationVerificationKind.PackageIdentity:
                    if (!provenanceIdentity.HasPackageFamilyIdentity ||
                        !executableIdentity.HasPackageFamilyIdentity ||
                        !provenanceIdentity.MatchesExactIdentity(executableIdentity))
                    {
                        throw new ArgumentException(
                            "Package observations require one exact verified package-family identity.");
                    }

                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(verificationKind));
            }

            VerificationKind = verificationKind;
        }

        public ApplicationIdentity ProvenanceIdentity { get; }

        public string ArtifactId { get; }

        public ApplicationIdentity ExecutableIdentity { get; }

        public ApplicationVerificationKind VerificationKind { get; }

        public string ArtifactDigestSha256 { get; }

        internal string ObservationKey => ArtifactId;
    }

    public sealed class VerifiedApplicationInventory
    {
        public const int MaximumApplicationCount = 4096;

        private readonly VerifiedApplicationObservation[] _applications;

        public VerifiedApplicationInventory(
            string deviceId,
            string bootId,
            string parentSessionId,
            DateTimeOffset capturedAt,
            IEnumerable<VerifiedApplicationObservation> applications)
        {
            DeviceId = RequireIdentifier(deviceId, nameof(deviceId), 128);
            BootId = RequireIdentifier(bootId, nameof(bootId), 128);
            ParentSessionId = RequireIdentifier(parentSessionId, nameof(parentSessionId), 128);
            if (applications == null)
            {
                throw new ArgumentNullException(nameof(applications));
            }

            var copied = new List<VerifiedApplicationObservation>();
            var artifactIds = new HashSet<string>(StringComparer.Ordinal);
            foreach (var application in applications)
            {
                if (application == null)
                {
                    throw new ArgumentException("Verified inventories cannot contain null observations.", nameof(applications));
                }

                if (copied.Count == MaximumApplicationCount)
                {
                    throw new ArgumentException("The verified application inventory is too large.", nameof(applications));
                }

                if (!artifactIds.Add(application.ObservationKey))
                {
                    throw new ArgumentException(
                        "Verified artifact ids must be unique within one snapshot.",
                        nameof(applications));
                }

                copied.Add(application);
            }

            CapturedAt = capturedAt;
            _applications = copied.ToArray();
        }

        public string DeviceId { get; }

        public string BootId { get; }

        public string ParentSessionId { get; }

        public DateTimeOffset CapturedAt { get; }

        public IReadOnlyList<VerifiedApplicationObservation> Applications =>
            Array.AsReadOnly((VerifiedApplicationObservation[])_applications.Clone());

        internal Dictionary<string, VerifiedApplicationObservation> ByProvenanceKey()
        {
            var result = new Dictionary<string, VerifiedApplicationObservation>(StringComparer.Ordinal);
            for (var index = 0; index < _applications.Length; index++)
            {
                result.Add(_applications[index].ObservationKey, _applications[index]);
            }

            return result;
        }

        private static string RequireIdentifier(string value, string parameterName, int maximumLength)
        {
            if (string.IsNullOrWhiteSpace(value) || value.Trim().Length > maximumLength)
            {
                throw new ArgumentException("A bounded identifier is required.", parameterName);
            }

            var normalized = value.Trim();
            for (var index = 0; index < normalized.Length; index++)
            {
                if (char.IsControl(normalized[index]))
                {
                    throw new ArgumentException("Control characters are not allowed in identifiers.", parameterName);
                }
            }

            return normalized;
        }
    }

    public enum MaintenanceApplicationCandidateKind
    {
        Added = 1,
        Updated = 2
    }

    public sealed class MaintenanceApplicationCandidate
    {
        internal MaintenanceApplicationCandidate(
            MaintenanceApplicationCandidateKind kind,
            VerifiedApplicationObservation current,
            VerifiedApplicationObservation? previous)
        {
            Kind = kind;
            Current = current;
            Previous = previous;
        }

        public MaintenanceApplicationCandidateKind Kind { get; }

        public VerifiedApplicationObservation Current { get; }

        public VerifiedApplicationObservation? Previous { get; }

        public ApplicationIdentity ProvenanceIdentity => Current.ProvenanceIdentity;

        public ApplicationIdentity ExactExecutableIdentity => Current.ExecutableIdentity;

        public bool RequiresParentApproval => true;
    }

    public sealed class MaintenanceApplicationDiscoveryDelta
    {
        private readonly MaintenanceApplicationCandidate[] _candidates;

        internal MaintenanceApplicationDiscoveryDelta(IEnumerable<MaintenanceApplicationCandidate> candidates)
        {
            _candidates = new List<MaintenanceApplicationCandidate>(candidates).ToArray();
        }

        public IReadOnlyList<MaintenanceApplicationCandidate> Candidates =>
            Array.AsReadOnly((MaintenanceApplicationCandidate[])_candidates.Clone());
    }

    public sealed class MaintenanceLeaseContext
    {
        public MaintenanceLeaseContext(
            MaintenanceLease lease,
            string bootId,
            string parentSessionId)
        {
            Lease = lease ?? throw new ArgumentNullException(nameof(lease));
            BootId = RequireIdentifier(bootId, nameof(bootId));
            ParentSessionId = RequireIdentifier(parentSessionId, nameof(parentSessionId));
        }

        public MaintenanceLease Lease { get; }

        public string BootId { get; }

        public string ParentSessionId { get; }

        public bool Allows(
            string deviceId,
            MaintenanceCapability capability,
            DateTimeOffset now,
            string currentBootId,
            string currentParentSessionId)
        {
            return string.Equals(BootId, currentBootId, StringComparison.Ordinal) &&
                   string.Equals(ParentSessionId, currentParentSessionId, StringComparison.Ordinal) &&
                   Lease.Allows(deviceId, capability, now);
        }

        private static string RequireIdentifier(string value, string parameterName)
        {
            if (string.IsNullOrWhiteSpace(value) || value.Trim().Length > 128)
            {
                throw new ArgumentException("A bounded maintenance context identifier is required.", parameterName);
            }

            var normalized = value.Trim();
            for (var index = 0; index < normalized.Length; index++)
            {
                if (char.IsControl(normalized[index]))
                {
                    throw new ArgumentException("Control characters are not allowed in maintenance context identifiers.", parameterName);
                }
            }

            return normalized;
        }
    }

    public static class MaintenanceApplicationDiscovery
    {
        public static readonly TimeSpan FinalSnapshotGrace = TimeSpan.FromMinutes(5);

        public static MaintenanceApplicationDiscoveryDelta Compare(
            MaintenanceLeaseContext maintenance,
            VerifiedApplicationInventory before,
            VerifiedApplicationInventory after,
            DateTimeOffset evaluatedAt)
        {
            if (maintenance == null)
            {
                throw new ArgumentNullException(nameof(maintenance));
            }

            if (before == null)
            {
                throw new ArgumentNullException(nameof(before));
            }

            if (after == null)
            {
                throw new ArgumentNullException(nameof(after));
            }

            if (!string.Equals(before.DeviceId, after.DeviceId, StringComparison.Ordinal) ||
                !string.Equals(before.DeviceId, maintenance.Lease.DeviceId, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Maintenance discovery cannot cross device bindings.");
            }

            if (after.CapturedAt < before.CapturedAt ||
                evaluatedAt < after.CapturedAt ||
                evaluatedAt - after.CapturedAt > FinalSnapshotGrace ||
                after.CapturedAt > maintenance.Lease.ExpiresAt + FinalSnapshotGrace ||
                !string.Equals(before.BootId, maintenance.BootId, StringComparison.Ordinal) ||
                !string.Equals(before.ParentSessionId, maintenance.ParentSessionId, StringComparison.Ordinal) ||
                !maintenance.Allows(
                    before.DeviceId,
                    MaintenanceCapability.UpdateInstallation,
                    before.CapturedAt,
                    before.BootId,
                    before.ParentSessionId))
            {
                throw new InvalidOperationException(
                    "Application discovery requires a lease-bound baseline and a prompt final snapshot.");
            }

            var beforeByProvenance = before.ByProvenanceKey();
            var candidates = new List<MaintenanceApplicationCandidate>();
            foreach (var current in after.Applications)
            {
                VerifiedApplicationObservation previous;
                if (!beforeByProvenance.TryGetValue(current.ObservationKey, out previous))
                {
                    candidates.Add(new MaintenanceApplicationCandidate(
                        MaintenanceApplicationCandidateKind.Added,
                        current,
                        null));
                    continue;
                }

                if (!current.ExecutableIdentity.MatchesExactIdentity(previous.ExecutableIdentity) ||
                    !string.Equals(
                        current.ArtifactDigestSha256,
                        previous.ArtifactDigestSha256,
                        StringComparison.Ordinal))
                {
                    candidates.Add(new MaintenanceApplicationCandidate(
                        MaintenanceApplicationCandidateKind.Updated,
                        current,
                        previous));
                }
            }

            candidates.Sort((left, right) =>
            {
                var identityOrder = string.CompareOrdinal(
                    left.ProvenanceIdentity.AuthorizationKey,
                    right.ProvenanceIdentity.AuthorizationKey);
                return identityOrder != 0 ? identityOrder : left.Kind.CompareTo(right.Kind);
            });

            return new MaintenanceApplicationDiscoveryDelta(candidates);
        }
    }
}
