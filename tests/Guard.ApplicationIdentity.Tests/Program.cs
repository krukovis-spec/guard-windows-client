using System;
using System.Collections.Generic;
using Guard.Domain.Policy;

namespace Guard.ApplicationIdentityChecks
{
    internal static class Program
    {
        private const string BootId = "boot-000000000001";
        private const string ParentSessionId = "parent-session-000001";
        private const string HashA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        private const string HashB = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        private const string HashC = "1111111111111111111111111111111111111111111111111111111111111111";
        private const string HashD = "2222222222222222222222222222222222222222222222222222222222222222";

        private static int Main()
        {
            var tests = new List<(string Name, Action Run)>
            {
                ("keeps the legacy constructor and adds exact package identity", SupportsThreeExclusiveModes),
                ("creates collision-free canonical identity keys", CreatesCanonicalKeys),
                ("keeps paths outside application identity", KeepsPathsOutsideIdentity),
                ("builds bounded exact executable bundles", BuildsExactBundles),
                ("rejects ambiguous or broad bundle components", RejectsUnsafeBundles),
                ("accepts only structurally verified observations", ValidatesVerifiedObservations),
                ("discovers exact added and updated candidates without grants", DiscoversMaintenanceDelta),
                ("finalizes only a scoped and promptly captured maintenance window", RequiresScopedMaintenance)
            };

            var failures = 0;
            foreach (var test in tests)
            {
                try
                {
                    test.Run();
                    Console.WriteLine("PASS " + test.Name);
                }
                catch (Exception exception)
                {
                    failures++;
                    Console.WriteLine("FAIL " + test.Name + ": " + exception.Message);
                }
            }

            Console.WriteLine(
                failures == 0
                    ? "All Guard application identity checks passed."
                    : failures + " application identity check(s) failed.");
            return failures == 0 ? 0 : 1;
        }

        private static void SupportsThreeExclusiveModes()
        {
            var signed = SignedIdentity("Reader");
            var hash = HashIdentity(HashA);
            var package = ApplicationIdentity.ForPackageFamily("Microsoft.Example_8wekyb3d8bbwe");

            Assert(signed.HasSignedPublisherIdentity, "Legacy signed constructor changed semantics.");
            Assert(hash.HasFileHashFallback, "Legacy SHA-256 constructor changed semantics.");
            Assert(package.HasPackageFamilyIdentity, "Package-family identity was not selected.");
            AssertEqual("MICROSOFT.EXAMPLE_8WEKYB3D8BBWE", package.PackageFamilyName, "Package family was not canonicalized.");
            Assert(!signed.IsExecutableGrantIdentity, "Signed provenance became an executable grant.");
            Assert(hash.IsExecutableGrantIdentity && package.IsExecutableGrantIdentity, "Exact executable identities were rejected.");

            Throws<ArgumentException>(
                () => new ApplicationIdentity("Acme", "Reader", SecureInstallRoot.ProgramFiles64, HashA),
                "Signed and hash modes were mixed.");
            Throws<ArgumentException>(
                () => new ApplicationIdentity(null, null, null, HashA, "Microsoft.Example_8wekyb3d8bbwe"),
                "Hash and package modes were mixed.");
            Throws<ArgumentException>(
                () => ApplicationIdentity.ForPackageFamily(@"C:\Apps\Reader.exe"),
                "A path was accepted as a package identity.");
            Throws<ArgumentException>(
                () => ApplicationIdentity.ForPackageFamily("Microsoft.Example"),
                "A package identity without publisher id was accepted.");
            Throws<ArgumentException>(
                () => ApplicationIdentity.ForPackageFamily("Microsoft.Example_short"),
                "A package identity with a non-canonical publisher id was accepted.");
        }

        private static void CreatesCanonicalKeys()
        {
            var first = new ApplicationIdentity(
                "Acme|Reader",
                "ProgramFiles64",
                SecureInstallRoot.ProgramFiles64,
                null);
            var second = new ApplicationIdentity(
                "Acme",
                "Reader|ProgramFiles64",
                SecureInstallRoot.ProgramFiles64,
                null);
            var packageLower = ApplicationIdentity.ForPackageFamily("Microsoft.Example_8wekyb3d8bbwe");
            var packageUpper = ApplicationIdentity.ForPackageFamily("MICROSOFT.EXAMPLE_8WEKYB3D8BBWE");
            var hashLower = HashIdentity(HashA);
            var hashUpper = HashIdentity(HashA.ToUpperInvariant());

            Assert(!first.Equals(second), "Length-prefixed signed tuples collided.");
            Assert(!string.Equals(first.AuthorizationKey, second.AuthorizationKey, StringComparison.Ordinal), "Canonical keys collided.");
            Assert(packageLower.Equals(packageUpper), "Equivalent package-family casing was not canonical.");
            Assert(hashLower.Equals(hashUpper), "Equivalent SHA-256 casing was not canonical.");
            Assert(!packageLower.Equals(hashLower), "Different identity modes collided.");
        }

        private static void KeepsPathsOutsideIdentity()
        {
            Assert(typeof(ApplicationIdentity).GetProperty("Path") == null, "ApplicationIdentity exposed a trusted path.");
            Assert(typeof(ApplicationBundleComponent).GetProperty("Path") == null, "Bundle components exposed a trusted path.");
            Assert(!SignedIdentity("Reader").MatchesExactIdentity(SignedIdentity("Writer")), "Same-publisher products inherited trust.");
        }

        private static void BuildsExactBundles()
        {
            var main = HashIdentity(HashA);
            var updater = HashIdentity(HashB);
            var helper = ApplicationIdentity.ForPackageFamily("Microsoft.Example_8wekyb3d8bbwe");
            var bundle = new ApplicationBundle(
                "reader",
                new[]
                {
                    new ApplicationBundleComponent(ApplicationBundleComponentRole.Main, main),
                    new ApplicationBundleComponent(ApplicationBundleComponentRole.Updater, updater),
                    new ApplicationBundleComponent(ApplicationBundleComponentRole.Helper, helper)
                });

            AssertEqual(3, bundle.Components.Count, "A bundle component was lost.");
            Assert(bundle.ContainsExactComponent(ApplicationBundleComponentRole.Main, main), "Exact main component was not found.");
            Assert(bundle.ContainsExactArtifact(helper), "Exact packaged helper was not found.");
            Assert(!bundle.ContainsExactArtifact(HashIdentity(HashC)), "An unrelated exact artifact was allowed.");
            Assert(!bundle.ContainsExactArtifact(SignedIdentity("Reader")), "Signed provenance became a bundle executable.");
        }

        private static void RejectsUnsafeBundles()
        {
            Throws<ArgumentException>(
                () => new ApplicationBundleComponent(
                    ApplicationBundleComponentRole.Main,
                    SignedIdentity("Reader")),
                "Broad signed provenance became a bundle executable.");

            var main = new ApplicationBundleComponent(ApplicationBundleComponentRole.Main, HashIdentity(HashA));
            Throws<ArgumentException>(
                () => new ApplicationBundle(
                    "duplicate",
                    new[] { main, new ApplicationBundleComponent(ApplicationBundleComponentRole.Main, HashIdentity(HashA)) }),
                "A duplicate role and identity was accepted.");
            Throws<ArgumentException>(
                () => new ApplicationBundle(
                    "no-main",
                    new[] { new ApplicationBundleComponent(ApplicationBundleComponentRole.Helper, HashIdentity(HashA)) }),
                "A bundle without a main executable was accepted.");

            var tooMany = new List<ApplicationBundleComponent>();
            for (var index = 0; index <= ApplicationBundle.MaximumComponentCount; index++)
            {
                tooMany.Add(new ApplicationBundleComponent(
                    index == 0 ? ApplicationBundleComponentRole.Main : ApplicationBundleComponentRole.Helper,
                    HashIdentity(index.ToString("X64"))));
            }

            Throws<ArgumentException>(
                () => new ApplicationBundle("too-many", tooMany),
                "An unbounded component set was accepted.");
        }

        private static void ValidatesVerifiedObservations()
        {
            var signed = SignedObservation("artifact-signed-0001", "Reader", HashA);
            var hash = HashObservation("artifact-hash-000001", HashB);
            var package = PackageObservation("artifact-package-01", "Microsoft.Example_8wekyb3d8bbwe", HashC);
            AssertEqual(ApplicationVerificationKind.Authenticode, signed.VerificationKind, "Signed evidence kind changed.");
            AssertEqual(ApplicationVerificationKind.FileHash, hash.VerificationKind, "Hash evidence kind changed.");
            AssertEqual(ApplicationVerificationKind.PackageIdentity, package.VerificationKind, "Package evidence kind changed.");

            Throws<ArgumentException>(
                () => new VerifiedApplicationObservation(
                    "artifact-invalid-0001",
                    SignedIdentity("Reader"),
                    ApplicationIdentity.ForPackageFamily("Microsoft.Example_8wekyb3d8bbwe"),
                    ApplicationVerificationKind.Authenticode,
                    HashA),
                "Authenticode evidence accepted a non-hash executable.");
            Throws<ArgumentException>(
                () => new VerifiedApplicationObservation(
                    "artifact-invalid-0002",
                    HashIdentity(HashA),
                    HashIdentity(HashB),
                    ApplicationVerificationKind.FileHash,
                    HashB),
                "Hash evidence accepted mismatched provenance.");
            Throws<ArgumentException>(
                () => new VerifiedApplicationObservation(
                    "artifact-invalid-0003",
                    ApplicationIdentity.ForPackageFamily("Microsoft.Example_8wekyb3d8bbwe"),
                    ApplicationIdentity.ForPackageFamily("Microsoft.Other_8wekyb3d8bbwe"),
                    ApplicationVerificationKind.PackageIdentity,
                    HashA),
                "Package evidence accepted mismatched identities.");
        }

        private static void DiscoversMaintenanceDelta()
        {
            var startedAt = Time();
            var before = new VerifiedApplicationInventory(
                "device-1",
                BootId,
                ParentSessionId,
                startedAt,
                new[]
                {
                    SignedObservation("artifact-reader-main", "Reader", HashA),
                    HashObservation("artifact-unsigned-01", HashD),
                    PackageObservation("artifact-package-01", "Microsoft.Example_8wekyb3d8bbwe", HashA)
                });
            var after = new VerifiedApplicationInventory(
                "device-1",
                BootId,
                ParentSessionId,
                startedAt.AddMinutes(5),
                new[]
                {
                    SignedObservation("artifact-reader-main", "Reader", HashB),
                    HashObservation("artifact-unsigned-01", HashC),
                    PackageObservation("artifact-package-01", "Microsoft.Example_8wekyb3d8bbwe", HashB),
                    PackageObservation("artifact-package-02", "Microsoft.NewApp_8wekyb3d8bbwe", HashD)
                });
            var lease = UpdateLease(startedAt);
            var delta = MaintenanceApplicationDiscovery.Compare(
                lease,
                before,
                after,
                startedAt.AddMinutes(6));

            AssertEqual(4, delta.Candidates.Count, "Added or updated applications were missed.");
            var added = 0;
            var updated = 0;
            foreach (var candidate in delta.Candidates)
            {
                Assert(candidate.RequiresParentApproval, "Discovery silently created an executable grant.");
                Assert(candidate.ExactExecutableIdentity.IsExecutableGrantIdentity, "A candidate lacked exact executable identity.");
                if (candidate.Kind == MaintenanceApplicationCandidateKind.Added)
                {
                    added++;
                    Assert(candidate.Previous == null, "An added candidate carried an old observation.");
                }
                else
                {
                    updated++;
                    Assert(candidate.Previous != null, "An updated candidate lost its old observation.");
                }
            }

            AssertEqual(1, added, "An exact addition was misclassified.");
            AssertEqual(3, updated, "Exact signed/hash/package updates were misclassified.");
        }

        private static void RequiresScopedMaintenance()
        {
            var startedAt = Time();
            var before = new VerifiedApplicationInventory(
                "device-1",
                BootId,
                ParentSessionId,
                startedAt,
                new[] { HashObservation("artifact-unsigned-01", HashA) });
            var after = new VerifiedApplicationInventory(
                "device-1",
                BootId,
                ParentSessionId,
                startedAt.AddMinutes(1),
                new[] { HashObservation("artifact-unsigned-01", HashB) });
            var wrongCapability = new MaintenanceLeaseContext(
                new MaintenanceLease(
                    "device-1",
                    "lease-web",
                    MaintenanceCapability.WebPolicy,
                    startedAt,
                    startedAt.AddMinutes(15)),
                BootId,
                ParentSessionId);
            Throws<InvalidOperationException>(
                () => MaintenanceApplicationDiscovery.Compare(
                    wrongCapability,
                    before,
                    after,
                    startedAt.AddMinutes(2)),
                "Discovery ran without update-maintenance scope.");
            Throws<InvalidOperationException>(
                () => MaintenanceApplicationDiscovery.Compare(
                    UpdateLease(startedAt),
                    before,
                    after,
                    startedAt.AddMinutes(15)),
                "A stale finalization reused an old snapshot.");

            var atExpiry = new VerifiedApplicationInventory(
                "device-1",
                BootId,
                ParentSessionId,
                startedAt.AddMinutes(15),
                new[] { HashObservation("artifact-unsigned-01", HashB) });
            AssertEqual(
                1,
                MaintenanceApplicationDiscovery.Compare(
                    UpdateLease(startedAt),
                    before,
                    atExpiry,
                    startedAt.AddMinutes(15)).Candidates.Count,
                "Maintenance could not be finalized at timer expiry.");

            var afterReboot = new VerifiedApplicationInventory(
                "device-1",
                "boot-after-reboot-01",
                "no-parent-session-01",
                startedAt.AddMinutes(2),
                new[] { HashObservation("artifact-unsigned-01", HashB) });
            AssertEqual(
                1,
                MaintenanceApplicationDiscovery.Compare(
                    UpdateLease(startedAt),
                    before,
                    afterReboot,
                    startedAt.AddMinutes(2)).Candidates.Count,
                "A reboot prevented safe post-maintenance discovery.");

            var afterParentLogout = new VerifiedApplicationInventory(
                "device-1",
                BootId,
                "parent-session-after-logout",
                startedAt.AddMinutes(2),
                new[] { HashObservation("artifact-unsigned-01", HashB) });
            AssertEqual(
                1,
                MaintenanceApplicationDiscovery.Compare(
                    UpdateLease(startedAt),
                    before,
                    afterParentLogout,
                    startedAt.AddMinutes(2)).Candidates.Count,
                "Parent logout prevented safe post-maintenance discovery.");

            var duplicate = HashObservation("artifact-unsigned-01", HashA);
            Throws<ArgumentException>(
                () => new VerifiedApplicationInventory(
                    "device-1",
                    BootId,
                    ParentSessionId,
                    startedAt,
                    new[] { duplicate, duplicate }),
                "A snapshot accepted duplicate verified identities.");
        }

        private static ApplicationIdentity SignedIdentity(string product)
        {
            return new ApplicationIdentity("Acme Ltd", product, SecureInstallRoot.ProgramFiles64, null);
        }

        private static ApplicationIdentity HashIdentity(string hash)
        {
            return new ApplicationIdentity(null, null, null, hash);
        }

        private static VerifiedApplicationObservation SignedObservation(
            string artifactId,
            string product,
            string artifactHash)
        {
            return new VerifiedApplicationObservation(
                artifactId,
                SignedIdentity(product),
                HashIdentity(artifactHash),
                ApplicationVerificationKind.Authenticode,
                artifactHash);
        }

        private static VerifiedApplicationObservation HashObservation(
            string artifactId,
            string artifactHash)
        {
            var identity = HashIdentity(artifactHash);
            return new VerifiedApplicationObservation(
                artifactId,
                identity,
                identity,
                ApplicationVerificationKind.FileHash,
                artifactHash);
        }

        private static VerifiedApplicationObservation PackageObservation(
            string artifactId,
            string packageFamilyName,
            string artifactDigest)
        {
            var identity = ApplicationIdentity.ForPackageFamily(packageFamilyName);
            return new VerifiedApplicationObservation(
                artifactId,
                identity,
                identity,
                ApplicationVerificationKind.PackageIdentity,
                artifactDigest);
        }

        private static MaintenanceLeaseContext UpdateLease(DateTimeOffset issuedAt)
        {
            return new MaintenanceLeaseContext(
                new MaintenanceLease(
                    "device-1",
                    "lease-update",
                    MaintenanceCapability.UpdateInstallation,
                    issuedAt,
                    issuedAt.AddMinutes(15)),
                BootId,
                ParentSessionId);
        }

        private static DateTimeOffset Time()
        {
            return new DateTimeOffset(2026, 7, 23, 12, 0, 0, TimeSpan.Zero);
        }

        private static void Throws<TException>(Action action, string message)
            where TException : Exception
        {
            try
            {
                action();
            }
            catch (TException)
            {
                return;
            }

            throw new InvalidOperationException(message);
        }

        private static void Assert(bool condition, string message)
        {
            if (!condition)
            {
                throw new InvalidOperationException(message);
            }
        }

        private static void AssertEqual<T>(T expected, T actual, string message)
        {
            if (!EqualityComparer<T>.Default.Equals(expected, actual))
            {
                throw new InvalidOperationException(
                    message + " Expected: " + expected + "; actual: " + actual + ".");
            }
        }
    }
}
