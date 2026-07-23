using System;
using System.Collections.Generic;
using Guard.Domain.Policy;

namespace Guard.AppControlPolicy.Tests
{
    internal static class Program
    {
        private const string HashA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        private const string HashB = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        private const string CatalogHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        private static int Main()
        {
            var tests = new List<(string Name, Action Run)>
            {
                ("keeps every executable collection enforced and default-deny", KeepsAllCollectionsDefaultDeny),
                ("requires current disposable-VM evidence before apply", RequiresCurrentVmEvidence),
                ("allows only exact hash or package identities", AllowsOnlyExactEnforcementIdentities),
                ("binds grants to one device and child", BindsGrants),
                ("fails closed for expiry, deny, and missing quota state", EvaluatesDecisionsFailClosed),
                ("produces deterministic exact rule ids", ProducesDeterministicRuleIds)
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

            Console.WriteLine(failures == 0 ? "All Guard app-control policy checks passed." : failures + " app-control policy check(s) failed.");
            return failures == 0 ? 0 : 1;
        }

        private static void KeepsAllCollectionsDefaultDeny()
        {
            var desired = CreateDesired(Array.Empty<ExactApplicationGrant>());
            var plan = DefaultDenyApplicationPolicyCompiler.Compile(desired, null, null, Now());
            AssertEqual(5, plan.Collections.Count, "A required executable collection was omitted.");
            foreach (var collection in plan.Collections)
            {
                Assert(collection.IsEnforced, "A collection was not enforced.");
                Assert(collection.IsDefaultDeny, "A collection was not default-deny.");
                AssertEqual(0, collection.AllowRules.Count, "An empty desired policy gained an implicit allow.");
            }

            Assert(!plan.CanApply, "An unattested rule catalog was deployable.");
        }

        private static void RequiresCurrentVmEvidence()
        {
            var now = Now();
            var desired = CreateDesired(Array.Empty<ExactApplicationGrant>());
            var incomplete = new DisposableVmRuleCatalogAttestation(
                desired.RequiredRuleCatalog,
                new[] { AppControlCollection.Executable, AppControlCollection.WindowsInstaller },
                guardSelfProtectionVerified: true,
                criticalSystemToolsVerified: true,
                arbitraryLaunchMatrixVerified: true,
                now.AddMinutes(-1));
            Assert(!DefaultDenyApplicationPolicyCompiler.Compile(desired, incomplete, null, now).CanApply, "Incomplete collection evidence was accepted.");

            var future = CreateCompleteAttestation(desired.RequiredRuleCatalog, now.AddMinutes(1));
            Assert(!DefaultDenyApplicationPolicyCompiler.Compile(desired, future, null, now).CanApply, "Future-dated VM evidence was accepted.");

            var wrongCatalog = CreateCompleteAttestation(
                new RuleCatalogReference("other", "1", CatalogHash, "26100.1000", "2.0.0"),
                now.AddMinutes(-1));
            Assert(!DefaultDenyApplicationPolicyCompiler.Compile(desired, wrongCatalog, null, now).CanApply, "Evidence for another catalog was accepted.");

            var complete = CreateCompleteAttestation(desired.RequiredRuleCatalog, now.AddMinutes(-1));
            Assert(DefaultDenyApplicationPolicyCompiler.Compile(desired, complete, null, now).CanApply, "Complete current evidence was rejected.");
        }

        private static void AllowsOnlyExactEnforcementIdentities()
        {
            var signedProvenance = new ApplicationIdentity("Acme", "Reader", SecureInstallRoot.ProgramFiles64, null);
            Throws(
                () => CreateGrant("signed", AppControlCollection.Executable, signedProvenance, new ParentDecision(ParentDecisionKind.AlwaysAllow)),
                "A broad signed provenance tuple became an executable grant.");

            var hash = new ApplicationIdentity(null, null, null, HashA);
            Throws(
                () => CreateGrant("wrong-appx", AppControlCollection.PackagedApp, hash, new ParentDecision(ParentDecisionKind.AlwaysAllow)),
                "A file hash became a packaged-app grant.");

            var package = ApplicationIdentity.ForPackageFamily("Microsoft.Example_8wekyb3d8bbwe");
            Throws(
                () => CreateGrant("wrong-exe", AppControlCollection.Executable, package, new ParentDecision(ParentDecisionKind.AlwaysAllow)),
                "A package identity became an unpackaged executable grant.");

            Assert(CreateGrant("hash", AppControlCollection.Executable, hash, new ParentDecision(ParentDecisionKind.AlwaysAllow)).Identity.HasFileHashFallback, "Exact hash grant was rejected.");
            Assert(CreateGrant("package", AppControlCollection.PackagedApp, package, new ParentDecision(ParentDecisionKind.AlwaysAllow)).Identity.HasPackageFamilyIdentity, "Exact package grant was rejected.");
        }

        private static void BindsGrants()
        {
            var grant = CreateGrant(
                "grant-a",
                AppControlCollection.Executable,
                new ApplicationIdentity(null, null, null, HashA),
                new ParentDecision(ParentDecisionKind.AlwaysAllow));
            Throws(
                () => new DesiredApplicationPolicy("other-device", ChildSid(), 1, Catalog(), new[] { grant }),
                "A grant crossed its device binding.");

            var duplicateTarget = CreateGrant(
                "grant-b",
                AppControlCollection.Executable,
                new ApplicationIdentity(null, null, null, HashA),
                new ParentDecision(ParentDecisionKind.Deny));
            Throws(
                () => CreateDesired(new[] { grant, duplicateTarget }),
                "Conflicting grants for the same exact target were accepted.");
        }

        private static void EvaluatesDecisionsFailClosed()
        {
            var now = Now();
            var always = CreateGrant("always", AppControlCollection.Executable, HashIdentity(HashA), new ParentDecision(ParentDecisionKind.AlwaysAllow));
            var expired = CreateGrant("expired", AppControlCollection.DynamicLibrary, HashIdentity(HashB), new ParentDecision(ParentDecisionKind.TemporaryAllow, now));
            var temporary = CreateGrant("temporary", AppControlCollection.DynamicLibrary, HashIdentity(HashA), new ParentDecision(ParentDecisionKind.TemporaryAllow, now.AddMinutes(10)));
            var quota = CreateGrant("quota", AppControlCollection.Script, HashIdentity(HashB), new ParentDecision(ParentDecisionKind.DailyQuota, dailyQuotaMinutes: 30));
            var deny = CreateGrant("deny", AppControlCollection.WindowsInstaller, HashIdentity(HashA), new ParentDecision(ParentDecisionKind.Deny));
            var desired = CreateDesired(new[] { always, expired, temporary, quota, deny });
            var attestation = CreateCompleteAttestation(desired.RequiredRuleCatalog, now.AddMinutes(-1));

            var withoutQuotaState = DefaultDenyApplicationPolicyCompiler.Compile(desired, attestation, null, now);
            AssertEqual(2, CountRules(withoutQuotaState), "Expired, denied, or unknown-quota grants became allows.");
            AssertEqual(now.AddMinutes(10), withoutQuotaState.NextReconcileAt, "Temporary expiry was not scheduled.");

            var withQuotaState = DefaultDenyApplicationPolicyCompiler.Compile(
                desired,
                attestation,
                new[] { new ApplicationGrantRuntimeState("quota", 29, now.AddSeconds(-30), now.AddSeconds(30)) },
                now);
            AssertEqual(3, CountRules(withQuotaState), "A quota with trusted remaining time was rejected.");
            AssertEqual(now.AddSeconds(30), withQuotaState.NextReconcileAt, "Quota freshness deadline was not scheduled first.");

            var exhausted = DefaultDenyApplicationPolicyCompiler.Compile(
                desired,
                attestation,
                new[] { new ApplicationGrantRuntimeState("quota", 30, now.AddSeconds(-30), now.AddSeconds(30)) },
                now);
            AssertEqual(2, CountRules(exhausted), "An exhausted quota remained allowed.");

            var stale = DefaultDenyApplicationPolicyCompiler.Compile(
                desired,
                attestation,
                new[] { new ApplicationGrantRuntimeState("quota", 0, now.AddMinutes(-2), now.AddMinutes(-1)) },
                now);
            AssertEqual(2, CountRules(stale), "Stale quota state became an allow.");
        }

        private static void ProducesDeterministicRuleIds()
        {
            var now = Now();
            var grant = CreateGrant("one", AppControlCollection.Executable, HashIdentity(HashA), new ParentDecision(ParentDecisionKind.AlwaysAllow));
            var desired = CreateDesired(new[] { grant });
            var attestation = CreateCompleteAttestation(desired.RequiredRuleCatalog, now.AddMinutes(-1));
            var first = DefaultDenyApplicationPolicyCompiler.Compile(desired, attestation, null, now);
            var second = DefaultDenyApplicationPolicyCompiler.Compile(desired, attestation, null, now.AddMinutes(1));
            AssertEqual(FirstRuleId(first), FirstRuleId(second), "Stable exact grant produced an unstable rule id.");
        }

        private static DesiredApplicationPolicy CreateDesired(IEnumerable<ExactApplicationGrant> grants)
        {
            return new DesiredApplicationPolicy(DeviceId(), ChildSid(), 7, Catalog(), grants);
        }

        private static ExactApplicationGrant CreateGrant(
            string grantId,
            AppControlCollection collection,
            ApplicationIdentity identity,
            ParentDecision decision)
        {
            return new ExactApplicationGrant(grantId, DeviceId(), ChildSid(), collection, identity, decision);
        }

        private static ApplicationIdentity HashIdentity(string hash)
        {
            return new ApplicationIdentity(null, null, null, hash);
        }

        private static RuleCatalogReference Catalog()
        {
            return new RuleCatalogReference("guard-v2-win11pro", "1", CatalogHash, "26100.1000", "2.0.0");
        }

        private static DisposableVmRuleCatalogAttestation CreateCompleteAttestation(
            RuleCatalogReference catalog,
            DateTimeOffset validatedAt)
        {
            return new DisposableVmRuleCatalogAttestation(
                catalog,
                new[]
                {
                    AppControlCollection.Executable,
                    AppControlCollection.WindowsInstaller,
                    AppControlCollection.Script,
                    AppControlCollection.PackagedApp,
                    AppControlCollection.DynamicLibrary
                },
                guardSelfProtectionVerified: true,
                criticalSystemToolsVerified: true,
                arbitraryLaunchMatrixVerified: true,
                validatedAt);
        }

        private static int CountRules(DefaultDenyApplicationPolicyPlan plan)
        {
            var count = 0;
            foreach (var collection in plan.Collections)
            {
                count += collection.AllowRules.Count;
            }

            return count;
        }

        private static string FirstRuleId(DefaultDenyApplicationPolicyPlan plan)
        {
            foreach (var collection in plan.Collections)
            {
                if (collection.AllowRules.Count > 0)
                {
                    return collection.AllowRules[0].RuleId;
                }
            }

            throw new InvalidOperationException("No compiled rule was found.");
        }

        private static DateTimeOffset Now() => new DateTimeOffset(2026, 7, 23, 12, 0, 0, TimeSpan.Zero);

        private static string DeviceId() => "device-v2-000001";

        private static string ChildSid() => "S-1-5-21-1000-1001-1002-1003";

        private static void Throws(Action action, string message)
        {
            try
            {
                action();
            }
            catch (ArgumentOutOfRangeException)
            {
                return;
            }
            catch (ArgumentException)
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
                throw new InvalidOperationException(message + " Expected=" + expected + ", actual=" + actual + ".");
            }
        }
    }
}
