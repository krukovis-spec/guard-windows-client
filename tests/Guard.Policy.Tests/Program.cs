using System;
using System.Collections.Generic;
using Guard.Domain.Policy;

namespace Guard.Policy.Tests
{
    internal static class Program
    {
        private const string HashA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        private const string HashB = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

        private static int Main()
        {
            var tests = new List<(string Name, Action Run)>
            {
                ("authorizes applications by signed tuple or hash, never path", AuthorizesApplications),
                ("uses collision-free signed authorization keys", UsesCollisionFreeSignedAuthorizationKeys),
                ("normalizes DNS names and matches explicit service bundles", MatchesDomains),
                ("deduplicates request keys by device and identity", DeduplicatesRequests),
                ("validates the four parent decisions fail-closed", ValidatesParentDecisions),
                ("limits maintenance to scoped expiring capabilities", LimitsMaintenance)
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

            Console.WriteLine(failures == 0 ? "All Guard policy checks passed." : failures + " Guard policy check(s) failed.");
            return failures == 0 ? 0 : 1;
        }

        private static void AuthorizesApplications()
        {
            var signed = new ApplicationIdentity("Acme Ltd", "Reader", SecureInstallRoot.ProgramFiles64, null);
            var sameSigned = new ApplicationIdentity("Acme Ltd", "Reader", SecureInstallRoot.ProgramFiles64, null);
            var hashOnly = new ApplicationIdentity(null, null, null, HashB);
            var sameHash = new ApplicationIdentity(null, null, null, HashB);
            Assert(signed.Authorizes(sameSigned), "Matching publisher/product/root tuple was rejected.");
            Assert(hashOnly.Authorizes(sameHash), "SHA-256 fallback was rejected.");
            Assert(!signed.Authorizes(hashOnly), "Pathless hash-only identity matched a different signed identity.");
            Assert(!signed.Authorizes(new ApplicationIdentity("Acme Ltd", "Reader", SecureInstallRoot.WindowsSystem, null)), "Secure-root mismatch was accepted.");
            Throws(() => new ApplicationIdentity("Acme Ltd", null, SecureInstallRoot.ProgramFiles64, null), "Partial publisher identity was accepted.");
            Throws(() => new ApplicationIdentity("Acme Ltd", "Reader", SecureInstallRoot.ProgramFiles64, HashA), "Mixed publisher/hash identity was accepted.");
            Throws(() => new ApplicationIdentity(null, null, null, null), "Missing identity was accepted.");
        }

        private static void UsesCollisionFreeSignedAuthorizationKeys()
        {
            var first = new ApplicationIdentity("Acme|Reader", "ProgramFiles64", SecureInstallRoot.ProgramFiles64, null);
            var second = new ApplicationIdentity("Acme", "Reader|ProgramFiles64", SecureInstallRoot.ProgramFiles64, null);
            Assert(!string.Equals(first.AuthorizationKey, second.AuthorizationKey, StringComparison.Ordinal), "Delimiter-containing publisher/product tuples collided.");
            Assert(!first.Equals(second), "Distinct signed tuples compared equal after key encoding.");
        }

        private static void MatchesDomains()
        {
            var bundle = new ServiceBundle("video", new[] { new DomainRule("ExAmple.com.", true), new DomainRule("cdn.example.net", false) });
            Assert(bundle.Matches("video.EXAMPLE.com"), "Subdomain did not match explicit suffix rule.");
            Assert(bundle.Matches("cdn.example.net"), "Exact domain did not match.");
            Assert(!bundle.Matches("other.cdn.example.net"), "Exact-only domain matched a subdomain.");
            Assert(!bundle.Matches("example.com.attacker.test"), "Suffix boundary was bypassed.");
            Throws(() => DomainName.Normalize("https://example.com"), "URL was accepted as a hostname.");
            Throws(() => DomainName.Normalize("localhost"), "Single-label host was accepted.");
            Throws(() => DomainName.Normalize("127.0.0.1"), "IP literal was accepted as a hostname.");
        }

        private static void DeduplicatesRequests()
        {
            var first = AccessRequestKey.ForSite("device-1", "Example.COM");
            var same = AccessRequestKey.ForSite("device-1", "example.com.");
            var otherDevice = AccessRequestKey.ForSite("device-2", "example.com");
            var application = AccessRequestKey.ForApplication("device-1", new ApplicationIdentity(null, null, null, HashA));
            Assert(first.Equals(same), "Normalized same site was not deduplicated.");
            Assert(!first.Equals(otherDevice), "Requests ignored device identity.");
            Assert(!first.Equals(application), "App and site target identities collided.");
        }

        private static void ValidatesParentDecisions()
        {
            var now = DateTimeOffset.UtcNow;
            Assert(new ParentDecision(ParentDecisionKind.AlwaysAllow).IsEffectiveAt(now), "Always allow was ineffective.");
            Assert(new ParentDecision(ParentDecisionKind.TemporaryAllow, now.AddMinutes(1)).IsEffectiveAt(now), "Temporary allow was ineffective.");
            Assert(!new ParentDecision(ParentDecisionKind.TemporaryAllow, now).IsEffectiveAt(now), "Expired temporary allow remained active.");
            Assert(new ParentDecision(ParentDecisionKind.DailyQuota, dailyQuotaMinutes: 30).IsEffectiveAt(now), "Daily quota was ineffective.");
            Assert(!new ParentDecision(ParentDecisionKind.Deny).IsEffectiveAt(now), "Deny was effective.");
            Throws(() => new ParentDecision(ParentDecisionKind.DailyQuota, dailyQuotaMinutes: 0), "Zero quota was accepted.");
            Throws(() => new ParentDecision(ParentDecisionKind.Deny, now.AddMinutes(1)), "Deny accepted an expiry.");
        }

        private static void LimitsMaintenance()
        {
            var now = DateTimeOffset.UtcNow;
            var lease = new MaintenanceLease("device-1", "lease-1", MaintenanceCapability.ApplicationPolicy | MaintenanceCapability.UpdateInstallation, now, now.AddMinutes(15));
            Assert(lease.Allows("device-1", MaintenanceCapability.ApplicationPolicy, now), "Granted capability was denied.");
            Assert(!lease.Allows("device-1", MaintenanceCapability.WebPolicy, now), "Ungrantable web capability was allowed.");
            Assert(!lease.Allows("device-2", MaintenanceCapability.ApplicationPolicy, now), "Lease crossed device scope.");
            Assert(!lease.Allows("device-1", MaintenanceCapability.ApplicationPolicy, now.AddTicks(-1)), "Lease was usable before its issue time.");
            Assert(!lease.Allows("device-1", MaintenanceCapability.ApplicationPolicy, now.AddMinutes(15)), "Expired lease remained active.");
            Throws(() => new MaintenanceLease("device-1", "lease-1", MaintenanceCapability.None, now, now.AddMinutes(15)), "Empty/global-style lease was accepted.");
            Throws(() => new MaintenanceLease("device-1", "lease-1", MaintenanceCapability.ApplicationPolicy, now, now.AddMinutes(5)), "Non-canonical maintenance duration was accepted.");
        }

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

        private static void Assert(bool value, string message)
        {
            if (!value)
            {
                throw new InvalidOperationException(message);
            }
        }
    }
}
