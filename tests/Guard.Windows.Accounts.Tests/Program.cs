using System;
using System.Collections.Generic;
using System.Threading;
using Guard.Domain;
using Guard.Domain.Readiness;
using Guard.Windows.Accounts;

namespace Guard.Windows.Accounts.Tests
{
    internal static class Program
    {
        private static int Main()
        {
            var tests = new List<(string Name, Action Run)>
            {
                ("accepts only an exact enabled local standard account", AcceptsOnlyEligibleAccount),
                ("rejects malformed and unknown SID candidates", RejectsMalformedAndUnknown),
                ("rejects disabled guest service domain and admin accounts", RejectsIneligibleAccounts),
                ("fails closed when account inspection errors", FailsClosedOnInspectionError),
                ("accepts a qualifying separate local administrator", AcceptsQualifyingSeparateAdministrator),
                ("rejects child-only and nonqualifying administrators", RejectsNonqualifyingAdministrators),
                ("fails closed for invalid administrator inventory", FailsClosedForInvalidAdministratorInventory),
                ("copies administrator inventory before evaluation", CopiesAdministratorInventory),
                ("cancellation does not query administrator inventory", AdministratorInventoryCancellation)
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

            Console.WriteLine(failures == 0
                ? "All Guard Windows account checks passed."
                : failures + " Guard Windows account check(s) failed.");
            return failures == 0 ? 0 : 1;
        }

        private static void AcceptsOnlyEligibleAccount()
        {
            var sid = new WindowsAccountSid("S-1-5-21-1001-2002-3003-1004");
            var validator = new ManagedChildAccountValidator(
                new FixedProvider(Facts(sid)));
            WindowsAccountSid binding;
            Assert(validator.TryValidate(sid.Value, out binding), "Eligible local child account was rejected.");
            Assert(binding.Equals(sid), "Validator returned a different SID binding.");
        }

        private static void RejectsMalformedAndUnknown()
        {
            var provider = new FixedProvider(null);
            var validator = new ManagedChildAccountValidator(provider);
            WindowsAccountSid ignored;
            Assert(!validator.TryValidate("not-a-sid", out ignored), "Malformed SID was accepted.");
            Assert(provider.CallCount == 0, "Malformed SID reached Windows account inspection.");
            Assert(!validator.TryValidate("S-1-5-21-1001-2002-3003-1004", out ignored), "Unknown SID was accepted.");
        }

        private static void RejectsIneligibleAccounts()
        {
            var sid = new WindowsAccountSid("S-1-5-21-1001-2002-3003-1004");
            AssertRejected(Facts(sid, enabled: false));
            AssertRejected(Facts(sid, guest: true));
            AssertRejected(Facts(sid, service: true));
            AssertRejected(Facts(sid, local: false));
            AssertRejected(Facts(sid, administrator: true));
        }

        private static void FailsClosedOnInspectionError()
        {
            var validator = new ManagedChildAccountValidator(new ThrowingProvider());
            WindowsAccountSid ignored;
            Assert(
                !validator.TryValidate("S-1-5-21-1001-2002-3003-1004", out ignored),
                "Account inspection failure produced a binding.");
        }

        private static void AcceptsQualifyingSeparateAdministrator()
        {
            var childSid = Sid(1004);
            var probe = new SeparateLocalAdministratorReadiness(
                new FixedAdministratorInventory(Inventory(childSid, Candidate(Sid(1005)))));
            Assert(
                probe.Probe(CancellationToken.None).State == ReadinessFactState.Satisfied,
                "Qualifying separate local administrator was rejected.");
        }

        private static void RejectsNonqualifyingAdministrators()
        {
            var childSid = Sid(1004);
            AssertAdministratorUnsatisfied(Inventory(childSid));
            AssertAdministratorUnsatisfied(Inventory(childSid, Candidate(childSid)));
            AssertAdministratorUnsatisfied(Inventory(childSid, Candidate(Sid(1005), local: false)));
            AssertAdministratorUnsatisfied(Inventory(childSid, Candidate(Sid(1005), enabled: false)));
            AssertAdministratorUnsatisfied(Inventory(childSid, Candidate(Sid(1005), locked: true)));
            AssertAdministratorUnsatisfied(Inventory(childSid, Candidate(Sid(1005), passwordRequired: false)));
            AssertAdministratorUnsatisfied(Inventory(childSid, Candidate(Sid(1005), guest: true)));
            AssertAdministratorUnsatisfied(Inventory(childSid, Candidate(Sid(1005), service: true)));
            AssertAdministratorUnsatisfied(Inventory(childSid, Candidate(Sid(1005), effectiveAdministrator: false)));
            AssertAdministratorUnsatisfied(Inventory(childSid, Candidate(new WindowsAccountSid("S-1-5-18"))));
            AssertAdministratorUnsatisfied(Inventory(childSid, Candidate(Sid(501))));
        }

        private static void FailsClosedForInvalidAdministratorInventory()
        {
            var childSid = Sid(1004);
            AssertAdministratorState(new FixedAdministratorInventory(null!), ReadinessFactState.Error);
            AssertAdministratorState(new ThrowingAdministratorInventory(), ReadinessFactState.Error);
            AssertAdministratorState(
                new FixedAdministratorInventory(
                    new SeparateLocalAdministratorInventory(
                        childSid,
                        new List<SeparateLocalAdministratorCandidateFacts> { null! })),
                ReadinessFactState.Error);
        }

        private static void AdministratorInventoryCancellation()
        {
            using (var cancellation = new CancellationTokenSource())
            {
                cancellation.Cancel();
                var inventory = new FixedAdministratorInventory(Inventory(Sid(1004), Candidate(Sid(1005))));
                var probe = new SeparateLocalAdministratorReadiness(inventory);
                Assert(probe.Probe(cancellation.Token).State == ReadinessFactState.Unknown, "Cancellation did not return Unknown.");
                Assert(inventory.CallCount == 0, "Cancelled probe queried administrator inventory.");
            }
        }

        private static void CopiesAdministratorInventory()
        {
            var source =
                new List<SeparateLocalAdministratorCandidateFacts>
                {
                    Candidate(Sid(1005))
                };
            var inventory = new SeparateLocalAdministratorInventory(
                Sid(1004),
                source);
            source.Clear();
            Assert(
                inventory.Candidates.Count == 1,
                "Administrator inventory retained a mutable caller collection.");
        }

        private static void AssertAdministratorUnsatisfied(SeparateLocalAdministratorInventory inventory)
        {
            AssertAdministratorState(new FixedAdministratorInventory(inventory), ReadinessFactState.Unsatisfied);
        }

        private static void AssertAdministratorState(
            ISeparateLocalAdministratorInventory inventory,
            ReadinessFactState expected)
        {
            var probe = new SeparateLocalAdministratorReadiness(inventory);
            Assert(probe.Probe(CancellationToken.None).State == expected, "Administrator readiness state was unexpected.");
        }

        private static SeparateLocalAdministratorInventory Inventory(
            WindowsAccountSid childSid,
            params SeparateLocalAdministratorCandidateFacts[] candidates)
        {
            return new SeparateLocalAdministratorInventory(childSid, candidates);
        }

        private static SeparateLocalAdministratorCandidateFacts Candidate(
            WindowsAccountSid sid,
            bool local = true,
            bool enabled = true,
            bool locked = false,
            bool passwordRequired = true,
            bool guest = false,
            bool service = false,
            bool effectiveAdministrator = true)
        {
            return new SeparateLocalAdministratorCandidateFacts(
                sid, local, enabled, locked, passwordRequired, guest, service, effectiveAdministrator);
        }

        private static WindowsAccountSid Sid(int rid)
        {
            return new WindowsAccountSid("S-1-5-21-1001-2002-3003-" + rid);
        }

        private static void AssertRejected(LocalAccountSecurityFacts facts)
        {
            var validator = new ManagedChildAccountValidator(new FixedProvider(facts));
            WindowsAccountSid ignored;
            Assert(!validator.TryValidate(facts.Sid.Value, out ignored), "Ineligible account was accepted.");
        }

        private static LocalAccountSecurityFacts Facts(
            WindowsAccountSid sid,
            bool local = true,
            bool enabled = true,
            bool guest = false,
            bool service = false,
            bool administrator = false)
        {
            return new LocalAccountSecurityFacts(
                sid,
                exists: true,
                isLocalUser: local,
                isEnabled: enabled,
                isGuest: guest,
                isServiceIdentity: service,
                isAdministrator: administrator);
        }

        private static void Assert(bool condition, string message)
        {
            if (!condition)
            {
                throw new InvalidOperationException(message);
            }
        }

        private sealed class FixedProvider : ILocalAccountSecurityFactsProvider
        {
            private readonly LocalAccountSecurityFacts? _facts;

            public FixedProvider(LocalAccountSecurityFacts? facts)
            {
                _facts = facts;
            }

            public int CallCount { get; private set; }

            public bool TryGet(
                WindowsAccountSid candidateSid,
                out LocalAccountSecurityFacts facts)
            {
                CallCount++;
                facts = _facts!;
                return _facts != null;
            }
        }

        private sealed class ThrowingProvider : ILocalAccountSecurityFactsProvider
        {
            public bool TryGet(
                WindowsAccountSid candidateSid,
                out LocalAccountSecurityFacts facts)
            {
                facts = null!;
                throw new UnauthorizedAccessException("Synthetic account query failure.");
            }
        }

        private sealed class FixedAdministratorInventory : ISeparateLocalAdministratorInventory
        {
            private readonly SeparateLocalAdministratorInventory _inventory;

            public FixedAdministratorInventory(SeparateLocalAdministratorInventory inventory)
            {
                _inventory = inventory;
            }

            public int CallCount { get; private set; }

            public SeparateLocalAdministratorInventory Get(CancellationToken cancellationToken)
            {
                CallCount++;
                return _inventory;
            }
        }

        private sealed class ThrowingAdministratorInventory : ISeparateLocalAdministratorInventory
        {
            public SeparateLocalAdministratorInventory Get(CancellationToken cancellationToken)
            {
                throw new UnauthorizedAccessException("Synthetic inventory query failure.");
            }
        }
    }
}
