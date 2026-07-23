using System;
using System.Collections.Generic;
using Guard.Domain;
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
                ("fails closed when account inspection errors", FailsClosedOnInspectionError)
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
    }
}
