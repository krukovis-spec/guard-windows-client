using System;
using System.Collections.Generic;
using System.Threading;
using Guard.Domain;
using Guard.Domain.Readiness;
using Guard.Windows.Accounts;
using Guard.Windows.Readiness;

namespace Guard.Windows.PlatformReadiness.Tests
{
    internal static class Program
    {
        private static int Main()
        {
            var tests = new List<(string Name, Action Run)>
            {
                ("accepts only Windows 11 Pro", AcceptsOnlyWindows11Pro),
                ("platform sources fail closed", PlatformSourcesFailClosed),
                ("secure boot maps registry states", SecureBootMapsStates),
                ("inventory preserves qualifying local administrator facts", InventoryPreservesQualifyingFacts),
                ("inventory excludes and bounds invalid candidates", InventoryExcludesAndBoundsCandidates),
                ("inventory cancellation does not query source", InventoryCancellationDoesNotQuerySource)
            };
            var failures = 0;
            foreach (var test in tests)
            {
                try { test.Run(); Console.WriteLine("PASS " + test.Name); }
                catch (Exception exception) { failures++; Console.WriteLine("FAIL " + test.Name + ": " + exception.Message); }
            }

            return failures == 0 ? 0 : 1;
        }

        private static void AcceptsOnlyWindows11Pro()
        {
            AssertEdition(22000, 0x30, ReadinessFactState.Satisfied);
            AssertEdition(21999, 0x30, ReadinessFactState.Unsatisfied);
            AssertEdition(26100, 0x04, ReadinessFactState.Unsatisfied);
            AssertEdition(26100, 0x79, ReadinessFactState.Unsatisfied);
            AssertEdition(26100, 0x31, ReadinessFactState.Unsatisfied);
        }

        private static void PlatformSourcesFailClosed()
        {
            var throwingEdition = new Windows11SupportedEditionReadinessProbe(new ThrowingEditionSource());
            Assert(throwingEdition.Probe(CancellationToken.None).State == ReadinessFactState.Error, "Edition source exception did not map to Error.");
            using (var cancellation = new CancellationTokenSource())
            {
                cancellation.Cancel();
                Assert(throwingEdition.Probe(cancellation.Token).State == ReadinessFactState.Unknown, "Cancelled edition probe did not map to Unknown.");
            }
        }

        private static void SecureBootMapsStates()
        {
            Assert(new SecureBootReadinessProbe(new FixedSecureBootSource(true, 1)).Probe(CancellationToken.None).State == ReadinessFactState.Satisfied, "Secure Boot value 1 was not satisfied.");
            Assert(new SecureBootReadinessProbe(new FixedSecureBootSource(true, 0)).Probe(CancellationToken.None).State == ReadinessFactState.Unsatisfied, "Secure Boot value 0 was not unsatisfied.");
            Assert(new SecureBootReadinessProbe(new FixedSecureBootSource(false, 0)).Probe(CancellationToken.None).State == ReadinessFactState.Unknown, "Missing Secure Boot state was not unknown.");
            Assert(new SecureBootReadinessProbe(new FixedSecureBootSource(true, 2)).Probe(CancellationToken.None).State == ReadinessFactState.Error, "Unexpected Secure Boot state did not fail closed.");
            Assert(new SecureBootReadinessProbe(new ThrowingSecureBootSource()).Probe(CancellationToken.None).State == ReadinessFactState.Error, "Secure Boot exception did not map to Error.");
        }

        private static void InventoryPreservesQualifyingFacts()
        {
            var source = new FixedAdministratorSource(new[] { Candidate(1005, effectiveAdministrator: true) });
            var inventory = new WindowsSeparateLocalAdministratorInventory(Sid(1004), source).Get(CancellationToken.None);
            Assert(inventory.Candidates.Count == 1, "Qualifying candidate was omitted.");
            var candidate = inventory.Candidates[0];
            Assert(candidate.IsLocalUser && candidate.IsEnabled && !candidate.IsLocked && candidate.PasswordRequired && candidate.IsEffectiveAdministrator, "Candidate facts changed.");
            Assert(new SeparateLocalAdministratorReadiness(new FixedInventory(inventory)).Probe(CancellationToken.None).State == ReadinessFactState.Satisfied, "Qualifying candidate did not satisfy readiness.");
        }

        private static void InventoryExcludesAndBoundsCandidates()
        {
            var rejected = new[]
            {
                Candidate(1005, normal: false), Candidate(1006, enabled: false), Candidate(1007, locked: true),
                Candidate(1008, passwordRequired: false), Candidate(501, guest: true), Candidate(1009, effectiveAdministrator: false)
            };
            var inventory = new WindowsSeparateLocalAdministratorInventory(Sid(1004), new FixedAdministratorSource(rejected)).Get(CancellationToken.None);
            Assert(new SeparateLocalAdministratorReadiness(new FixedInventory(inventory)).Probe(CancellationToken.None).State == ReadinessFactState.Unsatisfied, "Invalid candidate qualified as an administrator.");

            var tooMany = new List<WindowsSeparateLocalAdministratorSourceCandidate>();
            for (var index = 0; index <= WindowsSeparateLocalAdministratorInventory.MaximumCandidates; index++) { tooMany.Add(Candidate(2000 + index)); }
            AssertThrows(() => new WindowsSeparateLocalAdministratorInventory(Sid(1004), new FixedAdministratorSource(tooMany)).Get(CancellationToken.None), "Unbounded inventory was accepted.");
        }

        private static void InventoryCancellationDoesNotQuerySource()
        {
            var source = new FixedAdministratorSource(Array.Empty<WindowsSeparateLocalAdministratorSourceCandidate>());
            using (var cancellation = new CancellationTokenSource())
            {
                cancellation.Cancel();
                AssertThrowsCanceled(
                    () => new WindowsSeparateLocalAdministratorInventory(
                        Sid(1004),
                        source).Get(cancellation.Token),
                    "Cancelled inventory did not throw.");
            }

            Assert(source.CallCount == 0, "Cancelled inventory queried its source.");
        }

        private static void AssertEdition(uint build, uint product, ReadinessFactState expected)
        {
            var actual = new Windows11SupportedEditionReadinessProbe(new FixedEditionSource(build, product)).Probe(CancellationToken.None).State;
            Assert(actual == expected, "Windows edition state was unexpected.");
        }

        private static WindowsSeparateLocalAdministratorSourceCandidate Candidate(int rid, bool normal = true, bool enabled = true, bool locked = false, bool passwordRequired = true, bool guest = false, bool effectiveAdministrator = true)
        {
            return new WindowsSeparateLocalAdministratorSourceCandidate(Sid(rid), normal, enabled, locked, passwordRequired, guest, false, effectiveAdministrator);
        }

        private static WindowsAccountSid Sid(int rid) => new WindowsAccountSid("S-1-5-21-111-222-333-" + rid);
        private static void Assert(bool value, string message) { if (!value) { throw new InvalidOperationException(message); } }
        private static void AssertThrows(Action action, string message) { try { action(); } catch (InvalidOperationException) { return; } throw new InvalidOperationException(message); }
        private static void AssertThrowsCanceled(Action action, string message) { try { action(); } catch (OperationCanceledException) { return; } throw new InvalidOperationException(message); }

        private sealed class FixedEditionSource : IWindowsEditionFactsSource { private readonly WindowsEditionFacts _facts; public FixedEditionSource(uint build, uint product) { _facts = new WindowsEditionFacts(build, product); } public WindowsEditionFacts Get() => _facts; }
        private sealed class ThrowingEditionSource : IWindowsEditionFactsSource { public WindowsEditionFacts Get() => throw new InvalidOperationException(); }
        private sealed class FixedSecureBootSource : ISecureBootStateSource { private readonly bool _found; private readonly int _value; public FixedSecureBootSource(bool found, int value) { _found = found; _value = value; } public bool TryReadEnabled(out int enabled) { enabled = _value; return _found; } }
        private sealed class ThrowingSecureBootSource : ISecureBootStateSource { public bool TryReadEnabled(out int enabled) { enabled = 0; throw new InvalidOperationException(); } }
        private sealed class FixedAdministratorSource : IWindowsSeparateLocalAdministratorSource { private readonly IReadOnlyCollection<WindowsSeparateLocalAdministratorSourceCandidate> _candidates; public FixedAdministratorSource(IReadOnlyCollection<WindowsSeparateLocalAdministratorSourceCandidate> candidates) { _candidates = candidates; } public int CallCount { get; private set; } public IReadOnlyCollection<WindowsSeparateLocalAdministratorSourceCandidate> Enumerate(CancellationToken cancellationToken) { CallCount++; return _candidates; } }
        private sealed class FixedInventory : ISeparateLocalAdministratorInventory { private readonly SeparateLocalAdministratorInventory _inventory; public FixedInventory(SeparateLocalAdministratorInventory inventory) { _inventory = inventory; } public SeparateLocalAdministratorInventory Get(CancellationToken cancellationToken) => _inventory; }
    }
}
