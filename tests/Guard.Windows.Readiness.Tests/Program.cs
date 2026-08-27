using System;
using System.Collections.Generic;
using System.Threading;
using Guard.Contracts;
using Guard.Domain.Readiness;
using Guard.Windows.Readiness;

namespace Guard.Windows.Readiness.Tests
{
    internal static class Program
    {
        private static int Main()
        {
            var tests = new List<(string Name, Action Run)>
            {
                ("creates all-satisfied facts", CreatesAllSatisfiedFacts),
                ("fails closed for exceptions and null results", FailsClosedForErrors),
                ("preserves bounded browser-count semantics", PreservesBrowserCountSemantics),
                ("invokes every probe exactly once", InvokesEachProbeOnce),
                ("cancellation fails closed without probing", CancellationFailsClosed)
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

            Console.WriteLine(failures == 0 ? "All Guard Windows readiness checks passed." : failures + " readiness check(s) failed.");
            return failures == 0 ? 0 : 1;
        }

        private static void CreatesAllSatisfiedFacts()
        {
            var facts = CreateAdapter(Satisfied, () => BrowserSatisfied(2)).Probe(CancellationToken.None);
            AssertAll(facts, ReadinessFactState.Satisfied);
            Assert(facts.SupportedManagedBrowser.ManagedBrowserCount == 2, "Managed browser count changed.");
        }

        private static void FailsClosedForErrors()
        {
            var throwing = new FixedProbe(() => throw new InvalidOperationException("Synthetic failure."));
            var nullProbe = new FixedProbe(() => null!);
            var facts = new WindowsReadinessAdapter(
                throwing, nullProbe, FixedProbe.Satisfied(), FixedProbe.Satisfied(), FixedProbe.Satisfied(),
                FixedProbe.Satisfied(), FixedProbe.Satisfied(), new FixedBrowserProbe(() => throw new InvalidOperationException("Synthetic failure.")))
                .Probe(CancellationToken.None);
            Assert(facts.WindowsEdition.State == ReadinessFactState.Error, "Exception did not fail closed to Error.");
            Assert(facts.ChildAccount.State == ReadinessFactState.Error, "Null result did not fail closed to Error.");
            Assert(facts.SupportedManagedBrowser.State == ReadinessFactState.Error, "Browser exception did not fail closed to Error.");
            Assert(facts.SupportedManagedBrowser.ManagedBrowserCount == 0, "Error browser fact retained a count.");
        }

        private static void PreservesBrowserCountSemantics()
        {
            var one = CreateAdapter(Satisfied, () => BrowserSatisfied(1)).Probe(CancellationToken.None).SupportedManagedBrowser;
            var two = CreateAdapter(Satisfied, () => BrowserSatisfied(2)).Probe(CancellationToken.None).SupportedManagedBrowser;
            var excessive = CreateAdapter(Satisfied, () => BrowserSatisfied(GuardProtocol.MaximumManagedBrowserCount + 1)).Probe(CancellationToken.None).SupportedManagedBrowser;
            Assert(one.State == ReadinessFactState.Satisfied && one.ManagedBrowserCount == 1, "Single managed browser was not retained.");
            Assert(two.State == ReadinessFactState.Satisfied && two.ManagedBrowserCount == 2, "Multiple managed browsers were not retained.");
            Assert(excessive.State == ReadinessFactState.Error && excessive.ManagedBrowserCount == 0, "Unbounded browser result did not fail closed.");
        }

        private static void InvokesEachProbeOnce()
        {
            var required = new CountingProbe();
            var browser = new CountingBrowserProbe();
            var facts = new WindowsReadinessAdapter(required, required, required, required, required, required, required, browser)
                .Probe(CancellationToken.None);
            AssertAll(facts, ReadinessFactState.Satisfied);
            Assert(required.CallCount == 7, "Required probes were not invoked exactly once each.");
            Assert(browser.CallCount == 1, "Browser probe was not invoked exactly once.");
        }

        private static void CancellationFailsClosed()
        {
            using (var cancellation = new CancellationTokenSource())
            {
                cancellation.Cancel();
                var required = new CountingProbe();
                var browser = new CountingBrowserProbe();
                var facts = new WindowsReadinessAdapter(required, required, required, required, required, required, required, browser)
                    .Probe(cancellation.Token);
                AssertAll(facts, ReadinessFactState.Unknown);
                Assert(required.CallCount == 0 && browser.CallCount == 0, "Cancelled probe queried a source.");
            }

            var probeCancellation = new WindowsReadinessAdapter(
                new FixedProbe(() => throw new OperationCanceledException()), FixedProbe.Satisfied(), FixedProbe.Satisfied(),
                FixedProbe.Satisfied(), FixedProbe.Satisfied(), FixedProbe.Satisfied(), FixedProbe.Satisfied(),
                new FixedBrowserProbe(() => throw new OperationCanceledException()))
                .Probe(CancellationToken.None);
            Assert(probeCancellation.WindowsEdition.State == ReadinessFactState.Unknown, "Cancelled required probe did not fail closed to Unknown.");
            Assert(probeCancellation.SupportedManagedBrowser.State == ReadinessFactState.Unknown, "Cancelled browser probe did not fail closed to Unknown.");
        }

        private static WindowsReadinessAdapter CreateAdapter(Func<ReadinessProbeFact> required, Func<SupportedManagedBrowserProbeFact> browser)
        {
            return new WindowsReadinessAdapter(
                new FixedProbe(required), new FixedProbe(required), new FixedProbe(required), new FixedProbe(required),
                new FixedProbe(required), new FixedProbe(required), new FixedProbe(required), new FixedBrowserProbe(browser));
        }

        private static ReadinessProbeFact Satisfied() => new ReadinessProbeFact(ReadinessFactState.Satisfied);

        private static SupportedManagedBrowserProbeFact BrowserSatisfied(int count) => new SupportedManagedBrowserProbeFact(ReadinessFactState.Satisfied, count);

        private static void AssertAll(ReadinessProbeFacts facts, ReadinessFactState state)
        {
            Assert(facts.WindowsEdition.State == state, "Windows edition state was unexpected.");
            Assert(facts.ChildAccount.State == state, "Child account state was unexpected.");
            Assert(facts.SeparateLocalAdministrator.State == state, "Separate admin state was unexpected.");
            Assert(facts.SecureBoot.State == state, "Secure Boot state was unexpected.");
            Assert(facts.BitLocker.State == state, "BitLocker state was unexpected.");
            Assert(facts.ServiceBoundary.State == state, "Service boundary state was unexpected.");
            Assert(facts.ProgramDataAcl.State == state, "ProgramData ACL state was unexpected.");
            Assert(facts.SupportedManagedBrowser.State == state, "Browser state was unexpected.");
        }

        private static void Assert(bool condition, string message)
        {
            if (!condition)
            {
                throw new InvalidOperationException(message);
            }
        }

        private sealed class FixedProbe : IReadinessProbe
        {
            private readonly Func<ReadinessProbeFact> _probe;

            public FixedProbe(Func<ReadinessProbeFact> probe) => _probe = probe;

            public ReadinessProbeFact Probe(CancellationToken cancellationToken) => _probe();

            public static FixedProbe Satisfied() => new FixedProbe(Program.Satisfied);
        }

        private sealed class FixedBrowserProbe : ISupportedManagedBrowserReadinessProbe
        {
            private readonly Func<SupportedManagedBrowserProbeFact> _probe;

            public FixedBrowserProbe(Func<SupportedManagedBrowserProbeFact> probe) => _probe = probe;

            public SupportedManagedBrowserProbeFact Probe(CancellationToken cancellationToken) => _probe();
        }

        private sealed class CountingProbe : IReadinessProbe
        {
            public int CallCount { get; private set; }

            public ReadinessProbeFact Probe(CancellationToken cancellationToken)
            {
                CallCount++;
                return Satisfied();
            }
        }

        private sealed class CountingBrowserProbe : ISupportedManagedBrowserReadinessProbe
        {
            public int CallCount { get; private set; }

            public SupportedManagedBrowserProbeFact Probe(CancellationToken cancellationToken)
            {
                CallCount++;
                return BrowserSatisfied(2);
            }
        }
    }
}
