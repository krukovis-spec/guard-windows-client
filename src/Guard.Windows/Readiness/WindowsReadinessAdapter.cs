using System;
using System.Threading;
using Guard.Contracts;
using Guard.Domain.Readiness;

namespace Guard.Windows.Readiness
{
    public sealed class WindowsReadinessAdapter
    {
        private readonly IReadinessProbe _windowsEdition;
        private readonly IReadinessProbe _childAccount;
        private readonly IReadinessProbe _separateLocalAdministrator;
        private readonly IReadinessProbe _secureBoot;
        private readonly IReadinessProbe _bitLocker;
        private readonly IReadinessProbe _serviceBoundary;
        private readonly IReadinessProbe _programDataAcl;
        private readonly ISupportedManagedBrowserReadinessProbe _supportedManagedBrowser;

        public WindowsReadinessAdapter(
            IReadinessProbe windowsEdition,
            IReadinessProbe childAccount,
            IReadinessProbe separateLocalAdministrator,
            IReadinessProbe secureBoot,
            IReadinessProbe bitLocker,
            IReadinessProbe serviceBoundary,
            IReadinessProbe programDataAcl,
            ISupportedManagedBrowserReadinessProbe supportedManagedBrowser)
        {
            _windowsEdition = RequireProbe(windowsEdition, nameof(windowsEdition));
            _childAccount = RequireProbe(childAccount, nameof(childAccount));
            _separateLocalAdministrator = RequireProbe(separateLocalAdministrator, nameof(separateLocalAdministrator));
            _secureBoot = RequireProbe(secureBoot, nameof(secureBoot));
            _bitLocker = RequireProbe(bitLocker, nameof(bitLocker));
            _serviceBoundary = RequireProbe(serviceBoundary, nameof(serviceBoundary));
            _programDataAcl = RequireProbe(programDataAcl, nameof(programDataAcl));
            _supportedManagedBrowser = supportedManagedBrowser ?? throw new ArgumentNullException(nameof(supportedManagedBrowser));
        }

        public ReadinessProbeFacts Probe(CancellationToken cancellationToken)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                return UnknownFacts();
            }

            return new ReadinessProbeFacts(
                ProbeRequired(_windowsEdition, cancellationToken),
                ProbeRequired(_childAccount, cancellationToken),
                ProbeRequired(_separateLocalAdministrator, cancellationToken),
                ProbeRequired(_secureBoot, cancellationToken),
                ProbeRequired(_bitLocker, cancellationToken),
                ProbeRequired(_serviceBoundary, cancellationToken),
                ProbeRequired(_programDataAcl, cancellationToken),
                ProbeBrowser(_supportedManagedBrowser, cancellationToken));
        }

        private static IReadinessProbe RequireProbe(IReadinessProbe probe, string parameterName)
        {
            return probe ?? throw new ArgumentNullException(parameterName);
        }

        private static ReadinessProbeFact ProbeRequired(IReadinessProbe probe, CancellationToken cancellationToken)
        {
            try
            {
                return probe.Probe(cancellationToken) ?? ErrorFact();
            }
            catch (OperationCanceledException)
            {
                return UnknownFact();
            }
            catch (Exception)
            {
                return ErrorFact();
            }
        }

        private static SupportedManagedBrowserProbeFact ProbeBrowser(
            ISupportedManagedBrowserReadinessProbe probe,
            CancellationToken cancellationToken)
        {
            try
            {
                var fact = probe.Probe(cancellationToken);
                if (fact == null ||
                    fact.ManagedBrowserCount >
                        GuardProtocol.MaximumManagedBrowserCount)
                {
                    return ErrorBrowserFact();
                }

                return fact;
            }
            catch (OperationCanceledException)
            {
                return UnknownBrowserFact();
            }
            catch (Exception)
            {
                return ErrorBrowserFact();
            }
        }

        private static ReadinessProbeFacts UnknownFacts()
        {
            return new ReadinessProbeFacts(
                UnknownFact(), UnknownFact(), UnknownFact(), UnknownFact(),
                UnknownFact(), UnknownFact(), UnknownFact(), UnknownBrowserFact());
        }

        private static ReadinessProbeFact UnknownFact()
        {
            return new ReadinessProbeFact(ReadinessFactState.Unknown);
        }

        private static ReadinessProbeFact ErrorFact()
        {
            return new ReadinessProbeFact(ReadinessFactState.Error);
        }

        private static SupportedManagedBrowserProbeFact UnknownBrowserFact()
        {
            return new SupportedManagedBrowserProbeFact(ReadinessFactState.Unknown, 0);
        }

        private static SupportedManagedBrowserProbeFact ErrorBrowserFact()
        {
            return new SupportedManagedBrowserProbeFact(ReadinessFactState.Error, 0);
        }
    }
}
