using System;
using System.IO;
using System.Threading;
using Guard.Application.Readiness;
using Guard.Domain;
using Guard.Domain.Readiness;
using Guard.Windows.Accounts;
using Guard.Windows.Readiness;
using Guard.Windows.Services;

namespace Guard.Service
{
    internal static class GuardServiceIdentity
    {
        public const string ServiceName = "Guard";

        public static string ExpectedBinaryPath
        {
            get
            {
                var programFiles = Environment.GetFolderPath(
                    Environment.SpecialFolder.ProgramFiles);
                if (string.IsNullOrWhiteSpace(programFiles))
                {
                    throw new InvalidOperationException(
                        "The protected Program Files root is unavailable.");
                }

                return Path.Combine(
                    programFiles,
                    "Guard",
                    "Guard.Service.exe");
            }
        }
    }

    /// <summary>
    /// Placeholder for the future read-only SCM adapter. Until SCM install
    /// facts are observed, the final service-boundary fact remains Unknown.
    /// </summary>
    internal sealed class UnobservedServiceHealthQuery :
        IServiceHealthQuery
    {
        public ServiceHealthProbeResult Query(string serviceName)
        {
            return new ServiceHealthProbeResult(
                ServiceHealthProbeState.Unknown,
                facts: null);
        }
    }

    internal sealed class ProductionReadinessFactsProvider :
        IDeviceReadinessFactsProvider
    {
        private readonly ILocalAccountSecurityFactsProvider _accountFacts;
        private readonly IWindowsEditionFactsSource _windowsEditionFacts;
        private readonly ISecureBootStateSource _secureBootState;
        private readonly IWindowsSeparateLocalAdministratorSource
            _separateAdministratorSource;
        private readonly IServiceDataBoundaryGuard _dataBoundaryGuard;
        private readonly GuardServiceHealthInspector _serviceHealth;

        public ProductionReadinessFactsProvider(
            ILocalAccountSecurityFactsProvider accountFacts,
            IWindowsEditionFactsSource windowsEditionFacts,
            ISecureBootStateSource secureBootState,
            IWindowsSeparateLocalAdministratorSource
                separateAdministratorSource,
            IServiceDataBoundaryGuard dataBoundaryGuard,
            GuardServiceHealthInspector serviceHealth)
        {
            _accountFacts = accountFacts ??
                throw new ArgumentNullException(nameof(accountFacts));
            _windowsEditionFacts = windowsEditionFacts ??
                throw new ArgumentNullException(
                    nameof(windowsEditionFacts));
            _secureBootState = secureBootState ??
                throw new ArgumentNullException(
                    nameof(secureBootState));
            _separateAdministratorSource =
                separateAdministratorSource ??
                throw new ArgumentNullException(
                    nameof(separateAdministratorSource));
            _dataBoundaryGuard = dataBoundaryGuard ??
                throw new ArgumentNullException(nameof(dataBoundaryGuard));
            _serviceHealth = serviceHealth ??
                throw new ArgumentNullException(nameof(serviceHealth));
        }

        public ReadinessProbeFacts Probe(
            DeviceSecurityState authoritativeState,
            CancellationToken cancellationToken)
        {
            if (authoritativeState == null)
            {
                throw new ArgumentNullException(
                    nameof(authoritativeState));
            }

            var adapter = new WindowsReadinessAdapter(
                new Windows11SupportedEditionReadinessProbe(
                    _windowsEditionFacts),
                new BoundChildAccountReadinessProbe(
                    authoritativeState,
                    _accountFacts),
                CreateSeparateAdministratorProbe(authoritativeState),
                new SecureBootReadinessProbe(_secureBootState),
                UnknownReadinessProbe.Instance,
                new ServiceBoundaryReadinessProbe(_serviceHealth),
                new ProgramDataReadinessProbe(_dataBoundaryGuard),
                UnknownBrowserReadinessProbe.Instance);
            return adapter.Probe(cancellationToken);
        }

        private IReadinessProbe CreateSeparateAdministratorProbe(
            DeviceSecurityState authoritativeState)
        {
            if (authoritativeState.ChildAccountSid == null)
            {
                return UnknownReadinessProbe.Instance;
            }

            return new SeparateLocalAdministratorReadiness(
                new WindowsSeparateLocalAdministratorInventory(
                    authoritativeState.ChildAccountSid,
                    _separateAdministratorSource));
        }

        private sealed class UnknownReadinessProbe : IReadinessProbe
        {
            public static readonly UnknownReadinessProbe Instance =
                new UnknownReadinessProbe();

            public ReadinessProbeFact Probe(
                CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                return Fact(ReadinessFactState.Unknown);
            }
        }

        private sealed class UnknownBrowserReadinessProbe :
            ISupportedManagedBrowserReadinessProbe
        {
            public static readonly UnknownBrowserReadinessProbe Instance =
                new UnknownBrowserReadinessProbe();

            public SupportedManagedBrowserProbeFact Probe(
                CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                return new SupportedManagedBrowserProbeFact(
                    ReadinessFactState.Unknown,
                    managedBrowserCount: 0);
            }
        }

        private sealed class BoundChildAccountReadinessProbe :
            IReadinessProbe
        {
            private readonly DeviceSecurityState _state;
            private readonly ILocalAccountSecurityFactsProvider _factsProvider;

            public BoundChildAccountReadinessProbe(
                DeviceSecurityState state,
                ILocalAccountSecurityFactsProvider factsProvider)
            {
                _state = state;
                _factsProvider = factsProvider;
            }

            public ReadinessProbeFact Probe(
                CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var childSid = _state.ChildAccountSid;
                if (childSid == null)
                {
                    return Fact(ReadinessFactState.Unsatisfied);
                }

                LocalAccountSecurityFacts facts;
                if (!_factsProvider.TryGet(childSid, out facts) ||
                    facts == null ||
                    !facts.Sid.Equals(childSid) ||
                    !facts.Exists ||
                    !facts.IsLocalUser ||
                    !facts.IsEnabled ||
                    facts.IsGuest ||
                    facts.IsServiceIdentity ||
                    facts.IsAdministrator)
                {
                    return Fact(ReadinessFactState.Unsatisfied);
                }

                return Fact(ReadinessFactState.Satisfied);
            }
        }

        private sealed class ProgramDataReadinessProbe : IReadinessProbe
        {
            private readonly IServiceDataBoundaryGuard _guard;

            public ProgramDataReadinessProbe(
                IServiceDataBoundaryGuard guard)
            {
                _guard = guard;
            }

            public ReadinessProbeFact Probe(
                CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                _guard.DemandReady();
                return Fact(ReadinessFactState.Satisfied);
            }
        }

        private sealed class ServiceBoundaryReadinessProbe :
            IReadinessProbe
        {
            private readonly GuardServiceHealthInspector _inspector;

            public ServiceBoundaryReadinessProbe(
                GuardServiceHealthInspector inspector)
            {
                _inspector = inspector;
            }

            public ReadinessProbeFact Probe(
                CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var evaluation = _inspector.Inspect();
                if (evaluation.IsHealthy)
                {
                    return Fact(ReadinessFactState.Satisfied);
                }

                var state = ReadinessFactState.Unsatisfied;
                for (var index = 0;
                     index < evaluation.Failures.Count;
                     index++)
                {
                    if (evaluation.Failures[index] ==
                        ServiceHealthFailure.ProbeUnknown)
                    {
                        state = ReadinessFactState.Unknown;
                    }
                    else if (evaluation.Failures[index] ==
                             ServiceHealthFailure.ProbeError ||
                             evaluation.Failures[index] ==
                             ServiceHealthFailure.FactsMissing)
                    {
                        state = ReadinessFactState.Error;
                        break;
                    }
                }

                return Fact(state);
            }
        }

        private static ReadinessProbeFact Fact(
            ReadinessFactState state)
        {
            return new ReadinessProbeFact(state);
        }
    }
}
