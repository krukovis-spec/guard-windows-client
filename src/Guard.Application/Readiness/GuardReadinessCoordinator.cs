using System;
using System.Threading;
using System.Threading.Tasks;
using Guard.Domain;
using Guard.Domain.Readiness;

namespace Guard.Application.Readiness
{
    public interface IDeviceReadinessFactsProvider
    {
        ReadinessProbeFacts Probe(
            DeviceSecurityState authoritativeState,
            CancellationToken cancellationToken);
    }

    /// <summary>
    /// An observational snapshot only. A future enable-protection operation
    /// must collect fresh facts again immediately before its authoritative
    /// commit and policy application.
    /// </summary>
    public sealed class GuardReadinessSnapshot
    {
        public GuardReadinessSnapshot(
            long stateVersion,
            DateTimeOffset observedAtUtc,
            ReadinessProbeFacts facts,
            ReadinessEvaluation evaluation)
        {
            if (stateVersion < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(stateVersion));
            }

            StateVersion = stateVersion;
            ObservedAtUtc = observedAtUtc.ToUniversalTime();
            Facts = facts ?? throw new ArgumentNullException(nameof(facts));
            Evaluation = evaluation ??
                throw new ArgumentNullException(nameof(evaluation));
        }

        public long StateVersion { get; }

        public DateTimeOffset ObservedAtUtc { get; }

        public ReadinessProbeFacts Facts { get; }

        public ReadinessEvaluation Evaluation { get; }
    }

    public sealed class GuardReadinessCoordinator
    {
        private readonly IAuthoritativeStateStore _stateStore;
        private readonly IDeviceReadinessFactsProvider _factsProvider;

        public GuardReadinessCoordinator(
            IAuthoritativeStateStore stateStore,
            IDeviceReadinessFactsProvider factsProvider)
        {
            _stateStore = stateStore ??
                throw new ArgumentNullException(nameof(stateStore));
            _factsProvider = factsProvider ??
                throw new ArgumentNullException(nameof(factsProvider));
        }

        public async Task<GuardReadinessSnapshot> ObserveAsync(
            DateTimeOffset observedAtUtc,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var state = await _stateStore
                .LoadAsync(cancellationToken)
                .ConfigureAwait(false);

            ReadinessProbeFacts facts;
            try
            {
                facts = _factsProvider.Probe(
                    state,
                    cancellationToken) ?? ErrorFacts();
            }
            catch (OperationCanceledException)
                when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception)
            {
                facts = ErrorFacts();
            }

            return new GuardReadinessSnapshot(
                state.Version,
                observedAtUtc,
                facts,
                ReadinessEvaluator.Evaluate(facts));
        }

        private static ReadinessProbeFacts ErrorFacts()
        {
            var error = new ReadinessProbeFact(
                ReadinessFactState.Error);
            return new ReadinessProbeFacts(
                error,
                error,
                error,
                error,
                error,
                error,
                error,
                new SupportedManagedBrowserProbeFact(
                    ReadinessFactState.Error,
                    managedBrowserCount: 0));
        }
    }
}
