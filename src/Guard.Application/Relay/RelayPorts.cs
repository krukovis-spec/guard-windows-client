using System.Threading;
using System.Threading.Tasks;
using Guard.Domain.Relay;

namespace Guard.Application.Relay
{
    /// <summary>
    /// Sole authoritative persistence boundary for relay transactions. A caller
    /// must construct one complete successor aggregate and publish it with CAS;
    /// partial approval side effects are not exposed by this port.
    /// </summary>
    public interface IRelayTransactionStore
    {
        Task<RelayTransactionState> LoadAsync(
            CancellationToken cancellationToken);

        Task<bool> TryCommitAsync(
            long expectedVersion,
            RelayTransactionState nextState,
            CancellationToken cancellationToken);
    }
}
