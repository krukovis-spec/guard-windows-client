using System;
using System.Threading;
using System.Threading.Tasks;

namespace Guard.Storage
{
    /// <summary>
    /// Protects the complete authoritative-state payload. Implementations must
    /// provide confidentiality and integrity and must bind ciphertext to Guard v2.
    /// </summary>
    public interface IStateDataProtector
    {
        byte[] Protect(byte[] plaintext);

        byte[] Unprotect(byte[] protectedData);
    }

    /// <summary>
    /// Stores the highest state version ever made authoritative. Implementations
    /// must never decrease the returned value.
    /// </summary>
    public interface IStateVersionWatermark
    {
        Task<StateVersionWatermark?> GetCurrentAsync(CancellationToken cancellationToken);

        Task AdvanceToAsync(
            long version,
            byte[] stateCommitment,
            CancellationToken cancellationToken);
    }

    public sealed class StateVersionWatermark
    {
        public const int CommitmentBytes = 32;
        private readonly byte[] _stateCommitment;

        public StateVersionWatermark(long version, byte[] stateCommitment)
        {
            if (version < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(version));
            }

            if (stateCommitment == null || stateCommitment.Length != CommitmentBytes)
            {
                throw new ArgumentException(
                    "A complete SHA-256 state commitment is required.",
                    nameof(stateCommitment));
            }

            Version = version;
            _stateCommitment = (byte[])stateCommitment.Clone();
        }

        public long Version { get; }

        public byte[] GetStateCommitmentCopy()
        {
            return (byte[])_stateCommitment.Clone();
        }
    }
}
