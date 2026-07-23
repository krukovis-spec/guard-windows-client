using System;
using System.IO;

namespace Guard.Storage
{
    public sealed class StateStoreCorruptionException : IOException
    {
        public StateStoreCorruptionException(string message)
            : base(message)
        {
        }

        public StateStoreCorruptionException(string message, Exception innerException)
            : base(message, innerException)
        {
        }
    }

    public sealed class StateRollbackDetectedException : IOException
    {
        public StateRollbackDetectedException(long storedVersion, long highestVersion)
            : base("The authoritative state version is older than its monotonic watermark.")
        {
            StoredVersion = storedVersion;
            HighestVersion = highestVersion;
        }

        public long StoredVersion { get; }

        public long HighestVersion { get; }
    }
}
