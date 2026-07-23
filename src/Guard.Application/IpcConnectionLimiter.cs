using System;
using System.Threading;
using Guard.Contracts;

namespace Guard.Application
{
    public sealed class IpcConnectionLimiter
    {
        private readonly int _maximumConnections;
        private int _activeConnections;

        public IpcConnectionLimiter(int maximumConnections = GuardProtocol.MaximumConcurrentPipeConnections)
        {
            if (maximumConnections < 1 || maximumConnections > GuardProtocol.MaximumConcurrentPipeConnections)
            {
                throw new ArgumentOutOfRangeException(nameof(maximumConnections));
            }

            _maximumConnections = maximumConnections;
        }

        public int ActiveConnections => Volatile.Read(ref _activeConnections);

        public bool TryAcquire(out IDisposable? lease)
        {
            while (true)
            {
                var current = Volatile.Read(ref _activeConnections);
                if (current >= _maximumConnections)
                {
                    lease = null;
                    return false;
                }

                if (Interlocked.CompareExchange(ref _activeConnections, current + 1, current) == current)
                {
                    lease = new ConnectionLease(this);
                    return true;
                }
            }
        }

        private void Release()
        {
            var remaining = Interlocked.Decrement(ref _activeConnections);
            if (remaining < 0)
            {
                Interlocked.Exchange(ref _activeConnections, 0);
                throw new InvalidOperationException("IPC connection leases were released more than once.");
            }
        }

        private sealed class ConnectionLease : IDisposable
        {
            private IpcConnectionLimiter? _owner;

            public ConnectionLease(IpcConnectionLimiter owner)
            {
                _owner = owner;
            }

            public void Dispose()
            {
                var owner = Interlocked.Exchange(ref _owner, null);
                owner?.Release();
            }
        }
    }
}
