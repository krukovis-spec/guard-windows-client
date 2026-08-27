using System;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Guard.Application;
using Guard.Domain;
using Guard.Storage;
using Guard.Windows.Storage;

namespace Guard.Service
{
    internal sealed class ProgramDataServiceBoundaryGuard :
        IServiceDataBoundaryGuard,
        IServiceDataBoundaryBootstrapper
    {
        private readonly GuardDataPaths _paths;
        private readonly ProgramDataAclGuard _aclGuard;

        public ProgramDataServiceBoundaryGuard(
            GuardDataPaths paths,
            ProgramDataAclGuard aclGuard)
        {
            _paths = paths ?? throw new ArgumentNullException(nameof(paths));
            _aclGuard = aclGuard ?? throw new ArgumentNullException(nameof(aclGuard));
        }

        public void DemandReady()
        {
            _aclGuard.DemandServiceOnlyDirectory(_paths.SecurityRootDirectory);
            _aclGuard.DemandServiceOnlyDirectory(_paths.RootDirectory);
            _aclGuard.DemandServiceOnlyFileIfPresent(_paths.StateFile);
            _aclGuard.DemandServiceOnlyFileIfPresent(_paths.StateBackupFile);
            _aclGuard.DemandServiceOnlyFileIfPresent(_paths.JournalFile);
            _aclGuard.DemandServiceOnlyFileIfPresent(_paths.WriterLeaseFile);
        }

        public void PrepareEmptyBoundary()
        {
            _aclGuard.EnsureServiceOnlyDirectory(
                _paths.SecurityRootDirectory);
            _aclGuard.EnsureServiceOnlyDirectory(
                _paths.RootDirectory);
        }
    }

    /// <summary>
    /// Lazily opens the authoritative store only after the service execution
    /// boundary has been accepted. The ProgramData ACL is checked both before
    /// opening the lifetime writer lease and again by the outer initializer
    /// before any state is read or IPC is published.
    /// </summary>
    internal sealed class ServiceAuthoritativeStateBoundary :
        IServiceWriterLease,
        IAuthoritativeStateStore,
        IServiceAuthoritativeStateInitializer,
        IDisposable
    {
        private readonly object _sync = new object();
        private readonly GuardDataPaths _paths;
        private readonly IStateDataProtector _protector;
        private readonly IServiceDataBoundaryGuard _dataBoundaryGuard;
        private FileAuthoritativeStateStore? _store;

        public ServiceAuthoritativeStateBoundary(
            GuardDataPaths paths,
            IStateDataProtector protector,
            IServiceDataBoundaryGuard dataBoundaryGuard)
        {
            _paths = paths ?? throw new ArgumentNullException(nameof(paths));
            _protector = protector ?? throw new ArgumentNullException(nameof(protector));
            _dataBoundaryGuard = dataBoundaryGuard ??
                throw new ArgumentNullException(nameof(dataBoundaryGuard));
        }

        public Task AcquireAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (_sync)
            {
                if (_store != null)
                {
                    throw new InvalidOperationException(
                        "The authoritative writer lease is already held.");
                }

                _dataBoundaryGuard.DemandReady();
                var journal = new ProtectedFileStateVersionJournal(
                    _paths.JournalFile,
                    _protector);
                _store = new FileAuthoritativeStateStore(
                    _paths.StateFile,
                    _protector,
                    journal);
            }

            return Task.CompletedTask;
        }

        internal bool IsAcquired
        {
            get
            {
                lock (_sync)
                {
                    return _store != null;
                }
            }
        }

        public Task<DeviceSecurityState> LoadAsync(
            CancellationToken cancellationToken)
        {
            return GetAcquiredStore().LoadAsync(cancellationToken);
        }

        public async Task InitializeNewAsync(
            CancellationToken cancellationToken)
        {
            var randomBytes = new byte[16];
            RandomNumberGenerator.Fill(randomBytes);
            try
            {
                var deviceId =
                    "device-" +
                    Convert.ToHexString(randomBytes).ToLowerInvariant();
                await GetAcquiredStore()
                    .InitializeAsync(
                        new DeviceSecurityState(
                            deviceId,
                            version: 0,
                            highestAcceptedSequence: 0,
                            desiredPolicyRevision: 0),
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(randomBytes);
            }
        }

        public Task<bool> TryCommitAsync(
            long expectedVersion,
            DeviceSecurityState nextState,
            CancellationToken cancellationToken)
        {
            return GetAcquiredStore().TryCommitAsync(
                expectedVersion,
                nextState,
                cancellationToken);
        }

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }

        public void Dispose()
        {
            FileAuthoritativeStateStore? store;
            lock (_sync)
            {
                store = _store;
                _store = null;
            }

            store?.Dispose();
        }

        private FileAuthoritativeStateStore GetAcquiredStore()
        {
            lock (_sync)
            {
                return _store ?? throw new InvalidOperationException(
                    "The authoritative store cannot be used before its writer lease is acquired.");
            }
        }
    }

    internal sealed class NoProxyIdentityProvider :
        IServiceProxyIdentityProvider
    {
        public WindowsAccountSid? GetProxyAccountSid()
        {
            // The proxy endpoint stays absent until Stage 5 provisions a
            // dedicated low-privilege Windows identity.
            return null;
        }
    }

    internal sealed class BoundaryOnlyPolicyReconciler : IPolicyReconciler
    {
        public Task ReconcileAsync(
            DeviceSecurityState desiredState,
            CancellationToken cancellationToken)
        {
            if (desiredState == null)
            {
                throw new ArgumentNullException(nameof(desiredState));
            }

            cancellationToken.ThrowIfCancellationRequested();
            if (desiredState.DesiredPolicyRevision != 0 ||
                desiredState.HighestAcceptedSequence != 0)
            {
                throw new InvalidOperationException(
                    "Policy-bearing state cannot start before the Stage 4 enforcement adapter is installed.");
            }

            return Task.CompletedTask;
        }
    }

}
