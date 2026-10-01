using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Text.Json;
using Guard.Application;
using Guard.Domain;
using Guard.Domain.Relay;
using Guard.Storage;
using Guard.Storage.Relay;
using Guard.Windows.Storage;
using Guard.Windows.Cryptography;

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
            _aclGuard.DemandServiceOnlyDirectory(_paths.RelayRootDirectory);
            _aclGuard.DemandServiceOnlyFileIfPresent(_paths.RelayStateFile);
            _aclGuard.DemandServiceOnlyFileIfPresent(_paths.RelayStateBackupFile);
            _aclGuard.DemandServiceOnlyFileIfPresent(_paths.RelayJournalFile);
            _aclGuard.DemandServiceOnlyFileIfPresent(_paths.RelayWriterLeaseFile);
            _aclGuard.DemandServiceOnlyFileIfPresent(_paths.StateFile);
            _aclGuard.DemandServiceOnlyFileIfPresent(_paths.StateBackupFile);
            _aclGuard.DemandServiceOnlyFileIfPresent(_paths.JournalFile);
            _aclGuard.DemandServiceOnlyFileIfPresent(_paths.WriterLeaseFile);
            _aclGuard.DemandServiceOnlyFileIfPresent(_paths.DeviceIdentityFile);
            _aclGuard.DemandServiceOnlyFileIfPresent(_paths.DeviceIdentityPendingFile);
            _aclGuard.DemandServiceOnlyFileIfPresent(_paths.DeviceRelayConfigurationFile);
            _aclGuard.DemandServiceOnlyFileIfPresent(_paths.DeviceRelayConfigurationPendingFile);
            _aclGuard.DemandServiceOnlyFileIfPresent(_paths.DeviceRelayInstallFile);
            _aclGuard.DemandServiceOnlyFileIfPresent(_paths.DeviceRelayInstallPendingFile);
        }

        public void PrepareEmptyBoundary()
        {
            _aclGuard.EnsureServiceOnlyDirectory(
                _paths.SecurityRootDirectory);
            _aclGuard.EnsureServiceOnlyDirectory(
                _paths.RootDirectory);
            _aclGuard.EnsureServiceOnlyDirectory(_paths.RelayRootDirectory);
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
        private readonly DeviceIdentityStore _identityStore;
        private readonly Func<FileRelayTransactionStore> _openRelay;
        private FileAuthoritativeStateStore? _store;
        private FileRelayTransactionStore? _relay;
        private DeviceIdentity? _identity;

        public ServiceAuthoritativeStateBoundary(
            GuardDataPaths paths,
            IStateDataProtector protector,
            IServiceDataBoundaryGuard dataBoundaryGuard,
            DeviceIdentityStore identityStore,
            Func<FileRelayTransactionStore>? openRelay = null)
        {
            _paths = paths ?? throw new ArgumentNullException(nameof(paths));
            _protector = protector ?? throw new ArgumentNullException(nameof(protector));
            _dataBoundaryGuard = dataBoundaryGuard ??
                throw new ArgumentNullException(nameof(dataBoundaryGuard));
            _identityStore = identityStore ?? throw new ArgumentNullException(nameof(identityStore));
            _openRelay = openRelay ?? (() => new FileRelayTransactionStore(_paths.RelayStateFile,
                new LocalSystemDpapiDataProtector(FileRelayTransactionStore.StateDataProtectionPurpose),
                new ProtectedFileStateVersionJournal(_paths.RelayJournalFile,
                    new LocalSystemDpapiDataProtector(FileRelayTransactionStore.JournalDataProtectionPurpose))));
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
                var store = new FileAuthoritativeStateStore(
                    _paths.StateFile,
                    _protector,
                    journal);
                FileRelayTransactionStore? relay = null;
                try
                {
                    relay = _openRelay();
                    _dataBoundaryGuard.DemandReady();
                    cancellationToken.ThrowIfCancellationRequested();
                    _store = store;
                    _relay = relay;
                }
                catch
                {
                    relay?.Dispose();
                    store.Dispose();
                    throw;
                }
            }

            return Task.CompletedTask;
        }

        internal bool IsAcquired
        {
            get
            {
                lock (_sync)
                {
                    return _store != null && _relay != null;
                }
            }
        }

        public async Task<DeviceSecurityState> LoadAsync(
            CancellationToken cancellationToken)
        {
            _dataBoundaryGuard.DemandReady();
            var store = GetAcquiredStore();
            while (true)
            {
                var state = await store.LoadAsync(cancellationToken).ConfigureAwait(false);
                // The same owner -> relay lock order as native commits; no mixed owner/history snapshot.
                if (await store.TryWithCurrentStateAsync(state.Version, async (owner, token) =>
                {
                    RequireRelayMatches(owner, await RelayTransactions.LoadAsync(token).ConfigureAwait(false));
                    lock (_sync)
                    {
                        if (!ReferenceEquals(_store, store)) throw new InvalidOperationException("Service boundary changed.");
                        _identity ??= _identityStore.Load();
                        _identity.RequireMatches(owner);
                    }
                    _dataBoundaryGuard.DemandReady();
                    token.ThrowIfCancellationRequested();
                    return true;
                }, cancellationToken).ConfigureAwait(false)) return state;
                // A concurrent owner commit is not corruption: reload under the caller's cancellation budget.
            }
        }

        internal DeviceIdentity Identity
        {
            get { lock (_sync) return _identity ?? throw new InvalidOperationException("Device identity is not loaded."); }
        }

        internal FileAuthoritativeStateStore NativeEnrollmentStore => GetAcquiredStore();
        internal FileRelayTransactionStore RelayTransactions
        {
            get { lock (_sync) return _relay ?? throw new InvalidOperationException("Relay writer lease is not acquired."); }
        }

        internal async Task<DeviceSecurityState> LoadPristineAsync(CancellationToken cancellationToken)
        {
            var state = await LoadAsync(cancellationToken).ConfigureAwait(false);
            if (state.Version != 0 || state.IsProvisioned || state.SetupChallenge != null ||
                state.Enrollment != null || state.ChildAccountSid != null)
                throw new InvalidOperationException("Device provisioning requires pristine initial state.");
            return state;
        }

        // Public bootstrap request for the trusted off-PC operator, NOT a QR/session/ownership proof.
        // The installer must authenticate the service endpoint before presenting/exporting this response.
        internal async Task<byte[]> ExportDeviceProvisioningAsync(EnrollmentDeploymentTrust trust, CancellationToken cancellationToken)
        {
            _dataBoundaryGuard.DemandReady();
            await LoadPristineAsync(cancellationToken).ConfigureAwait(false);
            var identity = Identity;
            var payload = JsonSerializer.SerializeToUtf8Bytes(new
            {
                version = 1,
                relayOrigin = trust.Origin.GetLeftPart(UriPartial.Authority),
                deviceId = identity.DeviceId,
                signingKeyId = identity.SigningKeyId,
                signingPublicKeySpki = Convert.ToBase64String(identity.Signing.ExportSubjectPublicKeyInfo()),
                encryptionKeyId = identity.EncryptionKeyId,
                encryptionPublicKeySpki = Convert.ToBase64String(identity.Encryption.ExportSubjectPublicKeyInfo()),
                deviceEpoch = 1,
                authorityEpoch = 1
            });
            if (payload.Length > 2048) throw new InvalidOperationException("Device provisioning response size.");
            _dataBoundaryGuard.DemandReady();
            cancellationToken.ThrowIfCancellationRequested();
            return payload;
        }

        public async Task InitializeNewAsync(
            CancellationToken cancellationToken)
        {
            var store = GetAcquiredStore();
            using var identity = await _identityStore.InitializeOrResumeNewAsync(cancellationToken).ConfigureAwait(false);
            var initial = new DeviceSecurityState(identity.DeviceId, 0, 0, 0);
            var relay = RelayTransactions;
            if (File.Exists(_paths.RelayStateFile))
            {
                // Explicit bootstrap may resume only the exact untouched queue after keys were persisted.
                if (File.Exists(_paths.RelayStateBackupFile)) throw new InvalidDataException("Relay bootstrap has transaction history.");
                RequireRelayMatches(initial, await relay.LoadAsync(cancellationToken).ConfigureAwait(false));
            }
            else
                await relay.InitializeAsync(new RelayTransactionState(identity.DeviceId, 0, 1, 1, 0, 0, 0, 0), cancellationToken).ConfigureAwait(false);
            _dataBoundaryGuard.DemandReady();
            await store.InitializeAsync(initial, cancellationToken).ConfigureAwait(false);
            _dataBoundaryGuard.DemandReady();
        }

        private static void RequireRelayMatches(DeviceSecurityState owner, RelayTransactionState relay)
        {
            if (relay.DeviceId != owner.DeviceId || relay.DeviceEpoch != (owner.Enrollment?.Offer.DeviceEpoch ?? 1) ||
                relay.AuthorityEpoch != (owner.Enrollment?.Offer.AuthorityEpoch ?? 1))
                throw new InvalidDataException("Relay history does not match the device enrollment.");
            if (relay.Version == 0)
            {
                if (relay.CommittedInboundCursor != 0 || relay.HighestOutboundCursor != 0 || relay.AcknowledgedOutboundCursor != 0 ||
                    relay.PolicyRevision != 0 || relay.ReplayFloors.Count != 0 || relay.TrackedRequests.Count != 0 ||
                    relay.PolicyLedger.Count != 0 || relay.ReconcileIntents.Count != 0 || relay.SignedReceipts.Count != 0 ||
                    relay.Outbox.Count != 0 || relay.RecipientOutboundCursors.Count != 0)
                    throw new InvalidDataException("Initial relay history is not empty.");
            }
            else if (!owner.IsProvisioned || owner.Enrollment is not { Confirmed: true, PhoneKeyConfirmed: true })
                throw new InvalidDataException("Relay history requires a confirmed native owner.");
        }

        public Task<bool> TryCommitAsync(
            long expectedVersion,
            DeviceSecurityState nextState,
            CancellationToken cancellationToken)
        {
            Identity.RequireMatches(nextState);
            return GetAcquiredStore().TryCommitAsync(
                expectedVersion,
                nextState,
                cancellationToken);
        }

        public Task ImportDeviceRelayProfileAsync(CancellationToken cancellationToken) =>
            new DeviceRelayConfigurationStore(_paths,
                new LocalSystemDpapiDataProtector(DeviceRelayConfigurationStore.Purpose), _dataBoundaryGuard)
            .ImportStagedAsync(EnrollmentDeploymentTrust.FromServiceAssembly(), this,
                TimeProvider.System.GetUtcNow(), cancellationToken);

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }

        public void Dispose()
        {
            FileAuthoritativeStateStore? store;
            FileRelayTransactionStore? relay;
            DeviceIdentity? identity;
            lock (_sync)
            {
                store = _store;
                relay = _relay;
                identity = _identity;
                _store = null;
                _relay = null;
                _identity = null;
            }
            // Hosted workers and IPC drain first; keep keys alive until in-flight store operations finish.
            store?.Dispose();
            relay?.Dispose();
            identity?.Dispose();
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
