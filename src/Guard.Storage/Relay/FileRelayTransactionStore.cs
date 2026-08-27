using System;
using System.Collections.Concurrent;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Guard.Application.Relay;
using Guard.Domain.Relay;

namespace Guard.Storage.Relay
{
    /// <summary>
    /// DPAPI-ready, single-writer, versioned CAS store for the relay aggregate.
    /// State and journal must be constructed with the two distinct purposes
    /// below. The journal detects state-file rollback while intact; restoring
    /// both files offline still requires the future TPM/remote witness gate.
    /// WP1 accepts only the explicit publish, approval, and cumulative-ack
    /// transitions; enrollment, epoch rotation, and reconciliation completion
    /// must add their own exact transition validators in later work packets.
    /// </summary>
    public sealed class FileRelayTransactionStore :
        IRelayTransactionStore,
        IDisposable
    {
        public const string StateDataProtectionPurpose =
            "guard-v2-relay-transaction-state";
        public const string JournalDataProtectionPurpose =
            "guard-v2-relay-transaction-journal";

        private static readonly byte[] EnvelopeMagic =
        {
            0x47, 0x52, 0x44, 0x52, 0x4C, 0x59, 0x45, 0x56
        };

        private static readonly byte[] StoredRecordMagic =
        {
            0x47, 0x52, 0x44, 0x52, 0x4C, 0x59, 0x52, 0x43
        };

        private static readonly ConcurrentDictionary<string, SemaphoreSlim>
            ProcessLocks = new ConcurrentDictionary<string, SemaphoreSlim>(
                StringComparer.OrdinalIgnoreCase);

        private const int EnvelopeVersion = 1;
        private const int StoredRecordVersion = 1;
        private const int DigestBytes = 32;
        private const int EnvelopeHeaderBytes = 8 + 4 + 8 + 4 + DigestBytes;
        private const int StoredRecordHeaderBytes =
            8 + 4 + StateVersionWatermark.CommitmentBytes + 4;
        private const int MaximumStoredRecordPlaintextBytes =
            StoredRecordHeaderBytes + RelayStateCodec.MaximumPayloadBytes;
        private const int MaximumProtectedPayloadBytes = 896 * 1024;
        private const int MaximumStateFileBytes =
            EnvelopeHeaderBytes + MaximumProtectedPayloadBytes;

        private readonly string _stateFilePath;
        private readonly string _backupFilePath;
        private readonly string _writerLockFilePath;
        private readonly IStateDataProtector _protector;
        private readonly IStateVersionWatermark _watermark;
        private readonly SemaphoreSlim _processLock;
        private FileStream? _writerLease;
        private int _disposed;

        public FileRelayTransactionStore(
            string stateFilePath,
            IStateDataProtector stateProtector,
            IStateVersionWatermark journal)
        {
            if (string.IsNullOrWhiteSpace(stateFilePath))
            {
                throw new ArgumentException(
                    "A relay transaction state file path is required.",
                    nameof(stateFilePath));
            }

            _protector = stateProtector ??
                throw new ArgumentNullException(nameof(stateProtector));
            _watermark = journal ?? throw new ArgumentNullException(nameof(journal));
            _stateFilePath = Path.GetFullPath(stateFilePath);
            var directory = Path.GetDirectoryName(_stateFilePath);
            if (string.IsNullOrEmpty(directory))
            {
                throw new ArgumentException(
                    "The relay state file must have a parent directory.",
                    nameof(stateFilePath));
            }

            _backupFilePath = _stateFilePath + ".bak";
            _writerLockFilePath = _stateFilePath + ".writer.lock";
            _processLock = ProcessLocks.GetOrAdd(
                _stateFilePath,
                _ => new SemaphoreSlim(1, 1));
            Directory.CreateDirectory(directory);
            try
            {
                _writerLease = new FileStream(
                    _writerLockFilePath,
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    FileShare.None,
                    bufferSize: 1,
                    options: FileOptions.WriteThrough);
            }
            catch (IOException exception)
            {
                throw new IOException(
                    "Another process or service instance already owns the relay-state writer lease.",
                    exception);
            }
        }

        public string StateFilePath => _stateFilePath;

        public string BackupFilePath => _backupFilePath;

        public string WriterLockFilePath => _writerLockFilePath;

        public async Task InitializeAsync(
            RelayTransactionState initialState,
            CancellationToken cancellationToken)
        {
            if (initialState == null)
            {
                throw new ArgumentNullException(nameof(initialState));
            }

            if (initialState.Version != 0)
            {
                throw new ArgumentException(
                    "Initial relay transaction state must have version zero.",
                    nameof(initialState));
            }

            if (initialState.CommittedInboundCursor != 0 ||
                initialState.HighestOutboundCursor != 0 ||
                initialState.AcknowledgedOutboundCursor != 0 ||
                initialState.PolicyRevision != 0 ||
                initialState.ReplayFloors.Count != 0 ||
                initialState.TrackedRequests.Count != 0 ||
                initialState.PolicyLedger.Count != 0 ||
                initialState.ReconcileIntents.Count != 0 ||
                initialState.SignedReceipts.Count != 0 ||
                initialState.Outbox.Count != 0)
            {
                throw new ArgumentException(
                    "Initial relay state must contain no transaction history or queued frames.",
                    nameof(initialState));
            }

            ThrowIfDisposed();
            await _processLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ThrowIfDisposed();
                cancellationToken.ThrowIfCancellationRequested();
                var watermark = await _watermark
                    .GetCurrentAsync(cancellationToken)
                    .ConfigureAwait(false);
                if (File.Exists(_stateFilePath) ||
                    File.Exists(_backupFilePath) ||
                    watermark != null)
                {
                    throw new InvalidOperationException(
                        "Relay state initialization requires absent state, backup, and journal.");
                }

                var initialPreviousCommitment =
                    new byte[StateVersionWatermark.CommitmentBytes];
                var envelope = CreateEnvelope(
                    initialState,
                    initialPreviousCommitment);
                await WriteNewStateFileAsync(envelope, cancellationToken)
                    .ConfigureAwait(false);
                var persisted = await VerifyPublishedStateAsync(
                    initialState,
                    initialPreviousCommitment).ConfigureAwait(false);
                try
                {
                    await _watermark.AdvanceToAsync(
                        initialState.Version,
                        persisted.StateCommitment,
                        CancellationToken.None).ConfigureAwait(false);
                }
                catch (Exception exception)
                {
                    throw new IOException(
                        "The initial relay state was committed, but its journal could not be persisted.",
                        exception);
                }
            }
            finally
            {
                _processLock.Release();
            }
        }

        public async Task<RelayTransactionState> LoadAsync(
            CancellationToken cancellationToken)
        {
            ThrowIfDisposed();
            await _processLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ThrowIfDisposed();
                var persisted = await LoadCoreAsync(cancellationToken)
                    .ConfigureAwait(false);
                return persisted.State;
            }
            finally
            {
                _processLock.Release();
            }
        }

        public async Task<bool> TryCommitAsync(
            long expectedVersion,
            RelayTransactionState nextState,
            CancellationToken cancellationToken)
        {
            if (expectedVersion < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(expectedVersion));
            }

            if (nextState == null)
            {
                throw new ArgumentNullException(nameof(nextState));
            }

            if (expectedVersion == long.MaxValue ||
                nextState.Version != expectedVersion + 1)
            {
                throw new ArgumentException(
                    "A relay state commit must advance the expected version by exactly one.",
                    nameof(nextState));
            }

            ThrowIfDisposed();
            await _processLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ThrowIfDisposed();
                var current = await LoadCoreAsync(cancellationToken)
                    .ConfigureAwait(false);
                if (current.State.Version != expectedVersion)
                {
                    return false;
                }

                ValidateSafeSuccessor(current.State, nextState);
                var envelope = CreateEnvelope(
                    nextState,
                    current.StateCommitment);
                await ReplaceStateFileAsync(envelope, cancellationToken)
                    .ConfigureAwait(false);
                var persisted = await VerifyPublishedStateAsync(
                    nextState,
                    current.StateCommitment).ConfigureAwait(false);
                try
                {
                    await _watermark.AdvanceToAsync(
                        nextState.Version,
                        persisted.StateCommitment,
                        CancellationToken.None).ConfigureAwait(false);
                }
                catch (Exception exception)
                {
                    throw new IOException(
                        "The relay state was committed, but its journal could not be advanced.",
                        exception);
                }

                return true;
            }
            finally
            {
                _processLock.Release();
            }
        }

        private async Task<PersistedRelayState> LoadCoreAsync(
            CancellationToken cancellationToken)
        {
            var persisted = await ReadStateFileAsync(cancellationToken)
                .ConfigureAwait(false);
            var watermark = await _watermark
                .GetCurrentAsync(cancellationToken)
                .ConfigureAwait(false);
            if (watermark == null)
            {
                throw new StateStoreCorruptionException(
                    "The relay transaction state journal is missing.");
            }

            if (persisted.State.Version < watermark.Version)
            {
                throw new StateRollbackDetectedException(
                    persisted.State.Version,
                    watermark.Version);
            }

            var watermarkCommitment = watermark.GetStateCommitmentCopy();
            if (persisted.State.Version == watermark.Version)
            {
                if (!CryptographicOperations.FixedTimeEquals(
                    persisted.StateCommitment,
                    watermarkCommitment))
                {
                    throw new StateStoreCorruptionException(
                        "The relay state does not match the journal commitment.");
                }

                return persisted;
            }

            if (watermark.Version == long.MaxValue ||
                persisted.State.Version != watermark.Version + 1 ||
                !CryptographicOperations.FixedTimeEquals(
                    persisted.PreviousStateCommitment,
                    watermarkCommitment))
            {
                throw new StateStoreCorruptionException(
                    "The relay state is not the direct successor of its journal head.");
            }

            await _watermark.AdvanceToAsync(
                persisted.State.Version,
                persisted.StateCommitment,
                CancellationToken.None).ConfigureAwait(false);
            return persisted;
        }

        private async Task<PersistedRelayState> ReadStateFileAsync(
            CancellationToken cancellationToken)
        {
            if (!File.Exists(_stateFilePath))
            {
                throw new FileNotFoundException(
                    "The relay transaction state file does not exist. Explicit initialization is required.",
                    _stateFilePath);
            }

            byte[] envelope;
            using (var stream = new FileStream(
                _stateFilePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 4096,
                options: FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                if (stream.Length <= EnvelopeHeaderBytes ||
                    stream.Length > MaximumStateFileBytes)
                {
                    throw new StateStoreCorruptionException(
                        "The relay state envelope is empty or oversized.");
                }

                envelope = new byte[checked((int)stream.Length)];
                await stream.ReadExactlyAsync(envelope, cancellationToken)
                    .ConfigureAwait(false);
            }

            return DecodeEnvelope(envelope);
        }

        private async Task<PersistedRelayState> VerifyPublishedStateAsync(
            RelayTransactionState expectedState,
            byte[] expectedPreviousCommitment)
        {
            var persisted = await ReadStateFileAsync(CancellationToken.None)
                .ConfigureAwait(false);
            var expectedPayload = RelayStateCodec.Encode(expectedState);
            var persistedPayload = RelayStateCodec.Encode(persisted.State);
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(
                    expectedPayload,
                    persistedPayload) ||
                    !CryptographicOperations.FixedTimeEquals(
                        expectedPreviousCommitment,
                        persisted.PreviousStateCommitment))
                {
                    throw new StateStoreCorruptionException(
                        "The published relay state does not match the committed aggregate.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(expectedPayload);
                CryptographicOperations.ZeroMemory(persistedPayload);
            }

            return persisted;
        }

        private byte[] CreateEnvelope(
            RelayTransactionState state,
            byte[] previousStateCommitment)
        {
            if (previousStateCommitment == null ||
                previousStateCommitment.Length !=
                    StateVersionWatermark.CommitmentBytes)
            {
                throw new ArgumentException(
                    "A complete previous relay-state commitment is required.",
                    nameof(previousStateCommitment));
            }

            var statePayload = RelayStateCodec.Encode(state);
            byte[] plaintext;
            try
            {
                using (var stream = new MemoryStream(
                    StoredRecordHeaderBytes + statePayload.Length))
                {
                    stream.Write(
                        StoredRecordMagic,
                        0,
                        StoredRecordMagic.Length);
                    WriteInt32(stream, StoredRecordVersion);
                    stream.Write(
                        previousStateCommitment,
                        0,
                        previousStateCommitment.Length);
                    WriteInt32(stream, statePayload.Length);
                    stream.Write(statePayload, 0, statePayload.Length);
                    plaintext = stream.ToArray();
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(statePayload);
            }

            byte[] protectedPayload;
            try
            {
                var result = _protector.Protect(plaintext);
                protectedPayload = ReferenceEquals(result, plaintext)
                    ? (byte[])result.Clone()
                    : result;
            }
            catch (Exception exception) when (
                exception is CryptographicException ||
                exception is ArgumentException ||
                exception is InvalidOperationException)
            {
                throw new IOException(
                    "The relay transaction state could not be protected.",
                    exception);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }

            if (protectedPayload == null ||
                protectedPayload.Length == 0 ||
                protectedPayload.Length > MaximumProtectedPayloadBytes)
            {
                throw new IOException(
                    "The relay state protector returned an empty or oversized payload.");
            }

            var digest = SHA256.HashData(protectedPayload);
            using (var stream = new MemoryStream(
                EnvelopeHeaderBytes + protectedPayload.Length))
            {
                stream.Write(EnvelopeMagic, 0, EnvelopeMagic.Length);
                WriteInt32(stream, EnvelopeVersion);
                WriteInt64(stream, state.Version);
                WriteInt32(stream, protectedPayload.Length);
                stream.Write(digest, 0, digest.Length);
                stream.Write(
                    protectedPayload,
                    0,
                    protectedPayload.Length);
                return stream.ToArray();
            }
        }

        private PersistedRelayState DecodeEnvelope(byte[] envelope)
        {
            try
            {
                using (var stream = new MemoryStream(
                    envelope,
                    writable: false))
                {
                    RequireBytes(stream, EnvelopeMagic, "envelope magic");
                    if (ReadInt32(stream) != EnvelopeVersion)
                    {
                        throw new StateStoreCorruptionException(
                            "The relay state envelope version is unsupported.");
                    }

                    var declaredStateVersion = ReadInt64(stream);
                    if (declaredStateVersion < 0)
                    {
                        throw new StateStoreCorruptionException(
                            "The relay state envelope version marker is invalid.");
                    }

                    var protectedLength = ReadInt32(stream);
                    if (protectedLength <= 0 ||
                        protectedLength > MaximumProtectedPayloadBytes ||
                        protectedLength !=
                            stream.Length - stream.Position - DigestBytes)
                    {
                        throw new StateStoreCorruptionException(
                            "The relay protected-payload length is invalid.");
                    }

                    var expectedDigest = ReadExact(stream, DigestBytes);
                    var protectedPayload = ReadExact(stream, protectedLength);
                    var actualDigest = SHA256.HashData(protectedPayload);
                    if (!CryptographicOperations.FixedTimeEquals(
                        expectedDigest,
                        actualDigest))
                    {
                        throw new StateStoreCorruptionException(
                            "The relay state envelope digest is invalid.");
                    }

                    var plaintext = UnprotectStoredRecord(protectedPayload);
                    try
                    {
                        using (var recordStream = new MemoryStream(
                            plaintext,
                            writable: false))
                        {
                            RequireBytes(
                                recordStream,
                                StoredRecordMagic,
                                "protected record magic");
                            if (ReadInt32(recordStream) != StoredRecordVersion)
                            {
                                throw new StateStoreCorruptionException(
                                    "The protected relay record version is unsupported.");
                            }

                            var previousCommitment = ReadExact(
                                recordStream,
                                StateVersionWatermark.CommitmentBytes);
                            var stateLength = ReadInt32(recordStream);
                            if (stateLength <= 0 ||
                                stateLength > RelayStateCodec.MaximumPayloadBytes ||
                                stateLength !=
                                    recordStream.Length - recordStream.Position)
                            {
                                throw new StateStoreCorruptionException(
                                    "The protected relay-state length is invalid.");
                            }

                            var canonicalState = ReadExact(
                                recordStream,
                                stateLength);
                            RelayTransactionState state;
                            try
                            {
                                state = RelayStateCodec.Decode(canonicalState);
                            }
                            finally
                            {
                                CryptographicOperations.ZeroMemory(
                                    canonicalState);
                            }

                            if (state.Version != declaredStateVersion)
                            {
                                throw new StateStoreCorruptionException(
                                    "The protected relay-state version does not match its envelope.");
                            }

                            var commitment = SHA256.HashData(plaintext);
                            return new PersistedRelayState(
                                state,
                                previousCommitment,
                                commitment);
                        }
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(plaintext);
                    }
                }
            }
            catch (StateStoreCorruptionException)
            {
                throw;
            }
            catch (Exception exception) when (
                exception is EndOfStreamException ||
                exception is OverflowException)
            {
                throw new StateStoreCorruptionException(
                    "The relay state envelope is malformed.",
                    exception);
            }
        }

        private byte[] UnprotectStoredRecord(byte[] protectedPayload)
        {
            byte[] plaintext;
            try
            {
                plaintext = _protector.Unprotect(protectedPayload);
            }
            catch (Exception exception) when (
                exception is CryptographicException ||
                exception is ArgumentException ||
                exception is InvalidOperationException)
            {
                throw new StateStoreCorruptionException(
                    "The relay state could not be authenticated or decrypted.",
                    exception);
            }

            if (plaintext == null ||
                plaintext.Length <= StoredRecordHeaderBytes ||
                plaintext.Length > MaximumStoredRecordPlaintextBytes)
            {
                if (plaintext != null)
                {
                    CryptographicOperations.ZeroMemory(plaintext);
                }

                throw new StateStoreCorruptionException(
                    "The unprotected relay state record is empty or oversized.");
            }

            return plaintext;
        }

        private async Task WriteNewStateFileAsync(
            byte[] envelope,
            CancellationToken cancellationToken)
        {
            var temporaryPath = CreateTemporaryPath();
            try
            {
                await WriteTemporaryFileAsync(
                    temporaryPath,
                    envelope,
                    cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                File.Move(temporaryPath, _stateFilePath);
            }
            finally
            {
                TryDeleteTemporaryFile(temporaryPath);
            }
        }

        private async Task ReplaceStateFileAsync(
            byte[] envelope,
            CancellationToken cancellationToken)
        {
            var temporaryPath = CreateTemporaryPath();
            try
            {
                await WriteTemporaryFileAsync(
                    temporaryPath,
                    envelope,
                    cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                File.Replace(
                    temporaryPath,
                    _stateFilePath,
                    _backupFilePath,
                    ignoreMetadataErrors: false);
            }
            finally
            {
                TryDeleteTemporaryFile(temporaryPath);
            }
        }

        private static async Task WriteTemporaryFileAsync(
            string temporaryPath,
            byte[] envelope,
            CancellationToken cancellationToken)
        {
            using (var stream = new FileStream(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 4096,
                options: FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(envelope, cancellationToken)
                    .ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken)
                    .ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }
        }

        private static void ValidateSafeSuccessor(
            RelayTransactionState current,
            RelayTransactionState next)
        {
            if (!string.Equals(
                current.DeviceId,
                next.DeviceId,
                StringComparison.Ordinal))
            {
                throw new ArgumentException(
                    "A relay commit cannot replace the device identity.",
                    nameof(next));
            }

            if (next.DeviceEpoch < current.DeviceEpoch ||
                next.AuthorityEpoch < current.AuthorityEpoch ||
                next.CommittedInboundCursor < current.CommittedInboundCursor ||
                next.HighestOutboundCursor < current.HighestOutboundCursor ||
                next.AcknowledgedOutboundCursor <
                    current.AcknowledgedOutboundCursor ||
                next.PolicyRevision < current.PolicyRevision)
            {
                throw new ArgumentException(
                    "A relay commit cannot decrease durable epochs, cursors, or policy markers.",
                    nameof(next));
            }

            PreserveReplayFloors(current, next);
            PreserveResolvedRequests(current, next);
            PreservePolicyLedger(current, next);
            PreserveReconcileIntents(current, next);
            PreserveSignedReceipts(current, next);
            PreserveUnacknowledgedOutbox(current, next);
            if (!MatchesKnownAtomicTransition(current, next))
            {
                throw new ArgumentException(
                    "A relay commit must be one complete publish, approval, or ack transaction.",
                    nameof(next));
            }
        }

        private static bool MatchesKnownAtomicTransition(
            RelayTransactionState current,
            RelayTransactionState next)
        {
            if (current.DeviceEpoch != next.DeviceEpoch ||
                current.AuthorityEpoch != next.AuthorityEpoch)
            {
                return false;
            }

            try
            {
                if (next.AcknowledgedOutboundCursor >
                    current.AcknowledgedOutboundCursor)
                {
                    return SameState(
                        current.WithAcknowledgedOutboundCursor(
                            next.AcknowledgedOutboundCursor),
                        next);
                }

                if (next.CommittedInboundCursor ==
                    current.CommittedInboundCursor)
                {
                    if (next.TrackedRequests.Count !=
                            current.TrackedRequests.Count + 1 ||
                        next.Outbox.Count != current.Outbox.Count + 1)
                    {
                        return false;
                    }

                    return SameState(
                        current.WithPublishedRequest(
                            next.TrackedRequests[
                                next.TrackedRequests.Count - 1],
                            next.Outbox[next.Outbox.Count - 1]),
                        next);
                }

                if (current.CommittedInboundCursor == long.MaxValue ||
                    next.CommittedInboundCursor !=
                        current.CommittedInboundCursor + 1 ||
                    next.TrackedRequests.Count !=
                        current.TrackedRequests.Count ||
                    next.SignedReceipts.Count !=
                        current.SignedReceipts.Count + 1 ||
                    next.Outbox.Count != current.Outbox.Count + 1)
                {
                    return false;
                }

                var receipt =
                    next.SignedReceipts[next.SignedReceipts.Count - 1];
                var trackedRequest = FindTrackedRequest(
                    current,
                    receipt.RequestId);
                if (trackedRequest == null)
                {
                    return false;
                }

                var replayFloor = FindAdvancedReplayFloor(current, next);
                if (replayFloor == null)
                {
                    return false;
                }

                var disposition = RelayApprovalDisposition.AlreadyResolved;
                var changedRequestCount = 0;
                for (var index = 0;
                    index < current.TrackedRequests.Count;
                    index++)
                {
                    if (!SameTrackedRequest(
                        current.TrackedRequests[index],
                        next.TrackedRequests[index]))
                    {
                        changedRequestCount++;
                        if (!string.Equals(
                                current.TrackedRequests[index].RequestId,
                                receipt.RequestId,
                                StringComparison.Ordinal) ||
                            !current.TrackedRequests[index].IsPending)
                        {
                            return false;
                        }

                        disposition =
                            next.TrackedRequests[index].Resolution ==
                                RelayRequestResolution.Allowed
                            ? RelayApprovalDisposition.Allowed
                            : RelayApprovalDisposition.Denied;
                    }
                }

                if (changedRequestCount > 1 ||
                    (changedRequestCount == 0 && trackedRequest.IsPending))
                {
                    return false;
                }

                RelayPolicyLedgerEntry? policyEntry = null;
                if (next.PolicyLedger.Count ==
                    current.PolicyLedger.Count + 1)
                {
                    policyEntry =
                        next.PolicyLedger[next.PolicyLedger.Count - 1];
                }
                else if (next.PolicyLedger.Count != current.PolicyLedger.Count)
                {
                    return false;
                }

                RelayReconcileIntent? reconcileIntent = null;
                if (next.ReconcileIntents.Count ==
                    current.ReconcileIntents.Count + 1)
                {
                    reconcileIntent =
                        next.ReconcileIntents[
                            next.ReconcileIntents.Count - 1];
                }
                else if (next.ReconcileIntents.Count !=
                    current.ReconcileIntents.Count)
                {
                    return false;
                }

                var transaction = new RelayApprovalTransaction(
                    next.CommittedInboundCursor,
                    trackedRequest.RequestId,
                    trackedRequest.RequestRevision,
                    trackedRequest.GetSnapshotHashCopy(),
                    disposition,
                    replayFloor,
                    policyEntry,
                    reconcileIntent,
                    receipt,
                    next.Outbox[next.Outbox.Count - 1]);
                return SameState(
                    current.WithCommittedApproval(transaction),
                    next);
            }
            catch (Exception exception) when (
                exception is ArgumentException ||
                exception is InvalidOperationException ||
                exception is OverflowException)
            {
                return false;
            }
        }

        private static RelayTrackedRequest? FindTrackedRequest(
            RelayTransactionState state,
            string requestId)
        {
            for (var index = 0; index < state.TrackedRequests.Count; index++)
            {
                if (string.Equals(
                    state.TrackedRequests[index].RequestId,
                    requestId,
                    StringComparison.Ordinal))
                {
                    return state.TrackedRequests[index];
                }
            }

            return null;
        }

        private static RelayReplayFloor? FindAdvancedReplayFloor(
            RelayTransactionState current,
            RelayTransactionState next)
        {
            RelayReplayFloor? advanced = null;
            for (var index = 0; index < next.ReplayFloors.Count; index++)
            {
                var candidate = next.ReplayFloors[index];
                RelayReplayFloor existing;
                var existed = current.TryGetReplayFloor(
                    candidate.AuthorityEpoch,
                    candidate.ApprovalKeyId,
                    out existing);
                if (existed && SameReplayFloor(existing, candidate))
                {
                    continue;
                }

                if (advanced != null)
                {
                    return null;
                }

                advanced = candidate;
            }

            var expectedCount = advanced == null
                ? current.ReplayFloors.Count
                : current.TryGetReplayFloor(
                    advanced.AuthorityEpoch,
                    advanced.ApprovalKeyId,
                    out _)
                    ? current.ReplayFloors.Count
                    : current.ReplayFloors.Count + 1;
            return next.ReplayFloors.Count == expectedCount
                ? advanced
                : null;
        }

        private static bool SameState(
            RelayTransactionState left,
            RelayTransactionState right)
        {
            var leftBytes = RelayStateCodec.Encode(left);
            var rightBytes = RelayStateCodec.Encode(right);
            try
            {
                return CryptographicOperations.FixedTimeEquals(
                    leftBytes,
                    rightBytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(leftBytes);
                CryptographicOperations.ZeroMemory(rightBytes);
            }
        }

        private static bool SameReplayFloor(
            RelayReplayFloor left,
            RelayReplayFloor right)
        {
            return left.AuthorityEpoch == right.AuthorityEpoch &&
                   string.Equals(
                       left.ApprovalKeyId,
                       right.ApprovalKeyId,
                       StringComparison.Ordinal) &&
                   left.HighestAcceptedSequence ==
                       right.HighestAcceptedSequence &&
                   string.Equals(
                       left.CommandId,
                       right.CommandId,
                       StringComparison.Ordinal) &&
                   CryptographicOperations.FixedTimeEquals(
                       left.GetApprovalHashCopy(),
                       right.GetApprovalHashCopy());
        }

        private static bool SameTrackedRequest(
            RelayTrackedRequest left,
            RelayTrackedRequest right)
        {
            return string.Equals(
                       left.RequestId,
                       right.RequestId,
                       StringComparison.Ordinal) &&
                   left.RequestRevision == right.RequestRevision &&
                   left.Resolution == right.Resolution &&
                   string.Equals(
                       left.ResolvedCommandId,
                       right.ResolvedCommandId,
                       StringComparison.Ordinal) &&
                   CryptographicOperations.FixedTimeEquals(
                       left.GetSnapshotHashCopy(),
                       right.GetSnapshotHashCopy()) &&
                   CryptographicOperations.FixedTimeEquals(
                       left.GetDecisionChallengeCopy(),
                       right.GetDecisionChallengeCopy()) &&
                   CryptographicOperations.FixedTimeEquals(
                       left.GetApprovalHashCopy(),
                       right.GetApprovalHashCopy());
        }

        private static void PreserveReplayFloors(
            RelayTransactionState current,
            RelayTransactionState next)
        {
            for (var index = 0; index < current.ReplayFloors.Count; index++)
            {
                var existing = current.ReplayFloors[index];
                RelayReplayFloor candidate;
                if (!next.TryGetReplayFloor(
                    existing.AuthorityEpoch,
                    existing.ApprovalKeyId,
                    out candidate) ||
                    candidate.HighestAcceptedSequence <
                        existing.HighestAcceptedSequence)
                {
                    throw new ArgumentException(
                        "A relay commit cannot remove or decrease a per-key replay floor.",
                        nameof(next));
                }
            }
        }

        private static void PreserveResolvedRequests(
            RelayTransactionState current,
            RelayTransactionState next)
        {
            for (var index = 0; index < current.TrackedRequests.Count; index++)
            {
                var existing = current.TrackedRequests[index];
                if (existing.IsPending)
                {
                    continue;
                }

                RelayTrackedRequest? candidate = null;
                for (var nextIndex = 0;
                    nextIndex < next.TrackedRequests.Count;
                    nextIndex++)
                {
                    if (string.Equals(
                        next.TrackedRequests[nextIndex].RequestId,
                        existing.RequestId,
                        StringComparison.Ordinal))
                    {
                        candidate = next.TrackedRequests[nextIndex];
                        break;
                    }
                }

                if (candidate == null ||
                    candidate.Resolution != existing.Resolution ||
                    !string.Equals(
                        candidate.ResolvedCommandId,
                        existing.ResolvedCommandId,
                        StringComparison.Ordinal) ||
                    !CryptographicOperations.FixedTimeEquals(
                        candidate.GetApprovalHashCopy(),
                        existing.GetApprovalHashCopy()))
                {
                    throw new ArgumentException(
                        "A relay commit cannot remove or rewrite a resolved request.",
                        nameof(next));
                }
            }
        }

        private static void PreservePolicyLedger(
            RelayTransactionState current,
            RelayTransactionState next)
        {
            if (next.PolicyLedger.Count < current.PolicyLedger.Count)
            {
                throw new ArgumentException(
                    "A relay commit cannot truncate the policy ledger.",
                    nameof(next));
            }

            for (var index = 0; index < current.PolicyLedger.Count; index++)
            {
                if (!SamePolicyEntry(
                    current.PolicyLedger[index],
                    next.PolicyLedger[index]))
                {
                    throw new ArgumentException(
                        "A relay commit cannot rewrite the policy ledger.",
                        nameof(next));
                }
            }
        }

        private static void PreserveReconcileIntents(
            RelayTransactionState current,
            RelayTransactionState next)
        {
            if (next.ReconcileIntents.Count < current.ReconcileIntents.Count)
            {
                throw new ArgumentException(
                    "A relay commit cannot remove a reconciliation intent.",
                    nameof(next));
            }

            for (var index = 0;
                index < current.ReconcileIntents.Count;
                index++)
            {
                var left = current.ReconcileIntents[index];
                var right = next.ReconcileIntents[index];
                if (!string.Equals(
                        left.IntentId,
                        right.IntentId,
                        StringComparison.Ordinal) ||
                    left.PolicyRevision != right.PolicyRevision ||
                    !string.Equals(
                        left.CommandId,
                        right.CommandId,
                        StringComparison.Ordinal) ||
                    !CryptographicOperations.FixedTimeEquals(
                        left.GetPolicyDigestCopy(),
                        right.GetPolicyDigestCopy()))
                {
                    throw new ArgumentException(
                        "A relay commit cannot rewrite a reconciliation intent.",
                        nameof(next));
                }
            }
        }

        private static void PreserveSignedReceipts(
            RelayTransactionState current,
            RelayTransactionState next)
        {
            if (next.SignedReceipts.Count < current.SignedReceipts.Count)
            {
                throw new ArgumentException(
                    "A relay commit cannot remove a signed receipt.",
                    nameof(next));
            }

            for (var index = 0; index < current.SignedReceipts.Count; index++)
            {
                if (!SameReceipt(
                    current.SignedReceipts[index],
                    next.SignedReceipts[index]))
                {
                    throw new ArgumentException(
                        "A relay commit cannot rewrite a signed receipt.",
                        nameof(next));
                }
            }
        }

        private static void PreserveUnacknowledgedOutbox(
            RelayTransactionState current,
            RelayTransactionState next)
        {
            for (var index = 0; index < current.Outbox.Count; index++)
            {
                var existing = current.Outbox[index];
                if (existing.OutboundCursor <= next.AcknowledgedOutboundCursor)
                {
                    continue;
                }

                RelayEncryptedOutboxItem? candidate = null;
                for (var nextIndex = 0; nextIndex < next.Outbox.Count; nextIndex++)
                {
                    if (next.Outbox[nextIndex].OutboundCursor ==
                        existing.OutboundCursor)
                    {
                        candidate = next.Outbox[nextIndex];
                        break;
                    }
                }

                if (candidate == null ||
                    !SameOutboxItem(existing, candidate))
                {
                    throw new ArgumentException(
                        "A relay commit cannot remove or rewrite an unacknowledged frame.",
                        nameof(next));
                }
            }
        }

        private static bool SamePolicyEntry(
            RelayPolicyLedgerEntry left,
            RelayPolicyLedgerEntry right)
        {
            return left.PolicyRevision == right.PolicyRevision &&
                   string.Equals(
                       left.RequestId,
                       right.RequestId,
                       StringComparison.Ordinal) &&
                   string.Equals(
                       left.CommandId,
                       right.CommandId,
                       StringComparison.Ordinal) &&
                   left.TargetKind == right.TargetKind &&
                   string.Equals(
                       left.CanonicalTargetIdentity,
                       right.CanonicalTargetIdentity,
                       StringComparison.Ordinal) &&
                   left.Decision == right.Decision &&
                   left.DurationMinutes == right.DurationMinutes &&
                   CryptographicOperations.FixedTimeEquals(
                       left.GetApprovalHashCopy(),
                       right.GetApprovalHashCopy());
        }

        private static bool SameReceipt(
            RelaySignedReceiptRecord left,
            RelaySignedReceiptRecord right)
        {
            return string.Equals(
                       left.DeviceId,
                       right.DeviceId,
                       StringComparison.Ordinal) &&
                   left.DeviceEpoch == right.DeviceEpoch &&
                   string.Equals(
                       left.CommandId,
                       right.CommandId,
                       StringComparison.Ordinal) &&
                   string.Equals(
                       left.RequestId,
                       right.RequestId,
                       StringComparison.Ordinal) &&
                   left.RequestRevision == right.RequestRevision &&
                   left.AuthorityEpoch == right.AuthorityEpoch &&
                   string.Equals(
                       left.ApprovalKeyId,
                       right.ApprovalKeyId,
                       StringComparison.Ordinal) &&
                   left.Sequence == right.Sequence &&
                   left.Status == right.Status &&
                   CryptographicOperations.FixedTimeEquals(
                       left.GetApprovalHashCopy(),
                       right.GetApprovalHashCopy()) &&
                   CryptographicOperations.FixedTimeEquals(
                       left.GetSignedReceiptCopy(),
                       right.GetSignedReceiptCopy());
        }

        private static bool SameOutboxItem(
            RelayEncryptedOutboxItem left,
            RelayEncryptedOutboxItem right)
        {
            return string.Equals(
                       left.FrameId,
                       right.FrameId,
                       StringComparison.Ordinal) &&
                   left.OutboundCursor == right.OutboundCursor &&
                   left.Kind == right.Kind &&
                   CryptographicOperations.FixedTimeEquals(
                       left.GetEncryptedFrameCopy(),
                       right.GetEncryptedFrameCopy());
        }

        private string CreateTemporaryPath()
        {
            return _stateFilePath + "." +
                Guid.NewGuid().ToString("N") +
                ".tmp";
        }

        private static void TryDeleteTemporaryFile(string path)
        {
            try
            {
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        private static byte[] ReadExact(Stream stream, int count)
        {
            if (count < 0 || count > stream.Length - stream.Position)
            {
                throw new EndOfStreamException();
            }

            var result = new byte[count];
            var offset = 0;
            while (offset < count)
            {
                var read = stream.Read(result, offset, count - offset);
                if (read <= 0)
                {
                    throw new EndOfStreamException();
                }

                offset += read;
            }

            return result;
        }

        private static void RequireBytes(
            Stream stream,
            byte[] expected,
            string fieldName)
        {
            var actual = ReadExact(stream, expected.Length);
            if (!CryptographicOperations.FixedTimeEquals(actual, expected))
            {
                throw new StateStoreCorruptionException(
                    "The relay " + fieldName + " is invalid.");
            }
        }

        private static int ReadInt32(Stream stream)
        {
            var bytes = ReadExact(stream, 4);
            return (bytes[0] << 24) |
                   (bytes[1] << 16) |
                   (bytes[2] << 8) |
                   bytes[3];
        }

        private static long ReadInt64(Stream stream)
        {
            var bytes = ReadExact(stream, 8);
            ulong value = ((ulong)bytes[0] << 56) |
                          ((ulong)bytes[1] << 48) |
                          ((ulong)bytes[2] << 40) |
                          ((ulong)bytes[3] << 32) |
                          ((ulong)bytes[4] << 24) |
                          ((ulong)bytes[5] << 16) |
                          ((ulong)bytes[6] << 8) |
                          bytes[7];
            return unchecked((long)value);
        }

        private static void WriteInt32(Stream stream, int value)
        {
            stream.WriteByte((byte)((value >> 24) & 0xFF));
            stream.WriteByte((byte)((value >> 16) & 0xFF));
            stream.WriteByte((byte)((value >> 8) & 0xFF));
            stream.WriteByte((byte)(value & 0xFF));
        }

        private static void WriteInt64(Stream stream, long value)
        {
            stream.WriteByte((byte)((value >> 56) & 0xFF));
            stream.WriteByte((byte)((value >> 48) & 0xFF));
            stream.WriteByte((byte)((value >> 40) & 0xFF));
            stream.WriteByte((byte)((value >> 32) & 0xFF));
            stream.WriteByte((byte)((value >> 24) & 0xFF));
            stream.WriteByte((byte)((value >> 16) & 0xFF));
            stream.WriteByte((byte)((value >> 8) & 0xFF));
            stream.WriteByte((byte)(value & 0xFF));
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            _processLock.Wait();
            try
            {
                var lease = Interlocked.Exchange(ref _writerLease, null);
                lease?.Dispose();
            }
            finally
            {
                _processLock.Release();
            }
        }

        private void ThrowIfDisposed()
        {
            if (Volatile.Read(ref _disposed) != 0)
            {
                throw new ObjectDisposedException(
                    nameof(FileRelayTransactionStore));
            }
        }

        private sealed class PersistedRelayState
        {
            public PersistedRelayState(
                RelayTransactionState state,
                byte[] previousStateCommitment,
                byte[] stateCommitment)
            {
                State = state ?? throw new ArgumentNullException(nameof(state));
                if (previousStateCommitment == null ||
                    previousStateCommitment.Length !=
                        StateVersionWatermark.CommitmentBytes)
                {
                    throw new ArgumentException(
                        "A complete previous relay-state commitment is required.",
                        nameof(previousStateCommitment));
                }

                if (stateCommitment == null ||
                    stateCommitment.Length !=
                        StateVersionWatermark.CommitmentBytes)
                {
                    throw new ArgumentException(
                        "A complete relay-state commitment is required.",
                        nameof(stateCommitment));
                }

                PreviousStateCommitment =
                    (byte[])previousStateCommitment.Clone();
                StateCommitment = (byte[])stateCommitment.Clone();
            }

            public RelayTransactionState State { get; }

            public byte[] PreviousStateCommitment { get; }

            public byte[] StateCommitment { get; }
        }
    }
}
