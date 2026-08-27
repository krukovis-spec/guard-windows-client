using System;
using System.Collections.Concurrent;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Guard.Application;
using Guard.Domain;

namespace Guard.Storage
{
    public sealed class FileAuthoritativeStateStore : IAuthoritativeStateStore, IDisposable
    {
        private static readonly byte[] EnvelopeMagic =
        {
            0x47, 0x52, 0x44, 0x56, 0x32, 0x53, 0x54, 0x52
        };

        private static readonly byte[] StoredRecordMagic =
        {
            0x47, 0x52, 0x44, 0x56, 0x32, 0x52, 0x45, 0x43
        };

        private static readonly ConcurrentDictionary<string, SemaphoreSlim> ProcessLocks =
            new ConcurrentDictionary<string, SemaphoreSlim>(StringComparer.OrdinalIgnoreCase);

        private const int EnvelopeVersion = 1;
        private const int StoredRecordVersion = 1;
        private const int DigestBytes = 32;
        private const int EnvelopeHeaderBytes = 8 + 4 + 8 + 4 + DigestBytes;
        private const int StoredRecordHeaderBytes =
            8 + 4 + StateVersionWatermark.CommitmentBytes + 4;
        private const int MaximumStoredRecordPlaintextBytes =
            StoredRecordHeaderBytes + CanonicalStateCodec.MaximumPayloadBytes;
        private const int MaximumProtectedPayloadBytes = 256 * 1024;
        private const int MaximumStateFileBytes = EnvelopeHeaderBytes + MaximumProtectedPayloadBytes;

        private readonly string _stateFilePath;
        private readonly string _backupFilePath;
        private readonly string _writerLockFilePath;
        private readonly IStateDataProtector _protector;
        private readonly IStateVersionWatermark _watermark;
        private readonly SemaphoreSlim _processLock;
        private FileStream? _writerLease;
        private int _disposed;

        public FileAuthoritativeStateStore(
            string stateFilePath,
            IStateDataProtector protector,
            IStateVersionWatermark watermark)
        {
            if (string.IsNullOrWhiteSpace(stateFilePath))
            {
                throw new ArgumentException("An authoritative state file path is required.", nameof(stateFilePath));
            }

            _protector = protector ?? throw new ArgumentNullException(nameof(protector));
            _watermark = watermark ?? throw new ArgumentNullException(nameof(watermark));
            _stateFilePath = Path.GetFullPath(stateFilePath);
            var directory = Path.GetDirectoryName(_stateFilePath);
            if (string.IsNullOrEmpty(directory))
            {
                throw new ArgumentException("The state file must have a parent directory.", nameof(stateFilePath));
            }

            _backupFilePath = _stateFilePath + ".bak";
            _writerLockFilePath = _stateFilePath + ".writer.lock";
            _processLock = ProcessLocks.GetOrAdd(_stateFilePath, _ => new SemaphoreSlim(1, 1));
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
                    "Another process or service instance already owns the authoritative-state writer lease.",
                    exception);
            }
        }

        public string StateFilePath => _stateFilePath;

        public string BackupFilePath => _backupFilePath;

        public string WriterLockFilePath => _writerLockFilePath;

        public async Task InitializeAsync(
            DeviceSecurityState initialState,
            CancellationToken cancellationToken)
        {
            if (initialState == null)
            {
                throw new ArgumentNullException(nameof(initialState));
            }

            if (initialState.Version != 0)
            {
                throw new ArgumentException("Initial authoritative state must have version zero.", nameof(initialState));
            }

            ThrowIfDisposed();
            await _processLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ThrowIfDisposed();
                cancellationToken.ThrowIfCancellationRequested();
                var watermark = await _watermark.GetCurrentAsync(cancellationToken).ConfigureAwait(false);
                if (File.Exists(_stateFilePath) ||
                    File.Exists(_backupFilePath) ||
                    watermark != null)
                {
                    throw new InvalidOperationException(
                        "Authoritative state initialization is allowed only when no state, backup, or watermark exists.");
                }

                var directory = Path.GetDirectoryName(_stateFilePath)!;
                Directory.CreateDirectory(directory);
                var initialPreviousCommitment =
                    new byte[StateVersionWatermark.CommitmentBytes];
                var envelope = CreateEnvelope(initialState, initialPreviousCommitment);
                await WriteNewStateFileAsync(envelope, cancellationToken).ConfigureAwait(false);
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
                        "The initial state was committed, but its monotonic watermark could not be persisted.",
                        exception);
                }
            }
            finally
            {
                _processLock.Release();
            }
        }

        public async Task<DeviceSecurityState> LoadAsync(CancellationToken cancellationToken)
        {
            ThrowIfDisposed();
            await _processLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ThrowIfDisposed();
                var persisted = await LoadCoreAsync(cancellationToken).ConfigureAwait(false);
                return persisted.State;
            }
            finally
            {
                _processLock.Release();
            }
        }

        public async Task<bool> TryCommitAsync(
            long expectedVersion,
            DeviceSecurityState nextState,
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

            if (expectedVersion == long.MaxValue || nextState.Version != expectedVersion + 1)
            {
                throw new ArgumentException(
                    "A committed state must advance the expected version by exactly one.",
                    nameof(nextState));
            }

            ThrowIfDisposed();
            await _processLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ThrowIfDisposed();
                var current = await LoadCoreAsync(cancellationToken).ConfigureAwait(false);
                if (current.State.Version != expectedVersion)
                {
                    return false;
                }

                if (!string.Equals(current.State.DeviceId, nextState.DeviceId, StringComparison.Ordinal))
                {
                    throw new ArgumentException(
                        "A commit cannot replace the authoritative device identity.",
                        nameof(nextState));
                }

                if (current.State.ChildAccountSid != null &&
                    !current.State.ChildAccountSid.Equals(nextState.ChildAccountSid))
                {
                    throw new ArgumentException(
                        "A commit cannot remove or replace the bound child account.",
                        nameof(nextState));
                }

                if (nextState.HighestAcceptedSequence < current.State.HighestAcceptedSequence ||
                    nextState.DesiredPolicyRevision < current.State.DesiredPolicyRevision)
                {
                    throw new ArgumentException(
                        "A commit cannot decrease durable replay or policy markers.",
                        nameof(nextState));
                }

                var envelope = CreateEnvelope(nextState, current.StateCommitment);
                await ReplaceStateFileAsync(envelope, cancellationToken).ConfigureAwait(false);
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
                        "The state was committed, but its monotonic watermark could not be advanced.",
                        exception);
                }

                return true;
            }
            finally
            {
                _processLock.Release();
            }
        }

        private async Task<PersistedStateRecord> LoadCoreAsync(CancellationToken cancellationToken)
        {
            var persisted = await ReadStateFileAsync(cancellationToken).ConfigureAwait(false);
            var watermark = await _watermark.GetCurrentAsync(cancellationToken).ConfigureAwait(false);
            if (watermark == null)
            {
                throw new StateStoreCorruptionException(
                    "The authoritative state watermark is missing.");
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
                        "The authoritative state does not match the journal commitment for its version.");
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
                    "The authoritative state is not the direct successor of the journal head.");
            }

            await _watermark.AdvanceToAsync(
                persisted.State.Version,
                persisted.StateCommitment,
                CancellationToken.None).ConfigureAwait(false);
            return persisted;
        }

        private async Task<PersistedStateRecord> ReadStateFileAsync(CancellationToken cancellationToken)
        {
            if (!File.Exists(_stateFilePath))
            {
                throw new FileNotFoundException(
                    "The authoritative state file does not exist. Explicit initialization is required.",
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
                if (stream.Length <= EnvelopeHeaderBytes || stream.Length > MaximumStateFileBytes)
                {
                    throw new StateStoreCorruptionException(
                        "The authoritative state envelope is empty or oversized.");
                }

                envelope = new byte[checked((int)stream.Length)];
                await stream.ReadExactlyAsync(envelope, cancellationToken).ConfigureAwait(false);
            }

            return DecodeEnvelope(envelope);
        }

        private async Task<PersistedStateRecord> VerifyPublishedStateAsync(
            DeviceSecurityState expectedState,
            byte[] expectedPreviousCommitment)
        {
            var persisted = await ReadStateFileAsync(CancellationToken.None).ConfigureAwait(false);
            var expectedPayload = CanonicalStateCodec.Encode(expectedState);
            var persistedPayload = CanonicalStateCodec.Encode(persisted.State);
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(expectedPayload, persistedPayload) ||
                    !CryptographicOperations.FixedTimeEquals(
                        expectedPreviousCommitment,
                        persisted.PreviousStateCommitment))
                {
                    throw new StateStoreCorruptionException(
                        "The published authoritative state does not match the committed state.");
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
            DeviceSecurityState state,
            byte[] previousStateCommitment)
        {
            if (previousStateCommitment == null ||
                previousStateCommitment.Length != StateVersionWatermark.CommitmentBytes)
            {
                throw new ArgumentException(
                    "A complete previous-state commitment is required.",
                    nameof(previousStateCommitment));
            }

            var statePayload = CanonicalStateCodec.Encode(state);
            byte[] plaintext;
            try
            {
                using (var stream = new MemoryStream(
                    StoredRecordHeaderBytes + statePayload.Length))
                {
                    stream.Write(StoredRecordMagic, 0, StoredRecordMagic.Length);
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
                throw new IOException("The authoritative state could not be protected.", exception);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }

            if (protectedPayload == null ||
                protectedPayload.Length == 0 ||
                protectedPayload.Length > MaximumProtectedPayloadBytes)
            {
                throw new IOException("The state protector returned an empty or oversized payload.");
            }

            byte[] digest;
            using (var sha256 = SHA256.Create())
            {
                digest = sha256.ComputeHash(protectedPayload);
            }

            using (var stream = new MemoryStream(EnvelopeHeaderBytes + protectedPayload.Length))
            {
                stream.Write(EnvelopeMagic, 0, EnvelopeMagic.Length);
                WriteInt32(stream, EnvelopeVersion);
                WriteInt64(stream, state.Version);
                WriteInt32(stream, protectedPayload.Length);
                stream.Write(digest, 0, digest.Length);
                stream.Write(protectedPayload, 0, protectedPayload.Length);
                return stream.ToArray();
            }
        }

        private PersistedStateRecord DecodeEnvelope(byte[] envelope)
        {
            try
            {
                using (var stream = new MemoryStream(envelope, writable: false))
                {
                    RequireBytes(stream, EnvelopeMagic, "state envelope magic");
                    if (ReadInt32(stream) != EnvelopeVersion)
                    {
                        throw new StateStoreCorruptionException(
                            "The authoritative state envelope version is unsupported.");
                    }

                    var declaredStateVersion = ReadInt64(stream);
                    if (declaredStateVersion < 0)
                    {
                        throw new StateStoreCorruptionException(
                            "The authoritative state envelope version marker is invalid.");
                    }

                    var protectedLength = ReadInt32(stream);
                    if (protectedLength <= 0 ||
                        protectedLength > MaximumProtectedPayloadBytes ||
                        protectedLength != stream.Length - stream.Position - DigestBytes)
                    {
                        throw new StateStoreCorruptionException(
                            "The authoritative state protected-payload length is invalid.");
                    }

                    var expectedDigest = ReadExact(stream, DigestBytes);
                    var protectedPayload = ReadExact(stream, protectedLength);
                    byte[] actualDigest;
                    using (var sha256 = SHA256.Create())
                    {
                        actualDigest = sha256.ComputeHash(protectedPayload);
                    }

                    if (!CryptographicOperations.FixedTimeEquals(expectedDigest, actualDigest))
                    {
                        throw new StateStoreCorruptionException(
                            "The authoritative state envelope digest is invalid.");
                    }

                    var plaintext = UnprotectStoredRecord(protectedPayload);
                    try
                    {
                        using (var recordStream = new MemoryStream(plaintext, writable: false))
                        {
                            RequireBytes(
                                recordStream,
                                StoredRecordMagic,
                                "protected state-record magic");
                            if (ReadInt32(recordStream) != StoredRecordVersion)
                            {
                                throw new StateStoreCorruptionException(
                                    "The protected state-record version is unsupported.");
                            }

                            var previousCommitment = ReadExact(
                                recordStream,
                                StateVersionWatermark.CommitmentBytes);
                            var stateLength = ReadInt32(recordStream);
                            if (stateLength <= 0 ||
                                stateLength > CanonicalStateCodec.MaximumPayloadBytes ||
                                stateLength != recordStream.Length - recordStream.Position)
                            {
                                throw new StateStoreCorruptionException(
                                    "The protected canonical-state length is invalid.");
                            }

                            var canonicalState = ReadExact(recordStream, stateLength);
                            DeviceSecurityState state;
                            try
                            {
                                state = CanonicalStateCodec.Decode(canonicalState);
                            }
                            finally
                            {
                                CryptographicOperations.ZeroMemory(canonicalState);
                            }
                            if (state.Version != declaredStateVersion)
                            {
                                throw new StateStoreCorruptionException(
                                    "The protected state version does not match its envelope.");
                            }

                            byte[] commitment;
                            using (var sha256 = SHA256.Create())
                            {
                                commitment = sha256.ComputeHash(plaintext);
                            }

                            return new PersistedStateRecord(
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
                    "The authoritative state envelope is malformed.",
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
                    "The authoritative state could not be authenticated or decrypted.",
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
                    "The unprotected authoritative state record is empty or oversized.");
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
                await WriteTemporaryFileAsync(temporaryPath, envelope, cancellationToken).ConfigureAwait(false);
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
                await WriteTemporaryFileAsync(temporaryPath, envelope, cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                File.Replace(temporaryPath, _stateFilePath, _backupFilePath, ignoreMetadataErrors: false);
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
                await stream.WriteAsync(envelope, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }
        }

        private string CreateTemporaryPath()
        {
            return _stateFilePath + "." + Guid.NewGuid().ToString("N") + ".tmp";
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
            for (var index = 0; index < expected.Length; index++)
            {
                if (actual[index] != expected[index])
                {
                    throw new StateStoreCorruptionException(
                        "The authoritative " + fieldName + " is invalid.");
                }
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
                throw new ObjectDisposedException(nameof(FileAuthoritativeStateStore));
            }
        }

        private sealed class PersistedStateRecord
        {
            public PersistedStateRecord(
                DeviceSecurityState state,
                byte[] previousStateCommitment,
                byte[] stateCommitment)
            {
                State = state ?? throw new ArgumentNullException(nameof(state));
                if (previousStateCommitment == null ||
                    previousStateCommitment.Length != StateVersionWatermark.CommitmentBytes)
                {
                    throw new ArgumentException(
                        "A complete previous-state commitment is required.",
                        nameof(previousStateCommitment));
                }

                if (stateCommitment == null ||
                    stateCommitment.Length != StateVersionWatermark.CommitmentBytes)
                {
                    throw new ArgumentException(
                        "A complete state commitment is required.",
                        nameof(stateCommitment));
                }

                PreviousStateCommitment = (byte[])previousStateCommitment.Clone();
                StateCommitment = (byte[])stateCommitment.Clone();
            }

            public DeviceSecurityState State { get; }

            public byte[] PreviousStateCommitment { get; }

            public byte[] StateCommitment { get; }
        }
    }
}
