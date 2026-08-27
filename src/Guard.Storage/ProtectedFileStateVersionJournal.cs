using System;
using System.Collections.Concurrent;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Guard.Storage
{
    /// <summary>
    /// Append-only, protected, hash-chained state-version journal.
    /// This detects corruption, partial appends, and rollback of the state file
    /// relative to an intact journal. Because the journal is still a file, an
    /// attacker capable of restoring both state and journal offline can roll both
    /// back together. A separate BitLocker/TPM-backed anchor remains required for
    /// complete offline rollback resistance.
    /// </summary>
    public sealed class ProtectedFileStateVersionJournal : IStateVersionWatermark
    {
        private static readonly byte[] JournalMagic =
        {
            0x47, 0x52, 0x44, 0x56, 0x32, 0x4A, 0x4E, 0x4C
        };

        private static readonly byte[] RecordMagic = { 0x4A, 0x52, 0x45, 0x43 };
        private static readonly byte[] EntryMagic =
        {
            0x47, 0x52, 0x44, 0x56, 0x32, 0x4A, 0x45, 0x4E
        };

        private static readonly ConcurrentDictionary<string, SemaphoreSlim> ProcessLocks =
            new ConcurrentDictionary<string, SemaphoreSlim>(StringComparer.OrdinalIgnoreCase);

        private const int JournalVersion = 1;
        private const int EntryVersion = 1;
        private const int HashBytes = 32;
        private const int EntryPlaintextBytes =
            8 + 4 + 8 + StateVersionWatermark.CommitmentBytes + HashBytes;
        private const int MaximumProtectedEntryBytes = 4096;
        private const long MaximumJournalBytes = 64L * 1024L * 1024L;

        private readonly string _journalPath;
        private readonly IStateDataProtector _protector;
        private readonly SemaphoreSlim _processLock;

        public ProtectedFileStateVersionJournal(
            string journalPath,
            IStateDataProtector protector)
        {
            if (string.IsNullOrWhiteSpace(journalPath))
            {
                throw new ArgumentException("A state-version journal path is required.", nameof(journalPath));
            }

            _protector = protector ?? throw new ArgumentNullException(nameof(protector));
            _journalPath = Path.GetFullPath(journalPath);
            if (string.IsNullOrEmpty(Path.GetDirectoryName(_journalPath)))
            {
                throw new ArgumentException("The journal must have a parent directory.", nameof(journalPath));
            }

            _processLock = ProcessLocks.GetOrAdd(_journalPath, _ => new SemaphoreSlim(1, 1));
        }

        public string JournalPath => _journalPath;

        public async Task<StateVersionWatermark?> GetCurrentAsync(CancellationToken cancellationToken)
        {
            await _processLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (!File.Exists(_journalPath))
                {
                    return null;
                }

                var snapshot = ReadJournal(cancellationToken);
                return new StateVersionWatermark(
                    snapshot.HighestVersion,
                    snapshot.StateCommitment);
            }
            finally
            {
                _processLock.Release();
            }
        }

        public async Task AdvanceToAsync(
            long version,
            byte[] stateCommitment,
            CancellationToken cancellationToken)
        {
            if (version < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(version));
            }

            if (stateCommitment == null ||
                stateCommitment.Length != StateVersionWatermark.CommitmentBytes)
            {
                throw new ArgumentException(
                    "A complete SHA-256 state commitment is required.",
                    nameof(stateCommitment));
            }

            await _processLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!File.Exists(_journalPath))
                {
                    if (version != 0)
                    {
                        throw new StateStoreCorruptionException(
                            "A missing state-version journal can only be explicitly initialized at version zero.");
                    }

                    await CreateJournalAsync(stateCommitment, cancellationToken).ConfigureAwait(false);
                    return;
                }

                var snapshot = ReadJournal(cancellationToken);
                if (version < snapshot.HighestVersion)
                {
                    throw new StateRollbackDetectedException(version, snapshot.HighestVersion);
                }

                if (version == snapshot.HighestVersion)
                {
                    if (!CryptographicOperations.FixedTimeEquals(
                        stateCommitment,
                        snapshot.StateCommitment))
                    {
                        throw new StateStoreCorruptionException(
                            "The state-version journal already binds this version to a different state.");
                    }

                    return;
                }

                if (snapshot.HighestVersion == long.MaxValue ||
                    version != snapshot.HighestVersion + 1)
                {
                    throw new StateStoreCorruptionException(
                        "The state-version journal cannot skip versions.");
                }

                var record = CreateRecord(
                    version,
                    stateCommitment,
                    snapshot.LastRecordHash);
                using (var stream = new FileStream(
                    _journalPath,
                    FileMode.Append,
                    FileAccess.Write,
                    FileShare.Read,
                    bufferSize: 4096,
                    options: FileOptions.Asynchronous | FileOptions.WriteThrough))
                {
                    if (stream.Length > MaximumJournalBytes - record.Length)
                    {
                        throw new IOException("The state-version journal has reached its size limit.");
                    }

                    cancellationToken.ThrowIfCancellationRequested();
                    await stream.WriteAsync(record, CancellationToken.None).ConfigureAwait(false);
                    await stream.FlushAsync(CancellationToken.None).ConfigureAwait(false);
                    stream.Flush(flushToDisk: true);
                }
            }
            finally
            {
                _processLock.Release();
            }
        }

        private JournalSnapshot ReadJournal(CancellationToken cancellationToken)
        {
            using (var stream = new FileStream(
                _journalPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 4096,
                options: FileOptions.SequentialScan))
            {
                if (stream.Length <= JournalMagic.Length + 4 ||
                    stream.Length > MaximumJournalBytes)
                {
                    throw new StateStoreCorruptionException(
                        "The state-version journal is empty or oversized.");
                }

                RequireBytes(stream, JournalMagic, "journal magic");
                if (ReadInt32(stream) != JournalVersion)
                {
                    throw new StateStoreCorruptionException(
                        "The state-version journal format is unsupported.");
                }

                var previousHash = new byte[HashBytes];
                long highestVersion = -1;
                var recordCount = 0;
                while (stream.Position < stream.Length)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    RequireBytes(stream, RecordMagic, "journal record magic");
                    var protectedLength = ReadInt32(stream);
                    if (protectedLength <= 0 ||
                        protectedLength > MaximumProtectedEntryBytes ||
                        protectedLength > stream.Length - stream.Position - HashBytes)
                    {
                        throw new StateStoreCorruptionException(
                            "A state-version journal record length is invalid.");
                    }

                    var protectedEntry = ReadExact(stream, protectedLength);
                    var expectedRecordHash = ReadExact(stream, HashBytes);
                    var actualRecordHash = ComputeRecordHash(previousHash, protectedEntry);
                    if (!CryptographicOperations.FixedTimeEquals(expectedRecordHash, actualRecordHash))
                    {
                        throw new StateStoreCorruptionException(
                            "A state-version journal hash-chain record is invalid.");
                    }

                    var entry = DecodeEntry(protectedEntry);
                    if (!CryptographicOperations.FixedTimeEquals(entry.PreviousRecordHash, previousHash))
                    {
                        throw new StateStoreCorruptionException(
                            "A state-version journal entry breaks the protected hash chain.");
                    }

                    if (recordCount > 0 && highestVersion == long.MaxValue)
                    {
                        throw new StateStoreCorruptionException(
                            "The state-version journal contains records after the maximum version.");
                    }

                    var requiredVersion = recordCount == 0 ? 0 : highestVersion + 1;
                    if (entry.StateVersion != requiredVersion)
                    {
                        throw new StateStoreCorruptionException(
                            "State-version journal entries are not strictly consecutive from zero.");
                    }

                    highestVersion = entry.StateVersion;
                    var stateCommitment = entry.StateCommitment;
                    previousHash = actualRecordHash;
                    recordCount++;

                    if (stream.Position == stream.Length)
                    {
                        return new JournalSnapshot(
                            highestVersion,
                            stateCommitment,
                            previousHash);
                    }
                }

                throw new StateStoreCorruptionException(
                    "The state-version journal contains no records.");
            }
        }

        private async Task CreateJournalAsync(
            byte[] stateCommitment,
            CancellationToken cancellationToken)
        {
            var directory = Path.GetDirectoryName(_journalPath)!;
            Directory.CreateDirectory(directory);
            var temporaryPath = _journalPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                var firstRecord = CreateRecord(
                    0,
                    stateCommitment,
                    new byte[HashBytes]);
                using (var stream = new FileStream(
                    temporaryPath,
                    FileMode.CreateNew,
                    FileAccess.Write,
                    FileShare.None,
                    bufferSize: 4096,
                    options: FileOptions.Asynchronous | FileOptions.WriteThrough))
                {
                    await stream.WriteAsync(JournalMagic, cancellationToken).ConfigureAwait(false);
                    var versionBytes = GetInt32Bytes(JournalVersion);
                    await stream.WriteAsync(versionBytes, cancellationToken).ConfigureAwait(false);
                    await stream.WriteAsync(firstRecord, cancellationToken).ConfigureAwait(false);
                    await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                    stream.Flush(flushToDisk: true);
                }

                cancellationToken.ThrowIfCancellationRequested();
                File.Move(temporaryPath, _journalPath);
            }
            finally
            {
                TryDeleteTemporaryFile(temporaryPath);
            }
        }

        private byte[] CreateRecord(
            long stateVersion,
            byte[] stateCommitment,
            byte[] previousRecordHash)
        {
            var plaintext = CreateEntryPlaintext(
                stateVersion,
                stateCommitment,
                previousRecordHash);
            byte[] protectedEntry;
            try
            {
                var result = _protector.Protect(plaintext);
                protectedEntry = ReferenceEquals(result, plaintext)
                    ? (byte[])result.Clone()
                    : result;
            }
            catch (Exception exception) when (
                exception is CryptographicException ||
                exception is ArgumentException ||
                exception is InvalidOperationException)
            {
                throw new IOException("The state-version journal entry could not be protected.", exception);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }

            if (protectedEntry == null ||
                protectedEntry.Length == 0 ||
                protectedEntry.Length > MaximumProtectedEntryBytes)
            {
                throw new IOException("The journal protector returned an empty or oversized payload.");
            }

            var recordHash = ComputeRecordHash(previousRecordHash, protectedEntry);
            using (var stream = new MemoryStream(
                RecordMagic.Length + 4 + protectedEntry.Length + recordHash.Length))
            {
                stream.Write(RecordMagic, 0, RecordMagic.Length);
                WriteInt32(stream, protectedEntry.Length);
                stream.Write(protectedEntry, 0, protectedEntry.Length);
                stream.Write(recordHash, 0, recordHash.Length);
                return stream.ToArray();
            }
        }

        private JournalEntry DecodeEntry(byte[] protectedEntry)
        {
            byte[] plaintext;
            try
            {
                plaintext = _protector.Unprotect(protectedEntry);
            }
            catch (Exception exception) when (
                exception is CryptographicException ||
                exception is ArgumentException ||
                exception is InvalidOperationException)
            {
                throw new StateStoreCorruptionException(
                    "A state-version journal entry could not be authenticated or decrypted.",
                    exception);
            }

            if (plaintext == null || plaintext.Length != EntryPlaintextBytes)
            {
                if (plaintext != null)
                {
                    CryptographicOperations.ZeroMemory(plaintext);
                }

                throw new StateStoreCorruptionException(
                    "A state-version journal entry has an invalid plaintext length.");
            }

            try
            {
                using (var stream = new MemoryStream(plaintext, writable: false))
                {
                    RequireBytes(stream, EntryMagic, "journal entry magic");
                    if (ReadInt32(stream) != EntryVersion)
                    {
                        throw new StateStoreCorruptionException(
                            "A state-version journal entry format is unsupported.");
                    }

                    var stateVersion = ReadInt64(stream);
                    if (stateVersion < 0)
                    {
                        throw new StateStoreCorruptionException(
                            "A state-version journal entry has a negative version.");
                    }

                    var stateCommitment = ReadExact(
                        stream,
                        StateVersionWatermark.CommitmentBytes);
                    var previousHash = ReadExact(stream, HashBytes);
                    if (stream.Position != stream.Length)
                    {
                        throw new StateStoreCorruptionException(
                            "A state-version journal entry contains trailing bytes.");
                    }

                    return new JournalEntry(
                        stateVersion,
                        stateCommitment,
                        previousHash);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }

        private static byte[] CreateEntryPlaintext(
            long stateVersion,
            byte[] stateCommitment,
            byte[] previousRecordHash)
        {
            if (stateCommitment == null ||
                stateCommitment.Length != StateVersionWatermark.CommitmentBytes)
            {
                throw new ArgumentException(
                    "A complete SHA-256 state commitment is required.",
                    nameof(stateCommitment));
            }

            if (previousRecordHash == null || previousRecordHash.Length != HashBytes)
            {
                throw new ArgumentException("A complete previous-record hash is required.", nameof(previousRecordHash));
            }

            using (var stream = new MemoryStream(EntryPlaintextBytes))
            {
                stream.Write(EntryMagic, 0, EntryMagic.Length);
                WriteInt32(stream, EntryVersion);
                WriteInt64(stream, stateVersion);
                stream.Write(stateCommitment, 0, stateCommitment.Length);
                stream.Write(previousRecordHash, 0, previousRecordHash.Length);
                return stream.ToArray();
            }
        }

        private static byte[] ComputeRecordHash(byte[] previousRecordHash, byte[] protectedEntry)
        {
            using (var stream = new MemoryStream(
                previousRecordHash.Length + RecordMagic.Length + 4 + protectedEntry.Length))
            {
                stream.Write(previousRecordHash, 0, previousRecordHash.Length);
                stream.Write(RecordMagic, 0, RecordMagic.Length);
                WriteInt32(stream, protectedEntry.Length);
                stream.Write(protectedEntry, 0, protectedEntry.Length);
                using (var sha256 = SHA256.Create())
                {
                    return sha256.ComputeHash(stream.ToArray());
                }
            }
        }

        private static void RequireBytes(Stream stream, byte[] expected, string fieldName)
        {
            var actual = ReadExact(stream, expected.Length);
            for (var index = 0; index < expected.Length; index++)
            {
                if (actual[index] != expected[index])
                {
                    throw new StateStoreCorruptionException(
                        "The state-version " + fieldName + " is invalid.");
                }
            }
        }

        private static byte[] ReadExact(Stream stream, int count)
        {
            if (count < 0 || count > stream.Length - stream.Position)
            {
                throw new StateStoreCorruptionException(
                    "The state-version journal ended unexpectedly.");
            }

            var result = new byte[count];
            var offset = 0;
            while (offset < count)
            {
                var read = stream.Read(result, offset, count - offset);
                if (read <= 0)
                {
                    throw new StateStoreCorruptionException(
                        "The state-version journal ended unexpectedly.");
                }

                offset += read;
            }

            return result;
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

        private static byte[] GetInt32Bytes(int value)
        {
            return new[]
            {
                (byte)((value >> 24) & 0xFF),
                (byte)((value >> 16) & 0xFF),
                (byte)((value >> 8) & 0xFF),
                (byte)(value & 0xFF)
            };
        }

        private static void WriteInt32(Stream stream, int value)
        {
            var bytes = GetInt32Bytes(value);
            stream.Write(bytes, 0, bytes.Length);
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

        private sealed class JournalSnapshot
        {
            public JournalSnapshot(
                long highestVersion,
                byte[] stateCommitment,
                byte[] lastRecordHash)
            {
                HighestVersion = highestVersion;
                StateCommitment = stateCommitment;
                LastRecordHash = lastRecordHash;
            }

            public long HighestVersion { get; }

            public byte[] StateCommitment { get; }

            public byte[] LastRecordHash { get; }
        }

        private sealed class JournalEntry
        {
            public JournalEntry(
                long stateVersion,
                byte[] stateCommitment,
                byte[] previousRecordHash)
            {
                StateVersion = stateVersion;
                StateCommitment = stateCommitment;
                PreviousRecordHash = previousRecordHash;
            }

            public long StateVersion { get; }

            public byte[] StateCommitment { get; }

            public byte[] PreviousRecordHash { get; }
        }
    }
}
