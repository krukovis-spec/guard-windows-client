using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Guard.Domain;
using Guard.Storage;

namespace Guard.Storage.Tests
{
    internal static class Program
    {
        private static int Main()
        {
            var tests = new List<(string Name, Action Run)>
            {
                ("requires explicit initialization", RequiresExplicitInitialization),
                ("round-trips every security-boundary field", RoundTripsSecurityState),
                ("enforces the authoritative parent-key bound", EnforcesParentKeyBound),
                ("uses deterministic canonical plaintext", UsesDeterministicCanonicalPlaintext),
                ("allows exactly one concurrent CAS commit", AllowsExactlyOneConcurrentCommit),
                ("holds an exclusive lifetime writer lease", HoldsExclusiveWriterLease),
                ("rejects stale CAS without changing state", RejectsStaleCas),
                ("rejects marker and device rollback", RejectsSecurityMarkerRollback),
                ("detects state-file tampering", DetectsTampering),
                ("detects authenticated-payload tampering", DetectsAuthenticatedPayloadTampering),
                ("rejects unsupported and trailing envelopes", RejectsInvalidEnvelopes),
                ("rejects oversized state files", RejectsOversizedStateFile),
                ("detects rollback to the atomic backup", DetectsRollbackToBackup),
                ("detects same-version authenticated substitution", DetectsSameVersionSubstitution),
                ("recovers a lagging monotonic watermark", RecoversLaggingWatermark),
                ("fails closed when the watermark is missing", RejectsMissingWatermark),
                ("refuses ambiguous reinitialization artifacts", RefusesAmbiguousReinitialization),
                ("journal lookup never bootstraps missing state", JournalDoesNotAutoBootstrap),
                ("journal appends a persistent protected hash chain", JournalAppendsProtectedHashChain),
                ("journal requires strict consecutive versions", JournalRequiresConsecutiveVersions),
                ("journal rejects partial append and tampering", JournalRejectsPartialAndTamperedRecords),
                ("file store detects rollback with protected journal", StoreUsesProtectedJournal)
            };

            var failures = 0;
            foreach (var test in tests)
            {
                try
                {
                    test.Run();
                    Console.WriteLine("PASS " + test.Name);
                }
                catch (Exception exception)
                {
                    failures++;
                    Console.WriteLine("FAIL " + test.Name + ": " + exception);
                }
            }

            Console.WriteLine(failures == 0
                ? "All Guard.Storage checks passed."
                : failures + " Guard.Storage check(s) failed.");
            return failures == 0 ? 0 : 1;
        }

        private static void RequiresExplicitInitialization()
        {
            using (var directory = new TestDirectory())
            {
                using var store = CreateStore(directory, out _, out _);
                ExpectThrows<FileNotFoundException>(
                    () => store.LoadAsync(CancellationToken.None).GetAwaiter().GetResult(),
                    "A missing state file was silently treated as empty state.");
            }
        }

        private static void RoundTripsSecurityState()
        {
            using (var directory = new TestDirectory())
            {
                using var store = CreateStore(directory, out _, out _);
                var state = CreateCompleteState();
                store.InitializeAsync(state, CancellationToken.None).GetAwaiter().GetResult();

                var loaded = store.LoadAsync(CancellationToken.None).GetAwaiter().GetResult();
                AssertEqual(state.DeviceId, loaded.DeviceId, "Device id changed.");
                AssertEqual(state.Version, loaded.Version, "Version changed.");
                AssertEqual(state.HighestAcceptedSequence, loaded.HighestAcceptedSequence, "Sequence changed.");
                AssertEqual(state.DesiredPolicyRevision, loaded.DesiredPolicyRevision, "Policy revision changed.");
                AssertSequenceEqual(state.RecentCommandIds, loaded.RecentCommandIds, "Recent command ids changed.");
                AssertEqual(
                    state.ChildAccountSid!.Value,
                    loaded.ChildAccountSid!.Value,
                    "Bound child account changed.");
                Assert(loaded.SetupChallenge != null, "Setup challenge was lost.");
                AssertEqual(state.SetupChallenge!.ChallengeId, loaded.SetupChallenge!.ChallengeId, "Challenge id changed.");
                AssertEqual(
                    state.SetupChallenge.ExpiresAtUtc.UtcDateTime,
                    loaded.SetupChallenge.ExpiresAtUtc.UtcDateTime,
                    "Challenge expiry changed.");
                AssertEqual(state.SetupChallenge.Consumed, loaded.SetupChallenge.Consumed, "Challenge status changed.");
                AssertBytesEqual(
                    state.SetupChallenge.GetSecretHashCopy(),
                    loaded.SetupChallenge.GetSecretHashCopy(),
                    "Challenge secret hash changed.");
                AssertEqual(2, loaded.TrustedParentKeys.Count, "Trusted keys were lost.");
                for (var index = 0; index < state.TrustedParentKeys.Count; index++)
                {
                    Assert(state.TrustedParentKeys[index].Equals(loaded.TrustedParentKeys[index]), "Trusted key changed.");
                }
            }
        }

        private static void EnforcesParentKeyBound()
        {
            var keys = new List<ParentTrustAnchor>();
            for (var index = 0; index <= DeviceSecurityState.MaximumTrustedParentKeys; index++)
            {
                keys.Add(CreateParentKey((byte)(index + 1)));
            }

            ExpectThrows<ArgumentException>(
                () => new DeviceSecurityState(
                    "device-v2-000001",
                    version: 0,
                    highestAcceptedSequence: 0,
                    desiredPolicyRevision: 0,
                    trustedParentKeys: keys),
                "Authoritative state accepted more than the bounded parent-key count.");
        }

        private static void UsesDeterministicCanonicalPlaintext()
        {
            using (var firstDirectory = new TestDirectory())
            using (var secondDirectory = new TestDirectory())
            {
                var firstProtector = new RecordingAuthenticatedProtector();
                var secondProtector = new RecordingAuthenticatedProtector();
                using var first = new FileAuthoritativeStateStore(
                    firstDirectory.StatePath,
                    firstProtector,
                    new InMemoryWatermark());
                using var second = new FileAuthoritativeStateStore(
                    secondDirectory.StatePath,
                    secondProtector,
                    new InMemoryWatermark());
                var state = CreateCompleteState();

                first.InitializeAsync(state, CancellationToken.None).GetAwaiter().GetResult();
                second.InitializeAsync(state, CancellationToken.None).GetAwaiter().GetResult();

                AssertBytesEqual(
                    firstProtector.LastProtectedPlaintext!,
                    secondProtector.LastProtectedPlaintext!,
                    "Equivalent states did not produce the same canonical plaintext.");
            }
        }

        private static void AllowsExactlyOneConcurrentCommit()
        {
            using (var directory = new TestDirectory())
            {
                var protector = new RecordingAuthenticatedProtector();
                var watermark = new InMemoryWatermark();
                using var store = new FileAuthoritativeStateStore(directory.StatePath, protector, watermark);
                var initial = CreateInitialState();
                store.InitializeAsync(initial, CancellationToken.None).GetAwaiter().GetResult();

                var firstNext = initial.WithSetupChallenge(CreateChallenge("setup-000000000001"));
                var secondNext = initial.WithSetupChallenge(CreateChallenge("setup-000000000002"));
                var results = Task.WhenAll(
                    store.TryCommitAsync(0, firstNext, CancellationToken.None),
                    store.TryCommitAsync(0, secondNext, CancellationToken.None)).GetAwaiter().GetResult();

                AssertEqual(1, results.Count(value => value), "Concurrent CAS had more or less than one winner.");
                var loaded = store.LoadAsync(CancellationToken.None).GetAwaiter().GetResult();
                AssertEqual(1L, loaded.Version, "Winning CAS did not become authoritative.");
            }
        }

        private static void HoldsExclusiveWriterLease()
        {
            using (var directory = new TestDirectory())
            {
                using (var first = CreateStore(directory, out _, out _))
                {
                    ExpectThrows<IOException>(
                        () =>
                        {
                            using var unexpected = new FileAuthoritativeStateStore(
                                directory.StatePath,
                                new RecordingAuthenticatedProtector(),
                                new InMemoryWatermark());
                        },
                        "A second authoritative writer acquired the lifetime lease.");
                }

                using var reopened = CreateStore(directory, out _, out _);
                Assert(File.Exists(reopened.WriterLockFilePath), "Writer lock file was not retained.");
            }
        }

        private static void RejectsStaleCas()
        {
            using (var directory = new TestDirectory())
            {
                using var store = CreateStore(directory, out _, out _);
                var initial = CreateInitialState();
                store.InitializeAsync(initial, CancellationToken.None).GetAwaiter().GetResult();
                var committed = initial.WithSetupChallenge(CreateChallenge("setup-000000000001"));
                Assert(
                    store.TryCommitAsync(0, committed, CancellationToken.None).GetAwaiter().GetResult(),
                    "Fresh CAS failed.");

                var stale = initial.WithSetupChallenge(CreateChallenge("setup-000000000002"));
                Assert(
                    !store.TryCommitAsync(0, stale, CancellationToken.None).GetAwaiter().GetResult(),
                    "Stale CAS succeeded.");
                var loaded = store.LoadAsync(CancellationToken.None).GetAwaiter().GetResult();
                AssertEqual(
                    committed.SetupChallenge!.ChallengeId,
                    loaded.SetupChallenge!.ChallengeId,
                    "Stale CAS changed authoritative state.");
            }
        }

        private static void RejectsSecurityMarkerRollback()
        {
            using (var directory = new TestDirectory())
            {
                using var store = CreateStore(directory, out _, out _);
                var current = new DeviceSecurityState(
                    "device-v2-000001",
                    version: 0,
                    highestAcceptedSequence: 5,
                    desiredPolicyRevision: 3,
                    recentCommandIds: new[] { "cmd-000000000005" });
                store.InitializeAsync(current, CancellationToken.None).GetAwaiter().GetResult();

                var markerRollback = new DeviceSecurityState(
                    current.DeviceId,
                    version: 1,
                    highestAcceptedSequence: 4,
                    desiredPolicyRevision: 3);
                ExpectThrows<ArgumentException>(
                    () => store.TryCommitAsync(0, markerRollback, CancellationToken.None).GetAwaiter().GetResult(),
                    "A replay marker was allowed to decrease.");

                var wrongDevice = new DeviceSecurityState(
                    "device-v2-999999",
                    version: 1,
                    highestAcceptedSequence: 5,
                    desiredPolicyRevision: 3);
                ExpectThrows<ArgumentException>(
                    () => store.TryCommitAsync(0, wrongDevice, CancellationToken.None).GetAwaiter().GetResult(),
                    "The authoritative device identity was replaceable.");

                using (var boundDirectory = new TestDirectory())
                {
                    using var boundStore = CreateStore(boundDirectory, out _, out _);
                    var bound = new DeviceSecurityState(
                        current.DeviceId,
                        version: 0,
                        highestAcceptedSequence: 5,
                        desiredPolicyRevision: 3,
                        childAccountSid: new WindowsAccountSid("S-1-5-21-1000"));
                    boundStore.InitializeAsync(bound, CancellationToken.None).GetAwaiter().GetResult();
                    var childReplacement = new DeviceSecurityState(
                        bound.DeviceId,
                        version: 1,
                        highestAcceptedSequence: 5,
                        desiredPolicyRevision: 3,
                        childAccountSid: new WindowsAccountSid("S-1-5-21-2000"));
                    ExpectThrows<ArgumentException>(
                        () => boundStore.TryCommitAsync(
                            0,
                            childReplacement,
                            CancellationToken.None).GetAwaiter().GetResult(),
                        "The bound child account was replaceable.");
                }
            }
        }

        private static void DetectsTampering()
        {
            using (var directory = new TestDirectory())
            {
                using var store = CreateStore(directory, out _, out _);
                store.InitializeAsync(CreateInitialState(), CancellationToken.None).GetAwaiter().GetResult();
                var bytes = File.ReadAllBytes(directory.StatePath);
                bytes[bytes.Length - 1] ^= 0x5A;
                File.WriteAllBytes(directory.StatePath, bytes);

                ExpectThrows<StateStoreCorruptionException>(
                    () => store.LoadAsync(CancellationToken.None).GetAwaiter().GetResult(),
                    "Tampered ciphertext was accepted.");
            }
        }

        private static void DetectsAuthenticatedPayloadTampering()
        {
            using (var directory = new TestDirectory())
            {
                using var store = CreateStore(directory, out _, out _);
                store.InitializeAsync(CreateInitialState(), CancellationToken.None).GetAwaiter().GetResult();
                var bytes = File.ReadAllBytes(directory.StatePath);
                const int digestOffset = 8 + 4 + 8 + 4;
                const int digestLength = 32;
                var protectedOffset = digestOffset + digestLength;
                bytes[bytes.Length - 1] ^= 0x33;
                var digest = SHA256.HashData(bytes.AsSpan(protectedOffset));
                digest.CopyTo(bytes, digestOffset);
                File.WriteAllBytes(directory.StatePath, bytes);

                ExpectThrows<StateStoreCorruptionException>(
                    () => store.LoadAsync(CancellationToken.None).GetAwaiter().GetResult(),
                    "A recomputed unkeyed envelope digest bypassed authenticated protection.");
            }
        }

        private static void RejectsInvalidEnvelopes()
        {
            using (var directory = new TestDirectory())
            {
                using var store = CreateStore(directory, out _, out _);
                store.InitializeAsync(CreateInitialState(), CancellationToken.None).GetAwaiter().GetResult();
                var original = File.ReadAllBytes(directory.StatePath);

                var unsupported = (byte[])original.Clone();
                unsupported[11] = 2;
                File.WriteAllBytes(directory.StatePath, unsupported);
                ExpectThrows<StateStoreCorruptionException>(
                    () => store.LoadAsync(CancellationToken.None).GetAwaiter().GetResult(),
                    "An unsupported envelope version was accepted.");

                var trailing = new byte[original.Length + 1];
                Buffer.BlockCopy(original, 0, trailing, 0, original.Length);
                File.WriteAllBytes(directory.StatePath, trailing);
                ExpectThrows<StateStoreCorruptionException>(
                    () => store.LoadAsync(CancellationToken.None).GetAwaiter().GetResult(),
                    "Trailing envelope bytes were accepted.");
            }
        }

        private static void RejectsOversizedStateFile()
        {
            using (var directory = new TestDirectory())
            {
                Directory.CreateDirectory(Path.GetDirectoryName(directory.StatePath)!);
                File.WriteAllBytes(directory.StatePath, new byte[300 * 1024]);
                var watermark = new InMemoryWatermark();
                watermark.AdvanceToAsync(
                    0,
                    CreateCommitment(0),
                    CancellationToken.None).GetAwaiter().GetResult();
                using var store = new FileAuthoritativeStateStore(
                    directory.StatePath,
                    new RecordingAuthenticatedProtector(),
                    watermark);

                ExpectThrows<StateStoreCorruptionException>(
                    () => store.LoadAsync(CancellationToken.None).GetAwaiter().GetResult(),
                    "An oversized state file was read.");
            }
        }

        private static void DetectsRollbackToBackup()
        {
            using (var directory = new TestDirectory())
            {
                using var store = CreateStore(directory, out _, out _);
                var initial = CreateInitialState();
                store.InitializeAsync(initial, CancellationToken.None).GetAwaiter().GetResult();
                var next = initial.WithSetupChallenge(CreateChallenge("setup-000000000001"));
                store.TryCommitAsync(0, next, CancellationToken.None).GetAwaiter().GetResult();
                Assert(File.Exists(store.BackupFilePath), "Atomic replacement did not retain a backup.");

                File.Copy(store.BackupFilePath, store.StateFilePath, overwrite: true);
                var exception = ExpectThrows<StateRollbackDetectedException>(
                    () => store.LoadAsync(CancellationToken.None).GetAwaiter().GetResult(),
                    "A backup rollback was accepted.");
                AssertEqual(0L, exception.StoredVersion, "Rollback report has the wrong stored version.");
                AssertEqual(1L, exception.HighestVersion, "Rollback report has the wrong watermark.");
            }
        }

        private static void DetectsSameVersionSubstitution()
        {
            using (var firstDirectory = new TestDirectory())
            using (var secondDirectory = new TestDirectory())
            {
                var firstProtector = new RecordingAuthenticatedProtector();
                var secondProtector = new RecordingAuthenticatedProtector();
                using var first = new FileAuthoritativeStateStore(
                    firstDirectory.StatePath,
                    firstProtector,
                    new ProtectedFileStateVersionJournal(
                        Path.Combine(firstDirectory.PathValue, "version.journal"),
                        firstProtector));
                using var second = new FileAuthoritativeStateStore(
                    secondDirectory.StatePath,
                    secondProtector,
                    new ProtectedFileStateVersionJournal(
                        Path.Combine(secondDirectory.PathValue, "version.journal"),
                        secondProtector));
                var initial = CreateInitialState();
                first.InitializeAsync(initial, CancellationToken.None).GetAwaiter().GetResult();
                second.InitializeAsync(initial, CancellationToken.None).GetAwaiter().GetResult();
                first.TryCommitAsync(
                    0,
                    initial.WithSetupChallenge(CreateChallenge("setup-000000000001")),
                    CancellationToken.None).GetAwaiter().GetResult();
                second.TryCommitAsync(
                    0,
                    initial.WithSetupChallenge(CreateChallenge("setup-000000000002")),
                    CancellationToken.None).GetAwaiter().GetResult();

                File.Copy(second.StateFilePath, first.StateFilePath, overwrite: true);
                ExpectThrows<StateStoreCorruptionException>(
                    () => first.LoadAsync(CancellationToken.None).GetAwaiter().GetResult(),
                    "A different authenticated state at the same version bypassed the journal commitment.");
            }
        }

        private static void RecoversLaggingWatermark()
        {
            using (var directory = new TestDirectory())
            {
                var protector = new RecordingAuthenticatedProtector();
                var committedWatermark = new InMemoryWatermark();
                var initial = CreateInitialState();
                using (var writer = new FileAuthoritativeStateStore(
                    directory.StatePath,
                    protector,
                    committedWatermark))
                {
                    writer.InitializeAsync(initial, CancellationToken.None).GetAwaiter().GetResult();
                    writer.TryCommitAsync(
                        0,
                        initial.WithSetupChallenge(CreateChallenge("setup-000000000001")),
                        CancellationToken.None).GetAwaiter().GetResult();
                }

                var laggingWatermark = new InMemoryWatermark();
                laggingWatermark.AdvanceToAsync(
                    0,
                    committedWatermark.GetCommitmentForVersion(0),
                    CancellationToken.None).GetAwaiter().GetResult();
                using var reader = new FileAuthoritativeStateStore(
                    directory.StatePath,
                    protector,
                    laggingWatermark);
                var loaded = reader.LoadAsync(CancellationToken.None).GetAwaiter().GetResult();
                AssertEqual(1L, loaded.Version, "Newer authenticated state was not loaded.");
                AssertEqual(1L, laggingWatermark.Value, "Lagging watermark was not advanced.");
            }
        }

        private static void RejectsMissingWatermark()
        {
            using (var directory = new TestDirectory())
            {
                var protector = new RecordingAuthenticatedProtector();
                var originalWatermark = new InMemoryWatermark();
                using (var writer = new FileAuthoritativeStateStore(
                    directory.StatePath,
                    protector,
                    originalWatermark))
                {
                    writer.InitializeAsync(CreateInitialState(), CancellationToken.None).GetAwaiter().GetResult();
                }

                using var reader = new FileAuthoritativeStateStore(
                    directory.StatePath,
                    protector,
                    new InMemoryWatermark());

                ExpectThrows<StateStoreCorruptionException>(
                    () => reader.LoadAsync(CancellationToken.None).GetAwaiter().GetResult(),
                    "A state file without a watermark was accepted.");
            }
        }

        private static void RefusesAmbiguousReinitialization()
        {
            using (var directory = new TestDirectory())
            {
                Directory.CreateDirectory(Path.GetDirectoryName(directory.StatePath)!);
                File.WriteAllBytes(directory.StatePath + ".bak", new byte[] { 1 });
                using var store = CreateStore(directory, out _, out _);
                ExpectThrows<InvalidOperationException>(
                    () => store.InitializeAsync(CreateInitialState(), CancellationToken.None).GetAwaiter().GetResult(),
                    "A leftover backup was silently overwritten during initialization.");
            }
        }

        private static void JournalDoesNotAutoBootstrap()
        {
            using (var directory = new TestDirectory())
            {
                var journalPath = Path.Combine(directory.PathValue, "version.journal");
                var journal = new ProtectedFileStateVersionJournal(
                    journalPath,
                    new RecordingAuthenticatedProtector());
                AssertEqual(
                    null,
                    journal.GetCurrentAsync(CancellationToken.None).GetAwaiter().GetResult(),
                    "A missing journal did not report missing state.");
                Assert(!File.Exists(journalPath), "A watermark read silently created a journal.");

                ExpectThrows<StateStoreCorruptionException>(
                    () => journal.AdvanceToAsync(
                        1,
                        CreateCommitment(1),
                        CancellationToken.None).GetAwaiter().GetResult(),
                    "A missing journal was silently bootstrapped above version zero.");
                Assert(!File.Exists(journalPath), "Rejected bootstrap left a journal artifact.");
            }
        }

        private static void JournalAppendsProtectedHashChain()
        {
            using (var directory = new TestDirectory())
            {
                var journalPath = Path.Combine(directory.PathValue, "version.journal");
                var protector = new RecordingAuthenticatedProtector();
                var journal = new ProtectedFileStateVersionJournal(journalPath, protector);
                journal.AdvanceToAsync(
                    0,
                    CreateCommitment(0),
                    CancellationToken.None).GetAwaiter().GetResult();
                var zeroPrefix = File.ReadAllBytes(journalPath);
                journal.AdvanceToAsync(
                    1,
                    CreateCommitment(1),
                    CancellationToken.None).GetAwaiter().GetResult();
                var oneBytes = File.ReadAllBytes(journalPath);

                Assert(oneBytes.Length > zeroPrefix.Length, "Journal advancement did not append a record.");
                AssertBytesEqual(
                    zeroPrefix,
                    oneBytes.AsSpan(0, zeroPrefix.Length).ToArray(),
                    "Journal advancement rewrote its existing prefix.");
                var reopened = new ProtectedFileStateVersionJournal(journalPath, protector);
                AssertEqual(
                    1L,
                    reopened.GetCurrentAsync(CancellationToken.None).GetAwaiter().GetResult()!.Version,
                    "Reopened journal lost its highest version.");
            }
        }

        private static void JournalRequiresConsecutiveVersions()
        {
            using (var directory = new TestDirectory())
            {
                var journal = new ProtectedFileStateVersionJournal(
                    Path.Combine(directory.PathValue, "version.journal"),
                    new RecordingAuthenticatedProtector());
                journal.AdvanceToAsync(
                    0,
                    CreateCommitment(0),
                    CancellationToken.None).GetAwaiter().GetResult();
                journal.AdvanceToAsync(
                    0,
                    CreateCommitment(0),
                    CancellationToken.None).GetAwaiter().GetResult();
                ExpectThrows<StateStoreCorruptionException>(
                    () => journal.AdvanceToAsync(
                        0,
                        CreateCommitment(99),
                        CancellationToken.None).GetAwaiter().GetResult(),
                    "The same journal version accepted a different state commitment.");
                ExpectThrows<StateStoreCorruptionException>(
                    () => journal.AdvanceToAsync(
                        2,
                        CreateCommitment(2),
                        CancellationToken.None).GetAwaiter().GetResult(),
                    "The journal accepted a skipped version.");
                journal.AdvanceToAsync(
                    1,
                    CreateCommitment(1),
                    CancellationToken.None).GetAwaiter().GetResult();
                ExpectThrows<StateRollbackDetectedException>(
                    () => journal.AdvanceToAsync(
                        0,
                        CreateCommitment(0),
                        CancellationToken.None).GetAwaiter().GetResult(),
                    "The journal watermark decreased.");
            }
        }

        private static void JournalRejectsPartialAndTamperedRecords()
        {
            using (var partialDirectory = new TestDirectory())
            {
                var partialPath = Path.Combine(partialDirectory.PathValue, "version.journal");
                var partial = new ProtectedFileStateVersionJournal(
                    partialPath,
                    new RecordingAuthenticatedProtector());
                partial.AdvanceToAsync(
                    0,
                    CreateCommitment(0),
                    CancellationToken.None).GetAwaiter().GetResult();
                partial.AdvanceToAsync(
                    1,
                    CreateCommitment(1),
                    CancellationToken.None).GetAwaiter().GetResult();
                using (var stream = new FileStream(partialPath, FileMode.Open, FileAccess.Write, FileShare.None))
                {
                    stream.SetLength(stream.Length - 1);
                    stream.Flush(flushToDisk: true);
                }

                ExpectThrows<StateStoreCorruptionException>(
                    () => partial.GetCurrentAsync(CancellationToken.None).GetAwaiter().GetResult(),
                    "A partial journal append was silently truncated or accepted.");
            }

            using (var tamperedDirectory = new TestDirectory())
            {
                var tamperedPath = Path.Combine(tamperedDirectory.PathValue, "version.journal");
                var tampered = new ProtectedFileStateVersionJournal(
                    tamperedPath,
                    new RecordingAuthenticatedProtector());
                tampered.AdvanceToAsync(
                    0,
                    CreateCommitment(0),
                    CancellationToken.None).GetAwaiter().GetResult();
                var bytes = File.ReadAllBytes(tamperedPath);
                const int firstProtectedByte = 8 + 4 + 4 + 4;
                bytes[firstProtectedByte] ^= 0x22;
                File.WriteAllBytes(tamperedPath, bytes);

                ExpectThrows<StateStoreCorruptionException>(
                    () => tampered.GetCurrentAsync(CancellationToken.None).GetAwaiter().GetResult(),
                    "A tampered journal record was accepted.");
            }
        }

        private static void StoreUsesProtectedJournal()
        {
            using (var directory = new TestDirectory())
            {
                var protector = new RecordingAuthenticatedProtector();
                var journal = new ProtectedFileStateVersionJournal(
                    Path.Combine(directory.PathValue, "version.journal"),
                    protector);
                using var store = new FileAuthoritativeStateStore(
                    directory.StatePath,
                    protector,
                    journal);
                var initial = CreateInitialState();
                store.InitializeAsync(initial, CancellationToken.None).GetAwaiter().GetResult();
                store.TryCommitAsync(
                    0,
                    initial.WithSetupChallenge(CreateChallenge("setup-000000000001")),
                    CancellationToken.None).GetAwaiter().GetResult();

                File.Copy(store.BackupFilePath, store.StateFilePath, overwrite: true);
                ExpectThrows<StateRollbackDetectedException>(
                    () => store.LoadAsync(CancellationToken.None).GetAwaiter().GetResult(),
                    "The protected journal did not detect a state-file rollback.");
            }
        }

        private static FileAuthoritativeStateStore CreateStore(
            TestDirectory directory,
            out RecordingAuthenticatedProtector protector,
            out InMemoryWatermark watermark)
        {
            protector = new RecordingAuthenticatedProtector();
            watermark = new InMemoryWatermark();
            return new FileAuthoritativeStateStore(directory.StatePath, protector, watermark);
        }

        private static DeviceSecurityState CreateInitialState()
        {
            return new DeviceSecurityState("device-v2-000001", 0, 0, 0);
        }

        private static DeviceSecurityState CreateCompleteState()
        {
            return new DeviceSecurityState(
                "device-v2-000001",
                version: 0,
                highestAcceptedSequence: 12,
                desiredPolicyRevision: 7,
                recentCommandIds: new[]
                {
                    "cmd-000000000011",
                    "cmd-000000000012"
                },
                setupChallenge: CreateChallenge("setup-000000000001"),
                trustedParentKeys: new[]
                {
                    CreateParentKey(1),
                    CreateParentKey(2)
                },
                childAccountSid: new WindowsAccountSid("S-1-5-21-1000"));
        }

        private static SetupChallengeState CreateChallenge(string challengeId)
        {
            var hash = new byte[SetupChallengeState.SecretHashBytes];
            for (var index = 0; index < hash.Length; index++)
            {
                hash[index] = (byte)(index + 1);
            }

            return new SetupChallengeState(
                challengeId,
                hash,
                new DateTimeOffset(2030, 1, 2, 3, 4, 5, TimeSpan.Zero),
                consumed: false);
        }

        private static ParentTrustAnchor CreateParentKey(byte seed)
        {
            var publicKey = new byte[91];
            for (var index = 0; index < publicKey.Length; index++)
            {
                publicKey[index] = unchecked((byte)(seed + index));
            }

            return new ParentTrustAnchor(ParentKeyAlgorithm.EcdsaP256Sha256, publicKey);
        }

        private static byte[] CreateCommitment(byte seed)
        {
            return SHA256.HashData(new[] { seed });
        }

        private static TException ExpectThrows<TException>(Action action, string message)
            where TException : Exception
        {
            try
            {
                action();
            }
            catch (TException exception)
            {
                return exception;
            }

            throw new InvalidOperationException(message);
        }

        private static void Assert(bool condition, string message)
        {
            if (!condition)
            {
                throw new InvalidOperationException(message);
            }
        }

        private static void AssertEqual<T>(T expected, T actual, string message)
        {
            if (!EqualityComparer<T>.Default.Equals(expected, actual))
            {
                throw new InvalidOperationException(
                    message + " Expected=" + expected + " Actual=" + actual);
            }
        }

        private static void AssertSequenceEqual<T>(
            IReadOnlyList<T> expected,
            IReadOnlyList<T> actual,
            string message)
        {
            if (expected.Count != actual.Count)
            {
                throw new InvalidOperationException(message);
            }

            for (var index = 0; index < expected.Count; index++)
            {
                if (!EqualityComparer<T>.Default.Equals(expected[index], actual[index]))
                {
                    throw new InvalidOperationException(message);
                }
            }
        }

        private static void AssertBytesEqual(byte[] expected, byte[] actual, string message)
        {
            if (!CryptographicOperations.FixedTimeEquals(expected, actual))
            {
                throw new InvalidOperationException(message);
            }
        }

        private sealed class RecordingAuthenticatedProtector : IStateDataProtector
        {
            private static readonly byte[] Key = SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes("Guard.Storage.Tests fixed test key"));

            public byte[]? LastProtectedPlaintext { get; private set; }

            public byte[] Protect(byte[] plaintext)
            {
                LastProtectedPlaintext = (byte[])plaintext.Clone();
                var nonce = RandomNumberGenerator.GetBytes(12);
                var ciphertext = new byte[plaintext.Length];
                var tag = new byte[16];
                using (var aes = new AesGcm(Key, tag.Length))
                {
                    aes.Encrypt(nonce, plaintext, ciphertext, tag);
                }

                var result = new byte[nonce.Length + tag.Length + ciphertext.Length];
                Buffer.BlockCopy(nonce, 0, result, 0, nonce.Length);
                Buffer.BlockCopy(tag, 0, result, nonce.Length, tag.Length);
                Buffer.BlockCopy(ciphertext, 0, result, nonce.Length + tag.Length, ciphertext.Length);
                return result;
            }

            public byte[] Unprotect(byte[] protectedData)
            {
                const int nonceLength = 12;
                const int tagLength = 16;
                if (protectedData.Length <= nonceLength + tagLength)
                {
                    throw new CryptographicException("Synthetic protected payload is too short.");
                }

                var nonce = protectedData.AsSpan(0, nonceLength);
                var tag = protectedData.AsSpan(nonceLength, tagLength);
                var ciphertext = protectedData.AsSpan(nonceLength + tagLength);
                var plaintext = new byte[ciphertext.Length];
                using (var aes = new AesGcm(Key, tagLength))
                {
                    aes.Decrypt(nonce, ciphertext, tag, plaintext);
                }

                return plaintext;
            }
        }

        private sealed class InMemoryWatermark : IStateVersionWatermark
        {
            private readonly object _gate = new object();
            private readonly Dictionary<long, byte[]> _history =
                new Dictionary<long, byte[]>();
            private StateVersionWatermark? _current;

            public long? Value
            {
                get
                {
                    lock (_gate)
                    {
                        return _current?.Version;
                    }
                }
            }

            public byte[] GetCommitmentForVersion(long version)
            {
                lock (_gate)
                {
                    byte[]? commitment;
                    if (!_history.TryGetValue(version, out commitment))
                    {
                        throw new InvalidOperationException("The requested watermark version was not recorded.");
                    }

                    return (byte[])commitment.Clone();
                }
            }

            public Task<StateVersionWatermark?> GetCurrentAsync(
                CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                lock (_gate)
                {
                    if (_current == null)
                    {
                        return Task.FromResult<StateVersionWatermark?>(null);
                    }

                    return Task.FromResult<StateVersionWatermark?>(
                        new StateVersionWatermark(
                            _current.Version,
                            _current.GetStateCommitmentCopy()));
                }
            }

            public Task AdvanceToAsync(
                long version,
                byte[] stateCommitment,
                CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (version < 0)
                {
                    throw new ArgumentOutOfRangeException(nameof(version));
                }

                if (stateCommitment == null ||
                    stateCommitment.Length != StateVersionWatermark.CommitmentBytes)
                {
                    throw new ArgumentException(
                        "A complete state commitment is required.",
                        nameof(stateCommitment));
                }

                lock (_gate)
                {
                    if (_current == null)
                    {
                        if (version != 0)
                        {
                            throw new StateStoreCorruptionException(
                                "The watermark must initialize at zero.");
                        }
                    }
                    else if (version < _current.Version)
                    {
                        throw new StateRollbackDetectedException(version, _current.Version);
                    }
                    else if (version == _current.Version)
                    {
                        if (!CryptographicOperations.FixedTimeEquals(
                            stateCommitment,
                            _current.GetStateCommitmentCopy()))
                        {
                            throw new StateStoreCorruptionException(
                                "The version is bound to another state.");
                        }

                        return Task.CompletedTask;
                    }
                    else if (_current.Version == long.MaxValue ||
                             version != _current.Version + 1)
                    {
                        throw new StateStoreCorruptionException(
                            "The watermark cannot skip versions.");
                    }

                    var stored = (byte[])stateCommitment.Clone();
                    _history[version] = stored;
                    _current = new StateVersionWatermark(version, stored);
                }

                return Task.CompletedTask;
            }
        }

        private sealed class TestDirectory : IDisposable
        {
            private static readonly string BasePath = Path.GetFullPath(
                Path.Combine(Path.GetTempPath(), "Guard.Storage.Tests"));

            public TestDirectory()
            {
                PathValue = Path.GetFullPath(Path.Combine(BasePath, Guid.NewGuid().ToString("N")));
                if (!PathValue.StartsWith(BasePath + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException("Test directory escaped its dedicated temporary root.");
                }

                Directory.CreateDirectory(PathValue);
            }

            public string PathValue { get; }

            public string StatePath => Path.Combine(PathValue, "state.dat");

            public void Dispose()
            {
                var resolved = Path.GetFullPath(PathValue);
                if (!resolved.StartsWith(BasePath + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException("Refusing to delete a directory outside the test root.");
                }

                if (Directory.Exists(resolved))
                {
                    Directory.Delete(resolved, recursive: true);
                }
            }
        }
    }
}
