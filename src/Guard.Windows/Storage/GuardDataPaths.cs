using System;
using System.IO;

namespace Guard.Windows.Storage
{
    public sealed class GuardDataPaths
    {
        public GuardDataPaths(string commonApplicationData)
        {
            if (string.IsNullOrWhiteSpace(commonApplicationData) ||
                !Path.IsPathFullyQualified(commonApplicationData))
            {
                throw new ArgumentException("An absolute ProgramData root is required.", nameof(commonApplicationData));
            }

            var root = Path.GetFullPath(commonApplicationData)
                .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            SecurityRootDirectory = Path.Combine(root, "Guard");
            RootDirectory = Path.Combine(SecurityRootDirectory, "v2");
            StateFile = Path.Combine(RootDirectory, "state.dat");
            StateBackupFile = StateFile + ".bak";
            JournalFile = Path.Combine(RootDirectory, "state.journal");
            WriterLeaseFile = StateFile + ".writer.lock";
            RelayRootDirectory = Path.Combine(RootDirectory, "relay");
            RelayStateFile = Path.Combine(RelayRootDirectory, "state.dat");
            RelayStateBackupFile = RelayStateFile + ".bak";
            RelayJournalFile = Path.Combine(
                RelayRootDirectory,
                "state.journal");
            RelayWriterLeaseFile = RelayStateFile + ".writer.lock";
        }

        public string SecurityRootDirectory { get; }

        public string RootDirectory { get; }

        public string StateFile { get; }

        public string StateBackupFile { get; }

        public string JournalFile { get; }

        public string WriterLeaseFile { get; }

        public string RelayRootDirectory { get; }

        public string RelayStateFile { get; }

        public string RelayStateBackupFile { get; }

        public string RelayJournalFile { get; }

        public string RelayWriterLeaseFile { get; }

        public static GuardDataPaths ForCurrentMachine()
        {
            return new GuardDataPaths(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
        }
    }
}
