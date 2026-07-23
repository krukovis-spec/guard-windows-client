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
        }

        public string SecurityRootDirectory { get; }

        public string RootDirectory { get; }

        public string StateFile { get; }

        public string StateBackupFile { get; }

        public string JournalFile { get; }

        public string WriterLeaseFile { get; }

        public static GuardDataPaths ForCurrentMachine()
        {
            return new GuardDataPaths(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
        }
    }
}
