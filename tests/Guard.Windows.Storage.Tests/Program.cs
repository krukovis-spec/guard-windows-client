using System;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using Guard.Windows.Storage;

namespace Guard.Windows.Storage.Tests
{
    internal static class Program
    {
        private static int Main()
        {
            var tests = new List<(string Name, Action Run)>
            {
                ("uses only the fixed ProgramData Guard v2 paths", UsesFixedPaths),
                ("accepts only protected LocalSystem full-control ACL facts", AcceptsOnlyServiceAcl),
                ("rejects inherited broad and non-System ACL facts", RejectsUnsafeAclFacts),
                ("accepts only System-owned service-only state files", AcceptsOnlyServiceFiles)
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
                    Console.WriteLine("FAIL " + test.Name + ": " + exception.Message);
                }
            }

            Console.WriteLine(failures == 0
                ? "All Guard Windows storage-boundary checks passed."
                : failures + " Guard Windows storage-boundary check(s) failed.");
            return failures == 0 ? 0 : 1;
        }

        private static void UsesFixedPaths()
        {
            var root = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "program-data-root"));
            var paths = new GuardDataPaths(root);
            var securityRoot = Path.Combine(
                root.TrimEnd(Path.DirectorySeparatorChar),
                "Guard");
            var expected = Path.Combine(securityRoot, "v2");
            Assert(
                string.Equals(
                    paths.SecurityRootDirectory,
                    securityRoot,
                    StringComparison.OrdinalIgnoreCase),
                "Guard security root was not fixed directly under ProgramData.");
            Assert(string.Equals(paths.RootDirectory, expected, StringComparison.OrdinalIgnoreCase), "Guard data root was not fixed under ProgramData.");
            Assert(string.Equals(paths.StateFile, Path.Combine(expected, "state.dat"), StringComparison.OrdinalIgnoreCase), "State path changed.");
            Assert(
                string.Equals(
                    paths.StateBackupFile,
                    paths.StateFile + ".bak",
                    StringComparison.OrdinalIgnoreCase),
                "State backup path diverged from the authoritative store.");
            Assert(
                string.Equals(
                    paths.WriterLeaseFile,
                    paths.StateFile + ".writer.lock",
                    StringComparison.OrdinalIgnoreCase),
                "Documented writer lease path diverged from the authoritative store.");
            AssertThrows(() => new GuardDataPaths("relative-path"));
        }

        private static void AcceptsOnlyServiceAcl()
        {
            var rules = new[]
            {
                Rule("S-1-5-18", inherited: false)
            };
            Assert(
                ProgramDataAclPolicy.IsServiceOnly("S-1-5-18", accessRulesProtected: true, rules),
                "Expected service-only ACL facts were rejected.");
        }

        private static void RejectsUnsafeAclFacts()
        {
            Assert(!ProgramDataAclPolicy.IsServiceOnly(
                "S-1-5-32-544",
                accessRulesProtected: true,
                new[] { Rule("S-1-5-18", inherited: false) }),
                "Administrators owner was accepted.");
            Assert(!ProgramDataAclPolicy.IsServiceOnly(
                "S-1-5-18",
                accessRulesProtected: false,
                new[] { Rule("S-1-5-18", inherited: false) }),
                "Inherited DACL was accepted.");
            Assert(!ProgramDataAclPolicy.IsServiceOnly(
                "S-1-5-18",
                accessRulesProtected: true,
                new[] { Rule("S-1-5-18", inherited: false), Rule("S-1-5-32-545", inherited: false) }),
                "BUILTIN Users access was accepted.");
            Assert(!ProgramDataAclPolicy.IsServiceOnly(
                "S-1-5-18",
                accessRulesProtected: true,
                new[] { Rule("S-1-5-18", inherited: true) }),
                "Inherited SYSTEM rule was accepted.");
        }

        private static void AcceptsOnlyServiceFiles()
        {
            Assert(
                ProgramDataAclPolicy.IsServiceOnlyFile(
                    "S-1-5-18",
                    new[] { Rule("S-1-5-18", inherited: true) }),
                "A safely inherited SYSTEM-only state-file ACL was rejected.");
            Assert(!ProgramDataAclPolicy.IsServiceOnlyFile(
                "S-1-5-32-544",
                new[] { Rule("S-1-5-18", inherited: true) }),
                "A non-SYSTEM state-file owner was accepted.");
            Assert(!ProgramDataAclPolicy.IsServiceOnlyFile(
                "S-1-5-18",
                new[]
                {
                    Rule("S-1-5-18", inherited: true),
                    Rule("S-1-5-32-545", inherited: false)
                }),
                "A broad explicit state-file ACE was accepted.");
        }

        private static ProgramDataAclRuleFacts Rule(string sid, bool inherited)
        {
            return new ProgramDataAclRuleFacts(
                sid,
                FileSystemRights.FullControl,
                AccessControlType.Allow,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                inherited);
        }

        private static void AssertThrows(Action action)
        {
            try
            {
                action();
            }
            catch (ArgumentException)
            {
                return;
            }

            throw new InvalidOperationException("Expected an invalid data-root path.");
        }

        private static void Assert(bool condition, string message)
        {
            if (!condition)
            {
                throw new InvalidOperationException(message);
            }
        }
    }
}
