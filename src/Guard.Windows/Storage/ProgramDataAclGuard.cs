using System;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Guard.Windows.Storage
{
    public sealed class ProgramDataAclRuleFacts
    {
        public ProgramDataAclRuleFacts(
            string sid,
            FileSystemRights rights,
            AccessControlType accessControlType,
            InheritanceFlags inheritanceFlags,
            PropagationFlags propagationFlags,
            bool isInherited)
        {
            Sid = sid ?? string.Empty;
            Rights = rights;
            AccessControlType = accessControlType;
            InheritanceFlags = inheritanceFlags;
            PropagationFlags = propagationFlags;
            IsInherited = isInherited;
        }

        public string Sid { get; }

        public FileSystemRights Rights { get; }

        public AccessControlType AccessControlType { get; }

        public InheritanceFlags InheritanceFlags { get; }

        public PropagationFlags PropagationFlags { get; }

        public bool IsInherited { get; }
    }

    public static class ProgramDataAclPolicy
    {
        private const string LocalSystemSid = "S-1-5-18";

        public static bool IsServiceOnly(
            string ownerSid,
            bool accessRulesProtected,
            IReadOnlyList<ProgramDataAclRuleFacts> rules)
        {
            if (!string.Equals(ownerSid, LocalSystemSid, StringComparison.Ordinal) ||
                !accessRulesProtected ||
                rules == null ||
                rules.Count == 0)
            {
                return false;
            }

            var hasSystemFullControl = false;
            for (var index = 0; index < rules.Count; index++)
            {
                var rule = rules[index];
                if (rule == null ||
                    rule.IsInherited ||
                    !string.Equals(rule.Sid, LocalSystemSid, StringComparison.Ordinal) ||
                    rule.AccessControlType != AccessControlType.Allow ||
                    (rule.Rights & FileSystemRights.FullControl) != FileSystemRights.FullControl ||
                    (rule.InheritanceFlags & InheritanceFlags.ContainerInherit) == 0 ||
                    (rule.InheritanceFlags & InheritanceFlags.ObjectInherit) == 0 ||
                    rule.PropagationFlags != PropagationFlags.None)
                {
                    return false;
                }

                hasSystemFullControl = true;
            }

            return hasSystemFullControl;
        }

        public static bool IsServiceOnlyFile(
            string ownerSid,
            IReadOnlyList<ProgramDataAclRuleFacts> rules)
        {
            if (!string.Equals(ownerSid, LocalSystemSid, StringComparison.Ordinal) ||
                rules == null ||
                rules.Count == 0)
            {
                return false;
            }

            var hasSystemFullControl = false;
            for (var index = 0; index < rules.Count; index++)
            {
                var rule = rules[index];
                if (rule == null ||
                    !string.Equals(rule.Sid, LocalSystemSid, StringComparison.Ordinal) ||
                    rule.AccessControlType != AccessControlType.Allow ||
                    (rule.Rights & FileSystemRights.FullControl) != FileSystemRights.FullControl)
                {
                    return false;
                }

                hasSystemFullControl = true;
            }

            return hasSystemFullControl;
        }
    }

    public sealed class ProgramDataAclGuard
    {
        public void EnsureServiceOnlyDirectory(string directoryPath)
        {
            if (string.IsNullOrWhiteSpace(directoryPath) ||
                !Path.IsPathFullyQualified(directoryPath))
            {
                throw new ArgumentException(
                    "An absolute Guard data directory is required.",
                    nameof(directoryPath));
            }

            if (!OperatingSystem.IsWindows())
            {
                throw new PlatformNotSupportedException(
                    "Guard service storage ACLs require Windows.");
            }

            var directory = new DirectoryInfo(
                Path.GetFullPath(directoryPath));
            if (!directory.Exists)
            {
                var localSystem = new SecurityIdentifier(
                    WellKnownSidType.LocalSystemSid,
                    domainSid: null);
                var security = new DirectorySecurity();
                security.SetOwner(localSystem);
                security.SetAccessRuleProtection(
                    isProtected: true,
                    preserveInheritance: false);
                security.AddAccessRule(new FileSystemAccessRule(
                    localSystem,
                    FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit |
                        InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow));

                // This overload creates the directory with its final DACL in
                // one operation, so no broadly accessible intermediate state
                // is exposed.
                directory.Create(security);
            }

            DemandServiceOnlyDirectory(directory.FullName);
        }

        public void DemandServiceOnlyDirectory(string directoryPath)
        {
            if (string.IsNullOrWhiteSpace(directoryPath) ||
                !Path.IsPathFullyQualified(directoryPath))
            {
                throw new ArgumentException("An absolute Guard data directory is required.", nameof(directoryPath));
            }

            var directory = new DirectoryInfo(Path.GetFullPath(directoryPath));
            if (!directory.Exists)
            {
                throw new DirectoryNotFoundException("The Guard service data directory is missing.");
            }

            if ((directory.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new UnauthorizedAccessException("The Guard service data directory cannot be a reparse point.");
            }

            var security = directory.GetAccessControl(
                AccessControlSections.Owner | AccessControlSections.Access);
            var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
            if (owner == null)
            {
                throw new UnauthorizedAccessException("The Guard service data directory owner is unavailable.");
            }

            var accessRules = security.GetAccessRules(
                includeExplicit: true,
                includeInherited: true,
                targetType: typeof(SecurityIdentifier));
            var facts = new List<ProgramDataAclRuleFacts>();
            foreach (FileSystemAccessRule rule in accessRules)
            {
                var sid = rule.IdentityReference as SecurityIdentifier;
                facts.Add(new ProgramDataAclRuleFacts(
                    sid?.Value ?? string.Empty,
                    rule.FileSystemRights,
                    rule.AccessControlType,
                    rule.InheritanceFlags,
                    rule.PropagationFlags,
                    rule.IsInherited));
            }

            if (!ProgramDataAclPolicy.IsServiceOnly(
                owner.Value,
                security.AreAccessRulesProtected,
                facts))
            {
                throw new UnauthorizedAccessException("The Guard service data directory ACL is not service-only.");
            }
        }

        public void DemandServiceOnlyFileIfPresent(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath) ||
                !Path.IsPathFullyQualified(filePath))
            {
                throw new ArgumentException(
                    "An absolute Guard state file path is required.",
                    nameof(filePath));
            }

            var file = new FileInfo(Path.GetFullPath(filePath));
            if (!file.Exists)
            {
                return;
            }

            if ((file.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new UnauthorizedAccessException(
                    "A Guard service state file cannot be a reparse point.");
            }

            var security = file.GetAccessControl(
                AccessControlSections.Owner | AccessControlSections.Access);
            var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
            if (owner == null)
            {
                throw new UnauthorizedAccessException(
                    "The Guard service state-file owner is unavailable.");
            }

            var accessRules = security.GetAccessRules(
                includeExplicit: true,
                includeInherited: true,
                targetType: typeof(SecurityIdentifier));
            var facts = new List<ProgramDataAclRuleFacts>();
            foreach (FileSystemAccessRule rule in accessRules)
            {
                var sid = rule.IdentityReference as SecurityIdentifier;
                facts.Add(new ProgramDataAclRuleFacts(
                    sid?.Value ?? string.Empty,
                    rule.FileSystemRights,
                    rule.AccessControlType,
                    rule.InheritanceFlags,
                    rule.PropagationFlags,
                    rule.IsInherited));
            }

            if (!ProgramDataAclPolicy.IsServiceOnlyFile(owner.Value, facts))
            {
                throw new UnauthorizedAccessException(
                    "A Guard service state-file ACL is not service-only.");
            }
        }
    }
}
