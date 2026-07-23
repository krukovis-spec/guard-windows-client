using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Guard.Domain;

namespace Guard.Windows.Accounts
{
    public sealed class WindowsLocalAccountSecurityFactsProvider :
        ILocalAccountSecurityFactsProvider
    {
        private const int ErrorSuccess = 0;
        private const int ErrorInsufficientBuffer = 122;
        private const int MaximumPreferredLength = -1;
        private const int IncludeIndirectLocalGroups = 1;
        private const uint UserAccountDisabled = 0x0002;
        private const uint UserNormalAccount = 0x0200;
        private const uint GuestRelativeId = 501;
        private const string LocalSystemSid = "S-1-5-18";
        private const string LocalServiceSid = "S-1-5-19";
        private const string NetworkServiceSid = "S-1-5-20";

        public bool TryGet(
            WindowsAccountSid candidateSid,
            out LocalAccountSecurityFacts facts)
        {
            if (candidateSid == null)
            {
                throw new ArgumentNullException(nameof(candidateSid));
            }

            facts = null!;
            if (!OperatingSystem.IsWindows())
            {
                return false;
            }

            var sid = new SecurityIdentifier(candidateSid.Value);
            string accountName;
            string accountDomain;
            SidNameUse sidType;
            if (!TryLookupAccount(sid, out accountName, out accountDomain, out sidType))
            {
                return false;
            }

            var isLocalUser =
                sidType == SidNameUse.User &&
                string.Equals(accountDomain, Environment.MachineName, StringComparison.OrdinalIgnoreCase);
            var isEnabled = false;
            if (isLocalUser)
            {
                isEnabled = IsEnabledNormalLocalUser(accountName);
            }

            var isAdministrator =
                isLocalUser &&
                IsMemberOfBuiltinAdministrators(accountName);
            var value = candidateSid.Value;
            facts = new LocalAccountSecurityFacts(
                candidateSid,
                exists: true,
                isLocalUser: isLocalUser,
                isEnabled: isEnabled,
                isGuest: HasRelativeId(sid, GuestRelativeId),
                isServiceIdentity:
                    string.Equals(value, LocalSystemSid, StringComparison.Ordinal) ||
                    string.Equals(value, LocalServiceSid, StringComparison.Ordinal) ||
                    string.Equals(value, NetworkServiceSid, StringComparison.Ordinal),
                isAdministrator: isAdministrator);
            return true;
        }

        private static bool IsEnabledNormalLocalUser(string accountName)
        {
            IntPtr buffer;
            var status = NetUserGetInfo(null, accountName, 1, out buffer);
            if (status != ErrorSuccess)
            {
                return false;
            }

            try
            {
                var information = Marshal.PtrToStructure<UserInfo1>(buffer);
                return (information.Flags & UserAccountDisabled) == 0 &&
                       (information.Flags & UserNormalAccount) != 0;
            }
            finally
            {
                NetApiBufferFree(buffer);
            }
        }

        private static bool IsMemberOfBuiltinAdministrators(string accountName)
        {
            var administrators = new SecurityIdentifier(
                WellKnownSidType.BuiltinAdministratorsSid,
                domainSid: null);
            string groupName;
            string ignoredDomain;
            SidNameUse ignoredUse;
            if (!TryLookupAccount(administrators, out groupName, out ignoredDomain, out ignoredUse))
            {
                throw new Win32Exception("The local Administrators group could not be resolved.");
            }

            IntPtr buffer;
            int entriesRead;
            int totalEntries;
            var status = NetUserGetLocalGroups(
                null,
                accountName,
                0,
                IncludeIndirectLocalGroups,
                out buffer,
                MaximumPreferredLength,
                out entriesRead,
                out totalEntries);
            if (status != ErrorSuccess)
            {
                if (buffer != IntPtr.Zero)
                {
                    NetApiBufferFree(buffer);
                }

                throw new Win32Exception(status);
            }

            try
            {
                var itemSize = Marshal.SizeOf<LocalGroupUsersInfo0>();
                for (var index = 0; index < entriesRead; index++)
                {
                    var item = Marshal.PtrToStructure<LocalGroupUsersInfo0>(
                        IntPtr.Add(buffer, checked(index * itemSize)));
                    var candidateGroupName = item.Name == IntPtr.Zero
                        ? string.Empty
                        : Marshal.PtrToStringUni(item.Name) ?? string.Empty;
                    if (string.Equals(
                        candidateGroupName,
                        groupName,
                        StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }

                return false;
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                {
                    NetApiBufferFree(buffer);
                }
            }
        }

        private static bool TryLookupAccount(
            SecurityIdentifier sid,
            out string accountName,
            out string accountDomain,
            out SidNameUse sidType)
        {
            var sidBytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(sidBytes, 0);
            uint nameLength = 0;
            uint domainLength = 0;
            LookupAccountSid(
                null,
                sidBytes,
                null,
                ref nameLength,
                null,
                ref domainLength,
                out sidType);
            var error = Marshal.GetLastWin32Error();
            if (error != ErrorInsufficientBuffer || nameLength == 0 || domainLength == 0)
            {
                accountName = string.Empty;
                accountDomain = string.Empty;
                return false;
            }

            var name = new StringBuilder(checked((int)nameLength));
            var domain = new StringBuilder(checked((int)domainLength));
            if (!LookupAccountSid(
                null,
                sidBytes,
                name,
                ref nameLength,
                domain,
                ref domainLength,
                out sidType))
            {
                accountName = string.Empty;
                accountDomain = string.Empty;
                return false;
            }

            accountName = name.ToString();
            accountDomain = domain.ToString();
            return true;
        }

        private static bool HasRelativeId(SecurityIdentifier sid, uint relativeId)
        {
            var parts = sid.Value.Split('-');
            uint parsed;
            return parts.Length > 0 &&
                   uint.TryParse(parts[parts.Length - 1], out parsed) &&
                   parsed == relativeId;
        }

        private enum SidNameUse
        {
            User = 1,
            Group = 2,
            Domain = 3,
            Alias = 4,
            WellKnownGroup = 5,
            DeletedAccount = 6,
            Invalid = 7,
            Unknown = 8,
            Computer = 9,
            Label = 10
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct UserInfo1
        {
            public IntPtr Name;
            public IntPtr Password;
            public uint PasswordAge;
            public uint Privilege;
            public IntPtr HomeDirectory;
            public IntPtr Comment;
            public uint Flags;
            public IntPtr ScriptPath;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LocalGroupUsersInfo0
        {
            public IntPtr Name;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool LookupAccountSid(
            string? systemName,
            byte[] sid,
            StringBuilder? name,
            ref uint nameLength,
            StringBuilder? referencedDomainName,
            ref uint domainNameLength,
            out SidNameUse use);

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetUserGetInfo(
            string? serverName,
            string userName,
            int level,
            out IntPtr buffer);

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetUserGetLocalGroups(
            string? serverName,
            string userName,
            int level,
            int flags,
            out IntPtr buffer,
            int preferredMaximumLength,
            out int entriesRead,
            out int totalEntries);

        [DllImport("netapi32.dll")]
        private static extern int NetApiBufferFree(IntPtr buffer);
    }
}
