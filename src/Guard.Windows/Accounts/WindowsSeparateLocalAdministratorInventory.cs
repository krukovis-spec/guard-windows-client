using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using Guard.Domain;

namespace Guard.Windows.Accounts
{
    public sealed class WindowsSeparateLocalAdministratorSourceCandidate
    {
        public WindowsSeparateLocalAdministratorSourceCandidate(
            WindowsAccountSid sid,
            bool isNormalLocalUser,
            bool isEnabled,
            bool isLocked,
            bool passwordRequired,
            bool isGuest,
            bool isServiceIdentity,
            bool isEffectiveAdministrator,
            bool? isInternetIdentity = null)
        {
            Sid = sid ?? throw new ArgumentNullException(nameof(sid));
            IsNormalLocalUser = isNormalLocalUser;
            IsEnabled = isEnabled;
            IsLocked = isLocked;
            PasswordRequired = passwordRequired;
            IsGuest = isGuest;
            IsServiceIdentity = isServiceIdentity;
            IsEffectiveAdministrator = isEffectiveAdministrator;
            IsInternetIdentity = isInternetIdentity;
        }

        public WindowsAccountSid Sid { get; }
        public bool IsNormalLocalUser { get; }
        public bool IsEnabled { get; }
        public bool IsLocked { get; }
        public bool PasswordRequired { get; }
        public bool IsGuest { get; }
        public bool IsServiceIdentity { get; }
        public bool IsEffectiveAdministrator { get; }
        public bool? IsInternetIdentity { get; }
    }

    public interface IWindowsSeparateLocalAdministratorSource
    {
        IReadOnlyCollection<WindowsSeparateLocalAdministratorSourceCandidate> Enumerate(CancellationToken cancellationToken);
    }

    public sealed class WindowsSeparateLocalAdministratorInventory : ISeparateLocalAdministratorInventory
    {
        public const int MaximumCandidates = 256;
        private readonly WindowsAccountSid _authoritativeChildSid;
        private readonly IWindowsSeparateLocalAdministratorSource _source;

        public WindowsSeparateLocalAdministratorInventory(
            WindowsAccountSid authoritativeChildSid,
            IWindowsSeparateLocalAdministratorSource source)
        {
            _authoritativeChildSid = authoritativeChildSid ?? throw new ArgumentNullException(nameof(authoritativeChildSid));
            _source = source ?? throw new ArgumentNullException(nameof(source));
        }

        public SeparateLocalAdministratorInventory Get(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var sourceCandidates = _source.Enumerate(cancellationToken);
            if (sourceCandidates == null || sourceCandidates.Count > MaximumCandidates)
            {
                throw new InvalidOperationException("The administrator candidate inventory was invalid.");
            }

            var candidates = new List<SeparateLocalAdministratorCandidateFacts>(sourceCandidates.Count);
            foreach (var sourceCandidate in sourceCandidates)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (sourceCandidate == null)
                {
                    throw new InvalidOperationException("The administrator candidate inventory contained an invalid entry.");
                }

                candidates.Add(new SeparateLocalAdministratorCandidateFacts(
                    sourceCandidate.Sid,
                    sourceCandidate.IsNormalLocalUser,
                    sourceCandidate.IsEnabled,
                    sourceCandidate.IsLocked,
                    sourceCandidate.PasswordRequired,
                    sourceCandidate.IsGuest,
                    sourceCandidate.IsServiceIdentity,
                    sourceCandidate.IsEffectiveAdministrator,
                    sourceCandidate.IsInternetIdentity));
            }

            return new SeparateLocalAdministratorInventory(_authoritativeChildSid, candidates);
        }
    }

    public sealed class NativeWindowsSeparateLocalAdministratorSource : IWindowsSeparateLocalAdministratorSource
    {
        private const int ErrorSuccess = 0;
        private const int ErrorMoreData = 234;
        private const int MaximumPreferredLength = -1;
        private const int FilterNormalAccount = 2;
        private const uint UserAccountDisabled = 0x0002;
        private const uint UserPasswordNotRequired = 0x0020;
        private const uint UserLockout = 0x0010;
        private const uint UserNormalAccount = 0x0200;
        private const uint GuestRelativeId = 501;
        private readonly WindowsLocalAccountSecurityFactsProvider _securityFactsProvider;

        public NativeWindowsSeparateLocalAdministratorSource()
            : this(new WindowsLocalAccountSecurityFactsProvider())
        {
        }

        public NativeWindowsSeparateLocalAdministratorSource(WindowsLocalAccountSecurityFactsProvider securityFactsProvider)
        {
            _securityFactsProvider = securityFactsProvider ?? throw new ArgumentNullException(nameof(securityFactsProvider));
        }

        public IReadOnlyCollection<WindowsSeparateLocalAdministratorSourceCandidate> Enumerate(CancellationToken cancellationToken)
        {
            if (!OperatingSystem.IsWindows())
            {
                throw new PlatformNotSupportedException();
            }

            var candidates = new List<WindowsSeparateLocalAdministratorSourceCandidate>();
            var resumeHandle = IntPtr.Zero;
            var pageCount = 0;
            do
            {
                cancellationToken.ThrowIfCancellationRequested();
                pageCount++;
                if (pageCount >
                    WindowsSeparateLocalAdministratorInventory
                        .MaximumCandidates + 1)
                {
                    throw new InvalidOperationException(
                        "The local user inventory exceeded its page bound.");
                }

                IntPtr buffer;
                int entriesRead;
                int totalEntries;
                var status = NetUserEnum(null, 4, FilterNormalAccount, out buffer, MaximumPreferredLength, out entriesRead, out totalEntries, ref resumeHandle);
                try
                {
                    if (status != ErrorSuccess && status != ErrorMoreData)
                    {
                        throw new InvalidOperationException("Local user enumeration failed.");
                    }

                    var itemSize = Marshal.SizeOf<UserInfo4>();
                    for (var index = 0; index < entriesRead; index++)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        if (candidates.Count >= WindowsSeparateLocalAdministratorInventory.MaximumCandidates)
                        {
                            throw new InvalidOperationException("The local user inventory exceeded its bound.");
                        }

                        var information = Marshal.PtrToStructure<UserInfo4>(IntPtr.Add(buffer, checked(index * itemSize)));
                        if (information.UserSid == IntPtr.Zero)
                        {
                            throw new InvalidOperationException("A local user did not have a SID.");
                        }

                        var sid = new WindowsAccountSid(new SecurityIdentifier(information.UserSid).Value);
                        LocalAccountSecurityFacts facts;
                        if (!_securityFactsProvider.TryGet(sid, out facts) || facts == null || !facts.IsLocalUser)
                        {
                            throw new InvalidOperationException("A local account could not be classified safely.");
                        }

                        var flags = information.Flags;
                        candidates.Add(new WindowsSeparateLocalAdministratorSourceCandidate(
                            sid,
                            (flags & UserNormalAccount) != 0,
                            (flags & UserAccountDisabled) == 0,
                            (flags & UserLockout) != 0,
                            (flags & UserPasswordNotRequired) == 0,
                            HasRelativeId(sid.Value, GuestRelativeId),
                            facts.IsServiceIdentity,
                            facts.IsAdministrator,
                            facts.IsAdministrator ? ReadInternetIdentity(information.Name) : null));
                    }
                }
                finally
                {
                    if (buffer != IntPtr.Zero)
                    {
                        NetApiBufferFree(buffer);
                    }
                }

                if (status == ErrorSuccess)
                {
                    break;
                }
            }
            while (true);

            return candidates;
        }

        private static bool? ReadInternetIdentity(IntPtr namePointer)
        {
            var accountName = Marshal.PtrToStringUni(namePointer);
            if (string.IsNullOrEmpty(accountName)) return null;
            // USER_INFO_24 distinguishes a SAM account from a Microsoft/Internet-linked identity.
            // Never read or log the provider address, email or password.
            var status = NetUserGetInfo(null, accountName, 24, out var buffer);
            try
            {
                if (status != ErrorSuccess || buffer == IntPtr.Zero) return null;
                var information = Marshal.PtrToStructure<UserInfo24>(buffer);
                return information.InternetIdentity != 0;
            }
            finally { if (buffer != IntPtr.Zero) NetApiBufferFree(buffer); }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct UserInfo24
        {
            public int InternetIdentity;
            public uint Flags;
            public IntPtr ProviderName;
            public IntPtr PrincipalName;
            public IntPtr UserSid;
        }

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetUserGetInfo(string? serverName, string userName, int level, out IntPtr buffer);

        private static bool HasRelativeId(string sid, uint relativeId)
        {
            var parts = sid.Split('-');
            uint parsed;
            return parts.Length > 0 && uint.TryParse(parts[parts.Length - 1], out parsed) && parsed == relativeId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct UserInfo4
        {
            public IntPtr Name;
            public IntPtr Password;
            public uint PasswordAge;
            public uint Privilege;
            public IntPtr HomeDirectory;
            public IntPtr Comment;
            public uint Flags;
            public IntPtr ScriptPath;
            public uint AuthFlags;
            public IntPtr FullName;
            public IntPtr UserComment;
            public IntPtr Parameters;
            public IntPtr Workstations;
            public uint LastLogon;
            public uint LastLogoff;
            public uint AccountExpires;
            public uint MaxStorage;
            public uint UnitsPerWeek;
            public IntPtr LogonHours;
            public uint BadPasswordCount;
            public uint NumberOfLogons;
            public IntPtr LogonServer;
            public uint CountryCode;
            public uint CodePage;
            public IntPtr UserSid;
            public uint PrimaryGroupId;
            public IntPtr Profile;
            public IntPtr HomeDirectoryDrive;
            public uint PasswordExpired;
        }

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetUserEnum(
            string? serverName,
            int level,
            int filter,
            out IntPtr buffer,
            int preferredMaximumLength,
            out int entriesRead,
            out int totalEntries,
            ref IntPtr resumeHandle);

        [DllImport("netapi32.dll")]
        private static extern int NetApiBufferFree(IntPtr buffer);
    }
}
