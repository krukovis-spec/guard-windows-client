using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using Microsoft.Extensions.Hosting.WindowsServices;

namespace Guard.Service
{
    internal interface IServiceProcessContext
    {
        bool IsWindowsService { get; }

        bool IsLocalSystem { get; }
    }

    internal sealed class WindowsServiceProcessContext : IServiceProcessContext
    {
        // Called once by Main, before the host, workers or any state files exist.
        // LocalSystem's default object owner can be Administrators. Inherited
        // SYSTEM-only DACLs do not change that owner (which has implicit WRITE_DAC).
        // Set only this process token's creation owner; never adopt/repair existing files.
        internal static void PrepareFileCreationOwner()
        {
            if (!OperatingSystem.IsWindows() || !WindowsServiceHelpers.IsWindowsService())
                throw new SecurityException("File creation owner requires the Windows service boundary.");
            using var impersonation = WindowsIdentity.GetCurrent(ifImpersonating: true);
            if (impersonation != null)
                throw new SecurityException("Service startup cannot impersonate a client.");
            using var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query | TokenAccessLevels.AdjustDefault);
            if (!identity.IsSystem || identity.User is not { } systemSid)
                throw new SecurityException("File creation owner requires LocalSystem.");

            var bytes = new byte[systemSid.BinaryLength];
            systemSid.GetBinaryForm(bytes, 0);
            var sid = Marshal.AllocHGlobal(bytes.Length);
            try
            {
                Marshal.Copy(bytes, 0, sid, bytes.Length);
                // TOKEN_OWNER is a single pointer, not the SID bytes themselves.
                if (!SetTokenInformation(identity.AccessToken, 4 /* TokenOwner */, ref sid, (uint)IntPtr.Size))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            finally { Marshal.FreeHGlobal(sid); }

            // Reopen to avoid WindowsIdentity's cached Owner property.
            using var verified = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
            if (!verified.IsSystem || verified.Owner?.Equals(systemSid) != true)
                throw new SecurityException("LocalSystem file creation owner was not applied.");
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetTokenInformation(
            SafeAccessTokenHandle token, int informationClass, ref IntPtr information, uint informationLength);

        public bool IsWindowsService => WindowsServiceHelpers.IsWindowsService();

        public bool IsLocalSystem
        {
            get
            {
                using (var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query))
                {
                    return identity.IsSystem;
                }
            }
        }
    }

    internal sealed class ServiceExecutionBoundary
    {
        private readonly IServiceProcessContext _context;

        public ServiceExecutionBoundary(IServiceProcessContext context)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
        }

        public void DemandAuthorizedServiceProcess()
        {
            if (!_context.IsWindowsService || !_context.IsLocalSystem)
            {
                throw new SecurityException("Guard.Service requires the Windows Service Control Manager and LocalSystem identity.");
            }
        }
    }
}
