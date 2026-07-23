using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace Guard.Windows.Ipc
{
    public sealed class WindowsPipeClientTokenFactsResolver
    {
        public PipeClientTokenFacts Resolve(NamedPipeServerStream connectedPipe)
        {
            if (connectedPipe == null)
            {
                throw new ArgumentNullException(nameof(connectedPipe));
            }

            if (!connectedPipe.IsConnected)
            {
                throw new InvalidOperationException("A connected named pipe is required.");
            }

            PipeClientTokenFacts? facts = null;
            connectedPipe.RunAsClient(() =>
            {
                using (var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query))
                {
                    if (identity.User == null || !identity.IsAuthenticated)
                    {
                        throw new UnauthorizedAccessException("The pipe client has no authenticated user SID.");
                    }

                    var groups = new List<string>();
                    if (identity.Groups != null)
                    {
                        foreach (var group in identity.Groups)
                        {
                            var sid = group as SecurityIdentifier;
                            if (sid != null)
                            {
                                groups.Add(sid.Value);
                            }
                        }
                    }

                    facts = new PipeClientTokenFacts(
                        identity.User.Value,
                        groups,
                        ReadElevation(identity.AccessToken),
                        ReadIntegrityLevel(identity.AccessToken),
                        isRemote: false);
                }
            });

            return facts ?? throw new UnauthorizedAccessException(
                "The pipe client token could not be captured.");
        }

        private static bool ReadElevation(SafeAccessTokenHandle token)
        {
            var size = Marshal.SizeOf<TokenElevation>();
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                int returned;
                if (!GetTokenInformation(
                    token,
                    TokenInformationClass.TokenElevation,
                    buffer,
                    size,
                    out returned) ||
                    returned < size)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                return Marshal.PtrToStructure<TokenElevation>(buffer).IsElevated != 0;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static int ReadIntegrityLevel(SafeAccessTokenHandle token)
        {
            int required;
            GetTokenInformation(
                token,
                TokenInformationClass.TokenIntegrityLevel,
                IntPtr.Zero,
                0,
                out required);
            if (required <= 0)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            var buffer = Marshal.AllocHGlobal(required);
            try
            {
                int returned;
                if (!GetTokenInformation(
                    token,
                    TokenInformationClass.TokenIntegrityLevel,
                    buffer,
                    required,
                    out returned) ||
                    returned < Marshal.SizeOf<TokenMandatoryLabel>())
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                var label = Marshal.PtrToStructure<TokenMandatoryLabel>(buffer);
                if (label.Label.Sid == IntPtr.Zero)
                {
                    throw new UnauthorizedAccessException("The pipe client token has no integrity SID.");
                }

                var integritySid = new SecurityIdentifier(label.Label.Sid);
                var parts = integritySid.Value.Split('-');
                int rid;
                if (parts.Length == 0 ||
                    !int.TryParse(parts[parts.Length - 1], out rid))
                {
                    throw new UnauthorizedAccessException("The pipe client integrity SID is invalid.");
                }

                return rid;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private enum TokenInformationClass
        {
            TokenElevation = 20,
            TokenIntegrityLevel = 25
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TokenElevation
        {
            public int IsElevated;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SidAndAttributes
        {
            public IntPtr Sid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TokenMandatoryLabel
        {
            public SidAndAttributes Label;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetTokenInformation(
            SafeAccessTokenHandle tokenHandle,
            TokenInformationClass tokenInformationClass,
            IntPtr tokenInformation,
            int tokenInformationLength,
            out int returnLength);
    }
}
