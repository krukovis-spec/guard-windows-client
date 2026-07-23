using System;
using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Guard.Windows.Ipc
{
    public sealed class WindowsNamedPipeFactory
    {
        internal const uint PipeRejectRemoteClients = 0x00000008;
        internal const uint FileFlagFirstPipeInstance = 0x00080000;

        private const uint PipeAccessDuplex = 0x00000003;
        private const uint FileFlagOverlapped = 0x40000000;
        private const uint PipeTypeByte = 0x00000000;
        private const uint PipeReadModeByte = 0x00000000;
        private const uint PipeWait = 0x00000000;
        private const uint SecurityDescriptorRevision = 1;
        private const int MaximumInstances = 8;
        private const int BufferBytes = 64 * 1024;

        public NamedPipeServerStream Create(
            GuardPipeSecurityProfile profile,
            bool firstInstance)
        {
            if (profile == null)
            {
                throw new ArgumentNullException(nameof(profile));
            }

            var sddl = NamedPipeSecurityDescriptorFactory.CreateSddl(profile);
            IntPtr securityDescriptor;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
                sddl,
                SecurityDescriptorRevision,
                out securityDescriptor,
                IntPtr.Zero))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            try
            {
                var securityAttributes = new SecurityAttributes
                {
                    Length = Marshal.SizeOf<SecurityAttributes>(),
                    SecurityDescriptor = securityDescriptor,
                    InheritHandle = false
                };
                var openMode = PipeAccessDuplex | FileFlagOverlapped;
                if (firstInstance)
                {
                    openMode |= FileFlagFirstPipeInstance;
                }

                var pipeMode = PipeTypeByte |
                               PipeReadModeByte |
                               PipeWait |
                               PipeRejectRemoteClients;
                var handle = CreateNamedPipe(
                    @"\\.\pipe\" + profile.PipeName,
                    openMode,
                    pipeMode,
                    MaximumInstances,
                    BufferBytes,
                    BufferBytes,
                    0,
                    ref securityAttributes);
                var safeHandle = new SafePipeHandle(handle, ownsHandle: true);
                if (safeHandle.IsInvalid)
                {
                    var error = Marshal.GetLastWin32Error();
                    safeHandle.Dispose();
                    throw new Win32Exception(error);
                }

                return new NamedPipeServerStream(
                    PipeDirection.InOut,
                    isAsync: true,
                    isConnected: false,
                    safeHandle);
            }
            finally
            {
                LocalFree(securityDescriptor);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SecurityAttributes
        {
            public int Length;
            public IntPtr SecurityDescriptor;

            [MarshalAs(UnmanagedType.Bool)]
            public bool InheritHandle;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
            string stringSecurityDescriptor,
            uint stringSdRevision,
            out IntPtr securityDescriptor,
            IntPtr securityDescriptorSize);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateNamedPipe(
            string name,
            uint openMode,
            uint pipeMode,
            int maximumInstances,
            int outputBufferSize,
            int inputBufferSize,
            int defaultTimeout,
            ref SecurityAttributes securityAttributes);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr memory);
    }
}
