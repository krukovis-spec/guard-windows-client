using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Guard.Windows.Services
{
    /// <summary>Minimal, query-only SCM boundary. Implementations must not mutate service state.</summary>
    public interface IWindowsScmNativeApi
    {
        ScmServiceOpenResult OpenForQuery(string serviceName);
    }

    public interface IScmQuerySession : IDisposable
    {
        ScmServiceConfiguration ReadConfiguration();

        uint ReadCurrentState();
    }

    public sealed class ScmServiceOpenResult
    {
        private ScmServiceOpenResult(ScmServiceOpenState state, IScmQuerySession? session)
        {
            State = state;
            Session = session;
        }

        public ScmServiceOpenState State { get; }

        public IScmQuerySession? Session { get; }

        public static ScmServiceOpenResult Found(IScmQuerySession session)
        {
            return new ScmServiceOpenResult(ScmServiceOpenState.Found, session ?? throw new ArgumentNullException(nameof(session)));
        }

        public static ScmServiceOpenResult NotFound()
        {
            return new ScmServiceOpenResult(ScmServiceOpenState.NotFound, null);
        }

        public static ScmServiceOpenResult Error()
        {
            return new ScmServiceOpenResult(ScmServiceOpenState.Error, null);
        }
    }

    public enum ScmServiceOpenState { Found = 1, NotFound = 2, Error = 3 }

    public sealed class ScmServiceConfiguration
    {
        public ScmServiceConfiguration(uint startType, bool delayedAutoStart, string? accountName, string? binaryPath)
        {
            StartType = startType;
            DelayedAutoStart = delayedAutoStart;
            AccountName = accountName;
            BinaryPath = binaryPath;
        }

        public uint StartType { get; }
        public bool DelayedAutoStart { get; }
        public string? AccountName { get; }
        public string? BinaryPath { get; }
    }

    public interface IServiceAccountSidClassifier
    {
        bool TryGetSid(string accountName, out string sid);
    }

    public sealed class WindowsServiceHealthQuery : IServiceHealthQuery
    {
        internal const int MaximumAccountNameLength = 512;
        internal const int MaximumBinaryPathLength = 32768;

        private readonly IWindowsScmNativeApi _native;
        private readonly IServiceAccountSidClassifier _accountClassifier;

        public WindowsServiceHealthQuery()
            : this(new WindowsScmNativeApi(), new WindowsServiceAccountSidClassifier()) { }

        public WindowsServiceHealthQuery(IWindowsScmNativeApi native, IServiceAccountSidClassifier accountClassifier)
        {
            _native = native ?? throw new ArgumentNullException(nameof(native));
            _accountClassifier = accountClassifier ?? throw new ArgumentNullException(nameof(accountClassifier));
        }

        public ServiceHealthProbeResult Query(string serviceName)
        {
            if (!IsBoundedServiceName(serviceName))
            {
                return Error();
            }

            try
            {
                var opened = _native.OpenForQuery(serviceName);
                if (opened == null || opened.State == ScmServiceOpenState.Error)
                {
                    return Error();
                }

                if (opened.State == ScmServiceOpenState.NotFound)
                {
                    return new ServiceHealthProbeResult(ServiceHealthProbeState.NotFound, null);
                }

                if (opened.State != ScmServiceOpenState.Found || opened.Session == null)
                {
                    return Error();
                }

                using (opened.Session)
                {
                    var configuration = opened.Session.ReadConfiguration();
                    if (configuration == null ||
                        !TryBounded(configuration.AccountName, MaximumAccountNameLength, out var accountName) ||
                        !TryBounded(configuration.BinaryPath, MaximumBinaryPathLength, out var binaryPath) ||
                        !_accountClassifier.TryGetSid(accountName, out var accountSid) ||
                        !TryMapStartMode(configuration.StartType, configuration.DelayedAutoStart, out var startMode) ||
                        !TryMapRunState(opened.Session.ReadCurrentState(), out var runState))
                    {
                        return Error();
                    }

                    return new ServiceHealthProbeResult(
                        ServiceHealthProbeState.Found,
                        new ServiceHealthFacts(true, accountSid, startMode, runState, binaryPath));
                }
            }
            catch (Exception)
            {
                return Error();
            }
        }

        private static bool TryBounded(string? value, int maximumLength, out string bounded)
        {
            bounded = string.Empty;
            if (string.IsNullOrWhiteSpace(value) ||
                value.Length > maximumLength)
            {
                return false;
            }

            for (var index = 0; index < value.Length; index++)
            {
                if (char.IsControl(value[index]))
                {
                    return false;
                }
            }

            bounded = value;
            return true;
        }

        private static bool IsBoundedServiceName(string? serviceName)
        {
            if (string.IsNullOrWhiteSpace(serviceName) ||
                serviceName.Length > 256)
            {
                return false;
            }

            for (var index = 0; index < serviceName.Length; index++)
            {
                if (char.IsControl(serviceName[index]))
                {
                    return false;
                }
            }

            return true;
        }

        private static bool TryMapStartMode(uint startType, bool delayed, out GuardServiceStartMode value)
        {
            value = GuardServiceStartMode.Unspecified;
            if (startType == 2)
            {
                value = delayed ? GuardServiceStartMode.AutomaticDelayed : GuardServiceStartMode.Automatic;
                return true;
            }

            if (delayed)
            {
                return false;
            }

            if (startType == 3)
            {
                value = GuardServiceStartMode.Manual;
                return true;
            }

            if (startType == 4)
            {
                value = GuardServiceStartMode.Disabled;
                return true;
            }

            return false;
        }

        private static bool TryMapRunState(uint state, out GuardServiceRunState value)
        {
            value = GuardServiceRunState.Unspecified;
            switch (state)
            {
                case 1: value = GuardServiceRunState.Stopped; return true;
                case 2: value = GuardServiceRunState.StartPending; return true;
                case 3: value = GuardServiceRunState.StopPending; return true;
                case 4: value = GuardServiceRunState.Running; return true;
                case 7: value = GuardServiceRunState.Paused; return true;
                default: return false;
            }
        }

        private static ServiceHealthProbeResult Error()
        {
            return new ServiceHealthProbeResult(ServiceHealthProbeState.Error, null);
        }
    }

    public sealed class WindowsServiceAccountSidClassifier : IServiceAccountSidClassifier
    {
        public bool TryGetSid(string accountName, out string sid)
        {
            sid = string.Empty;
            if (string.IsNullOrWhiteSpace(accountName) || accountName.Length > WindowsServiceHealthQuery.MaximumAccountNameLength)
            {
                return false;
            }

            try
            {
                var identity = new NTAccount(accountName).Translate(typeof(SecurityIdentifier)) as SecurityIdentifier;
                if (identity == null)
                {
                    return false;
                }

                sid = identity.Value;
                return !string.IsNullOrWhiteSpace(sid);
            }
            catch (IdentityNotMappedException) { return false; }
            catch (SystemException) { return false; }
        }
    }

    public sealed class WindowsScmNativeApi : IWindowsScmNativeApi
    {
        private const uint ScManagerConnect = 0x0001;
        private const uint ServiceQueryConfig = 0x0001;
        private const uint ServiceQueryStatus = 0x0004;
        private const int ErrorServiceDoesNotExist = 1060;
        private const int ErrorInsufficientBuffer = 122;

        public ScmServiceOpenResult OpenForQuery(string serviceName)
        {
            var manager = NativeMethods.OpenSCManager(null, null, ScManagerConnect);
            if (manager.IsInvalid)
            {
                manager.Dispose();
                return ScmServiceOpenResult.Error();
            }

            var service = NativeMethods.OpenService(manager, serviceName, ServiceQueryConfig | ServiceQueryStatus);
            if (service.IsInvalid)
            {
                var error = Marshal.GetLastWin32Error();
                service.Dispose();
                manager.Dispose();
                return error == ErrorServiceDoesNotExist ? ScmServiceOpenResult.NotFound() : ScmServiceOpenResult.Error();
            }

            return ScmServiceOpenResult.Found(new NativeScmQuerySession(manager, service));
        }

        private sealed class NativeScmQuerySession : IScmQuerySession
        {
            private readonly SafeScmHandle _manager;
            private readonly SafeScmHandle _service;
            private bool _disposed;

            public NativeScmQuerySession(SafeScmHandle manager, SafeScmHandle service)
            {
                _manager = manager;
                _service = service;
            }

            public ScmServiceConfiguration ReadConfiguration()
            {
                ThrowIfDisposed();
                var config = ReadServiceConfig();
                return new ScmServiceConfiguration(config.StartType, ReadDelayedAutoStart(), config.AccountName, config.BinaryPath);
            }

            public uint ReadCurrentState()
            {
                ThrowIfDisposed();
                const int statusSize = 36;
                var buffer = Marshal.AllocHGlobal(statusSize);
                try
                {
                    uint bytesNeeded;
                    if (!NativeMethods.QueryServiceStatusEx(_service, 0, buffer, statusSize, out bytesNeeded) || bytesNeeded > statusSize)
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }

                    return unchecked((uint)Marshal.ReadInt32(buffer, 4));
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }

            public void Dispose()
            {
                if (_disposed) return;
                _disposed = true;
                _service.Dispose();
                _manager.Dispose();
            }

            private NativeConfig ReadServiceConfig()
            {
                uint bytesNeeded;
                var probeSucceeded = NativeMethods.QueryServiceConfig(_service, IntPtr.Zero, 0, out bytesNeeded);
                var probeError = Marshal.GetLastWin32Error();
                if (probeSucceeded || probeError != ErrorInsufficientBuffer || bytesNeeded == 0 || bytesNeeded > 131072)
                {
                    throw new Win32Exception(probeError);
                }

                var buffer = Marshal.AllocHGlobal(checked((int)bytesNeeded));
                try
                {
                    if (!NativeMethods.QueryServiceConfig(_service, buffer, bytesNeeded, out var received) || received == 0 || received > bytesNeeded)
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }

                    var config = Marshal.PtrToStructure<QueryServiceConfig>(buffer);
                    return new NativeConfig(
                        config.StartType,
                        Marshal.PtrToStringUni(config.ServiceStartName),
                        Marshal.PtrToStringUni(config.BinaryPathName));
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }

            private bool ReadDelayedAutoStart()
            {
                const int delayedSize = 4;
                var buffer = Marshal.AllocHGlobal(delayedSize);
                try
                {
                    if (!NativeMethods.QueryServiceConfig2(_service, 3, buffer, delayedSize, out var received) || received != delayedSize)
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }

                    return Marshal.ReadInt32(buffer) != 0;
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }

            private void ThrowIfDisposed()
            {
                if (_disposed) throw new ObjectDisposedException(nameof(NativeScmQuerySession));
            }

            private sealed class NativeConfig
            {
                public NativeConfig(uint startType, string? accountName, string? binaryPath)
                {
                    StartType = startType;
                    AccountName = accountName;
                    BinaryPath = binaryPath;
                }
                public uint StartType { get; }
                public string? AccountName { get; }
                public string? BinaryPath { get; }
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct QueryServiceConfig
        {
            public uint ServiceType;
            public uint StartType;
            public uint ErrorControl;
            public IntPtr BinaryPathName;
            public IntPtr LoadOrderGroup;
            public uint TagId;
            public IntPtr Dependencies;
            public IntPtr ServiceStartName;
            public IntPtr DisplayName;
        }

        private sealed class SafeScmHandle : SafeHandle
        {
            public SafeScmHandle() : base(IntPtr.Zero, true) { }
            public override bool IsInvalid => handle == IntPtr.Zero;
            protected override bool ReleaseHandle() => NativeMethods.CloseServiceHandle(handle);
        }

        private static class NativeMethods
        {
            [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            internal static extern SafeScmHandle OpenSCManager(string? machineName, string? databaseName, uint access);
            [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            internal static extern SafeScmHandle OpenService(SafeScmHandle manager, string serviceName, uint access);
            [DllImport("advapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool CloseServiceHandle(IntPtr handle);
            [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool QueryServiceConfig(SafeScmHandle service, IntPtr buffer, uint bufferSize, out uint bytesNeeded);
            [DllImport("advapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool QueryServiceConfig2(SafeScmHandle service, uint level, IntPtr buffer, uint bufferSize, out uint bytesNeeded);
            [DllImport("advapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool QueryServiceStatusEx(SafeScmHandle service, uint infoLevel, IntPtr buffer, uint bufferSize, out uint bytesNeeded);
        }
    }
}
