using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;
using Guard.Domain.Readiness;
using Microsoft.Win32;

namespace Guard.Windows.Readiness
{
    public sealed class WindowsEditionFacts
    {
        public WindowsEditionFacts(uint buildNumber, uint productType)
        {
            BuildNumber = buildNumber;
            ProductType = productType;
        }

        public uint BuildNumber { get; }
        public uint ProductType { get; }
    }

    public interface IWindowsEditionFactsSource
    {
        WindowsEditionFacts Get();
    }

    public sealed class Windows11SupportedEditionReadinessProbe : IReadinessProbe
    {
        private const uint MinimumWindows11Build = 22000;
        private const uint ProductProfessional = 0x00000030;
        private readonly IWindowsEditionFactsSource _source;

        public Windows11SupportedEditionReadinessProbe(IWindowsEditionFactsSource source)
        {
            _source = source ?? throw new ArgumentNullException(nameof(source));
        }

        public ReadinessProbeFact Probe(CancellationToken cancellationToken)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                return Unknown();
            }

            try
            {
                var facts = _source.Get();
                if (facts == null)
                {
                    return Error();
                }

                return facts.BuildNumber >= MinimumWindows11Build &&
                       IsSupportedProduct(facts.ProductType)
                    ? Satisfied()
                    : Unsatisfied();
            }
            catch (OperationCanceledException)
            {
                return Unknown();
            }
            catch (Exception)
            {
                return Error();
            }
        }

        private static bool IsSupportedProduct(uint productType)
        {
            return productType == ProductProfessional;
        }

        private static ReadinessProbeFact Satisfied() => new ReadinessProbeFact(ReadinessFactState.Satisfied);
        private static ReadinessProbeFact Unsatisfied() => new ReadinessProbeFact(ReadinessFactState.Unsatisfied);
        private static ReadinessProbeFact Unknown() => new ReadinessProbeFact(ReadinessFactState.Unknown);
        private static ReadinessProbeFact Error() => new ReadinessProbeFact(ReadinessFactState.Error);
    }

    public sealed class NativeWindowsEditionFactsSource : IWindowsEditionFactsSource
    {
        public WindowsEditionFacts Get()
        {
            var version = new OsVersionInfoEx
            {
                OsVersionInfoSize = (uint)Marshal.SizeOf<OsVersionInfoEx>()
            };
            var status = RtlGetVersion(ref version);
            if (status != 0)
            {
                throw new Win32Exception(unchecked((int)status));
            }

            uint productType;
            if (!GetProductInfo(
                    version.MajorVersion,
                    version.MinorVersion,
                    version.ServicePackMajor,
                    version.ServicePackMinor,
                    out productType))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return new WindowsEditionFacts(version.BuildNumber, productType);
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct OsVersionInfoEx
        {
            public uint OsVersionInfoSize;
            public uint MajorVersion;
            public uint MinorVersion;
            public uint BuildNumber;
            public uint PlatformId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string CsdVersion;
            public ushort ServicePackMajor;
            public ushort ServicePackMinor;
            public ushort SuiteMask;
            public byte ProductType;
            public byte Reserved;
        }

        [DllImport("ntdll.dll")]
        private static extern int RtlGetVersion(ref OsVersionInfoEx versionInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetProductInfo(
            uint majorVersion,
            uint minorVersion,
            ushort servicePackMajor,
            ushort servicePackMinor,
            out uint productType);
    }

    public interface ISecureBootStateSource
    {
        bool TryReadEnabled(out int enabled);
    }

    public sealed class SecureBootReadinessProbe : IReadinessProbe
    {
        private readonly ISecureBootStateSource _source;

        public SecureBootReadinessProbe(ISecureBootStateSource source)
        {
            _source = source ?? throw new ArgumentNullException(nameof(source));
        }

        public ReadinessProbeFact Probe(CancellationToken cancellationToken)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                return Unknown();
            }

            try
            {
                int enabled;
                if (!_source.TryReadEnabled(out enabled))
                {
                    return Unknown();
                }

                return enabled == 1 ? Satisfied() : enabled == 0 ? Unsatisfied() : Error();
            }
            catch (OperationCanceledException)
            {
                return Unknown();
            }
            catch (Exception)
            {
                return Error();
            }
        }

        private static ReadinessProbeFact Satisfied() => new ReadinessProbeFact(ReadinessFactState.Satisfied);
        private static ReadinessProbeFact Unsatisfied() => new ReadinessProbeFact(ReadinessFactState.Unsatisfied);
        private static ReadinessProbeFact Unknown() => new ReadinessProbeFact(ReadinessFactState.Unknown);
        private static ReadinessProbeFact Error() => new ReadinessProbeFact(ReadinessFactState.Error);
    }

    public sealed class RegistrySecureBootStateSource : ISecureBootStateSource
    {
        private const string SecureBootStateKey = @"SYSTEM\CurrentControlSet\Control\SecureBoot\State";
        private const string UefiSecureBootEnabledValue = "UEFISecureBootEnabled";

        public bool TryReadEnabled(out int enabled)
        {
            enabled = 0;
            using (var key = Registry.LocalMachine.OpenSubKey(SecureBootStateKey, writable: false))
            {
                if (key == null)
                {
                    return false;
                }

                var value = key.GetValue(UefiSecureBootEnabledValue, defaultValue: null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                if (value == null)
                {
                    return false;
                }

                if (key.GetValueKind(UefiSecureBootEnabledValue) !=
                        RegistryValueKind.DWord ||
                    !(value is int))
                {
                    throw new InvalidOperationException(
                        "The Secure Boot state has an invalid registry type.");
                }

                enabled = (int)value;
                return true;
            }
        }
    }
}
