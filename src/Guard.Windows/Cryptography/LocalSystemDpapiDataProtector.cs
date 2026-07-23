using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Guard.Storage;

namespace Guard.Windows.Cryptography
{
    /// <summary>
    /// Protects authoritative state with DPAPI CurrentUser while the effective
    /// identity is LocalSystem. The LocalMachine DPAPI flag is intentionally
    /// never used, so another local account cannot decrypt the state.
    /// </summary>
    public sealed class LocalSystemDpapiDataProtector : IStateDataProtector
    {
        public const int MaximumPlaintextBytes = 1024 * 1024;
        public const int MaximumProtectedBytes = MaximumPlaintextBytes + (64 * 1024);
        public const string DefaultPurpose = "guard-v2-authoritative-state";

        private const uint CryptProtectUiForbidden = 0x1;
        private static readonly byte[] EntropyDomain =
            Encoding.ASCII.GetBytes("Guard.v2.DPAPI.CurrentUser\0");

        private readonly byte[] _entropy;
        private readonly bool _allowNonLocalSystemForTests;

        public LocalSystemDpapiDataProtector()
            : this(DefaultPurpose, allowNonLocalSystemForTests: false)
        {
        }

        public LocalSystemDpapiDataProtector(string purpose)
            : this(purpose, allowNonLocalSystemForTests: false)
        {
        }

        internal LocalSystemDpapiDataProtector(
            string purpose,
            bool allowNonLocalSystemForTests)
        {
            _entropy = CreatePurposeEntropy(purpose);
            _allowNonLocalSystemForTests = allowNonLocalSystemForTests;
        }

        public byte[] Protect(byte[] plaintext)
        {
            EnsureEffectiveIdentity();
            ValidateInput(
                plaintext,
                MaximumPlaintextBytes,
                nameof(plaintext),
                "The authoritative state payload is empty or oversized.");

            return Transform(plaintext, protect: true);
        }

        public byte[] Unprotect(byte[] protectedData)
        {
            EnsureEffectiveIdentity();
            ValidateInput(
                protectedData,
                MaximumProtectedBytes,
                nameof(protectedData),
                "The protected state payload is empty or oversized.");

            return Transform(protectedData, protect: false);
        }

        internal static bool IsEffectiveIdentityLocalSystem()
        {
            if (!OperatingSystem.IsWindows())
            {
                return false;
            }

            using (var identity = WindowsIdentity.GetCurrent(ifImpersonating: false))
            {
                if (identity == null)
                {
                    return false;
                }

                var userSid = identity.User;
                return userSid != null &&
                       userSid.IsWellKnown(WellKnownSidType.LocalSystemSid);
            }
        }

        private static void ValidateInput(
            byte[] value,
            int maximumLength,
            string parameterName,
            string message)
        {
            if (value == null || value.Length == 0 || value.Length > maximumLength)
            {
                throw new ArgumentException(message, parameterName);
            }
        }

        private void EnsureEffectiveIdentity()
        {
            if (!OperatingSystem.IsWindows())
            {
                throw new PlatformNotSupportedException(
                    "Windows DPAPI is available only on Windows.");
            }

            if (!_allowNonLocalSystemForTests && !IsEffectiveIdentityLocalSystem())
            {
                throw new UnauthorizedAccessException(
                    "Authoritative state DPAPI requires the effective LocalSystem identity.");
            }
        }

        private byte[] Transform(byte[] input, bool protect)
        {
            var inputCopy = (byte[])input.Clone();
            var entropyCopy = (byte[])_entropy.Clone();
            var inputHandle = default(GCHandle);
            var entropyHandle = default(GCHandle);
            var output = default(DataBlob);
            var description = IntPtr.Zero;

            try
            {
                inputHandle = GCHandle.Alloc(inputCopy, GCHandleType.Pinned);
                entropyHandle = GCHandle.Alloc(entropyCopy, GCHandleType.Pinned);
                var inputBlob = new DataBlob(inputCopy.Length, inputHandle.AddrOfPinnedObject());
                var entropyBlob = new DataBlob(entropyCopy.Length, entropyHandle.AddrOfPinnedObject());

                var succeeded = protect
                    ? CryptProtectData(
                        ref inputBlob,
                        "Guard v2 authoritative state",
                        ref entropyBlob,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        CryptProtectUiForbidden,
                        out output)
                    : CryptUnprotectData(
                        ref inputBlob,
                        out description,
                        ref entropyBlob,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        CryptProtectUiForbidden,
                        out output);

                var error = succeeded ? 0 : Marshal.GetLastWin32Error();
                if (!succeeded)
                {
                    throw new CryptographicException(
                        "Windows DPAPI rejected the protected state.",
                        new Win32Exception(error));
                }

                var maximumOutput = protect
                    ? MaximumProtectedBytes
                    : MaximumPlaintextBytes;
                if (output.Size <= 0 ||
                    output.Size > maximumOutput ||
                    output.Data == IntPtr.Zero)
                {
                    throw new CryptographicException(
                        "Windows DPAPI returned an invalid payload.");
                }

                var result = new byte[output.Size];
                Marshal.Copy(output.Data, result, 0, result.Length);
                return result;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(inputCopy);
                CryptographicOperations.ZeroMemory(entropyCopy);

                if (inputHandle.IsAllocated)
                {
                    inputHandle.Free();
                }

                if (entropyHandle.IsAllocated)
                {
                    entropyHandle.Free();
                }

                if (output.Data != IntPtr.Zero)
                {
                    ZeroUnmanaged(output.Data, output.Size);
                    LocalFree(output.Data);
                }

                if (description != IntPtr.Zero)
                {
                    LocalFree(description);
                }
            }
        }

        private static byte[] CreatePurposeEntropy(string purpose)
        {
            if (!IsCanonicalPurpose(purpose))
            {
                throw new ArgumentException(
                    "A canonical 16 to 128 character DPAPI purpose is required.",
                    nameof(purpose));
            }

            var purposeBytes = Encoding.ASCII.GetBytes(purpose);
            var material = new byte[EntropyDomain.Length + purposeBytes.Length];
            try
            {
                Buffer.BlockCopy(EntropyDomain, 0, material, 0, EntropyDomain.Length);
                Buffer.BlockCopy(
                    purposeBytes,
                    0,
                    material,
                    EntropyDomain.Length,
                    purposeBytes.Length);
                return SHA256.HashData(material);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(purposeBytes);
                CryptographicOperations.ZeroMemory(material);
            }
        }

        private static bool IsCanonicalPurpose(string purpose)
        {
            if (string.IsNullOrWhiteSpace(purpose) ||
                purpose.Length < 16 ||
                purpose.Length > 128)
            {
                return false;
            }

            for (var index = 0; index < purpose.Length; index++)
            {
                var character = purpose[index];
                if (!((character >= 'a' && character <= 'z') ||
                      (character >= 'A' && character <= 'Z') ||
                      (character >= '0' && character <= '9') ||
                      character == '-' ||
                      character == '_' ||
                      character == '.' ||
                      character == ':'))
                {
                    return false;
                }
            }

            return true;
        }

        private static void ZeroUnmanaged(IntPtr pointer, int length)
        {
            if (pointer == IntPtr.Zero || length <= 0)
            {
                return;
            }

            var zeros = new byte[Math.Min(length, 4096)];
            var offset = 0;
            while (offset < length)
            {
                var count = Math.Min(zeros.Length, length - offset);
                Marshal.Copy(zeros, 0, IntPtr.Add(pointer, offset), count);
                offset += count;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct DataBlob
        {
            public DataBlob(int size, IntPtr data)
            {
                Size = size;
                Data = data;
            }

            public int Size;

            public IntPtr Data;
        }

        [DllImport(
            "crypt32.dll",
            CharSet = CharSet.Unicode,
            ExactSpelling = true,
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptProtectData(
            ref DataBlob dataIn,
            string description,
            ref DataBlob optionalEntropy,
            IntPtr reserved,
            IntPtr promptStruct,
            uint flags,
            out DataBlob dataOut);

        [DllImport(
            "crypt32.dll",
            CharSet = CharSet.Unicode,
            ExactSpelling = true,
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptUnprotectData(
            ref DataBlob dataIn,
            out IntPtr description,
            ref DataBlob optionalEntropy,
            IntPtr reserved,
            IntPtr promptStruct,
            uint flags,
            out DataBlob dataOut);

        [DllImport("kernel32.dll", ExactSpelling = true)]
        private static extern IntPtr LocalFree(IntPtr memory);
    }
}
