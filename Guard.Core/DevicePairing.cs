using System;
using System.Linq;
using System.Security.Cryptography;

namespace Guard
{
    public enum PairingStatus
    {
        NotStarted = 0,
        WaitingForParent = 1,
        Paired = 2,
        Expired = 3
    }

    public class DevicePairing
    {
        public string Code { get; set; } = "";
        public string DeviceName { get; set; } = "";
        public DateTime? GeneratedAtUtc { get; set; }
        public DateTime? ExpiresAtUtc { get; set; }
        public DateTime? PairedAtUtc { get; set; }
        public PairingStatus Status { get; set; } = PairingStatus.NotStarted;
    }

    public static class PairingCodeService
    {
        public const int NormalizedCodeLength = 8;
        public static readonly TimeSpan DefaultLifetime = TimeSpan.FromMinutes(15);
        private const string Alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

        public static DevicePairing StartPairing(string deviceName, DateTime utcNow)
        {
            return StartPairing(deviceName, utcNow, DefaultLifetime);
        }

        public static DevicePairing StartPairing(string deviceName, DateTime utcNow, TimeSpan lifetime)
        {
            return new DevicePairing
            {
                Code = GenerateCode(),
                DeviceName = SanitizeDeviceName(deviceName),
                GeneratedAtUtc = utcNow,
                ExpiresAtUtc = utcNow.Add(lifetime),
                Status = PairingStatus.WaitingForParent
            };
        }

        public static bool IsValidCode(string? code)
        {
            var normalized = NormalizeCode(code);
            return normalized.Length == NormalizedCodeLength && normalized.All(c => Alphabet.Contains(c));
        }

        public static bool IsExpired(DevicePairing pairing, DateTime utcNow)
        {
            return pairing.ExpiresAtUtc.HasValue && utcNow >= pairing.ExpiresAtUtc.Value;
        }

        public static string NormalizeCode(string? code)
        {
            if (string.IsNullOrWhiteSpace(code)) return "";

            var chars = code
                .Where(char.IsLetterOrDigit)
                .Select(char.ToUpperInvariant)
                .ToArray();

            return new string(chars);
        }

        public static string FormatCode(string? code)
        {
            var normalized = NormalizeCode(code);
            if (normalized.Length <= 4) return normalized;
            return normalized.Substring(0, 4) + "-" + normalized.Substring(4);
        }

        private static string GenerateCode()
        {
            var chars = new char[NormalizedCodeLength];
            var bytes = new byte[NormalizedCodeLength];

            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }

            for (int i = 0; i < chars.Length; i++)
            {
                chars[i] = Alphabet[bytes[i] % Alphabet.Length];
            }

            return FormatCode(new string(chars));
        }

        private static string SanitizeDeviceName(string? deviceName)
        {
            if (string.IsNullOrWhiteSpace(deviceName)) return "";

            var trimmed = deviceName!.Trim();
            return trimmed.Length > 80 ? trimmed.Substring(0, 80) : trimmed;
        }
    }
}
