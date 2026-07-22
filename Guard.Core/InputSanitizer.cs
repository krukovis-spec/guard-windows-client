using System.Linq;
using System.Net;
using System.Text.RegularExpressions;

namespace Guard
{
    public static class InputSanitizer
    {
        // Allows letters, numbers, hyphens, and periods. Rejects command injection characters.
        private static readonly Regex ValidDomainCharsRegex = new Regex(@"^[a-zA-Z0-9\.\-_]+$");

        public static bool IsValidDomainName(string domain)
        {
            if (string.IsNullOrWhiteSpace(domain) || domain.Length > 255)
            {
                return false;
            }

            return ValidDomainCharsRegex.IsMatch(domain);
        }

        public static bool IsValidIpAddress(string ip)
        {
            if (string.IsNullOrWhiteSpace(ip))
            {
                return false;
            }

            if (ip.Contains("/"))
            {
                var parts = ip.Split('/');
                if (parts.Length != 2)
                {
                    return false;
                }

                bool isValidIp = IPAddress.TryParse(parts[0], out _);
                bool isValidSubnet = int.TryParse(parts[1], out int subnet) && subnet >= 0 && subnet <= 32;

                return isValidIp && isValidSubnet;
            }

            return IPAddress.TryParse(ip, out _);
        }

        public static bool IsValidPin(string? pin)
        {
            if (string.IsNullOrWhiteSpace(pin) || pin?.Length != 6)
            {
                return false;
            }

            return pin.All(char.IsDigit);
        }

        public static string SanitizeString(string? input, int maxLength = 255)
        {
            if (string.IsNullOrEmpty(input))
            {
                return "";
            }

            var trimmed = input?.Trim() ?? "";
            return trimmed.Length > maxLength ? trimmed.Substring(0, maxLength) : trimmed;
        }
    }
}
