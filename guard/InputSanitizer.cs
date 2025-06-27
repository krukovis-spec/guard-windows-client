using System.Linq;
using System.Net;
using System.Text.RegularExpressions;

namespace Guard
{
    public static class InputSanitizer
    {
        // This regex allows letters, numbers, hyphens, and periods. It's a basic check
        // to prevent command injection characters like '&', '|', ';', etc.
        private static readonly Regex ValidDomainCharsRegex = new Regex(@"^[a-zA-Z0-9\.\-_]+$");

        /// <summary>
        /// Checks if a string is a valid, safe domain name.
        /// </summary>
        public static bool IsValidDomainName(string domain)
        {
            if (string.IsNullOrWhiteSpace(domain) || domain.Length > 255)
            {
                return false;
            }
            // Ensure it only contains valid characters.
            return ValidDomainCharsRegex.IsMatch(domain);
        }

        /// <summary>
        /// Checks if a string is a valid IP address (v4 or v6).
        /// </summary>
        public static bool IsValidIpAddress(string ip)
        {
            if (string.IsNullOrWhiteSpace(ip))
            {
                return false;
            }

            // Check if the input is in CIDR notation (e.g., 192.168.1.0/24)
            if (ip.Contains("/"))
            {
                var parts = ip.Split('/');
                if (parts.Length != 2)
                {
                    return false; // Invalid format, should only have one '/'
                }

                // Check if the part before the '/' is a valid IP address
                bool isValidIp = IPAddress.TryParse(parts[0], out _);

                // Check if the part after the '/' is a valid subnet number (e.g., 0-32 for IPv4)
                bool isValidSubnet = int.TryParse(parts[1], out int subnet) && subnet >= 0 && subnet <= 32;

                return isValidIp && isValidSubnet;
            }
            else
            {
                // If there's no '/', treat it as a single IP address
                return IPAddress.TryParse(ip, out _);
            }
        }

        /// <summary>
        /// Checks if a string is a valid 6-digit PIN.
        /// </summary>
        public static bool IsValidPin(string? pin) 
        {
            if (string.IsNullOrWhiteSpace(pin) || pin?.Length != 6)
            {
                return false;
            }
            return pin.All(char.IsDigit);
        }

        /// <summary>
        /// A generic method to clean up and truncate a string to a max length.
        /// </summary>
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