using System;
using System.Globalization;

namespace Guard.Domain
{
    public sealed class WindowsAccountSid : IEquatable<WindowsAccountSid>
    {
        public const int MaximumCharacters = 184;

        public WindowsAccountSid(string value)
        {
            if (!IsCanonical(value))
            {
                throw new ArgumentException("A canonical Windows account SID is required.", nameof(value));
            }

            Value = value;
        }

        public string Value { get; }

        public bool Equals(WindowsAccountSid? other)
        {
            return other != null &&
                   string.Equals(Value, other.Value, StringComparison.Ordinal);
        }

        public override bool Equals(object? obj)
        {
            return Equals(obj as WindowsAccountSid);
        }

        public override int GetHashCode()
        {
            return StringComparer.Ordinal.GetHashCode(Value);
        }

        public static bool IsCanonical(string value)
        {
            if (string.IsNullOrEmpty(value) ||
                value.Length > MaximumCharacters ||
                !value.StartsWith("S-", StringComparison.Ordinal))
            {
                return false;
            }

            var parts = value.Split('-');
            if (parts.Length < 4 || parts.Length > 18 ||
                !string.Equals(parts[0], "S", StringComparison.Ordinal) ||
                !IsCanonicalNumber(parts[1]) ||
                !IsCanonicalNumber(parts[2]))
            {
                return false;
            }

            ulong revision;
            ulong identifierAuthority;
            if (!ulong.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out revision) ||
                revision != 1 ||
                !ulong.TryParse(parts[2], NumberStyles.None, CultureInfo.InvariantCulture, out identifierAuthority) ||
                identifierAuthority > 0xFFFFFFFFFFFFUL)
            {
                return false;
            }

            for (var index = 3; index < parts.Length; index++)
            {
                uint subAuthority;
                if (!IsCanonicalNumber(parts[index]) ||
                    !uint.TryParse(parts[index], NumberStyles.None, CultureInfo.InvariantCulture, out subAuthority))
                {
                    return false;
                }
            }

            return true;
        }

        private static bool IsCanonicalNumber(string value)
        {
            if (string.IsNullOrEmpty(value) || (value.Length > 1 && value[0] == '0'))
            {
                return false;
            }

            for (var index = 0; index < value.Length; index++)
            {
                if (value[index] < '0' || value[index] > '9')
                {
                    return false;
                }
            }

            return true;
        }
    }
}
