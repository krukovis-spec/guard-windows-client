using System;

namespace Guard.Windows.BrowserPolicy
{
    public enum ManagedBrowserPolicyValueKind
    {
        String = 1,
        Integer = 2,
        Boolean = 3
    }

    public sealed class ManagedBrowserPolicySetting
    {
        internal ManagedBrowserPolicySetting(
            string name,
            ManagedBrowserPolicyValueKind valueKind,
            string canonicalValue)
        {
            if (string.IsNullOrEmpty(name) || name.Length > 128)
            {
                throw new ArgumentException(
                    "A bounded browser policy name is required.",
                    nameof(name));
            }

            for (var index = 0; index < name.Length; index++)
            {
                var character = name[index];
                if (!((character >= 'a' && character <= 'z') ||
                      (character >= 'A' && character <= 'Z') ||
                      (character >= '0' && character <= '9')))
                {
                    throw new ArgumentException(
                        "The browser policy name is not canonical.",
                        nameof(name));
                }
            }

            if (!Enum.IsDefined(
                    typeof(ManagedBrowserPolicyValueKind),
                    valueKind))
            {
                throw new ArgumentOutOfRangeException(nameof(valueKind));
            }

            if (string.IsNullOrEmpty(canonicalValue) ||
                canonicalValue.Length > 4096)
            {
                throw new ArgumentException(
                    "A bounded canonical browser policy value is required.",
                    nameof(canonicalValue));
            }

            for (var index = 0; index < canonicalValue.Length; index++)
            {
                if (char.IsControl(canonicalValue[index]))
                {
                    throw new ArgumentException(
                        "Browser policy values cannot contain control characters.",
                        nameof(canonicalValue));
                }
            }

            Name = name;
            ValueKind = valueKind;
            CanonicalValue = canonicalValue;
        }

        public string Name { get; }

        public ManagedBrowserPolicyValueKind ValueKind { get; }

        public string CanonicalValue { get; }
    }
}
