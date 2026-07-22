namespace Guard
{
    public static class EmergencyPinPolicy
    {
        public const string KnownCompromisedPin = "123456";

        public static bool IsAuthorized(string? storedPin, string? enteredPin)
        {
            var expected = storedPin?.Trim();
            var actual = enteredPin?.Trim();
            if (!IsAllowedCustomPin(expected) || !InputSanitizer.IsValidPin(actual))
            {
                return false;
            }

            int difference = 0;
            for (int index = 0; index < expected!.Length; index++)
            {
                difference |= expected[index] ^ actual![index];
            }

            return difference == 0;
        }

        public static bool IsMissingOrCompromised(string? storedPin)
        {
            var pin = storedPin?.Trim();
            return string.IsNullOrWhiteSpace(pin) ||
                   string.Equals(pin, KnownCompromisedPin, System.StringComparison.Ordinal);
        }

        public static bool IsAllowedCustomPin(string? pin)
        {
            var normalized = pin?.Trim();
            return InputSanitizer.IsValidPin(normalized) && !IsMissingOrCompromised(normalized);
        }
    }
}
