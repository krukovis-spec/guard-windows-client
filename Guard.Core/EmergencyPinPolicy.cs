namespace Guard
{
    public static class EmergencyPinPolicy
    {
        public const string TemporaryDefaultPin = "123456";

        public static string GetEffectivePin(string? storedPin)
        {
            var pin = storedPin?.Trim();
            if (string.IsNullOrWhiteSpace(pin))
            {
                return TemporaryDefaultPin;
            }

            return pin!;
        }

        public static bool IsTemporaryDefault(string? storedPin)
        {
            var pin = storedPin?.Trim();
            return string.IsNullOrWhiteSpace(pin) ||
                   string.Equals(pin, TemporaryDefaultPin, System.StringComparison.Ordinal);
        }

        public static bool IsAllowedCustomPin(string? pin)
        {
            return InputSanitizer.IsValidPin(pin) && !IsTemporaryDefault(pin);
        }
    }
}
