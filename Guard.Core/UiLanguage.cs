namespace Guard
{
    public static class UiLanguage
    {
        public const string Russian = "ru";
        public const string English = "en";

        public static string Normalize(string? language)
        {
            var value = (language ?? "").Trim().ToLowerInvariant();
            return value == English ? English : Russian;
        }

        public static bool IsRussian(string? language)
        {
            return Normalize(language) == Russian;
        }

        public static string Text(string? language, string russian, string english)
        {
            return IsRussian(language) ? russian : english;
        }
    }
}
