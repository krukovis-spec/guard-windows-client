namespace Guard
{
    public static class DomainGenerator
    {
        /// <summary>
        /// Returns domain variants: root, www., m., api. for a given bare domain such as "example.com".
        /// If domain already starts with www., m., or api., only returns that version.
        /// </summary>
        public static List<string> GetDomainVariants(string bareDomain)
        {
            if (string.IsNullOrWhiteSpace(bareDomain))
                return new List<string>();

            bareDomain = bareDomain.ToLowerInvariant().Trim();

            // Avoid generating variants if domain is already a variant
            if (bareDomain.StartsWith("www.") || bareDomain.StartsWith("m.") || bareDomain.StartsWith("api."))
                return new List<string> { bareDomain };

            // You can add more variants below if needed
            var variants = new List<string>
            {
                bareDomain,
                "www." + bareDomain,
                "m." + bareDomain,
                "api." + bareDomain
            };

            return variants.Distinct().ToList();
        }
    }
}