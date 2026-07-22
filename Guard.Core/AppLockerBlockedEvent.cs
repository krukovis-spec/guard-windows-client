using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace Guard
{
    public sealed class AppLockerBlockedEvent
    {
        public long RecordId { get; set; }
        public int EventId { get; set; }
        public string FilePath { get; set; } = "";
        public string User { get; set; } = "";
        public DateTime OccurredAtUtc { get; set; }
    }

    public static class AppLockerBlockedEventParser
    {
        private static readonly Regex WindowsExecutablePathRegex = new Regex(
            @"[A-Za-z]:\\[^""'\r\n]+?\.(?:exe|com)\b",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        public static bool IsRequestWorthyEventId(int eventId)
        {
            return eventId == 8003 || eventId == 8004;
        }

        public static bool TryExtractExecutablePath(
            IEnumerable<string?> propertyValues,
            string? description,
            out string filePath)
        {
            foreach (var value in propertyValues ?? Enumerable.Empty<string?>())
            {
                var normalized = ApplicationControlApplier.NormalizeExecutablePath(value);
                if (normalized != null)
                {
                    filePath = normalized;
                    return true;
                }
            }

            var text = description ?? "";
            foreach (Match match in WindowsExecutablePathRegex.Matches(text))
            {
                var normalized = ApplicationControlApplier.NormalizeExecutablePath(match.Value);
                if (normalized != null)
                {
                    filePath = normalized;
                    return true;
                }
            }

            filePath = "";
            return false;
        }
    }
}
