using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace Guard.Contracts
{
    public sealed class BlockedApplicationItem
    {
        public BlockedApplicationItem(string observationId, string displayName, DateTimeOffset observedAtUtc, DateTimeOffset expiresAtUtc)
        {
            if (!GuardIdentifier.IsCanonicalToken(observationId)) throw new ArgumentException("Invalid observation id.");
            if (string.IsNullOrWhiteSpace(displayName) || displayName.Length > 256 || displayName != displayName.Trim())
                throw new ArgumentException("Invalid application name.");
            for (var i = 0; i < displayName.Length; i++)
            {
                var category = CharUnicodeInfo.GetUnicodeCategory(displayName, i);
                if (category == UnicodeCategory.Control || category == UnicodeCategory.Format ||
                    category == UnicodeCategory.LineSeparator || category == UnicodeCategory.ParagraphSeparator)
                    throw new ArgumentException("Invalid name character.");
                if (char.IsHighSurrogate(displayName[i]))
                {
                    if (++i >= displayName.Length || !char.IsLowSurrogate(displayName[i])) throw new ArgumentException("Invalid Unicode.");
                }
                else if (char.IsLowSurrogate(displayName[i])) throw new ArgumentException("Invalid Unicode.");
            }
            if (observedAtUtc.Offset != TimeSpan.Zero || expiresAtUtc.Offset != TimeSpan.Zero ||
                expiresAtUtc <= observedAtUtc || expiresAtUtc - observedAtUtc > TimeSpan.FromMinutes(30))
                throw new ArgumentException("Invalid observation lifetime.");
            ObservationId = observationId; DisplayName = displayName;
            ObservedAtUtc = observedAtUtc; ExpiresAtUtc = expiresAtUtc;
        }
        public string ObservationId { get; }
        public string DisplayName { get; }
        public DateTimeOffset ObservedAtUtc { get; }
        public DateTimeOffset ExpiresAtUtc { get; }
    }

    // Historical events only. An empty list is not evidence of active protection.
    public sealed class BlockedApplicationsPayload
    {
        public const int MaximumItems = 16;
        public BlockedApplicationsPayload(DateTimeOffset checkedAtUtc, IReadOnlyList<BlockedApplicationItem> items)
        {
            if (checkedAtUtc.Offset != TimeSpan.Zero) throw new ArgumentException("UTC required.");
            if (items == null || items.Count > MaximumItems) throw new ArgumentException("Invalid observation count.");
            var copy = items.ToArray();
            var ids = new HashSet<string>(StringComparer.Ordinal);
            foreach (var item in copy)
                if (item == null || !ids.Add(item.ObservationId) || checkedAtUtc < item.ObservedAtUtc || checkedAtUtc >= item.ExpiresAtUtc)
                    throw new ArgumentException("Invalid or duplicate observation.");
            CheckedAtUtc = checkedAtUtc; Items = Array.AsReadOnly(copy);
        }
        public DateTimeOffset CheckedAtUtc { get; }
        public IReadOnlyList<BlockedApplicationItem> Items { get; }
    }

    // A durable local queue acknowledgement, not relay delivery or permission to run.
    public sealed class ApplicationRequestQueuedPayload
    {
        public ApplicationRequestQueuedPayload(string requestId, bool created, DateTimeOffset expiresAtUtc)
        {
            if (!GuardIdentifier.IsCanonicalToken(requestId) || expiresAtUtc.Offset != TimeSpan.Zero)
                throw new ArgumentException("Invalid queued request.");
            RequestId = requestId; Created = created; ExpiresAtUtc = expiresAtUtc;
        }
        public string RequestId { get; }
        public bool Created { get; }
        public DateTimeOffset ExpiresAtUtc { get; }
    }
}
