using System;
using System.Collections.Generic;
using System.Linq;

namespace Guard.Contracts
{
    // Historical outcomes only; none of these states proves current access or protection.
    public enum ApplicationRequestHistoryStatus
    {
        AwaitingResponse = 1,
        AwaitingApplication = 2,
        Denied = 3,
        Expired = 4,
        NotApplied = 5,
        AppliedPreviously = 6
    }

    public sealed class ApplicationRequestHistoryItem
    {
        public ApplicationRequestHistoryItem(string requestId, string displayName, DateTimeOffset createdAtUtc,
            DateTimeOffset recordedAtUtc, ApplicationRequestHistoryStatus status)
        {
            if (!GuardIdentifier.IsCanonicalToken(requestId) || !Enum.IsDefined(typeof(ApplicationRequestHistoryStatus), status))
                throw new ArgumentException("Invalid history identity or status.");
            BlockedApplicationItem.RequireDisplayName(displayName);
            if (createdAtUtc.Offset != TimeSpan.Zero || recordedAtUtc.Offset != TimeSpan.Zero || recordedAtUtc < createdAtUtc)
                throw new ArgumentException("Invalid history timestamps.");
            RequestId = requestId; DisplayName = displayName; CreatedAtUtc = createdAtUtc; RecordedAtUtc = recordedAtUtc; Status = status;
        }
        public string RequestId { get; }
        public string DisplayName { get; }
        public DateTimeOffset CreatedAtUtc { get; }
        public DateTimeOffset RecordedAtUtc { get; }
        public ApplicationRequestHistoryStatus Status { get; }
    }

    public sealed class ApplicationRequestHistoryPayload
    {
        public const int MaximumItems = 16;
        public ApplicationRequestHistoryPayload(DateTimeOffset checkedAtUtc, IReadOnlyList<ApplicationRequestHistoryItem> items)
        {
            if (checkedAtUtc.Offset != TimeSpan.Zero || items == null || items.Count > MaximumItems)
                throw new ArgumentException("Invalid history bounds.");
            var copy = items.ToArray();
            var ids = new HashSet<string>(StringComparer.Ordinal);
            foreach (var item in copy)
                if (item == null || !ids.Add(item.RequestId) || item.RecordedAtUtc > checkedAtUtc)
                    throw new ArgumentException("Invalid history item.");
            CheckedAtUtc = checkedAtUtc; Items = Array.AsReadOnly(copy);
        }
        public DateTimeOffset CheckedAtUtc { get; }
        public IReadOnlyList<ApplicationRequestHistoryItem> Items { get; }
    }
}
