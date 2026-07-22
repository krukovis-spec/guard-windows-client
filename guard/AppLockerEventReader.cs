using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;

namespace Guard
{
    internal static class AppLockerEventReader
    {
        private const string ExeAndDllChannel = "Microsoft-Windows-AppLocker/EXE and DLL";

        public static IReadOnlyList<AppLockerBlockedEvent> ReadExecutableAccessEvents(
            long afterRecordId,
            int maxEvents,
            Action<string>? log,
            out long latestRecordIdSeen)
        {
            var events = new List<AppLockerBlockedEvent>();
            latestRecordIdSeen = afterRecordId;
            if (maxEvents <= 0)
            {
                return events;
            }

            try
            {
                var query = new EventLogQuery(
                    ExeAndDllChannel,
                    PathType.LogName,
                    "*[System[(EventID=8003 or EventID=8004)]]")
                {
                    ReverseDirection = true
                };

                using (var reader = new EventLogReader(query))
                {
                    EventRecord? record;
                    while ((record = reader.ReadEvent()) != null && events.Count < maxEvents)
                    {
                        using (record)
                        {
                            var recordId = record.RecordId ?? 0;
                            if (recordId <= afterRecordId)
                            {
                                break;
                            }
                            latestRecordIdSeen = Math.Max(latestRecordIdSeen, recordId);

                            var eventId = record.Id;
                            if (!AppLockerBlockedEventParser.IsRequestWorthyEventId(eventId))
                            {
                                continue;
                            }

                            var propertyValues = record.Properties
                                .Select(property => property.Value?.ToString())
                                .ToList();
                            var description = SafeFormatDescription(record);
                            if (!AppLockerBlockedEventParser.TryExtractExecutablePath(propertyValues, description, out var filePath))
                            {
                                continue;
                            }

                            events.Add(new AppLockerBlockedEvent
                            {
                                RecordId = recordId,
                                EventId = eventId,
                                FilePath = filePath,
                                User = SafeUser(record),
                                OccurredAtUtc = record.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                log?.Invoke("[AppControl] Could not read AppLocker access events: " + ex.Message);
            }

            return events
                .OrderBy(item => item.RecordId)
                .ToList();
        }

        private static string SafeFormatDescription(EventRecord record)
        {
            try
            {
                return record.FormatDescription() ?? "";
            }
            catch
            {
                return "";
            }
        }

        private static string SafeUser(EventRecord record)
        {
            try
            {
                return record.UserId?.Value ?? "";
            }
            catch
            {
                return "";
            }
        }
    }
}
