using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Guard
{
    public class ScheduleEvent
    {
        public int MinuteOfWeek { get; set; }
        public string RuleId { get; set; } = "";
        public bool BecomesActive { get; set; }
    }

    public static class SchedulerEngine
    {

        /// Calculates the weekly timeline based entirely on LOCAL time

        public static void CalculateWeeklyTimeline(GuardState state, Action<string> log)
        {
            log("[SchedulerCalculator] Calculating local time weekly timeline...");
            var timeline = new List<ScheduleSnapshot>();
            var allBreakpoints = new HashSet<int> { 0 };

            foreach (var rule in state.ParsedRules)
            {
                // This function no longer needs the timezone offset.
                var ruleEvents = GetEventsForRuleString(rule);
                if (ruleEvents != null)
                {
                    foreach (var ev in ruleEvents)
                    {
                        allBreakpoints.Add(ev.MinuteOfWeek);
                    }
                }
            }
            var sortedBreakpoints = allBreakpoints.ToList();
            sortedBreakpoints.Sort();

            log($"[SchedulerCalculator] Found {sortedBreakpoints.Count} unique local time breakpoints.");

            foreach (var minute in sortedBreakpoints)
            {
                var snapshot = new ScheduleSnapshot
                {
                    StartMinuteOfWeek = minute,
                    ActiveRuleIds = new List<string>()
                };

                foreach (var rule in state.ParsedRules)
                {
                    if (IsRuleActiveAtMinute(rule, minute))
                    {
                        snapshot.ActiveRuleIds.Add(rule.RuleId);
                    }
                }

                if (timeline.Any() && timeline.Last().ActiveRuleIds.SequenceEqual(snapshot.ActiveRuleIds))
                {
                    continue;
                }
                timeline.Add(snapshot);
            }

            state.WeeklyTimeline = timeline;
            state.LastAppliedSnapshotMinute = -1;
            log($"[SchedulerCalculator] Local timeline calculation complete. Generated {state.WeeklyTimeline.Count} snapshots.");
        }


        /// The tick function now compares the trusted LOCAL time to the LOCAL timeline.
        public static async Task RunSchedulerTick(GuardState state, Action<string> log)
        {
            if (state.WeeklyTimeline == null || !state.WeeklyTimeline.Any())
            {
                log("[Scheduler] Timeline is not built. Skipping tick.");
                return;
            }

            // Get the current trusted LOCAL time.
            var nowLocal = TimeHelper.GetTrustedLocalNow(state);
            int currentMinuteOfWeek = GetMinuteOfWeek(nowLocal);

            log($"[Scheduler] Current Trusted Local Time: {nowLocal:yyyy-MM-dd HH:mm:ss}, Calculated Minute of Week: {currentMinuteOfWeek}");

            var currentSnapshot = state.WeeklyTimeline.LastOrDefault(s => s.StartMinuteOfWeek <= currentMinuteOfWeek)
                                  ?? state.WeeklyTimeline.Last();

            if (currentSnapshot.StartMinuteOfWeek != state.LastAppliedSnapshotMinute)
            {
                log($"[Scheduler] New time block entered at minute {currentSnapshot.StartMinuteOfWeek}. Applying state...");

                var desiredRuleIds = new HashSet<string>(currentSnapshot.ActiveRuleIds);
                var activeRules = state.ParsedRules.Where(r => desiredRuleIds.Contains(r.RuleId)).ToList();
                // Safely call the instance method. If Instance is null, applyTask will be null.
                var applyTask = MainForm.Instance?.ApplyRulesPhysicalAsync(activeRules);

                // Await the task, or if it's null, await a default completed task.
                await (applyTask ?? Task.CompletedTask);

                state.ActiveRuleIds = desiredRuleIds.ToList();
                state.LastAppliedSnapshotMinute = currentSnapshot.StartMinuteOfWeek;
            }
            else
            {
                log("[Scheduler] Tick completed. No rule changes were necessary.");
            }
        }

        // --- HELPER METHODS ---

        private static bool IsRuleActiveAtMinute(ParsedRule rule, int minuteOfWeek)
        {
            var events = GetEventsForRuleString(rule);
            if (events == null) return true;

            var lastEvent = events.Where(e => e.MinuteOfWeek <= minuteOfWeek)
                                  .OrderByDescending(e => e.MinuteOfWeek)
                                  .FirstOrDefault();
            if (lastEvent == null)
            {
                lastEvent = events.LastOrDefault();
            }
            return lastEvent?.BecomesActive ?? false;
        }

        /// This function is now much simpler. It directly converts local schedule times
        /// into local MinuteOfWeek values, with no UTC conversion.
        private static List<ScheduleEvent>? GetEventsForRuleString(ParsedRule rule)
        {
            var encoded = rule.Schedule;
            if (string.IsNullOrWhiteSpace(encoded) || encoded.Length < 1 || encoded[0] == '1') return null;

            var events = new List<ScheduleEvent>();
            var blocks = Enumerable.Range(0, (encoded.Length - 1) / 8)
                .Select(i => encoded.Substring(1 + i * 8, 8)).ToList();

            if (blocks.Count < 7) return events; // Invalid schedule string

            char modeDigit = encoded[0];

            if (modeDigit == '2') // same_time_each_day
            {
                var b = blocks[0];
                int startTime = int.Parse(b.Substring(0, 2)) * 60 + int.Parse(b.Substring(2, 2));
                int endTime = int.Parse(b.Substring(4, 2)) * 60 + int.Parse(b.Substring(6, 2));
                for (int day = 0; day < 7; day++)
                {
                    events.Add(new ScheduleEvent { RuleId = rule.RuleId, MinuteOfWeek = day * 1440 + startTime, BecomesActive = true });
                    events.Add(new ScheduleEvent { RuleId = rule.RuleId, MinuteOfWeek = day * 1440 + endTime, BecomesActive = false });
                }
            }
            else if (modeDigit == '3' || modeDigit == '4') // different_times_per_day or some_days
            {
                for (int day = 0; day < 7; day++) // Sunday = 0, Monday = 1...
                {
                    var b = blocks[day]; // Assumes API sends Sunday as the first block (index 0)
                    if (b == "00000000") // whole_day
                    {
                        events.Add(new ScheduleEvent { RuleId = rule.RuleId, MinuteOfWeek = day * 1440, BecomesActive = true });
                        events.Add(new ScheduleEvent { RuleId = rule.RuleId, MinuteOfWeek = (day + 1) * 1440, BecomesActive = false });
                    }
                    else if (b != "--------") // specific time
                    {
                        int startTime = int.Parse(b.Substring(0, 2)) * 60 + int.Parse(b.Substring(2, 2));
                        int endTime = int.Parse(b.Substring(4, 2)) * 60 + int.Parse(b.Substring(6, 2));
                        events.Add(new ScheduleEvent { RuleId = rule.RuleId, MinuteOfWeek = day * 1440 + startTime, BecomesActive = true });
                        events.Add(new ScheduleEvent { RuleId = rule.RuleId, MinuteOfWeek = day * 1440 + endTime, BecomesActive = false });
                    }
                }
            }

            return events.OrderBy(e => e.MinuteOfWeek).ToList();
        }

        private static int GetMinuteOfWeek(DateTime time)
        {
            // The time passed in is LOCAL time.
            int day = (int)time.DayOfWeek; // Sunday = 0, Monday = 1, etc.
            int minuteOfDay = (int)time.TimeOfDay.TotalMinutes;

            // Calculate the base minute of the week.
            int minuteOfWeek = day * 1440 + minuteOfDay;

            int adjustedMinute = minuteOfWeek;

            // and never exceeds the total minutes in a week (10080).
            return adjustedMinute % 10080;
        }
    }
}
