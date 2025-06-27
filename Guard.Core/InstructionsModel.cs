using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;
using System.Text.Json;
using System.Linq;
using System.Security.Cryptography; 

namespace Guard
{
    public class InstructionsRoot
    {
        [JsonPropertyName("restrictedCategoryIds")]
        public string RestrictedCategoryIds { get; set; } = "";

        [JsonPropertyName("rules")]
        public List<InstructionRule> Rules { get; set; } = new List<InstructionRule>();

        [JsonPropertyName("presets")]
        public List<Preset> Presets { get; set; } = new List<Preset>();

        [JsonPropertyName("restrictedCategories")]
        public List<RestrictedCategory> RestrictedCategories { get; set; } = new List<RestrictedCategory>();
    }

    public class InstructionRule
    {
        [JsonPropertyName("id")]
        public string Id { get; set; } = "";

        [JsonPropertyName("type")]
        public string Type { get; set; } = ""; // "preset" or "custom"

        [JsonPropertyName("value")]
        public string Value { get; set; } = ""; // domain or preset name

        [JsonPropertyName("schedule")]
        public string Schedule { get; set; } = ""; // encoded schedule string
    }

    public class Preset
    {
        [JsonPropertyName("id")]
        public string Id { get; set; } = "";

        [JsonPropertyName("name")]
        public string Name { get; set; } = "";

        [JsonPropertyName("url")]
        public string Url { get; set; } = "";

        [JsonPropertyName("domains")]
        public string Domains { get; set; } = ""; // "|" separated

        [JsonPropertyName("ips")]
        public string Ips { get; set; } = ""; // "|" separated
    }

    public class RestrictedCategory
    {
        [JsonPropertyName("id")]
        public int Id { get; set; }

        [JsonPropertyName("label")]
        public string Label { get; set; } = "";

        [JsonPropertyName("urls")]
        public string Urls { get; set; } = ""; // "|" separated, can be empty

        [JsonPropertyName("domains")]
        public string? Domains { get; set; } // can be null, handle null safely

        [JsonPropertyName("ips")]
        public string? Ips { get; set; }

        [JsonPropertyName("presets")]
        public string? Presets { get; set; } // presets (by name) pipe-separated, can be null
    }
    public static class InstructionsParser
    {
        public static InstructionsRoot? Parse(string json)
        {
            try
            {
                return JsonSerializer.Deserialize<InstructionsRoot>(json);
            }
            catch
            {
                return null;
            }
        }

        // Returns true if instructions are meaningfully different (can compare JSONs, or do a deep compare)
        public static bool InstructionsAreDifferent(string oldInstr, string newInstr)
        {
            if (string.IsNullOrWhiteSpace(oldInstr) || string.IsNullOrWhiteSpace(newInstr)) return true;
            // Option 1: Direct string compare (quick, but whitespace may differ)
            if (oldInstr.Trim() == newInstr.Trim()) return false;

            // Option 2: Deep model compare
            var oldParsed = Parse(oldInstr);
            var newParsed = Parse(newInstr);
            if (oldParsed == null || newParsed == null) return true;
            // For now, just do a deep re-serialize-for-compare
            return JsonSerializer.Serialize(oldParsed) != JsonSerializer.Serialize(newParsed);
        }
        public static bool CategoriesAreDifferent(string oldInstr, string newInstr)
        {
            if (string.IsNullOrWhiteSpace(oldInstr) || string.IsNullOrWhiteSpace(newInstr))
                return true;

            var oldParsed = Parse(oldInstr);
            var newParsed = Parse(newInstr);
            if (oldParsed == null || newParsed == null)
                return true;

            // Compare restrictedCategoryIds
            // Create the lists. If the source string is null, default to a new empty list.
            var oldIds = oldParsed.RestrictedCategoryIds?.Split(new[] { '.' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(s => int.TryParse(s, out var id) ? id : -1).Where(id => id > 0).OrderBy(x => x).ToList()
                ?? new List<int>();

            var newIds = newParsed.RestrictedCategoryIds?.Split(new[] { '.' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(s => int.TryParse(s, out var id) ? id : -1).Where(id => id > 0).OrderBy(x => x).ToList()
                ?? new List<int>();

            // Now that neither list can be null, the comparison is simple and safe.
            if (!oldIds.SequenceEqual(newIds))
                return true;

            // Compare presets (by name and IPs only — adjust if needed)
            var oldPresets = oldParsed.Presets
                .Select(p => (Name: p.Name.Trim(), Ips: p.Ips?.Trim() ?? ""))
                .OrderBy(p => p.Name)
                .ToList();

            var newPresets = newParsed.Presets
                .Select(p => (Name: p.Name.Trim(), Ips: p.Ips?.Trim() ?? ""))
                .OrderBy(p => p.Name)
                .ToList();

            if (!oldPresets.SequenceEqual(newPresets))
                return true;

            // Compare restricted categories (by ID and presets string)
            var oldCats = oldParsed.RestrictedCategories
                .Select(c => (c.Id, c.Presets?.Trim() ?? "", c.Domains?.Trim() ?? "", c.Ips?.Trim() ?? ""))
                .OrderBy(c => c.Id).ToList();

            var newCats = newParsed.RestrictedCategories
                .Select(c => (c.Id, c.Presets?.Trim() ?? "", c.Domains?.Trim() ?? "", c.Ips?.Trim() ?? ""))
                .OrderBy(c => c.Id).ToList();

            if (!oldCats.SequenceEqual(newCats))
                return true;

            return false; // Everything matches
        }

    }

    // Helper for decoding and evaluating the custom schedule string for InstructionRule
    public static class ScheduleHelper
    {
        // Returns true if the rule should be currently active (ON) for the provided schedule string and time (UTC)
        public static bool ShouldBeActive(string schedule, DateTime timeUtc)
        {
            if (string.IsNullOrWhiteSpace(schedule) || schedule.Length < 57)
                return true; // If no schedule or invalid, treat as ALWAYS ON

            int mode = int.TryParse(schedule.Substring(0, 1), out var m) ? m : 1;
            int dayIndex = (int)timeUtc.DayOfWeek; // Sunday = 0 ... Saturday = 6
            string[] segments = new string[7];
            for (int i = 0; i < 7; i++)
                segments[i] = schedule.Substring(1 + i * 8, 8);

            string todayBlock = segments[dayIndex];

            if (mode == 1)
            {
                // all_time: always ON
                return true;
            }
            else if (mode == 2)
            {
                // same_time_each_day
                return IsInBlock(todayBlock, timeUtc);
            }
            else if (mode == 3)
            {
                // different_times_per_day
                return IsInBlock(todayBlock, timeUtc);
            }
            else if (mode == 4)
            {
                // some_days (00000000 if ON today, -------- if OFF)
                return todayBlock == "00000000";
            }
            // Fallback: treat as ON
            return true;
        }

        // Helper: Checks if current time is in a hhmmHHMM block
        private static bool IsInBlock(string block, DateTime timeUtc)
        {
            if (block == "--------")
                return false;
            if (block.Length != 8)
                return true; // treat invalid as always on

            var startStr = block.Substring(0, 4);
            var endStr = block.Substring(4, 4);

            if (!int.TryParse(startStr, out var start) || !int.TryParse(endStr, out var end))
                return true;

            int minuteOfDay = timeUtc.Hour * 60 + timeUtc.Minute;
            int blockStart = (int.Parse(startStr.Substring(0, 2)) * 60) + int.Parse(startStr.Substring(2, 2));
            int blockEnd = (int.Parse(endStr.Substring(0, 2)) * 60) + int.Parse(endStr.Substring(2, 2));

            // If start == end, treat as always off
            if (blockStart == blockEnd)
                return false;

            // If blockEnd < blockStart, treat as crossing midnight (rare)
            if (blockEnd > blockStart)
                return (minuteOfDay >= blockStart && minuteOfDay < blockEnd);
            else
                return (minuteOfDay >= blockStart || minuteOfDay < blockEnd);
        }
    }

}