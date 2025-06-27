using System;
using System.Collections.Generic;
using System.Linq;

namespace Guard
{
    public static class RuleParser
    {
        public static ParsedRule ConvertRuleToParsedRule(InstructionRule rule, GuardState state)
        {
            var parsedRule = new ParsedRule
            {
                RuleId = rule.Id,
                Schedule = rule.Schedule
            };

            var urls = new List<string>();
            var ips = new List<string>();

            if (rule.Type == "custom_url" && !string.IsNullOrWhiteSpace(rule.Value))
            {
                var inputUrls = rule.Value
                    .Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(u => u.Trim().ToLowerInvariant())
                    .ToList();

                urls.AddRange(inputUrls);

                foreach (var url in inputUrls)
                {
                    // First — check if URL directly matches any preset URL
                    var preset = state.Presets.FirstOrDefault(p =>
                        string.Equals(p.Url, url, StringComparison.OrdinalIgnoreCase));

                    if (preset != null)
                    {
                        if (!string.IsNullOrWhiteSpace(preset.Domains))
                        {
                            var presetDomains = preset.Domains
                                .Split(new[] { '|' }, StringSplitOptions.RemoveEmptyEntries)
                                .Select(d => d.Trim().ToLowerInvariant());
                            urls.AddRange(presetDomains);
                        }

                        if (!string.IsNullOrWhiteSpace(preset.Ips))
                        {
                            var presetIps = preset.Ips
                                .Split(new[] { '|' }, StringSplitOptions.RemoveEmptyEntries)
                                .Select(ip => ip.Trim());
                            ips.AddRange(presetIps);
                        }
                    }

                    // Second — check if this URL matches any domains inside presets
                    foreach (var p in state.Presets)
                    {
                        if (string.IsNullOrWhiteSpace(p.Domains))
                            continue;

                        var domains = p.Domains.Split(new[] { '|' }, StringSplitOptions.RemoveEmptyEntries)
                                               .Select(d => d.Trim().ToLowerInvariant());

                        if (domains.Contains(url))
                        {
                            urls.AddRange(domains);

                            if (!string.IsNullOrWhiteSpace(p.Ips))
                            {
                                var presetIps = p.Ips
                                    .Split(new[] { '|' }, StringSplitOptions.RemoveEmptyEntries)
                                    .Select(ip => ip.Trim());
                                ips.AddRange(presetIps);
                            }
                        }
                    }
                }

                parsedRule.Urls = urls.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                parsedRule.Ips = ips.Distinct().ToList();
            }
            else if (rule.Type == "preset" && !string.IsNullOrWhiteSpace(rule.Value))
            {
                var preset = state.Presets.FirstOrDefault(p =>
                    string.Equals(p.Url, rule.Value, StringComparison.OrdinalIgnoreCase));

                if (preset != null)
                {
                    if (!string.IsNullOrWhiteSpace(preset.Domains))
                    {
                        urls = preset.Domains
                            .Split(new[] { '|' }, StringSplitOptions.RemoveEmptyEntries)
                            .Select(d => d.Trim().ToLowerInvariant())
                            .ToList();
                    }

                    if (!string.IsNullOrWhiteSpace(preset.Ips))
                    {
                        ips = preset.Ips
                            .Split(new[] { '|' }, StringSplitOptions.RemoveEmptyEntries)
                            .Select(ip => ip.Trim())
                            .ToList();
                    }
                }

                parsedRule.Urls = urls;
                parsedRule.Ips = ips;
            }

            return parsedRule;
        }
    }
}
