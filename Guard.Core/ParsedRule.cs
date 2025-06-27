using System.Collections.Generic;

namespace Guard
{
    public class ParsedRule
    {
        public string RuleId { get; set; } = "";
        public List<string> Urls { get; set; } = new List<string>();
        public List<string> Ips { get; set; } = new List<string>();
        public List<string> ResolvedIps { get; set; } = new List<string>();
        public string Schedule { get; set; } = "";
    }
}
