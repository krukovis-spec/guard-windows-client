using System.Text;

namespace Guard
{
    public static class GuardDiagnosticSummary
    {
        public static string Build(GuardState? state)
        {
            if (state == null)
            {
                return "Guard state is unavailable.";
            }

            var summary = new StringBuilder();
            summary.AppendLine("------ Guard Status Summary ------");
            summary.AppendLine($"Version: {state.Version}");
            summary.AppendLine($"Assigned: {state.Assigned}");
            summary.AppendLine($"ParentPinConfigured: {!EmergencyPinPolicy.IsMissingOrCompromised(state.PinCode)}");
            summary.AppendLine($"SyncEnabled: {state.SyncStatus}");
            summary.AppendLine($"HostsProtectionActive: {state.IsHostsFileActive}");
            summary.AppendLine($"StartupProtectionEnabled: {state.IsStartUp}");
            summary.AppendLine($"RuleCount: {state.Rules?.Count ?? 0}");
            summary.AppendLine($"ActiveRuleCount: {state.ActiveRuleIds?.Count ?? 0}");
            summary.AppendLine($"ErrorCount: {state.ErrorLog?.Count ?? 0}");
            summary.AppendLine("------ End of Summary ------");
            return summary.ToString();
        }
    }
}
