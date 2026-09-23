using System.Text;

namespace Guard
{
    public static class GuardDiagnosticSummary
    {
        public static string Build(GuardState? state)
        {
            if (state == null)
            {
                return "Состояние Guard недоступно.";
            }

            var summary = new StringBuilder();
            string L(string ru, string en) => UiLanguage.Text(state.UiLanguage, ru, en);
            string YesNo(bool value) => value ? L("да", "yes") : L("нет", "no");
            summary.AppendLine(L("------ Состояние Guard ------", "------ Guard Status Summary ------"));
            summary.AppendLine(L("Версия: ", "Version: ") + state.Version);
            summary.AppendLine(L("Устройство привязано: ", "Assigned: ") + YesNo(state.Assigned));
            summary.AppendLine(L("Безопасный PIN родителя задан: ", "Parent PIN configured: ") + YesNo(!EmergencyPinPolicy.IsMissingOrCompromised(state.PinCode)));
            summary.AppendLine(L("Синхронизация включена: ", "Sync enabled: ") + YesNo(state.SyncStatus));
            summary.AppendLine(L("Защита файла hosts активна: ", "Hosts protection active: ") + YesNo(state.IsHostsFileActive));
            summary.AppendLine(L("Автозапуск включён: ", "Startup enabled: ") + YesNo(state.IsStartUp));
            summary.AppendLine(L("Всего правил: ", "Rule count: ") + (state.Rules?.Count ?? 0));
            summary.AppendLine(L("Активных правил: ", "Active rule count: ") + (state.ActiveRuleIds?.Count ?? 0));
            summary.AppendLine(L("Ошибок: ", "Error count: ") + (state.ErrorLog?.Count ?? 0));
            summary.AppendLine(L("------ Конец сводки ------", "------ End of Summary ------"));
            return summary.ToString();
        }
    }
}
