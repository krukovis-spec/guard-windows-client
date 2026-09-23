namespace Guard
{
    public static class UiLanguage
    {
        public const string Russian = "ru";
        public const string English = "en";

        public static string Normalize(string? language)
        {
            var value = (language ?? "").Trim().ToLowerInvariant();
            return value == English ? English : Russian;
        }

        public static bool IsRussian(string? language)
        {
            return Normalize(language) == Russian;
        }

        public static string Text(string? language, string russian, string english)
        {
            return IsRussian(language) ? russian : english;
        }

        // Domain errors stay stable for callers; translate only at the presentation boundary.
        public static string Message(string? language, string message)
        {
            if (!IsRussian(language)) return message;
            switch (message)
            {
                case "Invalid application path.": return "Неверный путь к приложению.";
                case "Invalid domain.": return "Неверный адрес сайта.";
                case "Pending access request was not found.": return "Ожидающий решения запрос не найден.";
                case "Pending application request was not found.": return "Ожидающий решения запрос приложения не найден.";
                case "Task title is required.": return "Введите название задачи.";
                case "Verified task requires an application path.": return "Для проверки задачи нужен путь к приложению.";
                case "Active task was not found.": return "Активная задача не найдена.";
                case "Task is already completed for today.": return "Сегодня эта задача уже выполнена.";
                case "Task does not have enough verified active time yet.": return "Для выполнения задачи пока недостаточно подтверждённого времени работы.";
                default: return message;
            }
        }

        public static string CleanupStep(GuardCleanupStep? step)
        {
            switch (step)
            {
                case GuardCleanupStep.DisableWatchdog: return "остановка автоматического перезапуска";
                case GuardCleanupStep.HostsFile: return "восстановление файла hosts";
                case GuardCleanupStep.FirewallRules: return "удаление правил брандмауэра";
                case GuardCleanupStep.StartupEntries: return "удаление записей автозапуска";
                case GuardCleanupStep.StateFiles: return "удаление сохранённых настроек";
                default: return "неизвестный этап";
            }
        }
    }
}
