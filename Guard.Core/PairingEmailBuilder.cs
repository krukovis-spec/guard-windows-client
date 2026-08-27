using System;
using System.Linq;

namespace Guard
{
    public static class PairingEmailBuilder
    {
        public static bool IsLikelyEmail(string? email)
        {
            var trimmed = email?.Trim() ?? "";
            if (string.IsNullOrWhiteSpace(trimmed)) return false;

            return trimmed.Length <= 254 &&
                   trimmed.Count(c => c == '@') == 1 &&
                   trimmed.IndexOf('@') > 0 &&
                   trimmed.LastIndexOf('.') > trimmed.IndexOf('@') + 1 &&
                   trimmed.LastIndexOf('.') < trimmed.Length - 1 &&
                   !trimmed.Any(char.IsWhiteSpace);
        }

        public static string BuildSubject(DevicePairing pairing)
        {
            var name = string.IsNullOrWhiteSpace(pairing.DeviceName)
                ? "детский компьютер"
                : pairing.DeviceName.Trim();

            return "Настройка Guard для " + name;
        }

        public static string BuildBody(DevicePairing pairing, string parentCabinetUrls)
        {
            var expires = pairing.ExpiresAtUtc.HasValue
                ? pairing.ExpiresAtUtc.Value.ToLocalTime().ToString("HH:mm")
                : "soon";

            return "Guard ожидает настройки родителем." + Environment.NewLine +
                   Environment.NewLine +
                   "Код привязки: " + PairingCodeService.FormatCode(pairing.Code) + Environment.NewLine +
                   "Формат кода: ABCD-EFGH" + Environment.NewLine +
                   "Код действует до: " + expires + Environment.NewLine +
                   Environment.NewLine +
                   "Открой один из этих адресов на компьютере родителя в той же домашней сети:" + Environment.NewLine +
                   parentCabinetUrls.Trim() + Environment.NewLine +
                   Environment.NewLine +
                   "Потом введи код привязки и задай родительский пароль в браузере." + Environment.NewLine +
                   "Родительский пароль по почте не отправляй.";
        }

        public static string BuildMailToUri(string parentEmail, DevicePairing pairing, string parentCabinetUrls)
        {
            var email = (parentEmail ?? "").Trim();
            var subject = Uri.EscapeDataString(BuildSubject(pairing));
            var body = Uri.EscapeDataString(BuildBody(pairing, parentCabinetUrls));
            return "mailto:" + Uri.EscapeDataString(email) + "?subject=" + subject + "&body=" + body;
        }
    }
}
