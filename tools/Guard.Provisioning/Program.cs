using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Guard.Windows.Cryptography;

namespace Guard.Provisioning;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        try
        {
            if ((args.Length == 4 || args.Length == 6 && args[4] == "--credential-file") && args[0] == "prepare-mailbox")
            {
                Console.WriteLine("Только родительский ПК. Сначала создайте и сохраните в Bitwarden отдельный случайный пароль ящика (от 32 символов).");
                if (args.Length == 4) Console.Write("Вставьте этот пароль (не API-токен Cloudflare; ввод скрыт): ");
                var credential = args.Length == 6 ? ReadCredentialFile(args[5], "MAILBOX_ADMIN_TOKEN") : ReadCredential();
                MailboxProvisioningJob.Prepare(args[1], args[2], credential, args[3], DateTimeOffset.UtcNow);
                Console.WriteLine("Приватное задание ящика сохранено. На сервер ничего не отправлено; master copy оставьте в Bitwarden.");
                return 0;
            }
            if ((args.Length == 3 || args.Length == 5 && args[3] == "--credential-file") && args[0] == "publish-mailbox")
            {
                if (args.Length == 3) Console.Write("Введите отдельный BOOTSTRAP_ADMIN_TOKEN своего Guard relay (не API-токен Cloudflare; ввод скрыт): ");
                var credential = args.Length == 5 ? ReadCredentialFile(args[4], "BOOTSTRAP_ADMIN_TOKEN") : ReadCredential();
                var expires = await MailboxProvisioningJob.PublishAsync(args[1], args[2], credential, DateTimeOffset.UtcNow, CancellationToken.None);
                Console.WriteLine("Сервер подтвердил доступ администратора ящика до " + expires.ToString("u", CultureInfo.InvariantCulture) + ". Это не срок работы Guard.");
                return 0;
            }
            if (args.Length == 5 && args[0] == "publish-with-mailbox")
            {
                await MailboxProvisioningJob.PublishDeviceAsync(args[1], args[2], args[3], args[4], DateTimeOffset.UtcNow, CancellationToken.None);
                Console.WriteLine("Доступ устройства подтверждён. Зашифрованный профиль сохранён без административного ключа. Защита ещё не установлена.");
                return 0;
            }
            if (args.Length == 7 && args[0] == "prepare")
            {
                if (!DateTimeOffset.TryParseExact(args[5], "yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var expires))
                    throw new ArgumentException("Expiry format.");
                ProvisioningJob.Prepare(args[1], args[2], args[3], args[4], expires, args[6], DateTimeOffset.UtcNow);
                Console.WriteLine("Задание сохранено для текущего пользователя Windows. На сервер ничего не отправлено.");
                return 0;
            }
            if (args.Length == 4 && args[0] == "publish")
            {
                Console.WriteLine("Только родительский компьютер. Токен администратора ящика не попадёт в профиль ребёнка.");
                Console.Write("Введите токен администратора ящика (ввод скрыт): ");
                var credential = ReadCredential();
                await ProvisioningJob.PublishAsync(args[1], args[2], args[3], credential, DateTimeOffset.UtcNow, CancellationToken.None);
                Console.WriteLine("Доступ устройства подтверждён сервером. Зашифрованный профиль сохранён. Защита ещё не установлена.");
                return 0;
            }
            if (args.Length == 4 && args[0] == "verify-native")
            {
                var confirmed = ProvisioningJob.VerifyNativeConfirmation(args[1], args[2], args[3], DateTimeOffset.UtcNow);
                Console.WriteLine("Подпись проверена по исходному ключу компьютера. Подтверждение действительно до " +
                    confirmed.ExpiresAtUtc.ToString("u", CultureInfo.InvariantCulture) + ". Сеть и права доступа не изменены.");
                return 0;
            }
            if (args.Length == 5 && args[0] == "prepare-native")
            {
                ProvisioningJob.PrepareNativeActivation(args[1], args[2], args[3], args[4]);
                Console.WriteLine("Приватное задание активации сохранено. Права обмена ещё не изменены; этот файл оставьте только на родительском ПК.");
                return 0;
            }
            if (args.Length == 6 && args[0] == "activate-native")
            {
                await MailboxProvisioningJob.ActivateNativeAsync(args[1], args[2], args[3], args[4], args[5], CancellationToken.None);
                Console.WriteLine("Relay подтвердил права обмена компьютера и привязанного телефона. Задание сохранено для повтора. Передача доступа телефону ещё не выполнена; защита не подтверждена.");
                return 0;
            }
            if (args.Length == 7 && args[0] == "export-native")
            {
                var digest = await MailboxProvisioningJob.ActivateNativeAsync(args[1], args[2], args[3], args[4], args[5],
                    CancellationToken.None, outputPath: args[6]);
                Console.WriteLine("Права обмена подтверждены. Сохранён профиль, зашифрованный для привязанного телефона; административных ключей в нём нет.");
                Console.WriteLine("SHA-256 для независимой проверки на телефоне: " + digest);
                Console.WriteLine("Передавайте только этот .guard-native файл. Задания .job оставьте на родительском ПК. Это не разрешение приложения и не подтверждение защиты Windows.");
                return 0;
            }
            Console.WriteLine("Guard.Provisioning — служебная утилита, только для родительского ПК.");
            Console.WriteLine("prepare-mailbox <доверенный-HTTPS-origin> <новый-mailboxId> <новый-файл-задания-ящика>");
            Console.WriteLine("publish-mailbox <тот-же-доверенный-origin> <файл-задания-ящика>");
            Console.WriteLine("Для этих двух команд: необязательный --credential-file <приватный-DPAPI-файл>, вместо ручного ввода.");
            Console.WriteLine("prepare <доверенный-HTTPS-origin> <описание.json> <проверенный-SHA256> <mailboxId> <срок-UTC:2027-10-01T00:00:00Z> <новый-файл-задания>");
            Console.WriteLine("publish <тот-же-доверенный-origin> <файл-задания> <новый-файл-профиля>");
            Console.WriteLine("publish-with-mailbox <тот-же-доверенный-origin> <файл-задания-устройства> <файл-задания-ящика> <новый-файл-профиля>");
            Console.WriteLine("verify-native <тот-же-доверенный-origin> <исходный-файл-задания-устройства> <подтверждение.guard-proof>");
            Console.WriteLine("prepare-native <тот-же-доверенный-origin> <исходный-файл-задания-устройства> <подтверждение.guard-proof> <новое-задание-активации>");
            Console.WriteLine("activate-native <тот-же-доверенный-origin> <исходный-файл-задания-устройства> <задание-активации> <свежее-подтверждение.guard-proof> <задание-ящика>");
            Console.WriteLine("export-native <тот-же-доверенный-origin> <исходный-файл-задания-устройства> <задание-активации> <свежее-подтверждение.guard-proof> <задание-ящика> <новый-файл.guard-native>");
            Console.WriteLine("Файлы задания и профиля — по абсолютным путям вне Git. Секреты не передавайте в аргументах.");
            return args.Length == 0 || args.SequenceEqual(new[] { "--help" }) ? 0 : 2;
        }
        catch (Exception error)
        {
            // Never expose exception details: remote bodies, paths or credentials can occur in them.
            Console.Error.WriteLine(error switch {
                UnauthorizedAccessException => "Нет доступа к файлу либо его права не ограничены текущим пользователем Windows.",
                System.Security.Cryptography.CryptographicException => "Не удалось проверить зашифрованный файл. Нужны исходный файл и тот же пользователь Windows.",
                HttpRequestException or OperationCanceledException => "Обмен не завершён. Результат на сервере может быть неизвестен.",
                InvalidDataException or System.Text.Json.JsonException or ArgumentException => "Проверка адреса, описания компьютера, срока или ответа сервера не пройдена.",
                IOException => "Не удалось прочитать или создать файл. Существующие файлы утилита не перезаписывает.",
                _ => "Операция не завершена. Профиль не подтверждён."
            });
            Console.Error.WriteLine("Сохраните исходные задания: повторяйте ту же publish/activate-команду с ними. Для активации нужно действующее подтверждение Windows. Не заменяйте токен и не используйте другой сервер.");
            return 1;
        }
    }

    internal static string ReadCredentialFile(string path, string name)
    {
        var raw = LocalSystemDpapiDataProtector.ForOperatorCredential(name)
            .Unprotect(ProvisioningJob.ReadBounded(path, 8192, requirePrivate: true));
        try
        {
            if (raw.Length is < 32 or > 512) throw new InvalidDataException("Credential size.");
            var value = new UTF8Encoding(false, true).GetString(raw);
            ProvisioningJob.RequireCredential(value);
            return value;
        }
        finally { CryptographicOperations.ZeroMemory(raw); }
    }

    private static string ReadCredential()
    {
        if (Console.IsInputRedirected) throw new InvalidOperationException("Interactive input required.");
        var buffer = new char[512]; var length = 0;
        try
        {
            while (true)
            {
                var key = Console.ReadKey(intercept: true);
                if (key.Key == ConsoleKey.Escape) throw new OperationCanceledException();
                if (key.Key == ConsoleKey.Enter) break;
                if (key.Key == ConsoleKey.Backspace) { if (length > 0) buffer[--length] = '\0'; continue; }
                if (key.KeyChar < '!' || key.KeyChar > '~' || length == buffer.Length) throw new ArgumentException("Credential input.");
                buffer[length++] = key.KeyChar;
            }
            Console.WriteLine();
            var result = new string(buffer, 0, length); ProvisioningJob.RequireCredential(result); return result;
        }
        finally { Array.Clear(buffer); }
    }
}
