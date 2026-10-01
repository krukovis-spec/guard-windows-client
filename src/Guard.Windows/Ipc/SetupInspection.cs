using System;
using System.ComponentModel;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Guard.Contracts;
using Guard.Protocol;
using Guard.Windows.Cryptography;

namespace Guard.Windows.Ipc;

// Observation only. Neither owner binding nor readiness proves active enforcement.
public sealed class SetupInspection
{
    public const string ProtectionNotice = "Защита не подтверждена. Это проверка условий настройки, а не проверка действующих блокировок.";
    public GuardStatusPayload Status { get; }
    public GuardReadinessPayload Readiness { get; }
    public bool CanExport => Status.StateVersion == 0 && !Status.IsProvisioned && !Status.IsChildAccountBound;
    public string[] Lines => new[] {
        Status.IsProvisioned ? "Родитель: привязан" : "Родитель: ещё не привязан",
        Status.IsChildAccountBound ? "Детский аккаунт: выбран" : "Детский аккаунт: ещё не выбран",
        "Windows 11 Pro: " + Fact(Readiness.WindowsEdition),
        "Детский аккаунт без прав администратора: " + Fact(Readiness.ChildAccount),
        "Отдельный аварийный администратор: " + Fact(Readiness.SeparateLocalAdministrator),
        "Безопасная загрузка (Secure Boot): " + Fact(Readiness.SecureBoot),
        "Шифрование диска (BitLocker): " + Fact(Readiness.BitLocker),
        "Установка службы: " + Fact(Readiness.ServiceBoundary),
        "Права доступа к данным Guard: " + Fact(Readiness.ProgramDataAcl),
        "Управляемый браузер: " + Fact(Readiness.SupportedManagedBrowser),
        Readiness.ManagedBrowserCount == 1 ? "Проверен один управляемый браузер. Остальные браузеры не покрыты этой проверкой." : "",
        Readiness.CanEnableProtection ? "Условия настройки выполнены. Включение защиты этим не подтверждено." : "Не все условия настройки подтверждены. Смотрите результаты выше."
    };

    private SetupInspection(GuardStatusPayload status, GuardReadinessPayload readiness)
    { Status = status; Readiness = readiness; }

    public static Task<SetupInspection> ReadAsync(CancellationToken token) => ReadAsync(GuardSetupQueryClient.QueryAsync, token);
    internal static async Task<SetupInspection> ReadAsync(Func<GuardVerb, CancellationToken, Task<GuardIpcResponse>> query, CancellationToken token)
    {
        var status = GuardStatusPayloadCodec.Decode(await ReadPayload(query, GuardVerb.GetStatus, token).ConfigureAwait(false));
        var readiness = GuardReadinessPayloadCodec.Decode(await ReadPayload(query, GuardVerb.GetReadiness, token).ConfigureAwait(false));
        if (status.StateVersion != readiness.StateVersion) throw new SetupQueryException(GuardIpcResponseStatus.Conflict);
        return new SetupInspection(status, readiness);
    }

    public static Task<DeviceProvisioningDescriptor> ReadDescriptorAsync(CancellationToken token) =>
        ReadDescriptorAsync(GuardSetupQueryClient.QueryAsync, token);
    internal static async Task<DeviceProvisioningDescriptor> ReadDescriptorAsync(
        Func<GuardVerb, CancellationToken, Task<GuardIpcResponse>> query, CancellationToken token) =>
        DeviceProvisioningDescriptor.Parse(await ReadPayload(query, GuardVerb.GetDeviceProvisioning, token).ConfigureAwait(false));

    private static async Task<byte[]> ReadPayload(Func<GuardVerb, CancellationToken, Task<GuardIpcResponse>> query, GuardVerb verb, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var response = await query(verb, token).ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        if (response.ProtocolVersion != GuardProtocol.CurrentVersion) throw new InvalidDataException("Setup response version.");
        if (response.Status != GuardIpcResponseStatus.Success) throw new SetupQueryException(response.Status);
        return response.GetPayloadCopy();
    }

    public static string DescribeFailure(Exception error) => error switch {
        OperationCanceledException => "Проверка отменена или служба не ответила вовремя. Можно повторить проверку.",
        SetupQueryException { Status: GuardIpcResponseStatus.Conflict } => "Состояние настройки изменилось. Обновите проверку; повторная первичная привязка может быть недоступна.",
        SetupQueryException { Status: GuardIpcResponseStatus.Unavailable } => "Настройка недоступна в этой установке. Проверьте комплект выпуска и настройку службы.",
        UnauthorizedAccessException => "Не удалось подтвердить доступ к установленной службе Guard. Не продолжайте подключение: проверьте доверенную установку и права администратора.",
        InvalidDataException or System.Text.Json.JsonException or ArgumentException or FormatException or InvalidOperationException =>
            "Ответ службы не прошёл проверку. Подключение остановлено; проверьте, что окно настройки и служба из одного доверенного выпуска.",
        IOException or Win32Exception => "Не удалось прочитать данные или сохранить файл. Проверьте службу, выберите новое имя файла в локальной папке и повторите действие.",
        _ => "Не удалось завершить действие. Закройте окно и проверьте установку Guard. Настройки защиты этим окном не изменяются."
    };

    private static string Fact(GuardReadinessFactState fact) => fact switch {
        GuardReadinessFactState.Satisfied => "подтверждено",
        GuardReadinessFactState.Unsatisfied => "условие не выполнено",
        GuardReadinessFactState.Unknown => "ещё не подтверждено",
        _ => "не удалось проверить"
    };

    private sealed class SetupQueryException(GuardIpcResponseStatus status) : IOException("Setup request refused.")
    { internal GuardIpcResponseStatus Status { get; } = status; }
}
