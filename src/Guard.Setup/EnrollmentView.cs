using System;
using System.Linq;
using Guard.Windows.Ipc;

namespace Guard.Setup;

// Pure presentation of an authenticated session, not authority or enforcement evidence.
internal sealed class EnrollmentView
{
    public string Message { get; private init; } = "";
    public string ComparisonCode { get; private init; } = "";
    public bool ShowQr { get; private init; }
    public bool CanCompare { get; private init; }
    public bool CanCancel { get; private init; }
    public bool CanRefresh { get; private init; }
    public bool AutoRefresh { get; private init; }

    public static EnrollmentView Create(NativeSetupSnapshot state, DateTimeOffset expiry, DateTimeOffset now)
    {
        var phase = state.Phase;
        var live = now < expiry;
        if (!live && phase is not (NativeSetupPhase.Confirmed or NativeSetupPhase.ConfirmationUnknown or
            NativeSetupPhase.Cancelled or NativeSetupPhase.CancellationUnknown or NativeSetupPhase.RecoveryRequired))
            phase = NativeSetupPhase.Expired;
        var compare = phase == NativeSetupPhase.ComparePhone && state.ClaimHash?.Length == 64;
        return new EnrollmentView
        {
            ShowQr = phase == NativeSetupPhase.ScanPhone && state.QrText != null,
            CanCompare = compare && live,
            ComparisonCode = compare ? string.Join("\n", Enumerable.Range(0, 8).Select(i => state.ClaimHash!.Substring(i * 8, 8))) : "",
            CanCancel = live && state.StateVersion >= 0 && phase is (NativeSetupPhase.ScanPhone or
                NativeSetupPhase.PhoneProof or NativeSetupPhase.ComparePhone or NativeSetupPhase.RestartRequired),
            CanRefresh = phase is NativeSetupPhase.RelayPending or NativeSetupPhase.ScanPhone or NativeSetupPhase.PhoneProof or
                NativeSetupPhase.ComparePhone or NativeSetupPhase.ConfirmationUnknown or NativeSetupPhase.Confirmed,
            AutoRefresh = phase is NativeSetupPhase.RelayPending or NativeSetupPhase.ScanPhone or NativeSetupPhase.PhoneProof or
                NativeSetupPhase.ConfirmationUnknown || phase == NativeSetupPhase.Confirmed && !state.RelayPassCompleted && !state.RecoveryRequired,
            Message = phase switch
            {
                NativeSetupPhase.RelayPending => "Готовим подключение телефона. QR появится после ответа сервера.",
                NativeSetupPhase.ScanPhone => "Откройте Guard на родительском телефоне и отсканируйте QR. Не отправляйте этот код другим людям.",
                NativeSetupPhase.PhoneProof => "Проверяем телефон. Завершите подтверждение в приложении Guard на телефоне.",
                NativeSetupPhase.ComparePhone => "Сравните все восемь строк с кодом на телефоне. Если хотя бы один символ отличается, отмените привязку.",
                NativeSetupPhase.RestartRequired => "Служба перезапустилась; прежний QR недоступен. Отмените эту попытку либо дождитесь окончания её срока, затем откройте настройку заново.",
                NativeSetupPhase.ConfirmationUnknown => "Ответ на подтверждение потерян. Проверяем, сохранилась ли привязка. Не подтверждайте повторно и не начинайте новую попытку.",
                NativeSetupPhase.Confirmed when state.RecoveryRequired => "Привязка сохранена, но доставку результата телефону подтвердить не удалось. Нужна проверка подключения; не сбрасывайте владельца. Защита не подтверждена.",
                NativeSetupPhase.Confirmed => "Привязка сохранена на компьютере. Проверьте результат в Guard на телефоне. Это ещё не подтверждает рабочий обмен разрешениями или включённую защиту.",
                NativeSetupPhase.CancellationUnknown => "Ответ на отмену потерян. Неизвестно, приняла ли её служба. Не начинайте новую привязку; проверьте состояние установки после окончания срока попытки.",
                NativeSetupPhase.Cancelled => "Попытка привязки отменена. Для новой попытки закройте это окно и откройте настройку заново.",
                NativeSetupPhase.Expired => "Срок попытки закончился. QR и подтверждение недоступны. Закройте окно и проверьте состояние установки перед новой попыткой.",
                _ => "Продолжить эту попытку безопасно не удалось. Закройте окно и проверьте доверенную установку Guard. Привязку не сбрасывайте."
            }
        };
    }
}
