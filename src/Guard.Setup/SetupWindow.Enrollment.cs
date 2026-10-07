using System.IO;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Guard.Windows.Ipc;

namespace Guard.Setup;

public partial class SetupWindow
{
    private NativeSetupSession? _enrollment;
    private NativeSetupSnapshot? _displayed;
    private EnrollmentView? _enrollmentView;
    private bool _beginAttempted, _enrollmentBusy, _pollStopped, _clockInvalid, _polling;
    private DateTimeOffset _lastUiTime = DateTimeOffset.UtcNow, _nextPoll;
    private readonly DispatcherTimer _enrollmentTimer = new() { Interval = TimeSpan.FromSeconds(1) };

    private void InitializeEnrollment()
    {
        _enrollmentTimer.Tick += EnrollmentTick;
        Activated += (_, _) => TryRenderEnrollment();
        Deactivated += (_, _) => { ClearEnrollmentEvidence(); UpdateEnrollmentControls(); };
        Closed += async (_, _) =>
        {
            _closed = true; _enrollmentTimer.Stop(); _operation?.Cancel(); ClearEnrollmentEvidence();
            if (_enrollment != null) await _enrollment.DisposeAsync(); // Forget capability; never send remote cancel on close.
        };
    }

    private async void BeginEnrollment_Click(object sender, RoutedEventArgs e)
    {
        if (_beginAttempted || _operation != null || _inspection?.CanBeginEnrollment != true || !IsActive) return;
        _beginAttempted = true; // A lost first reply must not be retried from this window.
        await RunEnrollmentAsync(async token =>
        {
            EnrollmentStatus.Text = "Начинаем привязку родительского телефона…";
            var session = await NativeSetupSession.BeginAsync(token);
            if (_closed) { await session.DisposeAsync(); return; }
            _enrollment = session; _enrollmentTimer.Start();
            await session.RefreshAsync(token);
        });
    }

    private async void RefreshEnrollment_Click(object sender, RoutedEventArgs e)
    {
        if (_operation != null || _enrollment == null || _enrollmentView?.CanRefresh != true || _clockInvalid || !IsActive) return;
        _pollStopped = false;
        await RunEnrollmentAsync(token => _enrollment.RefreshAsync(token));
    }

    private async void ConfirmEnrollment_Click(object sender, RoutedEventArgs e)
    {
        var compared = _displayed; // Pin the exact screen, not a later asynchronous response.
        if (_operation != null || _enrollment == null || compared == null || Compared.IsChecked != true ||
            _enrollmentView?.CanCompare != true || _clockInvalid || !IsActive) return;
        await RunEnrollmentAsync(token => _enrollment.ConfirmComparedAsync(compared.StateVersion, compared.ClaimHash!, token));
    }

    private async void CancelEnrollment_Click(object sender, RoutedEventArgs e)
    {
        var displayed = _displayed;
        if (_operation != null || _enrollment == null || displayed == null || _enrollmentView?.CanCancel != true || _clockInvalid || !IsActive) return;
        // This clearly named button cancels only the live unconfirmed attempt, not protection or an owner.
        await RunEnrollmentAsync(token => _enrollment.CancelAsync(displayed.StateVersion, token));
    }

    private void Compared_Changed(object sender, RoutedEventArgs e) => UpdateEnrollmentControls();

    private async void EnrollmentTick(object? sender, EventArgs e)
    {
        if (_closed || _enrollment == null) return;
        if (!TryRenderEnrollment()) return;
        if (_operation == null && IsActive && !_pollStopped && !_clockInvalid && _enrollmentView?.AutoRefresh == true &&
            DateTimeOffset.UtcNow >= _nextPoll)
            await RunEnrollmentAsync(token => _enrollment.RefreshAsync(token), polling: true);
    }

    private async Task RunEnrollmentAsync(Func<CancellationToken, Task> action, bool polling = false)
    {
        _enrollmentBusy = true; _polling = polling;
        if (!polling) ClearEnrollmentEvidence();
        await RunAsync(async token =>
        {
            try { await action(token); }
            catch
            {
                _pollStopped = true;
                if (!_closed)
                {
                    ClearEnrollmentEvidence();
                    EnrollmentStatus.Text = _enrollment == null
                        ? "Ответ на начало привязки не получен. Неизвестно, создана ли попытка. Не повторяйте запуск сразу: закройте окно и проверьте установку после окончания срока попытки (до 10 минут)."
                        : "Не удалось получить проверенный ответ. Автообновление остановлено. Нажмите «Проверить привязку», чтобы узнать результат; не начинайте новую попытку.";
                }
            }
        });
        _enrollmentBusy = false; _polling = false;
        _nextPoll = DateTimeOffset.UtcNow.AddSeconds(_enrollment?.Snapshot.Phase == NativeSetupPhase.Confirmed ? 10 : 2);
        if (!_closed) TryRenderEnrollment();
    }

    private bool TryRenderEnrollment()
    {
        try { RenderEnrollment(); UpdateEnrollmentControls(); return true; }
        catch { FailEnrollmentDisplay(); return false; }
    }

    private void RenderEnrollment()
    {
        if (_closed || _enrollment == null) return;
        var now = DateTimeOffset.UtcNow;
        if (now < _lastUiTime) _clockInvalid = true;
        _lastUiTime = now;
        var snapshot = _enrollment.Snapshot;
        _enrollmentView = EnrollmentView.Create(snapshot, _enrollment.ExpiresAt, now);
        EnrollmentDeadline.Text = "Срок попытки: " + _enrollment.ExpiresAt.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss zzz");
        if (_clockInvalid) { FailEnrollmentDisplay(); return; }
        if (!_pollStopped || !_enrollmentView.CanRefresh) EnrollmentStatus.Text = _enrollmentView.Message;
        if (!IsActive || _enrollmentBusy && !_polling || _pollStopped) { ClearEnrollmentEvidence(); UpdateEnrollmentControls(); return; }
        if (_displayed == null || _displayed.Phase != snapshot.Phase || _displayed.StateVersion != snapshot.StateVersion ||
            _displayed.ClaimHash != snapshot.ClaimHash)
        {
            ClearEnrollmentEvidence();
            if (_enrollmentView.ShowQr)
            {
                var bytes = EnrollmentQr.Render(snapshot.QrText!);
                try
                {
                    using var stream = new MemoryStream(bytes, writable: false);
                    var image = new BitmapImage(); image.BeginInit(); image.CacheOption = BitmapCacheOption.OnLoad;
                    image.StreamSource = stream; image.EndInit(); image.Freeze();
                    EnrollmentQrImage.Source = image; EnrollmentQrImage.Visibility = Visibility.Visible;
                    Dispatcher.BeginInvoke(DispatcherPriority.Loaded, new Action(() =>
                    {
                        if (!_closed && IsActive && EnrollmentQrImage.Visibility == Visibility.Visible)
                            EnrollmentQrFrame.BringIntoView();
                    }));
                }
                finally { CryptographicOperations.ZeroMemory(bytes); }
            }
            ComparisonCode.Text = _enrollmentView.ComparisonCode;
            ComparisonPanel.Visibility = _enrollmentView.CanCompare ? Visibility.Visible : Visibility.Collapsed;
            _displayed = snapshot;
        }
        // Expiry can change the view without changing the session snapshot.
        if (!_enrollmentView.ShowQr) { EnrollmentQrImage.Source = null; EnrollmentQrImage.Visibility = Visibility.Collapsed; }
        if (!_enrollmentView.CanCompare) { ComparisonCode.Clear(); Compared.IsChecked = false; ComparisonPanel.Visibility = Visibility.Collapsed; }
        UpdateEnrollmentControls();
    }

    private void ClearEnrollmentEvidence()
    {
        _displayed = null; EnrollmentQrImage.Source = null; EnrollmentQrImage.Visibility = Visibility.Collapsed;
        ComparisonCode.Clear(); Compared.IsChecked = false; ComparisonPanel.Visibility = Visibility.Collapsed;
    }

    private void FailEnrollmentDisplay()
    {
        _clockInvalid = true; _pollStopped = true; ClearEnrollmentEvidence();
        EnrollmentStatus.Text = "Показ безопасного кода остановлен: часы изменились или код не удалось отобразить. Закройте окно и проверьте установку; сохранённую привязку не сбрасывайте.";
        UpdateEnrollmentControls();
    }

    private void UpdateEnrollmentControls()
    {
        // Checked/Unchecked may run during InitializeComponent.
        if (BeginEnrollment == null || ConfirmEnrollment == null) return;
        var available = !_closed && !_clockInvalid && _operation == null && !_enrollmentBusy && IsActive;
        BeginEnrollment.IsEnabled = available && !_beginAttempted && _inspection?.CanBeginEnrollment == true;
        RefreshEnrollment.IsEnabled = available && _enrollmentView?.CanRefresh == true;
        CancelEnrollment.IsEnabled = available && _displayed != null && _enrollmentView?.CanCancel == true;
        ConfirmEnrollment.IsEnabled = available && _displayed != null && _enrollmentView?.CanCompare == true && Compared.IsChecked == true;
    }
}
