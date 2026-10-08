using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Guard.Contracts;
using Guard.Protocol;

namespace Guard.Child;

public partial class ChildWindow : Window
{
    private readonly IChildBackend _backend;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly DispatcherTimer _expiry = new() { Interval = TimeSpan.FromSeconds(1) };
    private readonly Dictionary<string, string> _queued = new(StringComparer.Ordinal);
    private bool _busy;
    private bool _closed;
    private bool _historyVisible;

    internal ChildWindow(IChildBackend backend)
    {
        _backend = backend;
        InitializeComponent();
        _expiry.Tick += (_, _) => UpdateControls();
        Loaded += (_, _) => { _expiry.Start(); UpdateControls(); };
        Closed += (_, _) => { _closed = true; _expiry.Stop(); _lifetime.Cancel(); if (!_busy) _lifetime.Dispose(); };
    }

    private bool TryPayload(out CreateApplicationRequestPayload? payload)
    {
        payload = null;
        if (Applications?.SelectedItem is not BlockedApplicationItem item) return false;
        var reason = Reason.Text.Trim();
        try
        {
            // The signed native request has a 280-byte UTF-8 limit, not 280 letters.
            reason = reason.Normalize(NormalizationForm.FormC);
            if (Encoding.UTF8.GetByteCount(reason) > 280) return false;
            payload = new CreateApplicationRequestPayload(item.ObservationId, reason.Length == 0 ? null : reason);
            return true;
        }
        catch (ArgumentException) { return false; }
    }

    private void UpdateControls()
    {
        if (!IsInitialized || _closed) return;
        Refresh.IsEnabled = !_busy;
        ToggleHistory.IsEnabled = !_busy;
        Applications.IsEnabled = !_busy;
        Reason.IsEnabled = !_busy;
        var item = Applications.SelectedItem as BlockedApplicationItem;
        var valid = TryPayload(out _);
        Send.IsEnabled = !_busy && !_historyVisible && valid && item != null && DateTimeOffset.UtcNow >= item.ObservedAtUtc &&
            DateTimeOffset.UtcNow < item.ExpiresAtUtc && !_queued.ContainsKey(item.ObservationId);
        ReasonHint.Text = item != null && !valid ? "Сократите пояснение: до 140 русских букв. Переносы строк и скрытые символы не подходят." : "Короткого пояснения достаточно.";
    }

    private void Reason_Changed(object sender, TextChangedEventArgs e) => UpdateControls();
    private void Selection_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (!IsInitialized || _busy) return;
        if (Applications.SelectedItem is BlockedApplicationItem item && _queued.TryGetValue(item.ObservationId, out var message)) Status.Text = message;
        else Status.Text = "Выберите программу и нажмите «Попросить доступ».";
        UpdateControls();
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || _closed) return;
        if (_historyVisible) { await ReadHistoryAsync(); return; }
        _busy = true; UpdateControls(); Status.Text = "Получаем список с этого компьютера…";
        try
        {
            var response = await _backend.ReadAsync(_lifetime.Token);
            if (_closed) return;
            Applications.ItemsSource = null;
            if (response.Status != GuardIpcResponseStatus.Success) { Status.Text = Failure(response.Status, false); return; }
            var payload = BlockedApplicationsPayloadCodec.Decode(response.GetPayloadCopy());
            Applications.ItemsSource = payload.Items;
            Applications.SelectedIndex = -1;
            Status.Text = payload.Items.Count == 0
                ? "Недавних блокировок нет. Этот список не подтверждает, что защита включена."
                : "Выберите программу. Обновление списка ничего не разрешает.";
        }
        catch (Exception) when (!_closed)
        { Applications.ItemsSource = null; Status.Text = "Список недоступен. Попробуйте обновить его. Если это повторяется, попросите родителя проверить настройку Guard."; }
        catch (Exception) when (_closed) { }
        finally { Finish(); }
    }

    private void ToggleHistory_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || _closed) return;
        _historyVisible = !_historyVisible;
        Heading.Text = _historyVisible ? "Что с моей просьбой?" : "Нужен доступ к программе?";
        Introduction.Text = _historyVisible ? "Здесь — сохранённые просьбы и ответы на этом компьютере." :
            "Выберите её в списке и попросите родителя разрешить запуск.";
        Applications.Visibility = ReasonPanel.Visibility = Send.Visibility = _historyVisible ? Visibility.Collapsed : Visibility.Visible;
        History.Visibility = _historyVisible ? Visibility.Visible : Visibility.Collapsed;
        SectionTitle.Text = _historyVisible ? "Мои просьбы" : "Недавние блокировки";
        ToggleHistory.Content = _historyVisible ? "Новый запрос" : "Мои просьбы";
        Refresh.Content = _historyVisible ? "Обновить историю" : "Обновить список";
        Refresh_Click(sender, e);
    }

    private async Task ReadHistoryAsync()
    {
        _busy = true; UpdateControls(); History.ItemsSource = null;
        Status.Text = "Проверяем ответы на этом компьютере…";
        try
        {
            var response = await _backend.ReadHistoryAsync(_lifetime.Token);
            if (_closed) return;
            if (response.Status != GuardIpcResponseStatus.Success) { Status.Text = Failure(response.Status, false); return; }
            var payload = BlockedApplicationsPayloadCodec.DecodeHistory(response.GetPayloadCopy());
            History.ItemsSource = payload.Items.Select(item => new
            {
                item.DisplayName, CreatedAt = item.CreatedAtUtc.LocalDateTime, RecordedAt = item.RecordedAtUtc.LocalDateTime,
                StatusText = item.Status switch
                {
                    ApplicationRequestHistoryStatus.AwaitingResponse => "Ответа пока нет. Доставка родителю не подтверждена.",
                    ApplicationRequestHistoryStatus.AwaitingApplication => "Родитель разрешил. Компьютер ещё не подтвердил применение.",
                    ApplicationRequestHistoryStatus.Denied => "Родитель отклонил эту просьбу.",
                    ApplicationRequestHistoryStatus.Expired => "Срок просьбы истёк. Если доступ нужен, запросите его заново.",
                    ApplicationRequestHistoryStatus.NotApplied => "Ответ получен, но решение не применено. Попросите родителя проверить Guard.",
                    _ => "Компьютер подтвердил применение в прошлом. Доступ сейчас не проверен."
                }
            }).ToArray();
            Status.Text = payload.Items.Count == 0 ? "Сохранённых просьб этого аккаунта пока нет." :
                $"Последние {payload.Items.Count} просьб. Проверено {payload.CheckedAtUtc.LocalDateTime:dd.MM HH:mm}. История не подтверждает доступ сейчас.";
        }
        catch (Exception) when (!_closed)
        { History.ItemsSource = null; Status.Text = "Не удалось проверить историю. Нажмите «Обновить историю», чтобы повторить."; }
        catch (Exception) when (_closed) { }
        finally { Finish(); }
    }

    private async void Send_Click(object sender, RoutedEventArgs e)
    {
        UpdateControls();
        if (_busy || _closed || !Send.IsEnabled || !TryPayload(out var payload)) return;
        _busy = true; UpdateControls(); Status.Text = "Сохраняем просьбу на этом компьютере…";
        try
        {
            var response = await _backend.RequestAsync(payload!, _lifetime.Token);
            if (_closed) return;
            if (response.Status != GuardIpcResponseStatus.Success) { Status.Text = Failure(response.Status, true); return; }
            _ = BlockedApplicationsPayloadCodec.DecodeQueued(response.GetPayloadCopy());
            // Even a lost-response retry acknowledges only the original local queue entry.
            var message = "Просьба сохранена на компьютере для отправки родителю. Доступ пока не подтверждён.";
            _queued[payload!.ObservationId] = message;
            Status.Text = message;
        }
        catch (Exception) when (!_closed)
        { Status.Text = "Не удалось получить ответ. Просьба могла сохраниться. Повторите отправку той же программы — действующий запрос не продублируется."; }
        catch (Exception) when (_closed) { }
        finally { Finish(); }
    }

    private void Finish()
    {
        _busy = false;
        if (_closed) _lifetime.Dispose(); else UpdateControls();
    }
    private static string Failure(GuardIpcResponseStatus status, bool submission) => status switch
    {
        GuardIpcResponseStatus.Forbidden => "Этот аккаунт не подключён для запросов. Попросите родителя проверить настройку Guard.",
        GuardIpcResponseStatus.Conflict or GuardIpcResponseStatus.Rejected => "Сведения изменились или устарели. Обновите список и выберите программу заново.",
        GuardIpcResponseStatus.InvalidRequest => "Не удалось обработать просьбу. Обновите список и сократите пояснение.",
        _ => submission
            ? "Нет подтверждения сохранения. Просьба могла сохраниться. Повторите отправку той же программы."
            : "Список пока недоступен. Попросите родителя проверить настройку Guard."
    };
}
