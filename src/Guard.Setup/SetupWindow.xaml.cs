using System.Windows;
using Guard.Windows.Ipc;
using Microsoft.Win32;

namespace Guard.Setup;

public partial class SetupWindow : Window
{
    private CancellationTokenSource? _operation;
    private SetupInspection? _inspection;
    private bool _closed;

    public SetupWindow()
    {
        InitializeComponent();
        Protection.Text = SetupInspection.ProtectionNotice;
        Closed += (_, _) => { _closed = true; _operation?.Cancel(); };
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e)
    {
        if (_operation != null) return;
        _inspection = null; Facts.ItemsSource = null; CheckedAt.Text = "";
        Digest.Clear(); ExportStatus.Text = "";
        await RunAsync(async token =>
        {
            Status.Text = "Проверяем установленную службу Guard…";
            var inspection = await SetupInspection.ReadAsync(token);
            token.ThrowIfCancellationRequested();
            if (_closed) return;
            _inspection = inspection; Facts.ItemsSource = inspection.Lines.Where(line => line.Length != 0);
            CheckedAt.Text = "Состояние на " + inspection.Readiness.ObservedAtUtc.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss zzz");
            Status.Text = "Ответ получен от установленной службы Guard. Результаты проверки — ниже.";
            if (!inspection.CanExport) ExportStatus.Text = "Первичное описание недоступно: настройка этого компьютера уже начата. Не сбрасывайте привязку для повторного экспорта.";
        });
    }

    private async void Export_Click(object sender, RoutedEventArgs e)
    {
        if (_operation != null || _inspection?.CanExport != true) return;
        Digest.Clear(); ExportStatus.Text = "";
        await RunAsync(async token =>
        {
            Status.Text = "Читаем и проверяем описание компьютера…";
            var descriptor = await SetupInspection.ReadDescriptorAsync(token);
            token.ThrowIfCancellationRequested();
            if (_closed) return;
            var dialog = new SaveFileDialog { Title = "Сохранить новое описание компьютера", FileName = "guard-device.json",
                Filter = "Описание Guard (*.json)|*.json", DefaultExt = ".json", AddExtension = true,
                CheckPathExists = true, OverwritePrompt = false };
            if (dialog.ShowDialog(this) != true)
            { Status.Text = "Сохранение отменено. Описание компьютера не записано."; return; }
            token.ThrowIfCancellationRequested();
            descriptor.SaveNew(dialog.FileName);
            Digest.Text = descriptor.Sha256;
            ExportStatus.Text = "Описание сохранено. Сервер: " + descriptor.RelayOrigin +
                "\nКомпьютер: " + descriptor.DeviceId + "\nСверьте весь код ниже на доверенном компьютере оператора. Файл сам по себе не подтверждает владение.";
            Status.Text = "Файл сохранён. Подключение телефона и защита ещё не подтверждены.";
        });
    }

    private async Task RunAsync(Func<CancellationToken, Task> action)
    {
        using var operation = new CancellationTokenSource();
        _operation = operation; Refresh.IsEnabled = Export.IsEnabled = false; Cancel.IsEnabled = true;
        try { await action(operation.Token); }
        catch (Exception error)
        {
            if (!_closed)
            {
                _inspection = null; Facts.ItemsSource = null; CheckedAt.Text = ""; Digest.Clear(); ExportStatus.Text = "";
                Status.Text = SetupInspection.DescribeFailure(error); // Never display/log raw service payloads, paths or exception messages.
            }
        }
        finally
        {
            _operation = null;
            if (!_closed) { Refresh.IsEnabled = true; Cancel.IsEnabled = false; Export.IsEnabled = _inspection?.CanExport == true; }
        }
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => _operation?.Cancel();
    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
