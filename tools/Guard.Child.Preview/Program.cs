using System.IO;
using System.Security.Principal;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Guard.Contracts;
using Guard.Protocol;

namespace Guard.Child;

internal static class PreviewProgram
{
    [STAThread]
    private static int Main(string[] args)
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)) return 2;
        if (args.Length != 1 || args[0] != "--check") return 2;
        var app = new System.Windows.Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
        app.Startup += async (_, _) =>
        {
            try { await CheckAsync(); Console.WriteLine("PASS child WPF: real view, selection, UTF-8 bounds, double click, queue/unknown/failure/close and compact layout"); app.Shutdown(0); }
            catch (Exception error) { Console.Error.WriteLine(error); app.Shutdown(1); }
        };
        return app.Run();
    }

    private static async Task CheckAsync()
    {
        var backend = new PreviewBackend();
        var window = new ChildWindow(backend) { Title = "Guard — ДЕМО без службы и защиты" };
        try
        {
            window.Show(); await Task.Yield();
            Check(!window.Send.IsEnabled, "unselected send enabled");
            Click(window.Refresh); await Until(() => window.Refresh.IsEnabled);
            Check(window.Applications.Items.Count == 2 && !window.Send.IsEnabled && backend.Requests == 0, "list auto sent/selected");
            window.Applications.SelectedIndex = 0;
            Check(window.Send.IsEnabled, "selected send disabled");
            window.Reason.Text = new string('я', 141); Check(!window.Send.IsEnabled, "native byte bound");
            window.Reason.Text = "Урок\u202e"; Check(!window.Send.IsEnabled, "hidden format");
            window.Reason.Text = "Для домашнего задания";
            for (var i = 0; i < 2; i++)
            {
                window.Width = i == 0 ? 620 : 420; window.Height = i == 0 ? 610 : 500; window.UpdateLayout();
                Check(window.Applications.ActualHeight >= 38 && window.Send.TransformToAncestor(window).Transform(new Point()).Y + window.Send.ActualHeight < window.ActualHeight - 30,
                    "compact layout clipped");
            }
            window.Width = 620; window.Height = 610; window.UpdateLayout();
            var bitmap = new RenderTargetBitmap((int)window.ActualWidth, (int)window.ActualHeight, 96, 96, PixelFormats.Pbgra32);
            bitmap.Render(window); var png = new PngBitmapEncoder(); png.Frames.Add(BitmapFrame.Create(bitmap));
            var directory = Directory.CreateTempSubdirectory("Guard-child-preview-");
            var path = Path.Combine(directory.FullName, "child-window.png");
            using (var output = File.Create(path)) png.Save(output);
            Console.WriteLine("Preview image: " + path);
            var gate = new TaskCompletionSource<GuardIpcResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
            backend.Pending = gate.Task;
            Click(window.Send); Click(window.Send);
            Check(backend.Requests == 1 && !window.Refresh.IsEnabled && !window.Applications.IsEnabled && !window.Reason.IsEnabled, "double click/reentrant selection");
            gate.SetResult(PreviewBackend.Queued()); await Until(() => window.Refresh.IsEnabled);
            Check(!window.Send.IsEnabled && window.Status.Text.Contains("Доступ пока не подтверждён"), "queue shown as permission");
            Click(window.Send); Check(backend.Requests == 1, "repeat confirmed queue");
            window.Applications.SelectedIndex = 1; backend.Pending = Task.FromException<GuardIpcResponse>(new IOException("synthetic lost response"));
            Click(window.Send); await Until(() => window.Refresh.IsEnabled);
            Check(window.Status.Text.Contains("могла сохраниться") && window.Send.IsEnabled, "unknown result not recoverable");
            backend.Pending = Task.FromResult(PreviewBackend.Queued()); Click(window.Send); await Until(() => window.Refresh.IsEnabled);
            Check(backend.Requests == 3 && !window.Send.IsEnabled, "retry did not complete");
            backend.ReadStatus = GuardIpcResponseStatus.Unavailable; Click(window.Refresh); await Until(() => window.Refresh.IsEnabled);
            Check(window.Applications.Items.Count == 0 && !window.Send.IsEnabled && window.Status.Text.Contains("недоступен"), "read failure retained selectable stale list");
            backend.ReadStatus = GuardIpcResponseStatus.Success; backend.Empty = true; Click(window.Refresh); await Until(() => window.Refresh.IsEnabled);
            Check(window.Status.Text.Contains("не подтверждает"), "empty list implied protection");
            backend.Empty = false; Click(window.Refresh); await Until(() => window.Refresh.IsEnabled);
            window.Applications.SelectedIndex = 0; window.Reason.Text = "";
        }
        finally { window.Close(); }
        backend = new PreviewBackend(); window = new ChildWindow(backend);
        window.Show(); Click(window.Refresh); await Until(() => window.Refresh.IsEnabled);
        window.Applications.SelectedIndex = 0;
        var late = new TaskCompletionSource<GuardIpcResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
        backend.Pending = late.Task; Click(window.Send); window.Close();
        Check(backend.LastToken.IsCancellationRequested, "closing did not cancel");
        late.SetResult(PreviewBackend.Queued()); await Task.Yield(); await Task.Delay(50);
        Check(!window.IsVisible, "late completion reopened window");
    }

    private static void Click(Button button) => button.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
    private static void Check(bool value, string message) { if (!value) throw new InvalidOperationException(message); }
    private static async Task Until(Func<bool> predicate)
    {
        var end = DateTime.UtcNow.AddSeconds(3);
        while (!predicate()) { if (DateTime.UtcNow >= end) throw new TimeoutException("UI did not settle."); await Task.Delay(10); }
    }
}

internal sealed class PreviewBackend : IChildBackend
{
    internal int Requests;
    internal bool Empty;
    internal GuardIpcResponseStatus ReadStatus = GuardIpcResponseStatus.Success;
    internal Task<GuardIpcResponse>? Pending;
    internal CancellationToken LastToken;
    public Task<GuardIpcResponse> ReadAsync(CancellationToken token)
    {
        token.ThrowIfCancellationRequested(); var now = DateTimeOffset.UtcNow;
        var items = Empty ? Array.Empty<BlockedApplicationItem>() : new[] {
            new BlockedApplicationItem("demo-blocked-0001", "Учебная программа (демо)", now, now.AddMinutes(10)),
            new BlockedApplicationItem("demo-blocked-0002", "Игра (демо)", now, now.AddMinutes(10)) };
        return Task.FromResult(new GuardIpcResponse(1, Guid.NewGuid().ToString("D"), ReadStatus,
            ReadStatus == GuardIpcResponseStatus.Success ? BlockedApplicationsPayloadCodec.Encode(new BlockedApplicationsPayload(now, items)) : Array.Empty<byte>()));
    }
    public Task<GuardIpcResponse> RequestAsync(CreateApplicationRequestPayload request, CancellationToken token)
    { token.ThrowIfCancellationRequested(); LastToken = token; Requests++; return Pending ?? Task.FromResult(Queued()); }
    internal static GuardIpcResponse Queued() => new(1, Guid.NewGuid().ToString("D"), GuardIpcResponseStatus.Success,
        BlockedApplicationsPayloadCodec.EncodeQueued(new ApplicationRequestQueuedPayload("demo-request-0001", true, DateTimeOffset.UtcNow.AddMinutes(10))));
}
