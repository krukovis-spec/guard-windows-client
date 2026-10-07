using System.Security.Principal;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace Guard.Setup;

internal static class PreviewProgram
{
    [STAThread]
    private static int Main(string[] args)
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
        { Console.Error.WriteLine("Preview refuses administrator privileges. Run as a normal user."); return 2; }
        if (args.Length > 1 || args.Length == 1 && args[0] != "--check") return 2;
        var app = new System.Windows.Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
        if (args.Length == 1)
        {
            app.Startup += async (_, _) =>
            {
                try { await PreviewChecks.RunAsync(); Console.WriteLine("PASS: local WPF preview checks"); app.Shutdown(0); }
                catch (Exception e) { Console.Error.WriteLine(e); app.Shutdown(1); }
            };
        }
        else
        {
            var peer = new PreviewBackend();
            var window = CreateWindow(peer);
            var controls = new StackPanel();
            controls.Children.Add(new TextBlock { Text = "Только вымышленные данные. Телефон не нужен.\nВ окне Guard: «Проверить установку» → «Привязать телефон».\nЗатем выберите имитацию ответа ниже.", TextWrapping = TextWrapping.Wrap, Margin = new Thickness(12) });
            void Add(string label, Action action)
            {
                var button = new Button { Content = label, Margin = new Thickness(12, 4, 12, 4), Padding = new Thickness(10, 6, 10, 6) };
                button.Click += (_, _) => { action(); window.Activate(); };
                controls.Children.Add(button);
            }
            Add("Телефон ответил: показать код сравнения", () => { peer.Phase = "compare-phone"; peer.Version++; });
            Add("Связь пропала", () => peer.Fail = true);
            Add("Связь восстановилась", () => peer.Fail = false);
            Add("Новый тест с чистого экрана", () => { window.Close(); peer = new PreviewBackend(); window = CreateWindow(peer); window.Show(); });
            var panel = new Window { Title = "Guard — управление ДЕМО", Width = 360, Height = 310,
                Content = controls, WindowStartupLocation = WindowStartupLocation.CenterScreen, FontSize = 14 };
            panel.Closed += (_, _) => { window.Close(); app.Shutdown(); };
            panel.Show(); window.Show();
        }
        return app.Run();
    }

    internal static SetupWindow CreateWindow(PreviewBackend peer)
    {
        var window = new SetupWindow(peer) { Title = "Guard — ДЕМО интерфейса (без защиты)" };
        var content = (UIElement)window.Content; window.Content = null;
        var shell = new DockPanel();
        var banner = new TextBlock { Text = "ДЕМО · Вымышленные данные · Нет службы и сети · QR не для телефона",
            TextWrapping = TextWrapping.Wrap, FontWeight = FontWeights.Bold, Foreground = Brushes.Black,
            Background = Brushes.LightGoldenrodYellow, Padding = new Thickness(12) };
        DockPanel.SetDock(banner, Dock.Top); shell.Children.Add(banner); shell.Children.Add(content); window.Content = shell;
        return window;
    }
}
