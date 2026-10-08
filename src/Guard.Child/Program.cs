using System.Security.Principal;
using System.Windows;

namespace Guard.Child;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
        {
            MessageBox.Show("Откройте Guard из обычного аккаунта Windows, без прав администратора.", "Guard",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        new System.Windows.Application().Run(new ChildWindow(new ServiceChildBackend()));
    }
}
