using System.Security.Principal;
using System.Windows;

namespace Guard.Setup;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        // The manifest is the normal entry. Also refuse bypass through dotnet Guard.Setup.dll.
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
        {
            MessageBox.Show("Откройте Guard.Setup.exe из доверенного установочного комплекта и подтвердите запрос Windows на права администратора.",
                "Настройка Guard", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        new System.Windows.Application().Run(new SetupWindow(new ServiceSetupBackend()));
    }
}
