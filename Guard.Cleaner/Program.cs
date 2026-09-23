using System;
using System.Diagnostics;
using System.IO;
using System.Windows.Forms;

namespace Guard.Cleaner
{
    static class Program
    {
        [STAThread]

        private static bool CanWriteToHostsFile()
        {
            try
            {
                string hostsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts");
                // Try to open the file with write access. If it succeeds, we have permission.
                using (FileStream fs = new FileStream(hostsPath, FileMode.Open, FileAccess.ReadWrite))
                {
                    return true;
                }
            }
            catch (UnauthorizedAccessException)
            {
                // This specific exception means we were denied access.
                return false;
            }
            catch
            {
                // Any other exception also means we can't reliably write to it.
                return false;
            }
        }



        static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            var launchMode = CleanerLaunchPolicy.Parse(args);
            if (launchMode == CleanerLaunchMode.StartupFailureNotification)
            {
                MessageBox.Show(
                    "Guard несколько раз не смог запуститься. Защита не будет автоматически отключена или удалена. Родителю с правами администратора нужно проверить причину сбоя.",
                    "Ошибка запуска Guard",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
                Environment.Exit(1);
                return;
            }

            if (launchMode != CleanerLaunchMode.AuthorizedCleanup)
            {
                MessageBox.Show(
                    "Прямой запуск очистки и старые способы удаления отключены. Начните удаление через «Установленные приложения» в параметрах Windows.",
                    "Удаление Guard заблокировано",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                Environment.Exit(1);
                return;
            }

            if (!SystemCleaner.IsAdministrator())
            {
                MessageBox.Show("Для удаления Guard нужны права администратора.", "Ошибка доступа", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Environment.Exit(1);
                return;
            }
            else if (!CanWriteToHostsFile())
            {
                MessageBox.Show(
                    "Guard не может получить доступ к системному файлу hosts. Возможная причина — антивирус или политика безопасности. Продолжить удаление нельзя.",
                    "Ошибка доступа Guard",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                Environment.Exit(1);
                return;
            }

            var state = GuardStateStorage.Load();
            bool isAuthorized;
            using (var pinDialog = new PinForm("Введите ранее установленный PIN родителя для удаления Guard", null))
            {
                if (pinDialog.ShowDialog() != DialogResult.OK)
                {
                    Environment.Exit(1);
                    return;
                }

                isAuthorized = GuardV2ContainmentPolicy.CanAuthorizeCleaner(state?.PinCode, pinDialog.EnteredPin);
            }

            if (!isAuthorized)
            {
                MessageBox.Show(
                    "PIN родителя не задан, небезопасен или неверен, либо действие отменено. Guard не удалён.",
                    "Нужно подтверждение родителя",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                Environment.Exit(1);
                return;
            }

            MessageBox.Show("Начинается удаление Guard. Если какой-либо этап завершится с ошибкой, удаление будет остановлено.", "Удаление Guard", MessageBoxButtons.OK, MessageBoxIcon.Information);

            bool guardKilled = false, helperKilled = false;
            if (!SystemCleaner.TryWriteDisableFlag())
            {
                AbortCleanupAndRestoreProtection("Не удалось подготовить Guard к безопасному удалению.");
                return;
            }

            for (int attempt = 1; attempt <= 3; attempt++)
            {
                guardKilled = true;
                helperKilled = true;
                var guards = Process.GetProcessesByName("guard");
                if (guards.Length > 0)
                {
                    guardKilled = false;
                    foreach (var proc in guards)
                    {
                        try { proc.CloseMainWindow(); if (!proc.WaitForExit(1000)) proc.Kill(); }
                        catch { }
                        finally { proc.Dispose(); }
                    }
                }
                var helpers = Process.GetProcessesByName("StartHelperG");
                if (helpers.Length > 0)
                {
                    helperKilled = false;
                    foreach (var proc in helpers)
                    {
                        try { proc.Kill(); }
                        catch { }
                        finally { proc.Dispose(); }
                    }
                }
                if (guardKilled && helperKilled) break;
                System.Threading.Thread.Sleep(500);
            }

            guardKilled = NoProcessesNamed("guard");
            helperKilled = NoProcessesNamed("StartHelperG");
            if (!guardKilled || !helperKilled)
            {
                AbortCleanupAndRestoreProtection("Не удалось безопасно остановить процессы Guard.");
                return;
            }

            System.Threading.Thread.Sleep(500);

            GuardCleanupResult cleanupResult;
            try
            {
                cleanupResult = SystemCleaner.PerformFullCleanupAsync().GetAwaiter().GetResult();
            }
            catch
            {
                AbortCleanupAndRestoreProtection("При удалении Guard произошла непредвиденная ошибка.");
                return;
            }

            if (!cleanupResult.Succeeded)
            {
                AbortCleanupAndRestoreProtection(
                    "Не завершён этап удаления: " + UiLanguage.CleanupStep(cleanupResult.FailedStep) + ".");
                return;
            }

            Environment.Exit(CleanerExitCodePolicy.FromCleanupResult(cleanupResult));
        }

        private static void AbortCleanupAndRestoreProtection(string reason)
        {
            SystemCleaner.TryRemoveDisableFlag();
            TryRestartProtection();

            MessageBox.Show(
                reason + " Удаление остановлено. Выполнена попытка восстановить работу Guard.",
                "Ошибка удаления Guard",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
            Environment.Exit(CleanerExitCodePolicy.CleanupFailed);
        }

        private static bool NoProcessesNamed(string processName)
        {
            var processes = Process.GetProcessesByName(processName);
            try
            {
                return processes.Length == 0;
            }
            finally
            {
                foreach (var process in processes)
                {
                    process.Dispose();
                }
            }
        }

        private static void TryRestartProtection()
        {
            try
            {
                string helperPath = ScheduledTaskHelper.HelperPath;
                if (!File.Exists(helperPath))
                {
                    return;
                }

                Process.Start(new ProcessStartInfo
                {
                    FileName = helperPath,
                    Arguments = "/startup",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                });
            }
            catch
            {
                // Recovery is best-effort. The nonzero exit code still blocks file removal.
            }
        }
    }
}
