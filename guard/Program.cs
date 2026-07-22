using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.ComponentModel;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;
using System.Net.Http;
using System.DirectoryServices.ActiveDirectory;
using static System.Windows.Forms.AxHost;
using System.ServiceProcess;

namespace Guard
{
    static class Program
    {
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


        [STAThread]
        static void Main(string[] args)
        {

            // A unique name for our application's Mutex.
            const string appMutexName = "Global\\{E5A3525A-2D88-4DE5-8426-E824A69B7936}-GuardApp";
            bool createdNew;

            Mutex appMutex = new Mutex(true, appMutexName, out createdNew);
            if (!createdNew)
            {
                // If the Mutex already exists, it means another instance is running.
                // Show a message and exit immediately.
                MessageBox.Show("Guard уже запущен.", "Guard", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            try
            {
                bool startupOk = true; // Flag to track if checks pass
                                       // --- arg for Uninstall 
                if (args.Length == 1 && args[0] == "/uninstall")
                {
                    // visible form to prompt for the PIN.
                    Application.EnableVisualStyles();
                    Application.SetCompatibleTextRenderingDefault(false);
                    var mainForm = new MainForm(); // instance to access methods

                    if (mainForm.PromptPin("Введите PIN для удаления Guard:"))
                    {
                        // If PIN is correct - cleanup.
                        mainForm.CleanAndClose().Wait(); // .Wait() to ensure it finishes
                    }
                    return; // Exit after uninstall attempt.
                }




                try
                {
                    string helperPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "StartHelperG.exe");
                    if (File.Exists(helperPath))
                    {
                        // Check if helper is already running before starting a new one
                        if (Process.GetProcessesByName("StartHelperG").Length == 0)
                        {
                            var psi = new ProcessStartInfo(helperPath) { UseShellExecute = true, Verb = "runas" };
                            Process.Start(psi);
                        }
                    }
                }
                catch { }


                if (!IsAdministrator())
                {
                    using (var infoForm = new InformationForm("Нужны права администратора", "Guard нужны права администратора, чтобы правильно работать.", MessageBoxIcon.Error))
                    {
                        infoForm.ShowDialog();
                    }
                    startupOk = false; // Mark startup as failed
                }
                else if (!CanWriteToHostsFile()) // Also check hosts file permission
                {
                    using (var infoForm = new InformationForm("Ошибка доступа", "Guard не может получить доступ к системным файлам. Возможно, его блокирует антивирус. Добавьте Guard.exe в исключения.", MessageBoxIcon.Error))
                    {
                        infoForm.ShowDialog();
                    }
                    startupOk = false; // Mark startup as failed
                }

                try
                {

                    // setting up paths

                    string userAppData = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Guard");
                    Directory.CreateDirectory(userAppData);

                    string systemEtc = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\savedBU");
                    Directory.CreateDirectory(systemEtc);

                    string hostsPath = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts");

                    string appDataInitial = Path.Combine(userAppData, "hosts_initial.bak");
                    string systemInitial = Path.Combine(systemEtc, "hosts_initial.bak");

                    // Only if both missing, this is initial run
                    if (!File.Exists(appDataInitial) || !File.Exists(systemInitial))
                    {
                        File.Copy(hostsPath, appDataInitial, true);
                        File.Copy(hostsPath, systemInitial, true);
                    }

                }
                catch (Exception ex)
                {
                    MessageBox.Show("Ошибка при подготовке резервной копии: " + ex.Message, "Guard");
                }

                // Remove any "disable.guard" file if main is starting:
                try { if (File.Exists(AppSettings.DisableFlagPath)) File.Delete(AppSettings.DisableFlagPath); } catch { }

                // Standard WinForms initialization
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Application.Run(new MainForm(startupOk));
            }
            finally
            {
                // Release the Mutex so another instance can run later.
                appMutex.ReleaseMutex();
                appMutex.Close();
            }
        }

        static bool IsAdministrator()
        {
            try
            {
                var wi = WindowsIdentity.GetCurrent();
                var wp = new WindowsPrincipal(wi);
                return wp.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }
    }

    public class MainForm : Form
    {
        readonly NotifyIcon tray = new NotifyIcon();
        private DiagnosticWindow diagWin = null!;
        readonly ContextMenuStrip menu = new ContextMenuStrip();
        private Icon? icon_Active;
        private Icon? icon_Inactive;
        private Icon? icon_Updating;
        private Icon? icon_Grayscale;
        private ParentAdminServer? parentAdminServer;
        private bool isCheckingForUpdate = false;
        private bool isApplicationControlTickRunning = false;
        private readonly Dictionary<string, DateTime> lastWebsitePromptUtcByDomain =
            new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, DateTime> lastApplicationPromptUtcByPath =
            new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        public GuardState? State { get; private set; }
        public string CurrentAppVersion => System.Reflection.Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "0.0.0.0";
        private int pinFailCount = 0;
        private DateTime? lastPinAttemptTime = null;
        private int mainLoopTickCount = 0;
        private void ShowDiagnosticWindow(string message)
        {
            diagWin.Show();
            diagWin.Log(message);
        }

        private void Log(string message)
        {
            diagWin?.Log(message);
        }

        private string L(string russian, string english)
        {
            return UiLanguage.Text(State?.UiLanguage, russian, english);
        }

        private string ActivityCategoryText(ActivityCategory category)
        {
            switch (category)
            {
                case ActivityCategory.Study:
                    return L("Учёба", "Study");
                case ActivityCategory.Video:
                    return L("Видео", "Video");
                case ActivityCategory.Game:
                    return L("Игры", "Game");
                case ActivityCategory.UsefulTraining:
                    return L("Полезное обучение", "Useful training");
                case ActivityCategory.Communication:
                    return L("Общение", "Communication");
                case ActivityCategory.System:
                    return L("Система", "System");
                default:
                    return L("Без категории", "Uncategorized");
            }
        }

        private System.Windows.Forms.Timer? _helperWatchdogTimer;
        private System.Windows.Forms.Timer? _applicationControlTimer;


        public MainForm(bool startupOk = true)
        {
            Instance = this;
            State = GuardStateStorage.Load() ?? new GuardState();
            LoadAllIcons();
            diagWin = new DiagnosticWindow(this.State, icon_Active ?? SystemIcons.Application);
            this.Opacity = 0;
            this.ShowInTaskbar = false;
            this.WindowState = FormWindowState.Minimized;
            UpdateTrayIcon();
            diagWin.UpdateDisplay(State);
            tray.Visible = true;
            tray.Text = "Guard";
            StartParentAdminServer();




            //Register the startup task by default if it's not already installed.


            if (startupOk)
            {
                if (State.IsStartUp)
                {
                    try
                    {
                        if (!ScheduledTaskHelper.IsStartupTaskInstalled())
                        {
                            ScheduledTaskHelper.RegisterStartupTask(diagWin.Log, State);
                            diagWin?.Log("Startup task was missing and has been re-created.");
                        }
                    }
                    catch (Exception ex)
                    {
                        diagWin?.Log("Failed to verify or register startup task: " + ex.Message);
                    }

                }
                // assign button
                if (State == null || !State.Assigned)
                {
                    var pairingMenuItem = new ToolStripMenuItem(L("Показать код привязки", "Show Pairing Code"), null, (s, e) => ShowPairingCode());
                    menu.Items.Add(pairingMenuItem);
                }
                else
                {


                    if (!string.IsNullOrEmpty(State.LastTurnOnTime) && !string.IsNullOrEmpty(State.LastTurnOffTime))
                    {
                        // Send log about previous session
                        string msg = $"Guard app was running from {State.LastTurnOnTime} till {State.LastTurnOffTime}";
                        // Optionally rephrase more user-friendly:
                        // string msg = $"Guard was active from {State.LastTurnOnTime} to {State.LastTurnOffTime} on this device.";
                        // Send log (fire and forget)
                        _ = SendInfoLogAsync(msg);
                    }
                    // Update "last turn on" time
                    State.LastTurnOnTime = DateTime.Now.ToString("hh:mm tt MM/dd");
                    State.LastTurnOffTime = "";

                    ToolStripMenuItem updateMenuItem = null!;

                    // update button
                    updateMenuItem = new ToolStripMenuItem(L("Обновить правила", "Request new instructions"), null, async (s, e) =>
                    {
                        updateMenuItem.Enabled = false;
                        await RequestUpdateAsync(); // Call the new method

                        // Re-enable after a delay
                        var timer = new System.Windows.Forms.Timer { Interval = 10 * 1000 };
                        timer.Tick += (sender, args) =>
                        {
                            updateMenuItem.Enabled = true;
                            timer.Stop();
                            timer.Dispose();
                        };
                        timer.Start();
                    });


                    menu.Items.Add(updateMenuItem);
                }
                menu.Items.Add(new ToolStripSeparator());
                menu.Items.Add(new ToolStripMenuItem(L("Попросить приложение", "Request App Access"), null, (s, e) => ShowApplicationAccessRequest()));
                menu.Items.Add(new ToolStripMenuItem(L("Попросить сайт", "Request Site Access"), null, (s, e) => ShowWebsiteAccessRequest()));
                menu.Items.Add(new ToolStripMenuItem(L("Мои задачи", "My Tasks"), null, (s, e) => ShowChildTasks()));
                var mainLoopTimer = new System.Windows.Forms.Timer();
                mainLoopTimer.Interval = 60 * 1000; // 1 minute
                mainLoopTimer.Tick += async (s, e) => {
                    mainLoopTickCount++;
                    await RunMainLoopAsync();
                };
                mainLoopTimer.Start();
                diagWin?.Log("[MainLoop] Main timer started.");
                InitializeApplicationControlTimer();

                this.Load += async (s, e) =>
                {
                    await RunMainLoopAsync(forceUpdate: true);
                    if (State != null && !State.Assigned)
                    {
                        BeginInvoke(new Action(ShowPairingCode));
                    }
                };




                // admin button
                var adminMenuItem = new ToolStripMenuItem(L("Админ-панель", "Admin Panel"), null, async (s, e) =>
                {
                    // Use the new reusable PromptPin function
                    if (PromptPin(L("Введите PIN администратора:", "Enter Admin PIN:")))
                    {
                        diagWin?.Show();
                        await SendInfoLogAsync($"Admin Panel accessed at local time: {DateTime.Now}");
                        diagWin?.Activate(); // Bring the window to the front
                    }
                    else
                    {

                        tray.ShowBalloonTip(1200, L("Неверно", "Invalid"), L("Неверный PIN", "Wrong PIN"), ToolTipIcon.Warning);
                    }
                });
                menu.Items.Add(adminMenuItem);
            }
            else
            {
                // If startup failed, enter a disabled state
                State.SyncStatus = false; // Ensure sync is off
                diagWin.Log("Application started in a disabled state due to startup errors.");
                // We do NOT start the main loop timer.
            }

            UpdateTrayIcon(); // Update icon to reflect state

            // disable button
            menu.Items.Add(L("Отключить Guard", "Disable App"), null, async (s, e) => await DisableApp());


            tray.ContextMenuStrip = menu;
            tray.DoubleClick += async (s, e) => {
                await RequestUpdateAsync();
            };
            //diagWin.Show();
            if (State != null) State.DevUpdate = false;
            if (startupOk)
            {
                this.Load += async (s, e) =>
                {
                    await RunMainLoopAsync(forceUpdate: true);
                    InitializeHelperWatchdogTimer();
                };
            }



        }

        private void StartParentAdminServer()
        {
            var state = State;
            if (state == null) return;

            parentAdminServer = new ParentAdminServer(state, Log, RequestApplyFromParentAdmin);
            parentAdminServer.Start();
        }

        private void ShowApplicationAccessRequest()
        {
            var state = State;
            if (state == null)
            {
                tray.ShowBalloonTip(1500, "Guard", L("Guard ещё не готов.", "Guard state is not ready."), ToolTipIcon.Warning);
                return;
            }

            using (var dialog = new OpenFileDialog())
            {
                dialog.Title = L("Попросить доступ к приложению", "Request app access");
                dialog.Filter = L("Приложения (*.exe;*.com)|*.exe;*.com|Все файлы (*.*)|*.*",
                                  "Applications (*.exe;*.com)|*.exe;*.com|All files (*.*)|*.*");
                dialog.CheckFileExists = true;
                dialog.Multiselect = false;

                if (dialog.ShowDialog() != DialogResult.OK)
                {
                    return;
                }

                var displayName = Path.GetFileNameWithoutExtension(dialog.FileName);
                var result = AccessRequestApplier.RequestApplication(
                    state,
                    dialog.FileName,
                    displayName,
                    "child-manual",
                    Environment.UserName,
                    DateTime.UtcNow);

                if (!string.IsNullOrEmpty(result.Error))
                {
                    tray.ShowBalloonTip(2500, "Guard", result.Error, ToolTipIcon.Warning);
                    return;
                }

                GuardStateStorage.Save(state);
                diagWin?.UpdateDisplay(state);
                tray.ShowBalloonTip(2500, "Guard", L("Запрос отправлен родителю.", "Access request sent to parent cabinet."), ToolTipIcon.Info);
            }
        }

        private void ShowWebsiteAccessRequest()
        {
            var state = State;
            if (state == null)
            {
                tray.ShowBalloonTip(1500, "Guard", L("Guard ещё не готов.", "Guard state is not ready."), ToolTipIcon.Warning);
                return;
            }

            using (var form = new Form())
            using (var label = new Label())
            using (var textBox = new TextBox())
            using (var ok = new Button())
            using (var cancel = new Button())
            {
                form.Text = L("Попросить доступ к сайту", "Request site access");
                form.StartPosition = FormStartPosition.CenterScreen;
                form.FormBorderStyle = FormBorderStyle.FixedDialog;
                form.MaximizeBox = false;
                form.MinimizeBox = false;
                form.ClientSize = new Size(420, 132);

                label.Text = L("Сайт или домен", "Site or domain");
                label.SetBounds(16, 16, 380, 22);

                textBox.SetBounds(16, 42, 390, 24);
                textBox.Anchor = AnchorStyles.Left | AnchorStyles.Top | AnchorStyles.Right;

                ok.Text = L("Отправить", "Send request");
                ok.DialogResult = DialogResult.OK;
                ok.SetBounds(216, 84, 112, 28);

                cancel.Text = L("Отмена", "Cancel");
                cancel.DialogResult = DialogResult.Cancel;
                cancel.SetBounds(336, 84, 70, 28);

                form.Controls.Add(label);
                form.Controls.Add(textBox);
                form.Controls.Add(ok);
                form.Controls.Add(cancel);
                form.AcceptButton = ok;
                form.CancelButton = cancel;

                if (form.ShowDialog() != DialogResult.OK)
                {
                    return;
                }

                var result = AccessRequestApplier.RequestWebsite(
                    state,
                    textBox.Text,
                    "child-manual",
                    Environment.UserName,
                    DateTime.UtcNow);

                if (!string.IsNullOrEmpty(result.Error))
                {
                    tray.ShowBalloonTip(2500, "Guard", result.Error, ToolTipIcon.Warning);
                    return;
                }

                GuardStateStorage.Save(state);
                diagWin?.UpdateDisplay(state);
                tray.ShowBalloonTip(2500, "Guard", L("Запрос на сайт отправлен родителю.", "Site request sent to parent cabinet."), ToolTipIcon.Info);
            }
        }

        private void ShowPairingCode()
        {
            var state = State;
            if (state == null) return;

            EnsurePairingCode(state);
            using (var pairing = new PairingForm(state.Pairing, parentAdminServer?.GetAccessText() ?? "http://localhost:8765/"))
            {
                pairing.ShowDialog();
            }
        }

        private static void EnsurePairingCode(GuardState state)
        {
            var now = DateTime.UtcNow;
            if (state.Pairing == null ||
                state.Pairing.Status != PairingStatus.WaitingForParent ||
                PairingCodeService.IsExpired(state.Pairing, now))
            {
                state.Pairing = PairingCodeService.StartPairing(Environment.MachineName, now);
                GuardStateStorage.Save(state);
            }
        }

        private void RequestApplyFromParentAdmin()
        {
            try
            {
                BeginInvoke(new Action(async () => await RunMainLoopAsync(forceUpdate: true)));
            }
            catch (Exception ex)
            {
                Log("[ParentAdmin] Could not schedule policy apply: " + ex.Message);
            }
        }

        private void InitializeApplicationControlTimer()
        {
            _applicationControlTimer = new System.Windows.Forms.Timer();
            _applicationControlTimer.Interval = 10 * 1000;
            _applicationControlTimer.Tick += async (s, e) => await RunApplicationControlTickAsync();
            _applicationControlTimer.Start();
            diagWin?.Log("[AppControl] Timer started.");
        }

        protected override void OnFormClosed(FormClosedEventArgs e)
        {
            _applicationControlTimer?.Stop();
            _applicationControlTimer?.Dispose();
            parentAdminServer?.Dispose();
            base.OnFormClosed(e);
        }



        private void ShowUpdateMenuItem()
        {
            // Avoid duplicates
            foreach (ToolStripItem item in menu.Items)
            {
                if (item is ToolStripMenuItem mi && mi.Text == "Request new instructions")
                {
                    mi.Visible = true;
                    return;
                }
            }

            ToolStripMenuItem updateMenuItem = null!;

            // Define the click handler as a lambda that can see updateMenuItem
            EventHandler handler = async (s, e) =>
            {
                updateMenuItem.Enabled = false;
                await RequestUpdateAsync();
                var timer = new System.Windows.Forms.Timer { Interval = 10 * 1000 };
                timer.Tick += (sender, args) =>
                {
                    updateMenuItem.Enabled = true;
                    timer.Stop();
                    timer.Dispose();
                };
                timer.Start();
            };

            updateMenuItem = new ToolStripMenuItem("Request new instructions", null, handler);

            // Insert at the desired position
            menu.Items.Insert(0, updateMenuItem);
        }


        private void InitializeHelperWatchdogTimer()
        {
            _helperWatchdogTimer = new System.Windows.Forms.Timer();
            _helperWatchdogTimer.Interval = 2000; // Check every 2 seconds
            _helperWatchdogTimer.Tick += (s, e) =>
            {
                if (File.Exists(AppSettings.DisableFlagPath)) return;

                // *** Use correct process name ***
                if (Process.GetProcessesByName("StartHelperG").Length == 0)
                {
                    try
                    {
                        string helperPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "StartHelperG.exe");
                        if (File.Exists(helperPath))
                        {
                            var psi = new ProcessStartInfo(helperPath) { UseShellExecute = true };
                            Process.Start(psi);
                        }
                    }
                    catch { }
                }
            };
            _helperWatchdogTimer.Start();
        }



        public async Task RunMainLoopAsync(bool forceUpdate = false, string action = "")
        {

            var state = State;
            if (state == null)
            {
                diagWin?.Log("[CRITICAL] State object is null. Cannot run main loop.");
                return;
            }
            if (!state.Assigned) { Log($"[MainLoop] Device not assigned to account. Please assign. "); return; }
            Log($"[MainLoop] Running main loop. Forced: {forceUpdate}");

            if (state.DevUpdate)
            {
                // If this is a high-priority "forceUpdate" call, we will wait.
                if (forceUpdate || !string.IsNullOrWhiteSpace(action))
                {
                    Log("[MainLoop] Another process is running, but this is a forced update. Waiting...");
                    for (int i = 0; i < 5; i++)
                    {
                        if (!state.DevUpdate)
                        {
                            Log($"[MainLoop] Lock has been released. Proceeding now.");
                            break; // The lock is now free, we can continue.
                        }

                        if (i == 4) // This is the last attempt
                        {
                            Log("[MainLoop] Waited 50 seconds, but process is still running. Forcing execution now.");
                            break;
                        }

                        Log($"[MainLoop] Still waiting... (Attempt {i + 1}/5)");
                        await Task.Delay(10000); // Wait 10 seconds
                    }
                }
                else // If this is just a regular background tick, we give up immediately.
                {
                    Log("[MainLoop] Update is still in progress. Skipping this background tick.");
                    return;
                }
            }
            state.DevUpdate = true;
            UpdateTrayIcon();

            if (!string.IsNullOrWhiteSpace(action))
            {
                if (action == "cleanAndClose")
                {
                    await CleanAndClose();

                }

            }

            try
            {

                bool needsReapply = false;
                var utcNow = DateTime.UtcNow;

                var maintenanceExpired = MaintenanceModeApplier.ExpireIfNeeded(state, utcNow);
                if (maintenanceExpired.Changed)
                {
                    Log("[Maintenance] Maintenance mode expired. Restoring protection state.");
                    GuardStateStorage.Save(state);
                }
                else
                {
                    var maintenanceRefresh = MaintenanceModeApplier.RefreshActiveState(state, utcNow);
                    if (maintenanceRefresh.Changed)
                    {
                        Log("[Maintenance] Maintenance mode refreshed protection state.");
                        GuardStateStorage.Save(state);
                    }
                }

                var expiredWebsiteGrants = DomainAccessGrantApplier.RemoveExpiredTemporaryGrants(state, utcNow);
                if (expiredWebsiteGrants.Changed)
                {
                    Log("[DomainAccess] Temporary website access expired. Rebuilding domain rules.");
                    GuardStateStorage.Save(state);
                }

                if (forceUpdate || mainLoopTickCount % 5 == 0)
                {

                    if (mainLoopTickCount % 30 == 0)
                    {
                        if (state.IsStartUp)
                        {
                            try
                            {
                                if (!ScheduledTaskHelper.IsStartupTaskInstalled())
                                {
                                    ScheduledTaskHelper.RegisterStartupTask(Log, state);
                                    diagWin?.Log("Startup task or registry was missing and has been re-created.");
                                }
                            }
                            catch (Exception ex)
                            {
                                diagWin?.Log("Error verifying/re-creating startup task: " + ex.Message);
                            }
                        }
                    }


                    if (state.LocalParentMode)
                    {
                        diagWin?.Log("[MainLoop] Local parent mode: skipping remote DeviceUpdater.");
                    }
                    else
                    {
                        diagWin?.Log($"[MainLoop] Running DeviceUpdater. (force: {forceUpdate}, tick: {mainLoopTickCount})");
                        state.LastTurnOffTime = DateTime.Now.ToString("hh:mm tt MM/dd");
                        await DeviceUpdater.SendDeviceUpdateAsync(state, Log);
                    }

                }

                await ApplyApplicationControlPolicyIfNeeded(state);

                if (((mainLoopTickCount + 3) % 3) == 0)
                {
                    if (state.SyncStatus && !state.IsHostsFileActive)
                    {
                        Log("[STATE-CHECK] Rules should be active. Turning ON.");
                        needsReapply = true;
                    }
                    else if (state.HostsFileLastWriteTimeUtc.HasValue && state.HostsFileSize.HasValue)
                    {
                        try
                        {
                            var fileInfo = new FileInfo(hostsPath);
                            var currentWriteTime = fileInfo.LastWriteTimeUtc;
                            var currentSize = fileInfo.Length;

                            // Check 1: Is the file size different? (This is a strong indicator of tampering).
                            bool sizeMismatch = (currentSize - state.HostsFileSize.Value) > 1000;

                            // Check 2: Is the time difference significant (more than 60 seconds)?
                            var timeDifference = (currentWriteTime - state.HostsFileLastWriteTimeUtc.Value).TotalSeconds;
                            bool timeMismatch = Math.Abs(timeDifference) > 60; // 1-minute tolerance

                            // If either the size is different, OR the timestamp is significantly different,
                            // then we flag it as a potential tamper.
                            if (sizeMismatch || timeMismatch)
                            {
                                Log($"[TAMPER-DETECT] Hosts file change detected. Size different: {sizeMismatch}, Time different: {timeMismatch}.");
                                Log($"[TAMPER-DETECT] Current: {currentWriteTime}, {currentSize} bytes. Saved: {state.HostsFileLastWriteTimeUtc.Value}, {state.HostsFileSize.Value} bytes.");
                                needsReapply = true;
                            }
                        }
                        catch (Exception ex) { Log($"[TAMPER-CHECK] Could not check hosts file: {ex.Message}"); }
                    }
                }

                if (needsReapply)
                {
                    state.UpdateInfo.UpdateApplied = false;
                    state.UpdateInfo.SyncStatUpdate = true;
                }


                if (!state.UpdateInfo.UpdateApplied)
                {
                    if (state.SyncStatus == true)
                    {
                        bool catUpdated = false;
                        bool ruleUpdated = false;

                        if (state.UpdateInfo.Cats || state.UpdateInfo.Presets || state.UpdateInfo.RestrictedCats || state.UpdateInfo.Rules)
                        {
                            await SystemCleaner.ResetHostsFileAsync(Log);
                            await SystemCleaner.RemoveFirewallRulesAsync(Log);


                            if (state.UpdateInfo.Rules || state.UpdateInfo.Presets || state.UpdateInfo.RestrictedCats)
                            {
                                await PrepareRulesList(state);
                                ruleUpdated = true;
                            }
                            if (state.UpdateInfo.Cats || state.UpdateInfo.Presets || state.UpdateInfo.RestrictedCats)
                            {
                                await PrepareCatList(state);
                                catUpdated = true;
                            }
                            GuardStateStorage.Save(state);
                        }

                        if (catUpdated && ruleUpdated) state.IpsRecheck = DateTime.UtcNow;


                        if (state.UpdateInfo.Ips)
                        {
                            if (!catUpdated && !ruleUpdated)
                            {
                                await SystemCleaner.ResetHostsFileAsync(Log);
                                await SystemCleaner.RemoveFirewallRulesAsync(Log);
                            }

                            await PrepareUpdatedIps(state, catUpdated, ruleUpdated);
                            await CreateDatedHostsBackupAsync(Log);

                            if (!catUpdated || !ruleUpdated) GuardStateStorage.Save(state);
                        }

                        if (state.UpdateInfo.SyncStatUpdate || state.UpdateInfo.Cats || state.UpdateInfo.Rules || state.UpdateInfo.Presets || state.UpdateInfo.RestrictedCats || state.UpdateInfo.Ips)
                        {
                            await ApplyPermanentCategoriesAsync(state);

                            if (ruleUpdated)
                            {
                                // This is now the complete logic for handling a change in rules.
                                Log("[MainLoop] Detected rule changes. Calculating new weekly timeline...");
                                SchedulerEngine.CalculateWeeklyTimeline(state, Log);
                            }
                            state.LastAppliedSnapshotMinute = -1;
                            await SchedulerEngine.RunSchedulerTick(state, Log);
                            Log("[MainLoop] New rule state has been calculated and applied.");
                            //LogTimelineAndRules(State);

                        }
                        state.UpdateInfo.Cats = false;
                        state.UpdateInfo.Rules = false;
                        state.UpdateInfo.Presets = false;
                        state.UpdateInfo.Ips = false;
                        state.UpdateInfo.Parameters = false;
                        state.UpdateInfo.RestrictedCats = false;
                        state.UpdateInfo.SyncStatUpdate = false;
                        state.UpdateInfo.UpdateApplied = true;
                        state.IsHostsFileActive = true;
                        //diagWin.Log("[STATE-DUMP]Current state: " + System.Text.Json.JsonSerializer.Serialize(State));

                        GuardStateStorage.Save(state);

                        await SystemCleaner.FlushDnsAsync();
                        if (state.ResetConnection)
                        {
                            if (MainForm.Instance != null)
                            {
                                await SystemCleaner.DisableAndRestoreNetworkAsync(Log);
                                await SystemCleaner.FlushDnsAsync();
                            }
                        }


                    }
                    else // turned off
                    {
                        UpdateTrayIcon();
                        Log("SyncStatus is OFF. Cleaning hosts and firewall rules...");
                        await SystemCleaner.ResetHostsFileAsync(Log);
                        await SystemCleaner.RemoveFirewallRulesAsync(Log);
                        await SystemCleaner.FlushDnsAsync();
                        //diagWin.Log("[STATE-DUMP] Checking ResetConnection. Current state: " + System.Text.Json.JsonSerializer.Serialize(State));
                        if (state.ResetConnection)
                        {
                            await SystemCleaner.DisableAndRestoreNetworkAsync(Log); await SystemCleaner.FlushDnsAsync();
                        }
                        state.UpdateInfo.SyncStatUpdate = false;
                        state.UpdateInfo.UpdateApplied = true;
                        GuardStateStorage.Save(state);
                    }
                }
                else
                {
                    if (state.SyncStatus)
                    {

                        await SchedulerEngine.RunSchedulerTick(state, Log);
                    }
                }


            }
            catch (Exception ex)
            {
                Log("[Scheduler] Error: " + ex.Message);
            }
            finally { state.DevUpdate = false; diagWin.UpdateDisplay(state); UpdateTrayIcon(); GuardStateStorage.Save(state); }
        }

        private async Task ApplyApplicationControlPolicyIfNeeded(GuardState state)
        {
            if (state.AppControl == null || !state.AppControl.PolicyUpdatePending)
            {
                return;
            }

            await ApplicationControlPolicyManager.ApplyIfNeededAsync(state, Application.ExecutablePath, Log);
        }

        private async Task RunApplicationControlTickAsync()
        {
            if (isApplicationControlTickRunning)
            {
                return;
            }

            isApplicationControlTickRunning = true;
            try
            {
                var state = State;
                if (state == null)
                {
                    return;
                }

                RecordActivitySnapshot(state);

                var utcNow = DateTime.UtcNow;
                var maintenanceExpired = MaintenanceModeApplier.ExpireIfNeeded(state, utcNow);
                if (maintenanceExpired.Changed)
                {
                    Log("[Maintenance] Maintenance mode expired. Restoring protection state.");
                    GuardStateStorage.Save(state);
                    await ApplyApplicationControlPolicyIfNeeded(state);
                }
                else
                {
                    var maintenanceRefresh = MaintenanceModeApplier.RefreshActiveState(state, utcNow);
                    if (maintenanceRefresh.Changed)
                    {
                        Log("[Maintenance] Maintenance mode refreshed protection state.");
                        GuardStateStorage.Save(state);
                        await ApplyApplicationControlPolicyIfNeeded(state);
                    }
                }

                if (state.AppControl == null || state.AppControl.Mode == ApplicationControlMode.Off)
                {
                    return;
                }

                var runningApplications = GetRunningApplications();
                var result = ApplicationControlRuntime.Evaluate(state.AppControl, runningApplications, utcNow);

                foreach (var warning in result.WarningApplications)
                {
                    tray.ShowBalloonTip(
                        5000,
                        "Guard",
                        warning.Application.DisplayName + ": " +
                        L("сохранись, время закончится через ", "save your game. Time ends in ") +
                        warning.MinutesLeft +
                        L(" мин.", " min."),
                        ToolTipIcon.Warning);
                }

                foreach (var runningApp in result.ExpiredRunningApplications)
                {
                    StopExpiredApplication(runningApp);
                }

                foreach (var runningTool in result.BlockedManagementTools)
                {
                    StopBlockedManagementTool(runningTool);
                }

                var overLimitApps = TimeLimitEngine.GetOverLimitRunningApplications(state, runningApplications, utcNow);
                foreach (var runningApp in overLimitApps)
                {
                    StopOverLimitApplication(runningApp);
                }

                if (overLimitApps.Count > 0)
                {
                    state.AppControl.PolicyUpdatePending = true;
                    result.Changed = true;
                }

                var overLimitSiteGrants = TimeLimitEngine.GetOverLimitWebsiteGrants(state, utcNow);
                if (overLimitSiteGrants.Count > 0)
                {
                    state.UpdateInfo.Rules = true;
                    state.UpdateInfo.Cats = true;
                    state.UpdateInfo.UpdateApplied = false;
                    result.Changed = true;
                }

                CaptureApplicationAccessRequests(state);

                if (result.Changed)
                {
                    GuardStateStorage.Save(state);
                }

                await ApplyApplicationControlPolicyIfNeeded(state);
            }
            catch (Exception ex)
            {
                Log("[AppControl] Tick error: " + ex.Message);
            }
            finally
            {
                isApplicationControlTickRunning = false;
            }
        }

        private void RecordActivitySnapshot(GuardState state)
        {
            try
            {
                var snapshot = ActivityMonitor.Capture(DateTime.UtcNow);
                CaptureWebsiteAccessRequest(state, snapshot);

                var result = ActivityAccountingEngine.RecordSnapshot(
                    state,
                    snapshot);

                if (result.Changed)
                {
                    GuardStateStorage.Save(state);
                    diagWin?.UpdateDisplay(state);
                }
            }
            catch (Exception ex)
            {
                Log("[Activity] Could not record activity snapshot: " + ex.Message);
            }
        }

        private void CaptureWebsiteAccessRequest(GuardState state, ActivitySnapshot snapshot)
        {
            var utcNow = DateTime.UtcNow;
            var domain = DomainAccessGrantApplier.NormalizeDomainInput(snapshot.ForegroundDomain);
            if (!WebsiteAccessPolicy.ShouldBlockWebsite(state, domain, utcNow))
            {
                return;
            }

            var blockResult = WebsiteAccessPolicy.EnsureDefaultDeniedDomainRule(state, domain);
            bool changed = blockResult.Changed;
            if (!string.IsNullOrEmpty(blockResult.Error))
            {
                Log("[WebDefaultDeny] Could not mark blocked domain: " + blockResult.Error);
                return;
            }

            bool hasPendingRequest = AccessRequestApplier.GetPendingRequests(state).Any(request =>
                request.Type == AccessRequestType.Website &&
                string.Equals(request.Target, domain, StringComparison.OrdinalIgnoreCase));

            if (hasPendingRequest)
            {
                tray.ShowBalloonTip(
                    2500,
                    "Guard",
                    UiLanguage.Text(state.UiLanguage,
                        "Запрос на сайт " + domain + " уже отправлен родителю.",
                        "The site request for " + domain + " was already sent to the parent."),
                    ToolTipIcon.Info);
            }
            else if (ShouldShowWebsitePrompt(domain, utcNow) && PromptChildForWebsiteRequest(domain))
            {
                var requestResult = AccessRequestApplier.RequestWebsite(
                    state,
                    domain,
                    "browser",
                    Environment.UserName,
                    utcNow);
                if (!string.IsNullOrEmpty(requestResult.Error))
                {
                    tray.ShowBalloonTip(2500, "Guard", requestResult.Error, ToolTipIcon.Warning);
                }
                else
                {
                    changed = changed || requestResult.Changed;
                    tray.ShowBalloonTip(
                        2500,
                        "Guard",
                        UiLanguage.Text(state.UiLanguage,
                            "Запрос на сайт отправлен родителю.",
                            "The site request was sent to the parent."),
                        ToolTipIcon.Info);
                }
            }

            StopBlockedWebsiteBrowser(snapshot, domain);

            if (changed)
            {
                GuardStateStorage.Save(state);
                diagWin?.UpdateDisplay(state);
            }
        }

        private void ShowChildTasks()
        {
            var state = State;
            if (state == null)
            {
                tray.ShowBalloonTip(1500, "Guard", L("Guard ещё не готов.", "Guard state is not ready."), ToolTipIcon.Warning);
                return;
            }

            var tasks = DailyTaskEngine.GetActiveTasks(state);
            if (!tasks.Any())
            {
                tray.ShowBalloonTip(2000, "Guard", L("На сегодня задач нет.", "No tasks for today."), ToolTipIcon.Info);
                return;
            }

            using (var form = new Form())
            using (var panel = new FlowLayoutPanel())
            {
                form.Text = L("Мои задачи", "Guard Tasks");
                form.StartPosition = FormStartPosition.CenterScreen;
                form.Size = new Size(420, 360);
                form.MinimizeBox = false;
                form.MaximizeBox = false;

                panel.Dock = DockStyle.Fill;
                panel.FlowDirection = FlowDirection.TopDown;
                panel.WrapContents = false;
                panel.AutoScroll = true;
                panel.Padding = new Padding(12);
                form.Controls.Add(panel);

                foreach (var task in tasks)
                {
                    var button = new Button
                    {
                        Width = 360,
                        Height = 52,
                        Text = task.Title + "  (+" + task.RewardMinutes + " " + L("мин", "min") + " " + ActivityCategoryText(task.RewardCategory) + ")",
                        Tag = task.Id
                    };
                    button.Click += (sender, args) =>
                    {
                        var taskId = (string)((Button)sender!).Tag;
                        var result = ParentCommandApplier.Apply(state, new ParentCommand
                        {
                            Type = ParentCommandType.CompleteDailyTask,
                            Value = taskId,
                            DisplayName = "child"
                        });

                        if (!string.IsNullOrEmpty(result.Error))
                        {
                            MessageBox.Show(result.Error, "Guard", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                            return;
                        }

                        GuardStateStorage.Save(state);
                        MessageBox.Show(L("Задача выполнена.", "Task completed."), "Guard", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    };
                    panel.Controls.Add(button);
                }

                form.ShowDialog();
            }
        }

        private void CaptureApplicationAccessRequests(GuardState state)
        {
            try
            {
                var events = AppLockerEventReader.ReadExecutableAccessEvents(
                    state.LastAppLockerExeEventRecordId,
                    maxEvents: 50,
                    log: Log,
                    latestRecordIdSeen: out var latestRecordIdSeen);

                bool changed = false;
                foreach (var blockedEvent in events)
                {
                    var displayName = Path.GetFileNameWithoutExtension(blockedEvent.FilePath);
                    bool hasPendingRequest = AccessRequestApplier.GetPendingRequests(state).Any(request =>
                        request.Type == AccessRequestType.Application &&
                        string.Equals(
                            ApplicationControlApplier.NormalizeExecutablePath(request.Target),
                            ApplicationControlApplier.NormalizeExecutablePath(blockedEvent.FilePath),
                            StringComparison.OrdinalIgnoreCase));
                    bool shouldAskChild = state.AppControl != null &&
                        state.AppControl.Mode == ApplicationControlMode.Enforced &&
                        blockedEvent.EventId == 8004 &&
                        !hasPendingRequest;
                    if (shouldAskChild)
                    {
                        if (!ShouldShowApplicationPrompt(blockedEvent.FilePath, DateTime.UtcNow) ||
                            !PromptChildForApplicationRequest(displayName))
                        {
                            continue;
                        }
                    }

                    var result = AccessRequestApplier.RequestApplication(
                        state,
                        blockedEvent.FilePath,
                        displayName,
                        "applocker:" + blockedEvent.EventId,
                        blockedEvent.User,
                        blockedEvent.OccurredAtUtc);

                    if (result.Changed)
                    {
                        changed = true;
                        if (state.AppControl != null &&
                            state.AppControl.Mode == ApplicationControlMode.Enforced &&
                            blockedEvent.EventId == 8004)
                        {
                            tray.ShowBalloonTip(
                                2500,
                                "Guard",
                                UiLanguage.Text(state.UiLanguage,
                                    "Запрос на приложение отправлен родителю.",
                                    "The app request was sent to the parent."),
                                ToolTipIcon.Info);
                        }
                    }
                }

                if (latestRecordIdSeen > state.LastAppLockerExeEventRecordId)
                {
                    state.LastAppLockerExeEventRecordId = latestRecordIdSeen;
                    changed = true;
                }

                if (changed)
                {
                    GuardStateStorage.Save(state);
                    diagWin?.UpdateDisplay(state);
                }
            }
            catch (Exception ex)
            {
                Log("[AppControl] Could not capture application access requests: " + ex.Message);
            }
        }

        private bool ShouldShowWebsitePrompt(string domain, DateTime utcNow)
        {
            if (lastWebsitePromptUtcByDomain.TryGetValue(domain, out var lastPrompt) &&
                (utcNow - lastPrompt).TotalSeconds < 60)
            {
                return false;
            }

            lastWebsitePromptUtcByDomain[domain] = utcNow;
            return true;
        }

        private bool ShouldShowApplicationPrompt(string filePath, DateTime utcNow)
        {
            var normalized = ApplicationControlApplier.NormalizeExecutablePath(filePath) ?? filePath;
            if (lastApplicationPromptUtcByPath.TryGetValue(normalized, out var lastPrompt) &&
                (utcNow - lastPrompt).TotalSeconds < 60)
            {
                return false;
            }

            lastApplicationPromptUtcByPath[normalized] = utcNow;
            return true;
        }

        private bool PromptChildForWebsiteRequest(string domain)
        {
            var result = MessageBox.Show(
                L("Сайт " + domain + " закрыт. Попросить доступ у родителя?",
                  "The site " + domain + " is blocked. Ask the parent for access?"),
                "Guard",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning);
            return result == DialogResult.Yes;
        }

        private bool PromptChildForApplicationRequest(string displayName)
        {
            var safeName = string.IsNullOrWhiteSpace(displayName) ? L("это приложение", "this app") : displayName;
            var result = MessageBox.Show(
                L("Нельзя запустить " + safeName + ". Попросить доступ у родителя?",
                  "You cannot open " + safeName + ". Ask the parent for access?"),
                "Guard",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning);
            return result == DialogResult.Yes;
        }

        private void StopBlockedWebsiteBrowser(ActivitySnapshot snapshot, string domain)
        {
            if (snapshot.ForegroundProcessId <= 0)
            {
                return;
            }

            try
            {
                using (var process = Process.GetProcessById(snapshot.ForegroundProcessId))
                {
                    process.Kill();
                    Log("[WebDefaultDeny] Closed browser on blocked site: " + domain);
                }
            }
            catch (Exception ex)
            {
                Log("[WebDefaultDeny] Could not close browser on blocked site: " + ex.Message);
            }
        }

        private static List<RunningApplication> GetRunningApplications()
        {
            var applications = new List<RunningApplication>();
            foreach (var process in Process.GetProcesses())
            {
                try
                {
                    var path = process.MainModule?.FileName;
                    if (!string.IsNullOrWhiteSpace(path))
                    {
                        applications.Add(new RunningApplication
                        {
                            ProcessId = process.Id,
                            FilePath = path!
                        });
                    }
                }
                catch
                {
                }
                finally
                {
                    process.Dispose();
                }
            }

            return applications;
        }

        private void StopExpiredApplication(RunningApplication runningApp)
        {
            try
            {
                using (var process = Process.GetProcessById(runningApp.ProcessId))
                {
                    process.Kill();
                    Log("[AppControl] Stopped expired application: " + runningApp.FilePath);
                }
            }
            catch (Exception ex)
            {
                Log("[AppControl] Could not stop expired application: " + ex.Message);
            }
        }

        private void StopBlockedManagementTool(RunningApplication runningApp)
        {
            try
            {
                using (var process = Process.GetProcessById(runningApp.ProcessId))
                {
                    process.Kill();
                    Log("[AppControl] Stopped blocked management tool: " + runningApp.FilePath);
                }
            }
            catch (Exception ex)
            {
                Log("[AppControl] Could not stop blocked management tool: " + ex.Message);
            }
        }

        private void StopOverLimitApplication(RunningApplication runningApp)
        {
            try
            {
                using (var process = Process.GetProcessById(runningApp.ProcessId))
                {
                    process.Kill();
                    Log("[TimeLimit] Stopped over-limit application: " + runningApp.FilePath);
                }
            }
            catch (Exception ex)
            {
                Log("[TimeLimit] Could not stop over-limit application: " + ex.Message);
            }
        }


        public static MainForm? Instance { get; private set; }

        private async Task RequestUpdateAsync()
        {
            if (isCheckingForUpdate)
            {
                diagWin.Log("[Request] Update request ignored: an update is already in progress.");
                return;
            }

            isCheckingForUpdate = true;
            tray.Text = "Guard: Checking for updates..."; // Give immediate feedback
            try
            {
                await RunMainLoopAsync(forceUpdate: true);
            }
            finally
            {
                isCheckingForUpdate = false;
                // The icon and text will be fully updated at the end of RunMainLoopAsync
            }
        }


        public async Task<bool> SendInfoLogAsync(string message)
        {
            diagWin.Log(message);
            if (State == null)
            {
                diagWin?.Log("[CRITICAL] State object is null. Cannot run command.");
                return false;
            }
            if (State.LocalParentMode)
            {
                diagWin.Log("[Logger] Local parent mode: info log kept locally.");
                return true;
            }
            if (State.Assigned && !string.IsNullOrEmpty(State.DeviceId))
            {
                var payload = new Dictionary<string, object>
    {
        { "command", "saveLog" }, // A specific command for this log type
        { "info", message },
        { "deviceId", State.DeviceId }
    };





                // The retry logic is the same as the error log
                for (int i = 0; i < 3; i++)
                {
                    try
                    {
                        using (var client = new HttpClient())
                        {
                            var jsonPayload = System.Text.Json.JsonSerializer.Serialize(payload);
                            var content = new StringContent(jsonPayload, System.Text.Encoding.UTF8, "application/json");
                            var response = await client.PostAsync("https://guard.alexweb.app/checker/ping", content);

                            if (response.IsSuccessStatusCode)
                            {
                                diagWin.Log("[Logger] Info log sent successfully.");
                                return true;
                            }
                            else
                            {
                                diagWin.Log($"[Logger] Failed to send info log (Attempt {i + 1}/3). Status: {response.StatusCode}");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        diagWin.Log($"[Logger] Exception while sending info log (Attempt {i + 1}/3): {ex.Message}");
                    }

                    if (i < 2)
                    {
                        await Task.Delay(1000);
                    }
                }

                diagWin.Log("[Logger] Failed to send info log after 3 attempts.");
            }
            return false;
        }

        public async Task PrepareRulesList(GuardState state)
        {
            var utcNow = DateTime.UtcNow;
            var rulePresetUrls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var rule in state.Rules.Where(r => r.Type == "preset" && !string.IsNullOrWhiteSpace(r.Value)))
            {
                rulePresetUrls.Add(rule.Value.Trim());
            }
            var ruleCustomUrls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var rule in state.Rules.Where(r => r.Type == "custom_url" && !string.IsNullOrWhiteSpace(r.Value)))
            {
                var urls = rule.Value.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)
                                      .Select(u => u.Trim().ToLowerInvariant());

                foreach (var url in DomainAccessGrantApplier.FilterBlockedDomains(urls, state, utcNow))
                {
                    ruleCustomUrls.Add(url);
                }
            }

            foreach (var preset in state.Presets)
            {
                if (string.IsNullOrWhiteSpace(preset.Domains))
                    continue;

                var presetDomains = preset.Domains.Split(new[] { '|' }, StringSplitOptions.RemoveEmptyEntries)
                                                   .Select(d => d.Trim().ToLowerInvariant());

                if (presetDomains.Any(domain => ruleCustomUrls.Contains(domain)))
                {
                    rulePresetUrls.Add(preset.Url.Trim());  // store preset URL (not name)
                                                            //diagWin.Log($"[RulePresetCollector] Preset '{preset.Name}' included via custom_url match.");
                }
            }

            var oldRulePresets = new HashSet<string>(state.RulePresets ?? new List<string>(), StringComparer.OrdinalIgnoreCase);
            var newRulePresets = new HashSet<string>(rulePresetUrls, StringComparer.OrdinalIgnoreCase);

            int checkRules = 0;

            if (!oldRulePresets.SetEquals(newRulePresets))
            {
                state.RulePresets = rulePresetUrls.ToList();
                state.UpdateInfo.Cats = true;
                diagWin.Log($"[Updater] RulePresets updated.{string.Join(", ", state.RulePresets)}");
            }
            else
            {
                diagWin.Log("[Updater] RulePresets not changed.");
                checkRules += 1;
            }
            var oldRuleUrls = new HashSet<string>(state.RuleUrls ?? new List<string>(), StringComparer.OrdinalIgnoreCase);
            var newRuleUrls = new HashSet<string>(ruleCustomUrls, StringComparer.OrdinalIgnoreCase);

            if (!oldRuleUrls.SetEquals(newRuleUrls))
            {
                state.RuleUrls = ruleCustomUrls.ToList();
                state.UpdateInfo.Cats = true;
                diagWin.Log($"[Updater] RuleUrls updated. {string.Join(", ", state.RuleUrls)}");
            }
            else
            {
                diagWin.Log("[Updater] RuleUrls not changed.");
                checkRules += 1;
            }

            if (checkRules == 2) diagWin.Log("[Updater] Rules parameters updated");

            var parsedRules = new List<ParsedRule>();

            foreach (var rule in state.Rules)
            {
                var ruleToParse = rule;
                if (rule.Type == "custom_url" && !string.IsNullOrWhiteSpace(rule.Value))
                {
                    var filteredValues = DomainAccessGrantApplier.FilterBlockedDomains(
                        rule.Value.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)
                            .Select(u => u.Trim().ToLowerInvariant()),
                        state,
                        utcNow);
                    ruleToParse = new InstructionRule
                    {
                        Id = rule.Id,
                        Type = rule.Type,
                        Value = string.Join(",", filteredValues),
                        Schedule = rule.Schedule
                    };
                }

                var parsed = RuleParser.ConvertRuleToParsedRule(ruleToParse, state);
                parsed.Urls = DomainAccessGrantApplier.FilterBlockedDomains(parsed.Urls, state, utcNow);
                parsedRules.Add(parsed);

                // For debug output:
                //diagWin.Log($"Parsed rule: {rule.Id}");
                //diagWin.Log($"Urls: {string.Join(", ", parsed.Urls)}");
                //diagWin.Log($"Ips: {string.Join(", ", parsed.Ips)}");
                //diagWin.Log(ScheduleParser.FormatSchedule(parsed.Schedule));
            }
            state.ParsedRules = parsedRules;


            foreach (var rule in state.ParsedRules)
            {
                var resolvedIps = await DomainResolver.ResolveDomainsAsync(rule.Urls, diagWin.Log);
                rule.ResolvedIps = resolvedIps.Distinct().ToList();
            }

        }

        public async Task PrepareUpdatedIps(GuardState state, bool catUpdated = false, bool ruleUpdated = false)
        {
            if (!ruleUpdated) foreach (var rule in state.ParsedRules)
                {
                    var resolvedIps = await DomainResolver.ResolveDomainsAsync(rule.Urls, diagWin.Log);
                    rule.ResolvedIps = resolvedIps.Distinct().ToList();
                }
            if (!catUpdated) state.ResolvedPermanentIps = await DomainResolver.ResolveDomainsAsync(state.PermanentDomains, diagWin.Log);
            //diagWin.Log("[PermanentCollector] Resolved IPs count: " + blockState.ResolvedPermanentIps.Count);
        }

        public async Task PrepareCatList(GuardState state)
        {
            var permanentCategoryUrls = new List<string>();
            var permanentPresetDomains = new List<string>();
            var permanentPresetIps = new List<string>();
            var rulePresetUrlsCheck = new HashSet<string>(state.RulePresets, StringComparer.OrdinalIgnoreCase);
            var ruleUrls = new HashSet<string>(state.RuleUrls, StringComparer.OrdinalIgnoreCase);

            foreach (var categoryId in state.RestrictedCategoryIds)
            {
                var category = state.RestrictedCategories.FirstOrDefault(c => c.Id == categoryId);
                if (category == null)
                {
                    diagWin.Log($"[PermanentCollector] Category ID {categoryId} not found.");
                    continue;
                }

                // Skip Ads category (Possible will add in future)
                if (category.Id == 1) continue;

                // CATEGORY URLS (after excluding ruleUrls)
                if (!string.IsNullOrWhiteSpace(category.Urls))
                {
                    var urls = category.Urls.Split(new[] { '|' }, StringSplitOptions.RemoveEmptyEntries)
                                             .Select(u => u.Trim().ToLowerInvariant())
                                             .Where(url => !ruleUrls.Contains(url));
                    permanentCategoryUrls.AddRange(urls);
                }

                // PRESET DOMAINS + IPS
                if (!string.IsNullOrWhiteSpace(category.Presets))
                {
                    // Default to an empty list of preset names.
                    IEnumerable<string> presetNames = Enumerable.Empty<string>();

                    // Only try to split the string if it's not null.
                    if (category.Presets != null)
                    {
                        presetNames = category.Presets.Split(new[] { '|' }, StringSplitOptions.RemoveEmptyEntries).Select(p => p.Trim());
                    }

                    foreach (var presetName in presetNames)
                    {
                        var preset = state.Presets.FirstOrDefault(p =>
                            string.Equals(p.Name, presetName, StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(p.Url, presetName, StringComparison.OrdinalIgnoreCase));

                        if (preset == null) continue;

                        // Skip preset if it's covered by rules:
                        if (rulePresetUrlsCheck.Contains(preset.Url.Trim()))
                        {
                            //diagWin.Log($"[PermanentCollector] Skipping preset {presetName} (url={preset.Url}) because covered by rule.");
                            continue;
                        }

                        // Collect preset domains:
                        if (!string.IsNullOrWhiteSpace(preset.Domains))
                        {
                            var domains = preset.Domains.Split(new[] { '|' }, StringSplitOptions.RemoveEmptyEntries).Select(d => d.Trim().ToLowerInvariant());
                            permanentPresetDomains.AddRange(domains);
                        }

                        // Collect preset IPs:
                        if (!string.IsNullOrWhiteSpace(preset.Ips))
                        {
                            var ips = preset.Ips.Split(new[] { '|' }, StringSplitOptions.RemoveEmptyEntries).Select(ip => ip.Trim());
                            permanentPresetIps.AddRange(ips);
                        }
                    }
                }
            }

            // Remove duplicates
            permanentCategoryUrls = permanentCategoryUrls.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            permanentPresetDomains = permanentPresetDomains.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            permanentPresetIps = permanentPresetIps.Distinct().ToList();

            //diagWin.Log("[PermanentCollector] Final category URLs: " + string.Join(", ", permanentCategoryUrls));
            //diagWin.Log("[PermanentCollector] Final preset domains: " + string.Join(", ", permanentPresetDomains));
            //diagWin.Log("[PermanentCollector] Final preset IPs: " + string.Join(", ", permanentPresetIps));


            // STEP: Apply domain variants for permanentCategoryUrls

            var permanentCategoryVariants = new List<string>();

            foreach (var url in permanentCategoryUrls)
            {
                var variants = DomainGenerator.GetDomainVariants(url);
                permanentCategoryVariants.AddRange(variants);
            }

            permanentCategoryVariants = permanentCategoryVariants
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            //diagWin.Log("[PermanentCollector] Domain variants generated: " + string.Join(", ", permanentCategoryVariants));

            var totalDomainsToResolve = DomainAccessGrantApplier.FilterBlockedDomains(
                permanentCategoryVariants.Concat(permanentPresetDomains),
                state,
                DateTime.UtcNow);
            //diagWin.Log("[PermanentCollector] Total unique domains to resolve: " + totalDomainsToResolve.Count);
            state.ResolvedPermanentIps = await DomainResolver.ResolveDomainsAsync(totalDomainsToResolve, diagWin.Log);
            //diagWin.Log("[PermanentCollector] Resolved IPs count: " + blockState.ResolvedPermanentIps.Count);
            state.PermanentDomains = totalDomainsToResolve;
            state.PermanentPresetIps = permanentPresetIps;
            //diagWin.Log("[PermanentCollector] Final permanent domains for hosts: " + string.Join(", ", totalDomainsToResolve));
        }


        private void UpdateTrayIcon()
        {
            try
            {
                // Declare the local variable as nullable by adding a '?'
                Icon? iconToSet = null;
                string textToSet = "Guard"; // Default text
                if (State == null)
                {
                    diagWin?.Log("[CRITICAL] State object is null. Cannot run command.");
                    return;
                }
                // Determine which icon and text to use based on state priority.
                if (!State.Assigned)
                {
                    iconToSet = icon_Grayscale;
                    textToSet = "Guard: Not Assigned";
                }
                else if (!State.SyncStatus)
                {
                    iconToSet = icon_Inactive;
                    textToSet = "Guard: Disabled";
                }
                else if (State.DevUpdate)
                {
                    iconToSet = icon_Updating;
                    textToSet = "Guard: Updating...";
                }
                else // This is the default "active" state.
                {
                    iconToSet = icon_Active;
                    textToSet = "Guard: Active";
                }

                // Your existing logic here is already safe because of the 'iconToSet != null' check.
                if (iconToSet != null && tray.Icon != iconToSet)
                {
                    tray.Icon = iconToSet;
                }

                // Set the corresponding tooltip text.
                tray.Text = textToSet;
            }
            catch (Exception ex)
            {
                diagWin?.Log("[ICON ERROR] Could not update status icon: " + ex.Message);
            }
        }

        private Icon LoadIconFromResourceBytes(byte[] resourceBytes)
        {
            try
            {
                using (var ms = new System.IO.MemoryStream(resourceBytes))
                {
                    using (var bmp = new Bitmap(ms))
                    {
                        return Icon.FromHandle(bmp.GetHicon());
                    }
                }
            }
            catch (Exception ex)
            {
                diagWin.Log($"[ICON ERROR] Failed to load icon from resource bytes: {ex.Message}");
                // Return a default system icon as a fallback.
                return SystemIcons.Application;
            }
        }

        private void LoadAllIcons()
        {
            icon_Active = LoadIconFromResourceBytes(Properties.Resources.GuardIcon_Base);
            icon_Grayscale = LoadIconFromResourceBytes(Properties.Resources.Icon_Grayscale);
            icon_Inactive = LoadIconFromResourceBytes(Properties.Resources.Overlay_Inactive);
            icon_Updating = LoadIconFromResourceBytes(Properties.Resources.Overlay_Updating);
        }


        string hostsPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts");




        public void LogTimelineAndRules(GuardState state)
        {
            var log = new System.Text.StringBuilder();
            log.AppendLine("--- SCHEDULER DEBUG DUMP ---");

            // Log the Parsed Rules that were used for the calculation.
            log.AppendLine($"\n[Parsed Rules ({state.ParsedRules.Count})]");
            if (!state.ParsedRules.Any())
            {
                log.AppendLine("  (No rules are currently defined)");
            }
            else
            {
                foreach (var rule in state.ParsedRules)
                {
                    log.AppendLine($"  - Rule ID: {rule.RuleId}, Schedule: '{rule.Schedule}', URLs: {rule.Urls.Count}, IPs: {rule.Ips.Count}");
                }
            }

            // Log the final calculated timeline.
            log.AppendLine($"\n[Weekly Timeline ({state.WeeklyTimeline.Count} Snapshots)]");
            if (!state.WeeklyTimeline.Any())
            {
                log.AppendLine("  (Timeline is empty, no scheduled rules are active at any time)");
            }
            else
            {
                foreach (var snapshot in state.WeeklyTimeline)
                {
                    log.AppendLine($"  - Minute {snapshot.StartMinuteOfWeek}: Active IDs = [{string.Join(", ", snapshot.ActiveRuleIds)}]");
                }
            }

            log.AppendLine("\n--- END DEBUG DUMP ---");
            diagWin.Log(log.ToString());
        }

        // Add this new method inside the MainForm class
        public async Task CreateDatedHostsBackupAsync(Action<string>? log)
        {
            try
            {
                string hostsFilePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts");
                string backupFolder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\savedBU");

                // Create a filename with the current UTC date
                string backupFileName = $"hosts_{DateTime.UtcNow:yyyy-MM-dd}.bak";
                string destinationPath = Path.Combine(backupFolder, backupFileName);

                // Ensure the backup directory exists
                Directory.CreateDirectory(backupFolder);

                // Copy the file. We use Task.Run to perform the copy on a background thread.
                // The 'true' means it will overwrite a backup if one was already made today.
                await Task.Run(() => File.Copy(hostsFilePath, destinationPath, true));

                log?.Invoke($"[Backup] Successfully created dated backup: {destinationPath}");
            }
            catch (Exception ex)
            {
                log?.Invoke($"[Backup] ERROR: Failed to create dated hosts backup: {ex.Message}");
            }
        }





        // Add this new method inside the MainForm class

        private async Task WriteToHostsFileAsync(List<string> lines)
        {
            try
            {
                await Task.Run(() => File.WriteAllLines(hostsPath, lines));
                if (State == null)
                {
                    diagWin?.Log("[CRITICAL] State object is null. Cannot run command.");
                    return;
                }

                var fileInfo = new FileInfo(hostsPath);
                State.HostsFileLastWriteTimeUtc = fileInfo.LastWriteTimeUtc;
                // After a successful write, update our state tracking property
                State.HostsFileSize = fileInfo.Length;

                diagWin.Log($"[Hosts] Hosts file updated. New timestamp: {State.HostsFileLastWriteTimeUtc}, Size: {State.HostsFileSize} bytes");
            }
            catch (Exception ex)
            {
                if (State == null)
                {
                    diagWin?.Log("[CRITICAL] State object is null. Cannot run command.");
                    return;
                }
                diagWin.Log($"[Hosts] CRITICAL: Failed to write to hosts file: {ex.Message}");
                // If the write fails, we can't trust our state, so we nullify it.
                State.HostsFileLastWriteTimeUtc = null;
            }
            finally
            {
                if (State != null)
                {
                    GuardStateStorage.Save(State);
                }

            }
        }


        public async Task ApplyPermanentDomainBlocksToHostsAsync(List<string> domains, string tag = "# GuardBlock")
        {
            await Task.Run(async () =>
            {
                string hostsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts");
                var origLines = File.ReadAllLines(hostsPath).ToList();

                var cleanLines = origLines.Where(line => !line.TrimEnd().EndsWith(tag)).ToList();

                foreach (var dom in domains.Distinct(StringComparer.OrdinalIgnoreCase))
                {
                    cleanLines.Add($"127.0.0.1 {dom} {tag}");
                    cleanLines.Add($"::1 {dom} {tag}");
                }

                // Call our new helper method instead of writing directly
                await WriteToHostsFileAsync(cleanLines);
            });

            diagWin.Log($"[Hosts] Applied {domains.Count} permanent domains (tag={tag}).");
        }

        public async Task ApplyFirewallRulesAsync(List<string> blockedIps, List<string> permDomains, string tag = "GuardBlock-Cat")
        {
            await Task.Run(() =>
            {
                foreach (var ip in blockedIps.Distinct())
                {
                    SystemCleaner.RunCmd($"netsh advfirewall firewall add rule name=\"{tag}\" dir=out action=block remoteip={ip}");
                }

                foreach (var domain in permDomains.Distinct())
                {
                    SystemCleaner.RunCmd($"netsh advfirewall firewall add rule name=\"{tag}\" dir=out action=block remotehost={domain}");
                }
            });

            diagWin.Log($"[Firewall] Applied IPs: {blockedIps.Count}, domains: {permDomains.Count} (tag={tag}).");
        }

        public async Task ApplyPermanentCategoriesAsync(GuardState state)
        {
            // Always clean permanent CAT blocks before apply
            await SystemCleaner.ResetHostsFileAsync(diagWin.Log, "# GuardBlock");
            await SystemCleaner.RemoveFirewallRulesAsync(diagWin.Log, "GuardBlock-Cat");

            // Apply Hosts file (permanent domains)
            await ApplyPermanentDomainBlocksToHostsAsync(state.PermanentDomains, "# GuardBlock");

            // Build full list of permanent IPs = resolved IPs + preset IPs
            var fullPermanentIps = state.ResolvedPermanentIps
                                              .Concat(state.PermanentPresetIps)
                                              .Distinct()
                                              .ToList();

            // Apply Firewall IPs + Domains
            await ApplyFirewallRulesAsync(fullPermanentIps, state.PermanentDomains, "GuardBlock-Cat");

            diagWin.Log("[ApplyPermanentCategories] Permanent categories (domains + IPs + presets) fully applied.");
        }


        public async Task ApplyRulesPhysicalAsync(List<ParsedRule> activeRules)
        {
            await SystemCleaner.ResetHostsFileAsync(diagWin.Log, "# GuardBlock-Rules");
            await SystemCleaner.RemoveFirewallRulesAsync(diagWin.Log, "GuardBlock-Rules");

            if (activeRules == null || activeRules.Count == 0)
            {
                diagWin.Log("[ApplyRules] No active rules to apply.");
                return;
            }

            var allDomains = new List<string>();
            var allIps = new List<string>();

            foreach (var rule in activeRules)
            {
                if (rule.Urls != null)
                    allDomains.AddRange(rule.Urls);

                if (rule.Ips != null)
                    allIps.AddRange(rule.Ips);

                if (rule.ResolvedIps != null)
                    allIps.AddRange(rule.ResolvedIps);
            }

            allDomains = allDomains
                .Where(d => !string.IsNullOrWhiteSpace(d))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            if (State != null)
            {
                allDomains = DomainAccessGrantApplier.FilterBlockedDomains(allDomains, State, DateTime.UtcNow);
            }

            allIps = allIps
                .Where(ip => !string.IsNullOrWhiteSpace(ip))
                .Distinct()
                .ToList();

            // Apply to hosts
            await ApplyPermanentDomainBlocksToHostsAsync(allDomains, "# GuardBlock-Rules");

            // Apply to firewall
            await ApplyFirewallRulesAsync(allIps, allDomains, "GuardBlock-Rules");

            diagWin.Log($"[ApplyRules] Applied {allDomains.Count} domains and {allIps.Count} IPs from active rules.");
        }



        public async Task DisableApp(bool requirePin = true)
        {
            if (!requirePin || PromptPin(L("Введите PIN, чтобы отключить Guard:", "Enter PIN to disable app:")))
            {
                // We will now use the main 'State' property of the form,
                // instead of loading a separate local copy.
                await SendInfoLogAsync($"Application disabled with PIN at local time: {DateTime.Now}");
                await SystemCleaner.ResetHostsFileAsync(diagWin.Log);
                await SystemCleaner.RemoveFirewallRulesAsync(diagWin.Log);
                await SystemCleaner.FlushDnsAsync();

                // Use the main 'State' property for the check.
                if (State != null && State.ResetConnection)
                {
                    await SystemCleaner.DisableAndRestoreNetworkAsync(diagWin.Log);
                    await SystemCleaner.FlushDnsAsync();
                }

                // Create disable.guard for watchdog:
                try { System.IO.File.WriteAllText(AppSettings.DisableFlagPath, DateTime.Now.ToString()); } catch { }

                tray.Visible = false;

                // The ResetHostsFileAsync call already saved the correct timestamp.
                // We just ensure the DevUpdate flag is also saved before exiting.
                if (State != null)
                {
                    State.DevUpdate = false;
                    GuardStateStorage.Save(State);
                }
                await Task.Delay(200);

                Application.Exit();
            }
            else
            {
                tray.ShowBalloonTip(1200, L("Неверно", "Invalid"), L("Неверный PIN", "Wrong PIN"), ToolTipIcon.Warning);
            }
        }

        public void ShutdownApplication()
        {
            try
            {
                // Create disable.guard file to signal the watchdog to exit
                System.IO.File.WriteAllText(AppSettings.DisableFlagPath, DateTime.Now.ToString());
            }
            catch (Exception ex)
            {
                diagWin.Log("Failed to create disable flag file: " + ex.Message);
            }

            tray.Visible = false;
            Application.Exit();
        }

        public bool PromptPin(string promptText = "")
        {
            if (string.IsNullOrWhiteSpace(promptText))
            {
                promptText = L("Введите PIN, чтобы отключить Guard:", "Enter PIN to disable app:");
            }

            var now = DateTime.UtcNow;

            // This lockout logic remains the same
            if (lastPinAttemptTime != null)
            {
                var timeSinceLast = now - lastPinAttemptTime.Value;

                if (pinFailCount >= 3 && pinFailCount < 4 && timeSinceLast < TimeSpan.FromMinutes(1))
                {
                    tray.ShowBalloonTip(1000, L("Слишком рано", "Too Soon"), L("Подождите 1 минуту перед следующей попыткой PIN.", "Please wait 1 minute before next PIN attempt."), ToolTipIcon.Warning);
                    return false;
                }
                else if (pinFailCount >= 4 && timeSinceLast < TimeSpan.FromMinutes(10))
                {
                    tray.ShowBalloonTip(1000, L("Слишком рано", "Too Soon"), L("Подождите 10 минут перед следующей попыткой PIN.", "Please wait 10 minutes before next PIN attempt."), ToolTipIcon.Warning);
                    return false;
                }
            }

            // --- The UI logic is now replaced with a call to our new PinForm ---
            string enteredPin = "";
            using (var pinDialog = new PinForm(promptText, new Icon(new System.IO.MemoryStream(Properties.Resources.guard)), L("Введите PIN", "Enter PIN")))
            {
                // Show the reusable dialog and check if the user clicked OK
                if (pinDialog.ShowDialog() != DialogResult.OK)
                {
                    return false; // User cancelled
                }
                enteredPin = pinDialog.EnteredPin;
            }
            // --- End of new UI logic ---

            lastPinAttemptTime = now;

            string correctPin = EmergencyPinPolicy.GetEffectivePin(State?.PinCode);

            if (enteredPin == correctPin)
            {
                pinFailCount = 0;
                return true;
            }
            else
            {
                pinFailCount++;
                if (State != null && pinFailCount % 5 == 0)
                {
                    State.ErrorLog.Add($"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}Z] User tried to input pincode at least {pinFailCount} times");
                    GuardStateStorage.Save(State);
                }
                return false;
            }
        }


        public static async Task TrueTimePeriodicCheckAsync(GuardState state, Action<string> log)
        {
            log("[GUARD] Starting periodic time verification check...");
            if (state == null) return;

            var trustedUtc = await TrueTimeHelper.GetTrustedUtcNowAsync(log);
            if (!trustedUtc.HasValue)
            {
                log("[TimeCheck] Could not get a trusted UTC time from any provider. Aborting check.");
                return;
            }

            // Use the "u" format specifier to log the true UTC value without local conversion.
            log($"[TimeCheck] Trusted UTC time received: {trustedUtc.Value:u}");

            var deviceLocalTime = DateTime.Now;

            // To prevent automatic timezone conversion, we create new DateTime objects
            // with an "Unspecified" kind. This forces a raw subtraction of the time values.
            var localUnspecified = new DateTime(deviceLocalTime.Ticks, DateTimeKind.Unspecified);
            var utcUnspecified = new DateTime(trustedUtc.Value.Ticks, DateTimeKind.Unspecified);
            var trueOffset = localUnspecified - utcUnspecified;

            int trueOffsetMinutes = (int)Math.Round(trueOffset.TotalMinutes);

            log($"[TimeCheck] Device's current local time: {deviceLocalTime:yyyy-MM-dd HH:mm:ss}");
            log($"[TimeCheck] Calculated TRUE offset is: {trueOffsetMinutes} minutes.");

            // Compare the true offset with the offset we have stored in our state.
            if (state.DeviceUtcOffsetMinutes == null || Math.Abs(state.DeviceUtcOffsetMinutes.Value - trueOffsetMinutes) > 1)
            {
                log($"[TimeCheck] OFFSET MISMATCH! Stored offset was {state.DeviceUtcOffsetMinutes}, but true offset is {trueOffsetMinutes}. Correcting now.");
                state.DeviceUtcOffsetMinutes = trueOffsetMinutes;
                GuardStateStorage.Save(state);
            }
            else
            {
                log("[TimeCheck] Device time and offset appear to be correct. No changes needed.");
            }
        }

        public async Task InvokeAsync(Func<Task> func)
        {
            if (InvokeRequired)
                await (Task)Invoke(func);
            else
                await func();
        }
        public void LogToDiagnostics(string message)
        {
            if (diagWin != null)
            {
                diagWin.Log(message);
            }
        }
        public void UpdateState(GuardState newState)
        {
            State = newState;
        }

        public async Task CheckForUpdatesAsync()
        {
            // In future steps, we will add the logic here to call the GitHub API.
            // For now, it just shows a placeholder message.
            diagWin.Log("Update check initiated.");
            MessageBox.Show(L("Проверка обновлений пока не реализована.", "Update checking is not yet implemented."), L("Информация", "Info"));
            await Task.CompletedTask; // To make the method awaitable
        }

        public async Task CleanAndClose()
        {
            try
            {
                // Clear Hosts and Firewall Rules first
                await SystemCleaner.ResetHostsFileAsync(diagWin.Log);
                await SystemCleaner.RemoveFirewallRulesAsync(diagWin.Log);
                diagWin.Log("[Action] Hosts and firewall rules cleared.");

                // --- ADD THIS BLOCK TO REMOVE THE STARTUP TASK ---
                try
                {

                    ScheduledTaskHelper.RemoveStartupTask();
                    diagWin.Log("[Action] Startup task removed.");

                }
                catch (Exception ex)
                {
                    diagWin.Log("Error removing startup task: " + ex.Message);
                }
                // --- END OF NEW BLOCK ---

                // Delete GuardState main file
                File.Delete(GuardStateStorage.StateFilePath);
                diagWin.Log("GuardState main file deleted.");

                // Delete GuardState backup file
                try
                {
                    string etcSavedBU = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\savedBU");
                    string backupFile = Path.Combine(etcSavedBU, $"state.dat");
                    if (File.Exists(backupFile)) File.Delete(backupFile);
                    diagWin.Log("GuardState backup file deleted.");
                }
                catch (Exception ex)
                {
                    diagWin.Log("Error deleting GuardState backup: " + ex.Message);
                }

            }
            catch (Exception ex)
            {
                diagWin.Log("Error during full clean: " + ex.Message);
            }
            finally
            {
                // This section will run even if there was an error during cleanup.
                try
                {
                    File.WriteAllText(AppSettings.DisableFlagPath, DateTime.Now.ToString());
                }
                catch { }

                // Wait a bit for watchdog to see the flag
                await Task.Delay(500);

                // Finally exit the app
                Application.Exit();
            }
        }

    }
}
