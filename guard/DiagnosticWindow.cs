using System;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Windows.Forms;
using System.Text.Json;

namespace Guard
{
    public partial class DiagnosticWindow : Form
    {
        private TextBox logBox;

        private Button btnUpdateApp;
        private Button btnLogState;
        private GuardState _state; // store the state reference

        public DiagnosticWindow(GuardState state, Icon appIcon)
        {
            InitializeComponent();
            this.Icon = appIcon;
            this.Text = "Guard Diagnostics";
            this.Size = new System.Drawing.Size(720, 570);
            this.MinimumSize = new System.Drawing.Size(600, 400);

            // Use a TableLayoutPanel for a robust layout
            var mainLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 3,
            };
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 50F)); // Top row for info
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100F)); // Middle row for logs
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 50F)); // Bottom row for buttons
            this.Controls.Add(mainLayout);

            // --- Top Panel (now placed inside the table) ---
            var topPanel = new Panel
            {
                Dock = DockStyle.Fill, // Fills the top table cell
                BackColor = SystemColors.ControlLight,
            };
            mainLayout.Controls.Add(topPanel, 0, 0);

            // --- Log Box (now placed inside the table) ---
            logBox = new TextBox()
            {
                Multiline = true,
                ScrollBars = ScrollBars.Vertical,
                ReadOnly = true,
                Dock = DockStyle.Fill, // Fills the middle table cell
                Font = new Font("Consolas", 9.75F, FontStyle.Regular, GraphicsUnit.Point),
                BorderStyle = BorderStyle.Fixed3D,
                Margin = new Padding(10, 5, 10, 5) // Use margin to create space
            };
            mainLayout.Controls.Add(logBox, 0, 1);

            // --- Bottom Panel (now placed inside the table) ---
            var bottomPanel = new Panel
            {
                Dock = DockStyle.Fill, // Fills the bottom table cell
                BackColor = SystemColors.ControlLight,
            };
            mainLayout.Controls.Add(bottomPanel, 0, 2);

            // --- Controls for the Top Panel ---

            var btnAssign = new Button()
            {
                Text = "Assign Device",
                Width = 120,
                Height = 30,
                Left = 10,
                Top = 10,
                // FIX: Use the 'state' object that was passed in, NOT MainForm.Instance
                Enabled = !state.Assigned
            };
            topPanel.Controls.Add(btnAssign);

            // This is the click event handler for the new button
            btnAssign.Click += async (s, e) =>
            {
                using (var assignForm = new AssignForm())
                {
                    if (assignForm.ShowDialog() == DialogResult.OK)
                    {
                        var newState = assignForm.AssignedState ?? new GuardState();

                        // Call the new public method to update the state in the main form
                        MainForm.Instance?.UpdateState(newState);

                        Log("Device was assigned successfully. Fetching initial instructions...");

                        // Disable this button now that assignment is complete
                        btnAssign.Enabled = false;

                        // Immediately run the main loop to apply the new state
                        var updateTask = MainForm.Instance?.RunMainLoopAsync(forceUpdate: true);
                        await (updateTask ?? Task.CompletedTask);
                    }
                }
            };

            var btnToggleStartup = new Button()
            {
                Text = "Loading Status...",
                Width = 180, // A bit wider to fit the text
                Height = 30,
                Left = btnAssign.Right + 10, // Position it next to the assign button
                Top = 10
            };

            // This is a helper action to update the button's text and state.
            Action updateButtonState = () =>
            {
                try
                {
                    if (ScheduledTaskHelper.IsStartupTaskInstalled())
                    {
                        btnToggleStartup.Text = "Disable Start with Windows";
                    }
                    else
                    {
                        btnToggleStartup.Text = "Enable Start with Windows";
                    }
                    btnToggleStartup.Enabled = true;
                }
                catch (Exception ex)
                {
                    Log("Could not get startup task status: " + ex.Message);
                    btnToggleStartup.Text = "Startup Status Unavailable";
                    btnToggleStartup.Enabled = false;
                }
            };

            // Set the initial text of the button when the window is created.
            btnToggleStartup.Text = state.IsStartUp
    ? "Disable Start with Windows"
    : "Enable Start with Windows";

            // Define the action to take when the button is clicked.
            btnToggleStartup.Click += (s, e) =>
            {
                try
                {
                    if (ScheduledTaskHelper.IsStartupTaskInstalled())
                    {
                        ScheduledTaskHelper.RemoveStartupTask(Log, state);
                        Log("Startup task removed.");
                    }
                    else
                    {
                        ScheduledTaskHelper.RegisterStartupTask(Log, state);
                        Log("Startup task registered.");
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Error updating startup task: " + ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }

                // Refresh the button's text after performing the action.
                updateButtonState();
            };

            topPanel.Controls.Add(btnToggleStartup);
            // --- END OF NEW BLOCK ---



            btnUpdateApp = new Button()
            {
                Text = "Check for Updates",
                Width = 150,
                Height = 30,
                Left = btnToggleStartup.Right + 10, // Position it next to the startup button
                Top = 10,
            };
            btnUpdateApp.Click += async (s, e) =>
            {
                var updateCheckTask = MainForm.Instance?.CheckForUpdatesAsync();
                await (updateCheckTask ?? Task.CompletedTask);
            };
            topPanel.Controls.Add(btnUpdateApp);

            // HIDE it for now
            btnUpdateApp.Visible = false;

            // ADD "Log Current State" button in its place
            btnLogState = new Button()
            {
                Text = "Log Current State",
                Width = 150,
                Height = 30,
                Left = btnToggleStartup.Right + 10,
                Top = 10
            };
            btnLogState.Click += (s, e) =>
            {
                // Always log the MAIN, CURRENT state!
                Log(LogCurrentState(MainForm.Instance?.State ?? _state));
            };

            topPanel.Controls.Add(btnLogState);

            this._state = state; // Save state ref for logger


            Label labelTrueTime = new Label
            {
                Name = "labelTrueTime",
                Text = "Loading real time...",
                AutoSize = true,
                Location = new Point(topPanel.ClientSize.Width - 160, 10),
                Anchor = AnchorStyles.Top | AnchorStyles.Right
            };
            topPanel.Controls.Add(labelTrueTime);

            Label labelUtcOffset = new Label
            {
                Name = "labelUtcOffset",
                Text = "Offset: ...",
                AutoSize = true,
                ForeColor = Color.Gray,
                Location = new Point(topPanel.ClientSize.Width - 160, 28),
                Anchor = AnchorStyles.Top | AnchorStyles.Right
            };
            topPanel.Controls.Add(labelUtcOffset);

            // --- Controls for the Bottom Panel ---
            var btnReset = new Button()
            {
                Text = "Reset assignment and quit",
                Width = 190,
                Height = 30,
                Left = 10,
                Top = 10,
                ForeColor = Color.Red // Make the text red
            };
            bottomPanel.Controls.Add(btnReset);

            btnReset.Click += async (s, e) =>
            {
                var confirmResult = MessageBox.Show(
                    "Please confirm removing all instructions and the device assignment.",
                    "Confirm Full Reset",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Warning);

                if (confirmResult == DialogResult.No)
                {
                    Log("Reset operation canceled by user.");
                    return;
                }

                // Safely call the instance method. If Instance is null, the task will be null.
                var cleanTask = MainForm.Instance?.CleanAndClose();

                // Await the task, or if it's null, await an already completed task.
                await (cleanTask ?? Task.CompletedTask);
            };

            // Add a "Close" button that shuts down the application completely.
            var btnClose = new Button()
            {
                Text = "Close",
                Width = 90,
                Height = 30,
                Anchor = AnchorStyles.Top | AnchorStyles.Right
            };
            btnClose.Location = new Point(bottomPanel.ClientSize.Width - btnClose.Width - 10, 10);
            btnClose.Click += (s, e) =>
            {
                // Calls the new shutdown method
                MainForm.Instance?.ShutdownApplication();
            };
            bottomPanel.Controls.Add(btnClose);

            // Add a "Disable and Close" button.
            var btnDisable = new Button()
            {
                Text = "Disable and Close",
                Width = 140,
                Height = 30,
                Anchor = AnchorStyles.Top | AnchorStyles.Right
            };
            btnDisable.Location = new Point(btnClose.Left - btnDisable.Width - 5, 10);
            btnDisable.Click += async (s, e) =>
            {
                // Calls DisableApp, passing 'false' to bypass the PIN prompt.
                // Safely call the instance method. If Instance is null, the task will be null.
                var disableTask = MainForm.Instance?.DisableApp(requirePin: false);
                // Await the task, or if it's null, await an already completed task.
                await (disableTask ?? Task.CompletedTask);
            };
            bottomPanel.Controls.Add(btnDisable);

        }

        private string LogCurrentState(GuardState state)
        {
            var sb = new System.Text.StringBuilder();
            sb.AppendLine("------ Current Guard State ------");
            sb.AppendLine($"AssignCode: {state.AssignCode}");
            sb.AppendLine($"DeviceId: {state.DeviceId}");
            sb.AppendLine($"Version: {state.Version}");
            sb.AppendLine($"DevUpdate: {state.DevUpdate}");
            sb.AppendLine($"SyncStatus: {state.SyncStatus}");
            sb.AppendLine($"PinStatus: {state.PinStatus}");
            sb.AppendLine($"Assigned: {state.Assigned}");
            sb.AppendLine($"AdRecheck: {state.AdRecheck}");
            sb.AppendLine($"LastUpdate: {state.LastUpdate}");
            sb.AppendLine($"IpsRecheck: {state.IpsRecheck}");
            sb.AppendLine($"DeviceTimeZoneId: {state.DeviceTimeZoneId}");
            sb.AppendLine($"DeviceUtcOffsetMinutes: {state.DeviceUtcOffsetMinutes}");
            sb.AppendLine($"IsHostsFileActive: {state.IsHostsFileActive}");
            sb.AppendLine($"IsStartUp: {state.IsStartUp}");
            sb.AppendLine($"HostsFileLastWriteTimeUtc: {state.HostsFileLastWriteTimeUtc}");
            sb.AppendLine($"HostsFileSize: {state.HostsFileSize}");
            sb.AppendLine($"ResetConnection: {state.ResetConnection}");
            sb.AppendLine($"Sound: {state.Sound}");

            // Arrays & complex objects as JSON
            var opts = new JsonSerializerOptions { WriteIndented = true };
            sb.AppendLine("RestrictedCategoryIds: " + JsonSerializer.Serialize(state.RestrictedCategoryIds, opts));
            sb.AppendLine("ErrorLog: " + JsonSerializer.Serialize(state.ErrorLog, opts));
            sb.AppendLine("Rules: " + JsonSerializer.Serialize(state.Rules, opts));
            sb.AppendLine("Presets: " + JsonSerializer.Serialize(state.Presets, opts));
            sb.AppendLine("RestrictedCategories: " + JsonSerializer.Serialize(state.RestrictedCategories, opts));
            sb.AppendLine("UpdateInfo: " + JsonSerializer.Serialize(state.UpdateInfo, opts));
            sb.AppendLine("RulePresets: " + JsonSerializer.Serialize(state.RulePresets, opts));
            sb.AppendLine("RuleUrls: " + JsonSerializer.Serialize(state.RuleUrls, opts));
            sb.AppendLine("PermanentDomains: " + JsonSerializer.Serialize(state.PermanentDomains, opts));
            sb.AppendLine("ResolvedPermanentIps: " + JsonSerializer.Serialize(state.ResolvedPermanentIps, opts));
            sb.AppendLine("PermanentPresetIps: " + JsonSerializer.Serialize(state.PermanentPresetIps, opts));
            sb.AppendLine("ActiveRuleIds: " + JsonSerializer.Serialize(state.ActiveRuleIds, opts));
            sb.AppendLine("ParsedRules: " + JsonSerializer.Serialize(state.ParsedRules, opts));
            sb.AppendLine($"LastAppliedSnapshotMinute: {state.LastAppliedSnapshotMinute}");
            sb.AppendLine("WeeklyTimeline: " + JsonSerializer.Serialize(state.WeeklyTimeline, opts));

            sb.AppendLine("------ End of State ------");
            return sb.ToString();
        }




        public void UpdateDisplay(GuardState state)
        {
            if (this.IsDisposed || this.Disposing) return;

            Action updateAction = () =>
            {
                var offsetLabel = this.Controls.Find("labelUtcOffset", true).FirstOrDefault() as Label;
                if (offsetLabel != null)
                {
                    if (state.SyncStatus)
                    {
                        // If sync is ON, show the offset or a "waiting" message.
                        offsetLabel.Text = state.DeviceUtcOffsetMinutes.HasValue
                            ? $"Offset: {state.DeviceUtcOffsetMinutes.Value} minutes"
                            : "Offset: Awaiting check...";
                    }
                    else
                    {
                        // If sync is OFF, show that it's disabled.
                        offsetLabel.Text = "Offset: Sync Disabled";
                    }
                }
            };

            if (this.InvokeRequired)
            {
                try { this.Invoke(updateAction); } catch { }
            }
            else
            {
                updateAction();
            }
        }
        public void Log(string msg)
        {
            if (this.IsDisposed || this.Disposing || logBox == null || logBox.IsDisposed || logBox.Disposing)
                return;

            if (this.InvokeRequired)
            {
                try { this.Invoke(new Action(() => Log(msg))); }
                catch { /* ignore if form is closing */ }
            }
            else
            {
                try
                {
                    if (logBox.Text.Length > 60000)
                    {
                        logBox.Text = "--- LOGS TRIMMED ---\r\n";
                    }
                    logBox.AppendText(DateTime.Now.ToString("HH:mm:ss") + " " + msg + Environment.NewLine);
                    // This ensures the log box always shows the latest message
                    logBox.SelectionStart = logBox.Text.Length;
                    logBox.ScrollToCaret();
                }
                catch { /* ignore if form is closing */ }
            }
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (e.CloseReason == CloseReason.UserClosing)
            {
                e.Cancel = true;
                this.Hide();
            }
            else
            {
                base.OnFormClosing(e);
            }
        }
    }
}