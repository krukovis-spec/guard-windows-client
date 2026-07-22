using System;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;

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
            this._state = state;
            this.Icon = appIcon;
            this.Text = L("Диагностика Guard", "Guard Diagnostics");
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

            var containmentStatus = new Label
            {
                Text = L("Guard v2 P0: устаревшее управление отключено.",
                    "Guard v2 P0: legacy controls are disabled."),
                AutoSize = true,
                Left = 170,
                Top = 16
            };
            topPanel.Controls.Add(containmentStatus);

            btnUpdateApp = new Button()
            {
                Text = L("Проверить обновления", "Check for Updates"),
                Width = 150,
                Height = 30,
                Left = 10,
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
                Text = L("Записать состояние", "Log Current State"),
                Width = 150,
                Height = 30,
                Left = 10,
                Top = 10
            };
            btnLogState.Click += (s, e) =>
            {
                Log(GuardDiagnosticSummary.Build(MainForm.Instance?.State ?? _state));
            };

            topPanel.Controls.Add(btnLogState);

            Label labelTrueTime = new Label
            {
                Name = "labelTrueTime",
                Text = L("Проверяю точное время...", "Loading real time..."),
                AutoSize = true,
                Location = new Point(topPanel.ClientSize.Width - 160, 10),
                Anchor = AnchorStyles.Top | AnchorStyles.Right
            };
            topPanel.Controls.Add(labelTrueTime);

            Label labelUtcOffset = new Label
            {
                Name = "labelUtcOffset",
                Text = L("Смещение: ...", "Offset: ..."),
                AutoSize = true,
                ForeColor = Color.Gray,
                Location = new Point(topPanel.ClientSize.Width - 160, 28),
                Anchor = AnchorStyles.Top | AnchorStyles.Right
            };
            topPanel.Controls.Add(labelUtcOffset);

            // --- Controls for the Bottom Panel ---
            // Close only this diagnostics window. It must never stop Guard.
            var btnClose = new Button()
            {
                Text = L("Закрыть окно", "Close window"),
                Width = 110,
                Height = 30,
                Anchor = AnchorStyles.Top | AnchorStyles.Right
            };
            btnClose.Location = new Point(bottomPanel.ClientSize.Width - btnClose.Width - 10, 10);
            btnClose.Click += (s, e) =>
            {
                Hide();
            };
            bottomPanel.Controls.Add(btnClose);

        }

        private string L(string russian, string english)
        {
            return UiLanguage.Text(_state?.UiLanguage, russian, english);
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
                            ? L("Смещение: ", "Offset: ") + state.DeviceUtcOffsetMinutes.Value + " " + L("минут", "minutes")
                            : L("Смещение: ожидаю проверки...", "Offset: Awaiting check...");
                    }
                    else
                    {
                        // If sync is OFF, show that it's disabled.
                        offsetLabel.Text = L("Смещение: синхронизация выключена", "Offset: Sync Disabled");
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
