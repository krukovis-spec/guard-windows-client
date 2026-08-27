using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Windows.Forms;
using System.Linq; // for string LINQ

namespace Guard
{
    public partial class AssignForm : Form
    {
        // AssignedState is nullable, so no warning/error.
        public GuardState? AssignedState { get; private set; }
        private readonly string _language;

        public AssignForm(string language = UiLanguage.Russian)
        {
            _language = UiLanguage.Normalize(language);
            InitializeComponent();
            this.Icon = new Icon(new System.IO.MemoryStream(Properties.Resources.guard));
            this.Text = L("Привязать устройство", "Assign Device");
            this.Width = 720;
            this.Height = 480;
            this.StartPosition = FormStartPosition.CenterScreen;

            var bigFont = new Font("Segoe UI", 16, FontStyle.Regular);

            int marginLeft = 40;
            int width = 600;
            int boxHeight = 100;
            int lineSpacing = 32;    // vertical space between controls

            var label1 = new Label()
            {
                Text = L("Код привязки (12 цифр):", "Assign Code (12 digits):"),
                Left = marginLeft,
                Top = 40,
                Width = width,
                Font = bigFont,
                AutoSize = true
            };
            var tbAssignCode = new TextBox()
            {
                Name = "tbAssignCode",
                Left = marginLeft,
                Top = label1.Top + label1.Height + lineSpacing, // push textbox down
                Width = width,
                Height = boxHeight,
                Font = bigFont,
                MaxLength = 14 // allows for 12 digits + 2 dashes
            };

            // ADD: Auto-format assign code as XXXX-XXXX-XXXX
            tbAssignCode.TextChanged += (s, e) =>
            {
                // Remove all non-digits
                string digits = new string(tbAssignCode.Text.Where(char.IsDigit).ToArray());

                // Limit to 12 digits
                if (digits.Length > 12) digits = digits.Substring(0, 12);

                // Format as XXXX-XXXX-XXXX
                var sb = new StringBuilder();
                for (int i = 0; i < digits.Length; i++)
                {
                    if (i > 0 && i % 4 == 0) sb.Append("-");
                    sb.Append(digits[i]);
                }

                // Only update if necessary (to avoid infinite loop)
                string formatted = sb.ToString();
                if (tbAssignCode.Text != formatted)
                {
                    tbAssignCode.Text = formatted;
                    tbAssignCode.SelectionStart = formatted.Length; // Always jump caret to end
                }
                else
                {
                    // Even if text was already formatted, make sure caret is at end
                    tbAssignCode.SelectionStart = tbAssignCode.Text.Length;
                }
            };

            var label2 = new Label()
            {
                Text = L("PIN-код (6 цифр):", "PIN Code (6 digits):"),
                Left = marginLeft,
                Top = tbAssignCode.Top + tbAssignCode.Height + lineSpacing,
                Width = width,
                Font = bigFont,
                AutoSize = true
            };
            var tbPin = new TextBox()
            {
                Name = "tbPin",
                PasswordChar = '*',
                Left = marginLeft,
                Top = label2.Top + label2.Height + lineSpacing, // push textbox down
                Width = 400,
                Height = boxHeight,
                Font = bigFont,
                MaxLength = 6
            };
            var lblStatus = new Label()
            {
                Name = "lblStatus",
                Left = marginLeft,
                Top = tbPin.Top + tbPin.Height + lineSpacing,
                Width = width,
                ForeColor = Color.Red,
                Font = bigFont,
                AutoSize = true
            };
            var btnAssign = new Button()
            {
                Text = L("Привязать", "Assign"),
                Left = (this.Width - 180) / 2, // Center horizontally
                Top = lblStatus.Top + lblStatus.Height + lineSpacing,
                Width = 180,
                Height = 50,
                Font = bigFont
            };
            this.AcceptButton = btnAssign;

            this.Controls.Add(label1);
            this.Controls.Add(tbAssignCode);
            this.Controls.Add(label2);
            this.Controls.Add(tbPin);
            this.Controls.Add(lblStatus);
            this.Controls.Add(btnAssign);

            btnAssign.Click += async (s, e) =>
            {
                lblStatus.Text = "";
                // Strip dashes for validation and API
                string code = tbAssignCode.Text.Replace("-", "").Trim();
                string pin = tbPin.Text.Trim();

                // Input validation
                if (code.Length != 12 || !ulong.TryParse(code, out _))
                { lblStatus.Text = L("Код привязки должен состоять ровно из 12 цифр.", "Assign code must be exactly 12 digits."); return; }
                if (pin.Length != 6 || !ulong.TryParse(pin, out _))
                { lblStatus.Text = L("PIN должен состоять ровно из 6 цифр.", "PIN code must be exactly 6 digits."); return; }

                btnAssign.Enabled = false;
                lblStatus.Text = L("Привязываю ...", "Assigning ...");
                try
                {
                    using (var client = new HttpClient())
                    {
                        var body = new
                        {
                            assignCode = code,
                            pinCode = pin
                        };
                        var json = JsonSerializer.Serialize(body);
                        var content = new StringContent(json, Encoding.UTF8, "application/json");
                        var response = await client.PostAsync("https://guard.alexweb.app/api/device/assign", content);
                        if (!response.IsSuccessStatusCode)
                        {
                            lblStatus.Text = L("Ошибка сервера: ", "Server error: ") + response.StatusCode;
                            btnAssign.Enabled = true; return;
                        }
                        var respString = await response.Content.ReadAsStringAsync();
                        var doc = JsonDocument.Parse(respString).RootElement;
                        var deviceId = doc.GetProperty("deviceId").GetString() ?? string.Empty;
                        var version = doc.GetProperty("version").GetInt32();
                        AssignedState = new GuardState()
                        {
                            AssignCode = code,
                            PinCode = pin,
                            DeviceId = deviceId,
                            Version = 0,
                            RestrictedCategoryIds = new List<int>(),
                            Rules = new List<InstructionRule>(),
                            Presets = new List<Preset>(),
                            RestrictedCategories = new List<RestrictedCategory>(),
                            RulePresets = new List<string>(),
                            RuleUrls = new List<string>(),
                            SyncStatus = true,
                            LastUpdate = "",
                            PinStatus = 0,
                            Assigned = true,
                            UiLanguage = _language,
                            DeviceTimeZoneId = TimeZoneInfo.Local.Id,
                            DeviceUtcOffsetMinutes = (int)TimeZoneInfo.Local.GetUtcOffset(DateTime.Now).TotalMinutes
                        };

                        // Save state
                        GuardStateStorage.Save(AssignedState);
                        MessageBox.Show(L("Устройство успешно привязано. Подождите пару минут, пока Guard применит новые правила.",
                            "Device assigned successfully! Please allow a couple of minutes for the application to apply the new rules."),
                L("Привязка завершена", "Assignment Complete"),
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);

                        this.DialogResult = DialogResult.OK;
                        this.Close();
                    }
                }
                catch (Exception ex)
                {
                    lblStatus.Text = L("Ошибка: ", "Error: ") + ex.Message;
                    btnAssign.Enabled = true;
                }
            };

            this.Controls.AddRange(new Control[]
            {label1, tbAssignCode, label2, tbPin, btnAssign, lblStatus });
        }

        // --- ADDED: Format input as XXXX-XXXX-XXXX ---
        private string L(string russian, string english)
        {
            return UiLanguage.Text(_language, russian, english);
        }

    }
}
