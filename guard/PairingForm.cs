using System;
using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;

namespace Guard
{
    public sealed class PairingForm : Form
    {
        private readonly DevicePairing _pairing;
        private readonly string _parentCabinetUrls;
        private readonly TextBox _parentEmail;

        public PairingForm(DevicePairing pairing, string parentCabinetUrls)
        {
            _pairing = pairing;
            _parentCabinetUrls = parentCabinetUrls ?? "";

            Text = "Привязка детского компьютера / Pair child computer";
            StartPosition = FormStartPosition.CenterScreen;
            AutoScaleMode = AutoScaleMode.Dpi;
            ClientSize = new Size(680, 560);
            MinimumSize = new Size(620, 520);
            SizeGripStyle = SizeGripStyle.Show;
            MaximizeBox = false;
            MinimizeBox = false;

            var root = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                Padding = new Padding(24),
                ColumnCount = 1,
                RowCount = 10,
                AutoScroll = true
            };
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            var title = new Label
            {
                Text = "Привязать этот детский компьютер",
                Dock = DockStyle.Top,
                AutoSize = true,
                Font = new Font("Segoe UI", 18, FontStyle.Bold),
                TextAlign = ContentAlignment.MiddleLeft
            };

            var intro = new Label
            {
                Text = "Открой адрес родительского кабинета на компьютере родителя и введи этот код.",
                Dock = DockStyle.Top,
                AutoSize = true,
                Margin = new Padding(0, 8, 0, 12),
                Font = new Font("Segoe UI", 10.5f, FontStyle.Regular)
            };

            var code = new TextBox
            {
                Text = PairingCodeService.FormatCode(pairing.Code),
                Dock = DockStyle.Top,
                ReadOnly = true,
                TextAlign = HorizontalAlignment.Center,
                Font = new Font("Consolas", 34, FontStyle.Bold),
                BorderStyle = BorderStyle.FixedSingle,
                Margin = new Padding(0, 0, 0, 8)
            };

            var codeHint = new Label
            {
                Text = "Формат кода: ABCD-EFGH. Код действует примерно 15 минут.",
                Dock = DockStyle.Top,
                AutoSize = true,
                Font = new Font("Segoe UI", 9.5f, FontStyle.Regular),
                ForeColor = SystemColors.GrayText,
                Margin = new Padding(0, 0, 0, 12)
            };

            var urls = new TextBox
            {
                Text = _parentCabinetUrls,
                Dock = DockStyle.Fill,
                Font = new Font("Segoe UI", 10, FontStyle.Regular),
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                MinimumSize = new Size(0, 110)
            };

            var expires = new Label
            {
                Text = pairing.ExpiresAtUtc.HasValue
                    ? "Код действует до " + pairing.ExpiresAtUtc.Value.ToLocalTime().ToString("HH:mm")
                    : "Ожидаю родителя",
                Dock = DockStyle.Top,
                AutoSize = true,
                Font = new Font("Segoe UI", 10.5f, FontStyle.Regular),
                Margin = new Padding(0, 12, 0, 8)
            };

            var emailLabel = new Label
            {
                Text = "Отправить данные для настройки на почту родителя",
                Dock = DockStyle.Top,
                AutoSize = true,
                Font = new Font("Segoe UI", 10.5f, FontStyle.Bold),
                Margin = new Padding(0, 4, 0, 4)
            };

            _parentEmail = new TextBox
            {
                Dock = DockStyle.Top,
                Font = new Font("Segoe UI", 10.5f, FontStyle.Regular),
                Margin = new Padding(0, 0, 0, 8)
            };

            var safety = new Label
            {
                Text = "Черновик письма содержит только адрес кабинета и код привязки. Родительский пароль задаётся в браузере и по почте не отправляется.",
                Dock = DockStyle.Top,
                AutoSize = true,
                Font = new Font("Segoe UI", 9.25f, FontStyle.Regular),
                ForeColor = SystemColors.GrayText,
                Margin = new Padding(0, 0, 0, 10)
            };

            var buttons = new FlowLayoutPanel
            {
                Dock = DockStyle.Bottom,
                FlowDirection = FlowDirection.RightToLeft,
                WrapContents = true,
                AutoSize = true
            };

            var close = Button("Закрыть", 120);
            close.Click += (s, e) => Close();

            var email = Button("Открыть письмо", 170);
            email.Click += (s, e) => OpenEmailDraft();

            var copyAll = Button("Копировать всё", 150);
            copyAll.Click += (s, e) => CopySetupText();

            var copyCode = Button("Копировать код", 130);
            copyCode.Click += (s, e) => Clipboard.SetText(PairingCodeService.FormatCode(_pairing.Code));

            buttons.Controls.Add(close);
            buttons.Controls.Add(email);
            buttons.Controls.Add(copyAll);
            buttons.Controls.Add(copyCode);

            root.Controls.Add(title, 0, 0);
            root.Controls.Add(intro, 0, 1);
            root.Controls.Add(code, 0, 2);
            root.Controls.Add(codeHint, 0, 3);
            root.Controls.Add(urls, 0, 4);
            root.Controls.Add(expires, 0, 5);
            root.Controls.Add(emailLabel, 0, 6);
            root.Controls.Add(_parentEmail, 0, 7);
            root.Controls.Add(safety, 0, 8);
            root.Controls.Add(buttons, 0, 9);

            Controls.Add(root);
            AcceptButton = email;
            CancelButton = close;
        }

        private static Button Button(string text, int width)
        {
            return new Button
            {
                Text = text,
                Width = width,
                Height = 36,
                Margin = new Padding(6),
                Font = new Font("Segoe UI", 10, FontStyle.Regular)
            };
        }

        private void OpenEmailDraft()
        {
            var email = _parentEmail.Text.Trim();
            if (!PairingEmailBuilder.IsLikelyEmail(email))
            {
                MessageBox.Show("Сначала введи почту родителя.", "Почта родителя", MessageBoxButtons.OK, MessageBoxIcon.Information);
                _parentEmail.Focus();
                return;
            }

            var mailto = PairingEmailBuilder.BuildMailToUri(email, _pairing, _parentCabinetUrls);
            try
            {
                Process.Start(new ProcessStartInfo(mailto) { UseShellExecute = true });
            }
            catch
            {
                CopySetupText();
                MessageBox.Show("Не удалось открыть почтовую программу. Текст для настройки скопирован в буфер обмена.", "Письмо родителю", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private void CopySetupText()
        {
            Clipboard.SetText(PairingEmailBuilder.BuildBody(_pairing, _parentCabinetUrls));
        }
    }
}
