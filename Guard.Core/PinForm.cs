using System.Drawing;
using System.Windows.Forms;

namespace Guard
{
    public partial class PinForm : Form
    {
        public string EnteredPin { get; private set; } = "";

        public PinForm(string promptText, Icon? appIcon)
        {
            InitializeComponent();

            if (appIcon!= null) this.Icon = appIcon;
            // 1.5x scale
            this.Width = 480;    // was 320
            this.Height = 240;   // was 160 or 200
            this.Text = "Enter PIN";
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.StartPosition = FormStartPosition.CenterScreen; // Centered!
            this.MaximizeBox = false;
            this.MinimizeBox = false;

            // Use a larger font
            var bigFont = new Font("Segoe UI", 15F, FontStyle.Regular, GraphicsUnit.Point);

            var layoutPanel = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 3,
                Padding = new Padding(18),
            };

            layoutPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 40F));
            layoutPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 30F));
            layoutPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 30F));

            // Large prompt label
            var lbl = new Label()
            {
                Text = promptText,
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleCenter,
                AutoSize = true,
                Font = bigFont
            };

            // PIN textbox, bigger and centered
            var box = new TextBox()
            {
                Width = 270,
                Font = bigFont,
                PasswordChar = '*',
                Anchor = AnchorStyles.None,
                TextAlign = HorizontalAlignment.Center
            };

            // Big OK button
            var ok = new Button()
            {
                Text = "OK",
                Width = 110,
                Height = 40,
                DialogResult = DialogResult.OK,
                Anchor = AnchorStyles.None,
                Font = bigFont
            };

            ok.Click += (s, e) => {
                this.EnteredPin = box.Text;
                this.Close();
            };

            layoutPanel.Controls.Add(lbl, 0, 0);
            layoutPanel.Controls.Add(box, 0, 1);
            layoutPanel.Controls.Add(ok, 0, 2);

            this.Controls.Add(layoutPanel);
            this.AcceptButton = ok;
        }
    }
}
