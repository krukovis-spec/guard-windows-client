using System.Drawing;
using System.Windows.Forms;

namespace Guard
{
    public partial class InformationForm : Form
    {
        public InformationForm(string title, string message, MessageBoxIcon iconType = MessageBoxIcon.Information)
        {
            InitializeComponent();

            this.Text = title;
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.StartPosition = FormStartPosition.CenterScreen;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.ClientSize = new Size(420, 160);

            // Create and configure the icon PictureBox
            PictureBox picBox = new PictureBox();
            picBox.Location = new Point(20, 25);
            picBox.Size = new Size(32, 32);
            Icon? displayIcon = SystemIcons.Information;
            if (iconType == MessageBoxIcon.Error) displayIcon = SystemIcons.Error;
            if (iconType == MessageBoxIcon.Warning) displayIcon = SystemIcons.Warning;
            if (displayIcon != null) picBox.Image = displayIcon.ToBitmap();

            // Create and configure the Message Label
            Label lblMessage = new Label();
            lblMessage.Text = message;
            lblMessage.Location = new Point(65, 25);
            lblMessage.Size = new Size(330, 80);

            // Create and configure the OK Button
            Button btnOk = new Button();
            btnOk.Text = "OK";
            btnOk.DialogResult = DialogResult.OK;
            btnOk.Size = new Size(85, 30);
            btnOk.Location = new Point(this.ClientSize.Width - btnOk.Width - 15, this.ClientSize.Height - btnOk.Height - 15);
            btnOk.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;

            this.Controls.Add(picBox);
            this.Controls.Add(lblMessage);
            this.Controls.Add(btnOk);
            this.AcceptButton = btnOk;
        }
    }
}