using System.Windows;

namespace ByteGuard.Dialogs
{
    public partial class PasswordDialog : Window
    {
        public string Password { get; private set; } = string.Empty;

        public PasswordDialog()
        {
            InitializeComponent();
            TxtPassword.Focus();
        }

        private void BtnConfirm_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(TxtPassword.Password))
            {
                MessageBox.Show("La chiave non può essere vuota.", "Attenzione", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            Password = TxtPassword.Password;
            DialogResult = true;
            Close();
        }

        private void BtnCancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }
    }
}
