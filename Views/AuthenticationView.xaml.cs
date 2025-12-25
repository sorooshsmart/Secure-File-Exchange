using System.Windows;
using System.Windows.Controls;
using SecureFileExchange.ViewModels;

namespace SecureFileExchange.Views
{
    public partial class AuthenticationView : UserControl
    {
        public AuthenticationViewModel? ViewModel => DataContext as AuthenticationViewModel;

        public AuthenticationView()
        {
            InitializeComponent();
        }

        private void RegisterButton_Click(object sender, RoutedEventArgs e)
        {
            if (ViewModel != null)
            {
                ViewModel.Password = PasswordBox.Password;
            }
        }

        private void LoginButton_Click(object sender, RoutedEventArgs e)
        {
            if (ViewModel != null)
            {
                ViewModel.Password = PasswordBox.Password;
            }
        }
    }
}