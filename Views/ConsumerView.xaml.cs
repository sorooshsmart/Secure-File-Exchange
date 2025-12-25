using System.Windows;
using System.Windows.Controls;
using SecureFileExchange.ViewModels;

namespace SecureFileExchange.Views
{
    public partial class ConsumerView : UserControl
    {
        public ConsumerViewModel ViewModel => DataContext as ConsumerViewModel;

        public ConsumerView()
        {
            InitializeComponent();
        }

        private void DecryptButton_Click(object sender, RoutedEventArgs e)
        {
            // Transfer password from PasswordBox to ViewModel
            if (SharedPasswordBox != null)
            {
                ViewModel.SharedPassword = SharedPasswordBox.Password;
            }
        }
    }
}