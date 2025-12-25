using System.Windows;
using System.Windows.Controls;
using SecureFileExchange.ViewModels;

namespace SecureFileExchange.Views
{
    public partial class ProducerView : UserControl
    {
        public ProducerViewModel ViewModel => DataContext as ProducerViewModel;

        public ProducerView()
        {
            InitializeComponent();
        }

        private void EncryptButton_Click(object sender, RoutedEventArgs e)
        {
            // Transfer password from PasswordBox to ViewModel
            if (SharedPasswordBox != null)
            {
                ViewModel.SharedPassword = SharedPasswordBox.Password;
            }
        }
    }
}