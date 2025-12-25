using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using SecureFileExchange.Models;

namespace SecureFileExchange
{
    public partial class MainWindow : Window, INotifyPropertyChanged
    {
        private bool _isAuthenticated;
        private string _currentUserDisplay = "Not logged in";

        public bool IsAuthenticated
        {
            get => _isAuthenticated;
            set
            {
                _isAuthenticated = value;
                OnPropertyChanged();
                UpdateUserDisplay();
            }
        }

        public string CurrentUserDisplay
        {
            get => _currentUserDisplay;
            set
            {
                _currentUserDisplay = value;
                OnPropertyChanged();
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        public MainWindow()
        {
            InitializeComponent();
            DataContext = this;

            // Subscribe to tab changes
            AuthTab.Checked += (s, e) => ShowAuthView();
            ProducerTab.Checked += (s, e) => ShowProducerView();
            ConsumerTab.Checked += (s, e) => ShowConsumerView();

            // Subscribe to authentication completed event after window is loaded
            this.Loaded += MainWindow_Loaded;
        }

        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            // Now all controls are initialized
            if (AuthenticationView != null && AuthenticationView.ViewModel != null)
            {
                AuthenticationView.ViewModel.AuthenticationCompleted += OnAuthenticationCompleted;
            }
            
            UpdateUserDisplay();
        }

        private void OnAuthenticationCompleted(object? sender, bool success)
        {
            if (success)
            {
                IsAuthenticated = true;
                UpdateUserDisplay();
                MessageBox.Show("You can now use Producer and Consumer tabs", "Info",
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void UpdateUserDisplay()
        {
            var session = SessionContext.Instance;
            if (session.IsAuthenticated && session.CurrentUser != null)
            {
                CurrentUserDisplay = $"Logged in as: {session.CurrentUser.Username}";
            }
            else
            {
                CurrentUserDisplay = "Not logged in";
            }
        }

        private void LogoutButton_Click(object sender, RoutedEventArgs e)
        {
            var result = MessageBox.Show(
                "Are you sure you want to logout?",
                "Confirm Logout",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (result == MessageBoxResult.Yes)
            {
                SessionContext.Instance.Logout();
                IsAuthenticated = false;
                UpdateUserDisplay();
                
                // Switch to Auth tab
                AuthTab.IsChecked = true;
                ShowAuthView();
                
                MessageBox.Show("Logged out successfully", "Success",
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void ShowAuthView()
        {
            if (AuthenticationView != null) AuthenticationView.Visibility = Visibility.Visible;
            if (ProducerView != null) ProducerView.Visibility = Visibility.Collapsed;
            if (ConsumerView != null) ConsumerView.Visibility = Visibility.Collapsed;
        }

        private void ShowProducerView()
        {
            if (!IsAuthenticated)
            {
                if (AuthTab != null) AuthTab.IsChecked = true;
                MessageBox.Show("Please login first", "Warning",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (AuthenticationView != null) AuthenticationView.Visibility = Visibility.Collapsed;
            if (ProducerView != null) ProducerView.Visibility = Visibility.Visible;
            if (ConsumerView != null) ConsumerView.Visibility = Visibility.Collapsed;
        }

        private void ShowConsumerView()
        {
            if (!IsAuthenticated)
            {
                if (AuthTab != null) AuthTab.IsChecked = true;
                MessageBox.Show("Please login first", "Warning",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (AuthenticationView != null) AuthenticationView.Visibility = Visibility.Collapsed;
            if (ProducerView != null) ProducerView.Visibility = Visibility.Collapsed;
            if (ConsumerView != null) ConsumerView.Visibility = Visibility.Visible;
        }
    }
}