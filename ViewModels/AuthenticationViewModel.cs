using System;
using System.Windows;
using System.Windows.Input;
using SecureFileExchange.Models;
using SecureFileExchange.Services;
using SecureFileExchange.Commands;

namespace SecureFileExchange.ViewModels
{
    public class AuthenticationViewModel : BaseViewModel
    {
        private string _username = string.Empty;
        private string _password = string.Empty;
        private string _statusMessage = string.Empty;
        private bool _isLoginMode = true;

        public string Username
        {
            get => _username;
            set => SetProperty(ref _username, value);
        }

        public string Password
        {
            get => _password;
            set => SetProperty(ref _password, value);
        }

        public string StatusMessage
        {
            get => _statusMessage;
            set => SetProperty(ref _statusMessage, value);
        }

        public bool IsLoginMode
        {
            get => _isLoginMode;
            set => SetProperty(ref _isLoginMode, value);
        }

        public ICommand RegisterCommand { get; }
        public ICommand LoginCommand { get; }
        public ICommand SwitchModeCommand { get; }

        public event EventHandler<bool>? AuthenticationCompleted;

        public AuthenticationViewModel()
        {
            RegisterCommand = new RelayCommand(Register);
            LoginCommand = new RelayCommand(Login);
            SwitchModeCommand = new RelayCommand(SwitchMode);
        }

        private void Register()
        {
            if (string.IsNullOrWhiteSpace(Username))
            {
                StatusMessage = "Username cannot be empty";
                return;
            }

            if (string.IsNullOrWhiteSpace(Password) || Password.Length < 4)
            {
                StatusMessage = "Password must be at least 4 characters";
                return;
            }

            try
            {
                UserIdentityManager.RegisterUser(Username, Password);

                StatusMessage = $"User '{Username}' registered successfully!";
                MessageBox.Show(
                    $"Registration successful!\n\n" +
                    $"Username: {Username}\n" +
                    $"Your public keys have been saved to:\n" +
                    $"C:\\SecureFileExchange\\Users\\{Username}\\{Username}_PublicKeys.txt\n\n" +
                    $"Share this file with others who want to send you encrypted files.",
                    "Success",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);

                // Auto-login after registration
                AutoLogin();
            }
            catch (Exception ex)
            {
                StatusMessage = $"Registration failed: {ex.Message}";
                MessageBox.Show($"Registration failed: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void Login()
        {
            if (string.IsNullOrWhiteSpace(Username))
            {
                StatusMessage = "Username cannot be empty";
                return;
            }

            if (string.IsNullOrWhiteSpace(Password))
            {
                StatusMessage = "Password cannot be empty";
                return;
            }

            try
            {
                var user = UserIdentityManager.LoginUser(Username, Password);

                if (user == null)
                {
                    StatusMessage = "Login failed";
                    return;
                }

                // Set session
                SessionContext.Instance.Login(user);

                StatusMessage = $"Logged in as: {Username}";
                MessageBox.Show($"Welcome back, {Username}!", "Success",
                    MessageBoxButton.OK, MessageBoxImage.Information);

                // Clear password
                Password = string.Empty;

                // Notify UI
                AuthenticationCompleted?.Invoke(this, true);
            }
            catch (Exception ex)
            {
                StatusMessage = $"Login failed: {ex.Message}";
                MessageBox.Show($"Login failed: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void AutoLogin()
        {
            try
            {
                var user = UserIdentityManager.LoginUser(Username, Password);

                if (user != null)
                {
                    SessionContext.Instance.Login(user);
                    Password = string.Empty;
                    AuthenticationCompleted?.Invoke(this, true);
                }
            }
            catch
            {
                // Silent fail, user can login manually
            }
        }

        private void SwitchMode()
        {
            IsLoginMode = !IsLoginMode;
            StatusMessage = string.Empty;
            Password = string.Empty;
        }
    }
}