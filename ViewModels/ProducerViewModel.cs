using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Input;
using Microsoft.Win32;
using SecureFileExchange.Commands;
using SecureFileExchange.Cryptography;
using SecureFileExchange.Models;
using SecureFileExchange.Services;

namespace SecureFileExchange.ViewModels
{
    public class ProducerViewModel : BaseViewModel
    {
        private string _selectedFilePath = string.Empty;
        private string _selectedConsumerUsername = string.Empty;
        private string _sharedPassword = string.Empty;
        private string _sharedKeyFilePath = string.Empty;
        private Models.EncryptionMethod _selectedMethod = Models.EncryptionMethod.SecureEnvelope;
        private SymmetricAlgorithmType _selectedAlgorithm = SymmetricAlgorithmType.AES;
        private Models.EncryptionMode _selectedMode = Models.EncryptionMode.CBC;
        private MACAlgorithmType _selectedMACAlgorithm = MACAlgorithmType.HMACSHA256;
        private KeyGenerationMethod _keyGenMethod = KeyGenerationMethod.Password;
        private int _progress;
        private string _statusMessage = string.Empty;

        public string SelectedFilePath
        {
            get => _selectedFilePath;
            set => SetProperty(ref _selectedFilePath, value);
        }

        public string SelectedConsumerUsername
        {
            get => _selectedConsumerUsername;
            set => SetProperty(ref _selectedConsumerUsername, value);
        }

        public ObservableCollection<string> AvailableUsers { get; } = new ObservableCollection<string>();

        public string SharedPassword
        {
            get => _sharedPassword;
            set => SetProperty(ref _sharedPassword, value);
        }

        public string SharedKeyFilePath
        {
            get => _sharedKeyFilePath;
            set => SetProperty(ref _sharedKeyFilePath, value);
        }

        public Models.EncryptionMethod SelectedMethod
        {
            get => _selectedMethod;
            set => SetProperty(ref _selectedMethod, value);
        }

        public SymmetricAlgorithmType SelectedAlgorithm
        {
            get => _selectedAlgorithm;
            set => SetProperty(ref _selectedAlgorithm, value);
        }

        public Models.EncryptionMode SelectedMode
        {
            get => _selectedMode;
            set => SetProperty(ref _selectedMode, value);
        }

        public MACAlgorithmType SelectedMACAlgorithm
        {
            get => _selectedMACAlgorithm;
            set => SetProperty(ref _selectedMACAlgorithm, value);
        }

        public KeyGenerationMethod KeyGenMethod
        {
            get => _keyGenMethod;
            set => SetProperty(ref _keyGenMethod, value);
        }

        public int Progress
        {
            get => _progress;
            set => SetProperty(ref _progress, value);
        }

        public string StatusMessage
        {
            get => _statusMessage;
            set => SetProperty(ref _statusMessage, value);
        }

        public ICommand BrowseFileCommand { get; }
        public ICommand BrowseKeyFileCommand { get; }
        public ICommand EncryptCommand { get; }
        public ICommand RefreshUsersCommand { get; }

        public ProducerViewModel()
        {
            BrowseFileCommand = new RelayCommand(BrowseFile);
            BrowseKeyFileCommand = new RelayCommand(BrowseKeyFile);
            EncryptCommand = new RelayCommand(Encrypt);
            RefreshUsersCommand = new RelayCommand(RefreshUsers);

            RefreshUsers();
        }

        private void RefreshUsers()
        {
            AvailableUsers.Clear();
            var users = UserIdentityManager.GetAllUsernames();
            foreach (var user in users)
            {
                // Don't show current user as consumer option
                if (user != SessionContext.Instance.CurrentUser?.Username)
                {
                    AvailableUsers.Add(user);
                }
            }
        }

        private void BrowseFile()
        {
            var dialog = new OpenFileDialog
            {
                Title = "Select File to Encrypt",
                Filter = "All Files (*.*)|*.*"
            };

            if (dialog.ShowDialog() == true)
            {
                SelectedFilePath = dialog.FileName;
            }
        }

        private void BrowseKeyFile()
        {
            var dialog = new OpenFileDialog
            {
                Title = "Select Key File",
                Filter = "All Files (*.*)|*.*"
            };

            if (dialog.ShowDialog() == true)
            {
                SharedKeyFilePath = dialog.FileName;
            }
        }

        private void Encrypt()
        {
            if (string.IsNullOrWhiteSpace(SelectedFilePath))
            {
                MessageBox.Show("Please select a file to encrypt", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            try
            {
                Progress = 10;
                StatusMessage = "Loading keys...";

                // Get current user (Producer)
                var currentUser = SessionContext.Instance.CurrentUser;
                if (currentUser?.SigningPrivateKey == null)
                {
                    MessageBox.Show("Please login first", "Error",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                    Progress = 0;
                    return;
                }

                Progress = 30;
                StatusMessage = "Creating package...";

                // Create encryptor
                var encryptor = new Encryptor(SelectedMACAlgorithm, SelectedAlgorithm);

                RSAParameters? consumerPublicKey = null;
                byte[]? symmetricKey = null;

                // Handle different encryption methods
                if (SelectedMethod == Models.EncryptionMethod.SecureEnvelope || SelectedMethod == Models.EncryptionMethod.RSADirect)
                {
                    if (string.IsNullOrWhiteSpace(SelectedConsumerUsername))
                    {
                        MessageBox.Show("Please select a consumer user", "Error",
                            MessageBoxButton.OK, MessageBoxImage.Warning);
                        Progress = 0;
                        return;
                    }

                    // Load consumer's public key
                    try
                    {
                        var consumerIdentity = UserIdentityManager.LoadPublicKeysOnly(SelectedConsumerUsername);
                        consumerPublicKey = consumerIdentity.EncryptionPublicKey;
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"Failed to load consumer public key: {ex.Message}", "Error",
                            MessageBoxButton.OK, MessageBoxImage.Error);
                        Progress = 0;
                        return;
                    }
                }
                else if (SelectedMethod == Models.EncryptionMethod.Symmetric)
                {
                    if (KeyGenMethod == KeyGenerationMethod.Password)
                    {
                        if (string.IsNullOrWhiteSpace(SharedPassword))
                        {
                            MessageBox.Show("Please enter shared password", "Error",
                                MessageBoxButton.OK, MessageBoxImage.Warning);
                            Progress = 0;
                            return;
                        }

                        int keyLength = SelectedAlgorithm == SymmetricAlgorithmType.AES ? 32 :
                                       SelectedAlgorithm == SymmetricAlgorithmType.TripleDES ? 24 : 8;
                        symmetricKey = CryptoUtils.DeriveKeyFromPassword(SharedPassword, keyLength);
                    }
                    else
                    {
                        if (string.IsNullOrWhiteSpace(SharedKeyFilePath))
                        {
                            MessageBox.Show("Please select key file", "Error",
                                MessageBoxButton.OK, MessageBoxImage.Warning);
                            Progress = 0;
                            return;
                        }

                        int keyLength = SelectedAlgorithm == SymmetricAlgorithmType.AES ? 32 :
                                       SelectedAlgorithm == SymmetricAlgorithmType.TripleDES ? 24 : 8;
                        symmetricKey = CryptoUtils.DeriveKeyFromFile(SharedKeyFilePath, keyLength);
                    }
                }

                Progress = 60;
                StatusMessage = "Encrypting...";

                // Encrypt file
                var result = encryptor.EncryptFile(
                    SelectedFilePath,
                    SelectedMethod,
                    currentUser.SigningPrivateKey.Value,
                    consumerPublicKey,
                    symmetricKey,
                    SelectedMode
                );

                Progress = 100;

                if (result.Success)
                {
                    StatusMessage = "Encryption successful!";
                    MessageBox.Show($"File encrypted successfully!\nSaved to: {result.OutputPath}",
                        "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else
                {
                    StatusMessage = result.Message;
                    MessageBox.Show(result.Message, "Error",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                }

                Progress = 0;
            }
            catch (Exception ex)
            {
                Progress = 0;
                StatusMessage = $"Error: {ex.Message}";
                MessageBox.Show($"Encryption failed: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
}