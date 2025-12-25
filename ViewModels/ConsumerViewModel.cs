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
    public class ConsumerViewModel : BaseViewModel
    {
        private string _encryptedFilePath = string.Empty;
        private string _selectedProducerUsername = string.Empty;
        private string _sharedPassword = string.Empty;
        private string _sharedKeyFilePath = string.Empty;
        private KeyGenerationMethod _keyGenMethod = KeyGenerationMethod.Password;
        private int _progress;
        private string _statusMessage = string.Empty;

        public string EncryptedFilePath
        {
            get => _encryptedFilePath;
            set => SetProperty(ref _encryptedFilePath, value);
        }

        public string SelectedProducerUsername
        {
            get => _selectedProducerUsername;
            set => SetProperty(ref _selectedProducerUsername, value);
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

        public ICommand BrowseEncryptedFileCommand { get; }
        public ICommand BrowseKeyFileCommand { get; }
        public ICommand DecryptCommand { get; }
        public ICommand RefreshUsersCommand { get; }

        public ConsumerViewModel()
        {
            BrowseEncryptedFileCommand = new RelayCommand(BrowseEncryptedFile);
            BrowseKeyFileCommand = new RelayCommand(BrowseKeyFile);
            DecryptCommand = new RelayCommand(Decrypt);
            RefreshUsersCommand = new RelayCommand(RefreshUsers);

            RefreshUsers();
        }

        private void RefreshUsers()
        {
            AvailableUsers.Clear();
            var users = UserIdentityManager.GetAllUsernames();
            foreach (var user in users)
            {
                // Don't show current user as producer option
                if (user != SessionContext.Instance.CurrentUser?.Username)
                {
                    AvailableUsers.Add(user);
                }
            }
        }

        private void BrowseEncryptedFile()
        {
            var dialog = new OpenFileDialog
            {
                Title = "Select Encrypted File",
                Filter = "Encrypted Files (*.enc)|*.enc|All Files (*.*)|*.*"
            };

            if (dialog.ShowDialog() == true)
            {
                EncryptedFilePath = dialog.FileName;
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

        private void Decrypt()
        {
            if (string.IsNullOrWhiteSpace(EncryptedFilePath))
            {
                MessageBox.Show("Please select an encrypted file", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (string.IsNullOrWhiteSpace(SelectedProducerUsername))
            {
                MessageBox.Show("Please select the producer user who encrypted this file", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            try
            {
                Progress = 10;
                StatusMessage = "Loading keys...";

                // Get current user (Consumer)
                var currentUser = SessionContext.Instance.CurrentUser;
                if (currentUser?.EncryptionPrivateKey == null)
                {
                    MessageBox.Show("Please login first", "Error",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                    Progress = 0;
                    return;
                }

                // Load producer's signing public key
                RSAParameters producerSigningPublicKey;
                try
                {
                    var producerIdentity = UserIdentityManager.LoadPublicKeysOnly(SelectedProducerUsername);
                    producerSigningPublicKey = producerIdentity.SigningPublicKey;
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Failed to load producer public key: {ex.Message}", "Error",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                    Progress = 0;
                    return;
                }

                // Load encrypted file to determine method
                byte[] encryptedData = File.ReadAllBytes(EncryptedFilePath);
                Models.EncryptionMethod method = (Models.EncryptionMethod)encryptedData[0];

                Progress = 30;
                StatusMessage = "Preparing decryption...";

                RSAParameters? encryptionPrivateKey = currentUser.EncryptionPrivateKey;
                byte[]? symmetricKey = null;

                // Handle different encryption methods
                if (method == Models.EncryptionMethod.SecureEnvelope || method == Models.EncryptionMethod.RSADirect)
                {
                    // These methods use consumer's private key (already loaded)
                    // No additional input needed from user
                }
                else if (method == Models.EncryptionMethod.Symmetric)
                {
                    // Symmetric method REQUIRES key from user
                    // Get symmetric key
                    SymmetricAlgorithmType algoType = (SymmetricAlgorithmType)encryptedData[1];
                    int keyLength = algoType == SymmetricAlgorithmType.AES ? 32 :
                                   algoType == SymmetricAlgorithmType.TripleDES ? 24 : 8;

                    if (KeyGenMethod == KeyGenerationMethod.Password)
                    {
                        if (string.IsNullOrWhiteSpace(SharedPassword))
                        {
                            MessageBox.Show("This file was encrypted with Symmetric method.\nPlease enter the shared password.", "Password Required",
                                MessageBoxButton.OK, MessageBoxImage.Warning);
                            Progress = 0;
                            return;
                        }

                        symmetricKey = CryptoUtils.DeriveKeyFromPassword(SharedPassword, keyLength);
                    }
                    else
                    {
                        if (string.IsNullOrWhiteSpace(SharedKeyFilePath))
                        {
                            MessageBox.Show("This file was encrypted with Symmetric method.\nPlease select the key file.", "Key File Required",
                                MessageBoxButton.OK, MessageBoxImage.Warning);
                            Progress = 0;
                            return;
                        }

                        symmetricKey = CryptoUtils.DeriveKeyFromFile(SharedKeyFilePath, keyLength);
                    }
                }

                Progress = 60;
                StatusMessage = "Decrypting...";

                // Decrypt file
                var decryptor = new Decryptor();
                var result = decryptor.DecryptFile(
                    EncryptedFilePath,
                    producerSigningPublicKey,
                    encryptionPrivateKey,
                    symmetricKey
                );

                Progress = 100;

                if (result.Success)
                {
                    StatusMessage = "Decryption successful!";
                    MessageBox.Show($"File decrypted and verified successfully!\nSaved to: {result.OutputPath}",
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
                MessageBox.Show($"Decryption failed: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
}