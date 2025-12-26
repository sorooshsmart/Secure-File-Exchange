using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Input;
using System.Windows.Data;
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
        private string _externalPublicKeyPath = string.Empty;
        private string _externalSenderName = string.Empty;
        private string _sharedPassword = string.Empty;
        private string _sharedKeyFilePath = string.Empty;
        private KeyGenerationMethod _keyGenMethod = KeyGenerationMethod.Password;
        private SenderType _senderType = SenderType.Internal;
        private int _progress;
        private string _statusMessage = string.Empty;

        private ExternalPublicKeys? _loadedExternalKeys;

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

        public string ExternalPublicKeyPath
        {
            get => _externalPublicKeyPath;
            set => SetProperty(ref _externalPublicKeyPath, value);
        }

        public string ExternalSenderName
        {
            get => _externalSenderName;
            set => SetProperty(ref _externalSenderName, value);
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

        public SenderType SenderType
        {
            get => _senderType;
            set => SetProperty(ref _senderType, value);
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
        public ICommand BrowseExternalPublicKeyCommand { get; }
        public ICommand DecryptCommand { get; }
        public ICommand RefreshUsersCommand { get; }

        public ConsumerViewModel()
        {
            BrowseEncryptedFileCommand = new RelayCommand(BrowseEncryptedFile);
            BrowseKeyFileCommand = new RelayCommand(BrowseKeyFile);
            BrowseExternalPublicKeyCommand = new RelayCommand(BrowseExternalPublicKey);
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
                
                // Try to auto-detect sender type from file
                try
                {
                    byte[] encryptedData = File.ReadAllBytes(dialog.FileName);
                    var decryptor = new Decryptor();
                    RecipientMode mode = decryptor.GetRecipientMode(encryptedData);
                    
                    if (mode == RecipientMode.ExternalPublicKey)
                    {
                        SenderType = SenderType.External;
                        MessageBox.Show(
                            "This file was encrypted by an external user.\n" +
                            "Please load the sender's public keys file.",
                            "External Sender Detected",
                            MessageBoxButton.OK,
                            MessageBoxImage.Information);
                    }
                    else
                    {
                        SenderType = SenderType.Internal;
                    }
                }
                catch
                {
                    // Ignore errors, user will select manually
                }
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

        private void BrowseExternalPublicKey()
        {
            var dialog = new OpenFileDialog
            {
                Title = "Select Sender's Public Keys File",
                Filter = "Public Key Files (*.txt)|*.txt|All Files (*.*)|*.*",
                InitialDirectory = PublicKeyExchangeService.GetExportDirectory()
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    _loadedExternalKeys = PublicKeyExchangeService.ImportPublicKeys(dialog.FileName);
                    ExternalPublicKeyPath = dialog.FileName;
                    ExternalSenderName = _loadedExternalKeys.Username;
                    
                    MessageBox.Show(
                        $"External public keys loaded successfully!\n\n" +
                        $"Sender: {_loadedExternalKeys.Username}\n" +
                        $"Source: {Path.GetFileName(dialog.FileName)}",
                        "Success",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show(
                        $"Failed to load external public keys:\n{ex.Message}",
                        "Error",
                        MessageBoxButton.OK,
                        MessageBoxImage.Error);
                    
                    ExternalPublicKeyPath = string.Empty;
                    ExternalSenderName = string.Empty;
                    _loadedExternalKeys = null;
                }
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

                // Load encrypted file to determine method
                byte[] encryptedData = File.ReadAllBytes(EncryptedFilePath);
                Models.EncryptionMethod method = (Models.EncryptionMethod)encryptedData[0];

                Progress = 30;
                StatusMessage = "Preparing decryption...";

                RSAParameters? encryptionPrivateKey = currentUser.EncryptionPrivateKey;
                RSAParameters producerSigningPublicKey;
                byte[]? symmetricKey = null;

                // Load producer's signing public key based on sender type
                if (SenderType == SenderType.Internal)
                {
                    if (string.IsNullOrWhiteSpace(SelectedProducerUsername))
                    {
                        MessageBox.Show("Please select the producer user who encrypted this file", "Error",
                            MessageBoxButton.OK, MessageBoxImage.Warning);
                        Progress = 0;
                        return;
                    }

                    // Load internal producer's signing public key
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
                }
                else // External
                {
                    if (_loadedExternalKeys == null)
                    {
                        MessageBox.Show("Please load external sender's public keys", "Error",
                            MessageBoxButton.OK, MessageBoxImage.Warning);
                        Progress = 0;
                        return;
                    }

                    producerSigningPublicKey = _loadedExternalKeys.SigningPublicKey;
                }

                // Handle symmetric encryption key if needed
                if (method == Models.EncryptionMethod.Symmetric)
                {
                    // Symmetric method REQUIRES key from user
                    SymmetricAlgorithmType algoType = (SymmetricAlgorithmType)encryptedData[2];
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
                    string senderInfo = SenderType == SenderType.Internal 
                        ? SelectedProducerUsername 
                        : $"{ExternalSenderName} (External)";
                    
                    MessageBox.Show(
                        $"File decrypted and verified successfully!\n\n" +
                        $"Sender: {senderInfo}\n" +
                        $"Saved to: {result.OutputPath}",
                        "Success", 
                        MessageBoxButton.OK, 
                        MessageBoxImage.Information);
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

    public enum SenderType
    {
        Internal,
        External
    }

    // Converter for SenderType
    public class SenderTypeConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            if (value is SenderType senderType && parameter is string paramStr)
            {
                if (paramStr == "Internal")
                {
                    if (targetType == typeof(bool))
                        return senderType == SenderType.Internal;
                    else if (targetType == typeof(System.Windows.Visibility))
                        return senderType == SenderType.Internal ? System.Windows.Visibility.Visible : System.Windows.Visibility.Collapsed;
                }
                else if (paramStr == "External")
                {
                    if (targetType == typeof(bool))
                        return senderType == SenderType.External;
                    else if (targetType == typeof(System.Windows.Visibility))
                        return senderType == SenderType.External ? System.Windows.Visibility.Visible : System.Windows.Visibility.Collapsed;
                }
            }

            return targetType == typeof(bool) ? false : System.Windows.Visibility.Collapsed;
        }

        public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            if (value is bool boolValue && boolValue && parameter is string paramStr)
            {
                if (paramStr == "Internal")
                    return SenderType.Internal;
                else if (paramStr == "External")
                    return SenderType.External;
            }

            return SenderType.Internal;
        }
    }

    // Converter for String to Visibility
    public class StringToVisibilityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            if (value is string str && !string.IsNullOrWhiteSpace(str))
                return System.Windows.Visibility.Visible;

            return System.Windows.Visibility.Collapsed;
        }

        public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}