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
    public class ProducerViewModel : BaseViewModel
    {
        private string _selectedFilePath = string.Empty;
        private string _selectedConsumerUsername = string.Empty;
        private string _externalPublicKeyPath = string.Empty;
        private string _externalRecipientName = string.Empty;
        private string _sharedPassword = string.Empty;
        private string _sharedKeyFilePath = string.Empty;
        private Models.EncryptionMethod _selectedMethod = Models.EncryptionMethod.SecureEnvelope;
        private SymmetricAlgorithmType _selectedAlgorithm = SymmetricAlgorithmType.AES;
        private Models.EncryptionMode _selectedMode = Models.EncryptionMode.CBC;
        private MACAlgorithmType _selectedMACAlgorithm = MACAlgorithmType.HMACSHA256;
        private KeyGenerationMethod _keyGenMethod = KeyGenerationMethod.Password;
        private RecipientType _recipientType = RecipientType.Internal;
        private RSAEncryptionMode _rsaEncryptionMode = RSAEncryptionMode.WithSignature;
        private int _progress;
        private string _statusMessage = string.Empty;

        private ExternalPublicKeys? _loadedExternalKeys;

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

        public string ExternalPublicKeyPath
        {
            get => _externalPublicKeyPath;
            set => SetProperty(ref _externalPublicKeyPath, value);
        }

        public string ExternalRecipientName
        {
            get => _externalRecipientName;
            set => SetProperty(ref _externalRecipientName, value);
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

        public RecipientType RecipientType
        {
            get => _recipientType;
            set => SetProperty(ref _recipientType, value);
        }

        public RSAEncryptionMode RSAEncryptionMode
        {
            get => _rsaEncryptionMode;
            set => SetProperty(ref _rsaEncryptionMode, value);
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
        public ICommand BrowseExternalPublicKeyCommand { get; }
        public ICommand EncryptCommand { get; }
        public ICommand RefreshUsersCommand { get; }
        public ICommand ExportMyPublicKeysCommand { get; }

        public ProducerViewModel()
        {
            BrowseFileCommand = new RelayCommand(BrowseFile);
            BrowseKeyFileCommand = new RelayCommand(BrowseKeyFile);
            BrowseExternalPublicKeyCommand = new RelayCommand(BrowseExternalPublicKey);
            EncryptCommand = new RelayCommand(Encrypt);
            RefreshUsersCommand = new RelayCommand(RefreshUsers);
            ExportMyPublicKeysCommand = new RelayCommand(ExportMyPublicKeys);

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

        private void BrowseExternalPublicKey()
        {
            var dialog = new OpenFileDialog
            {
                Title = "Select External User's Public Keys File",
                Filter = "Public Key Files (*.txt)|*.txt|All Files (*.*)|*.*",
                InitialDirectory = PublicKeyExchangeService.GetExportDirectory()
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    _loadedExternalKeys = PublicKeyExchangeService.ImportPublicKeys(dialog.FileName);
                    ExternalPublicKeyPath = dialog.FileName;
                    ExternalRecipientName = _loadedExternalKeys.Username;

                    MessageBox.Show(
                        $"External public keys loaded successfully!\n\n" +
                        $"User: {_loadedExternalKeys.Username}\n" +
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
                    ExternalRecipientName = string.Empty;
                    _loadedExternalKeys = null;
                }
            }
        }

        private void ExportMyPublicKeys()
        {
            var currentUser = SessionContext.Instance.CurrentUser;
            if (currentUser == null)
            {
                MessageBox.Show("Please login first", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            try
            {
                string exportPath = PublicKeyExchangeService.ExportPublicKeys(currentUser);

                MessageBox.Show(
                    $"Your public keys have been exported successfully!\n\n" +
                    $"File: {Path.GetFileName(exportPath)}\n" +
                    $"Location: {Path.GetDirectoryName(exportPath)}\n\n" +
                    $"Share this file with others who want to send you encrypted files.",
                    "Export Successful",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Failed to export public keys:\n{ex.Message}",
                    "Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
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
                RecipientMode recipientMode = RecipientMode.InternalUser;

                // Handle different encryption methods
                if (SelectedMethod == Models.EncryptionMethod.SecureEnvelope ||
                    SelectedMethod == Models.EncryptionMethod.RSADirect)
                {
                    // Determine recipient type
                    if (RecipientType == RecipientType.Internal)
                    {
                        if (string.IsNullOrWhiteSpace(SelectedConsumerUsername))
                        {
                            MessageBox.Show("Please select a consumer user", "Error",
                                MessageBoxButton.OK, MessageBoxImage.Warning);
                            Progress = 0;
                            return;
                        }

                        // Load internal consumer's public key
                        try
                        {
                            var consumerIdentity = UserIdentityManager.LoadPublicKeysOnly(SelectedConsumerUsername);
                            consumerPublicKey = consumerIdentity.EncryptionPublicKey;
                            recipientMode = RecipientMode.InternalUser;
                        }
                        catch (Exception ex)
                        {
                            MessageBox.Show($"Failed to load consumer public key: {ex.Message}", "Error",
                                MessageBoxButton.OK, MessageBoxImage.Error);
                            Progress = 0;
                            return;
                        }
                    }
                    else // External
                    {
                        if (_loadedExternalKeys == null)
                        {
                            MessageBox.Show("Please load external user's public keys", "Error",
                                MessageBoxButton.OK, MessageBoxImage.Warning);
                            Progress = 0;
                            return;
                        }

                        consumerPublicKey = _loadedExternalKeys.EncryptionPublicKey;
                        recipientMode = RecipientMode.ExternalPublicKey;
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
                    SelectedMode,
                    recipientMode,
                    RSAEncryptionMode  // Pass RSA mode
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

    public enum RecipientType
    {
        Internal,
        External
    }

    // Converter for RecipientType
    public class RecipientTypeConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            if (value is RecipientType recipientType && parameter is string paramStr)
            {
                if (paramStr == "Internal")
                {
                    if (targetType == typeof(bool))
                        return recipientType == RecipientType.Internal;
                    else if (targetType == typeof(System.Windows.Visibility))
                        return recipientType == RecipientType.Internal ? System.Windows.Visibility.Visible : System.Windows.Visibility.Collapsed;
                }
                else if (paramStr == "External")
                {
                    if (targetType == typeof(bool))
                        return recipientType == RecipientType.External;
                    else if (targetType == typeof(System.Windows.Visibility))
                        return recipientType == RecipientType.External ? System.Windows.Visibility.Visible : System.Windows.Visibility.Collapsed;
                }
            }

            return targetType == typeof(bool) ? false : System.Windows.Visibility.Collapsed;
        }

        public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            if (value is bool boolValue && boolValue && parameter is string paramStr)
            {
                if (paramStr == "Internal")
                    return RecipientType.Internal;
                else if (paramStr == "External")
                    return RecipientType.External;
            }

            return RecipientType.Internal;
        }
    }

    // Converter for RSAEncryptionMode (NEW)
    public class RSAEncryptionModeConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            if (value is RSAEncryptionMode mode && parameter is string paramStr)
            {
                if (paramStr == "WithSignature")
                {
                    if (targetType == typeof(bool))
                        return mode == RSAEncryptionMode.WithSignature;
                    else if (targetType == typeof(System.Windows.Visibility))
                        return mode == RSAEncryptionMode.WithSignature ? System.Windows.Visibility.Visible : System.Windows.Visibility.Collapsed;
                }
                else if (paramStr == "NoSignature")
                {
                    if (targetType == typeof(bool))
                        return mode == RSAEncryptionMode.NoSignature;
                    else if (targetType == typeof(System.Windows.Visibility))
                        return mode == RSAEncryptionMode.NoSignature ? System.Windows.Visibility.Visible : System.Windows.Visibility.Collapsed;
                }
            }

            return targetType == typeof(bool) ? false : System.Windows.Visibility.Collapsed;
        }

        public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            if (value is bool boolValue && boolValue && parameter is string paramStr)
            {
                if (paramStr == "WithSignature")
                    return RSAEncryptionMode.WithSignature;
                else if (paramStr == "NoSignature")
                    return RSAEncryptionMode.NoSignature;
            }

            return RSAEncryptionMode.WithSignature;
        }
    }
}