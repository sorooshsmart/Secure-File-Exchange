using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Security.Cryptography;
using SecureFileExchange.Cryptography;
using SecureFileExchange.Cryptography.Symmetric;
using SecureFileExchange.Models;

namespace SecureFileExchange.Services
{
    public class UserIdentityManager
    {
        private static readonly string UsersBasePath = @"C:\SecureFileExchange\Users";

        static UserIdentityManager()
        {
            if (!Directory.Exists(UsersBasePath))
            {
                Directory.CreateDirectory(UsersBasePath);
            }
        }

        public static bool UserExists(string username)
        {
            string userDir = Path.Combine(UsersBasePath, username);
            return Directory.Exists(userDir);
        }

        public static string[] GetAllUsernames()
        {
            if (!Directory.Exists(UsersBasePath))
                return Array.Empty<string>();

            return Directory.GetDirectories(UsersBasePath)
                           .Select(Path.GetFileName)
                           .Where(name => !string.IsNullOrEmpty(name))
                           .ToArray()!;
        }

        public static void RegisterUser(string username, string password)
        {
            if (string.IsNullOrWhiteSpace(username))
                throw new ArgumentException("Username cannot be empty");

            if (string.IsNullOrWhiteSpace(password))
                throw new ArgumentException("Password cannot be empty");

            if (UserExists(username))
                throw new InvalidOperationException("User already exists");

            // Create user directory
            string userDir = Path.Combine(UsersBasePath, username);
            Directory.CreateDirectory(userDir);

            try
            {
                // Generate salt and hash
                byte[] salt = CryptoUtils.GenerateRandomBytes(16);
                byte[] saltPassword = salt.Concat(System.Text.Encoding.UTF8.GetBytes(password)).ToArray();
                byte[] hash = CryptoUtils.ComputeMD5(saltPassword);

                // Save credentials
                var credentials = new UserCredentials
                {
                    Username = username,
                    Salt = Convert.ToBase64String(salt),
                    PasswordHash = Convert.ToBase64String(hash)
                };

                string credPath = Path.Combine(userDir, "credentials.json");
                File.WriteAllText(credPath, JsonSerializer.Serialize(credentials, new JsonSerializerOptions { WriteIndented = true }));

                // Generate RSA key pairs (ONCE, NEVER regenerate)
                KeyManager.GenerateRSAKeyPair(out RSAParameters publicKeyEnc, out RSAParameters privateKeyEnc);
                KeyManager.GenerateRSAKeyPair(out RSAParameters publicKeySig, out RSAParameters privateKeySig);

                // Derive symmetric key from password for encrypting private keys
                byte[] passwordKey = CryptoUtils.DeriveKeyFromPassword(password, 16);

                // Export private keys
                byte[] privateKeyEncBytes = KeyManager.ExportPrivateKeyToBytes(privateKeyEnc);
                byte[] privateKeySigBytes = KeyManager.ExportPrivateKeyToBytes(privateKeySig);

                // Encrypt private keys with AES
                var aes = new AESEncryption();
                byte[] encryptedPrivKeyEnc = aes.Encrypt(privateKeyEncBytes, passwordKey, EncryptionMode.CBC);
                byte[] encryptedPrivKeySig = aes.Encrypt(privateKeySigBytes, passwordKey, EncryptionMode.CBC);

                // Save encrypted private keys
                File.WriteAllBytes(Path.Combine(userDir, "Priv_Enc.bin"), encryptedPrivKeyEnc);
                File.WriteAllBytes(Path.Combine(userDir, "Priv_Sig.bin"), encryptedPrivKeySig);

                // Save public keys
                string publicKeyEncStr = KeyManager.ExportPublicKeyToString(publicKeyEnc);
                string publicKeySigStr = KeyManager.ExportPublicKeyToString(publicKeySig);

                File.WriteAllText(Path.Combine(userDir, "Pub_Enc.txt"), publicKeyEncStr);
                File.WriteAllText(Path.Combine(userDir, "Pub_Sig.txt"), publicKeySigStr);

                // Export combined public keys for sharing
                string publicKeysExport = $"=== Encryption Public Key ===\n{publicKeyEncStr}\n\n=== Signing Public Key ===\n{publicKeySigStr}";
                File.WriteAllText(Path.Combine(userDir, $"{username}_PublicKeys.txt"), publicKeysExport);

                // Clear sensitive data
                CryptoUtils.ClearArray(passwordKey);
                CryptoUtils.ClearArray(privateKeyEncBytes);
                CryptoUtils.ClearArray(privateKeySigBytes);
            }
            catch
            {
                // Cleanup on failure
                if (Directory.Exists(userDir))
                {
                    Directory.Delete(userDir, true);
                }
                throw;
            }
        }

        public static UserIdentity? LoginUser(string username, string password)
        {
            if (!UserExists(username))
                throw new InvalidOperationException("User does not exist");

            string userDir = Path.Combine(UsersBasePath, username);

            // Load credentials
            string credPath = Path.Combine(userDir, "credentials.json");
            if (!File.Exists(credPath))
                throw new InvalidOperationException("User credentials not found");

            string credJson = File.ReadAllText(credPath);
            var credentials = JsonSerializer.Deserialize<UserCredentials>(credJson);

            if (credentials == null)
                throw new InvalidOperationException("Failed to load credentials");

            // Verify password
            byte[] salt = Convert.FromBase64String(credentials.Salt);
            byte[] saltPassword = salt.Concat(System.Text.Encoding.UTF8.GetBytes(password)).ToArray();
            byte[] inputHash = CryptoUtils.ComputeMD5(saltPassword);
            byte[] storedHash = Convert.FromBase64String(credentials.PasswordHash);

            if (!inputHash.SequenceEqual(storedHash))
            {
                throw new InvalidOperationException("Invalid password");
            }

            // Derive decryption key
            byte[] passwordKey = CryptoUtils.DeriveKeyFromPassword(password, 16);

            // Load and decrypt private keys
            byte[] encryptedPrivKeyEnc = File.ReadAllBytes(Path.Combine(userDir, "Priv_Enc.bin"));
            byte[] encryptedPrivKeySig = File.ReadAllBytes(Path.Combine(userDir, "Priv_Sig.bin"));

            var aes = new AESEncryption();
            byte[] privateKeyEncBytes = aes.Decrypt(encryptedPrivKeyEnc, passwordKey, EncryptionMode.CBC);
            byte[] privateKeySigBytes = aes.Decrypt(encryptedPrivKeySig, passwordKey, EncryptionMode.CBC);

            RSAParameters privateKeyEnc = KeyManager.ImportPrivateKeyFromBytes(privateKeyEncBytes);
            RSAParameters privateKeySig = KeyManager.ImportPrivateKeyFromBytes(privateKeySigBytes);

            // Load public keys
            string publicKeyEncStr = File.ReadAllText(Path.Combine(userDir, "Pub_Enc.txt"));
            string publicKeySigStr = File.ReadAllText(Path.Combine(userDir, "Pub_Sig.txt"));

            RSAParameters publicKeyEnc = KeyManager.ImportPublicKeyFromString(publicKeyEncStr);
            RSAParameters publicKeySig = KeyManager.ImportPublicKeyFromString(publicKeySigStr);

            // Clear sensitive temporary data
            CryptoUtils.ClearArray(passwordKey);
            CryptoUtils.ClearArray(privateKeyEncBytes);
            CryptoUtils.ClearArray(privateKeySigBytes);

            return new UserIdentity
            {
                Username = username,
                UserDirectory = userDir,
                EncryptionPublicKey = publicKeyEnc,
                SigningPublicKey = publicKeySig,
                EncryptionPrivateKey = privateKeyEnc,
                SigningPrivateKey = privateKeySig
            };
        }

        public static UserIdentity LoadPublicKeysOnly(string username)
        {
            if (!UserExists(username))
                throw new InvalidOperationException($"User '{username}' does not exist");

            string userDir = Path.Combine(UsersBasePath, username);

            string publicKeyEncStr = File.ReadAllText(Path.Combine(userDir, "Pub_Enc.txt"));
            string publicKeySigStr = File.ReadAllText(Path.Combine(userDir, "Pub_Sig.txt"));

            RSAParameters publicKeyEnc = KeyManager.ImportPublicKeyFromString(publicKeyEncStr);
            RSAParameters publicKeySig = KeyManager.ImportPublicKeyFromString(publicKeySigStr);

            return new UserIdentity
            {
                Username = username,
                UserDirectory = userDir,
                EncryptionPublicKey = publicKeyEnc,
                SigningPublicKey = publicKeySig,
                EncryptionPrivateKey = null,
                SigningPrivateKey = null
            };
        }

        public static void DeleteUser(string username)
        {
            if (!UserExists(username))
                return;

            string userDir = Path.Combine(UsersBasePath, username);
            Directory.Delete(userDir, true);
        }
    }
}