using SecureFileExchange.Cryptography;
using SecureFileExchange.Models;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace SecureFileExchange.Services
{
    public class PublicKeyExchangeService
    {
        private static readonly string ExportDirectory = @"C:\SecureFileExchange\ExportedKeys";

        static PublicKeyExchangeService()
        {
            if (!Directory.Exists(ExportDirectory))
            {
                Directory.CreateDirectory(ExportDirectory);
            }
        }

        /// <summary>
        /// Exports user's public keys to a shareable file
        /// </summary>
        public static string ExportPublicKeys(UserIdentity user)
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            string filename = $"{user.Username}_PublicKeys.txt";
            string filepath = Path.Combine(ExportDirectory, filename);

            // Export both encryption and signing public keys
            string encryptionKey = KeyManager.ExportPublicKeyToString(user.EncryptionPublicKey);
            string signingKey = KeyManager.ExportPublicKeyToString(user.SigningPublicKey);

            var sb = new StringBuilder();
            sb.AppendLine($"===== PUBLIC KEYS FOR: {user.Username} =====");
            sb.AppendLine($"Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine();
            sb.AppendLine("--- ENCRYPTION PUBLIC KEY ---");
            sb.AppendLine(encryptionKey);
            sb.AppendLine();
            sb.AppendLine("--- SIGNING PUBLIC KEY ---");
            sb.AppendLine(signingKey);
            sb.AppendLine();
            sb.AppendLine("===== END OF PUBLIC KEYS =====");

            File.WriteAllText(filepath, sb.ToString());

            return filepath;
        }

        /// <summary>
        /// Imports external public keys from file
        /// </summary>
        public static ExternalPublicKeys ImportPublicKeys(string filepath)
        {
            if (!File.Exists(filepath))
                throw new FileNotFoundException("Public key file not found", filepath);

            string content = File.ReadAllText(filepath);

            // Parse the file
            string username = ExtractUsername(content);
            string encryptionKey = ExtractKey(content, "ENCRYPTION PUBLIC KEY");
            string signingKey = ExtractKey(content, "SIGNING PUBLIC KEY");

            if (string.IsNullOrEmpty(encryptionKey) || string.IsNullOrEmpty(signingKey))
                throw new InvalidOperationException("Invalid public key file format");

            // Convert to RSAParameters
            RSAParameters encryptionPublicKey = KeyManager.ImportPublicKeyFromString(encryptionKey);
            RSAParameters signingPublicKey = KeyManager.ImportPublicKeyFromString(signingKey);

            return new ExternalPublicKeys
            {
                Username = username,
                EncryptionPublicKey = encryptionPublicKey,
                SigningPublicKey = signingPublicKey,
                SourceFile = filepath
            };
        }

        private static string ExtractUsername(string content)
        {
            string marker = "PUBLIC KEYS FOR:";
            int startIndex = content.IndexOf(marker);
            if (startIndex == -1)
                return "Unknown";

            startIndex += marker.Length;
            int endIndex = content.IndexOf("=====", startIndex);
            if (endIndex == -1)
                return "Unknown";

            return content.Substring(startIndex, endIndex - startIndex).Trim();
        }

        private static string ExtractKey(string content, string keyType)
        {
            var pattern = @$"--- {keyType} ---\s*(.*?)\s*(?=---|\=\=\=\=\=)";
            var match = Regex.Match(content, pattern, RegexOptions.Singleline);

            return match.Success ? match.Groups[1].Value.Trim() : string.Empty;
        }


        /// <summary>
        /// Validates if a file is a valid public key file
        /// </summary>
        public static bool ValidatePublicKeyFile(string filepath)
        {
            try
            {
                if (!File.Exists(filepath))
                    return false;

                string content = File.ReadAllText(filepath);

                return content.Contains("PUBLIC KEYS FOR:") &&
                       content.Contains("ENCRYPTION PUBLIC KEY") &&
                       content.Contains("SIGNING PUBLIC KEY");
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Gets the default export directory path
        /// </summary>
        public static string GetExportDirectory()
        {
            return ExportDirectory;
        }
    }
}