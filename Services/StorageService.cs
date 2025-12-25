using System;
using System.IO;
using System.Text.Json;
using SecureFileExchange.Models;

namespace SecureFileExchange.Services
{
    public class StorageService
    {
        private static readonly string BasePath = @"C:\SecureFileExchange";

        static StorageService()
        {
            if (!Directory.Exists(BasePath))
            {
                Directory.CreateDirectory(BasePath);
            }
        }

        public static void SaveSaltHashConfig(SaltHashConfig config)
        {
            string filePath = Path.Combine(BasePath, "salt_hash_config.json");
            string json = JsonSerializer.Serialize(config);
            File.WriteAllText(filePath, json);
        }

        public static SaltHashConfig? LoadSaltHashConfig()
        {
            string filePath = Path.Combine(BasePath, "salt_hash_config.json");
            if (!File.Exists(filePath))
                return null;

            string json = File.ReadAllText(filePath);
            return JsonSerializer.Deserialize<SaltHashConfig>(json);
        }

        public static void SaveEncryptedPrivateKey(byte[] encryptedKey, string keyType)
        {
            string fileName = keyType == "encryption" ? "Priv_Enc.bin" : "Priv_Sig.bin";
            string filePath = Path.Combine(BasePath, fileName);
            File.WriteAllBytes(filePath, encryptedKey);
        }

        public static byte[]? LoadEncryptedPrivateKey(string keyType)
        {
            string fileName = keyType == "encryption" ? "Priv_Enc.bin" : "Priv_Sig.bin";
            string filePath = Path.Combine(BasePath, fileName);

            if (!File.Exists(filePath))
                return null;

            return File.ReadAllBytes(filePath);
        }

        public static void SavePublicKey(string publicKey, string keyType)
        {
            string fileName = keyType == "encryption" ? "Pub_Enc.txt" : "Pub_Sig.txt";
            string filePath = Path.Combine(BasePath, fileName);
            File.WriteAllText(filePath, publicKey);
        }

        public static string? LoadPublicKey(string keyType)
        {
            string fileName = keyType == "encryption" ? "Pub_Enc.txt" : "Pub_Sig.txt";
            string filePath = Path.Combine(BasePath, fileName);

            if (!File.Exists(filePath))
                return null;

            return File.ReadAllText(filePath);
        }

        public static bool IsRegistered()
        {
            string filePath = Path.Combine(BasePath, "salt_hash_config.json");
            return File.Exists(filePath);
        }

        public static void SaveEncryptedFile(byte[] data, string outputPath)
        {
            File.WriteAllBytes(outputPath, data);
        }

        public static byte[] LoadEncryptedFile(string filePath)
        {
            return File.ReadAllBytes(filePath);
        }

        public static string GetOutputDirectory()
        {
            string outPath = Path.Combine(BasePath, "Output");
            if (!Directory.Exists(outPath))
            {
                Directory.CreateDirectory(outPath);
            }
            return outPath;
        }

        public static void ExportPublicKeys(string encryptionKey, string signingKey)
        {
            string outputPath = Path.Combine(GetOutputDirectory(), "MyPublicKeys.txt");
            string content = $"=== Encryption Public Key ===\n{encryptionKey}\n\n=== Signing Public Key ===\n{signingKey}";
            File.WriteAllText(outputPath, content);
        }
    }
}