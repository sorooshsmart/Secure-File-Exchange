using System;
using System.Security.Cryptography;

namespace SecureFileExchange.Cryptography
{
    public class KeyManager
    {
        public static RSAParameters GenerateRSAKeyPair(out RSAParameters publicKey, out RSAParameters privateKey)
        {
            using (var rsa = RSA.Create(2048))
            {
                privateKey = rsa.ExportParameters(true);
                publicKey = rsa.ExportParameters(false);
                return privateKey;
            }
        }

        public static string ExportPublicKeyToString(RSAParameters publicKey)
        {
            using (var rsa = RSA.Create())
            {
                rsa.ImportParameters(publicKey);
                byte[] publicKeyBytes = rsa.ExportSubjectPublicKeyInfo();
                return Convert.ToBase64String(publicKeyBytes);
            }
        }

        public static RSAParameters ImportPublicKeyFromString(string publicKeyString)
        {
            byte[] publicKeyBytes = Convert.FromBase64String(publicKeyString);
            using (var rsa = RSA.Create())
            {
                rsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);
                return rsa.ExportParameters(false);
            }
        }

        public static byte[] ExportPrivateKeyToBytes(RSAParameters privateKey)
        {
            using (var rsa = RSA.Create())
            {
                rsa.ImportParameters(privateKey);
                return rsa.ExportPkcs8PrivateKey();
            }
        }

        public static RSAParameters ImportPrivateKeyFromBytes(byte[] privateKeyBytes)
        {
            using (var rsa = RSA.Create())
            {
                rsa.ImportPkcs8PrivateKey(privateKeyBytes, out _);
                return rsa.ExportParameters(true);
            }
        }

        public static byte[] EncryptPrivateKey(byte[] privateKeyBytes, byte[] password)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = password;
                aes.GenerateIV();

                using (var encryptor = aes.CreateEncryptor())
                {
                    byte[] encryptedKey = encryptor.TransformFinalBlock(privateKeyBytes, 0, privateKeyBytes.Length);

                    // Combine IV and encrypted data
                    byte[] result = new byte[aes.IV.Length + encryptedKey.Length];
                    Array.Copy(aes.IV, 0, result, 0, aes.IV.Length);
                    Array.Copy(encryptedKey, 0, result, aes.IV.Length, encryptedKey.Length);

                    return result;
                }
            }
        }

        public static byte[] DecryptPrivateKey(byte[] encryptedPrivateKey, byte[] password)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = password;

                // Extract IV
                byte[] iv = new byte[16];
                Array.Copy(encryptedPrivateKey, 0, iv, 0, 16);
                aes.IV = iv;

                // Extract encrypted data
                byte[] encryptedData = new byte[encryptedPrivateKey.Length - 16];
                Array.Copy(encryptedPrivateKey, 16, encryptedData, 0, encryptedData.Length);

                using (var decryptor = aes.CreateDecryptor())
                {
                    return decryptor.TransformFinalBlock(encryptedData, 0, encryptedData.Length);
                }
            }
        }
    }
}