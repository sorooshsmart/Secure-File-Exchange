using System;
using System.IO;
using System.Security.Cryptography;
using SecureFileExchange.Cryptography.Interfaces;
using SecureFileExchange.Models;

namespace SecureFileExchange.Cryptography.Symmetric
{
    public class AESEncryption : ISymmetricEncryption
    {
        public byte[] Encrypt(byte[] data, byte[] key, EncryptionMode mode)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.Mode = mode == EncryptionMode.CBC ? CipherMode.CBC : CipherMode.ECB;
                aes.Padding = PaddingMode.PKCS7;

                byte[] iv = null;
                if (mode == EncryptionMode.CBC)
                {
                    aes.GenerateIV();
                    iv = aes.IV;
                }

                using (var encryptor = aes.CreateEncryptor())
                using (var ms = new MemoryStream())
                {
                    if (iv != null)
                    {
                        ms.Write(iv, 0, iv.Length);
                    }

                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        cs.Write(data, 0, data.Length);
                        cs.FlushFinalBlock();
                    }

                    return ms.ToArray();
                }
            }
        }

        public byte[] Decrypt(byte[] data, byte[] key, EncryptionMode mode)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.Mode = mode == EncryptionMode.CBC ? CipherMode.CBC : CipherMode.ECB;
                aes.Padding = PaddingMode.PKCS7;

                byte[] ciphertext;
                if (mode == EncryptionMode.CBC)
                {
                    byte[] iv = new byte[16];
                    Array.Copy(data, 0, iv, 0, 16);
                    aes.IV = iv;

                    ciphertext = new byte[data.Length - 16];
                    Array.Copy(data, 16, ciphertext, 0, ciphertext.Length);
                }
                else
                {
                    ciphertext = data;
                }

                using (var decryptor = aes.CreateDecryptor())
                using (var ms = new MemoryStream(ciphertext))
                using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                using (var resultMs = new MemoryStream())
                {
                    cs.CopyTo(resultMs);
                    return resultMs.ToArray();
                }
            }
        }

        public int GetKeyLength()
        {
            return 32; // AES-256
        }

        public SymmetricAlgorithmType GetAlgorithmType()
        {
            return SymmetricAlgorithmType.AES;
        }
    }
}