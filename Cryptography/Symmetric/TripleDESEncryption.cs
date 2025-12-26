using System;
using System.IO;
using System.Security.Cryptography;
using SecureFileExchange.Cryptography.Interfaces;
using SecureFileExchange.Models;

namespace SecureFileExchange.Cryptography.Symmetric
{
    public class TripleDESEncryption : ISymmetricEncryption
    {
        public byte[] Encrypt(byte[] data, byte[] key, EncryptionMode mode)
        {
            // Ensure key is exactly 24 bytes for 3DES
            byte[] normalizedKey = NormalizeKey(key);

            using (var tripledes = TripleDES.Create())
            {
                tripledes.Key = normalizedKey;
                tripledes.Mode = mode == EncryptionMode.CBC ? CipherMode.CBC : CipherMode.ECB;
                tripledes.Padding = PaddingMode.PKCS7;

                byte[] iv = null;
                if (mode == EncryptionMode.CBC)
                {
                    tripledes.GenerateIV();
                    iv = tripledes.IV; // 3DES IV is 8 bytes
                }

                using (var encryptor = tripledes.CreateEncryptor())
                using (var ms = new MemoryStream())
                {
                    // Write IV first if CBC mode
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
            // Ensure key is exactly 24 bytes for 3DES
            byte[] normalizedKey = NormalizeKey(key);

            using (var tripledes = TripleDES.Create())
            {
                tripledes.Key = normalizedKey;
                tripledes.Mode = mode == EncryptionMode.CBC ? CipherMode.CBC : CipherMode.ECB;
                tripledes.Padding = PaddingMode.PKCS7;

                byte[] ciphertext;
                if (mode == EncryptionMode.CBC)
                {
                    // 3DES IV is 8 bytes (not 16 like AES)
                    byte[] iv = new byte[8];
                    Array.Copy(data, 0, iv, 0, 8);
                    tripledes.IV = iv;

                    ciphertext = new byte[data.Length - 8];
                    Array.Copy(data, 8, ciphertext, 0, ciphertext.Length);
                }
                else
                {
                    ciphertext = data;
                }

                using (var decryptor = tripledes.CreateDecryptor())
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
            return 24; // 3DES uses 24-byte key
        }

        public SymmetricAlgorithmType GetAlgorithmType()
        {
            return SymmetricAlgorithmType.TripleDES;
        }

        /// Normalizes key to exactly 24 bytes for 3DES
        private byte[] NormalizeKey(byte[] key)
        {
            if (key.Length == 24)
                return key;

            byte[] normalizedKey = new byte[24];

            if (key.Length < 24)
            {
                // If key is shorter, repeat it
                int offset = 0;
                while (offset < 24)
                {
                    int copyLength = Math.Min(key.Length, 24 - offset);
                    Array.Copy(key, 0, normalizedKey, offset, copyLength);
                    offset += copyLength;
                }
            }
            else
            {
                // If key is longer, truncate it
                Array.Copy(key, 0, normalizedKey, 0, 24);
            }

            return normalizedKey;
        }
    }
}