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
            using (var tripledes = TripleDES.Create())
            {
                tripledes.Key = key;
                tripledes.Mode = mode == EncryptionMode.CBC ? CipherMode.CBC : CipherMode.ECB;
                tripledes.Padding = PaddingMode.PKCS7;

                byte[] iv = null;
                if (mode == EncryptionMode.CBC)
                {
                    tripledes.GenerateIV();
                    iv = tripledes.IV;
                }

                using (var encryptor = tripledes.CreateEncryptor())
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
            using (var tripledes = TripleDES.Create())
            {
                tripledes.Key = key;
                tripledes.Mode = mode == EncryptionMode.CBC ? CipherMode.CBC : CipherMode.ECB;
                tripledes.Padding = PaddingMode.PKCS7;

                byte[] ciphertext;
                if (mode == EncryptionMode.CBC)
                {
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
    }
}