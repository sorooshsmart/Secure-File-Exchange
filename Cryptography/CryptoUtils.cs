using System;
using System.Security.Cryptography;
using System.Text;

namespace SecureFileExchange.Cryptography
{
    public static class CryptoUtils
    {
        public static byte[] GenerateRandomBytes(int length)
        {
            byte[] randomBytes = new byte[length];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }
            return randomBytes;
        }

        public static byte[] ComputeMD5(byte[] data)
        {
            using (var md5 = MD5.Create())
            {
                return md5.ComputeHash(data);
            }
        }

        public static byte[] DeriveKeyFromPassword(string password, int keyLength)
        {
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            byte[] hash = ComputeMD5(passwordBytes);

            if (keyLength == 16)
            {
                return hash;
            }
            else if (keyLength == 24)
            {
                byte[] key = new byte[24];
                Array.Copy(hash, 0, key, 0, 16);
                Array.Copy(hash, 0, key, 16, 8);
                return key;
            }
            else if (keyLength == 32)
            {
                using (var sha256 = SHA256.Create())
                {
                    return sha256.ComputeHash(passwordBytes);
                }
            }

            return hash;
        }

        public static byte[] DeriveKeyFromFile(string filePath, int keyLength)
        {
            byte[] fileBytes = System.IO.File.ReadAllBytes(filePath);

            using (var sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(fileBytes);
                byte[] key = new byte[keyLength];
                Array.Copy(hash, 0, key, 0, Math.Min(keyLength, hash.Length));
                return key;
            }
        }

        public static byte[] CombineBytes(params byte[][] arrays)
        {
            int totalLength = 0;
            foreach (var arr in arrays)
            {
                totalLength += arr.Length;
            }

            byte[] result = new byte[totalLength];
            int offset = 0;

            foreach (var arr in arrays)
            {
                Array.Copy(arr, 0, result, offset, arr.Length);
                offset += arr.Length;
            }

            return result;
        }

        public static void ClearArray(byte[] array)
        {
            if (array != null)
            {
                Array.Clear(array, 0, array.Length);
            }
        }
    }
}