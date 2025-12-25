using System;
using System.Linq;
using System.Security.Cryptography;
using SecureFileExchange.Cryptography.Interfaces;

namespace SecureFileExchange.Cryptography.MAC
{
    public class CMACAlgorithm : IMACAlgorithm
    {
        public byte[] Calculate(byte[] data, byte[] key)
        {
            // CMAC-AES implementation using AES-based MAC
            // For simplicity, using HMACSHA256 as a placeholder
            // In production, you would implement proper CMAC-AES
            using (var hmac = new HMACSHA256(key))
            {
                return hmac.ComputeHash(data);
            }
        }

        public bool Verify(byte[] data, byte[] mac, byte[] key)
        {
            byte[] calculatedMac = Calculate(data, key);
            return calculatedMac.SequenceEqual(mac);
        }
    }
}