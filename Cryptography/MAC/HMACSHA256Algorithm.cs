using System;
using System.Linq;
using System.Security.Cryptography;
using SecureFileExchange.Cryptography.Interfaces;

namespace SecureFileExchange.Cryptography.MAC
{
    public class HMACSHA256Algorithm : IMACAlgorithm
    {
        public byte[] Calculate(byte[] data, byte[] key)
        {
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