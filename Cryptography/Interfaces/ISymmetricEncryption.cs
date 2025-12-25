using SecureFileExchange.Models;

namespace SecureFileExchange.Cryptography.Interfaces
{
    public interface ISymmetricEncryption
    {
        byte[] Encrypt(byte[] data, byte[] key, EncryptionMode mode);
        byte[] Decrypt(byte[] data, byte[] key, EncryptionMode mode);
        int GetKeyLength();
        SymmetricAlgorithmType GetAlgorithmType();
    }
}