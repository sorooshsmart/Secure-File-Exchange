namespace SecureFileExchange.Cryptography.Interfaces
{
    public interface IMACAlgorithm
    {
        byte[] Calculate(byte[] data, byte[] key);
        bool Verify(byte[] data, byte[] mac, byte[] key);
    }
}