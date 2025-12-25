namespace SecureFileExchange.Models
{
    public enum EncryptionMethod
    {
        SecureEnvelope = 0x01,
        Symmetric = 0x02,
        RSADirect = 0x03
    }

    public enum SymmetricAlgorithmType
    {
        AES = 0x01,
        DES = 0x02,
        TripleDES = 0x03
    }

    public enum EncryptionMode
    {
        CBC = 0x01,
        ECB = 0x02
    }

    public enum MACAlgorithmType
    {
        HMACSHA256,
        CMAC,
        CCM
    }

    public enum KeyGenerationMethod
    {
        Password,
        File
    }
}