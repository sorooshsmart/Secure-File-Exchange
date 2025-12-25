namespace SecureFileExchange.Models
{
    public class SaltHashConfig
    {
        public string Salt { get; set; } = string.Empty;
        public string Hash { get; set; } = string.Empty;
    }

    public class EncryptionPackage
    {
        public byte[] Signature { get; set; } = Array.Empty<byte>();
        public byte[] DataWithMAC { get; set; } = Array.Empty<byte>();
        public byte[] OriginalData { get; set; } = Array.Empty<byte>();
        public byte[] MAC { get; set; } = Array.Empty<byte>();
    }

    public class EncryptionResult
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public byte[]? EncryptedData { get; set; }
        public string? OutputPath { get; set; }
    }

    public class DecryptionResult
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public byte[]? DecryptedData { get; set; }
        public string? OutputPath { get; set; }
    }
}