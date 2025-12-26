using System.Security.Cryptography;

namespace SecureFileExchange.Models
{
    public class ExternalPublicKeys
    {
        public string Username { get; set; } = string.Empty;
        public RSAParameters EncryptionPublicKey { get; set; }
        public RSAParameters SigningPublicKey { get; set; }
        public string SourceFile { get; set; } = string.Empty;
    }

    public enum RecipientMode : byte
    {
        InternalUser = 0x01,
        ExternalPublicKey = 0x02
    }

    // NEW: RSA Encryption Mode Type
    public enum RSAEncryptionMode
    {
        WithSignature,      // Original: Includes signature and MAC
        NoSignature         // Educational: Direct RSA only, no signature/MAC
    }
}