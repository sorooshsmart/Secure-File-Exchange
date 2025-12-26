using System;
using System.IO;
using System.Security.Cryptography;
using SecureFileExchange.Cryptography;
using SecureFileExchange.Cryptography.Symmetric;
using SecureFileExchange.Models;

namespace SecureFileExchange.Services
{
    public class Decryptor
    {
        public byte[] DecryptPackage(
            byte[] encryptedData,
            RSAParameters? privateKeyEncryption = null,
            byte[]? symmetricKey = null)
        {
            if (encryptedData == null || encryptedData.Length == 0)
                throw new ArgumentException("Encrypted data is empty");

            Models.EncryptionMethod method = (Models.EncryptionMethod)encryptedData[0];

            switch (method)
            {
                case Models.EncryptionMethod.SecureEnvelope:
                    if (privateKeyEncryption == null)
                        throw new ArgumentNullException("Private key is required for Secure Envelope decryption");
                    return DecryptSecureEnvelope(encryptedData, privateKeyEncryption.Value);

                case Models.EncryptionMethod.Symmetric:
                    if (symmetricKey == null)
                        throw new ArgumentNullException("Symmetric key is required for Symmetric decryption");
                    return DecryptSymmetric(encryptedData, symmetricKey);

                case Models.EncryptionMethod.RSADirect:
                    if (privateKeyEncryption == null)
                        throw new ArgumentNullException("Private key is required for RSA Direct decryption");
                    return DecryptRSADirect(encryptedData, privateKeyEncryption.Value);

                default:
                    throw new InvalidOperationException($"Unknown encryption method: {method}");
            }
        }

        private byte[] DecryptSecureEnvelope(byte[] encryptedData, RSAParameters privateKey)
        {
            // Skip first byte (method flag) and second byte (recipient mode)
            // Read key length
            int keyLength = BitConverter.ToInt32(encryptedData, 2);

            // Extract encrypted session key
            byte[] encryptedSessionKey = new byte[keyLength];
            Array.Copy(encryptedData, 6, encryptedSessionKey, 0, keyLength);

            // Extract encrypted package
            byte[] encryptedPackage = new byte[encryptedData.Length - 6 - keyLength];
            Array.Copy(encryptedData, 6 + keyLength, encryptedPackage, 0, encryptedPackage.Length);

            // Decrypt session key
            byte[] sessionKey = DigitalSignature.Decrypt(encryptedSessionKey, privateKey);

            // Decrypt package
            var aes = new AESEncryption();
            return aes.Decrypt(encryptedPackage, sessionKey, Models.EncryptionMode.CBC);
        }

        private byte[] DecryptSymmetric(byte[] encryptedData, byte[] key)
        {
            // Skip first two bytes (method flag + placeholder)
            SymmetricAlgorithmType algoType = (SymmetricAlgorithmType)encryptedData[2];
            Models.EncryptionMode mode = (Models.EncryptionMode)encryptedData[3];

            // Extract encrypted package
            byte[] encryptedPackage = new byte[encryptedData.Length - 4];
            Array.Copy(encryptedData, 4, encryptedPackage, 0, encryptedPackage.Length);

            // Get appropriate decryption algorithm
            Cryptography.Interfaces.ISymmetricEncryption algorithm = algoType switch
            {
                SymmetricAlgorithmType.AES => (Cryptography.Interfaces.ISymmetricEncryption)new AESEncryption(),
                SymmetricAlgorithmType.DES => (Cryptography.Interfaces.ISymmetricEncryption)new DESEncryption(),
                SymmetricAlgorithmType.TripleDES => (Cryptography.Interfaces.ISymmetricEncryption)new TripleDESEncryption(),
                _ => throw new InvalidOperationException($"Unknown algorithm type: {algoType}")
            };

            return algorithm.Decrypt(encryptedPackage, key, mode);
        }

        private byte[] DecryptRSADirect(byte[] encryptedData, RSAParameters privateKey)
        {
            // Check if this is NoSignature mode (educational)
            bool isNoSignature = encryptedData.Length > 2 && encryptedData[2] == 0x00;

            if (isNoSignature)
            {
                // Skip first 3 bytes: [method flag][recipient mode][0x00 = NoSignature]
                byte[] encryptedPackage = new byte[encryptedData.Length - 3];
                Array.Copy(encryptedData, 3, encryptedPackage, 0, encryptedPackage.Length);

                // Direct RSA decryption - returns RAW file data
                return DigitalSignature.Decrypt(encryptedPackage, privateKey);
            }
            else
            {
                // Original mode: Skip first 3 bytes [method flag][recipient mode][0x01 = WithSignature]
                byte[] encryptedPackage = new byte[encryptedData.Length - 3];
                Array.Copy(encryptedData, 3, encryptedPackage, 0, encryptedPackage.Length);

                // Returns package with signature + data + MAC
                return DigitalSignature.Decrypt(encryptedPackage, privateKey);
            }
        }

        public (byte[] originalData, string extension) VerifyAndExtractData(byte[] packageData, RSAParameters publicKeySigning)
        {
            // Read signature length
            int signatureLength = BitConverter.ToInt32(packageData, 0);

            // Extract signature
            byte[] signature = new byte[signatureLength];
            Array.Copy(packageData, 4, signature, 0, signatureLength);

            // Extract data with extension + MAC
            byte[] dataWithExtensionAndMac = new byte[packageData.Length - 4 - signatureLength];
            Array.Copy(packageData, 4 + signatureLength, dataWithExtensionAndMac, 0, dataWithExtensionAndMac.Length);

            // Verify signature
            bool isValid = DigitalSignature.Verify(dataWithExtensionAndMac, signature, publicKeySigning);
            if (!isValid)
            {
                throw new InvalidOperationException("Digital signature verification failed!");
            }

            // Extract extension length
            byte extensionLength = dataWithExtensionAndMac[0];

            // Extract extension
            byte[] extensionBytes = new byte[extensionLength];
            Array.Copy(dataWithExtensionAndMac, 1, extensionBytes, 0, extensionLength);
            string extension = System.Text.Encoding.UTF8.GetString(extensionBytes);

            // Extract original data (remove extension and MAC - last 32 bytes)
            int macLength = 32;
            int dataStart = 1 + extensionLength;
            int dataLength = dataWithExtensionAndMac.Length - dataStart - macLength;

            byte[] originalData = new byte[dataLength];
            Array.Copy(dataWithExtensionAndMac, dataStart, originalData, 0, dataLength);

            return (originalData, extension);
        }

        public RecipientMode GetRecipientMode(byte[] encryptedData)
        {
            if (encryptedData == null || encryptedData.Length < 2)
                return RecipientMode.InternalUser;

            Models.EncryptionMethod method = (Models.EncryptionMethod)encryptedData[0];

            // Symmetric doesn't use recipient mode
            if (method == Models.EncryptionMethod.Symmetric)
                return RecipientMode.InternalUser;

            return (RecipientMode)encryptedData[1];
        }

        public DecryptionResult DecryptFile(
            string encryptedFilePath,
            RSAParameters signingPublicKey,
            RSAParameters? encryptionPrivateKey = null,
            byte[]? symmetricKey = null)
        {
            try
            {
                // Read encrypted file
                byte[] encryptedData = StorageService.LoadEncryptedFile(encryptedFilePath);

                Models.EncryptionMethod method = (Models.EncryptionMethod)encryptedData[0];

                // Check if RSA Direct (No Signature) mode
                bool isRSADirectNoSignature = method == Models.EncryptionMethod.RSADirect &&
                                              encryptedData.Length > 2 &&
                                              encryptedData[2] == 0x00;

                if (isRSADirectNoSignature)
                {
                    // RSA Direct (No Signature) - Educational Mode
                    if (encryptionPrivateKey == null)
                        throw new ArgumentNullException("Private key is required for RSA Direct decryption");

                    // Decrypt directly - no signature/MAC verification
                    byte[] decryptedData = DecryptPackage(encryptedData, encryptionPrivateKey, symmetricKey);

                    // Save output file
                    string baseFileName = Path.GetFileNameWithoutExtension(encryptedFilePath);
                    if (baseFileName.EndsWith(".enc"))
                    {
                        baseFileName = Path.GetFileNameWithoutExtension(baseFileName);
                    }

                    string outputFileName = baseFileName + "_decrypted.bin";
                    string outputPath = Path.Combine(StorageService.GetOutputDirectory(), outputFileName);

                    File.WriteAllBytes(outputPath, decryptedData);

                    return new DecryptionResult
                    {
                        Success = true,
                        Message = "File decrypted successfully (RSA Direct - No Signature mode)\n⚠️ This file was NOT authenticated or integrity-checked!",
                        DecryptedData = decryptedData,
                        OutputPath = outputPath
                    };
                }
                else
                {
                    // Standard mode with signature verification
                    byte[] packageData = DecryptPackage(encryptedData, encryptionPrivateKey, symmetricKey);

                    // Verify signature and extract data with original extension
                    var (originalData, extension) = VerifyAndExtractData(packageData, signingPublicKey);

                    // Create output filename with correct extension
                    string baseFileName = Path.GetFileNameWithoutExtension(encryptedFilePath);
                    if (baseFileName.EndsWith(".enc"))
                    {
                        baseFileName = Path.GetFileNameWithoutExtension(baseFileName);
                    }

                    string outputFileName = baseFileName + "_decrypted" + extension;
                    string outputPath = Path.Combine(StorageService.GetOutputDirectory(), outputFileName);

                    // Save decrypted file with original extension
                    File.WriteAllBytes(outputPath, originalData);

                    return new DecryptionResult
                    {
                        Success = true,
                        Message = $"File decrypted and verified successfully\nOriginal type: {extension}",
                        DecryptedData = originalData,
                        OutputPath = outputPath
                    };
                }
            }
            catch (Exception ex)
            {
                return new DecryptionResult
                {
                    Success = false,
                    Message = $"Decryption failed: {ex.Message}"
                };
            }
        }
    }
}