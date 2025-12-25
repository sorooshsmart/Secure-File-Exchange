using System;
using System.IO;
using System.Security.Cryptography;
using SecureFileExchange.Cryptography;
using SecureFileExchange.Cryptography.Interfaces;
using SecureFileExchange.Cryptography.MAC;
using SecureFileExchange.Cryptography.Symmetric;
using SecureFileExchange.Models;

namespace SecureFileExchange.Services
{
    public class Encryptor
    {
        private IMACAlgorithm _macAlgorithm;
        private ISymmetricEncryption _symmetricEncryption;

        public Encryptor(MACAlgorithmType macType, SymmetricAlgorithmType symType)
        {
            _macAlgorithm = CreateMACAlgorithm(macType);
            _symmetricEncryption = CreateSymmetricEncryption(symType);
        }

        private IMACAlgorithm CreateMACAlgorithm(MACAlgorithmType type)
        {
            return type switch
            {
                MACAlgorithmType.HMACSHA256 => new HMACSHA256Algorithm(),
                MACAlgorithmType.CMAC => new CMACAlgorithm(),
                MACAlgorithmType.CCM => new CCMAlgorithm(),
                _ => new HMACSHA256Algorithm()
            };
        }

        private ISymmetricEncryption CreateSymmetricEncryption(SymmetricAlgorithmType type)
        {
            return type switch
            {
                SymmetricAlgorithmType.AES => new AESEncryption(),
                SymmetricAlgorithmType.DES => new DESEncryption(),
                SymmetricAlgorithmType.TripleDES => new TripleDESEncryption(),
                _ => new AESEncryption()
            };
        }

        public byte[] CreatePackage(byte[] fileData, RSAParameters privateKeySigning, string originalFileName)
        {
            // Step 1: Get original file extension
            string extension = System.IO.Path.GetExtension(originalFileName);
            if (string.IsNullOrEmpty(extension))
            {
                extension = ".bin"; // Default for files without extension
            }
            byte[] extensionBytes = System.Text.Encoding.UTF8.GetBytes(extension);
            byte extensionLength = (byte)Math.Min(extensionBytes.Length, 255);

            // Step 2: Calculate MAC
            byte[] macKey = CryptoUtils.GenerateRandomBytes(32);
            byte[] mac = _macAlgorithm.Calculate(fileData, macKey);

            // Step 3: Combine extension_length + extension + data + MAC
            byte[] dataWithMac = new byte[1 + extensionLength + fileData.Length + mac.Length];
            dataWithMac[0] = extensionLength;
            Array.Copy(extensionBytes, 0, dataWithMac, 1, extensionLength);
            Array.Copy(fileData, 0, dataWithMac, 1 + extensionLength, fileData.Length);
            Array.Copy(mac, 0, dataWithMac, 1 + extensionLength + fileData.Length, mac.Length);

            // Step 4: Sign the combined data
            byte[] signature = DigitalSignature.Sign(dataWithMac, privateKeySigning);

            // Step 5: Create package structure: [signature_length(4)][signature][extension_len+extension+data+mac]
            byte[] package = new byte[4 + signature.Length + dataWithMac.Length];

            BitConverter.GetBytes(signature.Length).CopyTo(package, 0);
            signature.CopyTo(package, 4);
            dataWithMac.CopyTo(package, 4 + signature.Length);

            return package;
        }

        public byte[] EncryptSecureEnvelope(byte[] packageData, RSAParameters consumerPublicKey)
        {
            // Generate random session key
            byte[] sessionKey = CryptoUtils.GenerateRandomBytes(32);

            // Encrypt package with session key
            var aes = new AESEncryption();
            byte[] encryptedPackage = aes.Encrypt(packageData, sessionKey, Models.EncryptionMode.CBC);

            // Encrypt session key with consumer's public key
            byte[] encryptedSessionKey = DigitalSignature.Encrypt(sessionKey, consumerPublicKey);

            // Build final structure: [0x01][key_length(4)][encrypted_key][encrypted_package]
            byte[] result = new byte[1 + 4 + encryptedSessionKey.Length + encryptedPackage.Length];

            result[0] = (byte)Models.EncryptionMethod.SecureEnvelope;
            BitConverter.GetBytes(encryptedSessionKey.Length).CopyTo(result, 1);
            encryptedSessionKey.CopyTo(result, 5);
            encryptedPackage.CopyTo(result, 5 + encryptedSessionKey.Length);

            return result;
        }

        public byte[] EncryptSymmetric(byte[] packageData, byte[] key, Models.EncryptionMode mode)
        {
            byte[] encryptedPackage = _symmetricEncryption.Encrypt(packageData, key, mode);

            // Structure: [0x02][algo_type][mode_type][encrypted_package]
            byte[] result = new byte[3 + encryptedPackage.Length];

            result[0] = (byte)Models.EncryptionMethod.Symmetric;
            result[1] = (byte)_symmetricEncryption.GetAlgorithmType();
            result[2] = (byte)mode;

            encryptedPackage.CopyTo(result, 3);

            return result;
        }

        public byte[] EncryptRSADirect(byte[] packageData, RSAParameters consumerPublicKey)
        {
            // Note: packageData already contains: signature + data + MAC
            // RSA-2048 with OAEP-SHA256 can encrypt maximum 190 bytes
            // We need to check the PACKAGE size, not original file size

            if (packageData.Length > 190)
            {
                throw new InvalidOperationException(
                    $"Package is too large for RSA direct encryption.\n" +
                    $"Package size (with signature+MAC): {packageData.Length} bytes\n" +
                    $"Maximum allowed: 190 bytes\n\n" +
                    $"The original file was too large after adding security layers.\n" +
                    $"Please use Secure Envelope or Symmetric encryption instead.");
            }

            byte[] encryptedPackage = DigitalSignature.Encrypt(packageData, consumerPublicKey);

            // Structure: [0x03][encrypted_package]
            byte[] result = new byte[1 + encryptedPackage.Length];
            result[0] = (byte)Models.EncryptionMethod.RSADirect;
            encryptedPackage.CopyTo(result, 1);

            return result;
        }

        public EncryptionResult EncryptFile(
            string inputFilePath,
            Models.EncryptionMethod method,
            RSAParameters signingPrivateKey,
            RSAParameters? consumerPublicKey = null,
            byte[]? symmetricKey = null,
            Models.EncryptionMode symmetricMode = Models.EncryptionMode.CBC)
        {
            try
            {
                // Read file data
                byte[] fileData = File.ReadAllBytes(inputFilePath);
                string originalFileName = Path.GetFileName(inputFilePath);

                // Create package (extension + data + MAC + signature)
                byte[] package = CreatePackage(fileData, signingPrivateKey, originalFileName);

                byte[]? encryptedData = null;

                // Encrypt based on method
                switch (method)
                {
                    case Models.EncryptionMethod.SecureEnvelope:
                        if (consumerPublicKey == null)
                            throw new ArgumentNullException("Consumer public key is required for Secure Envelope");
                        encryptedData = EncryptSecureEnvelope(package, consumerPublicKey.Value);
                        break;

                    case Models.EncryptionMethod.Symmetric:
                        if (symmetricKey == null)
                            throw new ArgumentNullException("Symmetric key is required");
                        encryptedData = EncryptSymmetric(package, symmetricKey, symmetricMode);
                        break;

                    case Models.EncryptionMethod.RSADirect:
                        if (consumerPublicKey == null)
                            throw new ArgumentNullException("Consumer public key is required for RSA Direct");
                        encryptedData = EncryptRSADirect(package, consumerPublicKey.Value);
                        break;
                }

                // Save encrypted file
                string outputPath = Path.Combine(
                    StorageService.GetOutputDirectory(),
                    Path.GetFileNameWithoutExtension(inputFilePath) + ".enc"
                );

                StorageService.SaveEncryptedFile(encryptedData!, outputPath);

                return new EncryptionResult
                {
                    Success = true,
                    Message = "File encrypted successfully",
                    EncryptedData = encryptedData,
                    OutputPath = outputPath
                };
            }
            catch (Exception ex)
            {
                return new EncryptionResult
                {
                    Success = false,
                    Message = $"Encryption failed: {ex.Message}"
                };
            }
        }
    }
}