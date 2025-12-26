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

        public byte[] EncryptSecureEnvelope(byte[] packageData, RSAParameters consumerPublicKey, RecipientMode recipientMode)
        {
            // Generate random session key
            byte[] sessionKey = CryptoUtils.GenerateRandomBytes(32);

            // Encrypt package with session key
            var aes = new AESEncryption();
            byte[] encryptedPackage = aes.Encrypt(packageData, sessionKey, Models.EncryptionMode.CBC);

            // Encrypt session key with consumer's public key
            byte[] encryptedSessionKey = DigitalSignature.Encrypt(sessionKey, consumerPublicKey);

            // Build final structure: [0x01][recipient_mode][key_length(4)][encrypted_key][encrypted_package]
            byte[] result = new byte[2 + 4 + encryptedSessionKey.Length + encryptedPackage.Length];

            result[0] = (byte)Models.EncryptionMethod.SecureEnvelope;
            result[1] = (byte)recipientMode; // NEW: Recipient mode flag
            BitConverter.GetBytes(encryptedSessionKey.Length).CopyTo(result, 2);
            encryptedSessionKey.CopyTo(result, 6);
            encryptedPackage.CopyTo(result, 6 + encryptedSessionKey.Length);

            return result;
        }

        public byte[] EncryptSymmetric(byte[] packageData, byte[] key, Models.EncryptionMode mode)
        {
            byte[] encryptedPackage = _symmetricEncryption.Encrypt(packageData, key, mode);

            // Structure: [0x02][0x00][algo_type][mode_type][encrypted_package]
            // 0x00 is placeholder for recipient mode (not used in symmetric)
            byte[] result = new byte[4 + encryptedPackage.Length];

            result[0] = (byte)Models.EncryptionMethod.Symmetric;
            result[1] = 0x00; // Placeholder for consistency
            result[2] = (byte)_symmetricEncryption.GetAlgorithmType();
            result[3] = (byte)mode;

            encryptedPackage.CopyTo(result, 4);

            return result;
        }

        public byte[] EncryptRSADirect(byte[] packageData, RSAParameters consumerPublicKey, RecipientMode recipientMode, RSAEncryptionMode rsaMode = RSAEncryptionMode.WithSignature)
        {
            if (rsaMode == RSAEncryptionMode.WithSignature)
            {
                // ORIGINAL MODE: packageData contains signature + data + MAC
                // RSA-2048 with OAEP-SHA256 can encrypt maximum 190 bytes
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

                // Structure: [0x03][recipient_mode][0x01][encrypted_package]
                byte[] result = new byte[3 + encryptedPackage.Length];
                result[0] = (byte)Models.EncryptionMethod.RSADirect;
                result[1] = (byte)recipientMode;
                result[2] = 0x01; // WithSignature flag
                encryptedPackage.CopyTo(result, 3);

                return result;
            }
            else // NoSignature - EDUCATIONAL MODE
            {
                // packageData is RAW file data (no signature, no MAC)
                // RSA-2048 with OAEP-SHA256 can encrypt maximum 190 bytes
                if (packageData.Length > 190)
                {
                    throw new InvalidOperationException(
                        $"RSA Direct (No Signature) supports only very small files.\n" +
                        $"File size: {packageData.Length} bytes\n" +
                        $"Maximum allowed: 190 bytes\n\n" +
                        $"This mode is for EDUCATIONAL purposes only.\n" +
                        $"Please use Secure Envelope for real data.");
                }

                byte[] encryptedData = DigitalSignature.Encrypt(packageData, consumerPublicKey);

                // Structure: [0x03][recipient_mode][0x00][encrypted_data]
                byte[] result = new byte[3 + encryptedData.Length];
                result[0] = (byte)Models.EncryptionMethod.RSADirect;
                result[1] = (byte)recipientMode;
                result[2] = 0x00; // NoSignature flag
                encryptedData.CopyTo(result, 3);

                return result;
            }
        }

        public EncryptionResult EncryptFile(
            string inputFilePath,
            Models.EncryptionMethod method,
            RSAParameters signingPrivateKey,
            RSAParameters? consumerPublicKey = null,
            byte[]? symmetricKey = null,
            Models.EncryptionMode symmetricMode = Models.EncryptionMode.CBC,
            RecipientMode recipientMode = RecipientMode.InternalUser,
            RSAEncryptionMode rsaMode = RSAEncryptionMode.WithSignature)
        {
            try
            {
                // Read file data
                byte[] fileData = File.ReadAllBytes(inputFilePath);
                string originalFileName = Path.GetFileName(inputFilePath);

                byte[]? encryptedData = null;

                // Handle RSA Direct (No Signature) separately
                if (method == Models.EncryptionMethod.RSADirect && rsaMode == RSAEncryptionMode.NoSignature)
                {
                    if (consumerPublicKey == null)
                        throw new ArgumentNullException("Consumer public key is required for RSA Direct");

                    // Direct RSA encryption on raw file data (NO signature, NO MAC)
                    encryptedData = EncryptRSADirect(fileData, consumerPublicKey.Value, recipientMode, RSAEncryptionMode.NoSignature);
                }
                else
                {
                    // Standard flow: Create package with signature + MAC
                    byte[] package = CreatePackage(fileData, signingPrivateKey, originalFileName);

                    // Encrypt based on method
                    switch (method)
                    {
                        case Models.EncryptionMethod.SecureEnvelope:
                            if (consumerPublicKey == null)
                                throw new ArgumentNullException("Consumer public key is required for Secure Envelope");
                            encryptedData = EncryptSecureEnvelope(package, consumerPublicKey.Value, recipientMode);
                            break;

                        case Models.EncryptionMethod.Symmetric:
                            if (symmetricKey == null)
                                throw new ArgumentNullException("Symmetric key is required");
                            encryptedData = EncryptSymmetric(package, symmetricKey, symmetricMode);
                            break;

                        case Models.EncryptionMethod.RSADirect:
                            if (consumerPublicKey == null)
                                throw new ArgumentNullException("Consumer public key is required for RSA Direct");
                            encryptedData = EncryptRSADirect(package, consumerPublicKey.Value, recipientMode, RSAEncryptionMode.WithSignature);
                            break;
                    }
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