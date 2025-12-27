# 📚 **Secure File Exchange System - Complete Documentation**

## 📖 **فهرست مطالب**

1. [معماری کلی سیستم](#1-معماری-کلی-سیستم)
2. [فلوچارت و روند کلی](#2-فلوچارت-و-روند-کلی)
3. [لایه Models](#3-لایه-models)
4. [لایه Cryptography](#4-لایه-cryptography)
5. [لایه Services](#5-لایه-services)
6. [لایه ViewModels](#6-لایه-viewmodels)
7. [لایه Views](#7-لایه-views)
8. [سناریوهای استفاده](#8-سناریوهای-استفاده)
9. [الگوریتم‌های رمزنگاری](#9-الگوریتمهای-رمزنگاری)
10. [امنیت و تهدیدات](#10-امنیت-و-تهدیدات)

---

## 1. معماری کلی سیستم

### 1.1 ساختار کلی پروژه

```
SecureFileExchange/
├── Models/                    # مدل‌های داده
├── ViewModels/                # لاجیک UI (MVVM)
├── Views/                     # رابط کاربری (XAML)
├── Services/                  # سرویس‌های اصلی
├── Cryptography/              # پیاده‌سازی الگوریتم‌های رمزنگاری
│   ├── Interfaces/            # اینترفیس‌ها
│   ├── Symmetric/             # رمزنگاری متقارن
│   └── MAC/                   # الگوریتم‌های MAC
├── Commands/                  # Command Pattern
└── Converters/                # XAML Value Converters
```

### 1.2 الگوهای طراحی استفاده شده

1. **MVVM (Model-View-ViewModel)**
   - جداسازی لاجیک از UI
   - Data Binding دو طرفه
   - INotifyPropertyChanged برای آپدیت خودکار UI

2. **Strategy Pattern**
   - `IMACAlgorithm` - انتخاب الگوریتم MAC
   - `ISymmetricEncryption` - انتخاب الگوریتم رمزنگاری متقارن

3. **Factory Pattern**
   - `CreateMACAlgorithm()`
   - `CreateSymmetricEncryption()`

4. **Singleton Pattern**
   - `SessionContext.Instance` - مدیریت session کاربر

5. **Command Pattern**
   - `RelayCommand` - اجرای دستورات از UI

---

## 2. فلوچارت و روند کلی

### 2.1 فاز 1: Authentication (ثبت‌نام/ورود)

```
START
  │
  ├─→ [User Registered?]
  │     ├─ NO → Register User
  │     │        ├─ Generate Salt (16 bytes)
  │     │        ├─ Hash = MD5(Salt + Password)
  │     │        ├─ Generate RSA Keys (2048-bit)
  │     │        │   ├─ Encryption Key Pair
  │     │        │   └─ Signing Key Pair
  │     │        ├─ Derive Key from Password: MD5(Password) → 16 bytes
  │     │        ├─ Encrypt Private Keys with AES-128-CBC
  │     │        ├─ Save to: C:\SecureFileExchange\Users\{username}\
  │     │        │   ├─ credentials.json
  │     │        │   ├─ Priv_Enc.bin
  │     │        │   ├─ Priv_Sig.bin
  │     │        │   ├─ Pub_Enc.txt
  │     │        │   └─ Pub_Sig.txt
  │     │        └─ Export: {username}_PublicKeys.txt
  │     │
  │     └─ YES → Login User
  │              ├─ Load Salt from credentials.json
  │              ├─ Verify: Hash(Salt + Input_Password) == Stored_Hash
  │              ├─ Derive Key: MD5(Password) → 16 bytes
  │              ├─ Decrypt Private Keys with AES-128-CBC
  │              ├─ Load into SessionContext
  │              └─ Enable Producer/Consumer Tabs
  │
END
```

### 2.2 فاز 2: Producer (رمزنگاری فایل)

```
START: Encrypt File
  │
  ├─→ [Select File]
  │
  ├─→ [Select MAC Algorithm]
  │     ├─ HMAC-SHA256
  │     ├─ CMAC-AES
  │     └─ CCM
  │
  ├─→ [Select Encryption Method]
  │     │
  │     ├─ [1] Secure Envelope (Recommended)
  │     │     ├─ Select Recipient:
  │     │     │   ├─ Internal User → Load from local DB
  │     │     │   └─ External User → Import Public Keys file
  │     │     │
  │     │     ├─ Read File → Data
  │     │     ├─ Extract Extension → ".ext"
  │     │     ├─ Generate MAC Key (32 bytes random)
  │     │     ├─ Calculate MAC = HMAC-SHA256(Data, MAC_Key)
  │     │     ├─ Package = [ext_len][extension][Data][MAC]
  │     │     ├─ Sign = RSA-Sign(Package, Producer_Private_Signing_Key)
  │     │     ├─ Full_Package = [sign_len][Sign][Package]
  │     │     │
  │     │     ├─ Generate Session Key (32 bytes random)
  │     │     ├─ Encrypt Package with AES-256-CBC using Session Key
  │     │     ├─ Encrypt Session Key with RSA-OAEP using Consumer Public Key
  │     │     │
  │     │     └─ Output File Format:
  │     │         [0x01][recipient_mode][key_len(4)][encrypted_session_key][encrypted_package]
  │     │
  │     ├─ [2] Symmetric Encryption
  │     │     ├─ Select Algorithm: AES / DES / 3DES
  │     │     ├─ Select Mode: CBC / ECB
  │     │     ├─ Select Key Source:
  │     │     │   ├─ Password → Derive Key: MD5(Password)
  │     │     │   └─ File → Hash File: SHA256(FileBytes)
  │     │     │
  │     │     ├─ Create Package (same as Secure Envelope)
  │     │     ├─ Encrypt Package with Symmetric Algorithm
  │     │     │
  │     │     └─ Output File Format:
  │     │         [0x02][0x00][algo_type][mode_type][encrypted_package]
  │     │
  │     └─ [3] RSA Direct
  │           ├─ Select Mode:
  │           │   ├─ With Signature (Standard)
  │           │   │   ├─ Create Package with Signature + MAC
  │           │   │   ├─ Check Size: Package <= 190 bytes
  │           │   │   ├─ Encrypt with RSA-OAEP
  │           │   │   └─ Output: [0x03][recipient_mode][0x01][encrypted]
  │           │   │
  │           │   └─ No Signature (Educational)
  │           │       ├─ NO Package creation
  │           │       ├─ Check Size: Raw Data <= 190 bytes
  │           │       ├─ Direct RSA-OAEP(Data)
  │           │       └─ Output: [0x03][recipient_mode][0x00][encrypted]
  │           │
  │           └─ Warning: Max 190 bytes only!
  │
  └─→ Save as: {filename}.enc
  
END
```

### 2.3 فاز 3: Consumer (رمزگشایی فایل)

```
START: Decrypt File
  │
  ├─→ [Select .enc File]
  │
  ├─→ [Read Header Byte]
  │     ├─ 0x01 → Secure Envelope
  │     ├─ 0x02 → Symmetric
  │     └─ 0x03 → RSA Direct
  │
  ├─→ [Auto-detect Sender Type]
  │     ├─ Check byte[1] (Recipient Mode)
  │     │   ├─ 0x01 → Internal User
  │     │   └─ 0x02 → External User
  │     │
  │     └─ [Select Sender]
  │           ├─ Internal → Select from dropdown
  │           └─ External → Import Public Keys file
  │
  ├─→ [Decryption Process]
  │     │
  │     ├─ [1] Secure Envelope
  │     │     ├─ Read encrypted_session_key
  │     │     ├─ Decrypt Session Key with RSA-OAEP using Consumer Private Key
  │     │     ├─ Decrypt Package with AES-256-CBC using Session Key
  │     │     ├─ Extract: [sign_len][signature][ext_len][ext][Data][MAC]
  │     │     ├─ Verify Signature with Producer Public Signing Key
  │     │     ├─ Verify MAC
  │     │     └─ Extract Original Data + Extension
  │     │
  │     ├─ [2] Symmetric
  │     │     ├─ Read algo_type, mode_type
  │     │     ├─ Ask User for Password/File (same as Producer)
  │     │     ├─ Derive Key
  │     │     ├─ Decrypt Package with Selected Algorithm
  │     │     ├─ Verify Signature with Producer Public Signing Key
  │     │     ├─ Verify MAC
  │     │     └─ Extract Original Data + Extension
  │     │
  │     └─ [3] RSA Direct
  │           ├─ Check byte[2]:
  │           │   ├─ 0x01 → With Signature
  │           │   │   ├─ Decrypt with RSA-OAEP
  │           │   │   ├─ Verify Signature
  │           │   │   ├─ Verify MAC
  │           │   │   └─ Extract Data + Extension
  │           │   │
  │           │   └─ 0x00 → No Signature (Educational)
  │           │       ├─ Decrypt with RSA-OAEP
  │           │       ├─ NO Signature verification
  │           │       ├─ NO MAC verification
  │           │       └─ Return Raw Data
  │           │           └─ Display Warning: "NOT authenticated!"
  │           │
  │           └─ Save as: {filename}_decrypted{.ext}
  │
END
```

---

## 3. لایه Models

### 3.1 `UserIdentity.cs`

**هدف:** نگهداری اطلاعات هویتی کاربر (Identity)

```csharp
public class UserIdentity
{
    public string Username { get; set; }                    // نام کاربری
    public RSAParameters EncryptionPublicKey { get; set; }  // کلید عمومی رمزنگاری
    public RSAParameters SigningPublicKey { get; set; }     // کلید عمومی امضا
    public RSAParameters? EncryptionPrivateKey { get; set; }// کلید خصوصی رمزنگاری (nullable)
    public RSAParameters? SigningPrivateKey { get; set; }   // کلید خصوصی امضا (nullable)
    public string UserDirectory { get; set; }               // مسیر فولدر کاربر
}
```

**توضیحات:**
- `RSAParameters`: ساختار .NET برای نگهداری کلیدهای RSA
- کلیدهای خصوصی فقط برای کاربر لاگین شده لود می‌شن
- کلیدهای عمومی برای همه قابل دسترسی هستن

### 3.2 `SessionContext.cs` (Singleton)

**هدف:** مدیریت session کاربر لاگین شده

```csharp
public class SessionContext
{
    private static SessionContext? _instance;
    public UserIdentity? CurrentUser { get; private set; }
    public bool IsAuthenticated => CurrentUser != null;
    
    public void Login(UserIdentity user) { ... }
    public void Logout() { ... }
}
```

**روند کار:**
1. بعد از Login موفق، `CurrentUser` مقدار می‌گیره
2. تمام صفحات به `SessionContext.Instance.CurrentUser` دسترسی دارن
3. بعد از Logout، کلیدهای خصوصی از حافظه پاک می‌شن (Security)

### 3.3 `EncryptionMethod.cs`

**Enum برای روش‌های رمزنگاری:**

```csharp
public enum EncryptionMethod
{
    SecureEnvelope = 0x01,  // RSA + AES Hybrid
    Symmetric = 0x02,       // AES/DES/3DES فقط
    RSADirect = 0x03        // RSA مستقیم (محدود)
}

public enum SymmetricAlgorithmType
{
    AES = 0x01,       // AES-256
    DES = 0x02,       // DES (ناامن، برای آموزش)
    TripleDES = 0x03  // 3DES
}

public enum EncryptionMode
{
    CBC = 0x01,  // Cipher Block Chaining (امن)
    ECB = 0x02   // Electronic Codebook (ناامن، برای آموزش)
}

public enum MACAlgorithmType
{
    HMACSHA256,  // استاندارد، امن
    CMAC,        // برای آموزش
    CCM          // برای آموزش
}

public enum RecipientMode : byte
{
    InternalUser = 0x01,      // کاربر داخلی (همان سیستم)
    ExternalPublicKey = 0x02  // کاربر خارجی (سیستم دیگر)
}

public enum RSAEncryptionMode
{
    WithSignature,  // شامل امضا و MAC (امن)
    NoSignature     // بدون امضا و MAC (آموزشی، ناامن)
}
```

### 3.4 `ExternalPublicKeys.cs`

**هدف:** نگهداری کلیدهای عمومی کاربر خارجی

```csharp
public class ExternalPublicKeys
{
    public string Username { get; set; }
    public RSAParameters EncryptionPublicKey { get; set; }
    public RSAParameters SigningPublicKey { get; set; }
    public string SourceFile { get; set; }  // مسیر فایل .txt
}
```

**کاربرد:**
- وقتی Producer می‌خواد برای کاربر External رمزنگاری کنه
- فایل `{Username}_PublicKeys.txt` import می‌شه و به این کلاس map می‌شه

### 3.5 `EncryptionResult` & `DecryptionResult`

```csharp
public class EncryptionResult
{
    public bool Success { get; set; }
    public string Message { get; set; }
    public byte[]? EncryptedData { get; set; }
    public string? OutputPath { get; set; }
}
```

**روند:**
- سرویس‌ها به جای throw کردن exception، این کلاس رو برمی‌گردونن
- UI می‌تونه پیغام خطا یا موفقیت رو نمایش بده

---

## 4. لایه Cryptography

### 4.1 `KeyManager.cs`

**وظایف:**
1. تولید کلیدهای RSA
2. Export/Import کلیدها (Base64)
3. رمزگذاری/رمزگشایی کلید خصوصی

#### متد `GenerateRSAKeyPair`

```csharp
public static RSAParameters GenerateRSAKeyPair(
    out RSAParameters publicKey, 
    out RSAParameters privateKey)
{
    using (var rsa = RSA.Create(2048))  // RSA-2048
    {
        privateKey = rsa.ExportParameters(true);   // شامل D, P, Q, ...
        publicKey = rsa.ExportParameters(false);   // فقط Modulus & Exponent
        return privateKey;
    }
}
```

**توضیحات:**
- **RSA-2048:** امنیت معادل 112-bit Symmetric
- **Private Key شامل:** Modulus (n), Exponent (e), D, P, Q, DP, DQ, InverseQ
- **Public Key شامل:** فقط Modulus (n) و Exponent (e)

#### متد `EncryptPrivateKey`

```csharp
public static byte[] EncryptPrivateKey(byte[] privateKeyBytes, byte[] password)
{
    using (var aes = Aes.Create())
    {
        aes.Key = password;  // 16 bytes از MD5(Password)
        aes.GenerateIV();    // IV تصادفی 16 بایتی
        
        using (var encryptor = aes.CreateEncryptor())
        {
            byte[] encrypted = encryptor.TransformFinalBlock(privateKeyBytes, 0, privateKeyBytes.Length);
            
            // ترکیب: [IV(16)] + [Encrypted_Data]
            byte[] result = new byte[16 + encrypted.Length];
            Array.Copy(aes.IV, 0, result, 0, 16);
            Array.Copy(encrypted, 0, result, 16, encrypted.Length);
            
            return result;
        }
    }
}
```

**فرآیند:**
1. Password → MD5 → 16 bytes key
2. IV تصادفی تولید می‌شه (هر بار متفاوت)
3. AES-128-CBC برای رمزگذاری
4. IV به ابتدای فایل اضافه می‌شه (برای Decrypt)

### 4.2 `DigitalSignature.cs`

**الگوریتم:** RSA-SHA256 with PKCS#1 v1.5 Padding

#### متد `Sign`

```csharp
public static byte[] Sign(byte[] data, RSAParameters privateKey)
{
    using (var rsa = RSA.Create())
    {
        rsa.ImportParameters(privateKey);
        return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }
}
```

**فرآیند:**
1. Hash = SHA256(data)
2. Signature = RSA-Encrypt(Hash, Private_Key)
3. اندازه: 256 bytes (برای RSA-2048)

#### متد `Verify`

```csharp
public static bool Verify(byte[] data, byte[] signature, RSAParameters publicKey)
{
    using (var rsa = RSA.Create())
    {
        rsa.ImportParameters(publicKey);
        return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }
}
```

**فرآیند:**
1. Hash = SHA256(data)
2. Decrypted_Hash = RSA-Decrypt(Signature, Public_Key)
3. return Hash == Decrypted_Hash

#### متد `Encrypt` (RSA-OAEP)

```csharp
public static byte[] Encrypt(byte[] data, RSAParameters publicKey)
{
    using (var rsa = RSA.Create())
    {
        rsa.ImportParameters(publicKey);
        return rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
    }
}
```

**محدودیت:**
- RSA-2048 + OAEP-SHA256 → حداکثر **190 bytes** plaintext
- فرمول: `MaxSize = (KeySize / 8) - 2 * HashSize - 2`
- `(2048 / 8) - 2 * 32 - 2 = 256 - 66 = 190 bytes`

### 4.3 `CryptoUtils.cs`

#### متد `DeriveKeyFromPassword`

```csharp
public static byte[] DeriveKeyFromPassword(string password, int keyLength)
{
    byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
    
    if (keyLength == 32)  // AES-256
    {
        using (var sha256 = SHA256.Create())
        {
            return sha256.ComputeHash(passwordBytes);  // 32 bytes
        }
    }
    else if (keyLength == 16)  // AES-128, DES
    {
        byte[] hash = ComputeMD5(passwordBytes);  // 16 bytes
        return hash;
    }
    else if (keyLength == 24)  // 3DES
    {
        byte[] hash = ComputeMD5(passwordBytes);  // 16 bytes
        byte[] key = new byte[24];
        Array.Copy(hash, 0, key, 0, 16);
        Array.Copy(hash, 0, key, 16, 8);  // تکرار 8 بایت اول
        return key;
    }
}
```

**توضیحات:**
- **AES-256:** SHA256(Password) → 32 bytes
- **AES-128/DES:** MD5(Password) → 16 bytes (برای DES فقط 8 بایت اول استفاده می‌شه)
- **3DES:** MD5(Password) + repeat → 24 bytes

**نکته امنیتی:**
- این روش **PBKDF2** استفاده نمی‌کنه (برای سادگی آموزشی)
- در پروژه واقعی باید از `Rfc2898DeriveBytes` استفاده بشه

### 4.4 لایه Symmetric

#### `AESEncryption.cs`

```csharp
public class AESEncryption : ISymmetricEncryption
{
    public byte[] Encrypt(byte[] data, byte[] key, EncryptionMode mode)
    {
        using (var aes = Aes.Create())
        {
            aes.Key = key;  // 32 bytes (AES-256)
            aes.Mode = (mode == EncryptionMode.CBC) ? CipherMode.CBC : CipherMode.ECB;
            aes.Padding = PaddingMode.PKCS7;
            
            byte[] iv = null;
            if (mode == EncryptionMode.CBC)
            {
                aes.GenerateIV();  // 16 bytes random
                iv = aes.IV;
            }
            
            using (var encryptor = aes.CreateEncryptor())
            using (var ms = new MemoryStream())
            {
                if (iv != null)
                {
                    ms.Write(iv, 0, iv.Length);  // IV در ابتدا
                }
                
                using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    cs.Write(data, 0, data.Length);
                    cs.FlushFinalBlock();
                }
                
                return ms.ToArray();  // [IV(16)] + [Ciphertext]
            }
        }
    }
}
```

**فرآیند CBC:**
```
Block 1: C1 = AES_Encrypt(P1 XOR IV)
Block 2: C2 = AES_Encrypt(P2 XOR C1)
Block 3: C3 = AES_Encrypt(P3 XOR C2)
...
```

**فرآیند ECB (ناامن):**
```
Block 1: C1 = AES_Encrypt(P1)
Block 2: C2 = AES_Encrypt(P2)
Block 3: C3 = AES_Encrypt(P3)
```
⚠️ **هشدار:** ECB الگوهای plaintext رو حفظ می‌کنه (برای آموزش)

#### `TripleDESEncryption.cs`

**الگوریتم:** 3DES-EDE (Encrypt-Decrypt-Encrypt)

```
Key = K1 || K2 || K3  (24 bytes)

Encrypt: C = DES_Encrypt(K3, DES_Decrypt(K2, DES_Encrypt(K1, P)))
Decrypt: P = DES_Decrypt(K1, DES_Encrypt(K2, DES_Decrypt(K3, C)))
```

**توضیحات:**
- Block Size: 8 bytes (نه 16 مثل AES)
- IV Size: 8 bytes
- Key Size: 24 bytes (3 کلید 8 بایتی)

### 4.5 لایه MAC

#### `HMACSHA256Algorithm.cs`

**الگوریتم:** HMAC-SHA256

```csharp
public byte[] Calculate(byte[] data, byte[] key)
{
    using (var hmac = new HMACSHA256(key))
    {
        return hmac.ComputeHash(data);  // 32 bytes output
    }
}
```

**فرآیند HMAC:**
```
ipad = 0x36 repeated 64 times
opad = 0x5C repeated 64 times

HMAC(K, M) = H((K ⊕ opad) || H((K ⊕ ipad) || M))

where:
  K = key (padded to 64 bytes)
  M = message
  H = SHA256
  || = concatenation
  ⊕ = XOR
```

**امنیت:**
- Length Extension Attack رو می‌گیره
- Collision Resistance از SHA256

---

## 5. لایه Services

### 5.1 `UserIdentityManager.cs`

#### متد `RegisterUser`

```csharp
public static void RegisterUser(string username, string password)
{
    // 1. Generate Salt
    byte[] salt = CryptoUtils.GenerateRandomBytes(16);
    
    // 2. Hash Password
    byte[] saltPassword = salt.Concat(Encoding.UTF8.GetBytes(password)).ToArray();
    byte[] hash = CryptoUtils.ComputeMD5(saltPassword);
    
    // 3. Save Credentials
    var credentials = new UserCredentials
    {
        Username = username,
        Salt = Convert.ToBase64String(salt),
        PasswordHash = Convert.ToBase64String(hash)
    };
    File.WriteAllText(credPath, JsonSerializer.Serialize(credentials));
    
    // 4. Generate RSA Keys (ONCE, NEVER REGENERATE!)
    KeyManager.GenerateRSAKeyPair(out var pubKeyEnc, out var privKeyEnc);
    KeyManager.GenerateRSAKeyPair(out var pubKeySig, out var privKeySig);
    
    // 5. Derive AES Key from Password
    byte[] passwordKey = CryptoUtils.DeriveKeyFromPassword(password, 16);
    
    // 6. Encrypt Private Keys
    byte[] privKeyEncBytes = KeyManager.ExportPrivateKeyToBytes(privKeyEnc);
    byte[] privKeySigBytes = KeyManager.ExportPrivateKeyToBytes(privKeySig);
    
    var aes = new AESEncryption();
    byte[] encPrivKeyEnc = aes.Encrypt(privKeyEncBytes, passwordKey, EncryptionMode.CBC);
    byte[] encPrivKeySig = aes.Encrypt(privKeySigBytes, passwordKey, EncryptionMode.CBC);
    
    // 7. Save Files
    File.WriteAllBytes(Path.Combine(userDir, "Priv_Enc.bin"), encPrivKeyEnc);
    File.WriteAllBytes(Path.Combine(userDir, "Priv_Sig.bin"), encPrivKeySig);
    File.WriteAllText(Path.Combine(userDir, "Pub_Enc.txt"), pubKeyEncStr);
    File.WriteAllText(Path.Combine(userDir, "Pub_Sig.txt"), pubKeySigStr);
}
```

**ساختار فولدر:**
```
C:\SecureFileExchange\Users\
  └── Ali\
      ├── credentials.json        # {username, salt, hash}
      ├── Priv_Enc.bin           # Encrypted Encryption Private Key
      ├── Priv_Sig.bin           # Encrypted Signing Private Key
      ├── Pub_Enc.txt            # Encryption Public Key (Base64)
      ├── Pub_Sig.txt            # Signing Public Key (Base64)
      └── Ali_PublicKeys.txt     # برای Share کردن
```

#### متد `LoginUser`

```csharp
public static UserIdentity? LoginUser(string username, string password)
{
    // 1. Load Credentials
    var credentials = JsonSerializer.Deserialize<UserCredentials>(credJson);
    
    // 2. Verify Password
    byte[] salt = Convert.FromBase64String(credentials.Salt);
    byte[] inputHash = MD5(salt + password);
    byte[] storedHash = Convert.FromBase64String(credentials.PasswordHash);
    
    if (!inputHash.SequenceEqual(storedHash))
        throw new InvalidOperationException("Invalid password");
    
    // 3. Derive AES Key
    byte[] passwordKey = DeriveKeyFromPassword(password, 16);
    
    // 4. Decrypt Private Keys
    byte[] encPrivKeyEnc = File.ReadAllBytes("Priv_Enc.bin");
    byte[] encPrivKeySig = File.ReadAllBytes("Priv_Sig.bin");
    
    var aes = new AESEncryption();
    byte[] privKeyEncBytes = aes.Decrypt(encPrivKeyEnc, passwordKey, EncryptionMode.CBC);
    byte[] privKeySigBytes = aes.Decrypt(encPrivKeySig, passwordKey, EncryptionMode.CBC);
    
    // 5. Import Keys
    RSAParameters privKeyEnc = KeyManager.ImportPrivateKeyFromBytes(privKeyEncBytes);
    RSAParameters privKeySig = KeyManager.ImportPrivateKeyFromBytes(privKeySigBytes);
    
    // 6. Return UserIdentity
    return new UserIdentity
    {
        Username = username,
        EncryptionPrivateKey = privKeyEnc,
        SigningPrivateKey = privKeySig,
        // Load public keys too...
    };
}
```

### 5.2 `Encryptor.cs`

این کلاس **قلب سیستم رمزنگاری** هست.

#### متد `CreatePackage`

```csharp
public byte[] CreatePackage(byte[] fileData, RSAParameters privateKeySigning, string originalFileName)
{
    // Step 1: Extract Extension
    string extension = Path.GetExtension(originalFileName);  // e.g., ".pdf"
    if (string.IsNullOrEmpty(extension))
        extension = ".bin";
    
    byte[] extensionBytes = Encoding.UTF8.GetBytes(extension);
    byte extensionLength = (byte)Math.Min(extensionBytes.Length, 255);
    
    // Step 2: Calculate MAC
    byte[] macKey = CryptoUtils.GenerateRandomBytes(32);  // Random key
    byte[] mac = _macAlgorithm.Calculate(fileData, macKey);  // 32 bytes
    
    // Step 3: Build Package
    // [ext_len(1)] + [extension(n)] + [fileData] + [MAC(32)]
    byte[] dataWithMac = new byte[1 + extensionLength + fileData.Length + mac.Length];
    
    dataWithMac[0] = extensionLength;
    Array.Copy(extensionBytes, 0, dataWithMac, 1, extensionLength);
    Array.Copy(fileData, 0, dataWithMac, 1 + extensionLength, fileData.Length);
    Array.Copy(mac, 0, dataWithMac, 1 + extensionLength + fileData.Length, mac.Length);
    
    // Step 4: Sign Package
    byte[] signature = DigitalSignature.Sign(dataWithMac, privateKeySigning);
    
    // Step 5: Final Package Structure
    // [signature_length(4)] + [signature(256)] + [dataWithMac]
    byte[] package = new byte[4 + signature.Length + dataWithMac.Length];
    
    BitConverter.GetBytes(signature.Length).CopyTo(package, 0);
    signature.CopyTo(package, 4);
    dataWithMac.CopyTo(package, 4 + signature.Length);
    
    return package;
}
```

**ساختار Package:**
```
[0-3]:    Signature Length (int) = 256
[4-259]:  Digital Signature (256 bytes for RSA-2048)
[260]:    Extension Length (1 byte)
[261-n]:  Extension string (e.g., ".pdf")
[n+1-m]:  Original File Data
[m+1-m+32]: MAC (32 bytes)
```

#### متد `EncryptSecureEnvelope`

```csharp
public byte[] EncryptSecureEnvelope(byte[] packageData, RSAParameters consumerPublicKey, RecipientMode recipientMode)
{
    // Step 1: Generate Random Session Key
    byte[] sessionKey = CryptoUtils.GenerateRandomBytes(32);  // 256-bit AES key
    
    // Step 2: Encrypt Package with AES-256-CBC
    var aes = new AESEncryption();
    byte[] encryptedPackage = aes.Encrypt(packageData, sessionKey, EncryptionMode.CBC);
    // Output: [IV(16)] + [Ciphertext]
    
    // Step 3: Encrypt Session Key with Consumer's Public Key
    byte[] encryptedSessionKey = DigitalSignature.Encrypt(sessionKey, consumerPublicKey);
    // Output: 256 bytes (RSA-2048)
    
    // Step 4: Build Final Structure
    // [0x01][recipient_mode][key_length(4)][encrypted_key][encrypted_package]
    byte[] result = new byte[2 + 4 + encryptedSessionKey.Length + encryptedPackage.Length];
    
    result[0] = (byte)EncryptionMethod.SecureEnvelope;  // 0x01
    result[1] = (byte)recipientMode;                     // 0x01 or 0x02
    BitConverter.GetBytes(encryptedSessionKey.Length).CopyTo(result, 2);  // 256
    encryptedSessionKey.CopyTo(result, 6);
    encryptedPackage.CopyTo(result, 6 + encryptedSessionKey.Length);
    
    return result;
}
```

**چرا Secure Envelope؟**
1. **Performance:** RSA خیلی کنده (10-1000x کندتر از AES)
2. **Size Limit:** RSA-2048 حداکثر 190 بایت می‌تونه encrypt کنه
3. **Hybrid Solution:** 
   - Session Key با RSA رمز می‌شه (256 bytes overhead)
   - فایل با AES رمز می‌شه (سریع و بدون محدودیت سایز)

#### متد `EncryptRSADirect`

```csharp
public byte[] EncryptRSADirect(byte[] packageData, RSAParameters consumerPublicKey, RecipientMode recipientMode, RSAEncryptionMode rsaMode)
{
    if (rsaMode == RSAEncryptionMode.WithSignature)
    {
        // MODE 1: Standard (with Signature + MAC)
        if (packageData.Length > 190)
            throw new InvalidOperationException("Package too large!");
        
        byte[] encrypted = DigitalSignature.Encrypt(packageData, consumerPublicKey);
        
        // [0x03][recipient_mode][0x01][encrypted]
        byte[] result = new byte[3 + encrypted.Length];
        result[0] = 0x03;
        result[1] = (byte)recipientMode;
        result[2] = 0x01;  // WithSignature flag
        encrypted.CopyTo(result, 3);
        
        return result;
    }
    else
    {
        // MODE 2: Educational (NO Signature, NO MAC)
        // packageData is RAW file data
        if (packageData.Length > 190)
            throw new InvalidOperationException("File too large! Max 190 bytes.");
        
        byte[] encrypted = DigitalSignature.Encrypt(packageData, consumerPublicKey);
        
        // [0x03][recipient_mode][0x00][encrypted]
        byte[] result = new byte[3 + encrypted.Length];
        result[0] = 0x03;
        result[1] = (byte)recipientMode;
        result[2] = 0x00;  // NoSignature flag
        encrypted.CopyTo(result, 3);
        
        return result;
    }
}
```

**مقایسه دو حالت:**

| Feature | WithSignature (0x01) | NoSignature (0x00) |
|---------|---------------------|-------------------|
| Input | Package (with Signature+MAC) | Raw File Data |
| Max Size | ~0-2 bytes file | 0-190 bytes file |
| Security | ✅ Authenticated | ❌ NOT Authenticated |
| Use Case | Production | Educational Only |

### 5.3 `Decryptor.cs`

#### متد `DecryptSecureEnvelope`

```csharp
private byte[] DecryptSecureEnvelope(byte[] encryptedData, RSAParameters privateKey)
{
    // Step 1: Parse Structure
    // [0x01][mode][key_len(4)][encrypted_key][encrypted_package]
    
    int keyLength = BitConverter.ToInt32(encryptedData, 2);  // Read bytes 2-5
    
    // Step 2: Extract Encrypted Session Key
    byte[] encryptedSessionKey = new byte[keyLength];
    Array.Copy(encryptedData, 6, encryptedSessionKey, 0, keyLength);
    
    // Step 3: Extract Encrypted Package
    byte[] encryptedPackage = new byte[encryptedData.Length - 6 - keyLength];
    Array.Copy(encryptedData, 6 + keyLength, encryptedPackage, 0, encryptedPackage.Length);
    
    // Step 4: Decrypt Session Key with RSA
    byte[] sessionKey = DigitalSignature.Decrypt(encryptedSessionKey, privateKey);
    
    // Step 5: Decrypt Package with AES
    var aes = new AESEncryption();
    byte[] package = aes.Decrypt(encryptedPackage, sessionKey, EncryptionMode.CBC);
    
    return package;  // Returns Package with Signature + Data + MAC
}
```

#### متد `VerifyAndExtractData`

```csharp
public (byte[] originalData, string extension) VerifyAndExtractData(byte[] packageData, RSAParameters publicKeySigning)
{
    // Step 1: Extract Signature
    int signatureLength = BitConverter.ToInt32(packageData, 0);
    byte[] signature = new byte[signatureLength];
    Array.Copy(packageData, 4, signature, 0, signatureLength);
    
    // Step 2: Extract Data with Extension + MAC
    byte[] dataWithExtensionAndMac = new byte[packageData.Length - 4 - signatureLength];
    Array.Copy(packageData, 4 + signatureLength, dataWithExtensionAndMac, 0, dataWithExtensionAndMac.Length);
    
    // Step 3: VERIFY SIGNATURE
    bool isValid = DigitalSignature.Verify(dataWithExtensionAndMac, signature, publicKeySigning);
    if (!isValid)
        throw new InvalidOperationException("Digital signature verification FAILED!");
    
    // Step 4: Extract Extension
    byte extensionLength = dataWithExtensionAndMac[0];
    byte[] extensionBytes = new byte[extensionLength];
    Array.Copy(dataWithExtensionAndMac, 1, extensionBytes, 0, extensionLength);
    string extension = Encoding.UTF8.GetString(extensionBytes);
    
    // Step 5: Extract Original Data (remove MAC - last 32 bytes)
    int macLength = 32;
    int dataStart = 1 + extensionLength;
    int dataLength = dataWithExtensionAndMac.Length - dataStart - macLength;
    
    byte[] originalData = new byte[dataLength];
    Array.Copy(dataWithExtensionAndMac, dataStart, originalData, 0, dataLength);
    
    // TODO: Verify MAC (currently not implemented in full)
    
    return (originalData, extension);
}
```

### 5.4 `PublicKeyExchangeService.cs`

#### متد `ExportPublicKeys`

```csharp
public static string ExportPublicKeys(UserIdentity user)
{
    string filename = $"{user.Username}_PublicKeys.txt";
    string filepath = Path.Combine(ExportDirectory, filename);
    
    string encryptionKey = KeyManager.ExportPublicKeyToString(user.EncryptionPublicKey);
    string signingKey = KeyManager.ExportPublicKeyToString(user.SigningPublicKey);
    
    var content = $@"
===== PUBLIC KEYS FOR: {user.Username} =====
Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}

--- ENCRYPTION PUBLIC KEY ---
{encryptionKey}

--- SIGNING PUBLIC KEY ---
{signingKey}

===== END OF PUBLIC KEYS =====
";
    
    File.WriteAllText(filepath, content);
    return filepath;
}
```

**فرمت فایل خروجی:**
```
===== PUBLIC KEYS FOR: Ali =====
Generated: 2025-01-15 14:30:00

--- ENCRYPTION PUBLIC KEY ---
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwJ...
(Base64 encoded)

--- SIGNING PUBLIC KEY ---
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzT...
(Base64 encoded)

===== END OF PUBLIC KEYS =====
```

**کاربرد:**
1. Ali این فایل رو Export می‌کنه
2. Ali این فایل رو به Behnam می‌ده (USB, Email, etc.)
3. Behnam این فایل رو Import می‌کنه
4. Behnam حالا می‌تونه برای Ali رمزنگاری کنه (External mode)

---

## 6. لایه ViewModels

### 6.1 `BaseViewModel.cs`

**الگوی MVVM:** پیاده‌سازی `INotifyPropertyChanged`

```csharp
public class BaseViewModel : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    protected bool SetProperty<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (Equals(field, value)) return false;
        field = value;
        OnPropertyChanged(propertyName);
        return true;
    }
}
```

**چرا این الگو؟**
- وقتی Property تغییر می‌کنه، UI خودکار آپدیت می‌شه
- Two-way binding بین ViewModel و View

**مثال:**
```csharp
private string _username;
public string Username
{
    get => _username;
    set => SetProperty(ref _username, value);  // Fires PropertyChanged
}
```
در XAML:
```xml
<TextBox Text="{Binding Username, UpdateSourceTrigger=PropertyChanged}"/>
```

### 6.2 `AuthenticationViewModel.cs`

#### Properties

```csharp
private string _username = string.Empty;
private string _password = string.Empty;
private string _statusMessage = string.Empty;
private bool _isLoginMode = true;

public ICommand RegisterCommand { get; }
public ICommand LoginCommand { get; }
public ICommand SwitchModeCommand { get; }

public event EventHandler<bool>? AuthenticationCompleted;
```

#### متد `Register`

```csharp
private void Register()
{
    // 1. Validate Input
    if (string.IsNullOrWhiteSpace(Username))
    {
        StatusMessage = "Username cannot be empty";
        return;
    }
    
    if (Password.Length < 4)
    {
        StatusMessage = "Password must be at least 4 characters";
        return;
    }
    
    // 2. Call Service
    try
    {
        UserIdentityManager.RegisterUser(Username, Password);
        
        StatusMessage = $"User '{Username}' registered successfully!";
        
        // 3. Show Info
        MessageBox.Show(
            $"Registration successful!\n" +
            $"Your public keys: C:\\SecureFileExchange\\Users\\{Username}\\{Username}_PublicKeys.txt",
            "Success"
        );
        
        // 4. Auto-Login
        AutoLogin();
    }
    catch (Exception ex)
    {
        StatusMessage = $"Registration failed: {ex.Message}";
    }
}
```

#### متد `Login`

```csharp
private void Login()
{
    try
    {
        // 1. Call Service
        var user = UserIdentityManager.LoginUser(Username, Password);
        
        if (user == null)
        {
            StatusMessage = "Login failed";
            return;
        }
        
        // 2. Set Session
        SessionContext.Instance.Login(user);
        
        StatusMessage = $"Logged in as: {Username}";
        
        // 3. Notify UI (MainWindow will enable Producer/Consumer tabs)
        AuthenticationCompleted?.Invoke(this, true);
        
        // 4. Clear password from memory
        Password = string.Empty;
    }
    catch (Exception ex)
    {
        StatusMessage = $"Login failed: {ex.Message}";
    }
}
```

### 6.3 `ProducerViewModel.cs`

#### Properties

```csharp
private string _selectedFilePath = string.Empty;
private string _selectedConsumerUsername = string.Empty;
private string _externalPublicKeyPath = string.Empty;
private EncryptionMethod _selectedMethod = EncryptionMethod.SecureEnvelope;
private SymmetricAlgorithmType _selectedAlgorithm = SymmetricAlgorithmType.AES;
private EncryptionMode _selectedMode = EncryptionMode.CBC;
private MACAlgorithmType _selectedMACAlgorithm = MACAlgorithmType.HMACSHA256;
private RecipientType _recipientType = RecipientType.Internal;
private RSAEncryptionMode _rsaEncryptionMode = RSAEncryptionMode.WithSignature;

public ObservableCollection<string> AvailableUsers { get; }
```

**`ObservableCollection`:** وقتی item اضافه/حذف می‌شه، UI خودکار آپدیت می‌شه

#### متد `Encrypt`

```csharp
private void Encrypt()
{
    // 1. Validate File Selection
    if (string.IsNullOrWhiteSpace(SelectedFilePath))
    {
        MessageBox.Show("Please select a file", "Error");
        return;
    }
    
    Progress = 10;
    StatusMessage = "Loading keys...";
    
    // 2. Get Current User
    var currentUser = SessionContext.Instance.CurrentUser;
    if (currentUser?.SigningPrivateKey == null)
    {
        MessageBox.Show("Please login first", "Error");
        return;
    }
    
    Progress = 30;
    StatusMessage = "Creating package...";
    
    // 3. Create Encryptor
    var encryptor = new Encryptor(SelectedMACAlgorithm, SelectedAlgorithm);
    
    RSAParameters? consumerPublicKey = null;
    byte[]? symmetricKey = null;
    RecipientMode recipientMode = RecipientMode.InternalUser;
    
    // 4. Handle Different Methods
    if (SelectedMethod == EncryptionMethod.SecureEnvelope || 
        SelectedMethod == EncryptionMethod.RSADirect)
    {
        if (RecipientType == RecipientType.Internal)
        {
            // Load from local DB
            var consumer = UserIdentityManager.LoadPublicKeysOnly(SelectedConsumerUsername);
            consumerPublicKey = consumer.EncryptionPublicKey;
            recipientMode = RecipientMode.InternalUser;
        }
        else
        {
            // Load from imported file
            consumerPublicKey = _loadedExternalKeys.EncryptionPublicKey;
            recipientMode = RecipientMode.ExternalPublicKey;
        }
    }
    else if (SelectedMethod == EncryptionMethod.Symmetric)
    {
        if (KeyGenMethod == KeyGenerationMethod.Password)
        {
            int keyLength = SelectedAlgorithm == SymmetricAlgorithmType.AES ? 32 : 24;
            symmetricKey = CryptoUtils.DeriveKeyFromPassword(SharedPassword, keyLength);
        }
        else
        {
            int keyLength = SelectedAlgorithm == SymmetricAlgorithmType.AES ? 32 : 24;
            symmetricKey = CryptoUtils.DeriveKeyFromFile(SharedKeyFilePath, keyLength);
        }
    }
    
    Progress = 60;
    StatusMessage = "Encrypting...";
    
    // 5. Encrypt
    var result = encryptor.EncryptFile(
        SelectedFilePath,
        SelectedMethod,
        currentUser.SigningPrivateKey.Value,
        consumerPublicKey,
        symmetricKey,
        SelectedMode,
        recipientMode,
        RSAEncryptionMode
    );
    
    Progress = 100;
    
    // 6. Show Result
    if (result.Success)
    {
        MessageBox.Show($"File encrypted!\nSaved to: {result.OutputPath}", "Success");
    }
    else
    {
        MessageBox.Show(result.Message, "Error");
    }
    
    Progress = 0;
}
```

### 6.4 `ConsumerViewModel.cs`

مشابه Producer اما با تفاوت‌های زیر:
- به جای `BrowseFileCommand` → `BrowseEncryptedFileCommand`
- به جای `SelectedConsumerUsername` → `SelectedProducerUsername`
- Decrypt به جای Encrypt

---

## 7. لایه Views (UI)

### 7.1 `MainWindow.xaml`

**ساختار کلی:**

```xml
<Window>
    <Grid>
        <!-- Header (70px) -->
        <Border Height="70" VerticalAlignment="Top">
            <Grid>
                <StackPanel><!-- Logo + Title --></StackPanel>
                <StackPanel HorizontalAlignment="Right">
                    <!-- User Info + Logout Button -->
                </StackPanel>
            </Grid>
        </Border>
        
        <!-- Main Content -->
        <Grid Margin="0,70,0,0">
            <!-- Tab Navigation -->
            <Border Grid.Row="0">
                <StackPanel Orientation="Horizontal">
                    <RadioButton x:Name="AuthTab" Content="🔑 Authentication"/>
                    <RadioButton x:Name="ProducerTab" Content="📤 Encrypt File"/>
                    <RadioButton x:Name="ConsumerTab" Content="📥 Decrypt File"/>
                </StackPanel>
            </Border>
            
            <!-- Content Area -->
            <Border Grid.Row="1">
                <Grid>
                    <views:AuthenticationView x:Name="AuthenticationView" Visibility="Visible"/>
                    <views:ProducerView x:Name="ProducerView" Visibility="Collapsed"/>
                    <views:ConsumerView x:Name="ConsumerView" Visibility="Collapsed"/>
                </Grid>
            </Border>
        </Grid>
    </Grid>
</Window>
```

**Data Binding:**
```xml
<TextBlock Text="{Binding CurrentUserDisplay}"/>
```
این به `MainWindow.xaml.cs` که `INotifyPropertyChanged` پیاده کرده bind می‌شه.

### 7.2 `AuthenticationView.xaml`

**ویژگی اصلی:** ScrollViewer برای محتوای طولانی

```xml
<ScrollViewer VerticalScrollBarVisibility="Auto">
    <StackPanel Width="420">
        <Border><!-- Logo --></Border>
        <TextBlock Text="{Binding IsLoginMode, Converter={StaticResource BoolToStringConverter}, ConverterParameter='Welcome Back|Create New Account'}"/>
        
        <TextBox Text="{Binding Username}"/>
        <PasswordBox x:Name="PasswordBox"/>
        
        <Button Content="SIGN IN" 
                Command="{Binding LoginCommand}"
                Click="LoginButton_Click"
                Visibility="{Binding IsLoginMode, Converter={StaticResource BoolToVis}}"/>
        
        <Button Content="CREATE ACCOUNT"
                Command="{Binding RegisterCommand}"
                Visibility="{Binding IsLoginMode, Converter={StaticResource InverseBoolToVis}}"/>
    </StackPanel>
</ScrollViewer>
```

**PasswordBox Problem:**
- PasswordBox.Password **نمی‌تونه** Binding داشته باشه (به دلیل امنیت)
- راه حل: در Code-Behind manually منتقل می‌کنیم

```csharp
private void LoginButton_Click(object sender, RoutedEventArgs e)
{
    if (ViewModel != null)
    {
        ViewModel.Password = PasswordBox.Password;
    }
}
```

### 7.3 `ProducerView.xaml`

**بخش‌های اصلی:**

1. **Export Public Keys Button**
```xml
<Button Content="📤 Export My Public Keys"
        Command="{Binding ExportMyPublicKeysCommand}"/>
```

2. **File Selection**
```xml
<Grid>
    <TextBox Text="{Binding SelectedFilePath}" IsReadOnly="True"/>
    <Button Command="{Binding BrowseFileCommand}"/>
</Grid>
```

3. **MAC Algorithm Selection**
```xml
<ComboBox SelectedValue="{Binding SelectedMACAlgorithm}">
    <ComboBox.ItemsSource>
        <x:Array Type="models:MACAlgorithmType">
            <models:MACAlgorithmType>HMACSHA256</models:MACAlgorithmType>
            <models:MACAlgorithmType>CMAC</models:MACAlgorithmType>
            <models:MACAlgorithmType>CCM</models:MACAlgorithmType>
        </x:Array>
    </ComboBox.ItemsSource>
</ComboBox>
```

4. **Encryption Method Selection**
```xml
<StackPanel>
    <RadioButton Content="Secure Envelope"
                 IsChecked="{Binding SelectedMethod, Converter={StaticResource EnumToBoolConverter}, ConverterParameter=SecureEnvelope}"/>
    <RadioButton Content="Symmetric"
                 IsChecked="{Binding SelectedMethod, Converter={StaticResource EnumToBoolConverter}, ConverterParameter=Symmetric}"/>
    <RadioButton Content="RSA Direct"
                 IsChecked="{Binding SelectedMethod, Converter={StaticResource EnumToBoolConverter}, ConverterParameter=RSADirect}"/>
</StackPanel>
```

5. **Conditional UI (Visibility Converters)**
```xml
<!-- فقط برای Secure Envelope و RSA Direct نمایش داده می‌شه -->
<Border Visibility="{Binding SelectedMethod, Converter={StaticResource MethodToVisibilityConverter}, ConverterParameter='SecureEnvelope,RSADirect'}">
    <StackPanel>
        <!-- Recipient Type Selection -->
    </StackPanel>
</Border>

<!-- فقط برای Symmetric نمایش داده می‌شه -->
<Border Visibility="{Binding SelectedMethod, Converter={StaticResource MethodToVisibilityConverter}, ConverterParameter='Symmetric'}">
    <StackPanel>
        <!-- Symmetric Options -->
    </StackPanel>
</Border>
```

6. **RSA Direct Mode Selection**
```xml
<StackPanel>
    <RadioButton Content="With Signature &amp; MAC"
                 IsChecked="{Binding RSAEncryptionMode, Converter={StaticResource RSAEncryptionModeConverter}, ConverterParameter=WithSignature}"/>
    <RadioButton Content="No Signature (Educational)"
                 IsChecked="{Binding RSAEncryptionMode, Converter={StaticResource RSAEncryptionModeConverter}, ConverterParameter=NoSignature}"/>
</StackPanel>

<!-- Warning Box -->
<Border Visibility="{Binding RSAEncryptionMode, Converter={StaticResource RSAEncryptionModeConverter}, ConverterParameter=NoSignature}"
        Background="#2d1a1f"
        BorderBrush="#f85149">
    <TextBlock Text="⚠️ WARNING - Educational Mode Only..."/>
</Border>
```

7. **Progress Bar**
```xml
<Border Visibility="{Binding Progress, Converter={StaticResource ProgressToVisibilityConverter}}">
    <StackPanel>
        <TextBlock Text="{Binding StatusMessage}"/>
        <TextBlock Text="{Binding Progress, StringFormat={}{0}%}"/>
        <ProgressBar Value="{Binding Progress}" Maximum="100"/>
    </StackPanel>
</Border>
```

### 7.4 Value Converters

#### `EnumToBoolConverter`

```csharp
public class EnumToBoolConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value == null || parameter == null)
            return false;
        
        return value.ToString() == parameter.ToString();
    }
    
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is bool boolValue && boolValue && parameter != null)
        {
            return Enum.Parse(targetType, parameter.ToString());
        }
        
        return Binding.DoNothing;
    }
}
```

**کاربرد:**
```xml
<RadioButton IsChecked="{Binding SelectedMethod, Converter={StaticResource EnumToBoolConverter}, ConverterParameter=SecureEnvelope}"/>
```

- وقتی `SelectedMethod == EncryptionMethod.SecureEnvelope` → `IsChecked = true`
- وقتی RadioButton انتخاب می‌شه → `SelectedMethod = EncryptionMethod.SecureEnvelope`

---

## 8. سناریوهای استفاده

### سناریو 1: رمزنگاری برای کاربر Internal

**مراحل:**

1. **Ali** login می‌کنه
2. **Behnam** هم قبلاً register کرده (در همان سیستم)
3. Ali به Producer Tab می‌ره
4. فایل رو انتخاب می‌کنه
5. MAC: HMAC# 📚 **Secure File Exchange System - Complete Documentation**

## 📖 **فهرست مطالب**

1. [معماری کلی سیستم](#1-معماری-کلی-سیستم)
2. [فلوچارت و روند کلی](#2-فلوچارت-و-روند-کلی)
3. [لایه Models](#3-لایه-models)
4. [لایه Cryptography](#4-لایه-cryptography)
5. [لایه Services](#5-لایه-services)
6. [لایه ViewModels](#6-لایه-viewmodels)
7. [لایه Views](#7-لایه-views)
8. [سناریوهای استفاده](#8-سناریوهای-استفاده)
9. [الگوریتم‌های رمزنگاری](#9-الگوریتمهای-رمزنگاری)
10. [امنیت و تهدیدات](#10-امنیت-و-تهدیدات)

---

## 1. معماری کلی سیستم

### 1.1 ساختار کلی پروژه

```
SecureFileExchange/
├── Models/                    # مدل‌های داده
├── ViewModels/                # لاجیک UI (MVVM)
├── Views/                     # رابط کاربری (XAML)
├── Services/                  # سرویس‌های اصلی
├── Cryptography/              # پیاده‌سازی الگوریتم‌های رمزنگاری
│   ├── Interfaces/            # اینترفیس‌ها
│   ├── Symmetric/             # رمزنگاری متقارن
│   └── MAC/                   # الگوریتم‌های MAC
├── Commands/                  # Command Pattern
└── Converters/                # XAML Value Converters
```

### 1.2 الگوهای طراحی استفاده شده

1. **MVVM (Model-View-ViewModel)**
   - جداسازی لاجیک از UI
   - Data Binding دو طرفه
   - INotifyPropertyChanged برای آپدیت خودکار UI

2. **Strategy Pattern**
   - `IMACAlgorithm` - انتخاب الگوریتم MAC
   - `ISymmetricEncryption` - انتخاب الگوریتم رمزنگاری متقارن

3. **Factory Pattern**
   - `CreateMACAlgorithm()`
   - `CreateSymmetricEncryption()`

4. **Singleton Pattern**
   - `SessionContext.Instance` - مدیریت session کاربر

5. **Command Pattern**
   - `RelayCommand` - اجرای دستورات از UI

---

## 2. فلوچارت و روند کلی

### 2.1 فاز 1: Authentication (ثبت‌نام/ورود)

```
START
  │
  ├─→ [User Registered?]
  │     ├─ NO → Register User
  │     │        ├─ Generate Salt (16 bytes)
  │     │        ├─ Hash = MD5(Salt + Password)
  │     │        ├─ Generate RSA Keys (2048-bit)
  │     │        │   ├─ Encryption Key Pair
  │     │        │   └─ Signing Key Pair
  │     │        ├─ Derive Key from Password: MD5(Password) → 16 bytes
  │     │        ├─ Encrypt Private Keys with AES-128-CBC
  │     │        ├─ Save to: C:\SecureFileExchange\Users\{username}\
  │     │        │   ├─ credentials.json
  │     │        │   ├─ Priv_Enc.bin
  │     │        │   ├─ Priv_Sig.bin
  │     │        │   ├─ Pub_Enc.txt
  │     │        │   └─ Pub_Sig.txt
  │     │        └─ Export: {username}_PublicKeys.txt
  │     │
  │     └─ YES → Login User
  │              ├─ Load Salt from credentials.json
  │              ├─ Verify: Hash(Salt + Input_Password) == Stored_Hash
  │              ├─ Derive Key: MD5(Password) → 16 bytes
  │              ├─ Decrypt Private Keys with AES-128-CBC
  │              ├─ Load into SessionContext
  │              └─ Enable Producer/Consumer Tabs
  │
END
```

### 2.2 فاز 2: Producer (رمزنگاری فایل)

```
START: Encrypt File
  │
  ├─→ [Select File]
  │
  ├─→ [Select MAC Algorithm]
  │     ├─ HMAC-SHA256
  │     ├─ CMAC-AES
  │     └─ CCM
  │
  ├─→ [Select Encryption Method]
  │     │
  │     ├─ [1] Secure Envelope (Recommended)
  │     │     ├─ Select Recipient:
  │     │     │   ├─ Internal User → Load from local DB
  │     │     │   └─ External User → Import Public Keys file
  │     │     │
  │     │     ├─ Read File → Data
  │     │     ├─ Extract Extension → ".ext"
  │     │     ├─ Generate MAC Key (32 bytes random)
  │     │     ├─ Calculate MAC = HMAC-SHA256(Data, MAC_Key)
  │     │     ├─ Package = [ext_len][extension][Data][MAC]
  │     │     ├─ Sign = RSA-Sign(Package, Producer_Private_Signing_Key)
  │     │     ├─ Full_Package = [sign_len][Sign][Package]
  │     │     │
  │     │     ├─ Generate Session Key (32 bytes random)
  │     │     ├─ Encrypt Package with AES-256-CBC using Session Key
  │     │     ├─ Encrypt Session Key with RSA-OAEP using Consumer Public Key
  │     │     │
  │     │     └─ Output File Format:
  │     │         [0x01][recipient_mode][key_len(4)][encrypted_session_key][encrypted_package]
  │     │
  │     ├─ [2] Symmetric Encryption
  │     │     ├─ Select Algorithm: AES / DES / 3DES
  │     │     ├─ Select Mode: CBC / ECB
  │     │     ├─ Select Key Source:
  │     │     │   ├─ Password → Derive Key: MD5(Password)
  │     │     │   └─ File → Hash File: SHA256(FileBytes)
  │     │     │
  │     │     ├─ Create Package (same as Secure Envelope)
  │     │     ├─ Encrypt Package with Symmetric Algorithm
  │     │     │
  │     │     └─ Output File Format:
  │     │         [0x02][0x00][algo_type][mode_type][encrypted_package]
  │     │
  │     └─ [3] RSA Direct
  │           ├─ Select Mode:
  │           │   ├─ With Signature (Standard)
  │           │   │   ├─ Create Package with Signature + MAC
  │           │   │   ├─ Check Size: Package <= 190 bytes
  │           │   │   ├─ Encrypt with RSA-OAEP
  │           │   │   └─ Output: [0x03][recipient_mode][0x01][encrypted]
  │           │   │
  │           │   └─ No Signature (Educational)
  │           │       ├─ NO Package creation
  │           │       ├─ Check Size: Raw Data <= 190 bytes
  │           │       ├─ Direct RSA-OAEP(Data)
  │           │       └─ Output: [0x03][recipient_mode][0x00][encrypted]
  │           │
  │           └─ Warning: Max 190 bytes only!
  │
  └─→ Save as: {filename}.enc
  
END
```

### 2.3 فاز 3: Consumer (رمزگشایی فایل)

```
START: Decrypt File
  │
  ├─→ [Select .enc File]
  │
  ├─→ [Read Header Byte]
  │     ├─ 0x01 → Secure Envelope
  │     ├─ 0x02 → Symmetric
  │     └─ 0x03 → RSA Direct
  │
  ├─→ [Auto-detect Sender Type]
  │     ├─ Check byte[1] (Recipient Mode)
  │     │   ├─ 0x01 → Internal User
  │     │   └─ 0x02 → External User
  │     │
  │     └─ [Select Sender]
  │           ├─ Internal → Select from dropdown
  │           └─ External → Import Public Keys file
  │
  ├─→ [Decryption Process]
  │     │
  │     ├─ [1] Secure Envelope
  │     │     ├─ Read encrypted_session_key
  │     │     ├─ Decrypt Session Key with RSA-OAEP using Consumer Private Key
  │     │     ├─ Decrypt Package with AES-256-CBC using Session Key
  │     │     ├─ Extract: [sign_len][signature][ext_len][ext][Data][MAC]
  │     │     ├─ Verify Signature with Producer Public Signing Key
  │     │     ├─ Verify MAC
  │     │     └─ Extract Original Data + Extension
  │     │
  │     ├─ [2] Symmetric
  │     │     ├─ Read algo_type, mode_type
  │     │     ├─ Ask User for Password/File (same as Producer)
  │     │     ├─ Derive Key
  │     │     ├─ Decrypt Package with Selected Algorithm
  │     │     ├─ Verify Signature with Producer Public Signing Key
  │     │     ├─ Verify MAC
  │     │     └─ Extract Original Data + Extension
  │     │
  │     └─ [3] RSA Direct
  │           ├─ Check byte[2]:
  │           │   ├─ 0x01 → With Signature
  │           │   │   ├─ Decrypt with RSA-OAEP
  │           │   │   ├─ Verify Signature
  │           │   │   ├─ Verify MAC
  │           │   │   └─ Extract Data + Extension
  │           │   │
  │           │   └─ 0x00 → No Signature (Educational)
  │           │       ├─ Decrypt with RSA-OAEP
  │           │       ├─ NO Signature verification
  │           │       ├─ NO MAC verification
  │           │       └─ Return Raw Data
  │           │           └─ Display Warning: "NOT authenticated!"
  │           │
  │           └─ Save as: {filename}_decrypted{.ext}
  │
END
```

---

## 3. لایه Models

### 3.1 `UserIdentity.cs`

**هدف:** نگهداری اطلاعات هویتی کاربر (Identity)

```csharp
public class UserIdentity
{
    public string Username { get; set; }                    // نام کاربری
    public RSAParameters EncryptionPublicKey { get; set; }  // کلید عمومی رمزنگاری
    public RSAParameters SigningPublicKey { get; set; }     // کلید عمومی امضا
    public RSAParameters? EncryptionPrivateKey { get; set; }// کلید خصوصی رمزنگاری (nullable)
    public RSAParameters? SigningPrivateKey { get; set; }   // کلید خصوصی امضا (nullable)
    public string UserDirectory { get; set; }               // مسیر فولدر کاربر
}
```

**توضیحات:**
- `RSAParameters`: ساختار .NET برای نگهداری کلیدهای RSA
- کلیدهای خصوصی فقط برای کاربر لاگین شده لود می‌شن
- کلیدهای عمومی برای همه قابل دسترسی هستن

### 3.2 `SessionContext.cs` (Singleton)

**هدف:** مدیریت session کاربر لاگین شده

```csharp
public class SessionContext
{
    private static SessionContext? _instance;
    public UserIdentity? CurrentUser { get; private set; }
    public bool IsAuthenticated => CurrentUser != null;
    
    public void Login(UserIdentity user) { ... }
    public void Logout() { ... }
}
```

**روند کار:**
1. بعد از Login موفق، `CurrentUser` مقدار می‌گیره
2. تمام صفحات به `SessionContext.Instance.CurrentUser` دسترسی دارن
3. بعد از Logout، کلیدهای خصوصی از حافظه پاک می‌شن (Security)

### 3.3 `EncryptionMethod.cs`

**Enum برای روش‌های رمزنگاری:**

```csharp
public enum EncryptionMethod
{
    SecureEnvelope = 0x01,  // RSA + AES Hybrid
    Symmetric = 0x02,       // AES/DES/3DES فقط
    RSADirect = 0x03        // RSA مستقیم (محدود)
}

public enum SymmetricAlgorithmType
{
    AES = 0x01,       // AES-256
    DES = 0x02,       // DES (ناامن، برای آموزش)
    TripleDES = 0x03  // 3DES
}

public enum EncryptionMode
{
    CBC = 0x01,  // Cipher Block Chaining (امن)
    ECB = 0x02   // Electronic Codebook (ناامن، برای آموزش)
}

public enum MACAlgorithmType
{
    HMACSHA256,  // استاندارد، امن
    CMAC,        // برای آموزش
    CCM          // برای آموزش
}

public enum RecipientMode : byte
{
    InternalUser = 0x01,      // کاربر داخلی (همان سیستم)
    ExternalPublicKey = 0x02  // کاربر خارجی (سیستم دیگر)
}

public enum RSAEncryptionMode
{
    WithSignature,  // شامل امضا و MAC (امن)
    NoSignature     // بدون امضا و MAC (آموزشی، ناامن)
}
```

### 3.4 `ExternalPublicKeys.cs`

**هدف:** نگهداری کلیدهای عمومی کاربر خارجی

```csharp
public class ExternalPublicKeys
{
    public string Username { get; set; }
    public RSAParameters EncryptionPublicKey { get; set; }
    public RSAParameters SigningPublicKey { get; set; }
    public string SourceFile { get; set; }  // مسیر فایل .txt
}
```

**کاربرد:**
- وقتی Producer می‌خواد برای کاربر External رمزنگاری کنه
- فایل `{Username}_PublicKeys.txt` import می‌شه و به این کلاس map می‌شه

### 3.5 `EncryptionResult` & `DecryptionResult`

```csharp
public class EncryptionResult
{
    public bool Success { get; set; }
    public string Message { get; set; }
    public byte[]? EncryptedData { get; set; }
    public string? OutputPath { get; set; }
}
```

**روند:**
- سرویس‌ها به جای throw کردن exception، این کلاس رو برمی‌گردونن
- UI می‌تونه پیغام خطا یا موفقیت رو نمایش بده

---

## 4. لایه Cryptography

### 4.1 `KeyManager.cs`

**وظایف:**
1. تولید کلیدهای RSA
2. Export/Import کلیدها (Base64)
3. رمزگذاری/رمزگشایی کلید خصوصی

#### متد `GenerateRSAKeyPair`

```csharp
public static RSAParameters GenerateRSAKeyPair(
    out RSAParameters publicKey, 
    out RSAParameters privateKey)
{
    using (var rsa = RSA.Create(2048))  // RSA-2048
    {
        privateKey = rsa.ExportParameters(true);   // شامل D, P, Q, ...
        publicKey = rsa.ExportParameters(false);   // فقط Modulus & Exponent
        return privateKey;
    }
}
```

**توضیحات:**
- **RSA-2048:** امنیت معادل 112-bit Symmetric
- **Private Key شامل:** Modulus (n), Exponent (e), D, P, Q, DP, DQ, InverseQ
- **Public Key شامل:** فقط Modulus (n) و Exponent (e)

#### متد `EncryptPrivateKey`

```csharp
public static byte[] EncryptPrivateKey(byte[] privateKeyBytes, byte[] password)
{
    using (var aes = Aes.Create())
    {
        aes.Key = password;  // 16 bytes از MD5(Password)
        aes.GenerateIV();    // IV تصادفی 16 بایتی
        
        using (var encryptor = aes.CreateEncryptor())
        {
            byte[] encrypted = encryptor.TransformFinalBlock(privateKeyBytes, 0, privateKeyBytes.Length);
            
            // ترکیب: [IV(16)] + [Encrypted_Data]
            byte[] result = new byte[16 + encrypted.Length];
            Array.Copy(aes.IV, 0, result, 0, 16);
            Array.Copy(encrypted, 0, result, 16, encrypted.Length);
            
            return result;
        }
    }
}
```

**فرآیند:**
1. Password → MD5 → 16 bytes key
2. IV تصادفی تولید می‌شه (هر بار متفاوت)
3. AES-128-CBC برای رمزگذاری
4. IV به ابتدای فایل اضافه می‌شه (برای Decrypt)

### 4.2 `DigitalSignature.cs`

**الگوریتم:** RSA-SHA256 with PKCS#1 v1.5 Padding

#### متد `Sign`

```csharp
public static byte[] Sign(byte[] data, RSAParameters privateKey)
{
    using (var rsa = RSA.Create())
    {
        rsa.ImportParameters(privateKey);
        return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }
}
```

**فرآیند:**
1. Hash = SHA256(data)
2. Signature = RSA-Encrypt(Hash, Private_Key)
3. اندازه: 256 bytes (برای RSA-2048)

#### متد `Verify`

```csharp
public static bool Verify(byte[] data, byte[] signature, RSAParameters publicKey)
{
    using (var rsa = RSA.Create())
    {
        rsa.ImportParameters(publicKey);
        return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }
}
```

**فرآیند:**
1. Hash = SHA256(data)
2. Decrypted_Hash = RSA-Decrypt(Signature, Public_Key)
3. return Hash == Decrypted_Hash

#### متد `Encrypt` (RSA-OAEP)

```csharp
public static byte[] Encrypt(byte[] data, RSAParameters publicKey)
{
    using (var rsa = RSA.Create())
    {
        rsa.ImportParameters(publicKey);
        return rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
    }
}
```

**محدودیت:**
- RSA-2048 + OAEP-SHA256 → حداکثر **190 bytes** plaintext
- فرمول: `MaxSize = (KeySize / 8) - 2 * HashSize - 2`
- `(2048 / 8) - 2 * 32 - 2 = 256 - 66 = 190 bytes`

### 4.3 `CryptoUtils.cs`

#### متد `DeriveKeyFromPassword`

```csharp
public static byte[] DeriveKeyFromPassword(string password, int keyLength)
{
    byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
    
    if (keyLength == 32)  // AES-256
    {
        using (var sha256 = SHA256.Create())
        {
            return sha256.ComputeHash(passwordBytes);  // 32 bytes
        }
    }
    else if (keyLength == 16)  // AES-128, DES
    {
        byte[] hash = ComputeMD5(passwordBytes);  // 16 bytes
        return hash;
    }
    else if (keyLength == 24)  // 3DES
    {
        byte[] hash = ComputeMD5(passwordBytes);  // 16 bytes
        byte[] key = new byte[24];
        Array.Copy(hash, 0, key, 0, 16);
        Array.Copy(hash, 0, key, 16, 8);  // تکرار 8 بایت اول
        return key;
    }
}
```

**توضیحات:**
- **AES-256:** SHA256(Password) → 32 bytes
- **AES-128/DES:** MD5(Password) → 16 bytes (برای DES فقط 8 بایت اول استفاده می‌شه)
- **3DES:** MD5(Password) + repeat → 24 bytes

**نکته امنیتی:**
- این روش **PBKDF2** استفاده نمی‌کنه (برای سادگی آموزشی)
- در پروژه واقعی باید از `Rfc2898DeriveBytes` استفاده بشه

### 4.4 لایه Symmetric

#### `AESEncryption.cs`

```csharp
public class AESEncryption : ISymmetricEncryption
{
    public byte[] Encrypt(byte[] data, byte[] key, EncryptionMode mode)
    {
        using (var aes = Aes.Create())
        {
            aes.Key = key;  // 32 bytes (AES-256)
            aes.Mode = (mode == EncryptionMode.CBC) ? CipherMode.CBC : CipherMode.ECB;
            aes.Padding = PaddingMode.PKCS7;
            
            byte[] iv = null;
            if (mode == EncryptionMode.CBC)
            {
                aes.GenerateIV();  // 16 bytes random
                iv = aes.IV;
            }
            
            using (var encryptor = aes.CreateEncryptor())
            using (var ms = new MemoryStream())
            {
                if (iv != null)
                {
                    ms.Write(iv, 0, iv.Length);  // IV در ابتدا
                }
                
                using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    cs.Write(data, 0, data.Length);
                    cs.FlushFinalBlock();
                }
                
                return ms.ToArray();  // [IV(16)] + [Ciphertext]
            }
        }
    }
}
```

**فرآیند CBC:**
```
Block 1: C1 = AES_Encrypt(P1 XOR IV)
Block 2: C2 = AES_Encrypt(P2 XOR C1)
Block 3: C3 = AES_Encrypt(P3 XOR C2)
...
```

**فرآیند ECB (ناامن):**
```
Block 1: C1 = AES_Encrypt(P1)
Block 2: C2 = AES_Encrypt(P2)
Block 3: C3 = AES_Encrypt(P3)
```
⚠️ **هشدار:** ECB الگوهای plaintext رو حفظ می‌کنه (برای آموزش)

#### `TripleDESEncryption.cs`

**الگوریتم:** 3DES-EDE (Encrypt-Decrypt-Encrypt)

```
Key = K1 || K2 || K3  (24 bytes)

Encrypt: C = DES_Encrypt(K3, DES_Decrypt(K2, DES_Encrypt(K1, P)))
Decrypt: P = DES_Decrypt(K1, DES_Encrypt(K2, DES_Decrypt(K3, C)))
```

**توضیحات:**
- Block Size: 8 bytes (نه 16 مثل AES)
- IV Size: 8 bytes
- Key Size: 24 bytes (3 کلید 8 بایتی)

### 4.5 لایه MAC

#### `HMACSHA256Algorithm.cs`

**الگوریتم:** HMAC-SHA256

```csharp
public byte[] Calculate(byte[] data, byte[] key)
{
    using (var hmac = new HMACSHA256(key))
    {
        return hmac.ComputeHash(data);  // 32 bytes output
    }
}
```

**فرآیند HMAC:**
```
ipad = 0x36 repeated 64 times
opad = 0x5C repeated 64 times

HMAC(K, M) = H((K ⊕ opad) || H((K ⊕ ipad) || M))

where:
  K = key (padded to 64 bytes)
  M = message
  H = SHA256
  || = concatenation
  ⊕ = XOR
```

**امنیت:**
- Length Extension Attack رو می‌گیره
- Collision Resistance از SHA256

---

## 5. لایه Services

### 5.1 `UserIdentityManager.cs`

#### متد `RegisterUser`

```csharp
public static void RegisterUser(string username, string password)
{
    // 1. Generate Salt
    byte[] salt = CryptoUtils.GenerateRandomBytes(16);
    
    // 2. Hash Password
    byte[] saltPassword = salt.Concat(Encoding.UTF8.GetBytes(password)).ToArray();
    byte[] hash = CryptoUtils.ComputeMD5(saltPassword);
    
    // 3. Save Credentials
    var credentials = new UserCredentials
    {
        Username = username,
        Salt = Convert.ToBase64String(salt),
        PasswordHash = Convert.ToBase64String(hash)
    };
    File.WriteAllText(credPath, JsonSerializer.Serialize(credentials));
    
    // 4. Generate RSA Keys (ONCE, NEVER REGENERATE!)
    KeyManager.GenerateRSAKeyPair(out var pubKeyEnc, out var privKeyEnc);
    KeyManager.GenerateRSAKeyPair(out var pubKeySig, out var privKeySig);
    
    // 5. Derive AES Key from Password
    byte[] passwordKey = CryptoUtils.DeriveKeyFromPassword(password, 16);
    
    // 6. Encrypt Private Keys
    byte[] privKeyEncBytes = KeyManager.ExportPrivateKeyToBytes(privKeyEnc);
    byte[] privKeySigBytes = KeyManager.ExportPrivateKeyToBytes(privKeySig);
    
    var aes = new AESEncryption();
    byte[] encPrivKeyEnc = aes.Encrypt(privKeyEncBytes, passwordKey, EncryptionMode.CBC);
    byte[] encPrivKeySig = aes.Encrypt(privKeySigBytes, passwordKey, EncryptionMode.CBC);
    
    // 7. Save Files
    File.WriteAllBytes(Path.Combine(userDir, "Priv_Enc.bin"), encPrivKeyEnc);
    File.WriteAllBytes(Path.Combine(userDir, "Priv_Sig.bin"), encPrivKeySig);
    File.WriteAllText(Path.Combine(userDir, "Pub_Enc.txt"), pubKeyEncStr);
    File.WriteAllText(Path.Combine(userDir, "Pub_Sig.txt"), pubKeySigStr);
}
```

**ساختار فولدر:**
```
C:\SecureFileExchange\Users\
  └── Ali\
      ├── credentials.json        # {username, salt, hash}
      ├── Priv_Enc.bin           # Encrypted Encryption Private Key
      ├── Priv_Sig.bin           # Encrypted Signing Private Key
      ├── Pub_Enc.txt            # Encryption Public Key (Base64)
      ├── Pub_Sig.txt            # Signing Public Key (Base64)
      └── Ali_PublicKeys.txt     # برای Share کردن
```

#### متد `LoginUser`

```csharp
public static UserIdentity? LoginUser(string username, string password)
{
    // 1. Load Credentials
    var credentials = JsonSerializer.Deserialize<UserCredentials>(credJson);
    
    // 2. Verify Password
    byte[] salt = Convert.FromBase64String(credentials.Salt);
    byte[] inputHash = MD5(salt + password);
    byte[] storedHash = Convert.FromBase64String(credentials.PasswordHash);
    
    if (!inputHash.SequenceEqual(storedHash))
        throw new InvalidOperationException("Invalid password");
    
    // 3. Derive AES Key
    byte[] passwordKey = DeriveKeyFromPassword(password, 16);
    
    // 4. Decrypt Private Keys
    byte[] encPrivKeyEnc = File.ReadAllBytes("Priv_Enc.bin");
    byte[] encPrivKeySig = File.ReadAllBytes("Priv_Sig.bin");
    
    var aes = new AESEncryption();
    byte[] privKeyEncBytes = aes.Decrypt(encPrivKeyEnc, passwordKey, EncryptionMode.CBC);
    byte[] privKeySigBytes = aes.Decrypt(encPrivKeySig, passwordKey, EncryptionMode.CBC);
    
    // 5. Import Keys
    RSAParameters privKeyEnc = KeyManager.ImportPrivateKeyFromBytes(privKeyEncBytes);
    RSAParameters privKeySig = KeyManager.ImportPrivateKeyFromBytes(privKeySigBytes);
    
    // 6. Return UserIdentity
    return new UserIdentity
    {
        Username = username,
        EncryptionPrivateKey = privKeyEnc,
        SigningPrivateKey = privKeySig,
        // Load public keys too...
    };
}
```

### 5.2 `Encryptor.cs`

این کلاس **قلب سیستم رمزنگاری** هست.

#### متد `CreatePackage`

```csharp
public byte[] CreatePackage(byte[] fileData, RSAParameters privateKeySigning, string originalFileName)
{
    // Step 1: Extract Extension
    string extension = Path.GetExtension(originalFileName);  // e.g., ".pdf"
    if (string.IsNullOrEmpty(extension))
        extension = ".bin";
    
    byte[] extensionBytes = Encoding.UTF8.GetBytes(extension);
    byte extensionLength = (byte)Math.Min(extensionBytes.Length, 255);
    
    // Step 2: Calculate MAC
    byte[] macKey = CryptoUtils.GenerateRandomBytes(32);  // Random key
    byte[] mac = _macAlgorithm.Calculate(fileData, macKey);  // 32 bytes
    
    // Step 3: Build Package
    // [ext_len(1)] + [extension(n)] + [fileData] + [MAC(32)]
    byte[] dataWithMac = new byte[1 + extensionLength + fileData.Length + mac.Length];
    
    dataWithMac[0] = extensionLength;
    Array.Copy(extensionBytes, 0, dataWithMac, 1, extensionLength);
    Array.Copy(fileData, 0, dataWithMac, 1 + extensionLength, fileData.Length);
    Array.Copy(mac, 0, dataWithMac, 1 + extensionLength + fileData.Length, mac.Length);
    
    // Step 4: Sign Package
    byte[] signature = DigitalSignature.Sign(dataWithMac, privateKeySigning);
    
    // Step 5: Final Package Structure
    // [signature_length(4)] + [signature(256)] + [dataWithMac]
    byte[] package = new byte[4 + signature.Length + dataWithMac.Length];
    
    BitConverter.GetBytes(signature.Length).CopyTo(package, 0);
    signature.CopyTo(package, 4);
    dataWithMac.CopyTo(package, 4 + signature.Length);
    
    return package;
}
```

**ساختار Package:**
```
[0-3]:    Signature Length (int) = 256
[4-259]:  Digital Signature (256 bytes for RSA-2048)
[260]:    Extension Length (1 byte)
[261-n]:  Extension string (e.g., ".pdf")
[n+1-m]:  Original File Data
[m+1-m+32]: MAC (32 bytes)
```

#### متد `EncryptSecureEnvelope`

```csharp
public byte[] EncryptSecureEnvelope(byte[] packageData, RSAParameters consumerPublicKey, RecipientMode recipientMode)
{
    // Step 1: Generate Random Session Key
    byte[] sessionKey = CryptoUtils.GenerateRandomBytes(32);  // 256-bit AES key
    
    // Step 2: Encrypt Package with AES-256-CBC
    var aes = new AESEncryption();
    byte[] encryptedPackage = aes.Encrypt(packageData, sessionKey, EncryptionMode.CBC);
    // Output: [IV(16)] + [Ciphertext]
    
    // Step 3: Encrypt Session Key with Consumer's Public Key
    byte[] encryptedSessionKey = DigitalSignature.Encrypt(sessionKey, consumerPublicKey);
    // Output: 256 bytes (RSA-2048)
    
    // Step 4: Build Final Structure
    // [0x01][recipient_mode][key_length(4)][encrypted_key][encrypted_package]
    byte[] result = new byte[2 + 4 + encryptedSessionKey.Length + encryptedPackage.Length];
    
    result[0] = (byte)EncryptionMethod.SecureEnvelope;  // 0x01
    result[1] = (byte)recipientMode;                     // 0x01 or 0x02
    BitConverter.GetBytes(encryptedSessionKey.Length).CopyTo(result, 2);  // 256
    encryptedSessionKey.CopyTo(result, 6);
    encryptedPackage.CopyTo(result, 6 + encryptedSessionKey.Length);
    
    return result;
}
```

**چرا Secure Envelope؟**
1. **Performance:** RSA خیلی کنده (10-1000x کندتر از AES)
2. **Size Limit:** RSA-2048 حداکثر 190 بایت می‌تونه encrypt کنه
3. **Hybrid Solution:** 
   - Session Key با RSA رمز می‌شه (256 bytes overhead)
   - فایل با AES رمز می‌شه (سریع و بدون محدودیت سایز)

#### متد `EncryptRSADirect`

```csharp
public byte[] EncryptRSADirect(byte[] packageData, RSAParameters consumerPublicKey, RecipientMode recipientMode, RSAEncryptionMode rsaMode)
{
    if (rsaMode == RSAEncryptionMode.WithSignature)
    {
        // MODE 1: Standard (with Signature + MAC)
        if (packageData.Length > 190)
            throw new InvalidOperationException("Package too large!");
        
        byte[] encrypted = DigitalSignature.Encrypt(packageData, consumerPublicKey);
        
        // [0x03][recipient_mode][0x01][encrypted]
        byte[] result = new byte[3 + encrypted.Length];
        result[0] = 0x03;
        result[1] = (byte)recipientMode;
        result[2] = 0x01;  // WithSignature flag
        encrypted.CopyTo(result, 3);
        
        return result;
    }
    else
    {
        // MODE 2: Educational (NO Signature, NO MAC)
        // packageData is RAW file data
        if (packageData.Length > 190)
            throw new InvalidOperationException("File too large! Max 190 bytes.");
        
        byte[] encrypted = DigitalSignature.Encrypt(packageData, consumerPublicKey);
        
        // [0x03][recipient_mode][0x00][encrypted]
        byte[] result = new byte[3 + encrypted.Length];
        result[0] = 0x03;
        result[1] = (byte)recipientMode;
        result[2] = 0x00;  // NoSignature flag
        encrypted.CopyTo(result, 3);
        
        return result;
    }
}
```

**مقایسه دو حالت:**

| Feature | WithSignature (0x01) | NoSignature (0x00) |
|---------|---------------------|-------------------|
| Input | Package (with Signature+MAC) | Raw File Data |
| Max Size | ~0-2 bytes file | 0-190 bytes file |
| Security | ✅ Authenticated | ❌ NOT Authenticated |
| Use Case | Production | Educational Only |

### 5.3 `Decryptor.cs`

#### متد `DecryptSecureEnvelope`

```csharp
private byte[] DecryptSecureEnvelope(byte[] encryptedData, RSAParameters privateKey)
{
    // Step 1: Parse Structure
    // [0x01][mode][key_len(4)][encrypted_key][encrypted_package]
    
    int keyLength = BitConverter.ToInt32(encryptedData, 2);  // Read bytes 2-5
    
    // Step 2: Extract Encrypted Session Key
    byte[] encryptedSessionKey = new byte[keyLength];
    Array.Copy(encryptedData, 6, encryptedSessionKey, 0, keyLength);
    
    // Step 3: Extract Encrypted Package
    byte[] encryptedPackage = new byte[encryptedData.Length - 6 - keyLength];
    Array.Copy(encryptedData, 6 + keyLength, encryptedPackage, 0, encryptedPackage.Length);
    
    // Step 4: Decrypt Session Key with RSA
    byte[] sessionKey = DigitalSignature.Decrypt(encryptedSessionKey, privateKey);
    
    // Step 5: Decrypt Package with AES
    var aes = new AESEncryption();
    byte[] package = aes.Decrypt(encryptedPackage, sessionKey, EncryptionMode.CBC);
    
    return package;  // Returns Package with Signature + Data + MAC
}
```

#### متد `VerifyAndExtractData`

```csharp
public (byte[] originalData, string extension) VerifyAndExtractData(byte[] packageData, RSAParameters publicKeySigning)
{
    // Step 1: Extract Signature
    int signatureLength = BitConverter.ToInt32(packageData, 0);
    byte[] signature = new byte[signatureLength];
    Array.Copy(packageData, 4, signature, 0, signatureLength);
    
    // Step 2: Extract Data with Extension + MAC
    byte[] dataWithExtensionAndMac = new byte[packageData.Length - 4 - signatureLength];
    Array.Copy(packageData, 4 + signatureLength, dataWithExtensionAndMac, 0, dataWithExtensionAndMac.Length);
    
    // Step 3: VERIFY SIGNATURE
    bool isValid = DigitalSignature.Verify(dataWithExtensionAndMac, signature, publicKeySigning);
    if (!isValid)
        throw new InvalidOperationException("Digital signature verification FAILED!");
    
    // Step 4: Extract Extension
    byte extensionLength = dataWithExtensionAndMac[0];
    byte[] extensionBytes = new byte[extensionLength];
    Array.Copy(dataWithExtensionAndMac, 1, extensionBytes, 0, extensionLength);
    string extension = Encoding.UTF8.GetString(extensionBytes);
    
    // Step 5: Extract Original Data (remove MAC - last 32 bytes)
    int macLength = 32;
    int dataStart = 1 + extensionLength;
    int dataLength = dataWithExtensionAndMac.Length - dataStart - macLength;
    
    byte[] originalData = new byte[dataLength];
    Array.Copy(dataWithExtensionAndMac, dataStart, originalData, 0, dataLength);
    
    // TODO: Verify MAC (currently not implemented in full)
    
    return (originalData, extension);
}
```

### 5.4 `PublicKeyExchangeService.cs`

#### متد `ExportPublicKeys`

```csharp
public static string ExportPublicKeys(UserIdentity user)
{
    string filename = $"{user.Username}_PublicKeys.txt";
    string filepath = Path.Combine(ExportDirectory, filename);
    
    string encryptionKey = KeyManager.ExportPublicKeyToString(user.EncryptionPublicKey);
    string signingKey = KeyManager.ExportPublicKeyToString(user.SigningPublicKey);
    
    var content = $@"
===== PUBLIC KEYS FOR: {user.Username} =====
Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}

--- ENCRYPTION PUBLIC KEY ---
{encryptionKey}

--- SIGNING PUBLIC KEY ---
{signingKey}

===== END OF PUBLIC KEYS =====
";
    
    File.WriteAllText(filepath, content);
    return filepath;
}
```

**فرمت فایل خروجی:**
```
===== PUBLIC KEYS FOR: Ali =====
Generated: 2025-01-15 14:30:00

--- ENCRYPTION PUBLIC KEY ---
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwJ...
(Base64 encoded)

--- SIGNING PUBLIC KEY ---
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzT...
(Base64 encoded)

===== END OF PUBLIC KEYS =====
```

**کاربرد:**
1. Ali این فایل رو Export می‌کنه
2. Ali این فایل رو به Behnam می‌ده (USB, Email, etc.)
3. Behnam این فایل رو Import می‌کنه
4. Behnam حالا می‌تونه برای Ali رمزنگاری کنه (External mode)

---

## 6. لایه ViewModels

### 6.1 `BaseViewModel.cs`

**الگوی MVVM:** پیاده‌سازی `INotifyPropertyChanged`

```csharp
public class BaseViewModel : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    protected bool SetProperty<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (Equals(field, value)) return false;
        field = value;
        OnPropertyChanged(propertyName);
        return true;
    }
}
```

**چرا این الگو؟**
- وقتی Property تغییر می‌کنه، UI خودکار آپدیت می‌شه
- Two-way binding بین ViewModel و View

**مثال:**
```csharp
private string _username;
public string Username
{
    get => _username;
    set => SetProperty(ref _username, value);  // Fires PropertyChanged
}
```
در XAML:
```xml
<TextBox Text="{Binding Username, UpdateSourceTrigger=PropertyChanged}"/>
```

### 6.2 `AuthenticationViewModel.cs`

#### Properties

```csharp
private string _username = string.Empty;
private string _password = string.Empty;
private string _statusMessage = string.Empty;
private bool _isLoginMode = true;

public ICommand RegisterCommand { get; }
public ICommand LoginCommand { get; }
public ICommand SwitchModeCommand { get; }

public event EventHandler<bool>? AuthenticationCompleted;
```

#### متد `Register`

```csharp
private void Register()
{
    // 1. Validate Input
    if (string.IsNullOrWhiteSpace(Username))
    {
        StatusMessage = "Username cannot be empty";
        return;
    }
    
    if (Password.Length < 4)
    {
        StatusMessage = "Password must be at least 4 characters";
        return;
    }
    
    // 2. Call Service
    try
    {
        UserIdentityManager.RegisterUser(Username, Password);
        
        StatusMessage = $"User '{Username}' registered successfully!";
        
        // 3. Show Info
        MessageBox.Show(
            $"Registration successful!\n" +
            $"Your public keys: C:\\SecureFileExchange\\Users\\{Username}\\{Username}_PublicKeys.txt",
            "Success"
        );
        
        // 4. Auto-Login
        AutoLogin();
    }
    catch (Exception ex)
    {
        StatusMessage = $"Registration failed: {ex.Message}";
    }
}
```

#### متد `Login`

```csharp
private void Login()
{
    try
    {
        // 1. Call Service
        var user = UserIdentityManager.LoginUser(Username, Password);
        
        if (user == null)
        {
            StatusMessage = "Login failed";
            return;
        }
        
        // 2. Set Session
        SessionContext.Instance.Login(user);
        
        StatusMessage = $"Logged in as: {Username}";
        
        // 3. Notify UI (MainWindow will enable Producer/Consumer tabs)
        AuthenticationCompleted?.Invoke(this, true);
        
        // 4. Clear password from memory
        Password = string.Empty;
    }
    catch (Exception ex)
    {
        StatusMessage = $"Login failed: {ex.Message}";
    }
}
```

### 6.3 `ProducerViewModel.cs`

#### Properties

```csharp
private string _selectedFilePath = string.Empty;
private string _selectedConsumerUsername = string.Empty;
private string _externalPublicKeyPath = string.Empty;
private EncryptionMethod _selectedMethod = EncryptionMethod.SecureEnvelope;
private SymmetricAlgorithmType _selectedAlgorithm = SymmetricAlgorithmType.AES;
private EncryptionMode _selectedMode = EncryptionMode.CBC;
private MACAlgorithmType _selectedMACAlgorithm = MACAlgorithmType.HMACSHA256;
private RecipientType _recipientType = RecipientType.Internal;
private RSAEncryptionMode _rsaEncryptionMode = RSAEncryptionMode.WithSignature;

public ObservableCollection<string> AvailableUsers { get; }
```

**`ObservableCollection`:** وقتی item اضافه/حذف می‌شه، UI خودکار آپدیت می‌شه

#### متد `Encrypt`

```csharp
private void Encrypt()
{
    // 1. Validate File Selection
    if (string.IsNullOrWhiteSpace(SelectedFilePath))
    {
        MessageBox.Show("Please select a file", "Error");
        return;
    }
    
    Progress = 10;
    StatusMessage = "Loading keys...";
    
    // 2. Get Current User
    var currentUser = SessionContext.Instance.CurrentUser;
    if (currentUser?.SigningPrivateKey == null)
    {
        MessageBox.Show("Please login first", "Error");
        return;
    }
    
    Progress = 30;
    StatusMessage = "Creating package...";
    
    // 3. Create Encryptor
    var encryptor = new Encryptor(SelectedMACAlgorithm, SelectedAlgorithm);
    
    RSAParameters? consumerPublicKey = null;
    byte[]? symmetricKey = null;
    RecipientMode recipientMode = RecipientMode.InternalUser;
    
    // 4. Handle Different Methods
    if (SelectedMethod == EncryptionMethod.SecureEnvelope || 
        SelectedMethod == EncryptionMethod.RSADirect)
    {
        if (RecipientType == RecipientType.Internal)
        {
            // Load from local DB
            var consumer = UserIdentityManager.LoadPublicKeysOnly(SelectedConsumerUsername);
            consumerPublicKey = consumer.EncryptionPublicKey;
            recipientMode = RecipientMode.InternalUser;
        }
        else
        {
            // Load from imported file
            consumerPublicKey = _loadedExternalKeys.EncryptionPublicKey;
            recipientMode = RecipientMode.ExternalPublicKey;
        }
    }
    else if (SelectedMethod == EncryptionMethod.Symmetric)
    {
        if (KeyGenMethod == KeyGenerationMethod.Password)
        {
            int keyLength = SelectedAlgorithm == SymmetricAlgorithmType.AES ? 32 : 24;
            symmetricKey = CryptoUtils.DeriveKeyFromPassword(SharedPassword, keyLength);
        }
        else
        {
            int keyLength = SelectedAlgorithm == SymmetricAlgorithmType.AES ? 32 : 24;
            symmetricKey = CryptoUtils.DeriveKeyFromFile(SharedKeyFilePath, keyLength);
        }
    }
    
    Progress = 60;
    StatusMessage = "Encrypting...";
    
    // 5. Encrypt
    var result = encryptor.EncryptFile(
        SelectedFilePath,
        SelectedMethod,
        currentUser.SigningPrivateKey.Value,
        consumerPublicKey,
        symmetricKey,
        SelectedMode,
        recipientMode,
        RSAEncryptionMode
    );
    
    Progress = 100;
    
    // 6. Show Result
    if (result.Success)
    {
        MessageBox.Show($"File encrypted!\nSaved to: {result.OutputPath}", "Success");
    }
    else
    {
        MessageBox.Show(result.Message, "Error");
    }
    
    Progress = 0;
}
```

### 6.4 `ConsumerViewModel.cs`

مشابه Producer اما با تفاوت‌های زیر:
- به جای `BrowseFileCommand` → `BrowseEncryptedFileCommand`
- به جای `SelectedConsumerUsername` → `SelectedProducerUsername`
- Decrypt به جای Encrypt

---

## 7. لایه Views (UI)

### 7.1 `MainWindow.xaml`

**ساختار کلی:**

```xml
<Window>
    <Grid>
        <!-- Header (70px) -->
        <Border Height="70" VerticalAlignment="Top">
            <Grid>
                <StackPanel><!-- Logo + Title --></StackPanel>
                <StackPanel HorizontalAlignment="Right">
                    <!-- User Info + Logout Button -->
                </StackPanel>
            </Grid>
        </Border>
        
        <!-- Main Content -->
        <Grid Margin="0,70,0,0">
            <!-- Tab Navigation -->
            <Border Grid.Row="0">
                <StackPanel Orientation="Horizontal">
                    <RadioButton x:Name="AuthTab" Content="🔑 Authentication"/>
                    <RadioButton x:Name="ProducerTab" Content="📤 Encrypt File"/>
                    <RadioButton x:Name="ConsumerTab" Content="📥 Decrypt File"/>
                </StackPanel>
            </Border>
            
            <!-- Content Area -->
            <Border Grid.Row="1">
                <Grid>
                    <views:AuthenticationView x:Name="AuthenticationView" Visibility="Visible"/>
                    <views:ProducerView x:Name="ProducerView" Visibility="Collapsed"/>
                    <views:ConsumerView x:Name="ConsumerView" Visibility="Collapsed"/>
                </Grid>
            </Border>
        </Grid>
    </Grid>
</Window>
```

**Data Binding:**
```xml
<TextBlock Text="{Binding CurrentUserDisplay}"/>
```
این به `MainWindow.xaml.cs` که `INotifyPropertyChanged` پیاده کرده bind می‌شه.

### 7.2 `AuthenticationView.xaml`

**ویژگی اصلی:** ScrollViewer برای محتوای طولانی

```xml
<ScrollViewer VerticalScrollBarVisibility="Auto">
    <StackPanel Width="420">
        <Border><!-- Logo --></Border>
        <TextBlock Text="{Binding IsLoginMode, Converter={StaticResource BoolToStringConverter}, ConverterParameter='Welcome Back|Create New Account'}"/>
        
        <TextBox Text="{Binding Username}"/>
        <PasswordBox x:Name="PasswordBox"/>
        
        <Button Content="SIGN IN" 
                Command="{Binding LoginCommand}"
                Click="LoginButton_Click"
                Visibility="{Binding IsLoginMode, Converter={StaticResource BoolToVis}}"/>
        
        <Button Content="CREATE ACCOUNT"
                Command="{Binding RegisterCommand}"
                Visibility="{Binding IsLoginMode, Converter={StaticResource InverseBoolToVis}}"/>
    </StackPanel>
</ScrollViewer>
```

**PasswordBox Problem:**
- PasswordBox.Password **نمی‌تونه** Binding داشته باشه (به دلیل امنیت)
- راه حل: در Code-Behind manually منتقل می‌کنیم

```csharp
private void LoginButton_Click(object sender, RoutedEventArgs e)
{
    if (ViewModel != null)
    {
        ViewModel.Password = PasswordBox.Password;
    }
}
```

### 7.3 `ProducerView.xaml`

**بخش‌های اصلی:**

1. **Export Public Keys Button**
```xml
<Button Content="📤 Export My Public Keys"
        Command="{Binding ExportMyPublicKeysCommand}"/>
```

2. **File Selection**
```xml
<Grid>
    <TextBox Text="{Binding SelectedFilePath}" IsReadOnly="True"/>
    <Button Command="{Binding BrowseFileCommand}"/>
</Grid>
```

3. **MAC Algorithm Selection**
```xml
<ComboBox SelectedValue="{Binding SelectedMACAlgorithm}">
    <ComboBox.ItemsSource>
        <x:Array Type="models:MACAlgorithmType">
            <models:MACAlgorithmType>HMACSHA256</models:MACAlgorithmType>
            <models:MACAlgorithmType>CMAC</models:MACAlgorithmType>
            <models:MACAlgorithmType>CCM</models:MACAlgorithmType>
        </x:Array>
    </ComboBox.ItemsSource>
</ComboBox>
```

4. **Encryption Method Selection**
```xml
<StackPanel>
    <RadioButton Content="Secure Envelope"
                 IsChecked="{Binding SelectedMethod, Converter={StaticResource EnumToBoolConverter}, ConverterParameter=SecureEnvelope}"/>
    <RadioButton Content="Symmetric"
                 IsChecked="{Binding SelectedMethod, Converter={StaticResource EnumToBoolConverter}, ConverterParameter=Symmetric}"/>
    <RadioButton Content="RSA Direct"
                 IsChecked="{Binding SelectedMethod, Converter={StaticResource EnumToBoolConverter}, ConverterParameter=RSADirect}"/>
</StackPanel>
```

5. **Conditional UI (Visibility Converters)**
```xml
<!-- فقط برای Secure Envelope و RSA Direct نمایش داده می‌شه -->
<Border Visibility="{Binding SelectedMethod, Converter={StaticResource MethodToVisibilityConverter}, ConverterParameter='SecureEnvelope,RSADirect'}">
    <StackPanel>
        <!-- Recipient Type Selection -->
    </StackPanel>
</Border>

<!-- فقط برای Symmetric نمایش داده می‌شه -->
<Border Visibility="{Binding SelectedMethod, Converter={StaticResource MethodToVisibilityConverter}, ConverterParameter='Symmetric'}">
    <StackPanel>
        <!-- Symmetric Options -->
    </StackPanel>
</Border>
```

6. **RSA Direct Mode Selection**
```xml
<StackPanel>
    <RadioButton Content="With Signature &amp; MAC"
                 IsChecked="{Binding RSAEncryptionMode, Converter={StaticResource RSAEncryptionModeConverter}, ConverterParameter=WithSignature}"/>
    <RadioButton Content="No Signature (Educational)"
                 IsChecked="{Binding RSAEncryptionMode, Converter={StaticResource RSAEncryptionModeConverter}, ConverterParameter=NoSignature}"/>
</StackPanel>

<!-- Warning Box -->
<Border Visibility="{Binding RSAEncryptionMode, Converter={StaticResource RSAEncryptionModeConverter}, ConverterParameter=NoSignature}"
        Background="#2d1a1f"
        BorderBrush="#f85149">
    <TextBlock Text="⚠️ WARNING - Educational Mode Only..."/>
</Border>
```

7. **Progress Bar**
```xml
<Border Visibility="{Binding Progress, Converter={StaticResource ProgressToVisibilityConverter}}">
    <StackPanel>
        <TextBlock Text="{Binding StatusMessage}"/>
        <TextBlock Text="{Binding Progress, StringFormat={}{0}%}"/>
        <ProgressBar Value="{Binding Progress}" Maximum="100"/>
    </StackPanel>
</Border>
```

### 7.4 Value Converters

#### `EnumToBoolConverter`

```csharp
public class EnumToBoolConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value == null || parameter == null)
            return false;
        
        return value.ToString() == parameter.ToString();
    }
    
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is bool boolValue && boolValue && parameter != null)
        {
            return Enum.Parse(targetType, parameter.ToString());
        }
        
        return Binding.DoNothing;
    }
}
```

**کاربرد:**
```xml
<RadioButton IsChecked="{Binding SelectedMethod, Converter={StaticResource EnumToBoolConverter}, ConverterParameter=SecureEnvelope}"/>
```

- وقتی `SelectedMethod == EncryptionMethod.SecureEnvelope` → `IsChecked = true`
- وقتی RadioButton انتخاب می‌شه → `SelectedMethod = EncryptionMethod.SecureEnvelope`

---

## 8. سناریوهای استفاده

### سناریو 1: رمزنگاری برای کاربر Internal

**مراحل:**

1. **Ali** login می‌کنه
2. **Behnam** هم قبلاً register کرده (در همان سیستم)
3. Ali به Producer Tab می‌ره
4. فایل رو انتخاب می‌کنه
5. MAC: HMAC# 📚 **Secure File Exchange System - Complete Documentation**

## 📖 **فهرست مطالب**

1. [معماری کلی سیستم](#1-معماری-کلی-سیستم)
2. [فلوچارت و روند کلی](#2-فلوچارت-و-روند-کلی)
3. [لایه Models](#3-لایه-models)
4. [لایه Cryptography](#4-لایه-cryptography)
5. [لایه Services](#5-لایه-services)
6. [لایه ViewModels](#6-لایه-viewmodels)
7. [لایه Views](#7-لایه-views)
8. [سناریوهای استفاده](#8-سناریوهای-استفاده)
9. [الگوریتم‌های رمزنگاری](#9-الگوریتمهای-رمزنگاری)
10. [امنیت و تهدیدات](#10-امنیت-و-تهدیدات)

---

## 1. معماری کلی سیستم

### 1.1 ساختار کلی پروژه

```
SecureFileExchange/
├── Models/                    # مدل‌های داده
├── ViewModels/                # لاجیک UI (MVVM)
├── Views/                     # رابط کاربری (XAML)
├── Services/                  # سرویس‌های اصلی
├── Cryptography/              # پیاده‌سازی الگوریتم‌های رمزنگاری
│   ├── Interfaces/            # اینترفیس‌ها
│   ├── Symmetric/             # رمزنگاری متقارن
│   └── MAC/                   # الگوریتم‌های MAC
├── Commands/                  # Command Pattern
└── Converters/                # XAML Value Converters
```

### 1.2 الگوهای طراحی استفاده شده

1. **MVVM (Model-View-ViewModel)**
   - جداسازی لاجیک از UI
   - Data Binding دو طرفه
   - INotifyPropertyChanged برای آپدیت خودکار UI

2. **Strategy Pattern**
   - `IMACAlgorithm` - انتخاب الگوریتم MAC
   - `ISymmetricEncryption` - انتخاب الگوریتم رمزنگاری متقارن

3. **Factory Pattern**
   - `CreateMACAlgorithm()`
   - `CreateSymmetricEncryption()`

4. **Singleton Pattern**
   - `SessionContext.Instance` - مدیریت session کاربر

5. **Command Pattern**
   - `RelayCommand` - اجرای دستورات از UI

---

## 2. فلوچارت و روند کلی

### 2.1 فاز 1: Authentication (ثبت‌نام/ورود)

```
START
  │
  ├─→ [User Registered?]
  │     ├─ NO → Register User
  │     │        ├─ Generate Salt (16 bytes)
  │     │        ├─ Hash = MD5(Salt + Password)
  │     │        ├─ Generate RSA Keys (2048-bit)
  │     │        │   ├─ Encryption Key Pair
  │     │        │   └─ Signing Key Pair
  │     │        ├─ Derive Key from Password: MD5(Password) → 16 bytes
  │     │        ├─ Encrypt Private Keys with AES-128-CBC
  │     │        ├─ Save to: C:\SecureFileExchange\Users\{username}\
  │     │        │   ├─ credentials.json
  │     │        │   ├─ Priv_Enc.bin
  │     │        │   ├─ Priv_Sig.bin
  │     │        │   ├─ Pub_Enc.txt
  │     │        │   └─ Pub_Sig.txt
  │     │        └─ Export: {username}_PublicKeys.txt
  │     │
  │     └─ YES → Login User
  │              ├─ Load Salt from credentials.json
  │              ├─ Verify: Hash(Salt + Input_Password) == Stored_Hash
  │              ├─ Derive Key: MD5(Password) → 16 bytes
  │              ├─ Decrypt Private Keys with AES-128-CBC
  │              ├─ Load into SessionContext
  │              └─ Enable Producer/Consumer Tabs
  │
END
```

### 2.2 فاز 2: Producer (رمزنگاری فایل)

```
START: Encrypt File
  │
  ├─→ [Select File]
  │
  ├─→ [Select MAC Algorithm]
  │     ├─ HMAC-SHA256
  │     ├─ CMAC-AES
  │     └─ CCM
  │
  ├─→ [Select Encryption Method]
  │     │
  │     ├─ [1] Secure Envelope (Recommended)
  │     │     ├─ Select Recipient:
  │     │     │   ├─ Internal User → Load from local DB
  │     │     │   └─ External User → Import Public Keys file
  │     │     │
  │     │     ├─ Read File → Data
  │     │     ├─ Extract Extension → ".ext"
  │     │     ├─ Generate MAC Key (32 bytes random)
  │     │     ├─ Calculate MAC = HMAC-SHA256(Data, MAC_Key)
  │     │     ├─ Package = [ext_len][extension][Data][MAC]
  │     │     ├─ Sign = RSA-Sign(Package, Producer_Private_Signing_Key)
  │     │     ├─ Full_Package = [sign_len][Sign][Package]
  │     │     │
  │     │     ├─ Generate Session Key (32 bytes random)
  │     │     ├─ Encrypt Package with AES-256-CBC using Session Key
  │     │     ├─ Encrypt Session Key with RSA-OAEP using Consumer Public Key
  │     │     │
  │     │     └─ Output File Format:
  │     │         [0x01][recipient_mode][key_len(4)][encrypted_session_key][encrypted_package]
  │     │
  │     ├─ [2] Symmetric Encryption
  │     │     ├─ Select Algorithm: AES / DES / 3DES
  │     │     ├─ Select Mode: CBC / ECB
  │     │     ├─ Select Key Source:
  │     │     │   ├─ Password → Derive Key: MD5(Password)
  │     │     │   └─ File → Hash File: SHA256(FileBytes)
  │     │     │
  │     │     ├─ Create Package (same as Secure Envelope)
  │     │     ├─ Encrypt Package with Symmetric Algorithm
  │     │     │
  │     │     └─ Output File Format:
  │     │         [0x02][0x00][algo_type][mode_type][encrypted_package]
  │     │
  │     └─ [3] RSA Direct
  │           ├─ Select Mode:
  │           │   ├─ With Signature (Standard)
  │           │   │   ├─ Create Package with Signature + MAC
  │           │   │   ├─ Check Size: Package <= 190 bytes
  │           │   │   ├─ Encrypt with RSA-OAEP
  │           │   │   └─ Output: [0x03][recipient_mode][0x01][encrypted]
  │           │   │
  │           │   └─ No Signature (Educational)
  │           │       ├─ NO Package creation
  │           │       ├─ Check Size: Raw Data <= 190 bytes
  │           │       ├─ Direct RSA-OAEP(Data)
  │           │       └─ Output: [0x03][recipient_mode][0x00][encrypted]
  │           │
  │           └─ Warning: Max 190 bytes only!
  │
  └─→ Save as: {filename}.enc
  
END
```

### 2.3 فاز 3: Consumer (رمزگشایی فایل)

```
START: Decrypt File
  │
  ├─→ [Select .enc File]
  │
  ├─→ [Read Header Byte]
  │     ├─ 0x01 → Secure Envelope
  │     ├─ 0x02 → Symmetric
  │     └─ 0x03 → RSA Direct
  │
  ├─→ [Auto-detect Sender Type]
  │     ├─ Check byte[1] (Recipient Mode)
  │     │   ├─ 0x01 → Internal User
  │     │   └─ 0x02 → External User
  │     │
  │     └─ [Select Sender]
  │           ├─ Internal → Select from dropdown
  │           └─ External → Import Public Keys file
  │
  ├─→ [Decryption Process]
  │     │
  │     ├─ [1] Secure Envelope
  │     │     ├─ Read encrypted_session_key
  │     │     ├─ Decrypt Session Key with RSA-OAEP using Consumer Private Key
  │     │     ├─ Decrypt Package with AES-256-CBC using Session Key
  │     │     ├─ Extract: [sign_len][signature][ext_len][ext][Data][MAC]
  │     │     ├─ Verify Signature with Producer Public Signing Key
  │     │     ├─ Verify MAC
  │     │     └─ Extract Original Data + Extension
  │     │
  │     ├─ [2] Symmetric
  │     │     ├─ Read algo_type, mode_type
  │     │     ├─ Ask User for Password/File (same as Producer)
  │     │     ├─ Derive Key
  │     │     ├─ Decrypt Package with Selected Algorithm
  │     │     ├─ Verify Signature with Producer Public Signing Key
  │     │     ├─ Verify MAC
  │     │     └─ Extract Original Data + Extension
  │     │
  │     └─ [3] RSA Direct
  │           ├─ Check byte[2]:
  │           │   ├─ 0x01 → With Signature
  │           │   │   ├─ Decrypt with RSA-OAEP
  │           │   │   ├─ Verify Signature
  │           │   │   ├─ Verify MAC
  │           │   │   └─ Extract Data + Extension
  │           │   │
  │           │   └─ 0x00 → No Signature (Educational)
  │           │       ├─ Decrypt with RSA-OAEP
  │           │       ├─ NO Signature verification
  │           │       ├─ NO MAC verification
  │           │       └─ Return Raw Data
  │           │           └─ Display Warning: "NOT authenticated!"
  │           │
  │           └─ Save as: {filename}_decrypted{.ext}
  │
END
```

---

## 3. لایه Models

### 3.1 `UserIdentity.cs`

**هدف:** نگهداری اطلاعات هویتی کاربر (Identity)

```csharp
public class UserIdentity
{
    public string Username { get; set; }                    // نام کاربری
    public RSAParameters EncryptionPublicKey { get; set; }  // کلید عمومی رمزنگاری
    public RSAParameters SigningPublicKey { get; set; }     // کلید عمومی امضا
    public RSAParameters? EncryptionPrivateKey { get; set; }// کلید خصوصی رمزنگاری (nullable)
    public RSAParameters? SigningPrivateKey { get; set; }   // کلید خصوصی امضا (nullable)
    public string UserDirectory { get; set; }               // مسیر فولدر کاربر
}
```

**توضیحات:**
- `RSAParameters`: ساختار .NET برای نگهداری کلیدهای RSA
- کلیدهای خصوصی فقط برای کاربر لاگین شده لود می‌شن
- کلیدهای عمومی برای همه قابل دسترسی هستن

### 3.2 `SessionContext.cs` (Singleton)

**هدف:** مدیریت session کاربر لاگین شده

```csharp
public class SessionContext
{
    private static SessionContext? _instance;
    public UserIdentity? CurrentUser { get; private set; }
    public bool IsAuthenticated => CurrentUser != null;
    
    public void Login(UserIdentity user) { ... }
    public void Logout() { ... }
}
```

**روند کار:**
1. بعد از Login موفق، `CurrentUser` مقدار می‌گیره
2. تمام صفحات به `SessionContext.Instance.CurrentUser` دسترسی دارن
3. بعد از Logout، کلیدهای خصوصی از حافظه پاک می‌شن (Security)

### 3.3 `EncryptionMethod.cs`

**Enum برای روش‌های رمزنگاری:**

```csharp
public enum EncryptionMethod
{
    SecureEnvelope = 0x01,  // RSA + AES Hybrid
    Symmetric = 0x02,       // AES/DES/3DES فقط
    RSADirect = 0x03        // RSA مستقیم (محدود)
}

public enum SymmetricAlgorithmType
{
    AES = 0x01,       // AES-256
    DES = 0x02,       // DES (ناامن، برای آموزش)
    TripleDES = 0x03  // 3DES
}

public enum EncryptionMode
{
    CBC = 0x01,  // Cipher Block Chaining (امن)
    ECB = 0x02   // Electronic Codebook (ناامن، برای آموزش)
}

public enum MACAlgorithmType
{
    HMACSHA256,  // استاندارد، امن
    CMAC,        // برای آموزش
    CCM          // برای آموزش
}

public enum RecipientMode : byte
{
    InternalUser = 0x01,      // کاربر داخلی (همان سیستم)
    ExternalPublicKey = 0x02  // کاربر خارجی (سیستم دیگر)
}

public enum RSAEncryptionMode
{
    WithSignature,  // شامل امضا و MAC (امن)
    NoSignature     // بدون امضا و MAC (آموزشی، ناامن)
}
```

### 3.4 `ExternalPublicKeys.cs`

**هدف:** نگهداری کلیدهای عمومی کاربر خارجی

```csharp
public class ExternalPublicKeys
{
    public string Username { get; set; }
    public RSAParameters EncryptionPublicKey { get; set; }
    public RSAParameters SigningPublicKey { get; set; }
    public string SourceFile { get; set; }  // مسیر فایل .txt
}
```

**کاربرد:**
- وقتی Producer می‌خواد برای کاربر External رمزنگاری کنه
- فایل `{Username}_PublicKeys.txt` import می‌شه و به این کلاس map می‌شه

### 3.5 `EncryptionResult` & `DecryptionResult`

```csharp
public class EncryptionResult
{
    public bool Success { get; set; }
    public string Message { get; set; }
    public byte[]? EncryptedData { get; set; }
    public string? OutputPath { get; set; }
}
```

**روند:**
- سرویس‌ها به جای throw کردن exception، این کلاس رو برمی‌گردونن
- UI می‌تونه پیغام خطا یا موفقیت رو نمایش بده

---

## 4. لایه Cryptography

### 4.1 `KeyManager.cs`

**وظایف:**
1. تولید کلیدهای RSA
2. Export/Import کلیدها (Base64)
3. رمزگذاری/رمزگشایی کلید خصوصی

#### متد `GenerateRSAKeyPair`

```csharp
public static RSAParameters GenerateRSAKeyPair(
    out RSAParameters publicKey, 
    out RSAParameters privateKey)
{
    using (var rsa = RSA.Create(2048))  // RSA-2048
    {
        privateKey = rsa.ExportParameters(true);   // شامل D, P, Q, ...
        publicKey = rsa.ExportParameters(false);   // فقط Modulus & Exponent
        return privateKey;
    }
}
```

**توضیحات:**
- **RSA-2048:** امنیت معادل 112-bit Symmetric
- **Private Key شامل:** Modulus (n), Exponent (e), D, P, Q, DP, DQ, InverseQ
- **Public Key شامل:** فقط Modulus (n) و Exponent (e)

#### متد `EncryptPrivateKey`

```csharp
public static byte[] EncryptPrivateKey(byte[] privateKeyBytes, byte[] password)
{
    using (var aes = Aes.Create())
    {
        aes.Key = password;  // 16 bytes از MD5(Password)
        aes.GenerateIV();    // IV تصادفی 16 بایتی
        
        using (var encryptor = aes.CreateEncryptor())
        {
            byte[] encrypted = encryptor.TransformFinalBlock(privateKeyBytes, 0, privateKeyBytes.Length);
            
            // ترکیب: [IV(16)] + [Encrypted_Data]
            byte[] result = new byte[16 + encrypted.Length];
            Array.Copy(aes.IV, 0, result, 0, 16);
            Array.Copy(encrypted, 0, result, 16, encrypted.Length);
            
            return result;
        }
    }
}
```

**فرآیند:**
1. Password → MD5 → 16 bytes key
2. IV تصادفی تولید می‌شه (هر بار متفاوت)
3. AES-128-CBC برای رمزگذاری
4. IV به ابتدای فایل اضافه می‌شه (برای Decrypt)

### 4.2 `DigitalSignature.cs`

**الگوریتم:** RSA-SHA256 with PKCS#1 v1.5 Padding

#### متد `Sign`

```csharp
public static byte[] Sign(byte[] data, RSAParameters privateKey)
{
    using (var rsa = RSA.Create())
    {
        rsa.ImportParameters(privateKey);
        return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }
}
```

**فرآیند:**
1. Hash = SHA256(data)
2. Signature = RSA-Encrypt(Hash, Private_Key)
3. اندازه: 256 bytes (برای RSA-2048)

#### متد `Verify`

```csharp
public static bool Verify(byte[] data, byte[] signature, RSAParameters publicKey)
{
    using (var rsa = RSA.Create())
    {
        rsa.ImportParameters(publicKey);
        return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }
}
```

**فرآیند:**
1. Hash = SHA256(data)
2. Decrypted_Hash = RSA-Decrypt(Signature, Public_Key)
3. return Hash == Decrypted_Hash

#### متد `Encrypt` (RSA-OAEP)

```csharp
public static byte[] Encrypt(byte[] data, RSAParameters publicKey)
{
    using (var rsa = RSA.Create())
    {
        rsa.ImportParameters(publicKey);
        return rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
    }
}
```

**محدودیت:**
- RSA-2048 + OAEP-SHA256 → حداکثر **190 bytes** plaintext
- فرمول: `MaxSize = (KeySize / 8) - 2 * HashSize - 2`
- `(2048 / 8) - 2 * 32 - 2 = 256 - 66 = 190 bytes`

### 4.3 `CryptoUtils.cs`

#### متد `DeriveKeyFromPassword`

```csharp
public static byte[] DeriveKeyFromPassword(string password, int keyLength)
{
    byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
    
    if (keyLength == 32)  // AES-256
    {
        using (var sha256 = SHA256.Create())
        {
            return sha256.ComputeHash(passwordBytes);  // 32 bytes
        }
    }
    else if (keyLength == 16)  // AES-128, DES
    {
        byte[] hash = ComputeMD5(passwordBytes);  // 16 bytes
        return hash;
    }
    else if (keyLength == 24)  // 3DES
    {
        byte[] hash = ComputeMD5(passwordBytes);  // 16 bytes
        byte[] key = new byte[24];
        Array.Copy(hash, 0, key, 0, 16);
        Array.Copy(hash, 0, key, 16, 8);  // تکرار 8 بایت اول
        return key;
    }
}
```

**توضیحات:**
- **AES-256:** SHA256(Password) → 32 bytes
- **AES-128/DES:** MD5(Password) → 16 bytes (برای DES فقط 8 بایت اول استفاده می‌شه)
- **3DES:** MD5(Password) + repeat → 24 bytes

**نکته امنیتی:**
- این روش **PBKDF2** استفاده نمی‌کنه (برای سادگی آموزشی)
- در پروژه واقعی باید از `Rfc2898DeriveBytes` استفاده بشه

### 4.4 لایه Symmetric

#### `AESEncryption.cs`

```csharp
public class AESEncryption : ISymmetricEncryption
{
    public byte[] Encrypt(byte[] data, byte[] key, EncryptionMode mode)
    {
        using (var aes = Aes.Create())
        {
            aes.Key = key;  // 32 bytes (AES-256)
            aes.Mode = (mode == EncryptionMode.CBC) ? CipherMode.CBC : CipherMode.ECB;
            aes.Padding = PaddingMode.PKCS7;
            
            byte[] iv = null;
            if (mode == EncryptionMode.CBC)
            {
                aes.GenerateIV();  // 16 bytes random
                iv = aes.IV;
            }
            
            using (var encryptor = aes.CreateEncryptor())
            using (var ms = new MemoryStream())
            {
                if (iv != null)
                {
                    ms.Write(iv, 0, iv.Length);  // IV در ابتدا
                }
                
                using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    cs.Write(data, 0, data.Length);
                    cs.FlushFinalBlock();
                }
                
                return ms.ToArray();  // [IV(16)] + [Ciphertext]
            }
        }
    }
}
```

**فرآیند CBC:**
```
Block 1: C1 = AES_Encrypt(P1 XOR IV)
Block 2: C2 = AES_Encrypt(P2 XOR C1)
Block 3: C3 = AES_Encrypt(P3 XOR C2)
...
```

**فرآیند ECB (ناامن):**
```
Block 1: C1 = AES_Encrypt(P1)
Block 2: C2 = AES_Encrypt(P2)
Block 3: C3 = AES_Encrypt(P3)
```
⚠️ **هشدار:** ECB الگوهای plaintext رو حفظ می‌کنه (برای آموزش)

#### `TripleDESEncryption.cs`

**الگوریتم:** 3DES-EDE (Encrypt-Decrypt-Encrypt)

```
Key = K1 || K2 || K3  (24 bytes)

Encrypt: C = DES_Encrypt(K3, DES_Decrypt(K2, DES_Encrypt(K1, P)))
Decrypt: P = DES_Decrypt(K1, DES_Encrypt(K2, DES_Decrypt(K3, C)))
```

**توضیحات:**
- Block Size: 8 bytes (نه 16 مثل AES)
- IV Size: 8 bytes
- Key Size: 24 bytes (3 کلید 8 بایتی)

### 4.5 لایه MAC

#### `HMACSHA256Algorithm.cs`

**الگوریتم:** HMAC-SHA256

```csharp
public byte[] Calculate(byte[] data, byte[] key)
{
    using (var hmac = new HMACSHA256(key))
    {
        return hmac.ComputeHash(data);  // 32 bytes output
    }
}
```

**فرآیند HMAC:**
```
ipad = 0x36 repeated 64 times
opad = 0x5C repeated 64 times

HMAC(K, M) = H((K ⊕ opad) || H((K ⊕ ipad) || M))

where:
  K = key (padded to 64 bytes)
  M = message
  H = SHA256
  || = concatenation
  ⊕ = XOR
```

**امنیت:**
- Length Extension Attack رو می‌گیره
- Collision Resistance از SHA256

---

## 5. لایه Services

### 5.1 `UserIdentityManager.cs`

#### متد `RegisterUser`

```csharp
public static void RegisterUser(string username, string password)
{
    // 1. Generate Salt
    byte[] salt = CryptoUtils.GenerateRandomBytes(16);
    
    // 2. Hash Password
    byte[] saltPassword = salt.Concat(Encoding.UTF8.GetBytes(password)).ToArray();
    byte[] hash = CryptoUtils.ComputeMD5(saltPassword);
    
    // 3. Save Credentials
    var credentials = new UserCredentials
    {
        Username = username,
        Salt = Convert.ToBase64String(salt),
        PasswordHash = Convert.ToBase64String(hash)
    };
    File.WriteAllText(credPath, JsonSerializer.Serialize(credentials));
    
    // 4. Generate RSA Keys (ONCE, NEVER REGENERATE!)
    KeyManager.GenerateRSAKeyPair(out var pubKeyEnc, out var privKeyEnc);
    KeyManager.GenerateRSAKeyPair(out var pubKeySig, out var privKeySig);
    
    // 5. Derive AES Key from Password
    byte[] passwordKey = CryptoUtils.DeriveKeyFromPassword(password, 16);
    
    // 6. Encrypt Private Keys
    byte[] privKeyEncBytes = KeyManager.ExportPrivateKeyToBytes(privKeyEnc);
    byte[] privKeySigBytes = KeyManager.ExportPrivateKeyToBytes(privKeySig);
    
    var aes = new AESEncryption();
    byte[] encPrivKeyEnc = aes.Encrypt(privKeyEncBytes, passwordKey, EncryptionMode.CBC);
    byte[] encPrivKeySig = aes.Encrypt(privKeySigBytes, passwordKey, EncryptionMode.CBC);
    
    // 7. Save Files
    File.WriteAllBytes(Path.Combine(userDir, "Priv_Enc.bin"), encPrivKeyEnc);
    File.WriteAllBytes(Path.Combine(userDir, "Priv_Sig.bin"), encPrivKeySig);
    File.WriteAllText(Path.Combine(userDir, "Pub_Enc.txt"), pubKeyEncStr);
    File.WriteAllText(Path.Combine(userDir, "Pub_Sig.txt"), pubKeySigStr);
}
```

**ساختار فولدر:**
```
C:\SecureFileExchange\Users\
  └── Ali\
      ├── credentials.json        # {username, salt, hash}
      ├── Priv_Enc.bin           # Encrypted Encryption Private Key
      ├── Priv_Sig.bin           # Encrypted Signing Private Key
      ├── Pub_Enc.txt            # Encryption Public Key (Base64)
      ├── Pub_Sig.txt            # Signing Public Key (Base64)
      └── Ali_PublicKeys.txt     # برای Share کردن
```

#### متد `LoginUser`
```csharp
public static UserIdentity? LoginUser(string username, string password)
{
    // 1. Load Credentials
    var credentials = JsonSerializer.Deserialize<UserCredentials>(credJson);
    
    // 2. Verify Password
    byte[] salt = Convert.FromBase64String(credentials.Salt);
    byte[] inputHash = MD5(salt + password);
    byte[] storedHash = Convert.FromBase64String(credentials.PasswordHash);
    
    if (!inputHash.SequenceEqual(storedHash))
        throw new InvalidOperationException("Invalid password");
    
    // 3. Derive AES Key
    byte[] passwordKey = DeriveKeyFromPassword(password, 16);
    
    // 4. Decrypt Private Keys
    byte[] encPrivKeyEnc = File.ReadAllBytes("Priv_Enc.bin");
    byte[] encPrivKeySig = File.ReadAllBytes("Priv_Sig.bin");
    
    var aes = new AESEncryption();
    byte[] privKeyEncBytes = aes.Decrypt(encPrivKeyEnc, passwordKey, EncryptionMode.CBC);
    byte[] privKeySigBytes = aes.Decrypt(encPrivKeySig, passwordKey, EncryptionMode.CBC);
    
    // 5. Import Keys
    RSAParameters privKeyEnc = KeyManager.ImportPrivateKeyFromBytes(privKeyEncBytes);
    RSAParameters privKeySig = KeyManager.ImportPrivateKeyFromBytes(privKeySigBytes);
    
    // 6. Return UserIdentity
    return new UserIdentity
    {
        Username = username,
        EncryptionPrivateKey = privKeyEnc,
        SigningPrivateKey = privKeySig,
        // Load public keys too...
    };
}
```

### 5.2 `Encryptor.cs`

این کلاس **قلب سیستم رمزنگاری** هست.

#### متد `CreatePackage`

```csharp
public byte[] CreatePackage(byte[] fileData, RSAParameters privateKeySigning, string originalFileName)
{
    // Step 1: Extract Extension
    string extension = Path.GetExtension(originalFileName);  // e.g., ".pdf"
    if (string.IsNullOrEmpty(extension))
        extension = ".bin";
    
    byte[] extensionBytes = Encoding.UTF8.GetBytes(extension);
    byte extensionLength = (byte)Math.Min(extensionBytes.Length, 255);
    
    // Step 2: Calculate MAC
    byte[] macKey = CryptoUtils.GenerateRandomBytes(32);  // Random key
    byte[] mac = _macAlgorithm.Calculate(fileData, macKey);  // 32 bytes
    
    // Step 3: Build Package
    // [ext_len(1)] + [extension(n)] + [fileData] + [MAC(32)]
    byte[] dataWithMac = new byte[1 + extensionLength + fileData.Length + mac.Length];
    
    dataWithMac[0] = extensionLength;
    Array.Copy(extensionBytes, 0, dataWithMac, 1, extensionLength);
    Array.Copy(fileData, 0, dataWithMac, 1 + extensionLength, fileData.Length);
    Array.Copy(mac, 0, dataWithMac, 1 + extensionLength + fileData.Length, mac.Length);
    
    // Step 4: Sign Package
    byte[] signature = DigitalSignature.Sign(dataWithMac, privateKeySigning);
    
    // Step 5: Final Package Structure
    // [signature_length(4)] + [signature(256)] + [dataWithMac]
    byte[] package = new byte[4 + signature.Length + dataWithMac.Length];
    
    BitConverter.GetBytes(signature.Length).CopyTo(package, 0);
    signature.CopyTo(package, 4);
    dataWithMac.CopyTo(package, 4 + signature.Length);
    
    return package;
}
```

**ساختار Package:**
```
[0-3]:    Signature Length (int) = 256
[4-259]:  Digital Signature (256 bytes for RSA-2048)
[260]:    Extension Length (1 byte)
[261-n]:  Extension string (e.g., ".pdf")
[n+1-m]:  Original File Data
[m+1-m+32]: MAC (32 bytes)
```

#### متد `EncryptSecureEnvelope`

```csharp
public byte[] EncryptSecureEnvelope(byte[] packageData, RSAParameters consumerPublicKey, RecipientMode recipientMode)
{
    // Step 1: Generate Random Session Key
    byte[] sessionKey = CryptoUtils.GenerateRandomBytes(32);  // 256-bit AES key
    
    // Step 2: Encrypt Package with AES-256-CBC
    var aes = new AESEncryption();
    byte[] encryptedPackage = aes.Encrypt(packageData, sessionKey, EncryptionMode.CBC);
    // Output: [IV(16)] + [Ciphertext]
    
    // Step 3: Encrypt Session Key with Consumer's Public Key
    byte[] encryptedSessionKey = DigitalSignature.Encrypt(sessionKey, consumerPublicKey);
    // Output: 256 bytes (RSA-2048)
    
    // Step 4: Build Final Structure
    // [0x01][recipient_mode][key_length(4)][encrypted_key][encrypted_package]
    byte[] result = new byte[2 + 4 + encryptedSessionKey.Length + encryptedPackage.Length];
    
    result[0] = (byte)EncryptionMethod.SecureEnvelope;  // 0x01
    result[1] = (byte)recipientMode;                     // 0x01 or 0x02
    BitConverter.GetBytes(encryptedSessionKey.Length).CopyTo(result, 2);  // 256
    encryptedSessionKey.CopyTo(result, 6);
    encryptedPackage.CopyTo(result, 6 + encryptedSessionKey.Length);
    
    return result;
}
```

**چرا Secure Envelope؟**
1. **Performance:** RSA خیلی کنده (10-1000x کندتر از AES)
2. **Size Limit:** RSA-2048 حداکثر 190 بایت می‌تونه encrypt کنه
3. **Hybrid Solution:** 
   - Session Key با RSA رمز می‌شه (256 bytes overhead)
   - فایل با AES رمز می‌شه (سریع و بدون محدودیت سایز)

#### متد `EncryptRSADirect`

```csharp
public byte[] EncryptRSADirect(byte[] packageData, RSAParameters consumerPublicKey, RecipientMode recipientMode, RSAEncryptionMode rsaMode)
{
    if (rsaMode == RSAEncryptionMode.WithSignature)
    {
        // MODE 1: Standard (with Signature + MAC)
        if (packageData.Length > 190)
            throw new InvalidOperationException("Package too large!");
        
        byte[] encrypted = DigitalSignature.Encrypt(packageData, consumerPublicKey);
        
        // [0x03][recipient_mode][0x01][encrypted]
        byte[] result = new byte[3 + encrypted.Length];
        result[0] = 0x03;
        result[1] = (byte)recipientMode;
        result[2] = 0x01;  // WithSignature flag
        encrypted.CopyTo(result, 3);
        
        return result;
    }
    else
    {
        // MODE 2: Educational (NO Signature, NO MAC)
        // packageData is RAW file data
        if (packageData.Length > 190)
            throw new InvalidOperationException("File too large! Max 190 bytes.");
        
        byte[] encrypted = DigitalSignature.Encrypt(packageData, consumerPublicKey);
        
        // [0x03][recipient_mode][0x00][encrypted]
        byte[] result = new byte[3 + encrypted.Length];
        result[0] = 0x03;
        result[1] = (byte)recipientMode;
        result[2] = 0x00;  // NoSignature flag
        encrypted.CopyTo(result, 3);
        
        return result;
    }
}
```

**مقایسه دو حالت:**

| Feature | WithSignature (0x01) | NoSignature (0x00) |
|---------|---------------------|-------------------|
| Input | Package (with Signature+MAC) | Raw File Data |
| Max Size | ~0-2 bytes file | 0-190 bytes file |
| Security | ✅ Authenticated | ❌ NOT Authenticated |
| Use Case | Production | Educational Only |

### 5.3 `Decryptor.cs`

#### متد `DecryptSecureEnvelope`

```csharp
private byte[] DecryptSecureEnvelope(byte[] encryptedData, RSAParameters privateKey)
{
    // Step 1: Parse Structure
    // [0x01][mode][key_len(4)][encrypted_key][encrypted_package]
    
    int keyLength = BitConverter.ToInt32(encryptedData, 2);  // Read bytes 2-5
    
    // Step 2: Extract Encrypted Session Key
    byte[] encryptedSessionKey = new byte[keyLength];
    Array.Copy(encryptedData, 6, encryptedSessionKey, 0, keyLength);
    
    // Step 3: Extract Encrypted Package
    byte[] encryptedPackage = new byte[encryptedData.Length - 6 - keyLength];
    Array.Copy(encryptedData, 6 + keyLength, encryptedPackage, 0, encryptedPackage.Length);
    
    // Step 4: Decrypt Session Key with RSA
    byte[] sessionKey = DigitalSignature.Decrypt(encryptedSessionKey, privateKey);
    
    // Step 5: Decrypt Package with AES
    var aes = new AESEncryption();
    byte[] package = aes.Decrypt(encryptedPackage, sessionKey, EncryptionMode.CBC);
    
    return package;  // Returns Package with Signature + Data + MAC
}
```

#### متد `VerifyAndExtractData`

```csharp
public (byte[] originalData, string extension) VerifyAndExtractData(byte[] packageData, RSAParameters publicKeySigning)
{
    // Step 1: Extract Signature
    int signatureLength = BitConverter.ToInt32(packageData, 0);
    byte[] signature = new byte[signatureLength];
    Array.Copy(packageData, 4, signature, 0, signatureLength);
    
    // Step 2: Extract Data with Extension + MAC
    byte[] dataWithExtensionAndMac = new byte[packageData.Length - 4 - signatureLength];
    Array.Copy(packageData, 4 + signatureLength, dataWithExtensionAndMac, 0, dataWithExtensionAndMac.Length);
    
    // Step 3: VERIFY SIGNATURE
    bool isValid = DigitalSignature.Verify(dataWithExtensionAndMac, signature, publicKeySigning);
    if (!isValid)
        throw new InvalidOperationException("Digital signature verification FAILED!");
    
    // Step 4: Extract Extension
    byte extensionLength = dataWithExtensionAndMac[0];
    byte[] extensionBytes = new byte[extensionLength];
    Array.Copy(dataWithExtensionAndMac, 1, extensionBytes, 0, extensionLength);
    string extension = Encoding.UTF8.GetString(extensionBytes);
    
    // Step 5: Extract Original Data (remove MAC - last 32 bytes)
    int macLength = 32;
    int dataStart = 1 + extensionLength;
    int dataLength = dataWithExtensionAndMac.Length - dataStart - macLength;
    
    byte[] originalData = new byte[dataLength];
    Array.Copy(dataWithExtensionAndMac, dataStart, originalData, 0, dataLength);
    
    // TODO: Verify MAC (currently not implemented in full)
    
    return (originalData, extension);
}
```

### 5.4 `PublicKeyExchangeService.cs`

#### متد `ExportPublicKeys`

```csharp
public static string ExportPublicKeys(UserIdentity user)
{
    string filename = $"{user.Username}_PublicKeys.txt";
    string filepath = Path.Combine(ExportDirectory, filename);
    
    string encryptionKey = KeyManager.ExportPublicKeyToString(user.EncryptionPublicKey);
    string signingKey = KeyManager.ExportPublicKeyToString(user.SigningPublicKey);
    
    var content = $@"
===== PUBLIC KEYS FOR: {user.Username} =====
Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}

--- ENCRYPTION PUBLIC KEY ---
{encryptionKey}

--- SIGNING PUBLIC KEY ---
{signingKey}

===== END OF PUBLIC KEYS =====
";
    
    File.WriteAllText(filepath, content);
    return filepath;
}
```

**فرمت فایل خروجی:**
```
===== PUBLIC KEYS FOR: Ali =====
Generated: 2025-01-15 14:30:00

--- ENCRYPTION PUBLIC KEY ---
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwJ...
(Base64 encoded)

--- SIGNING PUBLIC KEY ---
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzT...
(Base64 encoded)

===== END OF PUBLIC KEYS =====
```

**کاربرد:**
1. Ali این فایل رو Export می‌کنه
2. Ali این فایل رو به Behnam می‌ده (USB, Email, etc.)
3. Behnam این فایل رو Import می‌کنه
4. Behnam حالا می‌تونه برای Ali رمزنگاری کنه (External mode)

---

## 6. لایه ViewModels

### 6.1 `BaseViewModel.cs`

**الگوی MVVM:** پیاده‌سازی `INotifyPropertyChanged`

```csharp
public class BaseViewModel : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    protected bool SetProperty<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (Equals(field, value)) return false;
        field = value;
        OnPropertyChanged(propertyName);
        return true;
    }
}
```

**چرا این الگو؟**
- وقتی Property تغییر می‌کنه، UI خودکار آپدیت می‌شه
- Two-way binding بین ViewModel و View

**مثال:**
```csharp
private string _username;
public string Username
{
    get => _username;
    set => SetProperty(ref _username, value);  // Fires PropertyChanged
}
```
در XAML:
```xml
<TextBox Text="{Binding Username, UpdateSourceTrigger=PropertyChanged}"/>
```

### 6.2 `AuthenticationViewModel.cs`

#### Properties

```csharp
private string _username = string.Empty;
private string _password = string.Empty;
private string _statusMessage = string.Empty;
private bool _isLoginMode = true;

public ICommand RegisterCommand { get; }
public ICommand LoginCommand { get; }
public ICommand SwitchModeCommand { get; }

public event EventHandler<bool>? AuthenticationCompleted;
```

#### متد `Register`

```csharp
private void Register()
{
    // 1. Validate Input
    if (string.IsNullOrWhiteSpace(Username))
    {
        StatusMessage = "Username cannot be empty";
        return;
    }
    
    if (Password.Length < 4)
    {
        StatusMessage = "Password must be at least 4 characters";
        return;
    }
    
    // 2. Call Service
    try
    {
        UserIdentityManager.RegisterUser(Username, Password);
        
        StatusMessage = $"User '{Username}' registered successfully!";
        
        // 3. Show Info
        MessageBox.Show(
            $"Registration successful!\n" +
            $"Your public keys: C:\\SecureFileExchange\\Users\\{Username}\\{Username}_PublicKeys.txt",
            "Success"
        );
        
        // 4. Auto-Login
        AutoLogin();
    }
    catch (Exception ex)
    {
        StatusMessage = $"Registration failed: {ex.Message}";
    }
}
```

#### متد `Login`

```csharp
private void Login()
{
    try
    {
        // 1. Call Service
        var user = UserIdentityManager.LoginUser(Username, Password);
        
        if (user == null)
        {
            StatusMessage = "Login failed";
            return;
        }
        
        // 2. Set Session
        SessionContext.Instance.Login(user);
        
        StatusMessage = $"Logged in as: {Username}";
        
        // 3. Notify UI (MainWindow will enable Producer/Consumer tabs)
        AuthenticationCompleted?.Invoke(this, true);
        
        // 4. Clear password from memory
        Password = string.Empty;
    }
    catch (Exception ex)
    {
        StatusMessage = $"Login failed: {ex.Message}";
    }
}
```

### 6.3 `ProducerViewModel.cs`

#### Properties

```csharp
private string _selectedFilePath = string.Empty;
private string _selectedConsumerUsername = string.Empty;
private string _externalPublicKeyPath = string.Empty;
private EncryptionMethod _selectedMethod = EncryptionMethod.SecureEnvelope;
private SymmetricAlgorithmType _selectedAlgorithm = SymmetricAlgorithmType.AES;
private EncryptionMode _selectedMode = EncryptionMode.CBC;
private MACAlgorithmType _selectedMACAlgorithm = MACAlgorithmType.HMACSHA256;
private RecipientType _recipientType = RecipientType.Internal;
private RSAEncryptionMode _rsaEncryptionMode = RSAEncryptionMode.WithSignature;

public ObservableCollection<string> AvailableUsers { get; }
```

**`ObservableCollection`:** وقتی item اضافه/حذف می‌شه، UI خودکار آپدیت می‌شه

#### متد `Encrypt`

```csharp
private void Encrypt()
{
    // 1. Validate File Selection
    if (string.IsNullOrWhiteSpace(SelectedFilePath))
    {
        MessageBox.Show("Please select a file", "Error");
        return;
    }
    
    Progress = 10;
    StatusMessage = "Loading keys...";
    
    // 2. Get Current User
    var currentUser = SessionContext.Instance.CurrentUser;
    if (currentUser?.SigningPrivateKey == null)
    {
        MessageBox.Show("Please login first", "Error");
        return;
    }
    
    Progress = 30;
    StatusMessage = "Creating package...";
    
    // 3. Create Encryptor
    var encryptor = new Encryptor(SelectedMACAlgorithm, SelectedAlgorithm);
    
    RSAParameters? consumerPublicKey = null;
    byte[]? symmetricKey = null;
    RecipientMode recipientMode = RecipientMode.InternalUser;
    
    // 4. Handle Different Methods
    if (SelectedMethod == EncryptionMethod.SecureEnvelope || 
        SelectedMethod == EncryptionMethod.RSADirect)
    {
        if (RecipientType == RecipientType.Internal)
        {
            // Load from local DB
            var consumer = UserIdentityManager.LoadPublicKeysOnly(SelectedConsumerUsername);
            consumerPublicKey = consumer.EncryptionPublicKey;
            recipientMode = RecipientMode.InternalUser;
        }
        else
        {
            // Load from imported file
            consumerPublicKey = _loadedExternalKeys.EncryptionPublicKey;
            recipientMode = RecipientMode.ExternalPublicKey;
        }
    }
    else if (SelectedMethod == EncryptionMethod.Symmetric)
    {
        if (KeyGenMethod == KeyGenerationMethod.Password)
        {
            int keyLength = SelectedAlgorithm == SymmetricAlgorithmType.AES ? 32 : 24;
            symmetricKey = CryptoUtils.DeriveKeyFromPassword(SharedPassword, keyLength);
        }
        else
        {
            int keyLength = SelectedAlgorithm == SymmetricAlgorithmType.AES ? 32 : 24;
            symmetricKey = CryptoUtils.DeriveKeyFromFile(SharedKeyFilePath, keyLength);
        }
    }
    
    Progress = 60;
    StatusMessage = "Encrypting...";
    
    // 5. Encrypt
    var result = encryptor.EncryptFile(
        SelectedFilePath,
        SelectedMethod,
        currentUser.SigningPrivateKey.Value,
        consumerPublicKey,
        symmetricKey,
        SelectedMode,
        recipientMode,
        RSAEncryptionMode
    );
    
    Progress = 100;
    
    // 6. Show Result
    if (result.Success)
    {
        MessageBox.Show($"File encrypted!\nSaved to: {result.OutputPath}", "Success");
    }
    else
    {
        MessageBox.Show(result.Message, "Error");
    }
    
    Progress = 0;
}
```

### 6.4 `ConsumerViewModel.cs`

مشابه Producer اما با تفاوت‌های زیر:
- به جای `BrowseFileCommand` → `BrowseEncryptedFileCommand`
- به جای `SelectedConsumerUsername` → `SelectedProducerUsername`
- Decrypt به جای Encrypt

---

## 7. لایه Views (UI)

### 7.1 `MainWindow.xaml`

**ساختار کلی:**

```xml
<Window>
    <Grid>
        <!-- Header (70px) -->
        <Border Height="70" VerticalAlignment="Top">
            <Grid>
                <StackPanel><!-- Logo + Title --></StackPanel>
                <StackPanel HorizontalAlignment="Right">
                    <!-- User Info + Logout Button -->
                </StackPanel>
            </Grid>
        </Border>
        
        <!-- Main Content -->
        <Grid Margin="0,70,0,0">
            <!-- Tab Navigation -->
            <Border Grid.Row="0">
                <StackPanel Orientation="Horizontal">
                    <RadioButton x:Name="AuthTab" Content="🔑 Authentication"/>
                    <RadioButton x:Name="ProducerTab" Content="📤 Encrypt File"/>
                    <RadioButton x:Name="ConsumerTab" Content="📥 Decrypt File"/>
                </StackPanel>
            </Border>
            
            <!-- Content Area -->
            <Border Grid.Row="1">
                <Grid>
                    <views:AuthenticationView x:Name="AuthenticationView" Visibility="Visible"/>
                    <views:ProducerView x:Name="ProducerView" Visibility="Collapsed"/>
                    <views:ConsumerView x:Name="ConsumerView" Visibility="Collapsed"/>
                </Grid>
            </Border>
        </Grid>
    </Grid>
</Window>
```

**Data Binding:**
```xml
<TextBlock Text="{Binding CurrentUserDisplay}"/>
```
این به `MainWindow.xaml.cs` که `INotifyPropertyChanged` پیاده کرده bind می‌شه.

### 7.2 `AuthenticationView.xaml`

**ویژگی اصلی:** ScrollViewer برای محتوای طولانی

```xml
<ScrollViewer VerticalScrollBarVisibility="Auto">
    <StackPanel Width="420">
        <Border><!-- Logo --></Border>
        <TextBlock Text="{Binding IsLoginMode, Converter={StaticResource BoolToStringConverter}, ConverterParameter='Welcome Back|Create New Account'}"/>
        
        <TextBox Text="{Binding Username}"/>
        <PasswordBox x:Name="PasswordBox"/>
        
        <Button Content="SIGN IN" 
                Command="{Binding LoginCommand}"
                Click="LoginButton_Click"
                Visibility="{Binding IsLoginMode, Converter={StaticResource BoolToVis}}"/>
        
        <Button Content="CREATE ACCOUNT"
                Command="{Binding RegisterCommand}"
                Visibility="{Binding IsLoginMode, Converter={StaticResource InverseBoolToVis}}"/>
    </StackPanel>
</ScrollViewer>
```

**PasswordBox Problem:**
- PasswordBox.Password **نمی‌تونه** Binding داشته باشه (به دلیل امنیت)
- راه حل: در Code-Behind manually منتقل می‌کنیم

```csharp
private void LoginButton_Click(object sender, RoutedEventArgs e)
{
    if (ViewModel != null)
    {
        ViewModel.Password = PasswordBox.Password;
    }
}
```

### 7.3 `ProducerView.xaml`

**بخش‌های اصلی:**

1. **Export Public Keys Button**
```xml
<Button Content="📤 Export My Public Keys"
        Command="{Binding ExportMyPublicKeysCommand}"/>
```

2. **File Selection**
```xml
<Grid>
    <TextBox Text="{Binding SelectedFilePath}" IsReadOnly="True"/>
    <Button Command="{Binding BrowseFileCommand}"/>
</Grid>
```

3. **MAC Algorithm Selection**
```xml
<ComboBox SelectedValue="{Binding SelectedMACAlgorithm}">
    <ComboBox.ItemsSource>
        <x:Array Type="models:MACAlgorithmType">
            <models:MACAlgorithmType>HMACSHA256</models:MACAlgorithmType>
            <models:MACAlgorithmType>CMAC</models:MACAlgorithmType>
            <models:MACAlgorithmType>CCM</models:MACAlgorithmType>
        </x:Array>
    </ComboBox.ItemsSource>
</ComboBox>
```

4. **Encryption Method Selection**
```xml
<StackPanel>
    <RadioButton Content="Secure Envelope"
                 IsChecked="{Binding SelectedMethod, Converter={StaticResource EnumToBoolConverter}, ConverterParameter=SecureEnvelope}"/>
    <RadioButton Content="Symmetric"
                 IsChecked="{Binding SelectedMethod, Converter={StaticResource EnumToBoolConverter}, ConverterParameter=Symmetric}"/>
    <RadioButton Content="RSA Direct"
                 IsChecked="{Binding SelectedMethod, Converter={StaticResource EnumToBoolConverter}, ConverterParameter=RSADirect}"/>
</StackPanel>
```

5. **Conditional UI (Visibility Converters)**
```xml
<!-- فقط برای Secure Envelope و RSA Direct نمایش داده می‌شه -->
<Border Visibility="{Binding SelectedMethod, Converter={StaticResource MethodToVisibilityConverter}, ConverterParameter='SecureEnvelope,RSADirect'}">
    <StackPanel>
        <!-- Recipient Type Selection -->
    </StackPanel>
</Border>

<!-- فقط برای Symmetric نمایش داده می‌شه -->
<Border Visibility="{Binding SelectedMethod, Converter={StaticResource MethodToVisibilityConverter}, ConverterParameter='Symmetric'}">
    <StackPanel>
        <!-- Symmetric Options -->
    </StackPanel>
</Border>
```

6. **RSA Direct Mode Selection**
```xml
<StackPanel>
    <RadioButton Content="With Signature &amp; MAC"
                 IsChecked="{Binding RSAEncryptionMode, Converter={StaticResource RSAEncryptionModeConverter}, ConverterParameter=WithSignature}"/>
    <RadioButton Content="No Signature (Educational)"
                 IsChecked="{Binding RSAEncryptionMode, Converter={StaticResource RSAEncryptionModeConverter}, ConverterParameter=NoSignature}"/>
</StackPanel>

<!-- Warning Box -->
<Border Visibility="{Binding RSAEncryptionMode, Converter={StaticResource RSAEncryptionModeConverter}, ConverterParameter=NoSignature}"
        Background="#2d1a1f"
        BorderBrush="#f85149">
    <TextBlock Text="⚠️ WARNING - Educational Mode Only..."/>
</Border>
```

7. **Progress Bar**
```xml
<Border Visibility="{Binding Progress, Converter={StaticResource ProgressToVisibilityConverter}}">
    <StackPanel>
        <TextBlock Text="{Binding StatusMessage}"/>
        <TextBlock Text="{Binding Progress, StringFormat={}{0}%}"/>
        <ProgressBar Value="{Binding Progress}" Maximum="100"/>
    </StackPanel>
</Border>
```

### 7.4 Value Converters

#### `EnumToBoolConverter`

```csharp
public class EnumToBoolConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value == null || parameter == null)
            return false;
        
        return value.ToString() == parameter.ToString();
    }
    
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is bool boolValue && boolValue && parameter != null)
        {
            return Enum.Parse(targetType, parameter.ToString());
        }
        
        return Binding.DoNothing;
    }
}
```

**کاربرد:**
```xml
<RadioButton IsChecked="{Binding SelectedMethod, Converter={StaticResource EnumToBoolConverter}, ConverterParameter=SecureEnvelope}"/>
```

- وقتی `SelectedMethod == EncryptionMethod.SecureEnvelope` → `IsChecked = true`
- وقتی RadioButton انتخاب می‌شه → `SelectedMethod = EncryptionMethod.SecureEnvelope`

---

## 8. سناریوهای استفاده

سناریو 1: رمزنگاری برای کاربر Internal
مراحل:
1.	Ali login می‌کنه
2.	Behnam هم قبلاً register کرده (در همان سیستم)
3.	Ali به Producer Tab می‌ره
4.	فایل document.pdf رو انتخاب می‌کنه (10 KB)
5.	MAC: HMAC-SHA256
6.	Method: Secure Envelope
7.	Recipient Type: Internal
8.	Consumer: Behnam (از dropdown)
9.	کلیک روی "Encrypt"
پشت صحنه:
1. Load Ali's Signing Private Key from SessionContext
2. Load Behnam's Encryption Public Key from: 
   C:\SecureFileExchange\Users\Behnam\Pub_Enc.txt
3. Read document.pdf → 10,240 bytes
4. Generate MAC Key (32 bytes random)
5. MAC = HMAC-SHA256(document.pdf, MAC_Key)
6. Package = [".pdf"][document.pdf][MAC]
7. Signature = RSA-Sign(Package, Ali_Signing_Private_Key)
8. Full_Package = [Signature_Length][Signature][Package]
9. Session_Key = Random(32 bytes)
10. Encrypted_Package = AES-256-CBC(Full_Package, Session_Key)
11. Encrypted_Session_Key = RSA-OAEP(Session_Key, Behnam_Encryption_Public_Key)
12. Output = [0x01][0x01][256][Encrypted_Session_Key][Encrypted_Package]
13. Save as: C:\SecureFileExchange\Output\document.enc
رمزگشایی توسط Behnam:
1.	Behnam login می‌کنه
2.	به Consumer Tab می‌ره
3.	فایل document.enc رو انتخاب می‌کنه
4.	Sender Type: Internal
5.	Producer: Ali
6.	کلیک روی "Decrypt"
پشت صحنه:
1. Read document.enc
2. Header[0] = 0x01 → Secure Envelope
3. Header[1] = 0x01 → Internal User
4. Load Behnam's Encryption Private Key from SessionContext
5. Load Ali's Signing Public Key from: 
   C:\SecureFileExchange\Users\Ali\Pub_Sig.txt
6. Extract Encrypted_Session_Key (256 bytes)
7. Session_Key = RSA-OAEP-Decrypt(Encrypted_Session_Key, Behnam_Private_Key)
8. Full_Package = AES-256-CBC-Decrypt(Encrypted_Package, Session_Key)
9. Extract Signature, Package
10. Verify: RSA-Verify(Package, Signature, Ali_Public_Signing_Key)
    → ✅ Valid
11. Extract: Extension=".pdf", Data, MAC
12. (MAC verification - simplified in current implementation)
13. Save as: C:\SecureFileExchange\Output\document_decrypted.pdf
________________________________________
سناریو 2: رمزنگاری برای کاربر External
مراحل:
سیستم A (Ali):
1.	Ali login می‌کنه
2.	کلیک روی "Export My Public Keys"
3.	فایل Ali_PublicKeys.txt ذخیره می‌شه در: C:\SecureFileExchange\ExportedKeys\Ali_PublicKeys.txt
4.	Ali این فایل رو به Behnam می‌ده (USB / Email)
سیستم B (Behnam):
1.	Behnam login می‌کنه
2.	کلیک روی "Export My Public Keys"
3.	فایل Behnam_PublicKeys.txt رو به Ali می‌ده
سیستم A (Ali - Encrypt):
1.	Ali به Producer Tab می‌ره
2.	فایل secret.txt رو انتخاب می‌کنه (500 bytes)
3.	Method: Secure Envelope
4.	Recipient Type: External
5.	کلیک روی "Load Keys"
6.	فایل Behnam_PublicKeys.txt رو import می‌کنه
7.	کلیک روی "Encrypt"
پشت صحنه:
1. Parse Behnam_PublicKeys.txt
2. Extract: Behnam_Encryption_Public_Key, Behnam_Signing_Public_Key
3. Same encryption process as Internal
4. BUT: Header[1] = 0x02 (External mode)
5. Output = [0x01][0x02][256][Encrypted_Session_Key][Encrypted_Package]
سیستم B (Behnam - Decrypt):
1.	Behnam به Consumer Tab می‌ره
2.	فایل secret.enc رو انتخاب می‌کنه
3.	Sender Type: External (auto-detected from Header[1] = 0x02)
4.	کلیک روی "Load Keys"
5.	فایل Ali_PublicKeys.txt رو import می‌کنه
6.	کلیک روی "Decrypt"
پشت صحنه:
1. Header[1] = 0x02 → External mode detected
2. Load Ali_Signing_Public_Key from imported file (not from DB)
3. Same decryption process
4. Signature verified with Ali's public key
5. Success!
________________________________________
سناریو 3: Symmetric Encryption (Password-based)
Producer:
1.	Ali login می‌کنه
2.	فایل data.bin رو انتخاب می‌کنه (5 MB)
3.	Method: Symmetric
4.	Algorithm: AES
5.	Mode: CBC
6.	Key Source: Password
7.	Password: MySecretPass123
8.	کلیک روی "Encrypt"
پشت صحنه:
1. Derive Key = SHA256("MySecretPass123") → 32 bytes
2. Create Package with Signature + MAC
3. Encrypt Package with AES-256-CBC using derived key
4. Output = [0x02][0x00][0x01][0x01][Encrypted_Package]
   - 0x02 = Symmetric
   - 0x00 = Placeholder (no recipient mode)
   - 0x01 = AES
   - 0x01 = CBC
Consumer:
1.	Behnam login می‌کنه
2.	فایل data.enc رو انتخاب می‌کنه
3.	Ali رو به عنوان Producer انتخاب می‌کنه
4.	Key Source: Password
5.	Password: MySecretPass123 (همان password)
6.	کلیک روی "Decrypt"
پشت صحنه:
1. Header[0] = 0x02 → Symmetric mode
2. Header[2] = 0x01 → AES
3. Header[3] = 0x01 → CBC
4. Derive Key = SHA256("MySecretPass123") → 32 bytes
5. Decrypt Package with AES-256-CBC
6. Verify Signature with Ali's Public Key
7. Extract Data
8. Success!
________________________________________
سناریو 4: RSA Direct (No Signature) - Educational
Producer:
1.	Ali login می‌کنه
2.	فایل tiny.txt رو انتخاب می‌کنه (محتوا: "Hi", 2 bytes)
3.	Method: RSA Direct
4.	RSA Mode: No Signature
5.	Recipient: Behnam (Internal)
6.	⚠️ Warning نمایش داده می‌شه
7.	کلیک روی "Encrypt"
پشت صحنه:
1. Read tiny.txt → "Hi" (2 bytes)
2. NO Package creation
3. NO Signature
4. NO MAC
5. Direct: Encrypted = RSA-OAEP("Hi", Behnam_Public_Key)
6. Output = [0x03][0x01][0x00][Encrypted]
   - 0x03 = RSA Direct
   - 0x01 = Internal
   - 0x00 = NoSignature mode
7. Size: 3 + 256 = 259 bytes
Consumer:
1.	Behnam login می‌کنه
2.	فایل tiny.enc رو انتخاب می‌کنه
3.	Producer: Ali
4.	کلیک روی "Decrypt"
پشت صحنه:
1. Header[0] = 0x03 → RSA Direct
2. Header[2] = 0x00 → NoSignature mode detected
3. Decrypt: Data = RSA-OAEP-Decrypt(Encrypted, Behnam_Private_Key)
4. NO Signature verification
5. NO MAC verification
6. Display Warning: "⚠️ This file was NOT authenticated!"
7. Save as: tiny_decrypted.bin
________________________________________
9. الگوریتم‌های رمزنگاری
9.1 RSA (Rivest-Shamir-Adleman)
پارامترها:
•	Key Size: 2048 bits
•	Public Exponent: 65537 (0x10001)
•	Padding: OAEP with SHA-256
اعداد اول:
p, q = two large primes (~1024 bits each)
n = p × q  (modulus, 2048 bits)
φ(n) = (p-1) × (q-1)
e = 65537  (public exponent)
d = e^(-1) mod φ(n)  (private exponent)
Public Key: (n, e) Private Key: (n, d, p, q, dp, dq, qInv)
Encryption:
C = M^e mod n
Decryption (با CRT برای سرعت بیشتر):
m1 = C^dp mod p   where dp = d mod (p-1)
m2 = C^dq mod q   where dq = d mod (q-1)
h = qInv × (m1 - m2) mod p
M = m2 + h × q
OAEP Padding:
Plaintext Max Size = (KeySize / 8) - 2×HashSize - 2
                   = (2048 / 8) - 2×32 - 2
                   = 256 - 66
                   = 190 bytes
9.2 AES (Advanced Encryption Standard)
پارامترها:
•	Block Size: 128 bits (16 bytes)
•	Key Sizes: 128, 192, 256 bits
•	Mode: CBC (Cipher Block Chaining)
•	Padding: PKCS7
ساختار Rijndael:
Rounds:
- AES-128: 10 rounds
- AES-192: 12 rounds
- AES-256: 14 rounds

Each round:
1. SubBytes (S-box substitution)
2. ShiftRows
3. MixColumns (except last round)
4. AddRoundKey (XOR with round key)
CBC Mode:
Encryption:
C[0] = AES_Encrypt(P[0] ⊕ IV, Key)
C[i] = AES_Encrypt(P[i] ⊕ C[i-1], Key)

Decryption:
P[0] = AES_Decrypt(C[0], Key) ⊕ IV
P[i] = AES_Decrypt(C[i], Key) ⊕ C[i-1]
PKCS7 Padding:
If last block needs N bytes padding:
Padding = [N, N, N, ..., N]  (N times)

Example: 
Data = "Hello" (5 bytes)
Block Size = 16
Padding needed = 11
Result = "Hello" + [11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11]
9.3 3DES (Triple DES)
پارامترها:
•	Block Size: 64 bits (8 bytes)
•	Key Size: 168 bits (24 bytes = 3×56-bit keys)
•	Mode: CBC / ECB
•	Algorithm: DES-EDE3 (Encrypt-Decrypt-Encrypt)
EDE Process:
K = K1 || K2 || K3  (24 bytes total)

Encryption:
Temp1 = DES_Encrypt(Plaintext, K1)
Temp2 = DES_Decrypt(Temp1, K2)
Ciphertext = DES_Encrypt(Temp2, K3)

Decryption:
Temp1 = DES_Decrypt(Ciphertext, K3)
Temp2 = DES_Encrypt(Temp1, K2)
Plaintext = DES_Decrypt(Temp2, K1)
چرا DES-EDE؟
•	Backward compatible با DES معمولی (اگر K1=K2=K3)
•	امنیت معادل 112-bit (نه 168-bit به دلیل Meet-in-the-Middle Attack)
9.4 HMAC-SHA256
پارامترها:
•	Hash Function: SHA-256
•	Output Size: 256 bits (32 bytes)
•	Block Size: 512 bits (64 bytes)
الگوریتم:
ipad = 0x36 repeated 64 times
opad = 0x5C repeated 64 times

if (key.length > 64)
    key = SHA256(key)

if (key.length < 64)
    key = key || [0x00...] (pad to 64)

HMAC(K, M) = SHA256((K ⊕ opad) || SHA256((K ⊕ ipad) || M))
چرا HMAC؟
1.	Keyed Hash: بدون کلید نمی‌شه محاسبه کرد
2.	Length Extension Attack Prevention: SHA256 آسیب‌پذیره، ولی HMAC نه
3.	Collision Resistance: از SHA256 ارث‌بری می‌کنه
9.5 Digital Signature (RSA-SHA256)
الگوریتم: RSASSA-PKCS1-v1_5
Sign:
1. Hash = SHA256(Message)
2. DigestInfo = ASN.1 structure:
   DigestInfo ::= SEQUENCE {
       digestAlgorithm AlgorithmIdentifier,  // SHA-256
       digest OCTET STRING                   // Hash value
   }
3. Padded = EMSA-PKCS1-v1_5-Encode(DigestInfo, KeyLength)
4. Signature = RSA_Private(Padded)
Verify:
1. Hash = SHA256(Message)
2. Padded = RSA_Public(Signature)
3. DigestInfo' = EMSA-PKCS1-v1_5-Decode(Padded)
4. return (Hash == DigestInfo'.digest)
Padding Scheme (EMSA-PKCS1-v1_5):
EM = 0x00 || 0x01 || PS || 0x00 || DigestInfo

where:
  PS = 0xFF repeated (KeyLength - len(DigestInfo) - 3) times
________________________________________
10. امنیت و تهدیدات
10.1 تهدیدات و دفاع‌ها
1. Man-in-the-Middle (MITM)
تهدید:
•	مهاجم کلید عمومی رو جعل می‌کنه
دفاع:
•	✅ Digital Signature: هویت Producer تأیید می‌شه
•	✅ Public Key Fingerprint: (پیشنهادی) نمایش SHA256(PublicKey) برای تأیید دستی
پیشنهاد بهبود:
public static string GetPublicKeyFingerprint(RSAParameters publicKey)
{
    byte[] keyBytes = ExportPublicKeyToBytes(publicKey);
    byte[] hash = SHA256.ComputeHash(keyBytes);
    return BitConverter.ToString(hash).Replace("-", "").Substring(0, 16);
}
2. Replay Attack
تهدید:
•	مهاجم فایل رمز شده قدیمی رو دوباره ارسال می‌کنه
دفاع:
•	⚠️ ضعف فعلی: Timestamp یا Nonce نداریم
•	💡 پیشنهاد: اضافه کردن Timestamp به Package
3. Password Brute-Force
تهدید:
•	مهاجم با دسترسی به Priv.enc سعی می‌کنه password رو حدس بزنه
دفاع:
•	⚠️ ضعف فعلی: از PBKDF2 استفاده نمی‌کنیم
•	✅ موجود: MD5(Salt + Password) یه لایه محافظت ارائه می‌ده
•	💡 پیشنهاد: استفاده از PBKDF2 با 100,000 iterations
4. Padding Oracle Attack
تهدید:
•	مهاجم با ارسال ciphertextهای modified سعی می‌کنه plaintext رو استخراج کنه
دفاع:
•	✅ OAEP Padding: برای RSA
•	✅ PKCS7 Padding: برای AES
•	✅ MAC Verification: قبل از Decryption
5. Chosen Ciphertext Attack
تهدید:
•	مهاجم ciphertext دلخواه رو decrypt می‌کنه
دفاع:
•	✅ Digital Signature: تغییرات تشخیص داده می‌شن
•	✅ MAC: integrity تضمین می‌شه
10.2 نقاط ضعف کد فعلی
1. MAC Key Management
مشکل:
byte[] macKey = CryptoUtils.GenerateRandomBytes(32);
byte[] mac = _macAlgorithm.Calculate(fileData, macKey);
❌ MAC Key ذخیره نمی‌شه! Consumer نمی‌تونه MAC رو verify کنه
راه حل:
// در Package باید MAC Key هم باشه (رمز شده با Session Key)
byte[] encryptedMacKey = EncryptWithSessionKey(macKey);
2. ECB Mode
مشکل:
aes.Mode = mode == EncryptionMode.CBC ? CipherMode.CBC : CipherMode.ECB;
❌ ECB ناامنه: الگوهای plaintext حفظ می‌شن
مثال:
Input:  "AAAA AAAA"  (2 blocks identical)
Output: "XXXX XXXX"  (2 blocks identical) → Pattern leaked!
توصیه:
•	فقط برای آموزش استفاده بشه
•	در Production همیشه CBC استفاده بشه
3. Exception Handling
مشکل:
catch (Exception ex)
{
    return new EncryptionResult { Success = false, Message = ex.Message };
}
❌ Information Leakage: پیغام خطا ممکنه اطلاعات حساس بده
بهبود:
catch (CryptographicException)
{
    return new EncryptionResult { Success = false, Message = "Decryption failed. Invalid key or corrupted data." };
}
10.3 بهترین شیوه‌های امنیتی
1. Key Storage
✅ خوب:
•	Private keys رمز شدن با AES
•	از password محافظت می‌شن
💡 بهتر:
•	استفاده از Windows DPAPI
•	ذخیره در Hardware Security Module (HSM)
2. Memory Management
⚠️ ضعف فعلی:
byte[] sessionKey = GenerateRandomBytes(32);
// After use, key remains in memory until GC
✅ بهبود:
try
{
    byte[] sessionKey = GenerateRandomBytes(32);
    // ... use key
}
finally
{
    Array.Clear(sessionKey, 0, sessionKey.Length);  // Wipe from memory
}
3. Random Number Generation
✅ استفاده صحیح:
using (var rng = RandomNumberGenerator.Create())
{
    rng.GetBytes(randomBytes);
}
این از CSPRNG (Cryptographically Secure Pseudo-Random Number Generator) استفاده می‌کنه.
________________________________________
11. فایل‌های خروجی و ساختارها
11.1 ساختار فایل .enc
Secure Envelope:
Byte Range    | Content
--------------|--------------------------------------------------
[0]           | 0x01 (Encryption Method Flag)
[1]           | 0x01 or 0x02 (Recipient Mode)
[2-5]         | Encrypted Session Key Length (int32, usually 256)
[6-261]       | Encrypted Session Key (256 bytes for RSA-2048)
[262-277]     | IV for AES (16 bytes)
[278-...]     | Encrypted Package (variable length)
Symmetric:
Byte Range    | Content
--------------|--------------------------------------------------
[0]           | 0x02 (Encryption Method Flag)
[1]           | 0x00 (Placeholder)
[2]           | Algorithm Type (0x01=AES, 0x02=DES, 0x03=3DES)
[3]           | Mode (0x01=CBC, 0x02=ECB)
[4-19]        | IV (if CBC mode, 16 bytes for AES, 8 for DES/3DES)
[20-...]      | Encrypted Package
RSA Direct (With Signature):
Byte Range    | Content
--------------|--------------------------------------------------
[0]           | 0x03 (Encryption Method Flag)
[1]           | 0x01 or 0x02 (Recipient Mode)
[2]           | 0x01 (WithSignature Flag)
[3-258]       | Encrypted Package (256 bytes for RSA-2048)
RSA Direct (No Signature):
Byte Range    | Content
--------------|--------------------------------------------------
[0]           | 0x03 (Encryption Method Flag)
[1]           | 0x01 or 0x02 (Recipient Mode)
[2]           | 0x00 (NoSignature Flag)
[3-258]       | Encrypted Raw Data (256 bytes for RSA-2048)
11.2 ساختار Package (قبل از رمزگذاری)
Byte Range    | Content
--------------|--------------------------------------------------
[0-3]         | Signature Length (int32) = 256
[4-259]       | Digital Signature (256 bytes)
[260]         | Extension Length (byte)
[261-n]       | Extension (e.g., ".pdf")
[n+1-m]       | Original File Data
[m+1-m+32]    | MAC (32 bytes HMAC-SHA256)
11.3 مثال عددی
فرض کنید فایل hello.txt حاوی "Hello World" (11 bytes):
Package Structure:
[0-3]:    00 00 01 00  (256 in little-endian)
[4-259]:  <signature_bytes>
[260]:    04           (length of ".txt")
[261-264]: 2E 74 78 74  (".txt" in UTF-8)
[265-275]: 48 65 6C 6C 6F 20 57 6F 72 6C 64  ("Hello World")
[276-307]: <mac_bytes>
Total Package Size: 308 bytes
After AES-256-CBC Encryption:
•	IV: 16 bytes
•	Ciphertext: 320 bytes (308 padded to multiple of 16)
•	Total: 336 bytes
After RSA Envelope:
•	Header: 6 bytes
•	Encrypted Session Key: 256 bytes
•	Encrypted Package: 336 bytes
•	Total .enc file: 598 bytes
________________________________________
12. مقایسه روش‌های رمزنگاری
Feature	Secure Envelope	Symmetric	RSA Direct (Sig)	RSA Direct (No Sig)
Max File Size	Unlimited	Unlimited	~0-2 bytes	0-190 bytes
Performance	Fast (AES)	Fast	Very Slow (RSA)	Very Slow (RSA)
Key Exchange	Public Key	Pre-shared	Public Key	Public Key
Authenticity	✅ Signature	✅ Signature	✅ Signature	❌ None
Integrity	✅ MAC	✅ MAC	✅ MAC	❌ None
Overhead	~256 bytes	~32 bytes	~260 bytes	~260 bytes
Use Case	Recommended	Shared Secret	Educational	Educational Only
Security	⭐⭐⭐⭐⭐	⭐⭐⭐⭐	⭐⭐⭐	⭐
________________________________________
13. نتیجه‌گیری
این سیستم یک پیاده‌سازی کامل از یک File Encryption System با قابلیت‌های زیر هست:
✅ Multi-User Authentication ✅ Three Encryption Methods ✅ Digital Signature ✅ MAC for Integrity ✅ External User Support ✅ Modern MVVM Architecture ✅ Educational RSA Direct Mode
نکات مهم برای ارائه:
1.	تأکید بر Hybrid Encryption (RSA + AES)
2.	توضیح Digital Signature برای Authentication
3.	نشان دادن External Mode برای سیستم‌های مستقل
4.	هشدار درباره RSA Direct (No Signature) - فقط آموزشی
5.	توضیح MVVM Pattern و جداسازی concerns
________________________________________
