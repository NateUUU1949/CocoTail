# 🧬 CocoTail – Hybrid Argon2id + Keccak KDF Framework

> **Powerful. Secure. Memory-Hard.**
> A next-generation Key Derivation Framework combining **Keccak-f[1600]**, **SHA-512**, and **Argon2id** for high-security password hashing and key derivation.

---

## 🚀 Overview

**CocoTail** is a **hybrid key derivation framework** that merges:

* The **Keccak-f[1600] sponge** (basis of SHA-3) for initial diffusion and entropy spreading.
* The well-tested **SHA-512** for robust intermediate hashing.
* **Argon2id** (RFC 9106) for memory-hard finalization, resistant to GPU/ASIC attacks.

This dual-primitive design provides extremely high resistance against:

* Dictionary and brute-force attacks.
* Specialized hardware attacks.
* Side-channel attacks and memory leakage.

---

## ✨ Key Features

| Category            | Description                                                    |
| ------------------- | -------------------------------------------------------------- |
| 🔐 Security         | Hybrid Keccak + SHA-512 + Argon2id for layered defense.        |
| 🧠 Memory-Hard      | Forces sequential memory access to slow down parallel attacks. |
| ⚙️ Configurable     | Control memory, iterations, and output size.                   |
| 🧩 Compatible       | Stable API: `ComputeHash(byte[] input, byte[] salt)`           |
| 🧼 Secure Memory    | Sensitive buffers zeroed automatically.                        |
| 🧱 Production-Ready | Fallback PBKDF2-HMAC-SHA512 for FIPS environments.             |

---

## 🧪 Usage Example

```csharp
using CocoTail;
using System.Security.Cryptography;
using System.Text;

var coco = new CocoTailDigest(outputLengthBits: 512, memoryBlocks: 1024, timeCost: 2);

string password = "my_ultra_secret_password_456!";
byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
byte[] salt = RandomNumberGenerator.GetBytes(16);

byte[] hash = coco.ComputeHash(passwordBytes, salt);

Console.WriteLine($"Salt: {BitConverter.ToString(salt).Replace("-", "")}");
Console.WriteLine($"Hash: {BitConverter.ToString(hash).Replace("-", "")}");
```

**Sample Output:**

```
Salt: BEA005D5321F146781B322C4358635EC
Hash: 42CE3AF7FE0B39BB2AD1FF2C5D6EC84465C3506957F4668F0272FFA9C93210B1944D4CADB1FAE3A998961C4F7E10C3BB986EFD1026BF85AB12216C522D94C1AC
```

---

## ⚙️ Recommended Parameters

| Scenario            | Memory (MB) | Iterations | Output (bits) |
| ------------------- | ----------- | ---------- | ------------- |
| Desktop / Local App | 64          | 3          | 512           |
| Server Backend      | 128         | 4          | 512           |
| Embedded Devices    | 16          | 2          | 256           |

---

## 🧩 Internal Architecture

```
 Input (password + salt)
          │
          ▼
 ┌────────────────────────┐
 │  Keccak-f[1600] Sponge │  → Diffusion & entropy
 └────────────────────────┘
          │
          ▼
 ┌────────────────────────┐
 │      SHA-512 Mix       │  → 64-byte intermediate hash
 └────────────────────────┘
          │
          ▼
 ┌────────────────────────┐
 │     Argon2id Layer     │  → Memory-hard finalization
 └────────────────────────┘
          │
          ▼
     Final Output (Hash)
```

---

## 🛡️ Security

* ✅ Argon2id compliant with [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106)
* ✅ Keccak-f[1600] validated on SHA-3 test vectors
* ✅ All critical buffers use `ArrayPool` and are zeroed after use
* ✅ No unsafe code, fully managed .NET implementation

---

## 📦 Installation

Include the source directly in your .NET solution:

```bash
git clone https://github.com/ZygoteCode/CocoTail.git
```

Or add as a project reference. Future NuGet support planned:

```bash
dotnet add package CocoTail
```

---

## 🧰 API

```csharp
public sealed class CocoTailDigest : IDisposable
{
    CocoTailDigest(int outputLengthBits = 512, int memoryBlocks = 8192, int timeCost = 3);
    byte[] ComputeHash(byte[] input, byte[] salt);
}
```

**Parameters:**

* `outputLengthBits` – output hash length in bits (multiple of 8)
* `memoryBlocks` – number of memory blocks used internally
* `timeCost` – number of mixing passes

---

## 🧾 License

MIT License © 2025
Created with ❤️ by **[ZygoteCode]**

---

## 🧠 References

* [RFC 9106 – Argon2id Password Hash](https://www.rfc-editor.org/rfc/rfc9106)
* [Keccak Reference](https://keccak.team/keccak_specs_summary.html)
* [NIST FIPS 202 – SHA-3 Standard](https://csrc.nist.gov/publications/detail/fips/202/final)

> ⚡ **CocoTail Hybrid-Argon2id** – A research-grade KDF made production-ready and extremely powerful.
