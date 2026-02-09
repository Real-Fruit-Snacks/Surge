---
tags:
  - Foundational
---

## Programming and Windows Internals
resources: [Microsoft Win32 API](https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-api-list)

> [!info] Understanding programming concepts and Windows internals is essential for developing custom tools and evasion techniques.

### Programming Language Levels

#### Low-Level Languages
> [!info] Machine code and assembly. Direct hardware interaction, no abstraction. Examples: x86 Assembly, ARM Assembly.

#### Mid-Level Languages
> [!info] Balance between hardware access and abstraction. Examples: C, C++.

#### High-Level Languages
> [!info] Significant abstraction from hardware. Examples: C#, Python, PowerShell.

### Managed vs Unmanaged Code

#### Unmanaged Code
> [!info] Compiled directly to machine code. Executes directly on CPU. Examples: C, C++.

#### Managed Code
> [!info] Runs within a runtime environment (CLR for .NET). Just-In-Time (JIT) compilation. Examples: C#, VB.NET, PowerShell.

### Windows on Windows (WoW64)

> [!important] **WoW64** allows 32-bit applications to run on 64-bit Windows. Important for payload compatibility.

#### Check Process Architecture [Remote]
```powershell
[Environment]::Is64BitProcess
```

#### Check OS Architecture [Remote]
```powershell
[Environment]::Is64BitOperatingSystem
```

#### WoW64 File System Redirection
> [!warning] 32-bit processes accessing `C:\Windows\System32` are redirected to `C:\Windows\SysWOW64`.

```powershell
# Access real System32 from 32-bit process
$env:windir + "\Sysnative"
```

### Win32 API Fundamentals

> [!info] Win32 APIs provide access to Windows functionality. Essential for shellcode execution and process manipulation.

#### Common API Categories
> - **Kernel32.dll** - Process/thread management, memory operations, file I/O
> - **Ntdll.dll** - Native API, lowest user-mode layer before kernel
> - **User32.dll** - GUI, windows, messages
> - **Advapi32.dll** - Security, registry, services

#### Key APIs for Offensive Operations
> [!important] Critical APIs:
> - **VirtualAlloc** - Allocate memory with specific permissions
> - **VirtualProtect** - Change memory protection
> - **CreateThread** - Create new thread in current process
> - **CreateRemoteThread** - Create thread in another process
> - **WriteProcessMemory** - Write to another process's memory
> - **NtCreateThreadEx** - Native API thread creation (less monitored)

### Windows Registry

> [!info] Hierarchical database storing configuration. Common persistence and evasion target.

#### Registry Hives
> - **HKEY_LOCAL_MACHINE (HKLM)** - System-wide settings
> - **HKEY_CURRENT_USER (HKCU)** - Current user settings
> - **HKEY_CLASSES_ROOT (HKCR)** - File associations, COM objects

#### Query Registry [Remote]
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

```powershell
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

#### Add Registry Value [Remote]
```cmd
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v <Name> /t REG_SZ /d "<Command>"
```
