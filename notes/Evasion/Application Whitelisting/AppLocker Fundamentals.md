---
tags:
  - Advanced
  - AppLocker_Bypass
  - Defense_Evasion
  - Windows
---

## Application Whitelisting Theory
resources: [Microsoft AppLocker](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview)

> [!info] Application whitelisting restricts which programs can run. Only approved applications are allowed to execute.

### AppLocker Rule Types
> - **Executable Rules** - .exe and .com files
> - **Windows Installer Rules** - .msi and .msp files
> - **Script Rules** - .ps1, .bat, .cmd, .vbs, .js files
> - **Packaged App Rules** - Windows Store apps
> - **DLL Rules** - .dll and .ocx files (optional, performance impact)

### AppLocker Rule Conditions
> - **Publisher** - Based on digital signature
> - **Path** - Based on file location
> - **File Hash** - Based on cryptographic hash

### Default AppLocker Rules
> [!important] Default rules that can be bypassed:
> - Allow Administrators to run anything
> - Allow Everyone to run from Program Files
> - Allow Everyone to run from Windows folder
> - Allow Everyone to run Windows Installer files

### Check AppLocker Status [Remote]
```powershell
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections
```

```powershell
Get-AppLockerPolicy -Effective -Xml | Out-File applocker.xml
```

### AppLocker Event Logs
```powershell
Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL"
Get-WinEvent -LogName "Microsoft-Windows-AppLocker/MSI and Script"
```

## AppLocker Configuration

### AppLocker Service
> [!info] **Application Identity** service must be running for AppLocker to work.

```cmd
sc query AppIDSvc
sc start AppIDSvc
```

### View Applied Rules [Remote]
```powershell
Get-AppLockerPolicy -Local | Format-List
```

```cmd
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2"
```
