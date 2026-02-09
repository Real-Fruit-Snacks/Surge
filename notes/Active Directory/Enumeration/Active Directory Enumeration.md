---
tags:
  - Active_Directory
  - Discovery
  - Enumeration
  - Foundational
  - Windows
---

## Domain Enumeration
resources: [HackTricks - Active Directory Methodology](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/index.html)

> [!info] After gaining initial foothold, enumerate AD to find privilege escalation paths.

### Current Domain Info
```powershell
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
```

### Domain Controller
```cmd
nltest /dclist:<DomainName>
```

```powershell
Get-ADDomainController
```

### Domain Users
```cmd
net user /domain
```

```powershell
Get-ADUser -Filter * | Select-Object Name,SamAccountName
```

### Domain Groups
```cmd
net group /domain
```

```powershell
Get-ADGroup -Filter * | Select-Object Name
```

### Domain Admins
```cmd
net group "Domain Admins" /domain
```

### PowerView

#### Import PowerView
```powershell
Import-Module .\PowerView.ps1
```

#### Get Domain Info
```powershell
Get-Domain
```

#### Get Domain Users
```powershell
Get-DomainUser | Select-Object samaccountname,description
```

#### Find Local Admin Access
```powershell
Find-LocalAdminAccess
```

#### Get Domain Computers
```powershell
Get-DomainComputer | Select-Object name,operatingsystem
```

#### Get Group Members
```powershell
Get-DomainGroupMember -Identity "Domain Admins"
```

#### Find Kerberoastable Users
```powershell
Get-DomainUser -SPN | Select-Object samaccountname,serviceprincipalname
```

### Service Principal Names (SPNs)

#### Find SPNs
```cmd
setspn -L <ServiceAccount>
```

```powershell
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```
