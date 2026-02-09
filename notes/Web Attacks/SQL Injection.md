---
tags:
  - Exploitation
  - Foundational
  - Initial_Access
  - SQL
  - Web_Application
---

### Database Connection

#### Connect to MySQL
```bash
mysql -u <Username> -p'<Password>' -h <Target> -P 3306
```

#### Connect to MSSQL
```bash
impacket-mssqlclient <Username>:<Password>@<Target> -windows-auth
```

### Database-Specific Syntax

#### MySQL Version
```sql
SELECT @@version;
SELECT version();
```

#### MSSQL Version
```sql
SELECT @@version;
```

#### MySQL List Databases
```sql
SHOW databases;
```

#### MSSQL List Databases
```sql
SELECT name FROM sys.databases;
```
