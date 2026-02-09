---
tags:
  - Active_Directory
  - Enumeration
  - LDAP
  - Foundational
---

## LDAP Enumeration
resources: [HackTricks LDAP](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap), [PayloadsAllTheThings LDAP](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#ldap)

> Comprehensive LDAP enumeration techniques for Active Directory reconnaissance.

## LDAP Basics

> [!info] LDAP (Lightweight Directory Access Protocol) is the protocol used to query Active Directory.
> - **Port 389**: LDAP (unencrypted)
> - **Port 636**: LDAPS (encrypted with SSL/TLS)
> - **Port 3268**: Global Catalog (LDAP)
> - **Port 3269**: Global Catalog (LDAPS)

### LDAP Distinguished Names (DN)

> [!info] Understanding LDAP structure:
> - **DN**: `CN=John Doe,OU=Users,DC=corp,DC=local`
> - **CN**: Common Name (user, computer, group)
> - **OU**: Organizational Unit (container)
> - **DC**: Domain Component (domain parts)

## Anonymous LDAP Bind

> [!tip] Some domains allow anonymous LDAP queries without authentication.

### Test Anonymous Bind with ldapsearch
```bash
ldapsearch -x -H ldap://<DomainController> -b "DC=corp,DC=local"
```

> [!info] Flags:
> - `-x`: Simple authentication (no SASL)
> - `-H`: LDAP URI
> - `-b`: Base DN to search from

### Enumerate All Users (Anonymous)
```bash
ldapsearch -x -H ldap://<DomainController> -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName userPrincipalName
```

### Enumerate All Computers (Anonymous)
```bash
ldapsearch -x -H ldap://<DomainController> -b "DC=corp,DC=local" "(objectClass=computer)" dNSHostName operatingSystem
```

### Enumerate All Groups (Anonymous)
```bash
ldapsearch -x -H ldap://<DomainController> -b "DC=corp,DC=local" "(objectClass=group)" cn member
```

## Authenticated LDAP Enumeration

> [!important] Most domains require authentication for LDAP queries.

### ldapsearch with Credentials
```bash
ldapsearch -x -H ldap://<DomainController> -D "<Username>@<Domain>" -w '<Password>' -b "DC=corp,DC=local"
```

> [!info] Flags:
> - `-D`: Bind DN (username)
> - `-w`: Password (use `-W` for interactive prompt)

### Find All Domain Admins
```bash
ldapsearch -x -H ldap://<DomainController> -D "<Username>@<Domain>" -w '<Password>' -b "DC=corp,DC=local" "(memberOf=CN=Domain Admins,CN=Users,DC=corp,DC=local)" sAMAccountName
```

### Find Users with SPN (Kerberoastable)
```bash
ldapsearch -x -H ldap://<DomainController> -D "<Username>@<Domain>" -w '<Password>' -b "DC=corp,DC=local" "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName
```

### Find Users with adminCount=1
```bash
ldapsearch -x -H ldap://<DomainController> -D "<Username>@<Domain>" -w '<Password>' -b "DC=corp,DC=local" "(&(objectClass=user)(adminCount=1))" sAMAccountName
```

> [!tip] `adminCount=1` indicates users who are/were members of privileged groups.

### Find Computers with Unconstrained Delegation
```bash
ldapsearch -x -H ldap://<DomainController> -D "<Username>@<Domain>" -w '<Password>' -b "DC=corp,DC=local" "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" dNSHostName
```

### Find Users with "Do Not Require Kerberos Preauthentication" (AS-REP Roastable)
```bash
ldapsearch -x -H ldap://<DomainController> -D "<Username>@<Domain>" -w '<Password>' -b "DC=corp,DC=local" "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName
```

## windapsearch - Automated LDAP Enumeration

> [!tip] `windapsearch` is a Python tool that automates common LDAP queries.

### Install windapsearch
```bash
git clone https://github.com/ropnop/windapsearch.git
cd windapsearch
pip3 install -r requirements.txt
```

### Enumerate Domain Users
```bash
python3 windapsearch.py -d <Domain> -u <Username> -p '<Password>' --dc-ip <DomainController> -U
```

### Enumerate Domain Computers
```bash
python3 windapsearch.py -d <Domain> -u <Username> -p '<Password>' --dc-ip <DomainController> -C
```

### Enumerate Domain Groups
```bash
python3 windapsearch.py -d <Domain> -u <Username> -p '<Password>' --dc-ip <DomainController> -G
```

### Enumerate Privileged Users
```bash
python3 windapsearch.py -d <Domain> -u <Username> -p '<Password>' --dc-ip <DomainController> --privileged-users
```

### Enumerate Domain Admins
```bash
python3 windapsearch.py -d <Domain> -u <Username> -p '<Password>' --dc-ip <DomainController> --da
```

### Full Enumeration (All Objects)
```bash
python3 windapsearch.py -d <Domain> -u <Username> -p '<Password>' --dc-ip <DomainController> --full
```

### Custom LDAP Query
```bash
python3 windapsearch.py -d <Domain> -u <Username> -p '<Password>' --dc-ip <DomainController> --custom "(&(objectClass=user)(adminCount=1))"
```

## ldapdomaindump - Comprehensive LDAP Dump

> [!tip] `ldapdomaindump` creates HTML reports of AD structure.

### Install ldapdomaindump
```bash
pip3 install ldapdomaindump
```

### Dump Domain Information
```bash
ldapdomaindump -u '<Domain>\<Username>' -p '<Password>' <DomainController>
```

> Creates HTML files: `domain_users.html`, `domain_computers.html`, `domain_groups.html`, etc.

### Dump with Output Directory
```bash
ldapdomaindump -u '<Domain>\<Username>' -p '<Password>' <DomainController> -o /tmp/ldap_dump
```

### Dump Over LDAPS (Port 636)
```bash
ldapdomaindump -u '<Domain>\<Username>' -p '<Password>' ldaps://<DomainController> -o /tmp/ldap_dump
```

## Useful LDAP Filters

> [!info] Common LDAP search filters for targeted enumeration.

### Find All Enabled Users
```text
(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))
```

### Find All Disabled Users
```text
(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))
```

### Find Users with Password Never Expires
```text
(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))
```

### Find Users with Password Not Required
```text
(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))
```

### Find Computers Running Specific OS
```text
(&(objectClass=computer)(operatingSystem=*Server*))
```

### Find Empty Groups
```text
(&(objectClass=group)(!(member=*)))
```

### Find Groups with Specific Member
```text
(&(objectClass=group)(member=CN=John Doe,OU=Users,DC=corp,DC=local))
```

## LDAP Enumeration with NetExec

> [!tip] NetExec (formerly CrackMapExec) has built-in LDAP enumeration.

### Enumerate Users
```bash
netexec ldap <DomainController> -u <Username> -p '<Password>' --users
```

### Enumerate Groups
```bash
netexec ldap <DomainController> -u <Username> -p '<Password>' --groups
```

### Enumerate Password Policy
```bash
netexec ldap <DomainController> -u <Username> -p '<Password>' --pass-pol
```

### Enumerate Trusted Domains
```bash
netexec ldap <DomainController> -u <Username> -p '<Password>' --trusted-for-delegation
```

## LDAP Enumeration with Impacket

### GetADUsers.py - Enumerate Users
```bash
impacket-GetADUsers -all -dc-ip <DomainController> <Domain>/<Username>:'<Password>'
```

### GetADUsers.py - Output to File
```bash
impacket-GetADUsers -all -dc-ip <DomainController> <Domain>/<Username>:'<Password>' > users.txt
```

## Extracting Useful Information

### Find User Email Addresses
```bash
ldapsearch -x -H ldap://<DomainController> -D "<Username>@<Domain>" -w '<Password>' -b "DC=corp,DC=local" "(objectClass=user)" mail | grep mail:
```

### Find User Descriptions (Often Contain Passwords)
```bash
ldapsearch -x -H ldap://<DomainController> -D "<Username>@<Domain>" -w '<Password>' -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName description | grep -B1 description:
```

> [!warning] Administrators sometimes store passwords in user description fields.

### Find Last Logon Times
```bash
ldapsearch -x -H ldap://<DomainController> -D "<Username>@<Domain>" -w '<Password>' -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName lastLogon
```

### Find Password Last Set
```bash
ldapsearch -x -H ldap://<DomainController> -D "<Username>@<Domain>" -w '<Password>' -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName pwdLastSet
```

## LDAP Enumeration Workflow

### Step 1: Test Anonymous Bind
```bash
ldapsearch -x -H ldap://<DomainController> -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName
```

> [!tip] If anonymous bind works, you can enumerate without credentials.

### Step 2: Enumerate Users with windapsearch
```bash
python3 windapsearch.py -d <Domain> -u <Username> -p '<Password>' --dc-ip <DomainController> -U --full > users.txt
```

### Step 3: Enumerate Computers
```bash
python3 windapsearch.py -d <Domain> -u <Username> -p '<Password>' --dc-ip <DomainController> -C --full > computers.txt
```

### Step 4: Find Privileged Users
```bash
python3 windapsearch.py -d <Domain> -u <Username> -p '<Password>' --dc-ip <DomainController> --privileged-users
```

### Step 5: Find Kerberoastable Users
```bash
ldapsearch -x -H ldap://<DomainController> -D "<Username>@<Domain>" -w '<Password>' -b "DC=corp,DC=local" "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName
```

### Step 6: Create HTML Reports
```bash
ldapdomaindump -u '<Domain>\<Username>' -p '<Password>' <DomainController> -o /tmp/ldap_dump
```

> [!tip] Open `domain_users.html` in a browser for easy analysis.

## Troubleshooting

### "Invalid Credentials" Error
> [!warning] Ensure you're using the correct authentication format:
> - `username@domain.com` (UPN format)
> - `DOMAIN\username` (NetBIOS format)
> - `CN=username,OU=Users,DC=domain,DC=com` (DN format)

### "Can't Contact LDAP Server" Error
```bash
# Test connectivity
nc -zv <DomainController> 389

# Try LDAPS instead
ldapsearch -x -H ldaps://<DomainController> -D "<Username>@<Domain>" -w '<Password>' -b "DC=corp,DC=local"
```

### "Operations Error" or "Referral" Error
> [!info] You may be querying a non-authoritative DC. Try specifying the PDC:
```bash
ldapsearch -x -H ldap://<PDC-IP> -D "<Username>@<Domain>" -w '<Password>' -b "DC=corp,DC=local"
```

### Empty Results
```bash
# Verify base DN is correct
ldapsearch -x -H ldap://<DomainController> -D "<Username>@<Domain>" -w '<Password>' -b "" -s base namingContexts
```

## OSCP Exam Tips

> [!important] LDAP enumeration is critical for AD environments.

**Time Estimate:** 10-15 minutes for comprehensive LDAP enumeration

**Quick Wins:**
1. **Test anonymous bind first** - Some domains allow it
2. **Use windapsearch for speed** - Faster than manual ldapsearch
3. **Check user descriptions** - Often contain passwords
4. **Find Kerberoastable users** - Easy privilege escalation path
5. **Enumerate privileged groups** - Identify high-value targets

**Common Mistakes:**
- Not testing anonymous LDAP access
- Using wrong authentication format
- Forgetting to enumerate SPNs for Kerberoasting
- Not checking user descriptions for passwords

**Pro Tips:**
- Save all LDAP output to files for later analysis
- Use `ldapdomaindump` for visual HTML reports
- Cross-reference LDAP data with BloodHound results
- Look for users with `adminCount=1` - they're privileged
