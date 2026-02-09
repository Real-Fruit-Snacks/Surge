---
tags:
  - Lab
---

## Lab Machine Template
resources: [RustScan](https://github.com/RustScan/RustScan), [feroxbuster](https://github.com/epi052/feroxbuster), [nikto](https://github.com/sullo/nikto), [ffuf](https://github.com/ffuf/ffuf), [nmap](https://github.com/nmap/nmap), [SecLists](https://github.com/danielmiessler/SecLists), [authfinder](https://github.com/Real-Fruit-Snacks/authfinder), [nxc_enum](https://github.com/Real-Fruit-Snacks/nxc_enum)

> [!tip] Copy this template to `/notes/Machines/` when starting a new box. Update the title, tags, and fill in sections as you progress.

> [!Info] Machine Info
> - **Platform**: HTB / OSCP / PG Practice
> - **Difficulty**: Easy / Medium / Hard
> - **OS**: Linux / Windows
> - **IP Address**: x.x.x.x
> - **Domain**: [optional - for AD environments]
> - **Date Started**:
> - **Date Completed**:
> - **User Flag**:
> - **Root Flag**:
> - **Target Hostname**: [optional]
> - **Target FQDN**: [optional]


### Scenario Description
> Brief description of the box and attack path summary once complete.

### Learning Objectives
> Skills and techniques this box is designed to teach.

### Provided Credentials [optional]

#### Username

```text
<Username>
```

#### Password

```text
<Password>
```

### Create Directory Structure

```bash
alias WD=/root/machines/<MachineName>/<TargetIP> && mkdir -p $WD/{logs,web,scan,nxc,exploit,bloodhound,loot,privesc,www} && cd $WD && touch usernames passwords confirmedCreds notes && ls
```

### Launch Logged Terminal Tabs

```bash
alias WD=/root/machines/<MachineName>/<TargetIP> && alias TS=$(date +%Y%m%d_%H%M) && xfce4-terminal --maximize --hide-menubar --hide-toolbar --working-directory=$WD/ --title="Shell" -e "script -q -f $WD/logs/shell_$TS.log" --tab --working-directory=$WD/scan --title="Scan" -e "script -q -f $WD/logs/scan_$TS.log" --tab --working-directory=$WD/nxc --title="NXC" -e "script -q -f $WD/logs/nxc_$TS.log" --tab --working-directory=$WD/web --title="Web" -e "script -q -f $WD/logs/web_$TS.log" --tab --working-directory=$WD/exploit --title="Exploit" -e "script -q -f $WD/logs/exploit_$TS.log" --tab --working-directory=$WD/ --title="Notes"
```

### Maximize Terminal Window [optional]

```bash
wmctrl -r :ACTIVE: -b add,maximized_vert,maximized_horz
```

### Enumeration

#### RustScan TCP

```bash
rustscan -a <TargetIP> --ulimit 5000 -b 1500 -- -sC -sV -Pn -oN scan.txt
```

```text
# Output

```

#### Nmap UDP

```bash
nmap -sU --top-ports 20 -sV <TargetIP> -oN udp_scan.txt
```

```text
# Output

```

#### authfinder [optional]

```bash
cd /opt/authfinder && python3 authfinder.py <TargetIP> '<Username>' '<Password>'
```

```text
# Output

```

#### nxc_enum [optional]

```bash
cd /opt/nxc_enum && python -m nxc_enum <TargetIP> -u '<Username>' -p '<Password>' -A --copy-paste -o /root/machines/<MachineName>/<TargetIP>/nxc/nxc_enum_results.txt
```

```text
# Output

```

#### Impacket Shell [optional]

```bash
cd /opt/impacket-shell && python -m impacket_shell --target <TargetIP> -u <Username> -p '<Password>' -d <Domain> -vv -A --log /root/machines/<MachineName>/<TargetIP>/impacket_shell.txt
```

```text
# Output

```

### Web Enumeration [optional]

```bash
cd /root/machines/<MachineName>/<TargetIP>/web
```

#### Directory Busting

```bash
feroxbuster -u http://<TargetIP> -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -o ferox.txt
```

```text
# Output

```

#### Vulnerability Scan

```bash
nikto -h http://<TargetIP> -o nikto.txt
```

```text
# Output

```

#### Subdomain Enumeration [optional]

```bash
ffuf -u http://<TargetIP> -H "Host: FUZZ.<Domain>" -w /usr/share/seclists/Discovery/Web-Content/subdomains-top1million-5000.txt -fc 301,302 -o subs.txt
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
<Username>
```

#### Password

```text
<Password>
```

#### Hash

```text
<NTHash>
```
### Credentials Discovered

#### Username

```text
<Username>
```

#### Password

```text
<Password>
```

#### Hash

```text
<NTHash>
```

### Lessons Learned
> Key takeaways and techniques to remember.
