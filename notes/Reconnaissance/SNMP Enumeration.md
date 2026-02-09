---
tags:
  - Discovery
  - Foundational
  - Network
  - Reconnaissance
  - SNMP
---

## SNMP Enumeration
resources: [HackTricks - Pentesting SNMP](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-snmp/index.html)

> [!info] **SNMP** (UDP 161) is often misconfigured with default community strings (**public**/**private**). SNMPv1, v2, v2c have no encryption. The MIB tree contains system info, users, processes, software, and open ports.

### Key Windows MIB OIDs
> [!important] Key Windows MIB OIDs:
> - **1.3.6.1.4.1.77.1.2.25** - User Accounts
> - **1.3.6.1.2.1.25.4.2.1.2** - Running Programs
> - **1.3.6.1.2.1.25.6.3.1.2** - Installed Software
> - **1.3.6.1.2.1.6.13.1.3** - TCP Local Ports
> - **1.3.6.1.2.1.25.4.2.1.4** - Processes Path
> - **1.3.6.1.2.1.25.2.3.1.4** - Storage Units

### Nmap UDP Scan
```bash
sudo nmap -sU --open -p 161 <NetworkRange> -oG open-snmp.txt
```

### Brute Force Community Strings
> [!tip] Create wordlist of community strings and list of target IPs for brute forcing with **onesixtyone**.

```bash
echo public > community
echo private >> community
echo manager >> community
```

```bash
for ip in $(seq 1 254); do echo 192.168.50.$ip; done > ips
```

```bash
onesixtyone -c community -i ips
```

### Enumerate Entire MIB Tree
```bash
snmpwalk -c <CommunityString> -v1 -t 10 <Target>
```

### Enumerate Windows Users
```bash
snmpwalk -c <CommunityString> -v1 <Target> 1.3.6.1.4.1.77.1.2.25
```

### Enumerate Running Processes
```bash
snmpwalk -c <CommunityString> -v1 <Target> 1.3.6.1.2.1.25.4.2.1.2
```

### Enumerate Installed Software
```bash
snmpwalk -c <CommunityString> -v1 <Target> 1.3.6.1.2.1.25.6.3.1.2
```

### Enumerate TCP Listening Ports
```bash
snmpwalk -c <CommunityString> -v1 <Target> 1.3.6.1.2.1.6.13.1.3
```
