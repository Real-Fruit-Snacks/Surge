---
tags:
  - Discovery
  - Foundational
  - Network
  - Nmap
  - Reconnaissance
---

## Port Scanning
resources: [HackTricks - Pentesting Network](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/pentesting-network/index.html)

> [!info] Default scan probes top 1000 TCP ports. Use **-Pn** to skip host discovery if target blocks ICMP.

### Basic Scans

#### Default Scan (Top 1000 Ports)
```bash
nmap <Target>
```

#### Skip Host Discovery
```bash
nmap -Pn <Target>
```

#### Scan All Ports
```bash
nmap -p- <Target>
```

#### Scan Specific Ports
```bash
nmap -p <Port1>,<Port2>,<Port3> <Target>
```

#### Scan Port Range
```bash
nmap -p <StartPort>-<EndPort> <Target>
```

### Scan Types

#### SYN/Stealth Scan (Default with Root)
> [!info] Sends SYN, receives SYN-ACK, never completes handshake. Faster and less likely to be logged.

```bash
sudo nmap -sS <Target>
```

#### TCP Connect Scan
> [!tip] Full TCP handshake. Works without root. Use when scanning through proxies.

```bash
nmap -sT <Target>
```

#### UDP Scan
> [!warning] Slower and less reliable than TCP. Requires root.

```bash
sudo nmap -sU <Target>
```

#### Combined TCP and UDP
```bash
sudo nmap -sS -sU <Target>
```

### Performance and Output

#### Timing Templates
> Timing templates: **T0** (paranoid) to **T5** (insane). Default is **T3**.

```bash
nmap -T4 <Target>
```

#### Min Rate
```bash
nmap --min-rate 1000 <Target>
```

#### All Output Formats
```bash
nmap -oA output <Target>
```

#### Greppable Output
```bash
nmap -oG output.txt <Target>
```

## Network Discovery

### Host Discovery (Ping Sweep)
> Sends ICMP echo, TCP SYN to port 443, TCP ACK to port 80, and ICMP timestamp.

```bash
nmap -sn <NetworkRange>
```

### Save to Greppable Output
```bash
nmap -sn <NetworkRange> -oG hosts.txt
```

### Extract Live Hosts
```bash
grep Up hosts.txt | cut -d " " -f 2
```

### Sweep for Specific Port
```bash
nmap -p <Port> <NetworkRange> -oG sweep.txt
```

### Top Ports Scan
```bash
nmap --top-ports=20 <NetworkRange>
```

## Service Enumeration

### OS Fingerprinting
> [!info] Guesses OS based on TCP/IP stack implementation.

```bash
sudo nmap -O <Target>
```

#### OS Fingerprinting with Guess
```bash
sudo nmap -O --osscan-guess <Target>
```

### Service Version Detection
```bash
nmap -sV <Target>
```

### Aggressive Scan
> [!info] Enables OS detection, version detection, script scanning, and traceroute.

```bash
nmap -A <Target>
```

### NSE Scripts
> [!tip] Scripts located in **/usr/share/nmap/scripts/**. Use for enumeration, brute force, and vulnerability detection.

#### Run Specific Script
```bash
nmap --script <ScriptName> <Target>
```

#### Run Script Category
```bash
nmap --script vuln <Target>
```

#### Get Script Help
```bash
nmap --script-help <ScriptName>
```

#### Common Scripts [optional]
```bash
nmap --script http-headers <Target>
```

```bash
nmap --script smb-os-discovery <Target>
```

```bash
nmap --script dns-brute <Target>
```

### PowerShell Port Scanning [Remote]
> [!info] Living off the Land when no tools are available.

#### Test Single Port
```powershell
Test-NetConnection -Port <Port> <Target>
```

#### Scan Port Range
```powershell
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("<Target>", $_)) "TCP port $_ is open"} 2>$null
```
