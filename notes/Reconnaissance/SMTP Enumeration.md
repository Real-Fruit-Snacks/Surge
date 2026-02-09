---
tags:
  - Discovery
  - Foundational
  - Reconnaissance
  - SMTP
---

## SMTP User Enumeration
resources: [HackTricks - Pentesting SMTP](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-smtp/index.html)

> [!info] SMTP supports **VRFY** (verify email address) and **EXPN** (expand mailing list) commands that can be abused to enumerate valid users.
> - Response **252** indicates user exists
> - Response **550** indicates user unknown

### Connect with Netcat
```bash
nc -nv <Target> 25
```

### Verify User Exists
```bash
VRFY <Username>
```

### Expand Mailing List [optional]
```bash
EXPN <MailingList>
```

### Python VRFY Script
```python
#!/usr/bin/python
import socket
import sys

if len(sys.argv) != 3:
    print("Usage: vrfy.py <username> <target_ip>")
    sys.exit(0)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((sys.argv[2], 25))

banner = s.recv(1024)
print(banner)

user = (sys.argv[1]).encode()
s.send(b'VRFY ' + user + b'\r\n')
result = s.recv(1024)
print(result)

s.close()
```

### Run Script
```bash
python3 vrfy.py <Username> <Target>
```

### Windows SMTP Enumeration [Remote]
> [!info] Living off the Land from a Windows machine.

#### Test SMTP Port
```powershell
Test-NetConnection -Port 25 <Target>
```

#### Install Telnet Client [optional]
> [!warning] Requires admin privileges. Alternatively, copy **telnet.exe** from another Windows machine.

```powershell
dism /online /Enable-Feature /FeatureName:TelnetClient
```

#### Connect with Telnet
```cmd
telnet <Target> 25
```
