---
tags:
  - Foundational
  - Windows
---

## Windows Remote Access
resources: [HackTricks WinRM](https://book.hacktricks.xyz/network-services-pentesting/5985-5986-pentesting-winrm), [HackTricks PSExec](https://book.hacktricks.xyz/windows-hardening/lateral-movement/psexec-and-winexec)

> [!info] Methods to connect to a Windows target with credentials or a shell.

### RDP
> [!tip] GUI access. Best for manual enumeration and when you need to interact with GUI apps.

```bash
xfreerdp3 /u:<Username> /p:'<Password>' /v:<TargetIP> /dynamic-resolution +clipboard /cert:ignore
```

```bash
# With domain
xfreerdp3 /u:<Username> /p:'<Password>' /d:<Domain> /v:<TargetIP> /dynamic-resolution +clipboard /cert:ignore
```

```bash
# Pass the hash (requires Restricted Admin mode enabled)
xfreerdp3 /u:<Username> /pth:<NTLMHash> /v:<TargetIP> /dynamic-resolution +clipboard /cert:ignore
```

### WinRM / Evil-WinRM
> [!info] PowerShell remoting. Port 5985 (HTTP) or 5986 (HTTPS).

```bash
evil-winrm -i <TargetIP> -u <Username> -p '<Password>'
```

```bash
# With domain
evil-winrm -i <TargetIP> -u <Username> -p '<Password>' -d <Domain>
```

```bash
# Pass the hash
evil-winrm -i <TargetIP> -u <Username> -H <NTLMHash>
```

```bash
# With SSL (port 5986)
evil-winrm -i <TargetIP> -u <Username> -p '<Password>' -S
```

### PSExec
> [!important] Requires admin credentials and SMB access (port 445).

```bash
impacket-psexec <Domain>/<Username>:'<Password>'@<TargetIP>
```

```bash
# Pass the hash
impacket-psexec -hashes :<NTLMHash> <Domain>/<Username>@<TargetIP>
```

### WMI
> [!important] Windows Management Instrumentation. Requires admin credentials.

```bash
impacket-wmiexec <Domain>/<Username>:'<Password>'@<TargetIP>
```

```bash
# Pass the hash
impacket-wmiexec -hashes :<NTLMHash> <Domain>/<Username>@<TargetIP>
```

### SSH
> [!info] If OpenSSH is installed on target.

```bash
ssh <Username>@<TargetIP>
```

### Reverse Shell Listener [Local]
> [!info] Catch a reverse shell from the target.

```bash
nc -lvnp <PORT>
```

```bash
rlwrap nc -lvnp <PORT>
```

#### Penelope [alternative]
> [!tip] Feature-rich shell handler with auto-upgrade, logging, and tab completion.

```bash
penelope <PORT>
```

```bash
# Multiple listeners
penelope 4444 5555 6666
```
