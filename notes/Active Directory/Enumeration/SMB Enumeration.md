---
tags:
  - Active_Directory
  - Discovery
  - Enumeration
  - Foundational
  - SMB
  - Windows
---

## Enumerating SMB (With Credentials)

> [!important] **What "(Pwn3d!)" means in NetExec output:**
> - **Pwn3d!** = Local administrator privileges on target (can dump SAM/LSA/NTDS, execute commands, perform lateral movement)
> - **No Pwn3d!** = Valid credentials but NOT local admin (can enumerate shares/users/groups, Kerberoast, ASREPRoast, but cannot dump credentials or execute)

### Enum4Linux

```bash
enum4linux-ng -A <TargetIP> -u '<Username>' -p '<Password>'
```

### SMBMap
> [!tip] Enumerates shares and checks permissions with credentials.

```bash
smbmap -H <TargetIP> -u '<Username>' -p '<Password>'
```

#### Recursive Listing

```bash
smbmap -H <TargetIP> -u '<Username>' -p '<Password>' -r <Share>
```

#### With Domain

```bash
smbmap -H <TargetIP> -u '<Username>' -p '<Password>' -d <Domain>
```

### NetExec

#### Directory Setup
```bash
mkdir -p /root/machines/<Machine>/<TargetIP>/netexec && cd /root/machines/<Machine>/<TargetIP>/netexec
```

#### Users

```bash
nxc smb <TargetIP> -u '<Username>' -p '<Password>' --users
```

#### Shares

```bash
nxc smb <TargetIP> -u '<Username>' -p '<Password>' --shares
```

#### [Optional] Download All Files from Every Accessible Share
```bash
netexec smb <TargetIP> -u '<Username>' -p '<Password>' -M spider_plus -o DOWNLOAD_FLAG=True OUTPUT_FOLDER=/root/machines/<Machine>/<TargetIP>/netexec
```

#### [Optional] Grep Output

```bash
grep -rniE 'pass|password|passwd|pwd|secret|api[_-]?key|apikey|token|auth|credential|private[_-]?key' /root/machines/<Machine>/<TargetIP>/netexec
```

#### [Optional] Cat Output (Lots of Lines if Big Files)

```bash
find /root/machines/<Machine>/<TargetIP>/netexec -type f -exec cat {} \;
```

#### Groups

```bash
nxc ldap <TargetIP> -u '<Username>' -p '<Password>' --groups
```

#### Administrator Group Members

```bash
nxc ldap <TargetIP> -u '<Username>' -p '<Password>' --groups Administrators
```

#### Domain Admin Members

```bash
nxc ldap <TargetIP> -u '<Username>' -p '<Password>' --groups 'Domain Admins'
```

#### Enterprise Admins

```bash
nxc ldap <TargetIP> -u '<Username>' -p '<Password>' --groups 'Enterprise Admins'
```

#### [Optional] Group Counts

```bash
nxc ldap <TargetIP> -u '<Username>' -p '<Password>' --groups | egrep -iv 'membercount: 0'
```

#### Password Policy

```bash
nxc smb <TargetIP> -u '<Username>' -p '<Password>' --pass-pol
```

#### Computers

```bash
nxc ldap <TargetIP> -u '<Username>' -p '<Password>' --computers
```

#### Qwinsta

```bash
nxc smb <TargetIP> -u '<Username>' -p '<Password>' --qwinsta
```

#### Local-Groups

```bash
nxc smb <TargetIP> -u '<Username>' -p '<Password>' --local-groups
```

#### Administrator Local Group Members

```bash
nxc smb <TargetIP> -u '<Username>' -p '<Password>' --local-groups Administrators
```

#### RID Brute
```bash
nxc smb <TargetIP> -u '<Username>' -p '<Password>' --rid-brute 10000
```

### SMB Client

```bash
smbclient //<TargetIP>/<Share> -U '<Domain_Local>/<Username>%<Password>'
```

#### Upload File

```bash
put <LocalFile>
```

#### Download File

```bash
get <RemoteFile>
```

#### Recursive Download
> [!tip] Downloads all files and subdirectories from current location.

```bash
mask ""
recurse ON
prompt OFF
mget *
```

### Mounting SMB Shares

#### Mount CIFS Share

```bash
sudo mount -t cifs -o 'user=<Username>,password=<Password>' //<TargetIP>/<Share> /mnt/<MountPoint>
```

#### List Mounted Contents [optional]

```bash
ls -latRr /mnt/<MountPoint>
```

### SMB Permissions [optional]

#### Check ACL with smbcacls
> [!tip] Displays Windows-style ACLs on files/directories within an SMB share.

```bash
smbcacls --no-pass //<TargetIP>/<Share> <RemotePath>
```

#### With Credentials [alternative]

```bash
smbcacls //<TargetIP>/<Share> <RemotePath> -U '<Username>'
```
