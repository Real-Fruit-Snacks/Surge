---
tags:
  - Foundational
  - Linux
---

## Linux File System Structure
resources: [Linux Filesystem Hierarchy](https://www.pathname.com/fhs/)

> Reference for standard Linux file system hierarchy and important directories.

### Root Directories
> Core directories at the root of the Linux file system.

```text
/ - Anchor and root of the filesystem
/bin - User binaries
/boot - Boot-up related files
/dev - Interface for system devices
/etc - System configuration files
/home - Base directory for user files
/lib - Critical software libraries
/opt - Third party software
/proc - System and running programs
/root - Home directory of root user
/sbin - System administrator binaries
/tmp - Temporary files
/usr - Contains all system files (less critical)
/var - Variable system files
```

### Important Files and Directories
> Critical files for enumeration and post-exploitation.

```bash
# User and authentication files
/etc/shadow           # User account info and password hashes
/etc/passwd           # User account information
/etc/group            # Group names

# Startup and services
/etc/rc.d             # Startup services (rc0.d-rc6.d)
/etc/init.d           # Contains startup/stop scripts

# Network configuration
/etc/hosts            # Hardcoded hostname and IP combinations
/etc/hostname         # Full hostname with domain
/etc/network/interfaces  # Network configuration (Debian)
/etc/netplan          # Network configuration (Ubuntu)
/etc/resolv.conf      # DNS configuration

# System configuration
/etc/profile          # System environment variables
/etc/apt/sources.list # Debian package source
/etc/fstab            # Local and network mounts/shares

# User directories
/home/<User>/.bash_history  # User Bash history
~/.ssh/               # SSH keystore

# Logs
/var/log              # System log files (most Linux)
/var/adm              # System log files (Unix)
/var/spool/cron       # List cron files
/var/log/apache2/access.log  # Apache connection log

# Misc
/usr/share/wireshark/manuf  # Vendor-MAC lookup (Kali)
```

## Shadow and Passwd File Formats

### /etc/shadow Format
> Format: `username:hash:lastchange:min:max:warn:inactive:expire:reserved`

```bash
# Example shadow entry:
# root:$6$RqNi$...PbED0:16520:0:99999:7:::
#
# Field 1: Login name
# Field 2: Encrypted password
# Field 3: Date of last password change (days since epoch)
# Field 4: Minimum password age (in days)
# Field 5: Maximum password age (in days)
# Field 6: Password warning period (in days)
# Field 7: Password inactivity period (in days)
# Field 8: Account expiration date (days since epoch)
# Field 9: Reserved

# View shadow configuration
cat /etc/login.defs
```

### Shadow Hash Types
> Identify hash algorithm from the first characters of the hash.

```text
$1$   - MD5
$2a$  - bcrypt
$2y$  - bcrypt
$5$   - SHA-256
$6$   - SHA-512

# Example: $6$n4wLdmr59pt... indicates SHA-512
```

### /etc/passwd Format
> Format: `username:password:uid:gid:comment:home:shell`

```bash
# Example passwd entry:
# root:x:0:0:Root:/root:/bin/bash
#
# Field 1: Login name
# Field 2: Password (x = in shadow, * = cannot login)
# Field 3: User ID (UID) - root = 0
# Field 4: Primary Group ID (GID)
# Field 5: Comment/User full name
# Field 6: User's home directory
# Field 7: User's default shell
```

## Common Commands Reference

### File Operations
```bash
# Find files
find / -name "filename" 2>/dev/null
find / -type f -name "*.conf" 2>/dev/null

# Search file contents
grep -r "pattern" /path 2>/dev/null

# File permissions
chmod 755 file
chmod +x file
chown user:group file

# Create/extract archives
tar -czf archive.tar.gz /path
tar -xzf archive.tar.gz
```

### Text Processing
```bash
# View files
cat file
less file
head -n 20 file
tail -n 20 file
tail -f /var/log/syslog

# Search and filter
grep "pattern" file
grep -i "pattern" file  # case insensitive
grep -v "pattern" file  # invert match
grep -r "pattern" /path # recursive

# Text manipulation
sed 's/old/new/g' file
awk '{print $1}' file
cut -d: -f1 /etc/passwd
sort file
uniq file
```

### System Information
```bash
# Hostname
hostname
hostname -I

# Uptime
uptime

# Memory
free -h

# Disk space
df -h
du -sh /path

# CPU info
lscpu
cat /proc/cpuinfo

# Loaded modules
lsmod
```

### Network Commands
```bash
# Network interfaces
ip addr
ifconfig

# Routing table
ip route
route -n

# Active connections
netstat -tulpn
ss -tulpn

# DNS lookup
nslookup domain
dig domain

# Ping
ping -c 4 target

# Traceroute
traceroute target
```

### Process Management
```bash
# List processes
ps aux
ps -ef
pstree

# Process by name
pgrep process_name
pidof process_name

# Kill process
kill PID
kill -9 PID
killall process_name

# Background/foreground
command &
fg
bg
jobs
```

### User Management
```bash
# Current user
whoami
id

# Switch user
su - username
sudo -i

# User info
finger username
w
who
last
```

## Useful One-Liners

### Find Writable Directories
```bash
find / -writable -type d 2>/dev/null
```

### Find SUID Binaries
```bash
find / -perm -4000 2>/dev/null
```

### Find Files Modified in Last 10 Minutes
```bash
find / -mmin -10 2>/dev/null
```

### Find Large Files
```bash
find / -type f -size +100M 2>/dev/null
```

### Search for Passwords in Files
```bash
grep -r -i "password" /home 2>/dev/null
grep -r -i "pass=" /var/www 2>/dev/null
```

### List All Listening Ports
```bash
netstat -tulpn | grep LISTEN
ss -tulpn | grep LISTEN
```
