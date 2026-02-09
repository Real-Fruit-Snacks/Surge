---
tags:
  - Discovery
  - Enumeration
  - Foundational
  - Linux
---

## Operating System Information
resources: [HackTricks - Linux Enumeration](https://book.hacktricks.wiki/en/linux-hardening/linux-privilege-escalation-checklist.html)

> Gather basic system information for situational awareness.

### Check Disk Usage
```bash
df -h
```

### Check Kernel and CPU Information
```bash
uname -a
```

### Display OS Information
```bash
cat /etc/issue
```

### Display OS Version
```bash
cat /etc/*release*
```

### Display Kernel Information
```bash
cat /proc/version
```

### Locate Shell Executables
```bash
# Find location of specific shells (bash, csh, ksh, tcsh, etc.)
which <ShellName>
```

### Display Connected Drives
```bash
fdisk -l
```

## Package Management - RPM (Red Hat)

### List Installed Packages
```bash
rpm -qa
```

### Install RPM Packages
```bash
# Install all .rpm files in current directory
rpm -ivh *.rpm
```

### Remove Package
```bash
rpm -e <PackageName>
```

## Package Management - DPKG (Debian)

### List Installed Packages
```bash
dpkg --get-selections
```

### Install Debian Packages
```bash
# Install all .deb files in current directory
dpkg -i *.deb
```

### Remove Package
```bash
dpkg -r <PackageName>
```

## System Updates with APT

### Update Package Lists
```bash
# Updates repositories and available packages
apt-get update
```

### Upgrade Packages
```bash
# Install newer versions of packages if available
apt-get upgrade
```

### Distribution Upgrade
```bash
# Intelligently updates system, updating dependencies and removing obsolete packages
apt-get dist-upgrade
```

## Situational Awareness and Process Manipulation

### Current User Information
```bash
id
```

### List Logged On Users
```bash
# List logged on users and what they are doing
w
```

### Show Currently Logged In Users
```bash
who -a
```

### Show Login History
```bash
last -a
```

### Process Listing
```bash
ps -ef
```

### List Mounted Drives
```bash
mount
```

```bash
findmnt
```

### Kill Process by PID
```bash
kill -9 <PID>
```

### Kill All Processes by Name
```bash
killall <ProcessName>
```

### Show Active Processes
```bash
top
```

### List Configured Mounts
```bash
cat /etc/fstab
```

## User Account Enumeration and Configuration

### Display User and Service Accounts
```bash
getent passwd
```

### Add User
```bash
useradd -m <Username>
```

### Add User to Group
```bash
usermod -g <GroupName> <Username>
```

### Change User Password
```bash
passwd <Username>
```

### Lock User Account
```bash
usermod --expiredate 1 --lock --shell /bin/nologin <Username>
```

### Unlock User Account
```bash
usermod --expiredate 99999 --unlock --shell /bin/bash <Username>
```

### Enumerate User Account Details
```bash
chage -l <Username>
```

### Delete User
```bash
userdel <Username>
```

## Network Configuration

### Monitor TCP Connections
```bash
# List all listening, established, and connected TCP sockets every 3 seconds
watch --interval 3 ss -t --all
```

### List Listening Sockets
```bash
# List all listening TCP and UDP sockets with PID/program name
netstat -tulpn
```

### List Network Activity by User
```bash
lsof -i -u <Username> -a
```

### Set IP Address (ifconfig)
```bash
ifconfig <InterfaceName> <NewIP> netmask <NewSubnetMask>
```

### Set IP Address (ip)
```bash
ip addr add <NewIP> dev <InterfaceName>
```

### Add Secondary IP (ifconfig)
```bash
ifconfig <InterfaceName>:<NewInterfaceName> <NewIP>
```

### Add Secondary IP (ip)
```bash
ip addr add <NewIP>/<CIDR> dev <InterfaceName>
```

### Set Default Gateway (route)
```bash
route add default gw <GatewayIP> <InterfaceName>
```

### Add Route (ip)
```bash
ip route add <Network>/<CIDR> via <GatewayIP> dev <InterfaceName>
```

### Change MTU Size (ifconfig)
```bash
ifconfig <InterfaceName> mtu <Size>
```

### Change MTU Size (ip)
```bash
ip link set dev <InterfaceName> mtu <Size>
```

### Change MAC Address (ifconfig)
```bash
ifconfig <InterfaceName> hw ether <MACAddress>
```

### Change MAC Address (ip)
```bash
ip link set dev <InterfaceName> down
ip link set dev <InterfaceName> address <MACAddress>
ip link set dev <InterfaceName> up
```

### Wireless Network Scan
```bash
iwlist <InterfaceName> scan
```

### List DHCP Assignments
```bash
cat /var/log/messages | grep DHCP
```

### Kill TCP Connection
```bash
tcpkill host <IPAddress> and port <Port>
```

### Enable IP Forwarding
```bash
echo "1" > /proc/sys/net/ipv4/ip_forward
```

### Add DNS Server
```bash
echo "nameserver <DNSServer>" >> /etc/resolv.conf
```

## DNS Zone Transfer

### Reverse Domain Lookup
```bash
dig -x <IPAddress>
```

### Domain Lookup
```bash
host <IPAddressOrHostname>
```

### DNS Zone Transfer (dig)
```bash
dig axfr <DomainName> @<DNSServerIP>
```

### DNS Zone Transfer (host)
```bash
host -t axfr -l <DomainName> <DNSServerIP>
```
