# Important File Locations

tags: #Reference #Windows #Linux #Files #Foundational

## Finding Files in Windows (CTF Style)

### Quick Directory Tree View

```cmd
cd C:\Users
tree /F
```

> [!tip] This displays all files in a tree structure, useful for finding sensitive files quickly.

## Windows Important Locations

### Registry and User Data

```plaintext
C:/Users/Administrator/NTUser.dat
C:/Documents and Settings/Administrator/NTUser.dat
```

### Web Server Configurations

```plaintext
C:/apache/logs/access.log
C:/apache/logs/error.log
C:/apache/php/php.ini
C:/inetpub/wwwroot/global.asa
```

### Apache Configurations

```plaintext
C:/Program Files/Apache Group/Apache2/conf/httpd.conf
C:/Program Files/Apache Group/Apache/conf/httpd.conf
C:/Program Files/Apache Group/Apache/logs/access.log
C:/Program Files/Apache Group/Apache/logs/error.log
C:/Program Files (x86)/Apache Group/Apache2/conf/httpd.conf
C:/Program Files (x86)/Apache Group/Apache/conf/httpd.conf
C:/Program Files (x86)/xampp/apache/conf/httpd.conf
```

### MySQL Configurations and Logs

```plaintext
C:/MySQL/data/hostname.err
C:/MySQL/data/mysql.err
C:/MySQL/data/mysql.log
C:/MySQL/my.cnf
C:/MySQL/my.ini
C:/Program Files/MySQL/data/hostname.err
C:/Program Files/MySQL/data/mysql-bin.log
C:/Program Files/MySQL/data/mysql.err
C:/Program Files/MySQL/data/mysql.log
C:/Program Files/MySQL/my.ini
C:/Program Files/MySQL/my.cnf
C:/Program Files/MySQL/MySQL Server 5.0/data/hostname.err
C:/Program Files/MySQL/MySQL Server 5.0/data/mysql-bin.log
C:/Program Files/MySQL/MySQL Server 5.0/my.cnf
C:/Program Files/MySQL/MySQL Server 5.1/my.ini
```

### PHP Configurations

```plaintext
C:/php4/php.ini
C:/php5/php.ini
C:/php/php.ini
C:/WINDOWS/php.ini
C:/WINNT/php.ini
C:/xampp/apache/bin/php.ini
```

### FTP Server Configurations

```plaintext
C:/Program Files/FileZilla Server/FileZilla Server.xml
C:/Program Files (x86)/FileZilla Server/FileZilla Server.xml
```

### Windows System Files

```plaintext
C:/boot.ini
C:/WINDOWS/Repair/SAM
C:/Windows/repair/system
C:/Windows/repair/software
C:/Windows/repair/security
C:/WINDOWS/System32/drivers/etc/hosts
C:/Windows/win.ini
C:/WINNT/win.ini
```

### Windows Setup and Installation Files

```plaintext
C:/Windows/Panther/Unattend/Unattended.xml
C:/Windows/Panther/Unattended.xml
C:/Windows/debug/NetSetup.log
```

### Windows Event Logs

```plaintext
C:/Windows/system32/config/AppEvent.Evt
C:/Windows/system32/config/SecEvent.Evt
```

### Registry Backups

```plaintext
C:/Windows/system32/config/default.sav
C:/Windows/system32/config/security.sav
C:/Windows/system32/config/software.sav
C:/Windows/system32/config/system.sav
C:/Windows/system32/config/regback/default
C:/Windows/system32/config/regback/sam
C:/Windows/system32/config/regback/security
C:/Windows/system32/config/regback/system
C:/Windows/system32/config/regback/software
```

### IIS Configurations and Logs

```plaintext
C:/Windows/System32/inetsrv/config/schema/ASPNET_schema.xml
C:/Windows/System32/inetsrv/config/applicationHost.config
C:/inetpub/logs/LogFiles/W3SVC1/u_ex[YYMMDD].log
```

### XAMPP Logs

```plaintext
C:/xampp/apache/logs/access.log
C:/xampp/apache/logs/error.log
```

## Linux Important Locations

### User and Authentication

```plaintext
/etc/passwd
/etc/shadow
/etc/groups
/etc/npasswd
```

### System Configuration

```plaintext
/etc/issue
/etc/lsb-release
/etc/motd
/etc/hosts
/etc/hosts.allow
/etc/hosts.deny
/etc/hostname
/etc/network/interfaces
/etc/networks
/etc/resolv.conf
/etc/fstab
/etc/mtab
```

### Boot and Kernel

```plaintext
/etc/grub.conf
/etc/lilo.conf
/etc/inittab
/proc/version
/proc/cmdline
/proc/cpuinfo
/proc/meminfo
/proc/modules
/proc/mounts
/proc/filesystems
/proc/interrupts
/proc/ioports
/proc/stat
/proc/swaps
```

### Scheduled Tasks

```plaintext
/etc/crontab
/etc/anacrontab
/etc/cron.allow
/etc/cron.deny
/var/spool/cron/crontabs/root
```

### Apache/Web Server

```plaintext
/etc/apache2/apache2.conf
/etc/apache2/httpd.conf
/etc/apache2/sites-enabled/000-default.conf
/etc/httpd/access.conf
/etc/httpd/conf/httpd.conf
/etc/httpd/httpd.conf
/etc/httpd/srm.conf
/etc/lighttpd.conf
/usr/local/apache/conf/modsec.conf
/usr/local/apache/conf/php.ini
/usr/local/etc/httpd/logs/access_log
/usr/local/etc/httpd/logs/error_log
```

### PHP Configurations

```plaintext
/etc/php.ini
/etc/php/php.ini
/etc/php/apache/php.ini
/etc/php/apache2/php.ini
/etc/php/cgi/php.ini
/etc/php4/apache/php.ini
/etc/php4/apache2/php.ini
/etc/php4/cgi/php.ini
/etc/php4.4/fcgi/php.ini
/etc/php5/apache/php.ini
/etc/php5/apache2/php.ini
/usr/lib/php.ini
/usr/lib/php/php.ini
/usr/local/etc/php.ini
/usr/local/lib/php.ini
```

### MySQL/Database

```plaintext
/etc/my.cnf
/etc/my.conf
/etc/mysql/my.cnf
/var/lib/mysql/my.cnf
/var/lib/mysql/mysql/user.MYD
```

### FTP Servers

```plaintext
/etc/ftpaccess
/etc/ftpchroot
/etc/ftphosts
/etc/ftpusers
/etc/pure-ftpd.conf
/etc/pure-ftpd/pure-ftpd.conf
/etc/pure-ftpd/pure-ftpd.pdb
/etc/pureftpd.passwd
/etc/pureftpd.pdb
/etc/proftp.conf
/etc/proftpd/proftpd.conf
/etc/vhcs2/proftpd/proftpd.conf
/etc/vsftpd.conf
/etc/vsftpd/vsftpd.conf
/etc/vsftpd.chroot_list
/etc/wu-ftpd/ftpaccess
/etc/wu-ftpd/ftphosts
/etc/wu-ftpd/ftpusers
/usr/etc/pure-ftpd.conf
/usr/local/etc/pure-ftpd.conf
/usr/local/etc/pureftpd.pdb
/usr/local/pureftpd/etc/pure-ftpd.conf
/usr/local/pureftpd/etc/pureftpd.pdn
/usr/local/pureftpd/sbin/pure-config.pl
/usr/sbin/pure-config.pl
```

### SSH Configuration

```plaintext
/etc/ssh/ssh_config
/etc/ssh/sshd_config
/etc/ssh/ssh_host_dsa_key
/etc/ssh/ssh_host_dsa_key.pub
/etc/ssh/ssh_host_key
/etc/ssh/ssh_host_key.pub
~/.ssh/authorized_keys
~/.ssh/id_dsa
~/.ssh/id_dsa.pub
~/.ssh/id_rsa
~/.ssh/id_rsa.pub
~/.ssh/id_edcsa
~/.ssh/identity
~/.ssh/identity.pub
```

### Samba

```plaintext
/etc/samba/smb.conf
```

### System Logs

```plaintext
/var/log/auth.log
/var/log/boot
/var/log/daemon.log
/var/log/debug
/var/log/dmesg
/var/log/dpkg.log
/var/log/faillog
/var/log/kern.log
/var/log/lastlog
/var/log/mail.info
/var/log/mail.log
/var/log/mail.warn
/var/log/maillog
/var/log/message
/var/log/messages
/var/log/secure
/var/log/syslog
/var/log/wtmp
/var/log/yum.log
/var/run/utmp
```

### Apache Logs

```plaintext
/var/log/apache/access.log
/var/log/apache/error.log
/var/log/apache2/access.log
/var/log/apache2/access_log
/var/log/apache2/error.log
/var/log/apache2/error_log
/var/log/apache-ssl/access.log
/var/log/apache-ssl/error.log
/var/log/httpd/access.log
/var/log/httpd/access_log
/var/log/httpd/error.log
/var/log/httpd/error_log
/var/log/httpd-access.log
/var/log/httpsd/ssl.access_log
/var/log/httpsd/ssl_log
/usr/local/apache/log
/usr/local/apache/logs
/usr/local/apache/logs/access_log
/usr/local/apache/logs/access.log
/usr/local/apache/audit_log
/usr/local/apache/error_log
/usr/local/apache/error.log
```

### Other Service Logs

```plaintext
/var/log/chttp.log
/var/log/cups/error.log
/var/log/exim_mainlog
/var/log/exim/mainlog
/var/log/exim_paniclog
/var/log/exim.paniclog
/var/log/exim_rejectlog
/var/log/exim/rejectlog
/var/log/ftp-proxy
/var/log/ftp-proxy/ftp-proxy.log
/var/log/ftplog
/var/log/lighttpd/access.log
/var/log/lighttpd/error.log
/var/log/lighttpd/lighttpd.access.log
/var/log/lighttpd/lighttpd.error.log
/var/log/mysqlderror.log
/var/log/mysql.log
/var/log/mysql/mysql-bin.log
/var/log/mysql/mysql.log
/var/log/mysql/mysql-slow.log
/var/log/proftpd
/var/log/pureftpd.log
/var/log/pure-ftpd/pure-ftpd.log
/var/log/vsftpd.log
/var/log/xferlog
/var/mysql.log
/logs/pure-ftpd.log
/logs/security_debug_log
/logs/security_log
```

### cPanel Logs

```plaintext
/usr/local/cpanel/logs
/usr/local/cpanel/logs/access_log
/usr/local/cpanel/logs/error_log
/usr/local/cpanel/logs/license_log
/usr/local/cpanel/logs/login_log
/usr/local/cpanel/logs/stats_log
```

### Web Application Files

```plaintext
/var/www/html/__init__.py
/var/www/html/db_connect.php
/var/www/html/utils.php
/var/www/log/access_log
/var/www/log/error_log
/var/www/logs/access_log
/var/www/logs/access.log
/var/www/logs/error_log
/var/www/logs/error.log
```

### XAMPP (Linux)

```plaintext
/opt/lampp/etc/httpd.conf
/opt/xampp/etc/php.ini
```

### User History Files

```plaintext
~/.bash_history
~/.bash_logout
~/.bash_profile
~/.bashrc
~/.atfp_history
~/.mysql_history
~/.nano_history
~/.php_history
~/.profile
~/.viminfo
~/.login
~/.logout
```

### X Window System

```plaintext
~/.gtkrc
~/.wm_style
~/.Xdefaults
~/.xinitrc
~/.Xresources
~/.xsession
```

### Process Information

```plaintext
/proc/self/cwd/app.py
/proc/self/environ
/proc/self/net/arp
/proc/<pid>/cmdline
/proc/<pid>/maps
/proc/sched_debug
/proc/net/arp
/proc/net/tcp
/proc/net/udp
```

### Other Configuration Files

```plaintext
/etc/aliases
/etc/bashrc
/etc/bootptab
/etc/chrootUsers
/etc/chttp.conf
/etc/cups/cupsd.conf
/etc/exports
/etc/inetd.conf
/etc/knockd.conf
/etc/logrotate.d/ftp
/etc/logrotate.d/proftpd
/etc/logrotate.d/vsftpd.log
/etc/modules.conf
/etc/printcap
/etc/profile
/etc/snmpd.conf
/etc/sysconfig/network
/etc/syslog.conf
/etc/termcap
/var/adm/log/xferlog
/var/apache2/config.inc
/var/cpanel/cpanel.config
/var/local/www/conf/php.ini
/var/webmin/miniserv.log
```

### RedHat Specific

```plaintext
/etc/redhat-release
/root/anaconda-ks.cfg
```

## Search Commands

### Windows Search

```cmd
dir /s SAM
dir /s SYSTEM
dir /s *.kdbx
dir /s *pass*
dir /s *cred*
dir /s *vnc*
dir /s *.config
```

### Linux Search

```bash
find / -name "*.kdbx" 2>/dev/null
find / -name "*pass*" 2>/dev/null
find / -name "*cred*" 2>/dev/null
find / -name "*.conf" 2>/dev/null
```
