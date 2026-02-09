# Password Strategy

tags: #Passwords #Strategy #Reference #Foundational

> [!info] Strategic approach to password attacks during penetration testing. Follow this methodology to maximize success while minimizing time waste.

## Testing Philosophy

> [!important] **Golden Rule**: Always try the easiest attacks first before moving to time-consuming brute-forcing.

### Priority Order

1. **Default Credentials** (30 seconds - 2 minutes)
2. **Username as Password** (30 seconds)
3. **Credential Reuse** (1 minute)
4. **Password Spraying** (5-10 minutes)
5. **Targeted Wordlist** (10-30 minutes)
6. **Rockyou.txt** (30 minutes - hours)
7. **Custom Wordlist Generation** (if needed)
8. **Brute Force** (last resort)

## Step 1: Default Credentials

> [!tip] **Always start here!** Many systems still use default credentials.

### Common Defaults to Try

```plaintext
admin:admin
administrator:administrator
admin:password
admin:Password1
root:root
root:toor
```

### Service-Specific Defaults

```plaintext
# MySQL
root:(blank)
root:root

# PostgreSQL
postgres:postgres

# MSSQL
sa:(blank)
sa:sa

# Tomcat
tomcat:tomcat
admin:admin

# Jenkins
admin:admin
```

### Quick Test

```bash
# Try admin:admin first
crackmapexec smb <TargetIP> -u admin -p admin

# Try administrator:administrator
crackmapexec smb <TargetIP> -u administrator -p administrator
```

> [!tip] If this works, you just saved hours of work!

## Step 2: Username as Password

> [!important] **Second most common** - users often set their password to their username.

### Testing Strategy

```bash
# If you have usernames
crackmapexec smb <TargetIP> -u users.txt -p users.txt --no-bruteforce

# Single user
crackmapexec smb <TargetIP> -u john -p john
```

### Why This Works

- Lazy password policies
- Temporary accounts
- Testing/development accounts
- Service accounts

## Step 3: Credential Reuse

> [!tip] **If you found ANY credentials, try them EVERYWHERE!**

### Found Credentials Checklist

```plaintext
✓ Try on all discovered services
✓ Try on all discovered hosts
✓ Try with different usernames
✓ Try variations (uppercase, lowercase)
```

### Example Workflow

```bash
# Found MySQL creds: root:Password123
# Try on SSH
ssh root@<TargetIP>
# Password: Password123

# Try on SMB
crackmapexec smb <TargetIP> -u root -p 'Password123'

# Try on WinRM
evil-winrm -i <TargetIP> -u root -p 'Password123'

# Try on RDP
xfreerdp3 /u:root /p:'Password123' /v:<TargetIP>
```

## Step 4: Password Spraying

> [!info] Try a few common passwords against all users. **Much faster than brute-forcing!**

### Common Password List

```plaintext
password
password1
Password1
Password123
Password@123
Welcome1
Welcome123
Welcome@123
Company123
Company2024
Summer2024
Winter2024
```

### Execution

```bash
# Create spray list
cat > spray.txt << EOF
password
Password1
Welcome1
Password123
EOF

# Spray against all users
crackmapexec smb <TargetIP> -u users.txt -p spray.txt --continue-on-success
```

> [!warning] Be careful with account lockout policies! Space out attempts if needed.

## Step 5: Dealing with Passwords

### When Brute-Forcing is Necessary

> [!important] Only brute-force when:
> - You have a valid username
> - Default credentials failed
> - Password spraying failed
> - You have a good wordlist

### Best Practices

1. **Have valid usernames first**
2. **Don't forget trying `admin:admin`**
3. **Try `username:username` as first credential**
4. **If related to a service, try default passwords**
5. **Service name as username AND password**
6. **Use Rockyou.txt only after trying common passwords**

### Common Mistakes to Avoid

```plaintext
❌ Starting with rockyou.txt immediately
❌ Brute-forcing without valid usernames
❌ Not trying credential reuse
❌ Ignoring default credentials
❌ Not checking for account lockout
```

## Password Patterns

### Year-Based Passwords

```plaintext
Password2024
Welcome2024
Company2024
Admin2024
Spring2024
Summer2024
Fall2024
Winter2024
```

### Month-Based Passwords

```plaintext
January2024
February2024
March2024
April2024
```

### Company-Based Passwords

```plaintext
<CompanyName>123
<CompanyName>2024
<CompanyName>!
<CompanyName>@123
<CompanyName>@2024
```

### Common Patterns

```plaintext
# Capital + lowercase + numbers + special
Password123!
Welcome123!
Admin123!

# Season + Year
Summer2024
Winter2024

# Month + Year
January2024
```

## Service-Specific Strategies

### SSH

```bash
# Try common defaults
ssh admin@<TargetIP>
# Passwords: admin, password, Password1

# Try username as password
ssh john@<TargetIP>
# Password: john

# Spray common passwords
hydra -L users.txt -P spray.txt ssh://<TargetIP>
```

### SMB/Windows

```bash
# Try admin:admin
crackmapexec smb <TargetIP> -u admin -p admin

# Try administrator:administrator
crackmapexec smb <TargetIP> -u administrator -p administrator

# Password spray
crackmapexec smb <TargetIP> -u users.txt -p spray.txt
```

### RDP

```bash
# Try administrator:password
xfreerdp3 /u:administrator /p:password /v:<TargetIP>

# Try admin:admin
xfreerdp3 /u:admin /p:admin /v:<TargetIP>
```

### Web Applications

```bash
# Try admin:admin on login form
# Try username:username
# Try default credentials for the specific CMS
```

## Time Management

### Quick Wins (0-5 minutes)

```plaintext
✓ Default credentials (2 min)
✓ Username as password (1 min)
✓ Credential reuse (2 min)
```

### Medium Effort (5-30 minutes)

```plaintext
✓ Password spraying (10 min)
✓ Common passwords (10 min)
✓ Service-specific defaults (10 min)
```

### High Effort (30+ minutes)

```plaintext
✓ Rockyou.txt (30 min - hours)
✓ Custom wordlist generation (varies)
✓ Brute force (hours - days)
```

## OSCP Exam Strategy

> [!warning] In OSCP exam:
> - Time is limited (24 hours for 3 machines)
> - Brute-forcing is rarely the answer
> - Focus on enumeration over brute-forcing
> - If you're brute-forcing, you're probably missing something

### Exam-Specific Workflow

```plaintext
1. Try admin:admin (30 sec)
2. Try username:username (30 sec)
3. Enumerate more (10 min)
4. Try password spray with 5-10 common passwords (5 min)
5. If still stuck, enumerate more - don't brute force yet
6. Only use rockyou.txt if you have strong evidence
```

### When to Brute Force in Exam

```plaintext
✓ Found a hash that needs cracking
✓ Found encrypted file (zip, keepass, etc.)
✓ Specific hint that brute-forcing is needed
✓ All other enumeration exhausted
```

### When NOT to Brute Force

```plaintext
❌ As first attempt
❌ Without valid usernames
❌ Without trying defaults first
❌ When you haven't fully enumerated
```

## Wordlist Recommendations

### Quick Tests (< 1 minute)

```bash
# Top 100 passwords
/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt

# Top 1000 passwords
/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt
```

### Medium Tests (5-30 minutes)

```bash
# Top 10000 passwords
/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt

# Common passwords
/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt
```

### Full Tests (30+ minutes)

```bash
# Rockyou
/usr/share/wordlists/rockyou.txt

# SecLists passwords
/usr/share/seclists/Passwords/
```

## Creating Custom Wordlists

### Based on Company Name

```bash
# Using cewl to scrape website
cewl http://<TargetWebsite> -w custom.txt -d 2

# Add year variations
cat custom.txt | sed 's/$/@2024/' >> custom_year.txt
cat custom.txt | sed 's/$/2024/' >> custom_year.txt
cat custom.txt | sed 's/$/123/' >> custom_year.txt
```

### Based on Username

```bash
# If username is "john.smith"
cat > john_passwords.txt << EOF
john
smith
johnsmith
john.smith
john123
smith123
johnsmith123
EOF
```

## Credential Storage

### Document Everything

```plaintext
Service: SSH
Host: 10.10.10.5
Username: admin
Password: Password123!
Notes: Found via password spray
Date: 2024-01-15
```

### Organize by Host

```plaintext
=== 10.10.10.5 ===
SSH: admin:Password123!
SMB: admin:Password123!
MySQL: root:Password123!

=== 10.10.10.6 ===
RDP: administrator:Welcome1
WinRM: administrator:Welcome1
```

## Common Password Lists

### Always Try These First

```plaintext
password
password1
Password1
Password123
Password@123
password@123
admin
administrator
admin@123
welcome
Welcome1
Welcome123
P@ssw0rd
P@ssword
P@ssword1
root
toor
changeme
12345678
123456
qwerty
```

### Service Account Patterns

```plaintext
service:service
mysql:mysql
postgres:postgres
tomcat:tomcat
jenkins:jenkins
apache:apache
nginx:nginx
```

## Summary Checklist

```plaintext
Before Brute-Forcing, Have You:
☐ Tried admin:admin?
☐ Tried username:username?
☐ Tried default credentials for the service?
☐ Tried credential reuse from other services?
☐ Tried password spraying with common passwords?
☐ Checked for password hints in enumeration?
☐ Verified you have valid usernames?
☐ Checked account lockout policy?
☐ Considered if brute-forcing is really necessary?
```

> [!tip] If you answered "No" to any of these, do that first before brute-forcing!
