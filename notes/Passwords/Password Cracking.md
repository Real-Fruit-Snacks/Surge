---
tags:
  - Credential_Access
  - Foundational
  - Hashcat
  - Password_Attack
---

## Password Cracking Methodology
resources: [Hashcat](https://hashcat.net/hashcat/), [John the Ripper](http://www.openwall.com/john/), [Weakpass Wordlists](https://weakpass.com/wordlist), [HashKiller](https://hashkiller.io/listmanager), [CrackStation](https://crackstation.net/)

> Comprehensive methodology for cracking password hashes using Hashcat and John the Ripper.

## Hash Identification

> [!tip] Always identify the hash type before attempting to crack it.

### hashid - Quick Hash Identification
```bash
hashid <Hash>
```

**Example:**
```bash
hashid 5f4dcc3b5aa765d61d8327deb882cf99
# Output: MD5
```

### name-that-hash - Advanced Identification
```bash
nth -t '<Hash>'
```

**Example:**
```bash
nth -t '5f4dcc3b5aa765d61d8327deb882cf99'
# Provides hash type + Hashcat mode number + John format
```

> [!info] `name-that-hash` is more accurate than `hashid` and provides Hashcat mode numbers directly.

### Install name-that-hash
```bash
pip3 install name-that-hash
```

### Hash Examples by Type

| Hash Type | Example Hash | Hashcat Mode | John Format |
|-----------|--------------|--------------|-------------|
| MD5 | `5f4dcc3b5aa765d61d8327deb882cf99` | `-m 0` | `--format=raw-md5` |
| SHA1 | `5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8` | `-m 100` | `--format=raw-sha1` |
| SHA256 | `5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8` | `-m 1400` | `--format=raw-sha256` |
| NTLM | `8846f7eaee8fb117ad06bdd830b7586c` | `-m 1000` | `--format=nt` |
| NetNTLMv2 | `admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030` | `-m 5600` | `--format=netntlmv2` |
| Kerberos 5 TGS-REP | `$krb5tgs$23$*user$realm$test/spn*$...` | `-m 13100` | `--format=krb5tgs` |
| Kerberos 5 AS-REP | `$krb5asrep$23$user@domain.com:...` | `-m 18200` | `--format=krb5asrep` |
| bcrypt | `$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6` | `-m 3200` | `--format=bcrypt` |
| SHA512crypt | `$6$52450745$k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnPgh2XzzF0NDrUhgrcLwg78xs1w5pJiypEdFX/` | `-m 1800` | `--format=sha512crypt` |

## Core Concepts

### Encoding vs Hashing vs Encrypting
> [!info] Understanding the differences:
> - **Encoding**: Transforms data into a publicly known scheme for usability
> - **Hashing**: One-way cryptographic function nearly impossible to reverse
> - **Encrypting**: Mapping of input/output data reversible with a key

### CPU vs GPU
> [!info] Hardware considerations:
> - **CPU**: 2-72 cores optimized for sequential serial processing
> - **GPU**: 1000s of cores with 1000s of threads for parallel processing

### Cracking Time Formula
> [!important] Calculate expected cracking time:
> - **Keyspace**: `charset^length` (e.g., `?a?a?a?a = 95^4 = 81,450,625`)
> - **Hashrate**: hashing function / hardware power
> - **Cracking Time**: `keyspace / hashrate`

### Salt and Iterations
> [!info] Hash strengthening:
> - **Salt**: Random data used as additional input to a one-way function
> - **Iterations**: Number of times an algorithm is run over a given hash

## Attack Types

> [!info] Different methods for attacking password hashes:
> - **Dictionary/Wordlist Attack**: Uses precompiled list of words and phrases
> - **Brute-Force Attack**: Attempts every possible combination of a character set
> - **Rule Attack**: Generates permutations against a wordlist
> - **Mask Attack**: Targeted brute-force using placeholders (e.g., `?a?a?a?l?d?d`)
> - **Hybrid Attack**: Combines Dictionary and Mask attacks

## Benchmark Testing

### John the Ripper Benchmark
```bash
john --test
```

### Hashcat Benchmark
```bash
hashcat -b
```

## Basic Cracking Playbook

> Step-by-step methodology for cracking hashes. This example assumes MD5 (fast hash).

### Step 1 - Custom Wordlist Attack
```bash
hashcat -a 0 -m 0 -w 4 <HashFile> <CustomWordlist>
```

### Step 2 - Custom Wordlist with Rules
```bash
hashcat -a 0 -m 0 -w 4 <HashFile> <CustomWordlist> -r best64.rule --loopback
```

### Step 3 - Dictionary Attack
```bash
hashcat -a 0 -m 0 -w 4 <HashFile> <Wordlist>
```

### Step 4 - Dictionary with Rules
```bash
hashcat -a 0 -m 0 -w 4 <HashFile> <Wordlist> -r best64.rule
```

### Step 5 - Combinator Attack
```bash
hashcat -a 1 -m 0 -w 4 <HashFile> <Wordlist1> <Wordlist2>
```

### Step 6 - Hybrid Attack
```bash
hashcat -a 6 -m 0 -w 4 <HashFile> <Wordlist> ?d?d?d?d
```

### Step 7 - Mask Attack
```bash
hashcat -a 3 -m 0 -w 4 <HashFile> ?a?a?a?a?a?a?a?a
```

## Hashcat Rule-Based Attacks

### Create Simple Rule
```bash
echo '$1' > example.rule
```

> Appends "1" to end of each password.

### Preview Mutated Passwords
```bash
hashcat -r example.rule --stdout wordlist.txt
```

### Common Rule Patterns
```text
$1      # Append 1
$!      # Append !
^1      # Prepend 1
c       # Capitalize first letter
u       # Uppercase all
l       # Lowercase all
sa@     # Replace 'a' with '@'
se3     # Replace 'e' with '3'
```

### Multi-Rule File
```bash
echo -e 'c $1\nc $!\nc $1 $!' > example.rule
```

> Each line is a separate rule. Creates: `Password1`, `Password!`, `Password1!`

## Advanced Techniques

### Loopback Mode
> [!tip] Use already cracked passwords as input for further cracking.

```bash
hashcat -a 0 -m 0 <HashFile> <Wordlist> --loopback
```

### Incremental Mode (John)
```bash
john --incremental <HashFile>
```

### Using Previously Found Passwords (John)
```bash
john --loopback <HashFile>
```

## Common Hash Types for OSCP

### Windows NTLM Hashes
```bash
# Hashcat
hashcat -a 0 -m 1000 ntlm.txt /usr/share/wordlists/rockyou.txt

# John
john --format=nt ntlm.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

> [!tip] NTLM hashes crack very quickly - try rockyou.txt first (5-10 minutes).

### NetNTLMv2 (Responder Captures)
```bash
# Hashcat
hashcat -a 0 -m 5600 netntlmv2.txt /usr/share/wordlists/rockyou.txt

# John
john --format=netntlmv2 netntlmv2.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

> [!warning] NetNTLMv2 is much slower to crack than NTLM due to iterations.

### Kerberos TGS-REP (Kerberoasting)
```bash
# Hashcat
hashcat -a 0 -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt

# John
john --format=krb5tgs kerberoast.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

> [!tip] Service account passwords are often weak - try common patterns first.

### Kerberos AS-REP (AS-REP Roasting)
```bash
# Hashcat
hashcat -a 0 -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt

# John
john --format=krb5asrep asrep.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

### Linux /etc/shadow Hashes (SHA512crypt)
```bash
# Hashcat
hashcat -a 0 -m 1800 shadow.txt /usr/share/wordlists/rockyou.txt

# John
john --format=sha512crypt shadow.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

> [!warning] SHA512crypt is VERY slow - consider targeted wordlists or rules.

### SSH Private Key Passphrases
```bash
# Extract hash
ssh2john id_rsa > ssh.hash

# Crack with John
john ssh.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

### ZIP File Passwords

#### fcrackzip - Dictionary Attack
```bash
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt <ZipFile>
```

#### fcrackzip - Brute Force
> **Charsets:** `a` lowercase, `A` uppercase, `1` digits, `!` special

```bash
fcrackzip -u -b -c a1 -l 4-8 <ZipFile>
```

#### zip2john - For Hashcat/John
```bash
# Extract hash
zip2john backup.zip > zip.hash

# Crack with John
john zip.hash --wordlist=/usr/share/wordlists/rockyou.txt

# Crack with Hashcat (mode 17200 for PKZIP)
hashcat -a 0 -m 17200 zip.hash /usr/share/wordlists/rockyou.txt
```

### 7z Archive Passwords
```bash
# Extract hash
7z2john backup.7z > 7z.hash

# Crack with John
john 7z.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

### RAR Archive Passwords
```bash
# Extract hash
rar2john backup.rar > rar.hash

# Crack with John
john rar.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

## Online Hash Lookup

> [!tip] Before spending time cracking, check if the hash is already known.

### CrackStation
```text
https://crackstation.net/
```

> Paste hash and check against massive precomputed tables.

### HashKiller
```text
https://hashkiller.io/listmanager
```

> Community-driven hash database with billions of entries.

### hashes.com
```text
https://hashes.com/en/decrypt/hash
```

> Free hash lookup with API access.

> [!warning] Never submit sensitive hashes to online services in real engagements.

## Hash Cracking Strategy for OSCP

> [!important] Time management is critical during the exam.

### Quick Wins (5-15 minutes)
1. **Online lookup** - Check CrackStation/HashKiller first
2. **NTLM with rockyou.txt** - Fast hash, large wordlist
3. **Common passwords** - `Password1`, `Welcome1`, `Summer2024`
4. **Username as password** - Try `john:john`, `admin:admin`

### Medium Effort (15-60 minutes)
1. **Kerberoast with rockyou.txt + best64.rule**
2. **NetNTLMv2 with rockyou.txt**
3. **Custom wordlist from website/documents**
4. **Hybrid attack** - `rockyou.txt` + `?d?d?d?d`

### Last Resort (1+ hours)
1. **Mask attack** - If you know password policy
2. **Large wordlists** - Weakpass, SecLists
3. **Incremental mode** - Brute force (usually not viable)

> [!tip] If a hash doesn't crack in 30 minutes, move on and come back later.

## Troubleshooting

### Hash Format Issues
```bash
# Remove username prefix if present
cat hashes.txt | cut -d: -f2 > clean_hashes.txt

# John expects username:hash format
cat hashes.txt | awk '{print "user:"$1}' > formatted.txt
```

### Show Cracked Passwords

#### Hashcat
```bash
hashcat -m 1000 ntlm.txt --show
```

#### John
```bash
john --show ntlm.txt
```

### Resume Interrupted Session

#### Hashcat
```bash
hashcat -m 1000 ntlm.txt /usr/share/wordlists/rockyou.txt --restore
```

#### John
```bash
# John automatically resumes from ~/.john/john.rec
john --restore
```

### Clear Hashcat Potfile (Start Fresh)
```bash
rm ~/.hashcat/hashcat.potfile
```

### Clear John Potfile
```bash
rm ~/.john/john.pot
```

## Required Software

> [!info] Install the following tools on your cracking rig:
> - **Hashcat v5.1+**: [https://hashcat.net/hashcat/](https://hashcat.net/hashcat/)
> - **John the Ripper (Jumbo)**: [http://www.openwall.com/john/](http://www.openwall.com/john/)
> - **PACK (Password Analysis & Cracking Toolkit)**: [http://thesprawl.org/projects/pack/](http://thesprawl.org/projects/pack/)
> - **Hashcat-utils**: [https://github.com/hashcat/hashcat-utils](https://github.com/hashcat/hashcat-utils)
