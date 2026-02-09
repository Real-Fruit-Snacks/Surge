---
tags:
  - Discovery
  - Exploitation
  - Foundational
  - HTTP
  - Reconnaissance
  - Web_Application
---

## Web Application Enumeration
resources: [HackTricks - Web Pentesting](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/index.html)

> [!info] Start web app enumeration from the web server. Identify server software, version, and technology stack before testing the application.

### Nmap Service Detection
```bash
nmap -p <Port> -sV <Target>
```

### Nmap HTTP Enumeration Script
> Performs initial fingerprinting, discovers directories, login pages, and interesting files using **Nmap** NSE scripts.

```bash
nmap -p <Port> --script=http-enum <Target>
```

### Wappalyzer Technology Lookup
> Passive technology stack identification using **Wappalyzer**. Reveals OS, frameworks, JavaScript libraries, and web server.

```
https://www.wappalyzer.com/lookup/<Domain>
```

### Directory Brute Forcing with Gobuster
resources: [HackTricks - Web Enumeration](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/index.html#brute-force-directories-and-files)

> [!warning] **Gobuster** generates significant traffic - not stealthy. Use smaller wordlists and fewer threads (**-t**) to reduce noise.

#### Basic Directory Scan
```bash
gobuster dir -u http://<Target> -w /usr/share/wordlists/dirb/common.txt
```

#### Reduce Threads
```bash
gobuster dir -u http://<Target> -w /usr/share/wordlists/dirb/common.txt -t 5
```

#### Common Wordlists
> [!tip] Common wordlists:
> - **/usr/share/wordlists/dirb/common.txt** - Common directories and files
> - **/usr/share/wordlists/dirb/big.txt** - Larger wordlist for thorough enumeration
> - **/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt** - Medium-sized comprehensive list

### Check robots.txt
> Contains **Allow/Disallow** directives for web crawlers. May reveal sensitive directories.

```bash
curl http://<Target>/robots.txt
```

> [!warning] Nmap's `http-robots.txt` script can miss data - always check manually.

### Check sitemap.xml
```bash
curl http://<Target>/sitemap.xml
```

### Check for .git Directory
> [!warning] Dirbuster and most wordlists do NOT check for `.git` folders.

```bash
# Manual check
curl http://<Target>/.git/

# Check for common .git files
curl http://<Target>/.git/config
curl http://<Target>/.git/HEAD
```

> [!tip] If `.git` directory is exposed, use git-dumper to extract the repository.

**Extract with git-dumper:**
```bash
git-dumper http://<Target>/.git/ ./output
cd output
git log
git show <commit-id>
```

> [!info] Look for credentials in commit history, config files, and old code.

### Check PHPInfo Pages
> [!tip] PHPInfo pages reveal absolute file paths for webshell uploads.

```bash
# Common PHPInfo locations
curl http://<Target>/phpinfo.php
curl http://<Target>/info.php
curl http://<Target>/test.php
curl http://<Target>/php.php
```

**What to look for:**
- `DOCUMENT_ROOT` - Web root directory
- `SCRIPT_FILENAME` - Current script path
- `_SERVER["PHP_SELF"]` - Script location
- `upload_tmp_dir` - Temporary upload directory

**Example use:**
```text
DOCUMENT_ROOT: /var/www/html
SCRIPT_FILENAME: /var/www/html/phpinfo.php
```

> [!tip] Use these paths to determine where uploaded files are stored.

### Inspect Response Headers
> [!tip] Look for **Server**, **X-Powered-By**, **X-Aspnet-Version**, and other headers revealing technology stack.

```bash
curl -I http://<Target>
```

**Use Nikto for comprehensive header analysis:**
```bash
nikto -h http://<Target>
```

> [!info] Nikto checks for interesting response headers, missing security headers, and server versions.

### WordPress Enumeration with WPScan
> [!important] Use aggressive mode for maximum coverage - passive mode misses vulnerabilities.

```bash
wpscan -e p --plugins-detection aggressive --detection-mode aggressive --url http://<Target>
```

**Flags:**
- `-e p` - Enumerate plugins
- `--plugins-detection aggressive` - Aggressive plugin detection
- `--detection-mode aggressive` - Aggressive detection mode

**Enumerate users:**
```bash
wpscan --url http://<Target> -e u
```

**Brute force login:**
```bash
wpscan --url http://<Target> -U users.txt -P /usr/share/wordlists/rockyou.txt
```

### Directory Traversal Test Files
> [!tip] If you suspect directory traversal, test these common files.

**Windows:**
```bash
# Test for directory traversal
curl http://<Target>/download?file=../../../../../../../Windows/System32/drivers/etc/hosts
curl http://<Target>/download?file=../../../../../../../inetpub/wwwroot/web.config
```

**Linux:**
```bash
# Test for directory traversal
curl http://<Target>/download?file=../../../../../../../etc/passwd
curl http://<Target>/download?file=../../../../../../../etc/shadow
```

**URL encoding:**
```bash
# Try URL-encoded paths
curl http://<Target>/download?file=..%2f..%2f..%2f..%2f..%2fetc%2fpasswd
curl http://<Target>/download?file=....//....//....//....//etc/passwd
```

### Recursive File Search
> [!tip] Find interesting files that could contain credentials.

**PowerShell (Windows):**
```powershell
Get-ChildItem -Path C: -Include *.ps1,*.txt,*.exe,*.log,*.ini,*.kdbx,*.pdf,*.xls,*.xlsx -Recurse -ErrorAction SilentlyContinue
```

**Bash (Linux):**
```bash
find / -type f \( -iname \*.txt\* -o -iname \*.log\* -o -iname \*.ps1\* -o -iname \*.exe\* \) 2>/dev/null
```

> [!info] Look for credentials in `.txt`, `.log`, `.ini`, `.kdbx`, and `.ps1` files.
