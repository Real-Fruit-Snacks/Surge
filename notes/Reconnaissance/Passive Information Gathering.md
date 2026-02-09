---
tags:
  - Discovery
  - Foundational
  - Reconnaissance
---

## Passive Information Gathering
resources: [HackTricks - Pentesting Methodology](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/pentesting-methodology.html)

> [!info] Query domain registration, infrastructure, and internet-connected devices without touching target directly.

### Whois Enumeration
> Query domain registration info including:
> - Registrant name and organization
> - Address and phone
> - Nameservers

#### Forward Lookup
```bash
whois <Domain>
```

#### Reverse Lookup (IP to Owner)
```bash
whois <IPAddress>
```

### Shodan
resources: [Shodan Search Query Fundamentals](https://help.shodan.io/the-basics/search-query-fundamentals)

> [!info] Search engine for internet-connected devices. Reveals IPs, services, banners, versions, and vulnerabilities.

#### Search by Hostname
```bash
hostname:<Domain>
```

#### Filter by Port
```bash
hostname:<Domain> port:22
```

#### Filter by Product
```bash
hostname:<Domain> product:Apache
```

#### Search by Organization
```bash
org:"<OrganizationName>"
```

#### Find Vulnerable Systems
```bash
hostname:<Domain> vuln:CVE-2021-44228
```

#### Shodan CLI [optional]
```bash
shodan search hostname:<Domain>
```

```bash
shodan host <IPAddress>
```

### Google Dorking
resources: [Google Hacking Database (GHDB)](https://www.exploit-db.com/google-hacking-database)

> [!info] Use search operators to find sensitive information indexed by Google:
> - **site:** - Limits to domain
> - **filetype/ext:** - Limits to file type
> - **intitle:** - Searches page titles
> - **inurl:** - Searches URLs

#### Find Subdomains
```bash
site:<Domain>
```

#### Find Specific File Types
```bash
site:<Domain> filetype:pdf
```

```
site:<Domain> ext:php
```

#### Find Directory Listings
```bash
intitle:"index of" "parent directory"
```

#### Find Login Pages
```bash
site:<Domain> inurl:admin
```

#### Find Configuration Files
```bash
site:<Domain> ext:env | ext:yaml | ext:json | ext:xml | ext:conf | ext:ini | ext:log
```

#### Find Sensitive Information
```bash
site:<Domain> "password" filetype:txt
```

### Technology Fingerprinting - Wappalyzer
```bash
https://www.wappalyzer.com/lookup/<Domain>
```

### Security Headers Analysis
resources: [Security Headers](https://securityheaders.com)

> Check for missing security headers:
> - **Content-Security-Policy**
> - **X-Frame-Options**
> - **Strict-Transport-Security**

```bash
https://securityheaders.com/?q=<URL>
```

### SSL/TLS Analysis
resources: [SSL Labs](https://www.ssllabs.com/ssltest/)

> Check SSL/TLS configuration for vulnerabilities like **POODLE**, **Heartbleed**, and weak ciphers.

```bash
https://www.ssllabs.com/ssltest/analyze.html?d=<Domain>
```

#### testssl.sh [optional]
```bash
testssl.sh <Domain>
```

### GitHub Search
resources: [HackTricks - GitHub Dorks](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/github-leaked-secrets.html)

> [!tip] Search within an org with **org:**, search filenames with **path:**, search file content with keywords.

#### Find Files by Name
```bash
org:<OrgName> path:users
```

```bash
org:<OrgName> path:password
```

```bash
org:<OrgName> path:config
```

#### Find Secrets in Code
```bash
org:<OrgName> password
```

```bash
org:<OrgName> api_key
```

```bash
org:<OrgName> secret
```

### Automated Secret Scanning [optional]

#### Gitleaks
```bash
gitleaks detect --source <RepoPath> -v
```

#### TruffleHog
```bash
trufflehog git <RepoURL>
```
