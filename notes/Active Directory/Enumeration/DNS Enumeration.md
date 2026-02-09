---
tags:
  - Active_Directory
  - DNS
  - Discovery
  - Enumeration
  - Foundational
  - Windows
---

## Enumerating DNS (No Credentials)
resources: [HackTricks DNS Enumeration](https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns)

> [!info] **What you're looking for:**
> - Domain Controller hostnames and IPs
> - Additional domain-joined hosts
> - Subdomains and service records
> - Zone transfer misconfigurations (rare but valuable)

> [!tip] **What to look for in output:**
> - `_ldap._tcp.dc._msdcs` records → Domain Controller locations
> - `_kerberos._tcp` records → Kerberos KDC (usually DC)
> - `_gc._tcp` records → Global Catalog servers
> - Multiple A records for same name → Potential load balancers or clusters

### Basic DNS Queries

#### host Command (Linux)
```bash
host <Domain>
```

```bash
host -t mx <Domain>
```

```bash
host -t txt <Domain>
```

```bash
host -t ns <Domain>
```

#### nslookup (Windows) [Remote]
> [!tip] Built-in Windows DNS query tool. Useful for Living off the Land scenarios.

```cmd
nslookup <Hostname>
```

```cmd
nslookup -type=<RecordType> <Hostname> <DNSServer>
```

### Zone Transfer
```bash
dig axfr @<DC_IP> <Domain_Local>
```

```bash
host -t axfr <Domain_Local> <DC_IP>
```

### DC Discovery via SRV Records
```bash
dig SRV _ldap._tcp.dc._msdcs.<Domain_Local> @<DC_IP>
```

```bash
dig SRV _kerberos._tcp.<Domain_Local> @<DC_IP>
```

```bash
nslookup -type=SRV _ldap._tcp.<Domain_Local>
```

### Subdomain Enumeration

#### Forward DNS Brute Force
> [!info] Uses a wordlist of common subdomain names. **SecLists** has comprehensive wordlists at `/usr/share/seclists/Discovery/DNS/`.

```bash
for sub in $(cat <Wordlist>); do host $sub.<Domain>; done | grep -v "not found"
```

#### Reverse DNS Lookup
> [!tip] Scan an IP range to discover hostnames via PTR records.

```bash
for ip in $(seq <Start> <End>); do host <NetworkPrefix>.$ip; done | grep -v "not found"
```

### DNS Enumeration Tools

#### DNSRecon Standard Scan
> [!info] Retrieves SOA, NS, MX, TXT records and checks DNSSEC.

```bash
dnsrecon -d <Domain_Local> -t std
```

#### DNSRecon Brute Force
```bash
dnsrecon -d <Domain> -D <Wordlist> -t brt
```

#### DNSenum
```bash
dnsenum <Domain_Local>
```

#### DNSenum with Custom Wordlist
```bash
dnsenum --dnsserver <DNSServer> -f <Wordlist> <Domain>
```
