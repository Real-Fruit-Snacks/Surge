---
tags:
  - Active_Directory
  - Discovery
  - Enumeration
  - Foundational
  - Kerberos
  - Windows
---

## Enumerating Kerberos Users (No Credentials)
resources: [HackTricks Kerberos User Enumeration](https://book.hacktricks.xyz/network-services-pentesting/pentesting-kerberos-88)

> [!info] **What you're looking for:**
> - Valid usernames (confirmed by Kerberos responses)
> - ASREPRoastable users (no pre-auth)
> - This works WITHOUT any credentials!

> [!tip] **Recommended wordlists for user enumeration:**
> - `/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt`
> - Custom list based on company naming convention (e.g., first.last, flast, firstl)
> - Names from LinkedIn, company website, OSINT

### Kerbrute for Valid Users
```bash
kerbrute userenum --dc '<DC_IP>' -d '<Domain_Local>' /root/machines/<Machine>/<TargetIP>/usernames
```

### [Alternate] Nmap Kerberos Enumeration
```bash
nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<Domain_Local>',userdb=/root/machines/<Machine>/<TargetIP>/usernames <DC-IP>
```
