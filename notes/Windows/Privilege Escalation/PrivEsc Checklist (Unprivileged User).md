---
tags:
  - Foundational
  - Privilege_Escalation
  - Windows
---
### Validate Discovered Credentials [Local]
> [!info] Test any credentials, hashes, or tickets found during enumeration. See **Credential Validation - NetExec** note for more options.

```bash
# Password
nxc smb <TargetIP> -u <Username> -p '<Password>' -d <Domain>
```

```bash
# NTLM hash
nxc smb <TargetIP> -u <Username> -H '<NTLMHash>'
```

```bash
# Check multiple targets
nxc smb 192.168.1.0/24 -u <Username> -p '<Password>'
```
