---
tags:
  - Credential_Access
  - Foundational
  - Windows
---
### Output Indicators
| Output | Meaning |
|--------|---------|
| `[+]` | Successful authentication |
| `(Pwn3d!)` | Admin access, can execute commands |
| `[-]` | Failed authentication |
| `STATUS_LOGON_FAILURE` | Wrong password |
| `STATUS_ACCOUNT_LOCKED_OUT` | Account locked |
| `STATUS_PASSWORD_EXPIRED` | Password expired |
| `STATUS_PASSWORD_MUST_CHANGE` | Must change password at next logon |
