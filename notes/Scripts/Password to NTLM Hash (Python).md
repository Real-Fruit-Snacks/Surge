---
tags:
  - Credential_Access
  - Foundational
  - NTLM
  - Password_Attack
  - Python
---

## Password to NTLM Hash (Python)
> [!info] Converts a cleartext password to its NTLM hash using **passlib**. NTLM hash is the MD4 hash of the password encoded in UTF-16LE.

### Create the Script
```python
#!/usr/bin/env python3
"""Convert a cleartext password to an NTLM hash."""

import sys
from passlib.hash import nthash

def password_to_ntlm(password: str) -> str:
    """
    Convert a cleartext password to its NTLM hash.
    
    NTLM hash is the MD4 hash of the password encoded in UTF-16LE (little-endian).
    """
    return nthash.hash(password).upper()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        password = sys.argv[1]
    else:
        password = input("Enter password: ")
    
    ntlm_hash = password_to_ntlm(password)
    print(f"Password: {password}")
    print(f"NTLM Hash: {ntlm_hash}")
```
