---
tags:
  - Credential_Access
  - Foundational
  - Initial_Access
  - Social_Engineering
  - Web_Application
---

### Cleanup Tasks

#### Remove CSRF/Security Code
> [!warning] Search for and remove security scripts that may trigger alerts or send requests to legitimate servers.

```bash
grep "csrf" *.html
```

#### Verify No External Requests
> [!tip] Minimize requests to legitimate servers to avoid detection.

```bash
grep -r "https://" signin.html
```
