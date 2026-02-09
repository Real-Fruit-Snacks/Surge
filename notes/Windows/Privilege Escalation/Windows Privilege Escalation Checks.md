---
tags:
  - Foundational
  - Privilege_Escalation
  - Windows
---
## Windows Privilege Escalation Checks
resources: [PrivescCheck GitHub](https://github.com/itm4n/PrivescCheck)

### Manual Checks [Remote]
```bash
whoami /all
```

```bash
systeminfo
```

### PrivescCheck - Basic [Remote]
```powershell
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"
```

### PrivescCheck - Extended [Remote]
```powershell
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report PrivescCheck_$($env:COMPUTERNAME) -Format TXT,HTML"
```

### PrivescCheck - All Checks [Remote]
```powershell
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Audit -Report PrivescCheck_$($env:COMPUTERNAME) -Format TXT,HTML,CSV,XML"
```

> [!tip] Copy report back to host machine for review.
