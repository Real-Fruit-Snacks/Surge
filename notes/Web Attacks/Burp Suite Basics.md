---
tags:
  - Burp_Suite
  - Exploitation
  - Foundational
  - Web_Application
---

### Useful Tips

#### Add Host to /etc/hosts
> [!important] Required when application uses hostnames in links/redirects.

```bash
echo "<TargetIP> <Hostname>" | sudo tee -a /etc/hosts
```

#### Send curl Through Burp
```bash
curl http://<Target> --proxy 127.0.0.1:8080
```
