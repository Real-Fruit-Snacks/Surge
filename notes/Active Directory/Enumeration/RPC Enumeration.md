---
tags:
  - Active_Directory
  - Discovery
  - Enumeration
  - Foundational
  - RPC
  - Windows
---

## Enumerating RPC (With Credentials)

### RPC Client
```bash
rpcclient -U '<Domain_Local>/<Username>%<Password>' <TargetIP>
```

#### RPC Client > List All Domain Users
```bash
enumdomusers
```

#### RPC Client > List All Domain Groups
```bash
enumdomgroups
```

#### RPC Client > Query Domain Admins (RID 512 = 0x200)
```bash
querygroup 0x200
```

#### RPC Client > Members of Domain Admins
```bash
querygroupmem 0x200
```

#### RPC Client > Password Policy
> [!warning] **Password Policy - What to look for:**
> - `Minimum password length: 7` - Weak if less than 8
> - `Password history: 24` - Number of remembered passwords
> - `Lockout threshold: 5` - **CRITICAL** - don't exceed this!
> - `Lockout duration: 30 minutes` - How long until unlock
> - `Lockout observation window: 30` - Window for counting failures

> [!danger] **Always check password policy before spraying!** If lockout threshold is 5, spray maximum 3-4 passwords to be safe.

```bash
getdompwinfo
```

#### RPC Client > Get SID for Specific User
```bash
lookupnames admin
```

#### RPC Client > Resolve SID to name

```bash
lookupsids S-1-5-21-...-500
```

#### RPC Client > Enumerate Privileges

```bash
enumpriv
```

#### RPC Client > User Password Policy
> [!info] Get user RID from queryuser first.

```bash
getuserdompwinfo <UserRID>
```

#### RPC Client > Server Information

```bash
srvinfo
```

#### RPC Client > Enumerate All SIDs

```bash
lsaenumsid
```

#### RPC Client > Enumerate Domains

```bash
enumdomains
```

#### RPC Client > Enumerate Shares

```bash
netshareenumall
```

#### RPC Client > User Descriptions

```bash
querydispinfo
```

#### RPC Client > Create Domain User

```bash
createdomuser <NewUsername>
```

#### RPC Client > Delete Domain User

```bash
deletedomuser <Username>
```
