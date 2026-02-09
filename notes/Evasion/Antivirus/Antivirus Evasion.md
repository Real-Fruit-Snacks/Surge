---
tags:
  - Defense_Evasion
  - Foundational
  - Windows
---

### On-Disk Techniques [optional]
> [!info] Methods to modify payloads on disk:
> - **Packers** - Compress and restructure executables (UPX). Creates new hash.
> - **Obfuscators** - Reorganize code, insert junk instructions, rename functions.
> - **Crypters** - Encrypt payload, decrypt in memory at runtime.

### In-Memory Techniques [optional]
> [!info] Advanced techniques that avoid disk writes:
> - **Remote Process Injection** - Inject into another process using VirtualAllocEx, WriteProcessMemory, CreateRemoteThread.
> - **Reflective DLL Injection** - Load DLL from memory without LoadLibrary.
> - **Process Hollowing** - Replace legitimate process memory with malicious code.
> - **Inline Hooking** - Redirect function calls to malicious code.
